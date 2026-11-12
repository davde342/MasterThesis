#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>   // NtCreateFile, NtOpenFile, RtlInitUnicodeString, InitializeObjectAttributes, FILE_OPEN, ...

#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)


static const wchar_t kFilesDir[] = L"files";

enum Outcome : uint8_t { kAllow, kDeny, kError };
static const char* const kOutcomeName[] = {"allow", "deny", "error"};

// The verdict and the raw code (GetLastError, errno or NTSTATUS), formatted only when the CSV is written.
struct Attempt {
    Outcome observed;
    uint32_t status;
    uint32_t lastError;  // native opens only: GetLastError() right after the call
};

static Outcome Verdict(bool opened, bool accessDenied) {
    return opened ? kAllow : accessDenied ? kDeny : kError;
}

static Attempt OpenCreateFileW(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD error = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return {Verdict(error == ERROR_SUCCESS, error == ERROR_ACCESS_DENIED), error};
}

static Attempt OpenWfopen(const std::wstring& path) {
    FILE* file = nullptr;
    const errno_t error = _wfopen_s(&file, path.c_str(), L"rb");
    if (file) fclose(file);
    return {Verdict(error == 0, error == EACCES), (uint32_t)error};
}

static Attempt OpenIfstream(const std::wstring& path) {
    errno = 0;
    std::ifstream file(std::filesystem::path(path), std::ios::binary);
    const int error = file.is_open() ? 0 : errno;  // set by the CRT open underneath (MSVC)
    return {Verdict(error == 0, error == EACCES), (uint32_t)error};
}

static const DWORD kLastErrorMark = 0x20000001;

// NtCreateFile (FILE_OPEN) or NtOpenFile of `name`, relative to `root` when it is not null
static Attempt OpenNative(bool useCreate, HANDLE root, const std::wstring& name) {
    UNICODE_STRING objectName;
    RtlInitUnicodeString(&objectName, name.c_str());
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &objectName, OBJ_CASE_INSENSITIVE, root, nullptr);
    IO_STATUS_BLOCK io = {};
    HANDLE file = nullptr;
    const ULONG options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE;
    SetLastError(kLastErrorMark);
    const NTSTATUS status = useCreate
        ? NtCreateFile(&file, FILE_GENERIC_READ, &attributes, &io, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, options, nullptr, 0)
        : NtOpenFile(&file, FILE_GENERIC_READ, &attributes, &io, FILE_SHARE_READ, options);
    const DWORD lastError = GetLastError();
    if (status >= 0) NtClose(file);
    return {Verdict(status >= 0, status == STATUS_ACCESS_DENIED), (uint32_t)status, lastError};
}

struct TestFile {
    std::wstring name;
    bool expectDeny;
    std::wstring absolute;
    std::wstring relative;
    std::wstring ntAbsolute;
};

// The ways of opening one file, in the order of E5's attempts[] table
struct Way {
    const char* api;
    const char* form;
    bool native;  // the status is an NTSTATUS
};
static const Way kWays[] = {
    {"CreateFileW", "absolute", false},  {"CreateFileW", "relative", false},
    {"_wfopen", "absolute", false},      {"_wfopen", "relative", false},
    {"ifstream", "absolute", false},     {"ifstream", "relative", false},
    {"NtCreateFile", "absolute", true},  {"NtCreateFile", "relative", true},
    {"NtOpenFile", "absolute", true},    {"NtOpenFile", "relative", true},
};
static const int kWayCount = sizeof(kWays) / sizeof(kWays[0]);

static Attempt Open(int way, const TestFile& f, HANDLE folder) {
    switch (way) {
        case 0: return OpenCreateFileW(f.absolute);
        case 1: return OpenCreateFileW(f.relative);
        case 2: return OpenWfopen(f.absolute);
        case 3: return OpenWfopen(f.relative);
        case 4: return OpenIfstream(f.absolute);
        case 5: return OpenIfstream(f.relative);
        case 6: return OpenNative(true, nullptr, f.ntAbsolute);
        case 7: return OpenNative(true, folder, f.name);
        case 8: return OpenNative(false, nullptr, f.ntAbsolute);
        default: return OpenNative(false, folder, f.name);
    }
}

struct Config {
    std::vector<TestFile> files;
    HANDLE folder = nullptr;  // the files folder, opened once and shared read-only for the relative native opens
    int threads = 0;
    int rounds = 0;           // run A
    bool untilStop = false;   // run B
    DWORD drainMs = 0;
};

struct Record {
    uint32_t seq;
    uint16_t file;
    uint8_t way;
    Outcome observed;
    uint32_t status;
    uint32_t lastError;
    uint32_t window;  // run B: the cycle k when the open ran entirely while the hooks of cycle k were installed, else 0
};

// alignas(64): each worker's fields sit on their own cache line, so no two workers write to the same line
struct alignas(64) Worker {
    DWORD tid = 0;
    std::vector<Record> journal;
    std::vector<std::array<uint64_t, 7>> counts;  // run B: per file and way, indexed by Outcome, kChanged, kInWindow
};
static const int kChanged = 3;   // native opens whose last-error code was not kLastErrorMark after the call
static const int kInWindow = 4;  // kInWindow + Outcome: the opens made inside a window

static std::atomic<bool> g_stop{false};

static std::atomic<uint32_t> g_window{0};

// One round: every file through every way
static void Round(Worker& w, const Config& c, uint32_t& seq) {
    for (size_t f = 0; f < c.files.size(); ++f) {
        for (int way = 0; way < kWayCount; ++way) {
            if (!c.untilStop) {
                const Attempt a = Open(way, c.files[f], c.folder);
                w.journal.push_back({seq++, (uint16_t)f, (uint8_t)way, a.observed, a.status, a.lastError, 0});
                continue;
            }
            const uint32_t before = g_window.load();
            const Attempt a = Open(way, c.files[f], c.folder);
            const uint32_t window = (g_window.load() == before) ? before : 0;
            auto& n = w.counts[f * kWayCount + way];
            n[a.observed]++;
            if (kWays[way].native && a.lastError != kLastErrorMark) n[kChanged]++;
            if (window != 0) n[kInWindow + a.observed]++;
            if (a.observed == kDeny) {
                w.journal.push_back({seq, (uint16_t)f, (uint8_t)way, a.observed, a.status, a.lastError, window});
            }
            seq++;
        }
    }
}

static void RunWorker(Worker& w, const Config& c, HANDLE start) {
    w.tid = GetCurrentThreadId();
    if (c.untilStop) {
        w.counts.assign(c.files.size() * kWayCount, {});
    } else {
        w.journal.reserve((size_t)c.rounds * c.files.size() * kWayCount);
    }
    WaitForSingleObject(start, INFINITE);
    uint32_t seq = 0;
    if (c.untilStop) {
        while (!g_stop.load(std::memory_order_relaxed)) Round(w, c, seq);
    } else {
        for (int r = 0; r < c.rounds; ++r) Round(w, c, seq);
    }
}

// The status as E5 writes it: decimal for GetLastError and errno, 8 hex digits for an NTSTATUS
static void PrintStatus(FILE* out, const Way& way, uint32_t status) {
    fprintf(out, way.native ? "0x%08lx" : "%lu", (unsigned long)status);
}

static void PrintCounts(FILE* out, const char* phase, const Worker& w, const Config& c) {
    for (size_t f = 0; f < c.files.size(); ++f) {
        for (int way = 0; way < kWayCount; ++way) {
            const auto& n = w.counts[f * kWayCount + way];
            fprintf(out, "%s,%lu,%s,%s,%ls,%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n", phase, w.tid, kWays[way].api,
                    kWays[way].form, c.files[f].name.c_str(), c.files[f].expectDeny ? "deny" : "allow", n[kAllow],
                    n[kDeny], n[kError], n[kChanged], n[kInWindow + kAllow], n[kInWindow + kDeny],
                    n[kInWindow + kError]);
        }
    }
}

// The rows of one worker's journal: run A's journal.csv, or run B's denied.csv, which has the window after seq
static void PrintJournal(FILE* out, const Worker& w, const Config& c, bool withWindow) {
    for (const Record& r : w.journal) {
        const TestFile& f = c.files[r.file];
        const Way& way = kWays[r.way];
        fprintf(out, "%lu,%u,", w.tid, r.seq);
        if (withWindow) fprintf(out, "%u,", r.window);
        fprintf(out, "%s,%s,%ls,%s,%s,", way.api, way.form, f.name.c_str(), f.expectDeny ? "deny" : "allow",
                kOutcomeName[r.observed]);
        PrintStatus(out, way, r.status);
        fputc(',', out);
        if (way.native) fprintf(out, "0x%08lx", (unsigned long)r.lastError);
        fputc('\n', out);
    }
}

int wmain(int argc, wchar_t* argv[]) {
    Config c;
    std::vector<std::pair<std::wstring, bool>> names;  // name, deny expected

    for (int i = 1; i < argc; ++i) {
        const wchar_t* flag = argv[i];
        if (!wcscmp(flag, L"--until-stop")) {
            c.untilStop = true;
            continue;
        }
        const wchar_t* value = argv[++i];
        if (!wcscmp(flag, L"--expect-allow")) names.push_back({value, false});
        else if (!wcscmp(flag, L"--expect-deny")) names.push_back({value, true});
        else if (!wcscmp(flag, L"--threads")) c.threads = _wtoi(value);
        else if (!wcscmp(flag, L"--rounds")) c.rounds = _wtoi(value);
        else if (!wcscmp(flag, L"--drain-ms")) c.drainMs = (DWORD)_wtoi(value);
    }

    wchar_t folder[MAX_PATH];
    GetFullPathNameW(kFilesDir, MAX_PATH, folder, nullptr);
    c.folder = CreateFileW(kFilesDir, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    for (const auto& [name, expectDeny] : names) {
        const std::wstring absolute = std::wstring(folder) + L"\\" + name;
        // \??\ is the directory of DOS device names, where C: is a link to the real volume
        c.files.push_back({name, expectDeny, absolute, std::wstring(kFilesDir) + L"\\" + name, L"\\??\\" + absolute});
    }

    // Start barrier
    HANDLE start = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::vector<Worker> workers(c.threads);
    std::vector<std::thread> threads;
    for (Worker& w : workers) threads.emplace_back(RunWorker, std::ref(w), std::cref(c), start);
    SetEvent(start);

    if (c.untilStop) {
        char line[32];
        while (fgets(line, sizeof(line), stdin)) {
            unsigned k = 0;
            if (sscanf_s(line, "on %u", &k) == 1) {
                g_window = k;
            } else if (!strncmp(line, "off", 3)) {
                g_window = 0;
                puts("off");
                fflush(stdout);
            } else {
                break;
            }
        }
        g_stop = true;
    }
    for (std::thread& t : threads) t.join();
    CloseHandle(start);

    FILE* out = nullptr;
    if (c.untilStop) {
        // The probe: one more round from the main thread, after the last ejection
        Worker probe;
        probe.tid = GetCurrentThreadId();
        probe.counts.assign(c.files.size() * kWayCount, {});
        uint32_t seq = 0;
        Round(probe, c, seq);
        CloseHandle(c.folder);

        _wfopen_s(&out, L"counts.csv", L"w");
        fprintf(out, "phase,tid,api,form,file,expected,allow,deny,error,last_error_changed,in_allow,in_deny,in_error\n");
        for (const Worker& w : workers) PrintCounts(out, "worker", w, c);
        PrintCounts(out, "probe", probe, c);
        fclose(out);

        _wfopen_s(&out, L"denied.csv", L"w");
        fprintf(out, "tid,seq,window,api,form,file,expected,observed,status,last_error\n");
        for (const Worker& w : workers) PrintJournal(out, w, c, true);
        PrintJournal(out, probe, c, true);
    } else {
        CloseHandle(c.folder);

        _wfopen_s(&out, L"journal.csv", L"w");
        fprintf(out, "tid,seq,api,form,file,expected,observed,status,last_error\n");
        for (const Worker& w : workers) PrintJournal(out, w, c, false);
    }
    fclose(out);

    // The hook DLL's logger is asynchronous and is not flushed when the process exits (_dllmain.cpp does nothing at
    // DLL_PROCESS_DETACH): this pause lets it write the last deny events, as E5's kLogDrainMs.
    Sleep(c.drainMs);
    return 0;
}
