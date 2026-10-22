// target: opens a set of test files through five APIs and two path forms, and journals each open.


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>   // NtCreateFile, NtOpenFile, RtlInitUnicodeString, InitializeObjectAttributes, FILE_OPEN, ...

#include <cerrno>
#include <cstdio>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)


static const wchar_t kFilesDir[] = L"files";
// The hook DLL's logger is asynchronous and is not flushed when the process exits: this pause lets it write the
// last deny events before exit, so a missing event can only mean a missing deny, not a lost log line.
static const DWORD kLogDrainMs = 500;

struct Row {
    const char* api;
    const char* form;
    std::wstring file;
    bool expectDeny;
    const char* observed;
    std::string status;
};

struct Attempt {
    const char* observed;
    std::string status;
};

static const char* Verdict(bool opened, bool accessDenied) {
    return opened ? "allow" : accessDenied ? "deny" : "error";
}

static Attempt OpenCreateFileW(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD error = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return {Verdict(error == ERROR_SUCCESS, error == ERROR_ACCESS_DENIED), std::to_string(error)};
}

static Attempt OpenWfopen(const std::wstring& path) {
    FILE* file = nullptr;
    const errno_t error = _wfopen_s(&file, path.c_str(), L"rb");
    if (file) fclose(file);
    return {Verdict(error == 0, error == EACCES), std::to_string(error)};
}

static Attempt OpenIfstream(const std::wstring& path) {
    errno = 0;
    std::ifstream file(std::filesystem::path(path), std::ios::binary);
    const int error = file.is_open() ? 0 : errno;  // set by the CRT open underneath (MSVC)
    return {Verdict(error == 0, error == EACCES), std::to_string(error)};
}

// NtCreateFile (FILE_OPEN) or NtOpenFile of `name`, relative to `root` when it is not null
static Attempt OpenNative(bool useCreate, HANDLE root, const std::wstring& name) {
    UNICODE_STRING objectName;
    RtlInitUnicodeString(&objectName, name.c_str());
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &objectName, OBJ_CASE_INSENSITIVE, root, nullptr);
    IO_STATUS_BLOCK io = {};
    HANDLE file = nullptr;
    const ULONG options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE;
    const NTSTATUS status = useCreate
        ? NtCreateFile(&file, FILE_GENERIC_READ, &attributes, &io, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, options, nullptr, 0)
        : NtOpenFile(&file, FILE_GENERIC_READ, &attributes, &io, FILE_SHARE_READ, options);
    if (status >= 0) NtClose(file);
    char hex[16];
    snprintf(hex, sizeof(hex), "0x%08lx", (unsigned long)status);
    return {Verdict(status >= 0, status == STATUS_ACCESS_DENIED), hex};
}

int wmain(int argc, wchar_t* argv[]) {
    std::vector<std::pair<std::wstring, bool>> files;  // name, deny expected
    bool badArgs = argc < 3 || argc % 2 == 0;
    for (int i = 1; !badArgs && i + 1 < argc; i += 2) {
        if (!wcscmp(argv[i], L"--expect-allow")) files.push_back({argv[i + 1], false});
        else if (!wcscmp(argv[i], L"--expect-deny")) files.push_back({argv[i + 1], true});
        else badArgs = true;
    }
    if (badArgs) {
        fwprintf(stderr, L"usage: filedeny_target.exe (--expect-allow <file> | --expect-deny <file>)...\n");
        return 2;
    }

    wchar_t folder[MAX_PATH];
    const DWORD length = GetFullPathNameW(kFilesDir, MAX_PATH, folder, nullptr);
    HANDLE folderHandle = CreateFileW(kFilesDir, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (length == 0 || length >= MAX_PATH || folderHandle == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"files folder not usable: %lu\n", GetLastError());
        return 3;
    }

    std::vector<Row> rows;
    for (const auto& [name, expectDeny] : files) {
        const std::wstring absolute = std::wstring(folder) + L"\\" + name;
        const std::wstring relative = std::wstring(kFilesDir) + L"\\" + name;
        //\??\ is the directory of DOS device names,
        // where C: is a link to the real volume
        const std::wstring ntAbsolute = L"\\??\\" + absolute;
        const struct {
            const char* api;
            const char* form;
            Attempt attempt;
        } attempts[] = {
            {"CreateFileW", "absolute", OpenCreateFileW(absolute)},
            {"CreateFileW", "relative", OpenCreateFileW(relative)},
            {"_wfopen", "absolute", OpenWfopen(absolute)},
            {"_wfopen", "relative", OpenWfopen(relative)},
            {"ifstream", "absolute", OpenIfstream(absolute)},
            {"ifstream", "relative", OpenIfstream(relative)},
            {"NtCreateFile", "absolute", OpenNative(true, nullptr, ntAbsolute)},
            {"NtCreateFile", "relative", OpenNative(true, folderHandle, name)},
            {"NtOpenFile", "absolute", OpenNative(false, nullptr, ntAbsolute)},
            {"NtOpenFile", "relative", OpenNative(false, folderHandle, name)},
        };
        for (const auto& a : attempts)
            rows.push_back({a.api, a.form, name, expectDeny, a.attempt.observed, a.attempt.status});
    }
    CloseHandle(folderHandle);

    FILE* out = nullptr;
    if (_wfopen_s(&out, L" results.csv", L"w") != 0 || !out) return 5;
    fprintf(out, "api,form,file,expected,observed,status\n");
    for (const Row& r : rows)
        fprintf(out, "%s,%s,%ls,%s,%s,%s\n", r.api, r.form, r.file.c_str(), r.expectDeny ? "deny" : "allow", r.observed, r.status.c_str());
    fclose(out);

    Sleep(kLogDrainMs);
    return 0;
}
