// target: one instance of a program that keeps a counter in HKCU\Software\HookDesignerGuardrail\Shared.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>

static const wchar_t kSharedKey[] = L"Software\\HookDesignerGuardrail\\Shared";
static const wchar_t kCounterValue[] = L"Counter";
static const DWORD kStartTimeoutMs = 60000;

// Release the ready semaphore, then wait for the start event
static bool WaitForStart(const wchar_t* readyName, const wchar_t* startName) {
    HANDLE ready = OpenSemaphoreW(SEMAPHORE_MODIFY_STATE, FALSE, readyName);
    HANDLE start = OpenEventW(SYNCHRONIZE, FALSE, startName);
    bool ok = ready && start && ReleaseSemaphore(ready, 1, nullptr) &&
              WaitForSingleObject(start, kStartTimeoutMs) == WAIT_OBJECT_0;
    if (ready) CloseHandle(ready);
    if (start) CloseHandle(start);
    return ok;
}

int wmain(int argc, wchar_t* argv[]) {
    unsigned long cycles = 0;
    const wchar_t* readyName = nullptr;
    const wchar_t* startName = nullptr;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!wcscmp(argv[i], L"--cycles")) cycles = wcstoul(argv[i + 1], nullptr, 10);
        else if (!wcscmp(argv[i], L"--ready")) readyName = argv[i + 1];
        else if (!wcscmp(argv[i], L"--start")) startName = argv[i + 1];
    }
    if (cycles == 0 || (readyName == nullptr) != (startName == nullptr)) {
        fwprintf(stderr, L"usage: guardrail_target.exe --cycles N [--ready <semaphore> --start <event>]\n");
        return 2;
    }

    HKEY key = nullptr;
    LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER, kSharedKey, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
    if (status != ERROR_SUCCESS) {
        fwprintf(stderr, L"RegOpenKeyExW failed: %ld\n", status);
        return 3;
    }

    if (readyName && !WaitForStart(readyName, startName)) {
        fwprintf(stderr, L"start synchronization failed: %lu\n", GetLastError());
        RegCloseKey(key);
        return 4;
    }

    DWORD lastWritten = 0;
    int errors = 0;
    for (int i = 0; i < cycles; ++i) {
        DWORD value = 0, size = sizeof(value), type = 0;
        if (RegQueryValueExW(key, kCounterValue, nullptr, &type, (BYTE*)&value, &size) != ERROR_SUCCESS || type != REG_DWORD) {
            ++errors;
            value = 0;
        }
        ++value;
        if (RegSetValueExW(key, kCounterValue, 0, REG_DWORD, (const BYTE*)&value, sizeof(value)) == ERROR_SUCCESS)
            lastWritten = value;
        else
            ++errors;
    }
    RegCloseKey(key);

    FILE* out = nullptr;
    if (fopen_s(&out, "result.json", "w") != 0 || !out) return 5;
    fprintf(out, "{\"pid\": %lu, \"cycles\": %lu, \"last_written\": %lu, \"errors\": %lu}\n",
            GetCurrentProcessId(), cycles, lastWritten, errors);
    fclose(out);
    return 0;
}
