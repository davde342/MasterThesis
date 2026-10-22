static DWORD g_TlsIndex = TLS_OUT_OF_INDEXES;

// RAII helper to prevent recursive hook execution on the same thread
struct RecursionHookGuard {
    bool active;
    RecursionHookGuard() : active(false) { Acquire(); }
    ~RecursionHookGuard() { Release(); }
    void Acquire() {
        if (!active) {
            TlsSetValue(g_TlsIndex, (LPVOID)1);
            active = true;
        }
    }
    void Release() {
        if (active) {
            TlsSetValue(g_TlsIndex, (LPVOID)0);
            active = false;
        }
    }
};

#include <cerrno>

// RAII helper to preserve Windows system error codes (GetLastError) and CRT errno
struct SystemErrorGuard {
    DWORD win32_error;
    int crt_errno; //we need to handle errno in case the DLL is built with --rt-link /MD 

    SystemErrorGuard() : win32_error(GetLastError()), crt_errno(errno) {}
    ~SystemErrorGuard() {
        SetLastError(win32_error);
        errno = crt_errno;
    }
    void Capture() {
        win32_error = GetLastError();
        crt_errno = errno;
    }
    void Restore() const {
        SetLastError(win32_error);
        errno = crt_errno;
    }
};

static std::atomic<int> activeThreads{0};

// RAII helper to track active hook execution count
struct HookActiveThreads {
    bool active;
    HookActiveThreads() : active(true) { activeThreads++; }
    ~HookActiveThreads() { if (active) activeThreads--; }
    void Release() {
        if (active) {
            activeThreads--;
            active = false;
        }
    }
};

// Safe-read helpers are defined before the user logic file is included so that its helpers and
// pre/post hook bodies can call them.

// Copy string safely using SIMD strnlen (memory violations will be caught by outer /EHa catch(...))
static std::string CopyString(const char* source, size_t maxChars = 512) {
    if (!source) {
        return "null";
    }
    size_t len = strnlen(source, maxChars);
    return std::string(source, len);
}

// CopyString overload that copy wide string safely and convert to UTF-8 std::string
static std::string CopyString(const wchar_t* source, size_t maxChars = 512) {
    if (!source) return "null";
    size_t len = wcsnlen(source, maxChars);
    if (len == 0) return std::string();
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, source, (int)len, NULL, 0, NULL, NULL);
    if (sizeNeeded <= 0) return std::string();
    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, source, (int)len, &result[0], sizeNeeded, NULL, NULL);
    return result;
}

// Copy a counted NT string (UNICODE_STRING layout: USHORT Length, USHORT MaximumLength, PWSTR Buffer).
// Buffer is NOT NUL-terminated, so the length is taken from Length (bytes), never from wcsnlen.
// Templated on the struct so this header does not depend on <winternl.h>. The transpiler emits calls
// to it automatically for PUNICODE_STRING / PCUNICODE_STRING parameters (see analyze_type).
// Memory violations are caught by the outer /EHa catch(...).
template <typename TUnicodeString>
static std::string CopyUnicodeString(const TUnicodeString* source, size_t maxChars = 512) {
    if (!source) return "null";
    const wchar_t* buffer = source->Buffer;
    size_t len = source->Length / sizeof(wchar_t);
    if (!buffer || len == 0) return std::string();
    if (len > maxChars) len = maxChars;
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, buffer, (int)len, NULL, 0, NULL, NULL);
    if (sizeNeeded <= 0) return std::string();
    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, buffer, (int)len, &result[0], sizeNeeded, NULL, NULL);
    return result;
}

// Dereference pointer safely (memory violations will be caught by outer catch(...))
template <typename T>
static T ReadPointer(const T* ptr, T fallback = T()) {
    if (!ptr) {
        return fallback;
    }
    return *ptr;
}

#include "{{ logic_file_rel }}"
