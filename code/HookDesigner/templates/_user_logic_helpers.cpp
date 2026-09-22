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

#include "{{ logic_file_rel }}"

// Copy string safely using SIMD strnlen (memory violations will be caught by outer /EHa catch(...))
static std::string CopyString(const char* source, size_t maxChars = 128) {
    if (!source) {
        return "null";
    }
    size_t len = strnlen(source, maxChars);
    return std::string(source, len);
}

// CopyString overload that copy wide string safely and convert to UTF-8 std::string
static std::string CopyString(const wchar_t* source, size_t maxChars = 128) {
    if (!source) return "null";
    size_t len = wcsnlen(source, maxChars);
    if (len == 0) return std::string();
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, source, (int)len, NULL, 0, NULL, NULL);
    if (sizeNeeded <= 0) return std::string();
    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, source, (int)len, &result[0], sizeNeeded, NULL, NULL);
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
