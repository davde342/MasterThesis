{% set need_active_counter = (engine == 'detours') or has_noreturn %}

static DWORD g_TlsIndex = TLS_OUT_OF_INDEXES;

// RAII helper to prevent recursive hook execution on the same thread
struct RecursionHookGuard {
    bool active;
    RecursionHookGuard() : active(true) { TlsSetValue(g_TlsIndex, (LPVOID)1); }
    ~RecursionHookGuard() { if (active) TlsSetValue(g_TlsIndex, (LPVOID)0); }
    void Release() {
        if (active) {
            TlsSetValue(g_TlsIndex, (LPVOID)0);
            active = false;
        }
    }
};

{% if need_active_counter %}
static std::atomic<int> g_ActiveHooks{0};

// RAII helper to track active hook execution count
struct HookActiveThreads {
    bool active;
    HookActiveThreads() : active(true) { g_ActiveHooks++; }
    ~HookActiveThreads() { if (active) g_ActiveHooks--; }
    void Release() {
        if (active) {
            g_ActiveHooks--;
            active = false;
        }
    }
};
{% endif %}

#include "{{ logic_file_rel }}"

// Copy string safely using SIMD strnlen (memory violations will be caught by outer /EHa catch(...))
static std::string CopyString(const char* source, size_t maxChars = 128) {
    if (!source) {
        return "null";
    }
    size_t len = strnlen(source, maxChars);
    return std::string(source, len);
}

// Dereference pointer safely (memory violations will be caught by outer catch(...))
template <typename T>
static T ReadPointer(const T* ptr, T fallback = T()) {
    if (!ptr) {
        return fallback;
    }
    return *ptr;
}

// Enlist all thread handles to suspend/resume during transaction operations
static std::vector<HANDLE> EnlistAllThreads() {
    std::vector<HANDLE> threadHandles;
    DWORD currentProcessId = GetCurrentProcessId();
    DWORD currentThreadId = GetCurrentThreadId();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return threadHandles;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == currentProcessId && te.th32ThreadID != currentThreadId) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    threadHandles.push_back(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    return threadHandles;
}
