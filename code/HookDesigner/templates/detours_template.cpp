#include <windows.h>
#include <detours.h>
#include <tlhelp32.h>
#include <iostream>
#include <sstream>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:DetourFinishHelperProcess=_DetourFinishHelperProcess@16,@1,NONAME")
#else 
#pragma comment(linker, "/EXPORT:DetourFinishHelperProcess=DetourFinishHelperProcess,@1,NONAME")
#endif

// Global synchronizations
static std::atomic<int> g_ActiveHooks{0};
static bool g_HooksAttached = false;
static LARGE_INTEGER g_PerfFrequency = {0};

// RAII helper to track active hook execution count
struct HookGuard {
    HookGuard() { g_ActiveHooks++; }
    ~HookGuard() { g_ActiveHooks--; }
};

{% include "_user_logic_helpers.cpp" %}

// Target functions typedefs and pointers
{% for hook in hooks %}
typedef {{ hook.return_type }} ({% if hook.calling_convention %}{{ hook.calling_convention }} {% endif %}*True{{ hook.function_name }}_t)({%- for param in hook.parameters -%}{{ param.type }} {{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
static True{{ hook.function_name }}_t True{{ hook.function_name }} = nullptr;
{% endfor %}

// Enlist all thread handles to suspend/resume in Detours transaction
std::vector<HANDLE> EnlistAllThreads() {
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

// Hook Implementations
{% for hook in hooks %}
{{ hook.return_type }} {% if hook.calling_convention %}{{ hook.calling_convention }} {% endif %}Hooked{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.type }} {{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%}) {
    HookGuard guard;
    {% include "_hook_body.cpp" %}
}
{% endfor %}



// Attach / Detach Transactions
extern "C" __declspec(dllexport) void InitializeHooks() {
    QueryPerformanceFrequency(&g_PerfFrequency);
    {% for hook in hooks %}
    {% if hook.module %}
    {
        HMODULE hMod = GetModuleHandleA("{{ hook.module }}");
        if (hMod) {
            True{{ hook.function_name }} = {{ hook.address_resolution_cpp }};
        } else {
            True{{ hook.function_name }} = nullptr;
        }
    }
    {% else %}
    True{{ hook.function_name }} = {{ hook.address_resolution_cpp }};
    {% endif %}
    if (!True{{ hook.function_name }}) {
        std::cerr << "[WARNING] Failed to resolve target function: '{{ hook.function_name }}' (check if module is loaded or function is exported)" << std::endl;
    }
    {% endfor %}


    std::vector<HANDLE> threads = EnlistAllThreads();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for (HANDLE hThread : threads) {
        DetourUpdateThread(hThread);
    }

    {% for hook in hooks %}
    if (True{{ hook.function_name }}) {
        DetourAttach(&(PVOID&)True{{ hook.function_name }}, (PVOID)Hooked{{ hook.function_name }});
    }
    {% endfor %}


    LONG error = DetourTransactionCommit();

    for (HANDLE hThread : threads) {
        CloseHandle(hThread);
    }

    if (error == NO_ERROR) {
        g_HooksAttached = true;
        std::ostringstream ss;
        ss << "[HOOK] Detours hooks successfully attached. Suspended/resumed " << threads.size() << " worker threads." << std::endl;
        std::cout << ss.str();
    } else {
        std::ostringstream ss;
        ss << "[CRITICAL] DetourTransactionCommit failed. Error code: " << error << std::endl;
        std::cerr << ss.str();
    }
}

extern "C" __declspec(dllexport) void DeinitializeHooks() {
    if (!g_HooksAttached) return;

    std::vector<HANDLE> threads = EnlistAllThreads();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for (HANDLE hThread : threads) {
        DetourUpdateThread(hThread);
    }

    {% for hook in hooks %}
    if (True{{ hook.function_name }}) {
        DetourDetach(&(PVOID&)True{{ hook.function_name }}, (PVOID)Hooked{{ hook.function_name }});
    }
    {% endfor %}



    LONG error = DetourTransactionCommit();

    for (HANDLE hThread : threads) {
        CloseHandle(hThread);
    }

    if (error == NO_ERROR) {
        g_HooksAttached = false;
        
        // Spin-wait safety loop for active threads inside hooks
        while (true) {
            while (g_ActiveHooks.load() > 0) {
                SwitchToThread();
            }
            Sleep(1000); 
            if (g_ActiveHooks.load() == 0) {
                break;
            }
        }
        
        std::ostringstream ss;
        ss << "[HOOK] Detours hooks successfully detached." << std::endl;
        std::cout << ss.str();
    } else {
        std::ostringstream ss;
        ss << "[CRITICAL] DetourTransactionCommit failed on detach. Error code: " << error << std::endl;
        std::cerr << ss.str();
    }
}

{% include "_dllmain.cpp" %}
