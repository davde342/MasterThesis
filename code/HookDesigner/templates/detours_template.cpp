#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <detours.h>
#include <tlhelp32.h>
#include <iostream>
#include "spdlog/fmt/fmt.h"
#include <mutex>
#include <atomic>
#include <vector>
#include <string>

{% if telemetry %}
{% include "_telemetry_globals.cpp" %}
{% endif %}
#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:DetourFinishHelperProcess=_DetourFinishHelperProcess@16,@1,NONAME")
#else 
#pragma comment(linker, "/EXPORT:DetourFinishHelperProcess=DetourFinishHelperProcess,@1,NONAME")
#endif

// Global synchronizations
static bool g_HooksAttached = false;
static bool g_Ejected = false;

{% include "_user_logic_helpers.cpp" %}

// Target functions typedefs and pointers
{% for hook in hooks %}
typedef {{ hook.return_type }} ({% if hook.calling_convention %}{{ hook.calling_convention }} {% endif %}*True{{ hook.function_name }}_t)({%- for param in hook.parameters -%}{{ param.type }} {{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
static True{{ hook.function_name }}_t True{{ hook.function_name }} = nullptr;
{% endfor %}

// Hook Implementations
{% for hook in hooks %}
{{ hook.return_type }} {% if hook.calling_convention %}{{ hook.calling_convention }} {% endif %}Hooked{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.type }} {{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%}) {
    if (TlsGetValue(g_TlsIndex) != 0) {
        {% if hook.return_type == 'void' %}
        True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
        return;
        {% else %}
        return True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
        {% endif %}
    }

    RecursionHookGuard hook_recursion_guard;
    HookActiveThreads hook_active_threads;
    {% include "_hook_body.cpp" %}
}
{% endfor %}



// Attach / Detach Transactions
extern "C" __declspec(dllexport) void InitializeHooks() {
    g_TlsIndex = TlsAlloc();
    {% if telemetry %}
    {% include "_telemetry_init.cpp" %}
    {% endif %}
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
        OutputDebugStringA("[WARNING] Failed to resolve target function: '{{ hook.function_name }}' (check if module is loaded or function is exported)\n");
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
        g_Ejected = false;
        std::string msg = fmt::format("[HOOK] Detours hooks successfully attached. Suspended/resumed {} worker threads.\n", threads.size());
        OutputDebugStringA(msg.c_str());
    } else {
        std::string msg = fmt::format("[CRITICAL] DetourTransactionCommit failed. Error code: {}\n", error);
        OutputDebugStringA(msg.c_str());
    }
}

extern "C" __declspec(dllexport) BOOL DeinitializeHooks() {
    if (g_Ejected) return TRUE;

    if (g_HooksAttached) {
        // 1. Stop background HTTP server thread first so Civetweb worker thread exits select()
        {% if telemetry and telemetry.metrics == "prometheus" %}
        g_PromExposer.reset();
        {% endif %}

        std::vector<HANDLE> threads = EnlistAllThreads();

        // 2. Detach API hooks so no new threads enter telemetry logic
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

        if (error != NO_ERROR) {
            std::string msg = fmt::format("[CRITICAL] DetourTransactionCommit failed on detach. Error code: {}\n", error);
            OutputDebugStringA(msg.c_str());
            return FALSE;
        }

        g_HooksAttached = false; // Hooks are now detached/reverted
    }

    // 3. Spin-wait safety loop for active threads inside hooks with a 2-second timeout
    DWORD start = GetTickCount();
    while (GetTickCount() - start < 2000) {
        if (activeThreads.load() == 0) {
            Sleep(1000);
            if (activeThreads.load() == 0) {
                g_Ejected = true;
                break;
            }
        }
        Sleep(50);
    }
    
    if (g_Ejected) {
        // 4. Destroy metrics & loggers AFTER flush confirms zero threads are inside hook bodies
        {% if telemetry and telemetry.metrics == "prometheus" %}
        g_PromRegistry.reset();
        {% endif %}
        {% if telemetry and telemetry.logger == "spdlog" %}
        spdlog::shutdown();
        {% endif %}

        if (g_TlsIndex != TLS_OUT_OF_INDEXES) {
            TlsFree(g_TlsIndex);
            g_TlsIndex = TLS_OUT_OF_INDEXES;
        }

        OutputDebugStringA("[HOOK] Detours hooks successfully detached and all active threads ejected.\n");
    } else {
        OutputDebugStringA("[WARNING] Detours hooks successfully detached, but some threads remain blocked inside them. Leaking DLL.\n");
    }

    return g_Ejected;
}

{% include "_dllmain.cpp" %}
