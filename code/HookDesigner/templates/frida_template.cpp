#include "frida-gum.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include "spdlog/fmt/fmt.h"
#if defined(SPDLOG_FMT_EXTERNAL)
#include <fmt/compile.h>
#else
#include "spdlog/fmt/bundled/compile.h"
#endif
#include <mutex>
#include <atomic>
#include <vector>
#include <string>
#include <stdexcept>

{% set has_noreturn = hooks | selectattr('is_noreturn') | list | length > 0 %}

{% if telemetry %}
{% include "_telemetry_globals.cpp" %}
{% endif %}

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:InitializeHooks=_InitializeHooks@4")
#pragma comment(linker, "/EXPORT:DeinitializeHooks=_DeinitializeHooks@4")
#endif

// Global synchronizations
static bool g_HooksAttached = false;
static bool g_Ejected = false;
static GumInterceptor* interceptor = nullptr;
{% if has_execution_time %}
static LARGE_INTEGER g_PerfFrequency = {0};
{% endif %}

{% include "_user_logic_helpers.cpp" %}

// Target functions typedefs, pointers, and entry points
{% for hook in hooks %}
typedef {{ hook.return_type }} ({% if hook.calling_convention %}{{ hook.calling_convention }} {% endif %}*True{{ hook.function_name }}_t)({%- for param in hook.parameters -%}{{ param.type }} {{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
static True{{ hook.function_name }}_t True{{ hook.function_name }} = nullptr;
static gpointer target_{{ hook.function_name }} = nullptr;
{% endfor %}

// Hook Implementations
{% for hook in hooks %}
{{ hook.return_type }} {% if hook.calling_convention %}{{ hook.calling_convention }} {% endif %}Hooked{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.type }} {{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%}) {
    // Re-entrant call: checked before SystemErrorGuard, so no destructor overwrites the error state of True<Fn>
    if (t_InHook) {
        {% if hook.return_type == 'void' %}
        True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
        return;
        {% else %}
        return True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
        {% endif %}
    }

    SystemErrorGuard system_error_guard;
    ReEntrancyHookGuard hook_reEntrancy_guard;
    {% if hook.is_noreturn %}
    HookActiveThreads hook_active_threads;
    {% endif %}
    {% include "_hook_body.cpp" %}
}
{% endfor %}



// Attach / Detach Transactions
extern "C" __declspec(dllexport) DWORD WINAPI InitializeHooks(LPVOID lpParam) {
    bool in_transaction = false;

    try {
        if (g_HooksAttached) return 0;
        {% if has_execution_time %}
        QueryPerformanceFrequency(&g_PerfFrequency);
        {% endif %}
        {% if telemetry %}
        {% include "_telemetry_init.cpp" %}
        {% endif %}
        gum_init_embedded();
        interceptor = gum_interceptor_obtain();

        {% for hook in hooks %}
        {% if hook.module %}
        {
            HMODULE hMod = GetModuleHandleA("{{ hook.module }}");
            if (hMod) {
                target_{{ hook.function_name }} = {{ hook.address_resolution_cpp }};
            } else {
                target_{{ hook.function_name }} = nullptr;
            }
        }
        {% else %}
        target_{{ hook.function_name }} = {{ hook.address_resolution_cpp }};
        {% endif %}
        if (!target_{{ hook.function_name }}) {
            std::string msg = fmt::format("[WARNING] Failed to resolve target function: '{}' (check if module is loaded or function is exported)\n", "{{ hook.function_name }}");
            OutputDebugStringA(msg.c_str());
        }
        {% endfor %}

        gum_interceptor_begin_transaction(interceptor);
        in_transaction = true;

        {% for hook in hooks %}
        if (target_{{ hook.function_name }}) {
            {% if hook.is_noreturn %}
            GumReplaceReturn r = gum_interceptor_replace_fast(interceptor,
                                    target_{{ hook.function_name }},
                                    (gpointer)Hooked{{ hook.function_name }},
                                    (gpointer*)&True{{ hook.function_name }});
            {% else %}
            GumReplaceReturn r = gum_interceptor_replace(interceptor,
                                    target_{{ hook.function_name }},
                                    (gpointer)Hooked{{ hook.function_name }},
                                    nullptr,
                                    (gpointer*)&True{{ hook.function_name }});
            {% endif %}
            // Gum reports failures only through the return code; throwing routes them into the catch rollback.
            if (r != GUM_REPLACE_OK) {
                throw std::runtime_error(fmt::format("Frida failed to replace function '{}'. Error code: {}", "{{ hook.function_name }}", (int)r));
            }
        }
        {% endfor %}

        gum_interceptor_end_transaction(interceptor);
        in_transaction = false;

        g_HooksAttached = true;
        g_Ejected = false;
        OutputDebugStringA("[HOOK] Frida-Gum hooks successfully attached.\n");
        return 0; // Success
    }
    catch (const std::exception& ex) {
        if (in_transaction && interceptor) {
            // True<Fn> is set only by a successful replace, so this reverts exactly the staged hooks
            {% for hook in hooks %}
            if (True{{ hook.function_name }}) {
                gum_interceptor_revert(interceptor, target_{{ hook.function_name }});
            }
            {% endfor %}
            gum_interceptor_end_transaction(interceptor);
        }
        if (interceptor) {
            g_object_unref(interceptor);
            interceptor = nullptr;
            gum_deinit_embedded();
        }
        {% if telemetry and telemetry.metrics == "prometheus" %}
        g_PromExposer.reset();
        g_PromRegistry.reset();
        {% endif %}
        {% if telemetry and telemetry.logger == "spdlog" %}
        spdlog::shutdown();
        {% endif %}
        // Stack buffer: a heap allocation could throw std::bad_alloc out of the catch block
        char msg[256];
        *fmt::format_to_n(msg, sizeof(msg) - 1, "[CRITICAL] Exception in InitializeHooks: {}\n", ex.what()).out = '\0';
        OutputDebugStringA(msg);
        return 0xE0000002;
    }
    catch (...) {
        // No revert/end_transaction: a fault inside replace leaves its nested transaction open, so nothing can commit,
        // and gum_deinit_embedded discards the staged hooks without writing them.
        if (interceptor) {
            g_object_unref(interceptor);
            interceptor = nullptr;
            gum_deinit_embedded();
        }
        {% if telemetry and telemetry.metrics == "prometheus" %}
        g_PromExposer.reset();
        g_PromRegistry.reset();
        {% endif %}
        {% if telemetry and telemetry.logger == "spdlog" %}
        spdlog::shutdown();
        {% endif %}
        OutputDebugStringA("[CRITICAL] SEH/Hardware fault in InitializeHooks\n");
        return 0xE0000003;
    }
}



extern "C" __declspec(dllexport) DWORD WINAPI DeinitializeHooks(LPVOID lpParam) {
    

    try {
        if (g_Ejected || !interceptor) return 0;

        if (g_HooksAttached) {
            // 1. Stop background HTTP server thread first so Civetweb worker thread exits select()
            {% if telemetry and telemetry.metrics == "prometheus" %}
            g_PromExposer.reset();
            {% endif %}

            // 2. Revert hooks so no new API calls enter telemetry logic
            gum_interceptor_begin_transaction(interceptor);
            

            {% for hook in hooks %}
            if (target_{{ hook.function_name }} != nullptr) {
                gum_interceptor_revert(interceptor, target_{{ hook.function_name }});
            }
            {% endfor %}

            gum_interceptor_end_transaction(interceptor);

            g_HooksAttached = false; // Hooks are now detached/reverted
        }

        // 3. Spin-wait flush loop until all in-flight application threads exit hook code
        DWORD start = GetTickCount();
        while (GetTickCount() - start < 2000) {
            {% if has_noreturn %}
            if (gum_interceptor_flush(interceptor) && activeThreads.load() == 0) {
                Sleep(1000);
                if (activeThreads.load() == 0) {
                    g_Ejected = true;
                    break;
                }
            }
            {% else %}
            if (gum_interceptor_flush(interceptor)) {
                g_Ejected = true;
                break;
            }
            {% endif %}
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

            if (interceptor) {
                g_object_unref(interceptor);
                interceptor = nullptr;
                gum_deinit_embedded();
            }

            OutputDebugStringA("[HOOK] Frida-Gum hooks successfully detached and all active threads ejected.\n");
            return 0; // Success
        } else {
            OutputDebugStringA("[WARNING] Frida-Gum hooks successfully detached, but some threads remain blocked inside them. Leaking DLL.\n");
            return 1; // Leaked DLL warning
        }
    }
    // Normally revert never reads target memory.
    // It only updates Gum's own tables: it clears
    //replacement_function, removes the context from function_by_address and
    //schedules the deactivation
    catch (const std::exception& ex) {
        char msg[256];
        *fmt::format_to_n(msg, sizeof(msg) - 1, "[CRITICAL] Exception in DeinitializeHooks: {}\n", ex.what()).out = '\0';
        OutputDebugStringA(msg);
        return 0xE0000002;
    }
    catch (...) {
        OutputDebugStringA("[CRITICAL] SEH/Hardware fault in DeinitializeHooks\n");
        return 0xE0000003;
    }
}

{% include "_dllmain.cpp" %}
