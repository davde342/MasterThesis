#include "frida-gum.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include "spdlog/fmt/fmt.h"
#include <mutex>
#include <atomic>
#include <vector>
#include <string>

{% set has_noreturn = hooks | selectattr('is_noreturn') | list | length > 0 %}

{% if telemetry %}
{% include "_telemetry_globals.cpp" %}
{% endif %}

// Global synchronizations
static bool g_HooksAttached = false;
static bool g_Ejected = false;
static GumInterceptor* interceptor = nullptr;

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
    if (TlsGetValue(g_TlsIndex) != 0) {
        {% if hook.return_type == 'void' %}
        True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
        return;
        {% else %}
        return True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
        {% endif %}
    }

    RecursionHookGuard hook_recursion_guard;
    {% if hook.is_noreturn %}
    HookActiveThreads hook_active_threads;
    {% endif %}
    {% include "_hook_body.cpp" %}
}
{% endfor %}



// Attach / Detach Transactions
extern "C" __declspec(dllexport) void InitializeHooks() {
    g_TlsIndex = TlsAlloc();
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
        if (r != GUM_REPLACE_OK) {
            std::string msg = fmt::format("[CRITICAL] Frida failed to replace function '{}'. Error code: {}\n", "{{ hook.function_name }}", (int)r);
            OutputDebugStringA(msg.c_str());
        }
    }
    {% endfor %}


    gum_interceptor_end_transaction(interceptor);

    g_HooksAttached = true;
    g_Ejected = false;
    OutputDebugStringA("[HOOK] Frida-Gum hooks successfully attached.\n");
}



extern "C" __declspec(dllexport) BOOL DeinitializeHooks() {
    if (g_Ejected) return TRUE;

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

        g_object_unref(interceptor);
        gum_deinit_embedded();

        if (g_TlsIndex != TLS_OUT_OF_INDEXES) {
            TlsFree(g_TlsIndex);
            g_TlsIndex = TLS_OUT_OF_INDEXES;
        }

        OutputDebugStringA("[HOOK] Frida-Gum hooks successfully detached and all active threads ejected.\n");
    } else {
        OutputDebugStringA("[WARNING] Frida-Gum hooks successfully detached, but some threads remain blocked inside them. Leaking DLL.\n");
    }

    return g_Ejected;
}

{% include "_dllmain.cpp" %}
