#include "frida-gum.h"
#include <windows.h>
#include <iostream>
#include <sstream>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>


static bool g_HooksAttached = false;
static GumInterceptor* interceptor = nullptr;
static LARGE_INTEGER g_PerfFrequency = {0};

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
    {% include "_hook_body.cpp" %}
}
{% endfor %}



// Attach / Detach Transactions
extern "C" __declspec(dllexport) void InitializeHooks() {
    QueryPerformanceFrequency(&g_PerfFrequency);
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
        std::cerr << "[WARNING] Failed to resolve target function: '{{ hook.function_name }}' (check if module is loaded or function is exported)" << std::endl;
    }
    {% endfor %}


    gum_interceptor_begin_transaction(interceptor);

    {% for hook in hooks %}
    if (target_{{ hook.function_name }}) {
        GumReplaceReturn r = gum_interceptor_replace(interceptor,
                                target_{{ hook.function_name }},
                                (gpointer)Hooked{{ hook.function_name }},
                                nullptr,
                                (gpointer*)&True{{ hook.function_name }});
        if (r != GUM_REPLACE_OK) {
            std::cerr << "[CRITICAL] Frida failed to replace function '{{ hook.function_name }}'. Error code: " << r << std::endl;
        }
    }
    {% endfor %}


    gum_interceptor_end_transaction(interceptor);

    g_HooksAttached = true;
    std::ostringstream ss;
    ss << "[HOOK] Frida-Gum hooks successfully attached." << std::endl;
    std::cout << ss.str();
}

extern "C" __declspec(dllexport) void DeinitializeHooks() {
    if (!g_HooksAttached) return;

    gum_interceptor_begin_transaction(interceptor);
    {% for hook in hooks %}
    if (target_{{ hook.function_name }} != nullptr) {
        gum_interceptor_revert(interceptor, target_{{ hook.function_name }});
    }
    {% endfor %}


    gum_interceptor_end_transaction(interceptor);

    while (!gum_interceptor_flush(interceptor)) {
        SwitchToThread ();
    }

    g_object_unref(interceptor);
    gum_deinit_embedded();
    g_HooksAttached = false;

    std::ostringstream ss;
    ss << "[HOOK] Frida-Gum hooks successfully detached." << std::endl;
    std::cout << ss.str();
}

{% include "_dllmain.cpp" %}
