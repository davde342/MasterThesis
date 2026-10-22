{% set on_deny = hook.behaviors.security_policy.on_deny %}

    {% if telemetry and hook.behaviors.input_vars_needed %}
    bool telemetry_inputs_ready = false;
    const char* capturing_input_param = nullptr;

    {% for param in hook.parameters %}
    {% if param.name in hook.behaviors.input_vars_needed %}
    {{ param.safe_type }} input_{{ param.name }} = {};
    {% endif %}
    {% endfor %}
    try {
        {% for param in hook.parameters %}
        {% if param.name in hook.behaviors.input_vars_needed %}
        capturing_input_param = "{{ param.name }}";
        input_{{ param.name }} = {{ param.safe_read_expr }};
        {% endif %}
        {% endfor %}
        telemetry_inputs_ready = true;
    } catch (const std::exception& ex) {
        std::string msg = fmt::format("[HOOK CAPTURE] Exception capturing parameter '{}' in {{ hook.function_name }}: {}\n", 
                                      capturing_input_param ? capturing_input_param : "unknown", ex.what());
        OutputDebugStringA(msg.c_str());
    } catch (...) {
        std::string msg = fmt::format("[HOOK CAPTURE] Hardware/SEH fault capturing parameter '{}' in {{ hook.function_name }}\n", 
                                      capturing_input_param ? capturing_input_param : "unknown");
        OutputDebugStringA(msg.c_str());
    }
    {% endif %}

    {% if hook.behaviors.security_policy.pre_hook %}
    {% if on_deny %}
    // on_deny: the pre-hook's verdict decides the call (true = allow). Fail-closed: if the pre-hook
    // throws or faults, the assignment below never happens and the call is denied.
    bool __hook_denied = true;
    {% endif %}
    // Pre-logic execution
    try {
        {{ "__hook_denied = !" if on_deny else "" }}{{ hook.behaviors.security_policy.pre_hook }}({%- for param in hook.behaviors.security_policy.pre_hook_params -%}{{ param }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
    } catch (const std::exception& ex) {
        std::string msg = fmt::format("[HOOK EXCEPTION] Exception in pre-hook {{ hook.function_name }}{{ " (call denied)" if on_deny else "" }}: {}\n", ex.what());
        OutputDebugStringA(msg.c_str());
    } catch (...) {
        OutputDebugStringA("[HOOK EXCEPTION] Hardware/SEH fault in pre-hook {{ hook.function_name }}{{ " (call denied)" if on_deny else "" }}\n");
    }
    {% endif %}

    {% if hook.is_noreturn and telemetry %}
    {% if hook.behaviors.input_vars_needed %}
    if (telemetry_inputs_ready) {
    {% endif %}
        try {
            {% include "_telemetry_body.cpp" %}
        } catch (const std::exception& ex) {
            std::string msg = fmt::format("[TELEMETRY EXCEPTION] Exception in telemetry {{ hook.function_name }}: {}\n", ex.what());
            OutputDebugStringA(msg.c_str());
        } catch (...) {
            OutputDebugStringA("[TELEMETRY EXCEPTION] Hardware/SEH fault in telemetry {{ hook.function_name }}\n");
        }
    {% if hook.behaviors.input_vars_needed %}
    }
    {% endif %}
    {% endif %}

    {% if on_deny %}
    // on_deny: declared before the branch because telemetry reads them for denied and allowed calls
    {% if hook.return_type != 'void' %}
    {{ hook.return_type }} __hook_result{};
    {% endif %}
    {% if hook.behaviors.performance_metrics.execution_time %}
    double elapsed_ms_{{ hook.function_name }} = 0.0;
    {% endif %}
    if (__hook_denied) {
        // Denied: True{{ hook.function_name }} is not called and the post-hook is skipped
        {% if hook.return_type != 'void' %}
        __hook_result = {{ on_deny.return_value }};
        {% endif %}
        {% if on_deny.last_error %}
        system_error_guard.win32_error = {{ on_deny.last_error }}; // returned to the caller by the guard's destructor
        {% endif %}
    } else {
    {% endif %}
    hook_recursion_guard.Release();
    {% if hook.is_noreturn %}
    hook_active_threads.Release();
    {% endif %}

    system_error_guard.Restore();

    {% if hook.behaviors.performance_metrics.execution_time %}
    LARGE_INTEGER start_time_{{ hook.function_name }};
    LARGE_INTEGER end_time_{{ hook.function_name }};
    QueryPerformanceCounter(&start_time_{{ hook.function_name }});
    {% endif %}
    {% if hook.return_type == 'void' %}
    True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
    {% elif on_deny %}
    __hook_result = True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
    {% else %}
    {{ hook.return_type }} __hook_result = True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
    {% endif %}

    {% if hook.behaviors.performance_metrics.execution_time %}
    QueryPerformanceCounter(&end_time_{{ hook.function_name }});
    {% if on_deny %}
    elapsed_ms_{{ hook.function_name }} = (g_PerfFrequency.QuadPart > 0) ? ((double)(end_time_{{ hook.function_name }}.QuadPart - start_time_{{ hook.function_name }}.QuadPart) * 1000.0 / (double)g_PerfFrequency.QuadPart) : 0.0;
    {% else %}
    double elapsed_ms_{{ hook.function_name }} = (g_PerfFrequency.QuadPart > 0) ? ((double)(end_time_{{ hook.function_name }}.QuadPart - start_time_{{ hook.function_name }}.QuadPart) * 1000.0 / (double)g_PerfFrequency.QuadPart) : 0.0;
    {% endif %}
    {% endif %}

    {% if not hook.is_noreturn %}
    {% if hook.behaviors.performance_metrics.execution_time %}
    {% endif %}
    system_error_guard.Capture();
    hook_recursion_guard.Acquire();

    {% if hook.behaviors.security_policy.post_hook %}
    // Post-logic execution
    try {
        {{ hook.behaviors.security_policy.post_hook }}({%- for param in hook.behaviors.security_policy.post_hook_params -%}{%- if param in ['result', '__hook_result'] -%}__hook_result{%- else -%}{{ param }}{%- endif -%}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
    } catch (const std::exception& ex) {
        std::string msg = fmt::format("[HOOK EXCEPTION] Exception in post-hook {{ hook.function_name }}: {}\n", ex.what());
        OutputDebugStringA(msg.c_str());
    } catch (...) {
        OutputDebugStringA("[HOOK EXCEPTION] Hardware/SEH fault in post-hook {{ hook.function_name }}\n");
    }
    {% endif %}
    {% if on_deny %}
    }
    {% endif %}

    {% if telemetry and hook.behaviors.output_vars_needed %}
    bool telemetry_outputs_ready = false;
    const char* capturing_output_param = nullptr;

    {% for param in hook.parameters %}
    {% if param.name in hook.behaviors.output_vars_needed %}
    {{ param.safe_type }} output_{{ param.name }} = {};
    {% endif %}
    {% endfor %}
    try {
        {% for param in hook.parameters %}
        {% if param.name in hook.behaviors.output_vars_needed %}
        capturing_output_param = "{{ param.name }}";
        output_{{ param.name }} = {{ param.safe_read_expr }};
        {% endif %}
        {% endfor %}
        telemetry_outputs_ready = true;
    } catch (const std::exception& ex) {
        std::string msg = fmt::format("[HOOK CAPTURE] Exception capturing output parameter '{}' in {{ hook.function_name }}: {}\n", 
                                      capturing_output_param ? capturing_output_param : "unknown", ex.what());
        OutputDebugStringA(msg.c_str());
    } catch (...) {
        std::string msg = fmt::format("[HOOK CAPTURE] Hardware/SEH fault capturing output parameter '{}' in {{ hook.function_name }}\n", 
                                      capturing_output_param ? capturing_output_param : "unknown");
        OutputDebugStringA(msg.c_str());
    }
    {% endif %}

    {% if telemetry %}
    {% if hook.behaviors.input_vars_needed and hook.behaviors.output_vars_needed %}
    if (telemetry_inputs_ready && telemetry_outputs_ready) {
    {% elif hook.behaviors.input_vars_needed %}
    if (telemetry_inputs_ready) {
    {% elif hook.behaviors.output_vars_needed %}
    if (telemetry_outputs_ready) {
    {% endif %}
        try {
            {% include "_telemetry_body.cpp" %}
        } catch (const std::exception& ex) {
            std::string msg = fmt::format("[TELEMETRY EXCEPTION] Exception in telemetry {{ hook.function_name }}: {}\n", ex.what());
            OutputDebugStringA(msg.c_str());
        } catch (...) {
            OutputDebugStringA("[TELEMETRY EXCEPTION] Hardware/SEH fault in telemetry {{ hook.function_name }}\n");
        }
    {% if hook.behaviors.input_vars_needed or hook.behaviors.output_vars_needed %}
    }
    {% endif %}
    {% endif %}
    {% endif %}

    {% if hook.return_type != 'void' %}
    return __hook_result;
    {% endif %}



