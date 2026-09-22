

    // Declare input variables at function scope
    {% if hook.behaviors.input_vars_needed %}
    {% for param in hook.parameters %}
    {% if param.name in hook.behaviors.input_vars_needed %}
    {{ param.safe_type }} input_{{ param.name }} = {};
    {% endif %}
    {% endfor %}
    {% endif %}

    try {
        // Capture arguments on entry
        {% if hook.behaviors.input_vars_needed %}
        {% for param in hook.parameters %}
        {% if param.name in hook.behaviors.input_vars_needed %}
        input_{{ param.name }} = {{ param.safe_read_expr }};
        {% endif %}
        {% endfor %}
        {% endif %}

        // Pre-logic execution
        {% if hook.behaviors.security_policy.pre_hook %}
        {{ hook.behaviors.security_policy.pre_hook }}({%- for param in hook.behaviors.security_policy.pre_hook_params -%}{{ param }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
        {% endif %}

        {% if hook.is_noreturn and telemetry %}
        {% include "_telemetry_body.cpp" %}
        {% endif %}
    } catch (const std::exception& ex) {
        std::string msg = fmt::format("[HOOK EXCEPTION] Exception in pre-hook {{ hook.function_name }}: {}\n", ex.what());
        OutputDebugStringA(msg.c_str());
    } catch (...) {
        OutputDebugStringA("[HOOK EXCEPTION] Unknown exception in pre-hook {{ hook.function_name }}\n");
    }

    {% if hook.behaviors.performance_metrics.execution_time %}
    LARGE_INTEGER start_time_{{ hook.function_name }};
    QueryPerformanceCounter(&start_time_{{ hook.function_name }});
    {% endif %}

    // Call Original
    hook_recursion_guard.Release();
    {% if hook.is_noreturn %}
    hook_active_threads.Release();
    {% endif %}
    {% if hook.return_type == 'void' %}
    True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
    {% else %}
    {{ hook.return_type }} __hook_result = True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
    {% endif %}

    {% if hook.behaviors.performance_metrics.execution_time %}
        LARGE_INTEGER end_time_{{ hook.function_name }};
        QueryPerformanceCounter(&end_time_{{ hook.function_name }});
        double elapsed_ms_{{ hook.function_name }} = (g_PerfFrequency.QuadPart > 0) ? ((double)(end_time_{{ hook.function_name }}.QuadPart - start_time_{{ hook.function_name }}.QuadPart) * 1000.0 / (double)g_PerfFrequency.QuadPart) : 0.0;
    {% endif %}

    {% if not hook.is_noreturn %}
    hook_recursion_guard.Acquire();
    try {
        // Post-logic execution
        {% if hook.behaviors.security_policy.post_hook %}
        {{ hook.behaviors.security_policy.post_hook }}({%- for param in hook.behaviors.security_policy.post_hook_params -%}{%- if param in ['result', '__hook_result'] -%}__hook_result{%- else -%}{{ param }}{%- endif -%}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
        {% endif %}

        // Capture arguments on exit
        {% if hook.behaviors.output_vars_needed %}
        {% for param in hook.parameters %}
        {% if param.name in hook.behaviors.output_vars_needed %}
        {{ param.safe_type }} output_{{ param.name }} = {{ param.safe_read_expr }};
        {% endif %}
        {% endfor %}
        {% endif %}

        {% if telemetry %}
        {% include "_telemetry_body.cpp" %}
        {% endif %}
    } catch (const std::exception& ex) {
        std::string msg = fmt::format("[HOOK EXCEPTION] Exception in post-hook {{ hook.function_name }}: {}\n", ex.what());
        OutputDebugStringA(msg.c_str());
    } catch (...) {
        OutputDebugStringA("[HOOK EXCEPTION] Unknown exception in post-hook {{ hook.function_name }}\n");
    }
    {% endif %}

    {% if hook.return_type != 'void' %}
    return __hook_result;
    {% endif %}
