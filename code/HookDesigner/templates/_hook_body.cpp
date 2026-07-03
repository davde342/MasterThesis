

    // Capture arguments on entry
    {% if hook.behaviors.runtime_monitoring and hook.behaviors.runtime_monitoring.log_arguments %}
    {% for param in hook.parameters %}
    {% if param.name in hook.behaviors.runtime_monitoring.log_arguments %}
    {% if param.is_char_ptr %}
    std::string input_{{ param.name }} = CopyString({{ param.name }});
    {% elif param.pointer_depth > 0 and 'void' not in param.underlying_type %}
    {{ param.underlying_type }} input_{{ param.name }} = {{ param.safe_read_expr }};
    {% else %}
    {{ param.type }} input_{{ param.name }} = {{ param.name }};
    {% endif %}
    {% endif %}
    {% endfor %}
    {% endif %}

    {% if hook.behaviors.performance_metrics.execution_time %}
    LARGE_INTEGER start_time_{{ hook.function_name }};
    QueryPerformanceCounter(&start_time_{{ hook.function_name }});
    {% endif %}


    // Pre-logic execution
    {% if hook.behaviors.security_policy.pre_hook %}
    RunPreLogic_{{ hook.behaviors.security_policy.pre_hook }}({%- for param in hook.behaviors.security_policy.pre_hook_params -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
    {% endif %}

    // Call Original
    {% if hook.return_type == 'void' %}
    True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
    {% else %}
    {{ hook.return_type }} __hook_result = True{{ hook.function_name }}({%- for param in hook.parameters -%}{{ param.name }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%});
    {{ hook.return_type }} __hook_input_result = __hook_result;
    {% endif %}

    // Post-logic execution
    {% if hook.behaviors.security_policy.post_hook %}
    RunPostLogic_{{ hook.behaviors.security_policy.post_hook }}(
        {%- for param in hook.behaviors.security_policy.post_hook_params -%}
            {%- if param.name == 'result' and hook.return_type != 'void' -%}
                __hook_result
            {%- else -%}
                {{ param.name }}
            {%- endif -%}
            {%- if not loop.last -%}, {%- endif -%}
        {%- endfor -%}
    );
    {% endif %}

    {% if hook.behaviors.performance_metrics.execution_time %}
    LARGE_INTEGER end_time_{{ hook.function_name }};
    QueryPerformanceCounter(&end_time_{{ hook.function_name }});
    double elapsed_ms_{{ hook.function_name }} = (double)(end_time_{{ hook.function_name }}.QuadPart - start_time_{{ hook.function_name }}.QuadPart) * 1000.0 / g_PerfFrequency.QuadPart;
    {% endif %}


    // Capture arguments on exit
    {% if hook.behaviors.runtime_monitoring and hook.behaviors.runtime_monitoring.log_arguments %}
    {% for param in hook.parameters %}
    {% if param.name in hook.behaviors.runtime_monitoring.log_arguments %}
    {% if param.is_char_ptr %}
    std::string output_{{ param.name }} = CopyString({{ param.name }});
    {% elif param.pointer_depth > 0 and 'void' not in param.underlying_type %}
    {{ param.underlying_type }} output_{{ param.name }} = {{ param.safe_read_expr }};
    {% else %}
    {{ param.type }} output_{{ param.name }} = {{ param.name }};
    {% endif %}
    {% endif %}
    {% endfor %}
    {% endif %}

    {% if hook.behaviors.runtime_monitoring and hook.behaviors.runtime_monitoring.log_arguments %}
    std::ostringstream ss;
    ss << "[HOOK {{ hook.function_name }}] TID: " << GetCurrentThreadId();
    {% for log_arg in hook.behaviors.runtime_monitoring.log_arguments %}
    {% if log_arg == 'result' and hook.return_type != 'void' %}
    if (__hook_input_result == __hook_result) {
        ss << " | result: " << __hook_result;
    } else {
        ss << " | result: " << __hook_input_result << " -> " << __hook_result;
    }
    {% else %}
    if (input_{{ log_arg }} == output_{{ log_arg }}) {
        ss << " | {{ log_arg }}: " << input_{{ log_arg }};
    } else {
        ss << " | {{ log_arg }}: " << input_{{ log_arg }} << " -> " << output_{{ log_arg }};
    }
    {% endif %}
    {% endfor %}
    {% if hook.behaviors.performance_metrics.execution_time %}
    ss << " | Latency: " << elapsed_ms_{{ hook.function_name }} << " ms";
    {% endif %}
    ss << std::endl;
    std::cout << ss.str();
    {% endif %}



    {% if hook.return_type != 'void' %}
    return __hook_result;
    {% endif %}
