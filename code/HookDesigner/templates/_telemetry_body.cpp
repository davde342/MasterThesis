        // --- Logging ---
        {% if hook.behaviors.log_rules %}
        {% for rule in hook.behaviors.log_rules %}
        if ({{ rule.condition }}) {
            {% if telemetry.logger == "spdlog" %}
            spdlog::{{ rule.level }}("{{ rule.cpp_log_format_str }}"{% for expr in rule.cpp_log_exprs %}, {{ expr }}{% endfor %});
            {% else %}
            fmt::memory_buffer ss_{{ rule.name }};
            fmt::format_to(std::back_inserter(ss_{{ rule.name }}), "{{ rule.cpp_log_format_str }}\n"{% for expr in rule.cpp_log_exprs %}, {{ expr }}{% endfor %});
            OutputDebugStringA(fmt::to_string(ss_{{ rule.name }}).c_str());
            {% endif %}
        }
        {% endfor %}
        {% endif %}

        // --- Prometheus Metrics ---
        {% if telemetry.metrics == "prometheus" %}
        // 2. Custom Counters
        {% for counter in hook.behaviors.performance_metrics.counters %}
        {% if counter.cpp_label %}
        if (g_PromFamily_{{ hook.function_name }}_{{ counter.name }}) {
            if ({{ counter.condition }}) {
                std::string cur_val = {{ counter.cpp_label.expr }};
                thread_local std::string last_val;
                thread_local prometheus::Counter* last_ptr = nullptr;
                thread_local std::unordered_map<std::string, prometheus::Counter*> label_dict;

                if (last_ptr && last_val == cur_val) {
                    last_ptr->Increment();
                } else {
                    auto it = label_dict.find(cur_val);
                    if (it != label_dict.end()) {
                        last_val = cur_val;
                        last_ptr = it->second;
                    } else {
                        last_ptr = &g_PromFamily_{{ hook.function_name }}_{{ counter.name }}->Add({ {"{{ counter.cpp_label.name }}", cur_val} });
                        label_dict[cur_val] = last_ptr;
                        last_val = cur_val;
                    }
                    if (last_ptr) last_ptr->Increment();
                }
            }
        }
        {% else %}
        if (g_PromMetric_{{ hook.function_name }}_{{ counter.name }}) {
            if ({{ counter.condition }}) {
                g_PromMetric_{{ hook.function_name }}_{{ counter.name }}->Increment();
            }
        }
        {% endif %}
        {% endfor %}

        // 3. Custom Gauges
        {% for gauge in hook.behaviors.performance_metrics.gauges %}
        {% if gauge.cpp_label %}
        if (g_PromFamily_{{ hook.function_name }}_{{ gauge.name }}) {
            if ({{ gauge.condition }}) {
                std::string cur_val = {{ gauge.cpp_label.expr }};
                thread_local std::string last_val;
                thread_local prometheus::Gauge* last_ptr = nullptr;
                thread_local std::unordered_map<std::string, prometheus::Gauge*> label_dict;

                if (last_ptr && last_val == cur_val) {
                    last_ptr->Set((double)({{ gauge.value }}));
                } else {
                    auto it = label_dict.find(cur_val);
                    if (it != label_dict.end()) {
                        last_val = cur_val;
                        last_ptr = it->second;
                    } else {
                        last_ptr = &g_PromFamily_{{ hook.function_name }}_{{ gauge.name }}->Add({ {"{{ gauge.cpp_label.name }}", cur_val} });
                        label_dict[cur_val] = last_ptr;
                        last_val = cur_val;
                    }
                    if (last_ptr) last_ptr->Set((double)({{ gauge.value }}));
                }
            }
        }
        {% else %}
        if (g_PromMetric_{{ hook.function_name }}_{{ gauge.name }}) {
            if ({{ gauge.condition }}) {
                g_PromMetric_{{ hook.function_name }}_{{ gauge.name }}->Set((double)({{ gauge.value }}));
            }
        }
        {% endif %}
        {% endfor %}

        // 4. Custom Histograms
        {% for hist in hook.behaviors.performance_metrics.histograms %}
        {% if hist.cpp_label %}
        if (g_PromFamily_{{ hook.function_name }}_{{ hist.name }}) {
            if ({{ hist.condition }}) {
                std::string cur_val = {{ hist.cpp_label.expr }};
                thread_local std::string last_val;
                thread_local prometheus::Histogram* last_ptr = nullptr;
                thread_local std::unordered_map<std::string, prometheus::Histogram*> label_dict;
                static const std::vector<double> buckets_{{ hook.function_name }}_{{ hist.name }} = { {%- for b in hist.buckets -%}{{ b }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%} };

                if (last_ptr && last_val == cur_val) {
                    last_ptr->Observe((double)({{ hist.value }}));
                } else {
                    auto it = label_dict.find(cur_val);
                    if (it != label_dict.end()) {
                        last_val = cur_val;
                        last_ptr = it->second;
                    } else {
                        last_ptr = &g_PromFamily_{{ hook.function_name }}_{{ hist.name }}->Add({ {"{{ hist.cpp_label.name }}", cur_val} }, buckets_{{ hook.function_name }}_{{ hist.name }});
                        label_dict[cur_val] = last_ptr;
                        last_val = cur_val;
                    }
                    if (last_ptr) last_ptr->Observe((double)({{ hist.value }}));
                }
            }
        }
        {% else %}
        if (g_PromMetric_{{ hook.function_name }}_{{ hist.name }}) {
            if ({{ hist.condition }}) {
                g_PromMetric_{{ hook.function_name }}_{{ hist.name }}->Observe((double)({{ hist.value }}));
            }
        }
        {% endif %}
        {% endfor %}

        {% endif %}
