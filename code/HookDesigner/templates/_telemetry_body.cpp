        // --- Logging ---
        {% if telemetry.logger == "spdlog" and hook.behaviors.log_rules %}
        {% for rule in hook.behaviors.log_rules %}
        {% if rule.condition != "true" %}
        if ({{ rule.condition }}) {
        {% else %}
        {
        {% endif %}
            fmt::memory_buffer ss_{{ rule.name }};
            fmt::format_to(std::back_inserter(ss_{{ rule.name }}), FMT_COMPILE("{{ rule.cpp_log_format_str }}"){% for expr in rule.cpp_log_exprs %}, {{ expr }}{% endfor %});
            spdlog::{{ rule.level }}(spdlog::string_view_t(ss_{{ rule.name }}.data(), ss_{{ rule.name }}.size()));
        }
        {% endfor %}
        {% endif %}

        // --- Prometheus Metrics ---
        {% if telemetry.metrics == "prometheus" %}
        // 2. Custom Counters
        {% for counter in hook.behaviors.performance_metrics.counters %}
        {% if counter.cpp_label %}
        if (g_PromFamily_{{ hook.function_name }}_{{ counter.name }}) {
            {% if counter.condition != "true" %}
            if ({{ counter.condition }}) {
                std::string cur_val = {{ counter.cpp_label.expr }};
                uint64_t cur_hash = std::hash<std::string>{}(cur_val);
                thread_local uint64_t tl_last_hash_{{ counter.name }} = 0;
                thread_local prometheus::Counter* tl_last_ptr_{{ counter.name }} = nullptr;

                if (tl_last_ptr_{{ counter.name }} == nullptr || tl_last_hash_{{ counter.name }} != cur_hash) {
                    tl_last_ptr_{{ counter.name }} = &g_PromFamily_{{ hook.function_name }}_{{ counter.name }}->Add({ {"{{ counter.cpp_label.name }}", cur_val} });
                    tl_last_hash_{{ counter.name }} = cur_hash;
                }
                tl_last_ptr_{{ counter.name }}->Increment();
            }
            {% else %}
            std::string cur_val = {{ counter.cpp_label.expr }};
            uint64_t cur_hash = std::hash<std::string>{}(cur_val);
            thread_local uint64_t tl_last_hash_{{ counter.name }} = 0;
            thread_local prometheus::Counter* tl_last_ptr_{{ counter.name }} = nullptr;

            if (tl_last_ptr_{{ counter.name }} == nullptr || tl_last_hash_{{ counter.name }} != cur_hash) {
                tl_last_ptr_{{ counter.name }} = &g_PromFamily_{{ hook.function_name }}_{{ counter.name }}->Add({ {"{{ counter.cpp_label.name }}", cur_val} });
                tl_last_hash_{{ counter.name }} = cur_hash;
            }
            tl_last_ptr_{{ counter.name }}->Increment();
            {% endif %}
        }
        {% else %}
        if (g_PromMetric_{{ hook.function_name }}_{{ counter.name }}) {
            {% if counter.condition != "true" %}
            if ({{ counter.condition }}) {
                g_PromMetric_{{ hook.function_name }}_{{ counter.name }}->Increment();
            }
            {% else %}
            g_PromMetric_{{ hook.function_name }}_{{ counter.name }}->Increment();
            {% endif %}
        }
        {% endif %}
        {% endfor %}

        // 3. Custom Gauges
        {% for gauge in hook.behaviors.performance_metrics.gauges %}
        {% if gauge.cpp_label %}
        if (g_PromFamily_{{ hook.function_name }}_{{ gauge.name }}) {
            {% if gauge.condition != "true" %}
            if ({{ gauge.condition }}) {
                std::string cur_val = {{ gauge.cpp_label.expr }};
                uint64_t cur_hash = std::hash<std::string>{}(cur_val);
                thread_local uint64_t tl_last_hash_{{ gauge.name }} = 0;
                thread_local prometheus::Gauge* tl_last_ptr_{{ gauge.name }} = nullptr;

                if (tl_last_ptr_{{ gauge.name }} == nullptr || tl_last_hash_{{ gauge.name }} != cur_hash) {
                    tl_last_ptr_{{ gauge.name }} = &g_PromFamily_{{ hook.function_name }}_{{ gauge.name }}->Add({ {"{{ gauge.cpp_label.name }}", cur_val} });
                    tl_last_hash_{{ gauge.name }} = cur_hash;
                }
                tl_last_ptr_{{ gauge.name }}->Set((double)({{ gauge.value }}));
            }
            {% else %}
            std::string cur_val = {{ gauge.cpp_label.expr }};
            uint64_t cur_hash = std::hash<std::string>{}(cur_val);
            thread_local uint64_t tl_last_hash_{{ gauge.name }} = 0;
            thread_local prometheus::Gauge* tl_last_ptr_{{ gauge.name }} = nullptr;

            if (tl_last_ptr_{{ gauge.name }} == nullptr || tl_last_hash_{{ gauge.name }} != cur_hash) {
                tl_last_ptr_{{ gauge.name }} = &g_PromFamily_{{ hook.function_name }}_{{ gauge.name }}->Add({ {"{{ gauge.cpp_label.name }}", cur_val} });
                tl_last_hash_{{ gauge.name }} = cur_hash;
            }
            tl_last_ptr_{{ gauge.name }}->Set((double)({{ gauge.value }}));
            {% endif %}
        }
        {% else %}
        if (g_PromMetric_{{ hook.function_name }}_{{ gauge.name }}) {
            {% if gauge.condition != "true" %}
            if ({{ gauge.condition }}) {
                g_PromMetric_{{ hook.function_name }}_{{ gauge.name }}->Set((double)({{ gauge.value }}));
            }
            {% else %}
            g_PromMetric_{{ hook.function_name }}_{{ gauge.name }}->Set((double)({{ gauge.value }}));
            {% endif %}
        }
        {% endif %}
        {% endfor %}

        // 4. Custom Histograms
        {% for hist in hook.behaviors.performance_metrics.histograms %}
        {% if hist.cpp_label %}
        if (g_PromFamily_{{ hook.function_name }}_{{ hist.name }}) {
            {% if hist.condition != "true" %}
            if ({{ hist.condition }}) {
                std::string cur_val = {{ hist.cpp_label.expr }};
                uint64_t cur_hash = std::hash<std::string>{}(cur_val);
                thread_local uint64_t tl_last_hash_{{ hist.name }} = 0;
                thread_local prometheus::Histogram* tl_last_ptr_{{ hist.name }} = nullptr;

                if (tl_last_ptr_{{ hist.name }} == nullptr || tl_last_hash_{{ hist.name }} != cur_hash) {
                    tl_last_ptr_{{ hist.name }} = &g_PromFamily_{{ hook.function_name }}_{{ hist.name }}->Add({ {"{{ hist.cpp_label.name }}", cur_val} }, g_PromBuckets_{{ hook.function_name }}_{{ hist.name }});
                    tl_last_hash_{{ hist.name }} = cur_hash;
                }
                tl_last_ptr_{{ hist.name }}->Observe((double)({{ hist.value }}));
            }
            {% else %}
            std::string cur_val = {{ hist.cpp_label.expr }};
            uint64_t cur_hash = std::hash<std::string>{}(cur_val);
            thread_local uint64_t tl_last_hash_{{ hist.name }} = 0;
            thread_local prometheus::Histogram* tl_last_ptr_{{ hist.name }} = nullptr;

            if (tl_last_ptr_{{ hist.name }} == nullptr || tl_last_hash_{{ hist.name }} != cur_hash) {
                tl_last_ptr_{{ hist.name }} = &g_PromFamily_{{ hook.function_name }}_{{ hist.name }}->Add({ {"{{ hist.cpp_label.name }}", cur_val} }, g_PromBuckets_{{ hook.function_name }}_{{ hist.name }});
                tl_last_hash_{{ hist.name }} = cur_hash;
            }
            tl_last_ptr_{{ hist.name }}->Observe((double)({{ hist.value }}));
            {% endif %}
        }
        {% else %}
        if (g_PromMetric_{{ hook.function_name }}_{{ hist.name }}) {
            {% if hist.condition != "true" %}
            if ({{ hist.condition }}) {
                g_PromMetric_{{ hook.function_name }}_{{ hist.name }}->Observe((double)({{ hist.value }}));
            }
            {% else %}
            g_PromMetric_{{ hook.function_name }}_{{ hist.name }}->Observe((double)({{ hist.value }}));
            {% endif %}
        }
        {% endif %}
        {% endfor %}

        {% endif %}
