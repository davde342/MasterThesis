
    {% if telemetry.logger == "spdlog" %}
    spdlog::init_thread_pool(65536, 1, []() {
        if (g_TlsIndex != TLS_OUT_OF_INDEXES) {
            TlsSetValue(g_TlsIndex, (LPVOID)1);
        }
    });

    spdlog::sink_ptr sink;
    {% if telemetry.logger_config.type == "udp" %}
    auto config = spdlog::sinks::udp_sink_config("{{ telemetry.logger_config.host }}", {{ telemetry.logger_config.port }});
    sink = std::make_shared<spdlog::sinks::udp_sink_mt>(config);
    {% else %}
    sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("{{ telemetry.logger_config.file }}", true);
    {% endif %}

    std::shared_ptr<spdlog::logger> logger = std::make_shared<spdlog::async_logger>("hook_logger", sink, spdlog::thread_pool(), spdlog::async_overflow_policy::overrun_oldest);
    {% if telemetry.logger_config.type == "udp" %}
    // Syslog format so Promtail parses it automatically
    logger->set_pattern("<165>1 %Y-%m-%dT%H:%M:%SZ - target_hook - - - %v", spdlog::pattern_time_type::utc);
    {% endif %}
    
    // Set log level
    {% if telemetry.logger_config.level == "debug" %}
    logger->set_level(spdlog::level::debug);
    {% elif telemetry.logger_config.level == "warn" or telemetry.logger_config.level == "warning" %}
    logger->set_level(spdlog::level::warn);
    {% elif telemetry.logger_config.level == "err" or telemetry.logger_config.level == "error" %}
    logger->set_level(spdlog::level::err);
    {% else %}
    logger->set_level(spdlog::level::info);
    {% endif %}
    
    spdlog::set_default_logger(logger);
    spdlog::flush_on(spdlog::level::err);
    spdlog::info("[TELEMETRY] spdlog async logger initialized successfully.");
    {% endif %}
   
    {% if telemetry.metrics == "prometheus" %}
    g_PromRegistry = std::make_shared<prometheus::Registry>();
    CivetCallbacks callbacks{};
    callbacks.init_thread = [](const struct mg_context*, int) -> void* {
        if (g_TlsIndex != TLS_OUT_OF_INDEXES) {
            TlsSetValue(g_TlsIndex, (LPVOID)1);
        }
        return nullptr;
    };
    g_PromExposer = std::make_unique<prometheus::Exposer>("{{ telemetry.metrics_config.endpoint }}", 2, &callbacks);
    g_PromExposer->RegisterCollectable(g_PromRegistry);

    // Register custom metrics Families
    {% for hook in hooks %}
      {% for counter in hook.behaviors.performance_metrics.counters %}
      g_PromFamily_{{ hook.function_name }}_{{ counter.name }} = &prometheus::BuildCounter()
          .Name("hook_metric_{{ hook.function_name }}_{{ counter.name }}")
          .Help("{{ counter.description }}")
          .Register(*g_PromRegistry);
      {% if not counter.cpp_label %}
      g_PromMetric_{{ hook.function_name }}_{{ counter.name }} = &g_PromFamily_{{ hook.function_name }}_{{ counter.name }}->Add({ {"function", "{{ hook.function_name }}"} });
      {% endif %}
      {% endfor %}
      
      {% for gauge in hook.behaviors.performance_metrics.gauges %}
      g_PromFamily_{{ hook.function_name }}_{{ gauge.name }} = &prometheus::BuildGauge()
          .Name("hook_metric_{{ hook.function_name }}_{{ gauge.name }}")
          .Help("{{ gauge.description }}")
          .Register(*g_PromRegistry);
      {% if not gauge.cpp_label %}
      g_PromMetric_{{ hook.function_name }}_{{ gauge.name }} = &g_PromFamily_{{ hook.function_name }}_{{ gauge.name }}->Add({ {"function", "{{ hook.function_name }}"} });
      {% endif %}
      {% endfor %}
      
      {% for hist in hook.behaviors.performance_metrics.histograms %}
      g_PromFamily_{{ hook.function_name }}_{{ hist.name }} = &prometheus::BuildHistogram()
          .Name("hook_metric_{{ hook.function_name }}_{{ hist.name }}")
          .Help("{{ hist.description }}")
          .Register(*g_PromRegistry);
      {% if not hist.cpp_label %}
      g_PromMetric_{{ hook.function_name }}_{{ hist.name }} = &g_PromFamily_{{ hook.function_name }}_{{ hist.name }}->Add({ {"function", "{{ hook.function_name }}"} }, g_PromBuckets_{{ hook.function_name }}_{{ hist.name }});
      {% endif %}
      {% endfor %}
    {% endfor %}
    
    {% if telemetry.logger == "spdlog" %}
    spdlog::info("[TELEMETRY] Prometheus exposer started at {{ telemetry.metrics_config.endpoint }}.");
    {% endif %}
    {% endif %}
