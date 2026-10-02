
{% if telemetry.logger == "spdlog" %}
#include "spdlog/spdlog.h"
#include "spdlog/async.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/udp_sink.h"
{% endif %}

{% if telemetry.has_execution_time %}
static LARGE_INTEGER g_PerfFrequency = {0};
{% endif %}



{% if telemetry.metrics == "prometheus" %}
#include "prometheus/exposer.h"
#include "CivetServer.h"
#include "prometheus/registry.h"
#include "prometheus/counter.h"
#include "prometheus/gauge.h"
#include "prometheus/histogram.h"
#include <memory>
#include <string>
#include <type_traits>
#include <map>
#include <unordered_map>
#include <vector>

static std::string ToLabelString(const std::string& val) {
    return val;
}

static std::string ToLabelString(const char* val) {
    return val ? std::string(val) : std::string();
}

static std::string ToLabelString(char* val) {
    return val ? std::string(val) : std::string();
}

template <typename T>
static std::string ToLabelString(const T& val) {
    return std::to_string(val);
}

static std::unique_ptr<prometheus::Exposer> g_PromExposer;

static std::shared_ptr<prometheus::Registry> g_PromRegistry;


{% for hook in hooks %}
  {% for counter in hook.behaviors.performance_metrics.counters %}
static prometheus::Family<prometheus::Counter>* g_PromFamily_{{ hook.function_name }}_{{ counter.name }} = nullptr;
{% if not counter.cpp_label %}
static prometheus::Counter* g_PromMetric_{{ hook.function_name }}_{{ counter.name }} = nullptr;
{% endif %}
  {% endfor %}
  {% for gauge in hook.behaviors.performance_metrics.gauges %}
static prometheus::Family<prometheus::Gauge>* g_PromFamily_{{ hook.function_name }}_{{ gauge.name }} = nullptr;
{% if not gauge.cpp_label %}
static prometheus::Gauge* g_PromMetric_{{ hook.function_name }}_{{ gauge.name }} = nullptr;
{% endif %}
  {% endfor %}
  {% for hist in hook.behaviors.performance_metrics.histograms %}
static const std::vector<double> g_PromBuckets_{{ hook.function_name }}_{{ hist.name }} = { {%- for b in hist.buckets -%}{{ b }}{%- if not loop.last -%}, {%- endif -%}{%- endfor -%} };
static prometheus::Family<prometheus::Histogram>* g_PromFamily_{{ hook.function_name }}_{{ hist.name }} = nullptr;
{% if not hist.cpp_label %}
static prometheus::Histogram* g_PromMetric_{{ hook.function_name }}_{{ hist.name }} = nullptr;
{% endif %}
  {% endfor %}
{% endfor %}
{% endif %}
