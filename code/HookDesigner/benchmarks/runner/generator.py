

from dataclasses import dataclass, field
from typing import List, Tuple
from pathlib import Path


@dataclass
class TargetFunction:
    name: str = "BenchFn0"
    return_type: str = "int"
    # work: extra dependent multiply-xor steps per call, the cost knob of the function-cost sweep (0: the two fixed steps only)
    params: List[Tuple[str, str]] = field(default_factory=lambda: [("int", "x"), ("int", "work")])
    # The loop comes after the fixed steps, so no branch targets the bytes the engines overwrite at the function's start
    body: str = (
        "int a = x;\n"
        "    a = (a * 33) ^ 0x5555;\n"
        "    a = (a * 33) ^ 0xAAAA;\n"
        "    for (int i = 0; i < work; ++i) a = (a * 33) ^ 0x5555;\n"
        "    return a;"
    )

    @property
    def param_sig(self) -> str:
        return ", ".join(f"{p_type} {p_name}" for p_type, p_name in self.params)

    @property
    def param_names(self) -> str:
        return ", ".join(p_name for _, p_name in self.params)


@dataclass
class BenchmarkSuiteSpec:
    target_module: str = "bench_functions.dll"
    functions: List[TargetFunction] = field(default_factory=lambda: [TargetFunction()])
    target_process: str = "bench_target.exe"


# hook conditions shared by RQ2 (one thread) and RQ3 (several threads), in run order: condition name,
# and, for the conditions that log, N: the  log rule writes one call in N (1: every call; 0: never, the control that pays the capture and the condition but

HOOK_CONDITIONS = [
    ("L2_HD_Bare", "hd_bare", None),
    ("I1_Safety", "hd_safety", None),
    ("I2_Timing", "hd_timing", None),
    ("I3_Counter", "hd_counter", None),
    ("I4_Label_Hit", "hd_label_hit", None),
    ("I5_Label_miss", "hd_label_miss", None),
    ("I6_Histogram", "hd_histogram", None),
    ("I7_Logging", "hd_logging", 1),
    ("I7_Logging_1in10", "hd_logging_1in10", 10),
    ("I7_Logging_1in100", "hd_logging_1in100", 100),
    ("I7_Logging_Never", "hd_logging_never", 0),
    ("Full", "hd_full", 10),
]

# Logic file (pre/post callbacks) of every hook policy
HOOK_LOGIC_FILE = "hd_logic.cpp"


def log_condition_yaml(n: int) -> str:
    """Condition line of a log rule writing one call in n; x runs 0, 1, 2, ... in every trial and is never negative."""
    if n == 1:
        return ""
    expr = f"input_x % {n} == 0" if n else "input_x < 0"
    return f'\n          condition: "{expr}"'


class SourceGenerator:

    def __init__(self, spec: BenchmarkSuiteSpec):
        self.spec = spec

    def generate_target_header(self) -> str:
        decls = "\n".join(
            f'extern "C" __declspec(dllexport) __declspec(noinline) {fn.return_type} {fn.name}({fn.param_sig});'
            for fn in self.spec.functions
        )
        return f"""{decls}

"""

    def generate_target_function_source(self) -> str:
        impls = []
        for fn in self.spec.functions:
            impls.append(
                f'extern "C" __declspec(dllexport) __declspec(noinline) {fn.return_type} {fn.name}({fn.param_sig}) {{\n'
                f'    {fn.body}\n'
                f'}}'
            )
        impls_str = "\n\n".join(impls)

        return f"""#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "bench_functions.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {{
    return TRUE;
}}

{impls_str}
"""

    def generate_handwritten_detours(self) -> str:
        typedefs = []
        attaches = []
        detaches = []

        for fn in self.spec.functions:
            typedefs.append(
                f'typedef {fn.return_type} (*{fn.name}_t)({fn.param_sig});\n'
                f'static {fn.name}_t True{fn.name} = nullptr;\n'
                f'static {fn.return_type} Hooked{fn.name}({fn.param_sig}) {{\n'
                f'    return True{fn.name}({fn.param_names});\n'
                f'}}'
            )
            attaches.append(
                f'    True{fn.name} = ({fn.name}_t)GetProcAddress(hTarget, "{fn.name}");\n'
                f'    if (!True{fn.name}) return 2;\n'
                f'    DetourAttach(&(PVOID&)True{fn.name}, (PVOID)Hooked{fn.name});'
            )
            detaches.append(
                f'    if (True{fn.name}) {{\n'
                f'        DetourDetach(&(PVOID&)True{fn.name}, (PVOID)Hooked{fn.name});\n'
                f'    }}'
            )

        typedefs_str = "\n\n".join(typedefs)
        attaches_str = "\n".join(attaches)
        detaches_str = "\n".join(detaches)

        return f"""#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <detours.h>
#include "bench_functions.h"

{typedefs_str}

extern "C" __declspec(dllexport) DWORD WINAPI InitializeHooks(LPVOID lpParam) {{
    HMODULE hTarget = GetModuleHandleA("{self.spec.target_module}");
    if (!hTarget) {{
        hTarget = LoadLibraryA("{self.spec.target_module}");
        if (!hTarget) return 1;
    }}

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

{attaches_str}

    LONG error = DetourTransactionCommit();
    return (error == NO_ERROR) ? 0 : 3;
}}

extern "C" __declspec(dllexport) DWORD WINAPI DeinitializeHooks(LPVOID lpParam) {{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

{detaches_str}

    LONG error = DetourTransactionCommit();
    return (error == NO_ERROR) ? 0 : 1;
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {{
    return TRUE;
}}
"""

    def generate_handwritten_frida(self) -> str:
        typedefs = []
        attaches = []
        reverts = []

        for fn in self.spec.functions:
            typedefs.append(
                f'typedef {fn.return_type} (*{fn.name}_t)({fn.param_sig});\n'
                f'static {fn.name}_t True{fn.name} = nullptr;\n'
                f'static gpointer g_target_{fn.name} = nullptr;\n'
                f'static {fn.return_type} Hooked{fn.name}({fn.param_sig}) {{\n'
                f'    return True{fn.name}({fn.param_names});\n'
                f'}}'
            )
            attaches.append(
                f'    g_target_{fn.name} = (gpointer)GetProcAddress(hTarget, "{fn.name}");\n'
                f'    if (!g_target_{fn.name}) return 2;\n'
                f'    GumReplaceReturn r_{fn.name} = gum_interceptor_replace(\n'
                f'        g_interceptor,\n'
                f'        g_target_{fn.name},\n'
                f'        (gpointer)Hooked{fn.name},\n'
                f'        nullptr,\n'
                f'        (gpointer*)&True{fn.name}\n'
                f'    );\n'
                f'    if (r_{fn.name} != GUM_REPLACE_OK) return 3;'
            )
            reverts.append(
                f'        if (g_target_{fn.name}) {{\n'
                f'            gum_interceptor_revert(g_interceptor, g_target_{fn.name});\n'
                f'        }}'
            )

        typedefs_str = "\n\n".join(typedefs)
        attaches_str = "\n".join(attaches)
        reverts_str = "\n".join(reverts)

        return f"""#include "frida-gum.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "bench_functions.h"

static GumInterceptor* g_interceptor = nullptr;

{typedefs_str}

extern "C" __declspec(dllexport) DWORD WINAPI InitializeHooks(LPVOID lpParam) {{
    gum_init_embedded();
    g_interceptor = gum_interceptor_obtain();

    HMODULE hTarget = GetModuleHandleA("{self.spec.target_module}");
    if (!hTarget) {{
        hTarget = LoadLibraryA("{self.spec.target_module}");
        if (!hTarget) return 1;
    }}

    gum_interceptor_begin_transaction(g_interceptor);

{attaches_str}

    gum_interceptor_end_transaction(g_interceptor);
    return 0;
}}

extern "C" __declspec(dllexport) DWORD WINAPI DeinitializeHooks(LPVOID lpParam) {{
    if (g_interceptor) {{
        gum_interceptor_begin_transaction(g_interceptor);
{reverts_str}
        gum_interceptor_end_transaction(g_interceptor);

        g_object_unref(g_interceptor);
        g_interceptor = nullptr;
        gum_deinit_embedded();
    }}
    return 0;
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {{
    return TRUE;
}}
"""

    def generate_target_source(self) -> str:
        return f"""#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <vector>
#include <thread>
#include <numeric>
#include <algorithm>
#include <cmath>
#include <string>
#include <atomic>
#include "bench_functions.h"

void RunWorker(
    int (*fn)(int, int),
    size_t batch_size,
    int work,
    size_t worker_id,
    double& out_ns_per_call,
    LARGE_INTEGER qpcFreq,
    std::atomic<size_t>* ready_count,
    HANDLE start_event
) {{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    // Block instead of spinning: with as many spinning workers as logical CPUs, the main thread could not run to release them
    if (ready_count != nullptr) {{
        ready_count->fetch_add(1, std::memory_order_release);
        WaitForSingleObject(start_event, INFINITE);
    }}

    // Warm-up explicitly omitted as per thesis methodology directive
    int sink = 0;

    LARGE_INTEGER qpcStart, qpcEnd;
    QueryPerformanceCounter(&qpcStart);

    for (size_t i = 0; i < batch_size; ++i) {{
        sink ^= fn((int) (i + worker_id), work);
    }}
    // A volatile write is observable behaviour: the compiler must compute every fn() result folded into sink
    volatile int sink_out = sink;

    QueryPerformanceCounter(&qpcEnd);

    double elapsed_sec = (double)(qpcEnd.QuadPart - qpcStart.QuadPart) / (double)(qpcFreq.QuadPart);
    double elapsed_ns = elapsed_sec * 1e9;

    out_ns_per_call = elapsed_ns / (double)(batch_size);
}}

int main(int argc, char* argv[]) {{
    std::string hookDllPath = "";
    size_t batchSize = 1000000;
    size_t numTrials = 30;
    size_t numThreads = 1;
    int work = 0;

    for (int i = 1; i < argc; ++i) {{
        std::string arg = argv[i];
        if (arg == "--hook" && i + 1 < argc) {{
            hookDllPath = argv[++i];
        }} else if (arg == "--batch-size" && i + 1 < argc) {{
            batchSize = std::stoull(argv[++i]);
        }} else if (arg == "--trials" && i + 1 < argc) {{
            numTrials = std::stoull(argv[++i]);
        }} else if (arg == "--threads" && i + 1 < argc) {{
            numThreads = std::stoull(argv[++i]);
        }} else if (arg == "--work" && i + 1 < argc) {{
            work = std::stoi(argv[++i]);
        }}
    }}

    // Manual-reset: one SetEvent releases every waiting worker
    HANDLE startEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!startEvent) {{
        std::cerr << "{{\\"error\\": \\"CreateEvent failed with code " << GetLastError() << "\\"}}\\n";
        return 6;
    }}

    HMODULE hTarget = LoadLibraryA("{self.spec.target_module}");
    if (!hTarget) {{
        std::cerr << "{{\\"error\\": \\"Failed to load {self.spec.target_module}\\"}}\\n";
        return 1;
    }}

    typedef int (*BenchFn_t)(int, int);
    BenchFn_t target_fn = (BenchFn_t)GetProcAddress(hTarget, "{self.spec.functions[0].name}");
    if (!target_fn) {{
        std::cerr << "{{\\"error\\": \\"{self.spec.functions[0].name} not exported by {self.spec.target_module}\\"}}\\n";
        FreeLibrary(hTarget);
        return 2;
    }}

    HMODULE hHook = nullptr;
    typedef DWORD(WINAPI* InitHooks_t)(LPVOID);
    typedef DWORD(WINAPI* DeinitHooks_t)(LPVOID);
    InitHooks_t pInitHooks = nullptr;
    DeinitHooks_t pDeinitHooks = nullptr;

    if (!hookDllPath.empty()) {{
        hHook = LoadLibraryA(hookDllPath.c_str());
        if (!hHook) {{
            std::cerr << "{{\\"error\\": \\"Failed to load hook DLL: " << hookDllPath << "\\"}}\\n";
            FreeLibrary(hTarget);
            return 4;
        }}

        pInitHooks = (InitHooks_t)GetProcAddress(hHook, "InitializeHooks");
        pDeinitHooks = (DeinitHooks_t)GetProcAddress(hHook, "DeinitializeHooks");

        if (pInitHooks) {{
            DWORD initRes = pInitHooks(nullptr);
            if (initRes != 0) {{
                std::cerr << "{{\\"error\\": \\"InitializeHooks failed with code " << initRes << "\\"}}\\n";
                FreeLibrary(hHook);
                FreeLibrary(hTarget);
                return 5;
            }}
        }}
    }}

    LARGE_INTEGER qpcFreq;
    QueryPerformanceFrequency(&qpcFreq);

    std::vector<double> trial_ns;
    trial_ns.reserve(numTrials);

    for (size_t t = 0; t < numTrials; ++t) {{
        if (numThreads == 1) {{
            double ns;
            RunWorker(target_fn, batchSize, work, 0, ns, qpcFreq, nullptr, nullptr);
            trial_ns.push_back(ns);
        }} else {{
            std::vector<std::thread> workers;
            std::vector<double> worker_ns(numThreads);
            workers.reserve(numThreads);

            std::atomic<size_t> ready_count{{0}};
            ResetEvent(startEvent);

            for (size_t w = 0; w < numThreads; ++w) {{
                // Every worker calls the same function
                workers.emplace_back(
                    RunWorker,
                    target_fn,
                    batchSize,
                    work,
                    w,
                    std::ref(worker_ns[w]),
                    qpcFreq,
                    &ready_count,
                    startEvent
                );
            }}

            while (ready_count.load(std::memory_order_acquire) < numThreads) {{
                std::this_thread::yield();
            }}
            SetEvent(startEvent);

            for (auto& w : workers) {{
                w.join();
            }}

            double avg_ns = 0.0;
            for (size_t w = 0; w < numThreads; ++w) {{
                avg_ns += worker_ns[w];
            }}
            trial_ns.push_back(avg_ns / (double)(numThreads));
        }}
    }}

    std::sort(trial_ns.begin(), trial_ns.end());

    double sum_ns = std::accumulate(trial_ns.begin(), trial_ns.end(), 0.0);
    double mean_ns = sum_ns / numTrials;

    double sq_sum_ns = 0.0;
    for (double v : trial_ns) sq_sum_ns += (v - mean_ns) * (v - mean_ns);
    double stddev_ns = (numTrials > 1) ? std::sqrt(sq_sum_ns / (numTrials - 1)) : 0.0;

    double median_ns = trial_ns[numTrials / 2];

    std::cout << "{{\\n"
              << "  \\"hook\\": \\"" << (hookDllPath.empty() ? "baseline_unhooked" : hookDllPath) << "\\",\\n"
              << "  \\"trials\\": " << numTrials << ",\\n"
              << "  \\"batch_size\\": " << batchSize << ",\\n"
              << "  \\"threads\\": " << numThreads << ",\\n"
              << "  \\"work\\": " << work << ",\\n"
              << "  \\"mean_ns\\": " << mean_ns << ",\\n"
              << "  \\"stddev_ns\\": " << stddev_ns << ",\\n"
              << "  \\"median_ns\\": " << median_ns << "\\n"
              << "}}\\n";

    if (hHook) {{
        if (pDeinitHooks) {{
            pDeinitHooks(nullptr);
        }}
        FreeLibrary(hHook);
    }}
    FreeLibrary(hTarget);
    CloseHandle(startEvent);

    return 0;
}}
"""

    def emit_common(self, out_dir: Path):
        """Atomically emits common target library and benchmark target sources."""
        out_dir.mkdir(parents=True, exist_ok=True)

        files = {
            out_dir / "bench_functions.h": self.generate_target_header(),
            out_dir / "bench_functions.cpp": self.generate_target_function_source(),
            out_dir / "bench_target.cpp": self.generate_target_source()
        }

        for path, content in files.items():
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

        return list(files.keys())

    def emit_handwritten(self, out_dir: Path):
        """Atomically emits the hand-written hook sources (RQ1 engine comparison and RQ2's L1 rung)."""
        out_dir.mkdir(parents=True, exist_ok=True)

        files = {
            out_dir / "handwritten_detours.cpp": self.generate_handwritten_detours(),
            out_dir / "handwritten_frida.cpp": self.generate_handwritten_frida()
        }

        for path, content in files.items():
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

        return list(files.keys())

    def generate_hook_logic(self) -> str:
        """Synthesizes the logic file of the hook policies: the signature they hook and the pre/post callbacks of I1 and Full."""
        fn = self.spec.functions[0]
        return f"""#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// @signatures-start
{fn.return_type} {fn.name}({fn.param_sig});
// @signatures-end

// @{fn.name}_pre-start
void {fn.name}_pre(int& x) {{
    if (x < 0) x = 0;
}}

// @{fn.name}_post-start
void {fn.name}_post(int& __hook_result) {{
    if (__hook_result < 0) __hook_result = 0;
}}
"""

    def generate_hook_policies(self) -> dict:
        """Synthesizes the HOOK_CONDITIONS policies : the bare hook, each feature alone,
        the sampled-logging variants and all features combined."""
        primary_fn = self.spec.functions[0].name
        target_mod = self.spec.target_module
        target_proc = self.spec.target_process
        logic_file = HOOK_LOGIC_FILE
        log_every = {stem: n for _, stem, n in HOOK_CONDITIONS if n is not None}

        def logging_policy(stem: str) -> str:
            # I7 and its sampled variants: the same rule, writing one call in N to <stem>.log
            return f"""configure:
  paradigm: inline_hook
  engines:
    - detours
    - frida
  process: {target_proc}
  logic_file: "{logic_file}"
  telemetry:
    logger: "spdlog"
    logger_config:
      type: "file"
      file: "{stem}.log"
      level: "info"

hooks:
  - module: {target_mod}
    function_name: {primary_fn}
    address_resolution:
      strategy: export
    behaviors:
      log_rules:
        - name: "audit_call"{log_condition_yaml(log_every[stem])}
          format: "[AUDIT] {primary_fn} called x={{input_x}} result={{__hook_result}}"
"""

        policies = {
            # L2. Bare Hook alone (HookDesigner's always-on wrapper, no features)
            "hd_bare.yaml": f"""configure:
  paradigm: inline_hook
  engines:
    - detours
    - frida
  process: {target_proc}
  logic_file: "{logic_file}"

hooks:
  - module: {target_mod}
    function_name: {primary_fn}
    address_resolution:
      strategy: export
""",
            # I1. Safety Layer alone
            "hd_safety.yaml": f"""configure:
  paradigm: inline_hook
  engines:
    - detours
    - frida
  process: {target_proc}
  logic_file: "{logic_file}"

hooks:
  - module: {target_mod}
    function_name: {primary_fn}
    address_resolution:
      strategy: export
    behaviors:
      security_policy:
        pre_hook: {primary_fn}_pre
        post_hook: {primary_fn}_post
""",
            # I2. Isolated Execution Timing alone
            "hd_timing.yaml": f"""configure:
  paradigm: inline_hook
  engines:
    - detours
    - frida
  process: {target_proc}
  logic_file: "{logic_file}"
  telemetry:
    logger: null
    metrics: null

hooks:
  - module: {target_mod}
    function_name: {primary_fn}
    address_resolution:
      strategy: export
    behaviors:
      performance_metrics:
        execution_time: true
""",
            # I3. Isolated Prometheus Counter alone
            "hd_counter.yaml": f"""configure:
  paradigm: inline_hook
  engines:
    - detours
    - frida
  process: {target_proc}
  logic_file: "{logic_file}"
  telemetry:
    metrics: "prometheus"
    metrics_config:
      endpoint: "127.0.0.1:8091"

hooks:
  - module: {target_mod}
    function_name: {primary_fn}
    address_resolution:
      strategy: export
    behaviors:
      performance_metrics:
        counters:
          - name: "calls_total"
            description: "Total invocations counter"
""",
            # I4. Isolated Prometheus Counter with Dynamic Label (MRU Cache Hit)
            "hd_label_hit.yaml": f"""configure:
  paradigm: inline_hook
  engines:
    - detours
    - frida
  process: {target_proc}
  logic_file: "{logic_file}"
  telemetry:
    metrics: "prometheus"
    metrics_config:
      endpoint: "127.0.0.1:8096"

hooks:
  - module: {target_mod}
    function_name: {primary_fn}
    address_resolution:
      strategy: export
    behaviors:
      performance_metrics:
        counters:
          - name: "calls_labeled_hit"
            description: "Counter with invariant dynamic label (cache hit)"
            label:
              status: "input_x * 0"
""",
            # I5. Isolated Prometheus Counter with Dynamic Label (MRU Cache Miss)
            "hd_label_miss.yaml": f"""configure:
  paradigm: inline_hook
  engines:
    - detours
    - frida
  process: {target_proc}
  logic_file: "{logic_file}"
  telemetry:
    metrics: "prometheus"
    metrics_config:
      endpoint: "127.0.0.1:8097"

hooks:
  - module: {target_mod}
    function_name: {primary_fn}
    address_resolution:
      strategy: export
    behaviors:
      performance_metrics:
        counters:
          - name: "calls_labeled_miss"
            description: "Counter with alternating dynamic label (cache miss)"
            label:
              status: "input_x % 2"
""",
            # I6. Isolated Prometheus Histogram alone. It observes __hook_result, not __hook_latency, which would
            # turn timing on too. Observe() costs the same: every result lands in the +Inf bucket, every latency in the first.
            "hd_histogram.yaml": f"""configure:
  paradigm: inline_hook
  engines:
    - detours
    - frida
  process: {target_proc}
  logic_file: "{logic_file}"
  telemetry:
    metrics: "prometheus"
    metrics_config:
      endpoint: "127.0.0.1:8092"

hooks:
  - module: {target_mod}
    function_name: {primary_fn}
    address_resolution:
      strategy: export
    behaviors:
      performance_metrics:
        histograms:
          - name: "result_hist"
            description: "Return value distribution"
            value: "__hook_result"
""",
            # I7. Isolated Asynchronous Logging alone, every call and sampled (one call in N, N from HOOK_CONDITIONS)
            **{f"{stem}.yaml": logging_policy(stem) for name, stem, _ in HOOK_CONDITIONS if name.startswith("I7_")},
            # Full: I1 + I2 + I4 + I6 + I7 combined, each configured exactly as in its isolated policy.
            # The counter is I4's labelled one (repeating label value), not I3's plain one; the log rule writes one
            # call in N (HOOK_CONDITIONS), like the I7 condition with the same N.
            "hd_full.yaml": f"""configure:
  paradigm: inline_hook
  engines:
    - detours
    - frida
  process: {target_proc}
  logic_file: "{logic_file}"
  telemetry:
    logger: "spdlog"
    logger_config:
      type: "file"
      file: "hd_full.log"
      level: "info"
    metrics: "prometheus"
    metrics_config:
      endpoint: "127.0.0.1:8095"

hooks:
  - module: {target_mod}
    function_name: {primary_fn}
    address_resolution:
      strategy: export
    behaviors:
      security_policy:
        pre_hook: {primary_fn}_pre
        post_hook: {primary_fn}_post
      performance_metrics:
        execution_time: true
        counters:
          - name: "calls_labeled_hit"
            description: "Counter with invariant dynamic label (cache hit)"
            label:
              status: "input_x * 0"
        histograms:
          - name: "result_hist"
            description: "Return value distribution"
            value: "__hook_result"
      log_rules:
        - name: "audit_call"{log_condition_yaml(log_every["hd_full"])}
          format: "[AUDIT] {primary_fn} called x={{input_x}} result={{__hook_result}}"
""",
        }
        # Every HOOK_CONDITIONS stem has a policy, and nothing else
        assert set(policies) == {f"{stem}.yaml" for _, stem, _ in HOOK_CONDITIONS}, "HOOK_CONDITIONS and policies differ"
        return policies

    def emit_hook_policies(self, out_dir: Path) -> List[Path]:
        """emits the hook policies shared by RQ2 and RQ3, and their logic file."""
        out_dir.mkdir(parents=True, exist_ok=True)

        logic_file = out_dir / HOOK_LOGIC_FILE
        with open(logic_file, "w", encoding="utf-8") as f:
            f.write(self.generate_hook_logic())

        emitted = [logic_file]
        for fname, content in self.generate_hook_policies().items():
            fpath = out_dir / fname
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(content)
            emitted.append(fpath)

        return emitted

    def emit_all(self, out_dir: Path) -> List[Path]:
        """Atomically emits all benchmark sources into the target directory."""
        return self.emit_common(out_dir) + self.emit_handwritten(out_dir) + self.emit_hook_policies(out_dir)



