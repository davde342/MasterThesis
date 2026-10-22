"""
HookDesigner Automated Benchmarking & Regression Audit Suite
Role: Senior Test Infrastructure Architect & Regression Auditor

Orchestrates:
1. Hermetic on-the-fly source code and policy generation into 'benchmarks/generated/'
2. Zero-drift MSVC compilation of the function DLL, hand-written hooks, transpiled hooks, and the target
3. QPC performance benchmarking
4. Per-condition statistics computed by the target (Mean, StdDev, Median)
5. CSV result files in 'benchmarks/results/raw/', including the records each RQ2 logging condition wrote vs expected
"""

import os
import sys
import json
import csv
import subprocess
import argparse
import time
from pathlib import Path

try:
    from dotenv import load_dotenv
    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False

from generator import SourceGenerator, BenchmarkSuiteSpec, TargetFunction, HOOK_CONDITIONS

# Canonical paths
BENCH_ROOT = Path(__file__).resolve().parent.parent
HOOKDESIGNER_ROOT = BENCH_ROOT.parent
ENV_PATH = HOOKDESIGNER_ROOT / ".env"

if ENV_PATH.exists():
    if HAS_DOTENV:
        load_dotenv(dotenv_path=ENV_PATH)
    else:
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())

VCVARS64_PATH = os.environ.get("VCVARS64_PATH", r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat")
DETOURS_INC = os.environ.get("DETOURS_INC", r"C:\Detours\Detours-main\include")
DETOURS_LIB_X64 = os.environ.get("DETOURS_LIB_X64", r"C:\Detours\Detours-main\lib.X64\detours.lib")
FRIDA_INC_X64 = os.environ.get("FRIDA_INC_X64", r"C:\Users\davig\Desktop\Thesis\Code")
FRIDA_LIB_X64 = os.environ.get("FRIDA_LIB_X64", r"C:\Users\davig\Desktop\Thesis\Code\frida-gum.lib")
SPDLOG_INC = os.environ.get("SPDLOG_INC", "")
PROMETHEUS_INC = os.environ.get("PROMETHEUS_INC", "")
PROMETHEUS_LIBS_X64 = os.environ.get("PROMETHEUS_LIBS_X64", "")

GENERATED_DIR = BENCH_ROOT / "generated"
BIN_DIR = BENCH_ROOT / "bin"
RESULTS_RAW_DIR = BENCH_ROOT / "results" / "raw"

TRANSPILER_PY = HOOKDESIGNER_ROOT / "transpiler.py"


def execute_shell(cmd_str: str, cwd: Path):
    """Executes a command shell invocation with audit verification."""
    cwd.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(cmd_str, shell=True, cwd=str(cwd), capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"\n[!] Build error encountered (Exit code {proc.returncode}):")
        print(proc.stdout)
        print(proc.stderr)
        raise RuntimeError(f"Command execution failed with exit code {proc.returncode}")
    return proc


def calls_per_trial(batch_size: int, work: int) -> int:
    """Calls per trial at a work level: batch_size up to work 100, then fewer in proportion, so a baseline trial
    lasts about as long at every level (one work step costs ~1 ns; L0_Baseline records the real function cost)."""
    return batch_size * 100 // max(work, 100)


def write_conditions_csv(results: list, csv_path: Path):
    """Writes RQ1/RQ2/RQ3 results, one row per (condition, work level). Hook is the DLL file name the target loaded."""
    RESULTS_RAW_DIR.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Condition", "Hook", "Work", "Trials", "Batch_Size", "Threads", "Mean_ns", "StdDev_ns", "Median_ns"])
        for name, r in results:
            writer.writerow([
                name, Path(r["hook"]).name, r["work"], r["trials"], r["batch_size"], r["threads"],
                f"{r['mean_ns']:.4f}", f"{r['stddev_ns']:.4f}", f"{r['median_ns']:.4f}"
            ])
    print(f"[+] Results written to: {csv_path}")


def expected_log_records(n: int, trials: int, batch_size: int, threads: int) -> int:
    """Records a rule logging when x % n == 0 writes (n = 1: every call, n = 0: never). Worker w calls with x = w .. w + batch_size - 1."""
    if n == 0:
        return 0
    return trials * sum((w + batch_size - 1) // n - (w - 1) // n for w in range(threads))


def count_log_records(log_path: Path, token: bytes = b"[AUDIT]") -> int:
    """Occurrences of token in the log, read in 16 MiB chunks: an every-call log reaches ~3 GB. 0 when the log is missing."""
    if not log_path.exists():
        return 0
    count, tail = 0, b""
    with open(log_path, "rb") as f:
        while chunk := f.read(1 << 24):
            buf = tail + chunk
            count += buf.count(token)
            tail = buf[-(len(token) - 1):]
    return count


def write_log_records_csv(rows: list, csv_path: Path):
    """Writes, for each RQ2 condition that logs, the records it should have written and the ones its log file holds."""
    RESULTS_RAW_DIR.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Condition", "Work", "Log_File", "Expected_Records", "Written_Records", "Dropped_Records"])
        writer.writerows(rows)
    print(f"[+] Log record counts written to: {csv_path}")


class BenchmarkOrchestrator:
    """End-to-end regression and benchmarking auditor."""

    def __init__(self):
        self.spec = self._build_spec()
        self.generator = SourceGenerator(self.spec)

    def _build_spec(self) -> BenchmarkSuiteSpec:
        # One target function: every condition, single- or multi-threaded, calls BenchFn0(x, work)
        return BenchmarkSuiteSpec(functions=[TargetFunction()])

    def generate_sources(self, rq: str = "all"):
        rq_norm = str(rq).lower()
        include_rq1 = rq_norm in ("1", "rq1", "all")
        include_rq2 = rq_norm in ("2", "rq2", "all")
        include_rq3 = rq_norm in ("3", "rq3", "all")

        GENERATED_DIR.mkdir(parents=True, exist_ok=True)
        print(f"\n=== [Stage 1/4] Dynamic Source Synthesis (SSoT) -> '{GENERATED_DIR}' ===")
        common_emitted = self.generator.emit_common(GENERATED_DIR)
        for p in common_emitted:
            print(f"  [+] Synthesized: {p.name}")

        handwritten_emitted = []
        if include_rq1 or include_rq2:
            handwritten_emitted = self.generator.emit_handwritten(GENERATED_DIR)
            for p in handwritten_emitted:
                print(f"  [+] Synthesized (RQ1/RQ2): {p.name}")

        hook_emitted = []
        if include_rq2 or include_rq3:
            hook_emitted = self.generator.emit_hook_policies(GENERATED_DIR)
            for p in hook_emitted:
                print(f"  [+] Synthesized (RQ2/RQ3): {p.name}")

        total = len(common_emitted) + len(handwritten_emitted) + len(hook_emitted)
        target_labels = []
        if include_rq1: target_labels.append("RQ1")
        if include_rq2: target_labels.append("RQ2")
        if include_rq3: target_labels.append("RQ3")
        target_label = "+".join(target_labels) if target_labels else "none"
        print(f"[+] All {total} benchmark sources ({target_label}) generated dynamically.")

    def compile_functions(self):
        print(f"\n=== [Stage 2/4] Compiling Target Dynamic Library ({self.spec.target_module}) ===")
        src = GENERATED_DIR / "bench_functions.cpp"
        out_dll = BIN_DIR / self.spec.target_module
        cmd = f'call "{VCVARS64_PATH}" && cl.exe /LD /O2 /EHsc /std:c++17 "{src}" /Fe:"{out_dll}"'
        execute_shell(cmd, BIN_DIR)
        print(f"  [+] Target built successfully: {out_dll.name}")

    def compile_handwritten_hooks(self):
        print("\n=== [Stage 3/4] Compiling Hand-Written Reference Baseline Hooks ===")
        
        # Detours
        src_detours = GENERATED_DIR / "handwritten_detours.cpp"
        out_detours = BIN_DIR / "handwritten_detours.dll"
        cmd_detours = (
            f'call "{VCVARS64_PATH}" && cl.exe /LD /O2 /EHsc /std:c++17 '
            f'/I"{DETOURS_INC}" /I"{GENERATED_DIR}" "{src_detours}" "{DETOURS_LIB_X64}" '
            f'user32.lib advapi32.lib /Fe:"{out_detours}"'
        )
        execute_shell(cmd_detours, BIN_DIR)
        print(f"  [+] Hand-written Detours compiled: {out_detours.name}")

        # Frida
        src_frida = GENERATED_DIR / "handwritten_frida.cpp"
        out_frida = BIN_DIR / "handwritten_frida.dll"
        cmd_frida = (
            f'call "{VCVARS64_PATH}" && cl.exe /LD /O2 /EHsc /std:c++17 '
            f'/I"{FRIDA_INC_X64}" /I"{GENERATED_DIR}" "{src_frida}" "{FRIDA_LIB_X64}" '
            f'user32.lib advapi32.lib ole32.lib shell32.lib /Fe:"{out_frida}"'
        )
        execute_shell(cmd_frida, BIN_DIR)
        print(f"  [+] Hand-written Frida-Gum compiled: {out_frida.name}")

    def compile_target(self):
        print("\n=== [Stage 4/4] Compiling High-Precision Benchmark target ===")
        src_target = GENERATED_DIR / "bench_target.cpp"
        out_target = BIN_DIR / "bench_target.exe"
        cmd = (
            f'call "{VCVARS64_PATH}" && cl.exe /O2 /EHsc /std:c++17 '
            f'/I"{GENERATED_DIR}" "{src_target}" /Fe:"{out_target}"'
        )
        execute_shell(cmd, BIN_DIR)
        print(f"  [+] Benchmark target built: {out_target.name}")

    def compile_hd_hooks(self):
        """Transpiles every HOOK_CONDITIONS policy <stem>.yaml into <stem>.cpp and <stem>_<engine>.dll (RQ2 and RQ3)."""
        print(f"\n=== Transpiling & Compiling HookDesigner Hooks (RQ2/RQ3) ===")
        BIN_DIR.mkdir(parents=True, exist_ok=True)

        for _, stem, _ in HOOK_CONDITIONS:
            pol_name, out_dll_name = f"{stem}.yaml", f"{stem}.dll"
            pol_file = GENERATED_DIR / pol_name
            out_cpp = BIN_DIR / f"{stem}.cpp"
            out_dll = BIN_DIR / out_dll_name

            cmd = [
                sys.executable, str(TRANSPILER_PY), str(pol_file),
                "--output-cpp", str(out_cpp),
                "--output-dll", str(out_dll),
                "--vcvars", VCVARS64_PATH
            ]
            if SPDLOG_INC:
                cmd.extend(["--spdlog-include", SPDLOG_INC])
            if PROMETHEUS_INC:
                cmd.extend(["--prometheus-include", PROMETHEUS_INC])
            if PROMETHEUS_LIBS_X64:
                cmd.extend(["--prometheus-libs", PROMETHEUS_LIBS_X64])

            try:
                subprocess.run(cmd, cwd=str(BIN_DIR), capture_output=True, text=True, check=True)
                print(f"  [+] Synthesized & compiled: {pol_name}")
            except subprocess.CalledProcessError as e:
                print(f"  [!] Note: compilation of {out_dll_name} skipped or failed:")
                err_snippet = (e.stderr or e.stdout or str(e)).strip()
                print(f"      {err_snippet[:200]}")

    def build(self, rq: str = "all"):
        """Full hermetic build pipeline discriminated by research question."""
        start_time = time.perf_counter()
        BIN_DIR.mkdir(parents=True, exist_ok=True)
        rq_norm = str(rq).lower()
        include_rq1 = rq_norm in ("1", "rq1", "all")
        include_rq2 = rq_norm in ("2", "rq2", "all")
        include_rq3 = rq_norm in ("3", "rq3", "all")

        self.generate_sources(rq=rq)
        self.compile_functions()
        if include_rq1 or include_rq2:
            self.compile_handwritten_hooks()
        if include_rq2 or include_rq3:
            self.compile_hd_hooks()
        self.compile_target()

        elapsed = time.perf_counter() - start_time
        suite_labels = []
        if include_rq1: suite_labels.append("RQ1")
        if include_rq2: suite_labels.append("RQ2")
        if include_rq3: suite_labels.append("RQ3")
        suite_desc = "all suites" if len(suite_labels) == 3 else ("+".join(suite_labels) if suite_labels else "none")
        print(f"\n[+] Benchmark binaries for {suite_desc} built successfully in {elapsed:.2f}s")

    def run(self, rq: str = "all", trials: int = 30, batch_size: int = 1000000, threads: int = 4, works: list = (0,)):
        """Execute benchmarks discriminated by research question. RQ1 and RQ2 run one thread; threads is RQ3's.
        RQ2 and RQ3 run at every work level in works; RQ1 always runs at work 0."""
        rq_norm = str(rq).lower()
        if rq_norm in ("1", "rq1", "all"):
            self.run_rq1(trials=trials, batch_size=batch_size)
        if rq_norm in ("2", "rq2", "all"):
            self.run_rq2(trials=trials, batch_size=batch_size, works=works)
        if rq_norm in ("3", "rq3", "all"):
            self.run_rq3(trials=trials, batch_size=batch_size, threads=threads, works=works)

    def run_condition(self, name: str, hook_dll: Path = None, trials: int = 30, batch_size: int = 1000000, threads: int = 1, work: int = 0):
        target_exe = BIN_DIR / "bench_target.exe"
        if not target_exe.exists():
            print(f"[!] Benchmark target binary not found: {target_exe}")
            print(f"    Please compile it first using --build-only.")
            raise RuntimeError(f"target binary missing: {target_exe}")

        cmd = [str(target_exe), "--trials", str(trials), "--batch-size", str(batch_size), "--threads", str(threads),
               "--work", str(work)]
        if hook_dll:
            # Pass forward-slashed normalized path
            cmd.extend(["--hook", str(hook_dll).replace("\\", "/")])

        proc = subprocess.run(cmd, cwd=str(BIN_DIR), capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"[!] Benchmark execution error for {name}:\n{proc.stdout}\n{proc.stderr}")
            raise RuntimeError(f"target run failed for {name}")

        return json.loads(proc.stdout)

    def run_rq1(self, trials: int = 30, batch_size: int = 1000000):
        print(f"\n========================================================")
        print(f" Executing RQ1 Benchmark Suite (Trials={trials}, Batch={batch_size}, Threads=1)")
        print(f"========================================================")

        # Engine cost only: hand-written passthrough hooks. HookDesigner's own cost is measured in RQ2.
        conditions = [
            ("C0_Baseline", None),
            ("C1_Handwritten_Detours", BIN_DIR / "handwritten_detours.dll"),
            ("C2_Handwritten_Frida", BIN_DIR / "handwritten_frida.dll"),
        ]

        results = []
        for name, dll_path in conditions:
            if dll_path is not None and not dll_path.exists():
                print(f"[-] Skipping {name}: binary not present ({dll_path.name})")
                continue
            print(f"[*] Running condition: {name} ...", end="", flush=True)
            res = self.run_condition(name, hook_dll=dll_path, trials=trials, batch_size=batch_size)
            results.append((name, res))
            print(f" Done. Latency: {res['mean_ns']:.2f} ns (SD: {res['stddev_ns']:.2f})")

        if not results:
            print("[!] No RQ1 conditions were executed.")
            return

        write_conditions_csv(results, RESULTS_RAW_DIR / "rq1_results.csv")

    def run_rq2(self, trials: int = 30, batch_size: int = 1000000, works: list = (0,)):
        """RQ2: what HookDesigner adds to the engine, one thread."""
        self.run_hook_suite("rq2", 1, trials, batch_size, works)

    def run_rq3(self, trials: int = 30, batch_size: int = 1000000, threads: int = 4, works: list = (0,)):
        """RQ3: RQ2 without L1_Handwritten, every thread calling the same hooked function. The calls of a trial
        are split across the threads, so a condition makes as many calls (and log records) as in RQ2."""
        self.run_hook_suite("rq3", threads, trials, batch_size, works)

    def run_hook_suite(self, rq: str, threads: int, trials: int, batch_size: int, works: list):
        """Runs L0, L1 (RQ2 only) and every HOOK_CONDITIONS hook per engine and work level, with
        calls_per_trial(batch_size, work) calls per trial split across the threads.
        Writes <rq>_<engine>_results.csv and, for the conditions that log, <rq>_<engine>_log_records.csv."""
        for eng in ["detours", "frida"]:
            # (name, DLL, (log file, N) for the conditions that log). L0 baseline, L1 engine only (RQ2), then
            # L2 = + HookDesigner's always-on wrapper, each feature alone on top of L2, and Full
            conditions = [("L0_Baseline", None, None)]
            if rq == "rq2":
                conditions.append(("L1_Handwritten", BIN_DIR / f"handwritten_{eng}.dll", None))
            conditions += [(name, BIN_DIR / f"{stem}_{eng}.dll", None if n is None else (f"{stem}.log", n))
                           for name, stem, n in HOOK_CONDITIONS]

            results = []
            log_rows = []
            for work in works:
                thread_batch = calls_per_trial(batch_size, work) // threads
                print(f"\n========================================================")
                print(f" Executing {rq.upper()} Benchmark Suite: HookDesigner Wrapper & Features ({eng.upper()})")
                print(f" Work={work}, Trials={trials}, Batch={thread_batch} per thread, Threads={threads}")
                print(f"========================================================")

                for name, dll_path, log in conditions:
                    if dll_path is not None and not dll_path.exists():
                        print(f"[-] Skipping {name}: binary not present ({dll_path.name})")
                        continue
                    print(f"[*] Running condition: {name} ...", end="", flush=True)
                    res = self.run_condition(name, hook_dll=dll_path, trials=trials, batch_size=thread_batch,
                                             threads=threads, work=work)
                    results.append((name, res))
                    print(f" Done. Latency: {res['mean_ns']:.2f} ns (SD: {res['stddev_ns']:.2f})")

                    if log:
                        # Count now: the other engine's DLL and the next work level write the same file, and opening it truncates it
                        log_file, n = log
                        expected = expected_log_records(n, trials, thread_batch, threads)
                        written = count_log_records(BIN_DIR / log_file)
                        log_rows.append([name, work, log_file, expected, written, expected - written])
                        print(f"    Log records: {written} of {expected} written, {expected - written} dropped")

            if not results:
                print(f"[!] No {rq.upper()} conditions were executed for engine {eng}.")
                continue

            write_conditions_csv(results, RESULTS_RAW_DIR / f"{rq}_{eng}_results.csv")
            if log_rows:
                write_log_records_csv(log_rows, RESULTS_RAW_DIR / f"{rq}_{eng}_log_records.csv")


def main():
    parser = argparse.ArgumentParser(description="HookDesigner Dynamic Benchmark Suite & Regression Auditor")
    parser.add_argument("--generate-only", action="store_true", help="Only synthesize source code and policies without compiling")
    parser.add_argument("--build-only", action="store_true", help="Generate sources and compile binaries without running benchmarks")
    parser.add_argument("--run-only", action="store_true", help="Execute benchmarks using existing compiled binaries")
    parser.add_argument("--rq", choices=["1", "2", "3", "all", "rq1", "rq2", "rq3"], default="all", help="Research question suite to run: rq1, rq2, rq3, or all (default: all)")
    parser.add_argument("--threads", type=int, default=4, help="Worker threads of RQ3, all calling the same hooked function (default: 4); RQ1 and RQ2 always run one thread")
    parser.add_argument("--trials", type=int, default=30, help="Number of measurement trials (default: 30)")
    parser.add_argument("--batch-size", type=int, default=1000000, help="Calls per trial (default: 1,000,000); RQ3 splits them across its threads")
    parser.add_argument("--work", type=int, nargs="+", default=[0], help="Work levels of RQ2/RQ3: extra multiply-xor steps BenchFn0 runs per call, e.g. 0 100 1000 10000 (default: 0). Above 100, calls per trial shrink in proportion; RQ1 always runs at 0")
    args = parser.parse_args()
    if args.threads < 2:
        parser.error("--threads must be at least 2: RQ3 is RQ2 with several threads")
    if min(args.work) < 0:
        parser.error("--work levels must not be negative")

    orchestrator = BenchmarkOrchestrator()

    if args.generate_only:
        orchestrator.generate_sources(rq=args.rq)
        return

    if args.build_only:
        orchestrator.build(rq=args.rq)
        return

    if args.run_only:
        orchestrator.run(rq=args.rq, trials=args.trials, batch_size=args.batch_size, threads=args.threads, works=args.work)
        return

    # Default: build then execute benchmark suite for the targeted RQ
    orchestrator.build(rq=args.rq)
    orchestrator.run(rq=args.rq, trials=args.trials, batch_size=args.batch_size, threads=args.threads, works=args.work)


if __name__ == "__main__":
    main()


