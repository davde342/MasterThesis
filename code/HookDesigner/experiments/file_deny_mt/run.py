

import argparse
import http.client
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import yaml

EXP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXP_DIR.parent.parent / "suite"))
import common  

BUILD_DIR = EXP_DIR / "build"
POLICY = {"launch": EXP_DIR / "policy.yaml",          
          "cycles": EXP_DIR / "policy_cycles.yaml"}  
TARGET_EXE = BUILD_DIR / "filedeny_mt_target.exe"


def hook_dll(mode: str) -> Path:
    return BUILD_DIR / f"filedeny_mt_{mode}_hook.dll"


def metrics_endpoint() -> tuple[str, int]:
    with open(POLICY["launch"], "r", encoding="utf-8") as f:
        host, port = yaml.safe_load(f)["configure"]["telemetry"]["metrics_config"]["endpoint"].rsplit(":", 1)
    return host, int(port)

# Experiment test files
FILES = ["allowed_1.txt", "not_denied_1.txt", "denied_1.txt", "DENIED_2.TXT"]
LIST_FILE = "denylist.txt"  # read by E5's logic.cpp from the target's working folder on every hooked call
DENYLIST = {"denied_1.txt", "denied_2.txt", LIST_FILE}  # the list names itself (compared ignoring case)

# Run B: injector.exe output lines (injector.cpp). The injector exits with 0 even when it skips FreeLibrary.
INJECTED = "Hooks successfully initialized in target process."
EJECTED = "Ejection successful"
LEAKED = "Skipping FreeLibrary"
WAIT_S = 1.0  # pause after the injection (the window) and after the ejection
ANSWER_S = 10.0  # the target answers "off" at once; no answer within this time means it hangs
CYCLE_COLUMNS = ["cycle", "injected", "ejected", "leaked", "dll_unloaded", "died_at"]


def create_files(cond_dir: Path) -> list[str]:
    """Create the test files and return the target's --expect-* arguments"""
    files_dir = cond_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    with open(cond_dir / LIST_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write("".join(f"{name}\n" for name in sorted(DENYLIST)))
    args = []
    for name in FILES:
        (files_dir / name).write_text("HookDesigner E5 test file\n", encoding="utf-8")
        args += ["--expect-deny" if name.lower() in DENYLIST else "--expect-allow", name]
    return args


def write_process(cond_dir: Path, pid: int, exit_code: int | None) -> None:
    common.write_csv([{"pid": pid, "exit_code": exit_code}], cond_dir / "process.csv")



# Run A: launch mode

def read_metrics(target: common.Target, cond_dir: Path, timeout: float) -> None:
    """Save the hook DLL's /metrics page as metrics.txt. The counters exist only inside the running target. The
    target creates journal.csv only after all its workers have joined, so from then on the counts are final, and its
    pause before exit (--drain-ms) keeps the endpoint up while it is read."""
    deadline = time.monotonic() + timeout
    while not (cond_dir / "journal.csv").exists():
        if target.proc.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError(f"{cond_dir.name}: no journal.csv, metrics not read")
        time.sleep(0.05)
    host, port = metrics_endpoint()
    conn = http.client.HTTPConnection(host, port, timeout=5)  # http.client ignores proxy settings
    conn.request("GET", "/metrics")
    (cond_dir / "metrics.txt").write_bytes(conn.getresponse().read())
    conn.close()


def run_launch(cond_dir: Path, dll: Path, threads: int, args) -> None:
    target_args = create_files(cond_dir) + [
        "--threads", str(threads), "--rounds", str(args.rounds), "--drain-ms", str(args.drain_ms)]
    target = common.start(TARGET_EXE, target_args, dll=dll, cwd=cond_dir)
    read_metrics(target, cond_dir, args.timeout)
    result = common.finish(target, args.timeout)
    shutil.rmtree(cond_dir / "files")
    write_process(cond_dir, result.pid, result.exit_code)
    common.log(f"  {cond_dir.name:<22} pid {result.pid} exit {result.exit_code}")



# Run B: inject/eject cycles
def run_injector(mode: str, pid: int, dll: Path) -> str:
    """injector.exe inject|eject on the running target; returns its output."""
    proc = subprocess.run([str(common.INJECTOR), mode, str(pid), str(dll)], capture_output=True, text=True,
                          timeout=60)
    return proc.stdout + proc.stderr


def module_loaded(pid: int, dll: Path) -> bool:
    """Is the DLL in the target's module list?"""
    out = subprocess.run(["tasklist", "/m", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"],
                         capture_output=True, text=True).stdout.lower()
    return dll.name.lower() in out


def tell(proc: subprocess.Popen, line: str) -> None:
    """One line to the target's stdin"""
    proc.stdin.write(f"{line}\n".encode())
    proc.stdin.flush()


def read_answer(proc: subprocess.Popen) -> bytes | None:
    """The target's next line on stdout"""
    answer = []
    reader = threading.Thread(target=lambda: answer.append(proc.stdout.readline()), daemon=True)
    reader.start()
    reader.join(ANSWER_S)
    return answer[0] if answer else None


def run_cycle(proc: subprocess.Popen, dll: Path, i: int, cond_dir: Path) -> dict:
    row = {"cycle": i, "injected": 0, "ejected": 0, "leaked": 0, "dll_unloaded": "", "died_at": ""}

    row["injected"] = int(INJECTED in run_injector("inject", proc.pid, dll))
    if proc.poll() is not None:
        row["died_at"] = "inject"
        return row
    
    try:
        tell(proc, f"on {i}")
        time.sleep(WAIT_S)
        tell(proc, "off")
        answer = read_answer(proc)
    except OSError:  # the pipe is closed: the target has died
        answer = b""
    if answer is None:
        raise RuntimeError(f"cycle {i}: no answer to off within {ANSWER_S:.0f} s")
    if answer.strip() != b"off":  # end of file
        row["died_at"] = "hooked"
        return row

    out = run_injector("eject", proc.pid, dll)
    row["ejected"], row["leaked"] = int(EJECTED in out), int(LEAKED in out)
    if proc.poll() is not None:
        row["died_at"] = "eject"
        return row
    (cond_dir / "hook.log").replace(cond_dir / f"hook_{i:02d}.log")
    row["dll_unloaded"] = int(not module_loaded(proc.pid, dll))
    time.sleep(WAIT_S)
    if proc.poll() is not None:
        row["died_at"] = "unhooked"
    return row


def run_cycled(cond_dir: Path, dll: Path, threads: int, args) -> None:
    target_args = create_files(cond_dir) + [
        "--threads", str(threads), "--until-stop", "--drain-ms", str(args.drain_ms)]
    proc = subprocess.Popen([str(TARGET_EXE), *target_args], cwd=str(cond_dir), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    cycles = []
    for i in range(1, args.cycles + 1):
        row = run_cycle(proc, dll, i, cond_dir)
        cycles.append(row)
        if row["died_at"]:  # stop rule: a dead target
            break
    proc.communicate(input=b"stop\n", timeout=args.timeout)
    shutil.rmtree(cond_dir / "files")
    common.write_csv(cycles, cond_dir / "cycles.csv", CYCLE_COLUMNS)
    write_process(cond_dir, proc.pid, proc.returncode)

    died = next((c for c in cycles if c["died_at"]), None)
    common.log(f"  {cond_dir.name:<22} pid {proc.pid} exit {proc.returncode}, {len(cycles)} cycles, "
               f"{sum(c['ejected'] for c in cycles)} ejected"
               + (f", died at {died['died_at']} of cycle {died['cycle']}" if died else ""))


def build(mode: str) -> dict[str, Path]:
    common.log(f"Building target and hook DLLs ({POLICY[mode]})")
    common.compile_exe(EXP_DIR / "target.cpp", TARGET_EXE, libs=["ntdll.lib"])
    dll = hook_dll(mode)
    return common.transpile(POLICY[mode], dll.with_suffix(".cpp"), dll)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Multi-thread variant of E5: runner")
    p.add_argument("--mode", choices=["launch", "cycles"], default="launch",
                   help="launch: run A (hooked from the start); cycles: run B (live inject/eject)")
    p.add_argument("--threads", type=int, nargs="+",
                   help="Worker thread counts, one set of conditions each (default: 1 4 16 for launch, 16 for cycles)")
    p.add_argument("--rounds", type=int, default=100, help="Run A: rounds per worker (one round = 40 opens)")
    p.add_argument("--cycles", type=int, default=20, help="Run B: inject/eject cycles per run")
    p.add_argument("--drain-ms", type=int, default=2000,
                   help="Target's pause before exit, for the asynchronous logger (run A: also the time to read /metrics)")
    p.add_argument("--runs", type=int, default=1, help="Number of repetitions")
    p.add_argument("--timeout", type=float, default=120.0, help="Per-target timeout in seconds")
    p.add_argument("--skip-build", action="store_true", help="Reuse the binaries in build/")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    common.load_env()
    threads = args.threads or ([1, 4, 16] if args.mode == "launch" else [16])

    if args.skip_build:
        dll = hook_dll(args.mode)
        dlls = {e: dll.with_name(f"{dll.stem}_{e}{dll.suffix}") for e in common.policy_engines(POLICY[args.mode])}
    else:
        dlls = build(args.mode)
    engines = list(dlls)
    for path in [TARGET_EXE, *(dlls[e] for e in engines)]:
        if not path.is_file():
            print(f"Missing {path}: run without --skip-build", file=sys.stderr)
            return 2

    kind, run_condition = ("hooked", run_launch) if args.mode == "launch" else ("cycled", run_cycled)
    conditions = [(f"{kind}_{e}", dlls[e]) for e in engines]

    session = common.new_session(EXP_DIR)
    common.log(f"Session output: {session}")
    for i in range(1, args.runs + 1):
        common.log(f"=== Run {i}/{args.runs} ===")
        for t in threads:
            for name, dll in conditions:
                run_condition(session / f"run_{i:02d}" / f"{name}_t{t}", dll, t, args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
