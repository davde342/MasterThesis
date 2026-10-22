"""Shared helpers for the HookDesigner evaluation experiments (experiments/*/run.py and check.py).

Only what at least two experiments need. Each helper comes from code that already produced thesis results
(source noted per function). E2 (experiments/registry_fidelity) now uses them too, so its check.py must still
regenerate its existing CSVs byte-identically.
"""

import csv
import datetime as dt
import os
import re
import statistics
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
TRANSPILER = REPO_ROOT / "transpiler.py"
INJECTOR = REPO_ROOT / "injector.exe"

# Injector output lines (from E2's former run_registry_comparison.py)
RE_INJECTOR_PID = re.compile(r"launched process suspended\. PID:\s*(\d+)")
RE_INJECTOR_EXIT = re.compile(r"Process exited with code:\s*(-?\d+)")


def log(msg: str) -> None:
    print(f"{msg}", flush=True)


# =========================================================================
# Environment and build
# =========================================================================
def load_env() -> None:
    """Load <repo>/.env into os.environ without overriding existing variables (benchmarks/runner/bench_runner.py)."""
    env_path = REPO_ROOT / ".env"
    if not env_path.exists():
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def _run_shell(cmd: str, cwd: Path) -> None:
    """Run a cmd.exe command line; print its output and raise on failure (bench_runner.execute_shell)."""
    cwd.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(cmd, shell=True, cwd=str(cwd), capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        raise RuntimeError(f"command failed with exit code {proc.returncode}: {cmd}")


def compile_exe(src: Path, out: Path, libs=(), defines=()) -> Path:
    """Compile a single-file x64 test target with MSVC (flags as the bench_runner.py targets)."""
    vcvars = os.environ.get("VCVARS64_PATH", "")
    if not Path(vcvars).is_file():
        raise RuntimeError("VCVARS64_PATH is not set to an existing vcvars64.bat (see .env.example)")
    out.parent.mkdir(parents=True, exist_ok=True)
    args = ["cl.exe", "/nologo", "/O2", "/EHsc", "/std:c++17",
            *[f"/D{d}" for d in defines], str(src), *libs,
            f"/Fe:{out}", f"/Fo:{out.with_suffix('.obj')}"]
    _run_shell(f'call "{vcvars}" && {subprocess.list2cmdline(args)}', out.parent)
    return out


def policy_engines(policy: Path) -> list[str]:
    """Engines listed in a policy, in the order the transpiler processes them."""
    with open(policy, "r", encoding="utf-8") as f:
        engines = (yaml.safe_load(f).get("configure") or {}).get("engines", ["detours"])
    return [engines.lower()] if isinstance(engines, str) else [e.lower() for e in engines]


def transpile(policy: Path, out_cpp: Path, out_dll: Path, arch: str = "x64") -> dict[str, Path]:
    """Generate and compile the hook DLL(s) of a policy with transpiler.py; returns {engine: dll}.

    With several engines the transpiler suffixes the outputs with the engine name (README)."""
    out_dll.parent.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(TRANSPILER), str(policy),
           "--output-cpp", str(out_cpp), "--output-dll", str(out_dll), "--arch", arch]
    proc = subprocess.run(cmd, cwd=str(out_dll.parent), capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        raise RuntimeError(f"transpiler failed for {policy}")
    engines = policy_engines(policy)
    if len(engines) == 1:
        return {engines[0]: out_dll}
    return {e: out_dll.with_name(f"{out_dll.stem}_{e}{out_dll.suffix}") for e in engines}


# =========================================================================
# Target execution
# =========================================================================
@dataclass
class Target:
    proc: subprocess.Popen
    hooked: bool


@dataclass
class TargetResult:
    pid: int
    exit_code: int | None
    stdout: str
    stderr: str


def start(exe: Path, args=(), dll: Path | None = None, cwd: Path | None = None) -> Target:
    """Start a target without waiting: through `injector.exe launch` when `dll` is given (hooks installed
    before the first instruction), directly otherwise (unhooked baseline). The target inherits `cwd`, so
    a hook DLL with a relative log file writes it there."""
    cmd = [str(INJECTOR), "launch", str(exe), str(dll), *args] if dll else [str(exe), *args]
    proc = subprocess.Popen(cmd, cwd=str(cwd) if cwd else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return Target(proc, dll is not None)


def stop(target: Target) -> None:
    """Kill a target and, when hooked, the injector that waits for it."""
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(target.proc.pid)], capture_output=True)


def finish(target: Target, timeout: float) -> TargetResult:
    """Wait for a started target; returns its PID and exit code (E2's former run_target)."""
    try:
        out, err = target.proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # The target is a child of the injector and holds the write end of our pipes:
        # killing only the injector would leave communicate() blocked until the target exits.
        stop(target)
        try:
            target.proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        raise
    out = out.decode("utf-8", errors="replace")
    err = err.decode("utf-8", errors="replace")
    if not target.hooked:
        return TargetResult(target.proc.pid, target.proc.returncode, out, err)
    m_pid = RE_INJECTOR_PID.search(out)
    if not m_pid:
        raise RuntimeError(f"target PID not found in the injector output: {(out + err)[-500:]!r}")
    m_exit = RE_INJECTOR_EXIT.search(out)
    return TargetResult(int(m_pid.group(1)), int(m_exit.group(1)) if m_exit else None, out, err)


def launch(exe: Path, args=(), dll: Path | None = None, cwd: Path | None = None,
           timeout: float = 120.0) -> TargetResult:
    """start() + finish()."""
    return finish(start(exe, args, dll, cwd), timeout)


# =========================================================================
# Results
# =========================================================================
def new_session(exp_dir: Path, out_dir: Path | None = None) -> Path:
    """Create the session folder <exp_dir>/results/<timestamp> (or out_dir)."""
    session = (out_dir or exp_dir / "results" / dt.datetime.now().strftime("%Y%m%d_%H%M%S")).resolve()
    session.mkdir(parents=True, exist_ok=True)
    return session


def parse_events(hook_log: Path, event: str) -> list[dict]:
    """EVENT|<event>|key=value|... lines of a hook log as dicts, in log order; empty when the log is missing
    (E3's redirect and E5's deny events; from E3's check.py)."""
    marker = f"EVENT|{event}|"
    events = []
    if not hook_log.exists():
        return events
    with open(hook_log, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            idx = line.find(marker)
            if idx < 0:
                continue
            fields = line[idx:].rstrip("\r\n").split("|")[2:]
            events.append(dict(field.split("=", 1) for field in fields if "=" in field))
    return events


def write_csv(rows: list[dict], csv_path: Path, fieldnames: list[str] | None = None) -> None:
    """Write rows as CSV; the columns are the keys of the first row unless `fieldnames` is given."""
    columns = fieldnames or (list(rows[0].keys()) if rows else [])
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def mean_sd(values: list[float]) -> tuple[float, float]:
    """Mean and sample standard deviation (0 for fewer than two values)."""
    if not values:
        return 0.0, 0.0
    return statistics.fmean(values), statistics.stdev(values) if len(values) > 1 else 0.0
