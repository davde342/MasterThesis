# HookDesigner (Ring 3, Detours + spdlog) vs Sysinternals ProcMon (Ring 0).

import argparse
import csv
import ctypes
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

EXP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXP_DIR.parent.parent / "suite"))
import common  # noqa: E402

BUILD_DIR = EXP_DIR / "build"
TARGET_EXE = BUILD_DIR / "registry_target.exe"
HOOK_LOG_NAME = "registry_hook.log"  # hard-coded in the generated DLL (basic_file_sink_mt, relative path)

# --layer -> (policy, hook DLL)
LAYERS = {
    "native": (EXP_DIR / "policy.yaml", BUILD_DIR / "registry_hook_native.dll"),
    "win32": (EXP_DIR / "policy_win32.yaml", BUILD_DIR / "registry_hook_win32.dll"),
}

PROCMON_CANDIDATES = ("Procmon64.exe", "Procmon.exe")
PROCMON_START_TIMEOUT_S = 30
PROCMON_STOP_TIMEOUT_S = 60
PROCMON_EXPORT_TIMEOUT_S = 300

# Opt-in injector marker (see EmitAttachMarker in injector.cpp): one RegOpenKey of the injector process on
# HKCU\Software\HookDesignerAttachMarker_<target pid>, issued after InitializeHooks returned and before the
# target is resumed. check.py uses its position as the attach point.
ATTACH_MARKER_ENV = "HOOKDESIGNER_ATTACH_MARKER"
ATTACH_MARKER = "HookDesignerAttachMarker_"


# =========================================================================
# Helpers
# =========================================================================
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def resolve_procmon(cli_value: str | None) -> Path:
    candidates = []
    if cli_value:
        candidates.append(Path(cli_value))
    if os.environ.get("PROCMON_PATH"):
        candidates.append(Path(os.environ["PROCMON_PATH"]))
    for name in PROCMON_CANDIDATES:
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
        candidates.append(EXP_DIR / name)

    for c in candidates:
        if c.is_dir():
            for name in PROCMON_CANDIDATES:
                if (c / name).is_file():
                    return (c / name).resolve()
        elif c.is_file():
            return c.resolve()
    raise FileNotFoundError(
        "ProcMon not found. Pass --procmon <path>, set PROCMON_PATH, or put Procmon64.exe on PATH."
    )


# =========================================================================
# ProcMon control
# =========================================================================
class ProcMon:
    # Bypass the user's persisted ProcMon filter (stored in HKCU) so the capture is reproducible;
    # PID/operation filtering is done afterwards in Python.
    FILTER_ARGS = ["/NoFilter"]

    def __init__(self, exe: Path):
        self.exe = exe
        self.proc: subprocess.Popen | None = None

    def _run(self, args: list[str], timeout: float) -> int:
        return subprocess.run([str(self.exe), *args], timeout=timeout,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode

    def terminate_stale(self) -> None:
        # A second ProcMon instance would attach to the already-running driver session
        # and write into the *other* backing file; make sure we own the capture.
        try:
            self._run(["/AcceptEula", "/Terminate"], timeout=PROCMON_STOP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            common.log("WARNING: stale ProcMon /Terminate timed out")

    def start(self, backing_file: Path) -> None:
        args = [str(self.exe), "/AcceptEula", "/Quiet", "/Minimized",
                "/BackingFile", str(backing_file), *self.FILTER_ARGS]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # /WaitForIdle blocks until the running instance is ready to capture.
        try:
            self._run(["/AcceptEula", "/WaitForIdle"], timeout=PROCMON_START_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            raise RuntimeError("ProcMon did not become idle/ready in time")

    def stop(self) -> None:
        try:
            self._run(["/Terminate"], timeout=PROCMON_STOP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            common.log("WARNING: ProcMon /Terminate timed out")
        if self.proc:
            try:
                self.proc.wait(timeout=PROCMON_STOP_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None

    def export_csv(self, pml: Path, csv_out: Path) -> None:
        args = ["/AcceptEula", "/Quiet", "/OpenLog", str(pml), "/SaveAs", str(csv_out), *self.FILTER_ARGS]
        self._run(args, timeout=PROCMON_EXPORT_TIMEOUT_S)
        if not csv_out.exists():
            raise RuntimeError(f"ProcMon export did not produce {csv_out}")


def filter_procmon_csv(raw_csv: Path, out_csv: Path, pid: int, injector_pid: int) -> tuple[int, bool]:
    """Keep the registry operations (Reg*) issued by the target PID, plus the injector's attach-marker row.

    Returns (number of target rows kept, marker row found)."""
    kept = 0
    marker_found = False
    with open(raw_csv, "r", encoding="utf-8-sig", newline="") as fin, \
         open(out_csv, "w", encoding="utf-8", newline="") as fout:
        reader = csv.DictReader(fin)
        if not reader.fieldnames or "Operation" not in reader.fieldnames or "PID" not in reader.fieldnames:
            raise RuntimeError(f"Unexpected ProcMon CSV header: {reader.fieldnames}")
        writer = csv.DictWriter(fout, fieldnames=reader.fieldnames)
        writer.writeheader()
        for row in reader:
            if not row["Operation"].startswith("Reg"):
                continue
            if row["PID"].strip() == str(injector_pid) and ATTACH_MARKER in row.get("Path", ""):
                writer.writerow(row)
                marker_found = True
                continue
            if row["PID"].strip() != str(pid):
                continue
            writer.writerow(row)
            kept += 1
    return kept, marker_found


def count_hook_events(path: Path) -> int:
    """Number of EVENT lines in the hook log (0 when it is missing)."""
    if not path.exists():
        return 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return sum("EVENT|" in line for line in f)


# =========================================================================
# One capture
# =========================================================================
def capture(run_dir: Path, dll: Path, args, procmon: ProcMon) -> bool:
    """Run one hooked capture into run_dir; returns True when the capture is usable for the analysis."""
    run_dir.mkdir(parents=True, exist_ok=True)
    pml = run_dir / "procmon_raw.pml"
    raw_csv = run_dir / "procmon_raw.csv"
    cap_csv = run_dir / "procmon_capture.csv"
    hook_log = run_dir / HOOK_LOG_NAME
    ok, warnings = True, []

    common.log(f"  starting ProcMon capture -> {pml.name}")
    procmon.start(pml)
    try:
        time.sleep(args.pre_delay)
        # The target inherits the injector's CWD, so the DLL writes registry_hook.log into run_dir.
        target = common.start(args.target, args.target_args, dll=dll, cwd=run_dir)
        common.log(f"  launched: {subprocess.list2cmdline(target.proc.args)}")
        result = common.finish(target, args.timeout)
        time.sleep(args.post_delay)
    finally:
        common.log("  stopping ProcMon")
        procmon.stop()
    injector_pid = target.proc.pid  # the attach-marker row is issued by the injector

    if result.exit_code != 0:
        ok = False
        warnings.append(f"target exit code {result.exit_code} (launcher rc {target.proc.returncode})")

    common.log("  exporting PML -> CSV")
    procmon.export_csv(pml, raw_csv)
    registry_rows, marker_found = filter_procmon_csv(raw_csv, cap_csv, result.pid, injector_pid)
    if registry_rows == 0:
        ok = False
        warnings.append("ProcMon captured 0 registry rows for the target PID")
    if not marker_found:
        ok = False
        warnings.append("attach marker missing: rebuild the injector (EmitAttachMarker); "
                        "check.py will skip this run")

    # The injector waits for the target to exit before returning, so the hook log is already complete here
    hook_events = count_hook_events(hook_log)
    if hook_events == 0:
        ok = False
        warnings.append(f"{HOOK_LOG_NAME} missing or contains no EVENT lines")

    for p in (pml, raw_csv):
        p.unlink(missing_ok=True)

    common.log(f"  {'OK' if ok else 'FAILED'}: pid={result.pid} exit={result.exit_code} "
               f"procmon_reg={registry_rows} marker={'yes' if marker_found else 'no'} hook_events={hook_events}")
    for w in warnings:
        common.log(f"  WARNING: {w}")
    return ok


# =========================================================================
# Main
# =========================================================================
def build(policy: Path, dll: Path) -> None:
    common.log("Building target and hook DLL")
    common.compile_exe(EXP_DIR / "target.cpp", TARGET_EXE, libs=["advapi32.lib"])
    common.transpile(policy, dll.with_suffix(".cpp"), dll)  # single engine: no _<engine> suffix


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="E2 HookDesigner vs ProcMon registry comparison runner")
    p.add_argument("--layer", choices=list(LAYERS), default="native",
                   help="Hook layer: native = policy.yaml (ntdll), win32 = policy_win32.yaml (advapi32)")
    p.add_argument("--procmon", help="Path to Procmon64.exe / Procmon.exe or its directory "
                                     "(default: $PROCMON_PATH, PATH, script dir)")
    p.add_argument("--target", type=Path, default=TARGET_EXE,
                   help="Program to launch (default: the built target.cpp; e.g. C:\\Windows\\System32\\reg.exe)")
    p.add_argument("--runs", type=int, default=1, help="Number of repetitions")
    p.add_argument("--timeout", type=float, default=120.0, help="Per-target timeout in seconds")
    p.add_argument("--pre-delay", type=float, default=1.0, help="Seconds between capture start and launch")
    p.add_argument("--post-delay", type=float, default=1.0, help="Seconds between target exit and capture stop")
    p.add_argument("--skip-build", action="store_true", help="Reuse the binaries in build/")
    p.add_argument("--out-dir", type=Path, help="Session output directory (default: results/<timestamp>)")
    p.add_argument("--target-args", nargs=argparse.REMAINDER, default=[],
                   help='Everything after this flag is passed to the target as separate arguments, so '
                        'it must be the LAST option (e.g. --target-args query "HKLM\\SOFTWARE\\Windows NT" /s)')
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if not is_admin():
        print("ProcMon needs to load its kernel driver: run this script from an elevated (Administrator) shell.",
              file=sys.stderr)
        return 2

    try:
        procmon_exe = resolve_procmon(args.procmon)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 2

    common.load_env()
    policy, dll = LAYERS[args.layer]
    if not args.skip_build:
        build(policy, dll)
    args.target = args.target.resolve()
    for path in (common.INJECTOR, args.target, dll):
        if not path.is_file():
            print(f"Missing {path}", file=sys.stderr)
            return 2

    # Read by injector.exe only
    os.environ[ATTACH_MARKER_ENV] = "1"

    session = common.new_session(EXP_DIR, args.out_dir)
    common.log(f"Session output: {session}")
    common.log(f"ProcMon: {procmon_exe}")
    procmon = ProcMon(procmon_exe)
    procmon.terminate_stale()

    all_ok = True
    try:
        for i in range(1, args.runs + 1):
            common.log(f"=== Run {i}/{args.runs} ===")
            try:
                all_ok &= capture(session / f"run_{i:02d}" / "hooked", dll, args, procmon)
            except (RuntimeError, subprocess.TimeoutExpired) as e:
                common.log(f"  ERROR: {e}")
                all_ok = False
    except KeyboardInterrupt:
        common.log("Interrupted, stopping ProcMon")
        procmon.stop()
        all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
