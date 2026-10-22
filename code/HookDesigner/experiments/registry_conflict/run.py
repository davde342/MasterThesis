"""E3 runner: registry guard-rail (redirect).

For every repetition and condition the runner resets the test key, starts the instances (through
`injector.exe launch` when hooked), releases them together once all of them have opened the key, waits for
them and keeps only what check.py reads:
"""

import argparse
import ctypes
import json
import subprocess
import sys
import uuid
import winreg
from ctypes import wintypes
from pathlib import Path

EXP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXP_DIR.parent.parent / "suite"))
import common  # noqa: E402

BUILD_DIR = EXP_DIR / "build"
POLICY = EXP_DIR / "policy.yaml"
TARGET_EXE = BUILD_DIR / "guardrail_target.exe"
HOOK_DLL = BUILD_DIR / "guardrail_hook.dll"  # the transpiler suffixes it per engine

ROOT_KEY = r"Software\HookDesignerGuardrail"  # must match kSharedKey in target.cpp / kProtectedKey in logic.cpp
SHARED_KEY = ROOT_KEY + r"\Shared"
READY_TIMEOUT_MS = 30000
WAIT_OBJECT_0 = 0

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

#we need to define function signatures otherwise ctypes wrongly guess them
kernel32.CreateSemaphoreW.argtypes = [wintypes.LPVOID, wintypes.LONG, wintypes.LONG, wintypes.LPCWSTR]
kernel32.CreateSemaphoreW.restype = wintypes.HANDLE
kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateEventW.restype = wintypes.HANDLE
kernel32.SetEvent.argtypes = [wintypes.HANDLE]
kernel32.SetEvent.restype = wintypes.BOOL
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


# =========================================================================
# Registry
# =========================================================================
def delete_tree(subkey: str) -> None:
    """Delete HKCU\\<subkey> and everything below it (no-op when missing)."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_ALL_ACCESS)
    except FileNotFoundError:
        return
    with key:
        while True:
            try:
                child = winreg.EnumKey(key, 0)
            except OSError:
                break
            delete_tree(subkey + "\\" + child)
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)


def reset_registry() -> None:
    """Start every condition from the same state: only the shared key, with Counter = 0."""
    delete_tree(ROOT_KEY)
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, SHARED_KEY) as key:
        winreg.SetValueEx(key, "Counter", 0, winreg.REG_DWORD, 0)


def read_keys() -> dict:
    """{subkey name: Counter} for every key under the test root (None when Counter is missing)."""
    keys = {}
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, ROOT_KEY)
    except FileNotFoundError:
        return keys
    with root:
        index = 0
        while True:
            try:
                name = winreg.EnumKey(root, index)
            except OSError:
                break
            index += 1
            with winreg.OpenKey(root, name) as key:
                try:
                    keys[name] = winreg.QueryValueEx(key, "Counter")[0]
                except FileNotFoundError:
                    keys[name] = None
    return keys


# =========================================================================
# One condition
# =========================================================================
def run_condition(cond_dir: Path, instances: int, dll: Path | None, args) -> None:
    reset_registry()

    tag = uuid.uuid4().hex
    ready_name, start_name = f"Local\\HD_E3_ready_{tag}", f"Local\\HD_E3_start_{tag}"
    ready = kernel32.CreateSemaphoreW(None, 0, instances, ready_name)
    start = kernel32.CreateEventW(None, True, False, start_name)
    targets = []
    try:
        if not ready or not start:
            raise OSError(ctypes.get_last_error(), "CreateSemaphoreW / CreateEventW failed")
        for i in range(1, instances + 1):
            inst_dir = cond_dir / f"instance_{i}"
            inst_dir.mkdir(parents=True, exist_ok=True)
            target_args = ["--cycles", str(args.cycles), "--ready", ready_name, "--start", start_name]
            targets.append(common.start(TARGET_EXE, target_args, dll=dll, cwd=inst_dir))
        # Every instance has opened the key (so ownership is decided) before any of them starts the cycles
        for _ in range(instances):
            if kernel32.WaitForSingleObject(ready, READY_TIMEOUT_MS) != WAIT_OBJECT_0:
                raise RuntimeError("an instance did not open the key and signal ready in time")
        kernel32.SetEvent(start)
        results = [common.finish(t, args.timeout) for t in targets]
    except Exception:
        for t in targets:
            if t.proc.poll() is None:
                common.stop(t)
        raise
    finally:
        for handle in (ready, start):
            if handle:
                kernel32.CloseHandle(handle)

    keys = read_keys()
    (cond_dir / "keys.json").write_text(json.dumps(keys, indent=2) + "\n", encoding="utf-8")
    delete_tree(ROOT_KEY)
    exits = ", ".join(f"pid {r.pid} exit {r.exit_code}" for r in results)
    common.log(f"  {cond_dir.name:<16} {exits} | keys {keys}")


# =========================================================================
# Main
# =========================================================================
def build() -> dict[str, Path]:
    common.log("Building target and hook DLLs")
    common.compile_exe(EXP_DIR / "target.cpp", TARGET_EXE, libs=["advapi32.lib"])
    return common.transpile(POLICY, BUILD_DIR / "guardrail_hook.cpp", HOOK_DLL)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="E3 registry guard-rail runner")
    p.add_argument("--runs", type=int, default=1, help="Number of repetitions")
    p.add_argument("--cycles", type=int, default=10000, help="Read-increment-write cycles per instance (N)")
    p.add_argument("--engines", nargs="+", help="Subset of the policy's engines (default: all)")
    p.add_argument("--timeout", type=float, default=120.0, help="Per-instance timeout in seconds")
    p.add_argument("--skip-build", action="store_true", help="Reuse the binaries in build/")
    p.add_argument("--out-dir", type=Path, help="Session output directory (default: results/<timestamp>)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    common.load_env()

    if args.skip_build:
        dlls = {e: HOOK_DLL.with_name(f"{HOOK_DLL.stem}_{e}{HOOK_DLL.suffix}") for e in common.policy_engines(POLICY)}
    else:
        dlls = build()
    engines = args.engines or list(dlls)
    for path in [TARGET_EXE, *(dlls[e] for e in engines)]:
        if not path.is_file():
            print(f"Missing {path}: run without --skip-build", file=sys.stderr)
            return 2

    conditions = [("baseline", 2, None)]
    conditions += [(f"hooked_{e}", 2, dlls[e]) for e in engines]
    conditions += [(f"control_{e}", 1, dlls[e]) for e in engines]

    session = common.new_session(EXP_DIR, args.out_dir)
    common.log(f"Session output: {session}")
    all_ok = True
    for i in range(1, args.runs + 1):
        common.log(f"=== Run {i}/{args.runs} ===")
        for name, instances, dll in conditions:
            try:
                run_condition(session / f"run_{i:02d}" / name, instances, dll, args)
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
                common.log(f"  {name}: ERROR {e}")
                all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
