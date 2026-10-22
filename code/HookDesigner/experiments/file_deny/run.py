"""E5 runner: file restriction (deny).

For every repetition and condition the runner creates the test files, runs the target (through
`injector.exe launch` when hooked), removes the files again and keeps only what check.py reads:

  <session>/run_NN/<condition>/
       results.csv   written by the target: one row per open (api, form, file, expected, observed, status)
      hook.log      written by the hook DLL into the target's working folder (hooked only)

Conditions per run:
  baseline          no hook   -> every open succeeds: the files are readable
  hooked_<engine>   hook DLL  -> exactly the opens of denylisted files are denied

The files are created here, not by the target: in a hooked run the hook is active from the target's first
instruction, so the target could not create the files it may not open.

No Administrator rights needed. Analyse with: python check.py <session>
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

EXP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXP_DIR.parent.parent / "suite"))
import common  # noqa: E402

BUILD_DIR = EXP_DIR / "build"
POLICY = EXP_DIR / "policy.yaml"
TARGET_EXE = BUILD_DIR / "filedeny_target.exe"
HOOK_DLL = BUILD_DIR / "filedeny_hook.dll"  # the transpiler suffixes it per engine

# Test files, created in <condition>/files (kFilesDir in target.cpp).
#   not_denied_1.txt  ends with a denied name: a suffix match would wrongly deny it
#   DENIED_2.TXT      a denied name in another case: NTFS names are case-insensitive, so the match must be too
FILES = ["allowed_1.txt", "not_denied_1.txt", "denied_1.txt", "DENIED_2.TXT"]
DENYLIST = {"denied_1.txt", "denied_2.txt"}  # must match kDenylist in logic.cpp (compared ignoring case)


# =========================================================================
# One condition
# =========================================================================
def run_condition(cond_dir: Path, dll: Path | None, args) -> None:
    files_dir = cond_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    target_args = []
    for name in FILES:
        (files_dir / name).write_text("HookDesigner E5 test file\n", encoding="utf-8")
        denied = dll is not None and name.lower() in DENYLIST
        target_args += ["--expect-deny" if denied else "--expect-allow", name]
    try:
        result = common.launch(TARGET_EXE, target_args, dll=dll, cwd=cond_dir, timeout=args.timeout)
    finally:
        shutil.rmtree(files_dir, ignore_errors=True)
    common.log(f"  {cond_dir.name:<16} pid {result.pid} exit {result.exit_code}")


# =========================================================================
# Main
# =========================================================================
def build() -> dict[str, Path]:
    common.log("Building target and hook DLLs")
    common.compile_exe(EXP_DIR / "target.cpp", TARGET_EXE, libs=["ntdll.lib"])
    return common.transpile(POLICY, BUILD_DIR / "filedeny_hook.cpp", HOOK_DLL)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="E5 file restriction runner")
    p.add_argument("--runs", type=int, default=1, help="Number of repetitions")
    p.add_argument("--engines", nargs="+", help="Subset of the policy's engines (default: all)")
    p.add_argument("--timeout", type=float, default=60.0, help="Per-target timeout in seconds")
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

    conditions = [("baseline", None)] + [(f"hooked_{e}", dlls[e]) for e in engines]

    session = common.new_session(EXP_DIR, args.out_dir)
    common.log(f"Session output: {session}")
    all_ok = True
    for i in range(1, args.runs + 1):
        common.log(f"=== Run {i}/{args.runs} ===")
        for name, dll in conditions:
            try:
                run_condition(session / f"run_{i:02d}" / name, dll, args)
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
                common.log(f"  {name}: ERROR {e}")
                all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
