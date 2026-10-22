"""E2 analysis. Coverage breakdown per registry operation: HookDesigner hook log vs Sysinternals ProcMon (Ring 0).

Reads the output of run.py (<session>/run_NN/hooked/) and, for every ProcMon
operation, explains the difference to the number of events recorded by the hooks:

  procmon_total   all ProcMon rows of the target PID for that operation
  reparse         rows with Result == REPARSE. ProcMon logs a registry reparse twice (REPARSE, then the
                  final result) although the process issued one call, so these rows are duplicates.
  pre_attach      non-reparse rows before the attach point: activity that happened before the hooks were
                  installed (process / loader start-up), which no hook can observe.
  comparable      procmon_total - reparse - pre_attach: the rows the hooks had a chance to see.
  hook_events     events logged by the hooks mapped to that operation (see OP_MAP_*).
  delta           hook_events - comparable (negative = missed, positive = hook sees more than ProcMon).
  coverage        hook_events / comparable.

Operations with no hooked counterpart (e.g. RegCloseKey when NtClose is not hooked) are reported as
"(not hooked)" and belong outside the in-scope coverage, so that it only measures what the policy can
express. They stay in the table: they are a result, not noise.

The hook layer is detected from the logged function names: Nt* = native (ntdll) policy, otherwise the
Win32 (advapi32) policy.

Attach point. injector.cpp, with HOOKDESIGNER_ATTACH_MARKER=1 (set by run.py), opens the
non-existent key HKCU\\Software\\HookDesignerAttachMarker_<pid> after InitializeHooks returned and before the
target is resumed. ProcMon records it as a row of the injector process, which is removed from all counts; its
position among the rows is the attach point. A capture without the marker is skipped.

Per-call matching (native layer only). The counts above can hide a miss and an extra of the same type that
cancel out, so for the native (ntdll) policy every hook event is also paired with one ProcMon row by
operation, rebuilt key path, result and call order (match_calls.py, with its scope and assumptions).

Several runs. Given a session directory with two or more runs (run.py --runs N), every
run is analysed as above and a session summary is added: per operation the ProcMon rows, comparable rows,
hook events and coverage of every run, and whether the counts are the same in all runs.

Usage:
    python check.py <session_dir | run_dir> [--layer auto|native|win32]

Writes coverage_by_operation.csv next to each analysed capture (plus call_matching.csv for the native layer)
and, for a session, coverage_summary.csv in the session directory. Totals are not written; they follow from
these files: the in-scope coverage is hook_events / comparable summed over the hooked rows of
coverage_by_operation.csv, the per-call coverage is matched / (matched + missed) rows of call_matching.csv.
"""

import argparse
import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "suite"))
import common  # noqa: E402
from match_calls import CSV_ROW, match_calls, parse_native_log  # noqa: E402
from match_calls import records_for_csv as call_records_for_csv  # noqa: E402

# ProcMon operation -> hook functions that observe it. Empty tuple = no hook in the policy.
OP_MAP_NATIVE: dict[str, tuple[str, ...]] = {
    "RegOpenKey": ("NtOpenKey", "NtOpenKeyEx"),
    "RegCreateKey": ("NtCreateKey",),
    "RegQueryValue": ("NtQueryValueKey",),
    "RegSetValue": ("NtSetValueKey",),
    "RegDeleteValue": ("NtDeleteValueKey",),
    "RegDeleteKey": ("NtDeleteKey",),
    "RegEnumKey": ("NtEnumerateKey",),
    "RegEnumValue": ("NtEnumerateValueKey",),
    "RegQueryKey": ("NtQueryKey",),
    "RegSetInfoKey": ("NtSetInformationKey",),
    "RegCloseKey": ("NtClose",),  # NtClose filtered to tracked key handles
    "RegQueryKeySecurity": ("NtQuerySecurityObject",),  # filtered to tracked key handles
}

OP_MAP_WIN32: dict[str, tuple[str, ...]] = {
    "RegOpenKey": ("RegOpenKeyExW", "RegOpenKeyExA"),
    "RegCreateKey": ("RegCreateKeyExW", "RegCreateKeyExA"),
    "RegQueryValue": ("RegQueryValueExW", "RegQueryValueExA"),
    "RegSetValue": ("RegSetValueExW", "RegSetValueExA"),
    "RegDeleteValue": ("RegDeleteValueW", "RegDeleteValueA"),
    "RegDeleteKey": ("RegDeleteKeyW", "RegDeleteKeyA", "RegDeleteKeyExW", "RegDeleteKeyExA"),
    "RegEnumKey": ("RegEnumKeyExW", "RegEnumKeyExA"),
    "RegEnumValue": ("RegEnumValueW", "RegEnumValueA"),
    "RegQueryKey": ("RegQueryInfoKeyW", "RegQueryInfoKeyA"),
    "RegCloseKey": ("RegCloseKey",),
}

# Registry path opened by the injector right after InitializeHooks returned (EmitAttachMarker in injector.cpp)
ATTACH_MARKER = "HookDesignerAttachMarker_"

RE_LOG_EVENT = re.compile(r"\bEVENT\|(\w+)\|")


def read_hook_log(path: Path) -> list[str]:
    """Function names of the EVENT lines, in log order."""
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        return [m[1] for m in map(RE_LOG_EVENT.search, f) if m]


def read_procmon(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def split_marker(rows: list[dict]) -> tuple[list[dict], int | None]:
    """Remove the injector's attach-marker rows; returns (target rows, index of the first row after the marker).

    The marker is one ProcMon row of the injector process, so it is not target activity and must not be
    counted. The returned index is where it sat among the remaining rows (None when there is no marker)."""
    kept, cut = [], None
    for n, r in enumerate(rows):
        r[CSV_ROW] = n  # data-row index in procmon_capture.csv, for call_matching.csv (list indices shift without the marker)
        if ATTACH_MARKER in r.get("Path", ""):
            if cut is None:
                cut = len(kept)
            continue
        kept.append(r)
    return kept, cut


def build_table(rows: list[dict], hook_funcs: list[str], op_map: dict, attach_row: int) -> list[dict]:
    stats: dict[str, dict[str, int]] = {}
    for i, r in enumerate(rows):
        d = stats.setdefault(r["Operation"], {"total": 0, "reparse": 0, "pre_attach": 0, "comparable": 0})
        d["total"] += 1
        if r["Result"].strip().upper() == "REPARSE":
            d["reparse"] += 1
        elif i < attach_row:
            d["pre_attach"] += 1
        else:
            d["comparable"] += 1

    hook_counts: dict[str, int] = {}
    for fn in hook_funcs:
        hook_counts[fn] = hook_counts.get(fn, 0) + 1

    table = []
    for op in sorted(set(stats) | set(op_map), key=lambda o: (-stats.get(o, {}).get("total", 0), o)):
        pm = stats.get(op, {"total": 0, "reparse": 0, "pre_attach": 0, "comparable": 0})
        funcs = op_map.get(op, ())
        hooked = bool(funcs)
        hook_events = sum(hook_counts.get(fn, 0) for fn in funcs)
        table.append({
            "operation": op,
            "hooked_by": "+".join(funcs) if hooked else "(not hooked)",
            "procmon_total": pm["total"], "reparse": pm["reparse"],
            "pre_attach": pm["pre_attach"], "comparable": pm["comparable"],
            "hook_events": hook_events if hooked else 0,
            "delta": (hook_events - pm["comparable"]) if hooked else None,
            "coverage": (hook_events / pm["comparable"]) if hooked and pm["comparable"] else None,
        })
    return table


def analyse(run_dir: Path, layer_arg: str) -> dict | None:
    """Analyse one run, write its per-run files, and return the results for the session summary."""
    log_path, pm_path = run_dir / "registry_hook.log", run_dir / "procmon_capture.csv"
    if not log_path.is_file() or not pm_path.is_file():
        print(f"[skip] {run_dir}: missing registry_hook.log or procmon_capture.csv")
        return None
    rows, attach_row = split_marker(read_procmon(pm_path))
    if attach_row is None:
        print(f"[skip] {run_dir}: no attach marker in procmon_capture.csv (injector without EmitAttachMarker?)")
        return None
    hook_funcs = read_hook_log(log_path)
    layer = layer_arg
    if layer == "auto":
        layer = "native" if any(fn.startswith("Nt") for fn in hook_funcs) else "win32"
    op_map = OP_MAP_NATIVE if layer == "native" else OP_MAP_WIN32

    table = build_table(rows, hook_funcs, op_map, attach_row)
    common.write_csv(table, run_dir / "coverage_by_operation.csv")

    # Per-call matching (match_calls.py): native layer only, the Win32 log does not carry the key paths
    if layer == "native":
        calls = match_calls(rows, attach_row, parse_native_log(log_path), op_map)
        common.write_csv(call_records_for_csv(rows, calls, op_map), run_dir / "call_matching.csv")
    return {"run": run_dir.parent.name, "table": table}


# =========================================================================
# Session summary (several runs)
# =========================================================================
def summarise_session(session_dir: Path, results: list[dict]) -> None:
    runs = [r["run"] for r in results]
    ops: dict[str, dict] = {}
    for r in results:
        for row in r["table"]:
            o = ops.setdefault(row["operation"], {"hooked_by": row["hooked_by"], "comparable": [], "hook": [],
                                                  "procmon": [], "coverage": []})
            o["comparable"].append(row["comparable"])
            o["hook"].append(row["hook_events"])
            o["procmon"].append(row["procmon_total"])
            o["coverage"].append(row["coverage"])
    order = sorted(ops, key=lambda k: -max(ops[k]["procmon"]))

    # One row per operation, one column group per run
    fields = ["operation", "hooked_by"]
    for kind in ("procmon_total", "comparable", "hook_events", "coverage"):
        fields += [f"{kind}_{run}" for run in runs]
    fields += ["stable_across_runs"]
    csv_rows = []
    for k in order:
        o = ops[k]
        row = {"operation": k, "hooked_by": o["hooked_by"],
               "stable_across_runs": len(set(o["comparable"])) == 1 and len(set(o["hook"])) == 1}
        for i, run in enumerate(runs):
            row[f"procmon_total_{run}"] = o["procmon"][i]
            row[f"comparable_{run}"] = o["comparable"][i]
            row[f"hook_events_{run}"] = o["hook"][i]
            row[f"coverage_{run}"] = "" if o["coverage"][i] is None else f"{o['coverage'][i]:.6f}"
        csv_rows.append(row)
    common.write_csv(csv_rows, session_dir / "coverage_summary.csv", fields)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", type=Path, help="Session dir (contains run_NN/) or a run's hooked/ dir")
    p.add_argument("--layer", choices=["auto", "native", "win32"], default="auto")
    a = p.parse_args()

    is_single_run = (a.path / "procmon_capture.csv").is_file()
    targets = [a.path] if is_single_run else sorted(d for d in a.path.glob("run_*/hooked") if d.is_dir())
    if not targets:
        print(f"No hooked run directories under {a.path}", file=sys.stderr)
        return 1
    results = [analyse(t, a.layer) for t in targets]
    ok = [r for r in results if r is not None]
    if not is_single_run and len(ok) >= 2:
        summarise_session(a.path, ok)
    return 0 if len(ok) == len(targets) else 1


if __name__ == "__main__":
    sys.exit(main())
