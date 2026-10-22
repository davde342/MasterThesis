"""E5 analysis: checks a run.py session and writes run_NN/check.csv and, per session, summary.csv.

Expected outcome of each condition:
  baseline          every open in  results.csv succeeds: the test files are readable, so a failed open in a hooked
                    run can only come from the hook
  hooked_<engine>   every open has the verdict run.py expected (false denies = 0, missed denies = 0) and at least
                    one open is denied; hook.log has exactly one EVENT|deny line per denied open, in the same order,
                    from the ntdll function the API reaches, naming the same file, with a root handle exactly for
                    relative opens, and with status STATUS_ACCESS_DENIED (the on_deny return_value)

Reads only the files written by run.py, so a session can be re-analysed at any time.
Exit code 0 when every condition of every run passes.
"""

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "suite"))
import common  # noqa: E402

# ntdll function each  results API reaches (CreateFileW, _wfopen and std::ifstream all go through NtCreateFile)
NT_FUNCTION = {"CreateFileW": "NtCreateFile", "_wfopen": "NtCreateFile", "ifstream": "NtCreateFile",
               "NtCreateFile": "NtCreateFile", "NtOpenFile": "NtOpenFile"}
STATUS_ACCESS_DENIED = "0xc0000022"  # on_deny return_value in policy.yaml
COUNTS = ["opens", "denied", "false_denies", "missed_denies", "deny_events"]


def load_journal(cond_dir: Path) -> list[dict] | None:
    path = cond_dir / " results.csv"
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def event_matches(row: dict, event: dict) -> bool:
    """Does a deny event describe this denied open?"""
    final_component = event.get("name", "").rsplit("\\", 1)[-1]
    return (event.get("fn") == NT_FUNCTION[row["api"]]
            and final_component.lower() == row["file"].lower()
            and (event.get("root") != "0x0") == (row["form"] == "relative")
            and event.get("status") == STATUS_ACCESS_DENIED)


def check_condition(kind: str, rows: list[dict] | None, events: list[dict]) -> tuple[bool, str, dict]:
    """(passed, detail, counts)."""
    if rows is None:
        return False, "no  results.csv (crashed or timed out)", {c: "" for c in COUNTS}
    denied = [r for r in rows if r["observed"] == "deny"]
    counts = {
        "opens": len(rows),
        "denied": len(denied),
        "false_denies": sum(r["expected"] == "allow" and r["observed"] != "allow" for r in rows),
        "missed_denies": sum(r["expected"] == "deny" and r["observed"] != "deny" for r in rows),
        "deny_events": len(events),
    }
    wrong = [r for r in rows if r["observed"] != r["expected"]]
    if wrong:
        r = wrong[0]
        return False, (f"{counts['false_denies']} false denies, {counts['missed_denies']} missed denies, e.g. "
                       f"{r['api']} {r['form']} {r['file']}: expected {r['expected']}, observed {r['observed']} "
                       f"(status {r['status']})"), counts
    if kind == "hooked" and not denied:
        return False, "no open was denied: the denylist was not exercised", counts
    if len(events) != len(denied):
        return False, f"{len(denied)} denied opens but {len(events)} deny events in hook.log", counts
    mismatched = [(r, e) for r, e in zip(denied, events) if not event_matches(r, e)]
    if mismatched:
        r, e = mismatched[0]
        return False, (f"{len(mismatched)} deny events do not match their open, e.g. {r['api']} {r['form']} "
                       f"{r['file']} -> {e}"), counts
    if not denied:
        return True, f"all {len(rows)} opens allowed", counts
    return True, f"{len(denied)} of {len(rows)} opens denied, each with its deny event", counts


def analyse_run(run_dir: Path) -> list[dict]:
    rows = []
    for cond_dir in sorted(p for p in run_dir.iterdir() if p.is_dir()):
        kind = cond_dir.name.split("_")[0]
        events = common.parse_events(cond_dir / "hook.log", "deny")
        ok, detail, counts = check_condition(kind, load_journal(cond_dir), events)
        rows.append({"condition": cond_dir.name, "result": "PASS" if ok else "FAIL", **counts, "detail": detail})
    common.write_csv(rows, run_dir / "check.csv")
    return rows


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("session", type=Path, help="Session directory written by run.py (contains run_NN/)")
    session = p.parse_args().session.resolve()

    run_dirs = sorted(d for d in session.glob("run_*") if d.is_dir())
    if not run_dirs:
        print(f"No run_NN folders in {session}", file=sys.stderr)
        return 2

    by_condition = defaultdict(list)
    failed = []
    for run_dir in run_dirs:
        for row in analyse_run(run_dir):
            by_condition[row["condition"]].append(row)
            if row["result"] != "PASS":
                failed.append(f"{run_dir.name}/{row['condition']}: {row['detail']}")

    summary = []
    for condition, rows in by_condition.items():
        entry = {"condition": condition, "runs": len(rows), "passed": sum(r["result"] == "PASS" for r in rows)}
        for c in COUNTS:  # summed over the runs that wrote a  results
            entry[c] = sum(r[c] for r in rows if r[c] != "")
        summary.append(entry)
    common.write_csv(summary, session / "summary.csv")

    for line in failed:
        print(f"FAIL {line}")
    print("ALL PASS" if not failed else f"{len(failed)} condition(s) failed")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
