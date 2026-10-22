"""E3 analysis: checks a run.py session and writes run_NN/check.csv and, per session, summary.csv.

Expected outcome of each condition (N = cycles per instance):
  baseline          the two instances share the key, so it ends below 2N: lost updates, the race to prevent
  hooked_<engine>   one instance has no redirect events and the original key ends at N; the other one's
                    redirect events all point to Shared_<its pid>, which also ends at N; no other keys
  control_<engine>  a single hooked instance is never redirected and the original key ends at N

Reads only the files written by run.py (never the registry), so a session can be re-analysed at any time.
Exit code 0 when every condition of every run passes.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "suite"))
import common  # noqa: E402

ORIGINAL = "Shared"


def load_instances(cond_dir: Path) -> list[dict]:
    instances = []
    for inst_dir in sorted(cond_dir.glob("instance_*")):
        result_path = inst_dir / "result.json"
        result = json.loads(result_path.read_text(encoding="utf-8")) if result_path.exists() else None
        instances.append({"name": inst_dir.name, "result": result, "events": common.parse_events(inst_dir / "hook.log", "redirect")})
    return instances


def check_condition(kind: str, instances: list[dict], keys: dict) -> tuple[bool, str, float | None]:
    """(passed, detail, lost-update rate for the baseline)."""
    expected_instances = 1 if kind == "control" else 2
    if len(instances) != expected_instances:
        return False, f"{len(instances)} instances, expected {expected_instances}", None
    for inst in instances:
        if inst["result"] is None:
            return False, f"{inst['name']} wrote no result.json (crashed or timed out)", None
        if inst["result"]["errors"]:
            return False, f"{inst['name']} reported {inst['result']['errors']} registry errors", None
    n = instances[0]["result"]["cycles"]
    original = keys.get(ORIGINAL)
    copies = {k: v for k, v in keys.items() if k != ORIGINAL}

    if kind == "baseline":
        if copies:
            return False, f"unexpected keys without hook: {copies}", None
        if original is None:
            return False, "original key missing", None
        lost = 2 * n - original
        rate = lost / (2 * n)
        detail = f"{ORIGINAL}={original} of {2 * n}: {lost} updates lost ({rate:.1%})"
        return lost > 0, detail if lost > 0 else detail + ", race not visible: raise --cycles", rate

    owners = [i for i in instances if not i["events"]]
    redirected = [i for i in instances if i["events"]]

    if kind == "control":
        ok = not redirected and keys == {ORIGINAL: n}
        return ok, f"redirect events: {sum(len(i['events']) for i in redirected)}, keys {keys}", None

    # hooked
    if len(owners) != 1 or len(redirected) != 1:
        return False, f"{len(owners)} instances kept the original key and {len(redirected)} were redirected, expected 1 and 1", None
    owner, other = owners[0], redirected[0]
    copy = f"{ORIGINAL}_{other['result']['pid']}"
    wrong = [e for e in other["events"]
             if not re.search(rf"\\{re.escape(copy)}(\\|$)", e.get("to", ""), re.I) or e.get("status") != "0x0"]
    if wrong:
        return False, f"{other['name']}: {len(wrong)} redirect events not to {copy} or failed, e.g. {wrong[0]}", None
    if keys != {ORIGINAL: n, copy: n}:
        return False, f"keys {keys}, expected {{{ORIGINAL}: {n}, {copy}: {n}}}", None
    detail = (f"pid {owner['result']['pid']} kept {ORIGINAL}={original}; pid {other['result']['pid']} "
              f"redirected to {copy}={keys[copy]} ({len(other['events'])} redirected opens)")
    return True, detail, None


def analyse_run(run_dir: Path) -> list[dict]:
    rows = []
    for cond_dir in sorted(p for p in run_dir.iterdir() if p.is_dir()):
        kind = cond_dir.name.split("_")[0]
        keys_path = cond_dir / "keys.json"
        keys = json.loads(keys_path.read_text(encoding="utf-8")) if keys_path.exists() else {}
        ok, detail, rate = check_condition(kind, load_instances(cond_dir), keys)
        rows.append({"condition": cond_dir.name, "result": "PASS" if ok else "FAIL", "detail": detail,
                     "lost_update_rate": "" if rate is None else f"{rate:.4f}"})
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
        rates = [float(r["lost_update_rate"]) for r in rows if r["lost_update_rate"]]
        mean, sd = common.mean_sd(rates)
        summary.append({
            "condition": condition,
            "runs": len(rows),
            "passed": sum(r["result"] == "PASS" for r in rows),
            "lost_updates_mean": f"{mean:.1%}" if rates else "-",
            "lost_updates_sd": f"{sd:.1%}" if rates else "-",
        })
    common.write_csv(summary, session / "summary.csv")

    for line in failed:
        print(f"FAIL {line}")
    print("ALL PASS" if not failed else f"{len(failed)} condition(s) failed")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
