import argparse
import csv
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "suite"))
import common 


NT_FUNCTION = {"CreateFileW": "NtCreateFile", "_wfopen": "NtCreateFile", "ifstream": "NtCreateFile",
               "NtCreateFile": "NtCreateFile", "NtOpenFile": "NtOpenFile"}
STATUS_ACCESS_DENIED = "0xc0000022"  # on_deny return_value in E5's policy.yaml
DENY_CODE = {"CreateFileW": "5", "_wfopen": "13", "ifstream": "13",
             "NtCreateFile": STATUS_ACCESS_DENIED, "NtOpenFile": STATUS_ACCESS_DENIED}
NATIVE = {"NtCreateFile", "NtOpenFile"}
LAST_ERROR_MARK = 0x20000001  
QUEUE_SIZE = 65536

# A6: the counter lines of metrics.txt, e.g. hook_metric_NtOpenFile_opens_total{verdict="denied"} 4
RE_COUNTER = re.compile(r'^hook_metric_(\w+)_opens_total\{verdict="(allowed|denied)"\} (\S+)$')

# denied, deny_events, unpaired, last_error_changed and log_error_unchanged are also run B columns; listed once, so
# that they are not written twice
A_COUNTS = ["opens", "denied", "missed_denies", "false_denies", "wrong_codes", "deny_events", "unpaired",
            "counted_denies", "counted_allows", "last_error_changed", "log_error_unchanged"]
B_COUNTS = ["cycles", "injected", "ejected", "leaked", "dll_unloaded", "allow_denied", "logs_without_event",
            "probe_not_allowed", "errors", "worker_opens", "window_blocked", "window_missed"]


def read_csv(path: Path) -> list[dict] | None:
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def event_matches(row: dict, event: dict) -> bool:
    """Copied from E5's check.py: does a deny event describe this denied open?"""
    final_component = event["name"].rsplit("\\", 1)[-1]
    return (event["fn"] == NT_FUNCTION[row["api"]]
            and final_component.lower() == row["file"].lower()
            and (event["root"] != "0x0") == (row["form"] == "relative")
            and event["status"] == STATUS_ACCESS_DENIED)


def read_counter(path: Path) -> dict[tuple[str, str], int]:
    """A6: {(function, verdict): count} from metrics.txt. prometheus-cpp writes the values with 16 significant
    digits, so the counts are exact."""
    counts = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = RE_COUNTER.match(line)
        if m:
            counts[(m[1], m[2])] = int(float(m[3]))
    return counts


def exit_code_of(cond_dir: Path) -> str:
    return read_csv(cond_dir / "process.csv")[0]["exit_code"]


# =========================================================================
# Run A
# =========================================================================
def log_error_kept(event: dict) -> bool:
    """A8: does a deny event show no change of the last-error code (its last_error field is the mark)?"""
    return int(event["last_error"], 16) == LAST_ERROR_MARK


def pair_events(by_tid: dict[str, list[dict]], events: list[dict]) -> tuple[int, str, int]:
    """A4, B9: the number of denied opens and deny events that do not pair one by one within their thread, and a
    description of the first such thread. A8, B10: the number of pairs of a native denied open whose event shows
    that the hook code did not change the last-error code."""
    events_by_tid = defaultdict(list)
    for e in events:
        events_by_tid[e["tid"]].append(e)
    unpaired, first, error_unchanged = 0, "", 0
    for tid in sorted(by_tid.keys() | events_by_tid.keys()):
        denied = [r for r in by_tid.get(tid, []) if r["observed"] == "deny"]
        evs = events_by_tid.get(tid, [])
        bad = [k for k, (r, e) in enumerate(zip(denied, evs)) if not event_matches(r, e)]
        unpaired += abs(len(denied) - len(evs)) + len(bad)
        error_unchanged += sum(r["api"] in NATIVE and log_error_kept(e) for r, e in zip(denied, evs))
        if first:
            continue
        if tid not in by_tid:
            first = f"{len(evs)} deny events from thread {tid}, which is not a worker"
        elif len(denied) != len(evs):
            first = f"thread {tid}: {len(denied)} denied opens but {len(evs)} deny events"
        elif bad:
            r, e = denied[bad[0]], evs[bad[0]]
            first = f"thread {tid}: deny event {bad[0]} does not match {r['api']} {r['form']} {r['file']} -> {e}"
    return unpaired, first, error_unchanged


def check_counter(rows: list[dict], metrics: dict[tuple[str, str], int], counts: dict, failures: list[str]) -> None:
    """A6: compare each hook function's opens_total counter with the journal; adds counts and failures."""
    counts["counted_denies"] = sum(n for (_, verdict), n in metrics.items() if verdict == "denied")
    counts["counted_allows"] = sum(n for (_, verdict), n in metrics.items() if verdict == "allowed")
    for fn in sorted(set(NT_FUNCTION.values())):
        journal_denies = sum(r["observed"] == "deny" and NT_FUNCTION[r["api"]] == fn for r in rows)
        journal_allows = sum(r["observed"] == "allow" and NT_FUNCTION[r["api"]] == fn for r in rows)
        denies, allows = metrics[(fn, "denied")], metrics[(fn, "allowed")]
        if denies != journal_denies:
            failures.append(f"A6: {fn} counted {denies} denied calls, the journal has {journal_denies}")
        if allows < journal_allows:
            failures.append(f"A6: {fn} counted {allows} allowed calls, fewer than the journal's {journal_allows}")


def group_by_tid(rows: list[dict]) -> dict[str, list[dict]]:
    """Journal rows per thread, in seq order (A4, B9)."""
    by_tid = defaultdict(list)
    for r in rows:
        by_tid[r["tid"]].append(r)
    for tid_rows in by_tid.values():
        tid_rows.sort(key=lambda r: int(r["seq"]))
    return by_tid


def check_journal(threads: int, rows: list[dict], events: list[dict], metrics: dict[tuple[str, str], int],
                  exit_code: str) -> tuple[bool, str, dict]:
    """(passed, detail, counts) of a run A condition."""
    by_tid = group_by_tid(rows)
    denied = [r for r in rows if r["observed"] == "deny"]
    native = [r for r in rows if r["api"] in NATIVE]
    unpaired, unpaired_detail, log_error_unchanged = pair_events(by_tid, events)
    counts = {
        "opens": len(rows),
        "denied": len(denied),
        "missed_denies": sum(r["expected"] == "deny" and r["observed"] != "deny" for r in rows),
        "false_denies": sum(r["expected"] == "allow" and r["observed"] != "allow" for r in rows),
        "wrong_codes": sum(r["status"] != DENY_CODE[r["api"]] for r in denied),
        "deny_events": len(events),
        "unpaired": unpaired,
        "last_error_changed": sum(int(r["last_error"], 16) != LAST_ERROR_MARK for r in native),
        "exit_code": exit_code,
        "log_error_unchanged": log_error_unchanged,
    }

    failures = []
    sizes = Counter(len(v) for v in by_tid.values())
    if len(by_tid) != threads or len(sizes) != 1 or not rows:
        failures.append(f"journal incomplete: {len(by_tid)} of {threads} workers, opens per worker {dict(sizes)}")
    if not any(r["expected"] == "deny" for r in rows):
        failures.append("no open expected deny: the denylist was not exercised")
    if counts["missed_denies"]:
        r = next(r for r in rows if r["expected"] == "deny" and r["observed"] != "deny")
        failures.append(f"A1: {counts['missed_denies']} missed denies, e.g. {r['api']} {r['form']} {r['file']} "
                        f"observed {r['observed']} (status {r['status']})")
    if counts["false_denies"]:
        r = next(r for r in rows if r["expected"] == "allow" and r["observed"] != "allow")
        failures.append(f"A2: {counts['false_denies']} false denies, e.g. {r['api']} {r['form']} {r['file']} "
                        f"observed {r['observed']} (status {r['status']})")
    if counts["wrong_codes"]:
        r = next(r for r in denied if r["status"] != DENY_CODE[r["api"]])
        failures.append(f"A3: {counts['wrong_codes']} denied opens with another code, e.g. {r['api']} {r['status']}")
    if unpaired:
        failures.append(f"A4: {unpaired} unpaired, {unpaired_detail}")
    if exit_code != "0":
        failures.append(f"A5: exit code {exit_code}")
    check_counter(rows, metrics, counts, failures)
    if counts["last_error_changed"]:
        r = next(r for r in native if int(r["last_error"], 16) != LAST_ERROR_MARK)
        failures.append(f"A7: {counts['last_error_changed']} native opens changed the last-error code, e.g. "
                        f"{r['api']} {r['form']} {r['file']} observed {r['observed']} -> {r['last_error']}")
    if log_error_unchanged:
        failures.append(f"A8: {log_error_unchanged} deny events of native opens show the mark: the hook code did not "
                        f"change the last-error code, so A7 does not test the error guard")
    if failures:
        return False, "; ".join(failures), counts
    return True, (f"{len(denied)} of {len(rows)} opens of {len(by_tid)} threads denied, "
                  f"each with its deny event in its thread's order and counted by the metrics"), counts


# Run B
def check_counts(threads: int, rows: list[dict] | None, cycles: list[dict], cond_dir: Path,
                 exit_code: str) -> tuple[bool, str, dict]:
    """(passed, detail, counts) of a run B condition. rows is None when the target died before it wrote counts.csv."""
    died = next((c for c in cycles if c["died_at"]), None)
    counts = {
        "cycles": len(cycles),
        "injected": sum(c["injected"] == "1" for c in cycles),
        "ejected": sum(c["ejected"] == "1" for c in cycles),
        "leaked": sum(c["leaked"] == "1" for c in cycles),
        "dll_unloaded": sum(c["dll_unloaded"] == "1" for c in cycles),
        "died_at": f"{died['died_at']} of cycle {died['cycle']}" if died else "",
        "exit_code": exit_code,
    }
    failures = []
    if died or exit_code != "0":
        failures.append(f"B1: died at {counts['died_at']}, exit code {exit_code}")
    if rows is None:
        failures.append("no counts.csv")
        return False, "; ".join(failures), counts
    denied = read_csv(cond_dir / "denied.csv")

    workers = [r for r in rows if r["phase"] == "worker"]
    probe = [r for r in rows if r["phase"] == "probe"]
    deny_rows = [r for r in rows if r["expected"] == "deny"]
    # The log of every injection, in cycle order (B4, B9)
    injected = [int(c["cycle"]) for c in cycles if c["injected"] == "1"]
    logs = [cond_dir / f"hook_{k:02d}.log" for k in injected]
    events_per_log = [common.parse_events(log, "deny") for log in logs]
    events = [e for log_events in events_per_log for e in log_events]
    without_event = sum(not any(event_matches(r, e) for e in log_events for r in deny_rows)
                        for log_events in events_per_log)
   
    windows_used = {int(r["window"]) for r in denied}
    unused_windows = [k for k in injected if k not in windows_used]
    
    by_tid = group_by_tid(denied)
    unpaired, unpaired_detail, log_error_unchanged = pair_events(by_tid, events)
    full_logs = [log.name for log in logs if log.read_bytes().count(b"\n") >= QUEUE_SIZE]
    deny_count = Counter()
    for r in rows:
        deny_count[r["tid"]] += int(r["deny"])
    journal_short = sorted(tid for tid in deny_count.keys() | by_tid.keys()
                           if len(by_tid.get(tid, [])) != deny_count[tid])
    counts.update({
        "allow_denied": sum(int(r["deny"]) for r in rows if r["expected"] == "allow"),
        "logs_without_event": without_event,
        "probe_not_allowed": sum(int(r["deny"]) + int(r["error"]) for r in probe),
        "errors": sum(int(r["error"]) for r in rows),
        "worker_opens": sum(int(r["allow"]) + int(r["deny"]) + int(r["error"]) for r in workers),
        "last_error_changed": sum(int(r["last_error_changed"]) for r in rows),
        "window_blocked": sum(int(r["in_deny"]) for r in rows),
        "window_missed": sum(int(r["in_allow"]) + int(r["in_error"]) for r in deny_rows),
        "denied": len(denied),
        "deny_events": len(events),
        "unpaired": unpaired,
        "log_error_unchanged": log_error_unchanged,
    })

    if len({r["tid"] for r in workers}) != threads or not probe:
        failures.append(f"counts incomplete: {len({r['tid'] for r in workers})} of {threads} workers, "
                        f"{len(probe)} probe rows")
    if not cycles or counts["injected"] != len(cycles) or counts["ejected"] != len(cycles) \
            or counts["leaked"] or counts["dll_unloaded"] != len(cycles):
        failures.append(f"B2: {len(cycles)} cycles, {counts['injected']} injected, {counts['ejected']} ejected, "
                        f"{counts['leaked']} leaked, {counts['dll_unloaded']} DLL unloaded")
    if without_event:
        failures.append(f"B4: {without_event} cycle logs without a matching deny event")
    if counts["allow_denied"]:
        failures.append(f"B3: {counts['allow_denied']} denied opens of files expected allow")
    if counts["probe_not_allowed"]:
        failures.append(f"B5: {counts['probe_not_allowed']} probe opens not allowed")
    if counts["errors"]:
        r = next(r for r in rows if r["error"] != "0")
        failures.append(f"B6: {counts['errors']} opens failed with an unexpected code, e.g. {r['api']} {r['form']} "
                        f"{r['file']}")
    if counts["last_error_changed"]:
        r = next(r for r in rows if r["last_error_changed"] != "0")
        failures.append(f"B7: {counts['last_error_changed']} native opens changed the last-error code, e.g. "
                        f"{r['phase']} {r['api']} {r['form']} {r['file']}")
    if counts["window_missed"]:
        r = next(r for r in deny_rows if r["in_allow"] != "0" or r["in_error"] != "0")
        failures.append(f"B8: {counts['window_missed']} opens expected deny not denied inside a window, e.g. "
                        f"{r['phase']} {r['api']} {r['form']} {r['file']}")
    if unused_windows:
        failures.append(f"B8: {len(unused_windows)} cycles without a denied open inside the window, e.g. cycle "
                        f"{unused_windows[0]}")
    if unpaired:
        failures.append(f"B9: {unpaired} unpaired, {unpaired_detail}")
    if full_logs:
        failures.append(f"B9: {len(full_logs)} cycle logs with {QUEUE_SIZE} lines or more, so the queue may have "
                        f"dropped lines, e.g. {full_logs[0]}")
    if journal_short:
        tid = journal_short[0]
        failures.append(f"B9: denied.csv and counts.csv differ for {len(journal_short)} threads, e.g. thread {tid}: "
                        f"{len(by_tid.get(tid, []))} rows, {deny_count[tid]} denied opens")
    if log_error_unchanged:
        failures.append(f"B10: {log_error_unchanged} deny events of native opens show the mark: the hook code did not "
                        f"change the last-error code, so B7 does not test the error guard")
    if failures:
        return False, "; ".join(failures), counts
    return True, (f"{len(cycles)} cycles, {counts['worker_opens']} opens, {len(denied)} denied, each with its "
                  f"deny event in its thread's order, {counts['window_blocked']} of them inside the windows, "
                  f"probe allowed"), counts



# Session
def analyse_run(run_dir: Path) -> list[dict]:
    rows = []
    for cond_dir in sorted(p for p in run_dir.iterdir() if p.is_dir()):
        threads = int(cond_dir.name.rsplit("_t", 1)[1])
        exit_code = exit_code_of(cond_dir)
        if cond_dir.name.startswith("hooked_"):  # run A
            ok, detail, counts = check_journal(threads, read_csv(cond_dir / "journal.csv"),
                                               common.parse_events(cond_dir / "hook.log", "deny"),
                                               read_counter(cond_dir / "metrics.txt"), exit_code)
        else:  # cycled_*, run B
            ok, detail, counts = check_counts(threads, read_csv(cond_dir / "counts.csv"),
                                              read_csv(cond_dir / "cycles.csv"), cond_dir, exit_code)
        rows.append({"condition": cond_dir.name, "result": "PASS" if ok else "FAIL", **counts, "detail": detail})
    columns = ["condition", "result"] + [c for c in A_COUNTS + B_COUNTS + ["died_at", "exit_code"]
                                         if any(c in r for r in rows)] + ["detail"]
    common.write_csv(rows, run_dir / "check.csv", columns)
    return rows


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("session", type=Path, help="Session directory written by run.py (contains run_NN/)")
    session = p.parse_args().session.resolve()

    by_condition = defaultdict(list)
    failed = []
    for run_dir in sorted(d for d in session.glob("run_*") if d.is_dir()):
        for row in analyse_run(run_dir):
            by_condition[row["condition"]].append(row)
            if row["result"] != "PASS":
                failed.append(f"{run_dir.name}/{row['condition']}: {row['detail']}")

    summary = []
    for condition, rows in by_condition.items():
        entry = {"condition": condition, "runs": len(rows), "passed": sum(r["result"] == "PASS" for r in rows)}
        for c in A_COUNTS + B_COUNTS:  # summed over the runs that wrote the column
            if any(r.get(c, "") != "" for r in rows):
                entry[c] = sum(int(r[c]) for r in rows if r.get(c, "") != "")
        summary.append(entry)
    columns = ["condition", "runs", "passed"] + [c for c in A_COUNTS + B_COUNTS if any(c in s for s in summary)]
    common.write_csv(summary, session / "summary.csv", columns)

    for line in failed:
        print(f"FAIL {line}")
    print("ALL PASS" if not failed else f"{len(failed)} condition(s) failed")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
