"""
Per-call matching of native (ntdll) hook events against ProcMon rows.

check.py compares COUNTS per operation, which shows that the hooks saw as many calls of each type as
the kernel, but not that they saw the SAME calls (a miss and an extra of the same type cancel out). This module
pairs every hook event with one ProcMon row, using the fields both sides carry:

  operation   ProcMon "Operation" vs the hooked function (OP_MAP_NATIVE of check.py)
  key path    ProcMon "Path" vs the path rebuilt from the hook log
  result      ProcMon "Result" vs the logged NTSTATUS (NTSTATUS_TO_PROCMON)
  order       the call order

Key path. Opens/creates log the RootDirectory handle, the ObjectName as passed to the kernel (absolute
"\\REGISTRY\\..." or relative to the root) and the returned handle; the other operations log the key handle
(plus the value name for value operations). Walking the log in order, a handle -> path table is filled at
every successful open and cleared at NtClose. Each match records how much of the path was known:
  full path       the full path was rebuilt from the log and equals the ProcMon path
  relative path   the call is on a handle opened before attach (unknown), so only the part after it is known;
                  it must be a suffix of the ProcMon path
  operation only  a handle-only call on an unknown handle: operation, result and order only

Matching. The target is single-threaded (both experiments: after attach, every registry call of the target
comes from its main thread), so log order = call order = ProcMon order. Hook events are taken in log order and
each takes the first compatible row within MATCH_WINDOW rows of the ProcMon queue (post-attach, in-scope,
REPARSE duplicates removed). The rows skipped before it are MISSED (the order is strict), and an event with no
compatible row is EXTRA (seen by the hooks, absent from the kernel view). Rows left at the end are missed. With
more than one thread id in the hook log (tid column of call_matching.csv) the single order no longer holds.

Not hooked. Post-attach rows (REPARSE removed) of operations the policy does not hook at all are listed as NOT
HOOKED: policy gaps, not part of the per-call coverage. They are kept out of the
matching queue because no hook event can match them, and a burst of more than MATCH_WINDOW of them would push
the next real match out of the search window. The two kinds of gap read differently: a NOT HOOKED row is an
operation the policy does not cover; a MISSED row of a hooked operation in mid-trace (not at process exit)
points to an unhooked entry point of a covered operation (e.g. a transacted open).

Scope. Fitted to the two native experiments (target.cpp and reg.exe query /s, 64-bit, single thread
of activity): keys under \\REGISTRY\\MACHINE and the current user's \\REGISTRY\\USER\\<SID>, which ProcMon shows as
HKLM / HKCU, and the status codes observed there. Other hives (HKCR / *_Classes, HKU, app hives), WOW64
redirection and other status codes are not modelled: an unknown status is not used as a matching key, an
unknown hive prefix will not match its ProcMon row. Revisit both before using other targets.
"""

import re
from dataclasses import dataclass, field

MATCH_WINDOW = 256  # largest skip seen between consecutive matches in the two experiments: 2 rows

# Key added to each ProcMon row by check.split_marker: its data-row index in procmon_capture.csv
# (0 = first row after the header). call_matching.csv uses it so row numbers can be looked up in the capture.
CSV_ROW = "_csv_row"

OPEN_FUNCS = {"NtOpenKey", "NtOpenKeyEx", "NtCreateKey"}
VALUE_FUNCS = {"NtQueryValueKey", "NtSetValueKey", "NtDeleteValueKey"}
CLOSE_FUNC = "NtClose"

# NTSTATUS -> ProcMon "Result" text, for the codes observed in the two experiments. A status or a ProcMon result
# not listed here is not used as a matching key.
NTSTATUS_TO_PROCMON = {
    0x00000000: "SUCCESS",
    0x40000016: "PREDEFINED HANDLE",  # Perflib\009, Perflib\CurrentLanguage (reg.exe query /s)
    0x80000005: "BUFFER OVERFLOW",
    0x8000001A: "NO MORE ENTRIES",
    0xC0000022: "ACCESS DENIED",
    0xC0000023: "BUFFER TOO SMALL",  # RegQueryKeySecurity size probe (reg.exe query /s, Perflib)
    0xC0000034: "NAME NOT FOUND",
}
KNOWN_RESULTS = set(NTSTATUS_TO_PROCMON.values())

# Kernel object names -> the root names ProcMon prints (every S-1-5-21 user SID is taken as the current user)
_PREFIX_RULES = [
    (re.compile(r"^\\registry\\machine(?=\\|$)"), "hklm"),
    (re.compile(r"^\\registry\\user\\s-1-5-21-[0-9-]+(?=\\|$)"), "hkcu"),
]
_RE_SLASHES = re.compile(r"\\+")


def norm(path: str) -> str:
    """Lower case, single separators, no trailing separator."""
    return _RE_SLASHES.sub(r"\\", path.strip()).rstrip("\\").lower()


def canonical(path: str) -> str:
    p = norm(path)
    for rx, repl in _PREFIX_RULES:
        p = rx.sub(repl, p, count=1)
    return p


@dataclass(frozen=True)
class KeyPath:
    """Path of a key (or value) as far as it is known from the hook log."""
    absolute: bool  # True: `path` is the full path; False: `path` is what follows an unknown handle
    path: str

    def join(self, name: str) -> "KeyPath":
        name = norm(name)
        if not name:
            return self
        return KeyPath(self.absolute, self.path + "\\" + name if self.path else name)


UNKNOWN = KeyPath(False, "")


def show_path(kp: KeyPath) -> str:
    """Printable path; a relative one is prefixed with '...\\' (the unknown handle)."""
    return kp.path if kp.absolute else "...\\" + kp.path


def show_status(status: int | None) -> str:
    return "" if status is None else f"0x{status:08X}"


@dataclass
class HookEvent:
    line: int
    func: str
    tid: str | None
    fields: dict
    path: KeyPath = UNKNOWN
    status: int | None = None
    match: dict = field(default_factory=dict)


def _hex(v: str | None) -> int | None:
    try:
        return int(v, 16) if v is not None else None
    except ValueError:
        return None


def _name(v: str | None) -> str:
    return "" if v in (None, "null") else v


def parse_native_log(path) -> list[HookEvent]:
    """EVENT lines of the native policy with their k=v fields; a cut-off last line is dropped."""
    events = []
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        for lineno, line in enumerate(f, 1):
            if not line.endswith("\n"):
                continue
            i = line.find("EVENT|")
            if i < 0:
                continue
            parts = line[i:].rstrip("\r\n").split("|")
            fields = {k: v for k, _, v in (p.partition("=") for p in parts[2:])}
            events.append(HookEvent(lineno, parts[1], fields.get("tid"), fields, status=_hex(fields.get("status"))))
    return events


def _path_evidence(kp: KeyPath, row_path: str) -> str | None:
    if kp.absolute:
        return "full path" if kp.path == row_path else None
    if not kp.path:
        return "operation only"
    return "relative path" if row_path == kp.path or row_path.endswith("\\" + kp.path) else None


def _result_ok(status: int | None, result: str) -> bool:
    """Compatible; true when either side is not a known code."""
    expected = NTSTATUS_TO_PROCMON.get(status) if status is not None else None
    got = result.strip().upper()
    if expected is None or got not in KNOWN_RESULTS:
        return True
    return expected == got


def match_calls(rows: list[dict], attach_row: int, events: list[HookEvent], op_map: dict,
                window: int = MATCH_WINDOW) -> dict:
    """Pair hook events with ProcMon rows. Returns the per-call records, the missed and the not-hooked rows."""
    func_to_op = {fn: op for op, fns in op_map.items() for fn in fns}
    hooked_ops = {op for op, fns in op_map.items() if fns}

    post_attach = [i for i in range(attach_row, len(rows)) if rows[i]["Result"].strip().upper() != "REPARSE"]
    q = [i for i in post_attach if rows[i]["Operation"] in hooked_ops]
    not_hooked = [i for i in post_attach if rows[i]["Operation"] not in hooked_ops]
    pos = 0
    row_path = {i: norm(rows[i]["Path"]) for i in q}

    handles: dict[int, KeyPath] = {}
    records, missed_rows = [], []

    for ev in events:
        f = ev.fields
        # --- path of the call, from the handle table as it is BEFORE this call
        if ev.func in OPEN_FUNCS:
            root, name = _hex(f.get("root")) or 0, _name(f.get("name"))
            if root == 0:
                ev.path = KeyPath(True, canonical(name)) if name.startswith("\\") else KeyPath(False, norm(name))
            else:
                ev.path = handles.get(root, UNKNOWN).join(name)
        elif ev.func in VALUE_FUNCS:
            value = _name(f.get("valName")) or "(default)"
            ev.path = handles.get(_hex(f.get("hKey")), UNKNOWN).join(value)
        else:
            ev.path = handles.get(_hex(f.get("hKey")), UNKNOWN)

        op = func_to_op.get(ev.func)
        if op:
            for k in range(pos, min(len(q), pos + window)):
                i = q[k]
                if rows[i]["Operation"] != op:
                    continue
                evidence = _path_evidence(ev.path, row_path[i])
                if evidence is None:
                    continue
                if _result_ok(ev.status, rows[i]["Result"]):
                    missed_rows += q[pos:k]
                    pos = k + 1
                    ev.match = {"row": i, "evidence": evidence}
                    break
        records.append(ev)

        # --- handle table update AFTER the call
        if ev.func in OPEN_FUNCS and ev.status is not None and ev.status < 0x80000000:
            out = _hex(f.get("out"))
            if out:
                handles[out] = ev.path
        elif ev.func == CLOSE_FUNC:
            handles.pop(_hex(f.get("hKey")), None)

    missed_rows += q[pos:]
    return {"events": records, "missed_rows": sorted(missed_rows), "not_hooked_rows": not_hooked}


def records_for_csv(rows: list[dict], result: dict, op_map: dict) -> list[dict]:
    """One row per hook event (matched / extra), then one per missed and per not-hooked ProcMon row."""
    func_to_op = {fn: op for op, fns in op_map.items() for fn in fns}
    out = []
    for ev in result["events"]:
        r = rows[ev.match["row"]] if ev.match else None
        out.append({
            "kind": "matched" if ev.match else "extra",
            "operation": func_to_op.get(ev.func, ""),
            "tid": ev.tid or "",
            "hook_line": ev.line,
            "hook_function": ev.func,
            "hook_path": show_path(ev.path),
            "hook_status": show_status(ev.status),
            "procmon_row": r.get(CSV_ROW, ev.match["row"]) if r else "",
            "procmon_path": r["Path"] if r else "",
            "procmon_result": r["Result"] if r else "",
            "evidence": ev.match.get("evidence", ""),
        })
    for kind, indices in (("missed", result["missed_rows"]), ("not hooked", result["not_hooked_rows"])):
        for i in indices:
            r = rows[i]
            out.append({
                "kind": kind, "operation": r["Operation"], "tid": r.get("TID", ""), "hook_line": "",
                "hook_function": "", "hook_path": "", "hook_status": "", "procmon_row": r.get(CSV_ROW, i),
                "procmon_path": r["Path"], "procmon_result": r["Result"], "evidence": "",
            })
    return out
