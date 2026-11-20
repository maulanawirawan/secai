r"""[SAFETY: read-only, NOL jaringan] crash_triage — groups crashes from
fuzzing / tests / production logs into unique bugs and ranks them by bug
class, so the memory-corruption bug hiding among 500 crash logs is found
first. Triage only: it classifies; it never builds an exploit.

Input (--input FILE repeatable, or --dir): plain text with one or more
reports, auto-split on report headers, and/or JSONL corpora written by
tools/api_fuzz_lab.py --corpus-out. Recognised report kinds:
  ASan / LSan / MSan / TSan / UBSan (clang/gcc sanitizers),
  "Segmentation fault" / "stack smashing detected",
  Python tracebacks, Go panics, Java exceptions, Node.js errors.

Mechanism:
  1. split into reports (a sanitizer word inside ordinary prose is NOT a
     report — a header shape is required);
  2. bug class + access type (READ/WRITE) from the report header;
  3. stack frames -> top 3 PROJECT frames (runtime, libc, sanitizer and
     interpreter frames dropped), function + file name only (addresses
     and line numbers removed, so rebuilds do not split buckets);
  4. bucket = sha1(class + frames); count, first sample, inputs.

Severity by class (triage hint, not proof of exploitability):
  critical : heap/stack/global buffer WRITE overflow, use-after-free,
             double-free, invalid-free (memory corruption)
  high     : buffer READ overflow (info leak), SQL error on input
             (injection lead), wild (non-null) SEGV
  medium   : stack overflow / recursion, integer overflow, uninitialised
             read, data race, resource exhaustion
  low      : null dereference, leak, unhandled input (validation),
             generic panic / exception
Verdict: L1 LEAD; L2 when a fuzz record says the crash reproduced.
Exit: 0 nothing >= --fail-on; 1 buckets >= --fail-on (default high);
2 input error (nothing readable / no report recognised).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

TOOL = "crash-triage"
SCHEMA = "secai.crash-triage/1"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_REPORTS = 50_000
SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

HEADERS = re.compile(
    r"^(?:==\d+==\s*ERROR: (?:Address|Leak|Memory|Thread)Sanitizer|"
    r"WARNING: (?:ThreadSanitizer|MemorySanitizer)|"
    r"\S+:\d+:\d+: runtime error: |"
    r"Traceback \(most recent call last\):|"
    r"panic: |fatal error: |"
    r"Exception in thread |"
    # Java / Node headers need a following stack line, otherwise the last
    # line of a Python traceback ("TypeError: ...") would split it
    r"(?:\w+\.)+\w*(?:Exception|Error)(?::[^\n]*)?\n\s+at |"
    r"(?:Uncaught )?(?:TypeError|ReferenceError|RangeError|SyntaxError): "
    r"[^\n]*\n\s+at |"
    r"Segmentation fault|\*\*\* stack smashing detected)", re.M)

CLASS_SEVERITY = {
    "heap-buffer-overflow-write": "critical",
    "stack-buffer-overflow-write": "critical",
    "global-buffer-overflow-write": "critical",
    "use-after-free": "critical", "double-free": "critical",
    "invalid-free": "critical", "stack-smashing": "critical",
    "heap-buffer-overflow-read": "high", "stack-buffer-overflow-read": "high",
    "global-buffer-overflow-read": "high", "wild-access": "high",
    "sql-error": "high",
    "stack-overflow": "medium", "recursion": "medium",
    "integer-overflow": "medium", "uninitialized-read": "medium",
    "data-race": "medium", "resource-exhaustion": "medium",
    "out-of-bounds-index": "medium", "division-by-zero": "low",
    "null-deref": "low", "memory-leak": "low", "unhandled-input": "low",
    "panic": "low", "exception": "low", "segv": "medium",
}
CLASS_CWE = {
    "use-after-free": "CWE-416", "double-free": "CWE-415",
    "invalid-free": "CWE-590", "null-deref": "CWE-476",
    "integer-overflow": "CWE-190", "uninitialized-read": "CWE-457",
    "data-race": "CWE-362", "memory-leak": "CWE-401",
    "stack-overflow": "CWE-674", "recursion": "CWE-674",
    "resource-exhaustion": "CWE-400", "division-by-zero": "CWE-369",
    "sql-error": "CWE-89", "unhandled-input": "CWE-20",
    "out-of-bounds-index": "CWE-129", "stack-smashing": "CWE-121",
}
NOISE_FRAME = re.compile(
    r"__asan|__interceptor|__sanitizer|__ubsan|__msan|__tsan|__lsan|"
    r"^(?:malloc|calloc|realloc|free|memcpy|memmove|strcpy|strlen|"
    r"operator new|operator delete|__libc_start|_start|start_thread|"
    r"clone|raise|abort|__GI_|libc\.so|ld-linux)|"
    r"^(?:std::|java\.lang\.reflect|jdk\.internal|sun\.reflect|"
    r"java\.base/|runtime\.|node:internal|internal/)|"
    r"/(?:site-packages|dist-packages|lib/python\d)", re.I)

PY_EXC_CLASS = {
    "RecursionError": "recursion", "MemoryError": "resource-exhaustion",
    "ZeroDivisionError": "division-by-zero", "OperationalError": "sql-error",
    "ProgrammingError": "sql-error", "IntegrityError": "unhandled-input",
    "IndexError": "out-of-bounds-index", "KeyError": "unhandled-input",
    "ValueError": "unhandled-input", "TypeError": "unhandled-input",
    "AttributeError": "unhandled-input", "UnicodeDecodeError":
    "unhandled-input", "JSONDecodeError": "unhandled-input",
    "OverflowError": "integer-overflow", "TimeoutError":
    "resource-exhaustion"}
JAVA_EXC_CLASS = {
    "NullPointerException": "null-deref",
    "ArrayIndexOutOfBoundsException": "out-of-bounds-index",
    "StringIndexOutOfBoundsException": "out-of-bounds-index",
    "StackOverflowError": "recursion", "OutOfMemoryError":
    "resource-exhaustion", "NumberFormatException": "unhandled-input",
    "SQLException": "sql-error", "SQLSyntaxErrorException": "sql-error",
    "ArithmeticException": "division-by-zero",
    "IllegalArgumentException": "unhandled-input"}


def split_reports(text: str) -> list[str]:
    starts = [m.start() for m in HEADERS.finditer(text)]
    if not starts:
        return []
    starts.append(len(text))
    chunks = [text[a:b] for a, b in zip(starts, starts[1:])]
    out = []
    for c in chunks:
        # a Java "Caused by" / Python chained traceback belongs to its parent
        if out and (c.startswith("Caused by") or
                    c.lstrip().startswith("During handling")):
            out[-1] += c
        else:
            out.append(c)
    return out[:MAX_REPORTS]


def classify(rep: str) -> tuple[str, str]:
    """(engine, bug class)"""
    head = rep[:600]
    m = re.search(r"ERROR: AddressSanitizer: ([\w-]+)", head)
    if m:
        kind = m.group(1)
        access = re.search(r"\b(READ|WRITE) of size \d+", rep)
        acc = (access.group(1).lower() if access else "read")
        if kind in ("heap-buffer-overflow", "stack-buffer-overflow",
                    "global-buffer-overflow", "container-overflow",
                    "stack-use-after-return", "stack-use-after-scope"):
            base = kind if kind.endswith("overflow") and \
                kind != "container-overflow" else "heap-buffer-overflow"
            if kind.startswith("stack-use-after"):
                return "asan", "use-after-free"
            return "asan", f"{base}-{acc}"
        if kind == "heap-use-after-free":
            return "asan", "use-after-free"
        if kind in ("double-free",):
            return "asan", "double-free"
        if kind in ("attempting", "bad-free", "alloc-dealloc-mismatch"):
            return "asan", "invalid-free"
        if kind == "stack-overflow":
            return "asan", "stack-overflow"
        if kind == "SEGV":
            addr = re.search(r"unknown address (0x[0-9a-fA-F]+)", head)
            if addr and int(addr.group(1), 16) < 0x1000:
                return "asan", "null-deref"
            return "asan", "wild-access"
        if "attempting double-free" in head:
            return "asan", "double-free"
        if "attempting free" in head:
            return "asan", "invalid-free"
        return "asan", "segv"
    if "LeakSanitizer" in head:
        return "lsan", "memory-leak"
    if "MemorySanitizer" in head:
        return "msan", "uninitialized-read"
    if "ThreadSanitizer" in head:
        return "tsan", "data-race"
    # Go before UBSan: "panic: runtime error: ..." is a Go panic
    if head.startswith(("panic: ", "fatal error: ")):
        if "nil pointer" in head or "invalid memory address" in head:
            return "go", "null-deref"
        if "index out of range" in head or "slice bounds" in head:
            return "go", "out-of-bounds-index"
        if "stack overflow" in head or "goroutine stack exceeds" in head:
            return "go", "recursion"
        if "out of memory" in head:
            return "go", "resource-exhaustion"
        return "go", "panic"
    m = re.match(r"\S+:\d+:\d+: runtime error: (.+)", head)
    if m:
        msg = m.group(1)
        if "overflow" in msg:
            return "ubsan", "integer-overflow"
        if "out of bounds" in msg:
            return "ubsan", "out-of-bounds-index"
        if "null pointer" in msg:
            return "ubsan", "null-deref"
        if "division by zero" in msg:
            return "ubsan", "division-by-zero"
        return "ubsan", "exception"
    if head.startswith("*** stack smashing detected"):
        return "native", "stack-smashing"
    if head.startswith("Segmentation fault"):
        return "native", "segv"
    if head.startswith("Traceback"):
        last = [ln for ln in rep.strip().splitlines() if ln.strip()][-1]
        exc = re.match(r"([\w.]+?)(?::|$)", last.strip())
        name = exc.group(1).rsplit(".", 1)[-1] if exc else "Exception"
        return "python", PY_EXC_CLASS.get(name, "exception")
    m = re.search(r"(?:Exception in thread \"[^\"]*\" )?(?:[\w$]+\.)*"
                  r"(\w+(?:Exception|Error))", head)
    if m and (head.startswith("Exception in thread") or "\tat " in rep or
              re.match(r"(?:\w+\.)+\w+", head)):
        if "\tat " in rep or head.startswith("Exception in thread"):
            return "java", JAVA_EXC_CLASS.get(m.group(1), "exception")
    m = re.match(r"(?:Uncaught )?(TypeError|ReferenceError|RangeError|"
                 r"SyntaxError): (.*)", head)
    if m:
        if "Maximum call stack" in m.group(2):
            return "node", "recursion"
        return "node", "unhandled-input" if m.group(1) == "TypeError" \
            else "exception"
    return "unknown", "exception"


def frames(rep: str, engine: str) -> list[str]:
    # only the crashing stack defines the bug; ASan's "freed by" /
    # "allocated by" stacks are context, not signature
    rep = re.split(r"\n(?:freed by|previously allocated by|allocated by)",
                   rep)[0]
    out = []
    pats = {
        "python": r'File "([^"]+)", line \d+, in (\S+)',
        "java": r"\tat ([\w$.<>]+)\(([\w$]+\.java|Native Method|Unknown "
                r"Source)",
        "go": r"^(\S+)\([^\n]*\)\n\s+(\S+\.go):\d+",
        "node": r"at (?:([\w.<>$]+) )?\(?([^():\s]+\.(?:js|ts|mjs)):\d+",
    }
    if engine in ("asan", "lsan", "msan", "tsan", "ubsan", "native",
                  "unknown"):
        for m in re.finditer(r"#\d+ 0x[0-9a-fA-F]+ in (.+?)(?: (\S+?)"
                             r"(?::\d+)+)?\s*$", rep, re.M):
            out.append((m.group(1).strip(), m.group(2) or ""))
        if engine == "ubsan" and not out:
            m = re.search(r"^(\S+?):\d+:\d+: runtime error", rep, re.M)
            if m:
                out.append(("", m.group(1)))
    elif engine in pats:
        for m in re.finditer(pats[engine], rep, re.M):
            if engine == "python":
                out.append((m.group(2), m.group(1)))
            elif engine == "java":
                out.append((m.group(1), m.group(2)))
            elif engine == "go":
                out.append((m.group(1), m.group(2)))
            else:
                out.append((m.group(1) or "<anon>", m.group(2)))
        if engine == "python":
            out.reverse()  # innermost first, like native stacks
    proj = []
    for func, path in out:
        file = re.split(r"[\\/]+", path)[-1] if path else ""
        if NOISE_FRAME.search(func) or NOISE_FRAME.search(path or ""):
            continue
        func = re.sub(r"\((?:\.\.\.|[^()]*)\)$", "", func)  # trailing args
        func = re.sub(r"\+0x[0-9a-f]+$", "", func)
        proj.append(f"{func}@{file}" if file and func else (func or file))
    return proj[:3]


def load_reports(paths: list[Path]) -> tuple[list[dict], dict]:
    reports, stats = [], {"files": 0, "fuzz_records": 0}
    for p in paths:
        if p.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"{p} larger than {MAX_FILE_BYTES} bytes")
        # any CR run (CRLF, CRCRLF from double conversion, bare CR) -> LF
        text = re.sub(r"\r+\n?", "\n",
                      p.read_bytes().decode("utf-8", "replace"))
        stats["files"] += 1
        stripped = text.lstrip()
        if stripped.startswith("{"):
            for line in text.splitlines():
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(rec, dict) or not rec.get("body"):
                    continue
                stats["fuzz_records"] += 1
                for chunk in split_reports(rec["body"]):
                    reports.append({"text": chunk, "file": p.name,
                                    "input": rec.get("payload"),
                                    "where": rec.get("op", ""),
                                    "reproduced": bool(rec.get(
                                        "reproduced"))})
            continue
        for chunk in split_reports(text):
            reports.append({"text": chunk, "file": p.name, "input": None,
                            "where": "", "reproduced": False})
    return reports, stats


def audit(reports: list[dict]) -> tuple[list[dict], dict]:
    """Pure: crash reports -> (rows, meta), one row per unique bucket."""
    buckets: dict[str, dict] = {}
    for r in reports:
        engine, cls = classify(r["text"])
        fr = frames(r["text"], engine)
        key = hashlib.sha1(f"{cls}|{'|'.join(fr)}".encode()).hexdigest()[:12]
        b = buckets.setdefault(key, {
            "bucket": key, "engine": engine, "class": cls, "frames": fr,
            "count": 0, "files": set(), "inputs": [], "where": set(),
            "reproduced": False, "sample": r["text"][:1500]})
        b["count"] += 1
        b["files"].add(r["file"])
        if r["where"]:
            b["where"].add(r["where"])
        if r["input"] is not None and len(b["inputs"]) < 5:
            b["inputs"].append(str(r["input"])[:200])
        b["reproduced"] = b["reproduced"] or r["reproduced"]
    rows = []
    order = sorted(buckets.values(), key=lambda b: (
        -SEV_ORDER[CLASS_SEVERITY.get(b["class"], "low")], -b["count"],
        b["bucket"]))
    for b in order:
        sev = CLASS_SEVERITY.get(b["class"], "low")
        top = b["frames"][0] if b["frames"] else "unknown frame"
        rows.append(make_finding(
            tool=TOOL,
            title=f"{b['class']} ({b['engine']}) in {top} — {b['count']} "
                  "report(s)",
            severity=sev, cwe=CLASS_CWE.get(b["class"]),
            description=(f"Bucket {b['bucket']}: {b['count']} crash "
                         f"report(s) with the same class and top frames "
                         f"{' <- '.join(b['frames']) or '(none)'}"
                         + (f"; triggered via {', '.join(sorted(b['where']))}"
                            if b["where"] else "")
                         + ". Triage hint by class, not proof of "
                           "exploitability: fix and add the input as a "
                           "regression test."),
            recommendation=_REC.get(b["class"], "Root-cause the top frame; "
                                    "add the crashing input to the test "
                                    "suite."),
            response=b["sample"][:600], evidence_kind="artifact-parse",
            finding_class="weakness", confidence=0.9,
            status="confirmed", verdict=2 if b["reproduced"] else 1,
            extra={"category": "LEAD", "bucket": b["bucket"],
                   "class": b["class"], "engine": b["engine"],
                   "frames": b["frames"], "count": b["count"],
                   "files": sorted(b["files"]), "inputs": b["inputs"],
                   "safety_class": "read-only"}))
    meta = {"schema": SCHEMA, "reports": len(reports),
            "buckets": len(rows), "requests": 0,
            "by_class": {c: sum(1 for b in buckets.values()
                                if b["class"] == c)
                         for c in sorted({b["class"]
                                          for b in buckets.values()})}}
    return rows, meta


_REC = {
    "use-after-free": "Fix object lifetime (ownership / refcount); rerun "
                      "under ASan with the stored input.",
    "double-free": "Make ownership single (null the pointer after free).",
    "heap-buffer-overflow-write": "Bounds-check the write length against "
                                  "the allocation; prefer size-checked APIs.",
    "stack-buffer-overflow-write": "Bounds-check before copying into the "
                                   "stack buffer; enable stack protector.",
    "sql-error": "Parameterise the query that failed on this input.",
    "recursion": "Bound recursion depth / make it iterative.",
    "null-deref": "Check the value before use; handle the error path.",
    "unhandled-input": "Validate the input type/range at the boundary.",
}


def main(argv: "list[str] | None" = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(
        description="[SAFETY: read-only] crash-triage: bucket and rank "
                    "crashes (sanitizers, tracebacks, panics, fuzz corpus)")
    ap.add_argument("--input", action="append", default=[],
                    help="crash log / fuzz corpus JSONL (repeatable)")
    ap.add_argument("--dir", default=None, help="directory of crash files")
    ap.add_argument("--out", default="crash_triage.json")
    ap.add_argument("--fail-on", default="high",
                    choices=["none", "low", "medium", "high", "critical"])
    args = ap.parse_args(argv)
    paths = [Path(p) for p in args.input]
    if args.dir:
        d = Path(args.dir)
        if not d.is_dir():
            print(f"[{TOOL}] input error: --dir {d} is not a directory",
                  file=sys.stderr)
            return 2
        for dirpath, _dirs, files in os.walk(d):
            paths += [Path(dirpath) / f for f in sorted(files)]
    if not paths:
        print(f"[{TOOL}] input error: give --input and/or --dir",
              file=sys.stderr)
        return 2
    try:
        reports, stats = load_reports(paths)
    except (OSError, ValueError) as exc:
        print(f"[{TOOL}] input error: {exc}", file=sys.stderr)
        return 2
    if not reports:
        print(f"[{TOOL}] input error: no crash report recognised in "
              f"{len(paths)} file(s) — nothing to triage (fail-closed)",
              file=sys.stderr)
        return 2
    rows, meta = audit(reports)
    meta.update(stats)
    write_findings(args.out, rows, {**meta, "safety_class": "read-only"})
    print(f"{TOOL}: {meta['reports']} report(s) -> {meta['buckets']} "
          f"unique bug(s) {meta['by_class']} -> {args.out}")
    if args.fail_on == "none":
        return 0
    thr = SEV_ORDER[args.fail_on]
    return 1 if any(SEV_ORDER[r["severity"]] >= thr for r in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
