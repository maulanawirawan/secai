r"""[LAB: loopback-only, active] api_fuzz_lab — specification-driven API
fuzzer for YOUR lab: reads an OpenAPI 3 / Swagger 2 JSON document, sends
deterministic mutations of every parameter to a service running on
127.0.0.1, and reports inputs the service does not handle (the raw
material of unknown bugs) — before anyone else finds them.

Gate (core/lab_gate.py, before the first request): env LAB=1 AND a
literal loopback --base-url. This tool is loopback-ONLY: LAB_REMOTE_ACK
does not open it (fuzzing is high-volume by nature).

Safety by construction:
  - GET only by default; other methods must be listed in --methods
    (they change state, even in a lab);
  - bounded: --max-requests (default 400) and --rps (default 25);
  - benign corpus: boundary numbers, type confusion, quotes and special
    characters, long strings, a template-arithmetic marker. No shell
    commands, no file reads, no payloads that act on their own;
  - if the service stops answering, fuzzing stops (no hammering).

Oracle — always a DIFFERENTIAL against a baseline request that must be
stable (sent twice, same status class) or the operation is skipped:
  server-error      : 5xx where the baseline was < 500        (CWE-248)
  error-leak        : stack trace / DB / runtime error signature that the
                      baseline does not contain (sql signature -> CWE-89
                      lead, otherwise CWE-209)
  template-eval     : {{1337*7}} / ${1337*7} answered with 9359 while
                      the raw marker is not simply echoed       (CWE-1336)
  slow-response     : > --slow-ms slower than the baseline     (CWE-400)
  connection-drop   : socket closed without a response         (CWE-248)
Each anomaly is re-sent once: reproduced = L2 REPRODUCED, otherwise L1.
Every anomaly is also written to --corpus-out (JSONL) for
tools/crash_triage.py.

Exit: 0 nothing >= --fail-on; 1 findings >= --fail-on (default medium);
2 refused / input error.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
import lab_gate  # noqa: E402

TOOL = "api-fuzz-lab"
SCHEMA = "secai.api-fuzz-lab/1"
SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TIMEOUT_S = 10.0
MAX_BODY = 64_000
MAX_SPEC_BYTES = 8 * 1024 * 1024
MARKERS = ("{{1337*7}}", "${1337*7}", "<%= 1337*7 %>")
MARKER_RESULT = "9359"

STRING_CORPUS = [
    "", "'", '"', "`", "\\", "' OR '1'='1", "1'--", ";", "|", "&", "<>",
    "%00", "\x00", "%s%s%s%s%n", "../../../../nonexistent-secai-canary",
    "A" * 4096, "A" * 65536, "‮\u0000﻿", "\U0001f600" * 64,
    "[]", "{}", "null", "true", "-1", "0", "1e309", "NaN",
    "99999999999999999999999999", *MARKERS]
NUMBER_CORPUS = [0, -1, 2 ** 31 - 1, 2 ** 31, 2 ** 63, -(2 ** 63) - 1,
                 10 ** 30, "abc", "", "1e309", "NaN", "-0", "0x41", "1.5"]
CONFUSION = [None, [], {}, True, ["a"], {"a": 1}]

ERROR_SIGNATURES = [
    ("sql", re.compile(
        r"SQLSTATE|SQL syntax|sqlite3\.\w*Error|OperationalError|"
        r"ORA-\d{5}|PG::\w+|psycopg2\.\w+|mysqli?_\w+\(\)|"
        r"unterminated quoted string|syntax error at or near|"
        r"Unclosed quotation mark|near \"[^\"]*\": syntax error", re.I)),
    ("python", re.compile(r"Traceback \(most recent call last\)|"
                          r"File \"[^\"]+\", line \d+")),
    ("java", re.compile(r"Exception in thread|\tat [\w.$]+\([\w]+\.java:\d+\)"
                        r"|java\.lang\.\w+Exception")),
    ("node", re.compile(r"at [\w.<>]+ \(/[^)]+:\d+:\d+\)|ReferenceError:|"
                        r"TypeError: Cannot read propert")),
    ("php", re.compile(r"(?:Fatal error|Warning|Notice): .+ in /\S+ on line "
                       r"\d+")),
    ("go", re.compile(r"panic: |goroutine \d+ \[")),
    ("native", re.compile(r"Segmentation fault|stack smashing detected|"
                          r"AddressSanitizer")),
]


# --------------------------------------------------------------------------
# spec
# --------------------------------------------------------------------------
def _resolve(spec: dict, node, depth: int = 0):
    if not isinstance(node, dict) or depth > 8:
        return node if isinstance(node, dict) else {}
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        cur = spec
        for part in ref[2:].split("/"):
            cur = cur.get(part, {}) if isinstance(cur, dict) else {}
        return _resolve(spec, cur, depth + 1)
    return node


def _schema_type(schema: dict) -> str:
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), "string")
    if t:
        return t
    if "properties" in schema:
        return "object"
    if "items" in schema:
        return "array"
    return "string"


def baseline_value(schema: dict):
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if schema.get("enum"):
        return schema["enum"][0]
    t = _schema_type(schema)
    return {"integer": 1, "number": 1.5, "boolean": True, "array": ["a"],
            "object": {}}.get(t, "secai")


def load_operations(spec: dict, methods: set) -> list[dict]:
    """[{method, path, params:[{name, in, schema}], body:{props}|None}]"""
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        raise ValueError("spec has no 'paths' object (OpenAPI 3 / "
                         "Swagger 2 JSON expected)")
    ops = []
    for path, item in sorted(spec["paths"].items()):
        item = _resolve(spec, item)
        shared = item.get("parameters", [])
        for method in sorted(m for m in item if m.lower() in methods):
            op = _resolve(spec, item[method])
            params, body = [], None
            for prm in list(shared) + list(op.get("parameters", [])):
                prm = _resolve(spec, prm)
                where = prm.get("in")
                if where in ("path", "query", "header"):
                    schema = _resolve(spec, prm.get("schema") or prm)
                    params.append({"name": prm.get("name", "p"), "in": where,
                                   "schema": schema})
                elif where == "body":           # Swagger 2
                    body = _resolve(spec, prm.get("schema", {}))
            rb = _resolve(spec, op.get("requestBody", {}))
            content = rb.get("content", {}) if isinstance(rb, dict) else {}
            if "application/json" in content:
                body = _resolve(spec, content["application/json"].get(
                    "schema", {}))
            props = {}
            if isinstance(body, dict):
                for k, v in (body.get("properties") or {}).items():
                    props[k] = _resolve(spec, v)
            ops.append({"method": method.upper(), "path": path,
                        "params": params, "body": props or None})
    return ops


# --------------------------------------------------------------------------
# requests
# --------------------------------------------------------------------------
class Budget:
    def __init__(self, max_requests: int, rps: float):
        self.left, self.sent = max_requests, 0
        self.gap = 1.0 / rps if rps > 0 else 0.0
        self._last = 0.0

    def take(self) -> bool:
        if self.left <= 0:
            return False
        wait = self._last + self.gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        self.left -= 1
        self.sent += 1
        return True


def build_request(base: str, op: dict, values: dict) -> tuple:
    path = op["path"]
    query, headers = [], {"User-Agent": "secai-api-fuzz-lab",
                          "Accept": "application/json"}
    for p in op["params"]:
        v = values.get(("p", p["name"]))
        sv = v if isinstance(v, str) else json.dumps(v)
        if p["in"] == "path":
            path = path.replace("{" + p["name"] + "}",
                                urllib.parse.quote(sv, safe=""))
        elif p["in"] == "query":
            query.append((p["name"], sv))
        elif p["in"] == "header":
            headers[p["name"]] = re.sub(r"[\r\n]", "", sv)[:4096]
    data = None
    if op["body"] is not None:
        body = {k: values.get(("b", k)) for k in op["body"]}
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    url = base.rstrip("/") + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    return url, headers, data


def send(base: str, op: dict, values: dict) -> dict:
    url, headers, data = build_request(base, op, values)
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=op["method"])
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            body = r.read(MAX_BODY).decode("utf-8", "replace")
            status = r.status
    except urllib.error.HTTPError as e:
        body = (e.read(MAX_BODY) or b"").decode("utf-8", "replace")
        status = e.code
    except (urllib.error.URLError, ConnectionError, socket.timeout,
            OSError) as exc:
        return {"url": url, "status": None, "body": "",
                "error": f"{type(exc).__name__}: {exc}"[:160],
                "ms": int((time.monotonic() - t0) * 1000)}
    return {"url": url, "status": status, "body": body,
            "ms": int((time.monotonic() - t0) * 1000)}


def signatures(body: str) -> set:
    return {name for name, rx in ERROR_SIGNATURES if rx.search(body or "")}


def classify(base_resp: dict, resp: dict, payload, slow_ms: int
             ) -> "tuple[str, str] | None":
    """(kind, detail) when `resp` is anomalous relative to the baseline."""
    if resp["status"] is None:
        return "connection-drop", resp.get("error", "")
    new_sigs = signatures(resp["body"]) - signatures(base_resp["body"])
    if resp["status"] >= 500 and base_resp["status"] < 500:
        return "server-error", ",".join(sorted(new_sigs)) or "5xx"
    if new_sigs:
        return "error-leak", ",".join(sorted(new_sigs))
    if isinstance(payload, str) and payload in MARKERS and \
            MARKER_RESULT in resp["body"] and \
            MARKER_RESULT not in base_resp["body"] and \
            payload not in resp["body"]:
        return "template-eval", payload
    if resp["ms"] > base_resp["ms"] + slow_ms:
        return "slow-response", f"{resp['ms']}ms vs baseline " \
                                f"{base_resp['ms']}ms"
    return None


KIND_INFO = {
    "server-error": ("medium", "CWE-248", "Unhandled input causes a 5xx"),
    "error-leak": ("medium", "CWE-209", "Error / stack trace leaked for "
                                        "malformed input"),
    "template-eval": ("high", "CWE-1336", "Template expression evaluated"),
    "slow-response": ("medium", "CWE-400", "Input makes the response "
                                           "much slower"),
    "connection-drop": ("high", "CWE-248", "Input drops the connection "
                                           "(possible crash)"),
}


def mutations(op: dict, seed: int):
    """Yield (target, name, payload) deterministically per operation."""
    rng = random.Random(f"{seed}:{op['method']}:{op['path']}")
    fields = [("p", p["name"], p["schema"]) for p in op["params"]]
    fields += [("b", k, s) for k, s in (op["body"] or {}).items()]
    for kind, name, schema in fields:
        t = _schema_type(schema)
        corpus = list(NUMBER_CORPUS if t in ("integer", "number") else
                      STRING_CORPUS)
        if kind == "b":
            corpus += CONFUSION
        rng.shuffle(corpus)
        for payload in corpus:
            yield kind, name, payload


def run(base: str, ops: list, budget: Budget, seed: int, slow_ms: int
        ) -> tuple[list[dict], dict]:
    anomalies, skipped, seen = [], [], set()
    stopped = None
    for op in ops:
        label = f"{op['method']} {op['path']}"
        base_vals = {("p", p["name"]): baseline_value(p["schema"])
                     for p in op["params"]}
        base_vals.update({("b", k): baseline_value(s)
                          for k, s in (op["body"] or {}).items()})
        if not (budget.take() and budget.take()):
            break
        b1, b2 = send(base, op, base_vals), send(base, op, base_vals)
        if b1["status"] is None or b2["status"] is None:
            stopped = f"baseline of {label} unreachable"
            break
        if b1["status"] // 100 != b2["status"] // 100 or b1["status"] >= 500:
            skipped.append({"op": label, "reason":
                            f"unstable/5xx baseline ({b1['status']}, "
                            f"{b2['status']})"})
            continue
        base_resp = dict(b1, ms=max(b1["ms"], b2["ms"]))
        for kind, name, payload in mutations(op, seed):
            if not budget.take():
                break
            vals = dict(base_vals)
            vals[(kind, name)] = payload
            resp = send(base, op, vals)
            hit = classify(base_resp, resp, payload, slow_ms)
            if hit is None:
                continue
            key = (label, name, hit[0], hit[1].split(",")[0][:20])
            if key in seen:
                continue
            seen.add(key)
            again = send(base, op, vals) if budget.take() else None
            hit2 = classify(base_resp, again, payload, slow_ms) \
                if again is not None else None
            repro = hit2 is not None and hit2[0] == hit[0]
            anomalies.append({
                "op": label, "param": name, "where": kind, "kind": hit[0],
                "detail": hit[1], "payload": payload, "reproduced": repro,
                "baseline_status": base_resp["status"],
                "status": resp["status"], "ms": resp["ms"],
                "url": resp["url"], "body": resp["body"][:4000]})
            if resp["status"] is None:
                alive = send(base, op, base_vals) if budget.take() else None
                if alive is None or alive["status"] is None:
                    stopped = f"service stopped answering after input to " \
                              f"{label} param {name}"
                    break
        if stopped:
            break
    return anomalies, {"skipped_ops": skipped, "stopped": stopped}


def audit(base: str, anomalies: list, info: dict) -> tuple[list[dict], dict]:
    """Pure: anomalies -> (rows, meta)."""
    rows = []
    for a in anomalies:
        sev, cwe, label = KIND_INFO[a["kind"]]
        if a["kind"] in ("error-leak", "server-error") and \
                "sql" in a["detail"].split(","):
            sev, cwe = "high", "CWE-89"  # DB error on malformed input: lead
        payload = a["payload"] if isinstance(a["payload"], str) else \
            json.dumps(a["payload"])
        rows.append(make_finding(
            tool=TOOL,
            title=f"{label}: {a['op']} {a['where'] == 'b' and 'body' or 'param'}"
                  f" '{a['param']}'",
            severity=sev, cwe=cwe,
            description=(f"Mutated input {payload[:80]!r} turned a stable "
                         f"baseline ({a['baseline_status']}) into "
                         f"{a['kind']} ({a['detail'][:120]}; status "
                         f"{a['status']}, {a['ms']} ms). "
                         + ("Reproduced on a second send." if
                            a["reproduced"] else "Seen once (LEAD).")
                         + " Lab finding: root-cause it in code; it is not "
                           "an exploit."),
            recommendation="Validate and type-check this input at the edge; "
                           "handle the error path without leaking internals; "
                           "add the payload as a regression test.",
            target_url=a["url"], param=a["param"],
            request=f"{a['op']} {a['url']}"[:600],
            response=a["body"][:600], evidence_kind="request-response",
            finding_class="weakness", lab_only=True,
            confidence=0.9 if a["reproduced"] else 0.5,
            status="confirmed", verdict=2 if a["reproduced"] else 1,
            extra={"category": "LEAD", "kind": a["kind"],
                   "payload": payload[:300], "reproduced": a["reproduced"],
                   "safety_class": "active-probe"}))
    meta = {"schema": SCHEMA, "base_url": base, "anomalies": len(rows),
            **info}
    return rows, meta


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="[LAB: loopback-only] api-fuzz-lab: OpenAPI-driven "
                    "differential fuzzer for your own lab service. "
                    "Requires env LAB=1.")
    ap.add_argument("--spec", required=True,
                    help="OpenAPI 3 / Swagger 2 document (JSON file)")
    ap.add_argument("--base-url", required=True,
                    help="loopback base URL, e.g. http://127.0.0.1:8000")
    ap.add_argument("--methods", default="get",
                    help="comma list; default get (others change state)")
    ap.add_argument("--max-requests", type=int, default=400)
    ap.add_argument("--rps", type=float, default=25.0)
    ap.add_argument("--slow-ms", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", default="api_fuzz_lab.json")
    ap.add_argument("--corpus-out", default=None,
                    help="JSONL of anomalous inputs (for crash_triage)")
    ap.add_argument("--fail-on", default="medium",
                    choices=["none", "low", "medium", "high", "critical"])
    args = ap.parse_args(argv)

    refused, gate = lab_gate.check(args.base_url, TOOL, allow_remote=False)
    if refused is not None:
        return refused
    if not (1 <= args.max_requests <= 100_000) or args.rps <= 0:
        print(f"[{TOOL}] input error: --max-requests 1..100000, --rps > 0",
              file=sys.stderr)
        return 2
    methods = {m.strip().lower() for m in args.methods.split(",")
               if m.strip()}
    try:
        raw = Path(args.spec).read_bytes()
        if len(raw) > MAX_SPEC_BYTES:
            raise ValueError("spec larger than 8 MiB")
        ops = load_operations(json.loads(raw.decode("utf-8-sig")), methods)
    except (OSError, ValueError) as exc:
        print(f"[{TOOL}] input error: --spec: {exc}", file=sys.stderr)
        return 2
    if not ops:
        print(f"[{TOOL}] input error: no operation with methods "
              f"{sorted(methods)} in the spec", file=sys.stderr)
        return 2
    budget = Budget(args.max_requests, args.rps)
    anomalies, info = run(args.base_url, ops, budget, args.seed,
                          args.slow_ms)
    info.update({"operations": len(ops), "requests": budget.sent,
                 "methods": sorted(methods), "seed": args.seed})
    rows, meta = audit(args.base_url, anomalies, info)
    meta.update(gate)
    meta.update({"safety_class": "active-probe", "lab_only": True})
    write_findings(args.out, rows, meta)
    if args.corpus_out:
        with open(args.corpus_out, "w", encoding="utf-8") as fh:
            for a in anomalies:
                fh.write(json.dumps({"source": TOOL, **{
                    k: a[k] for k in ("op", "param", "kind", "detail",
                                      "status", "reproduced", "body")},
                    "payload": a["payload"] if isinstance(a["payload"], str)
                    else json.dumps(a["payload"])}) + "\n")
    print(f"{TOOL}: {len(rows)} anomaly(ies) over {len(ops)} operation(s), "
          f"{budget.sent} request(s)"
          + (f", STOPPED: {info['stopped']}" if info["stopped"] else "")
          + f" -> {args.out}")
    if args.fail_on == "none":
        return 0
    thr = SEV_ORDER[args.fail_on]
    return 1 if any(SEV_ORDER[r["severity"]] >= thr for r in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
