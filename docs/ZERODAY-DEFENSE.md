# Zero-day defense — find, triage, detect, respond

A zero-day is a bug nobody has a signature for yet, so matching against
CVE databases cannot catch it. Defending against it means four things:
find the bug in your own code before an attacker does, triage what your
testing produces, catch the *behaviour* of exploitation when it happens
anyway, and respond fast when one is disclosed. secai covers each step
with offline or lab-only tools. None of them produces an exploit; every
output is a finding, its location and how to fix it.

**Lab gate:** only `api_fuzz_lab` sends traffic. It refuses to run
without `LAB=1` and is **loopback-only** — `LAB_REMOTE_ACK` cannot open
it. Everything else reads files you give it.

```
  your code ──► 1. taint_engine ──► leads with source→sink flows
      │
      ▼ (run it locally)
  your service ──► 2. api_fuzz_lab ──► anomalies + crash corpus
                                              │
                                              ▼
                       3. crash_triage ◄── sanitizer logs, tracebacks
                              │
                              ▼ fix, add regression test
  production telemetry ──► 4. exploit_behavior_hunt ──► intrusion shape
  disclosure day ──► 5. cve_matcher / detection_rule_gen / kev_gap
```

## 1. Find unknown injection bugs in source — `taint_engine`

```bash
python tools/taint_engine.py --repo path/to/your/app --out taint.json
```

- Python: real AST dataflow, across functions **and files** (per-parameter
  summaries iterated to a fixed point). JS/TS and PHP: intra-file
  heuristics at lower confidence.
- Sources: request data in Flask/Django/FastAPI/Starlette, Express/Koa,
  PHP superglobals; route parameters of decorated handlers.
- Sinks: SQL, OS command, eval/exec, file paths, outbound URLs (SSRF),
  template source (SSTI), deserialization, unescaped markup, redirects.
- Zero-FP rules: only the dangerous argument counts (parameterised
  queries, list-form `subprocess`, constant URLs are safe); sanitizers are
  per class; unknown library calls do not propagate taint.
- Each row is an L1 lead with the full trace, for example
  `app.py:21 request.args → find_user(arg 0) → db.py:6 query →
  db.py:7 cur.execute()`.
- Fixtures: `tests/fixtures/zeroday/taint_vuln` (23 flows) and its safe
  twin `taint_safe` (0 flows).

## 2. Shake your running service — `api_fuzz_lab`

```bash
LAB=1 python tools/api_fuzz_lab.py --spec openapi.json \
    --base-url http://127.0.0.1:8000 --corpus-out crashes.jsonl
```

- Reads your OpenAPI 3 / Swagger 2 JSON, sends deterministic mutations
  (boundaries, type confusion, quotes, long strings, a template marker) to
  every parameter. GET only unless you add `--methods`.
- Differential oracle against a stable baseline: new 5xx, new
  stack-trace / DB-error signature, template arithmetic evaluated, much
  slower response, dropped connection. Each anomaly is re-sent once —
  reproduced = L2. Flaky endpoints are skipped, not guessed.
- Fixture: `tests/fixtures/zeroday/fuzz_app.py` (5 fragile routes, 4
  FP-control routes).

## 3. Turn 500 crash logs into 5 bugs — `crash_triage`

```bash
python tools/crash_triage.py --input crashes.jsonl --dir sanitizer-logs/
```

- ASan / UBSan / MSan / LSan / TSan, segfaults, Python, Go, Java, Node.
- Buckets by bug class + top 3 project frames (addresses and line numbers
  ignored, so rebuilds do not split a bug); ranks memory corruption
  (write overflow, use-after-free, double free) first.

## 4. Catch exploitation in progress — `exploit_behavior_hunt`

```bash
python tools/exploit_behavior_hunt.py --events today.jsonl \
    --baseline last-week.jsonl
```

- A web or database server starting a shell, binaries run from writable
  temp paths by service accounts, first-seen lineage and egress against a
  baseline, and the full chain server → shell → outbound.
- Sysmon XML (EID 1/3) or JSONL from any EDR/auditd pipeline. Hosts
  without baseline coverage are reported as such, never as clean.
- Companions: `webshell_triage` (access logs), `lolbin_scan`,
  `sysmon_triage`.

## 5. Disclosure day — existing response tools

- Am I affected? `tools/cve_matcher.py --findings scan.json`, SBOM and
  version facts; `tools/kev_gap.py` for KEV deadlines.
- Virtual patch while you upgrade: `tools/detection_rule_gen.py`
  (Sigma + YARA from a finding).
- Blast radius: `tools/container_escape_check.py`,
  `tools/insecure_defaults.py`, the escalation playbooks.

## Evidence contract

| Output | Level | Why |
|---|---|---|
| taint flow | L1 | a path exists in code; exploitability not shown |
| fuzz anomaly seen once / reproduced | L1 / L2 | the service mishandles the input, reproducibly |
| crash bucket | L1 (L2 if the fuzzer reproduced it) | triage by class, not proof |
| behaviour lead | L1 | observed in telemetry; needs investigation |

Promotion to L3 needs a reproduced proof in your lab under the exploit
tier's gates ([EXPLOIT-TIER.md](EXPLOIT-TIER.md)).
