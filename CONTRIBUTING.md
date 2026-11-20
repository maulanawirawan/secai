# Contributing to secai

*(Ringkasan Bahasa Indonesia di bawah.)*

Thanks for wanting to help. Bug fixes, new detection skills, offline
tools, false-positive reports, docs, even typos — all welcome. This page
tells you exactly what a contribution has to satisfy, so a first PR can
be merged without guesswork. Every rule below is enforced by a test; if
the suite is green, you have met the contract.

```bash
python -m pytest tests/ -q          # the whole contract, ~5 min, zero network
python -m pytest tests/test_<yours>.py -q   # while iterating
```

## Ground rules

- **Authorized testing only** — your own assets, a local lab, or a program
  that gives explicit permission. Same rule as the README, no exceptions.
- **Proof, not claims** — a PR that changes behaviour shows before/after
  output. The project holds its PRs to the bar it holds its findings to.
- **Zero network in tests.** Fixtures are local files or servers bound to
  `127.0.0.1` on an ephemeral port.
- **Never weaken a gate or the NEVER-LIST** (DoS, persistence/backdoor,
  worms, ransomware simulation, mass exfiltration). PRs adding those
  techniques are closed, whatever the framing.
- One PR, one idea. Python: standard library first, match the code
  around you. English or Indonesian in comments and messages is fine.

## Which kind of contribution is it?

| You want to… | Add a… | Lives in |
|---|---|---|
| check a live target (request-based, budgeted) | **skill** | `skills/<name>.py` + a `skills/registry.json` entry |
| analyse an artefact offline (logs, exports, configs, binaries) | **tool** | `tools/<name>.py` |
| prove an exploit class in a lab | **exploit-lab skill** | `skills/<name>_lab.py`, `"tier": "exploit-lab"` |
| teach a technique (no code) | **playbook** | `docs/<NAME>.md` |

Look at a recent example of the same kind before starting:
`skills/banner_posture.py` (small skill), `tools/container_escape_check.py`
(offline tool), `skills/jwt_lab.py` (exploit-lab), `docs/ESCALATION-LINUX.md`
(playbook).

## The four skill contracts

**1. Output contract — one door.** Every row is built with
`core/findings.py: make_finding(...)` and written with `write_findings()`.
Never hand-build the JSON. Verdicts follow the ladder: `0` checked/clean,
`1` lead, `2` reproduced, `3`+ proven (requires `request`, `response` or
`poc` evidence — `make_finding` refuses otherwise). Check any output with
`python secai.py validate out.json`.

**2. Shape contract.** A pure `audit(...) -> (rows, meta)` that does no
I/O, and a `main(argv: list[str] | None = None) -> int` that parses
arguments, does the I/O and calls `audit`. Every `return` in `audit` is a
literal 2-tuple (an AST guard, `tests/test_tool_skill_signature_guard.py`,
checks this). `main` must accept `argv` so tests can call it in-process.

**3. Safety contract.** The registry entry declares a `safety_class`
(`read-only`, `1-request`, `bounded-requests`, `active-probe`,
`credential-bearing`, `state-changing`) and `needs`. tier0 scans only run
the first three. Anything active is `lab_only: true` and refuses to run
without its gate (`--lab` / `LAB=1`; exploit-lab: `LAB=1` only, checked by
`core/lab_gate.py`, refusal = exit 2 before the first request). Declare an
honest `est_requests` if you send more than the class default. Add a
curation line for your skill to `STRATEGI` in `tools/verdict_audit.py`
(how its verdict could ever be raised, or `"-"` if it is pure posture).

**4. Zero-false-positive contract.**
- Bad, missing or unreadable input → message on stderr, **exit 2**, no
  claim. Never treat "no evidence" as "evidence of absence".
- Ship an **FP-control** test: a lookalike input that must NOT fire (a
  hardened config, a fixed endpoint, an echo/honeypot response).
- Claims above L1 need a differential with a control (baseline that must
  fail, reproduced twice) — see `skills/jwt_lab.py`.
- Output must survive a Windows `cp1252` console and CRLF input; split
  paths with `re.split(r"[\\/]+", p)`, never a hardcoded separator.

## The tool contract (offline `tools/`)

- Docstring starts with `[SAFETY: read-only]` (plus what it reads), and
  the module never opens a socket.
- Evidence in (file / directory flags) → deterministic `findings.json`
  out (`--out`), same input = byte-identical rows.
- Exit codes: `0` nothing at or above `--fail-on`, `1` findings at or
  above it, `2` input error (missing, empty, binary, malformed —
  `tests/test_reliability_hardening.py` shows the cases).
- Tests under `tests/test_<tool>.py` with fixtures under `tests/fixtures/`
  including at least one FP-control.

## Bookkeeping when the count changes

Adding a skill or a tool changes public numbers. In the **same** PR:

1. `skills/registry.json` entry (skills only) and the `STRATEGI` line.
2. Counts in `README.md`, `README.es.md`, `README.zh.md`, `AGENTS.md`,
   `SKILL.md` — `tests/test_doc_counts_truth.py` derives the real numbers
   and tells you every stale line.
3. The literal count in `tests/test_secai_cli.py` (`"<N> skill"`).
4. A `CHANGELOG.md` entry under `[Unreleased]`.

`agent-shield.lock.json` pins the agent-facing files (`SKILL.md`,
`AGENTS.md`, `skills/registry.json`, …). **Do not re-pin it in your PR** —
a maintainer re-pins after review; that pin is the approval.

## Reporting a false positive

FP reports are first-class: open one with the
[false positive template](.github/ISSUE_TEMPLATE/false_positive.md)
including the input (redacted) and the row it produced. Each one becomes
an FP-control test.

## License

Contributions fall under the [LICENSE](LICENSE.md) (PolyForm NC): free for
noncommercial use. If secai is ever used commercially, that is sorted out
in the open with everyone who contributed — standard for a
source-available project. A merged PR puts you in the contributors list.

---

# Kontribusi ke secai (ringkas)

- Hanya pengujian **berotorisasi**; test tanpa jaringan; jangan pernah
  melemahkan gerbang/NEVER-LIST.
- **Skill** (`skills/`, target live) vs **tool** (`tools/`, artefak
  offline) vs **exploit-lab** (`LAB=1`) vs **playbook** (`docs/`).
- Empat kontrak skill: (1) output via `make_finding`/`write_findings`;
  (2) `audit()` murni → `(rows, meta)`, `main(argv=None)`;
  (3) `safety_class` + registry + gate + `STRATEGI`; (4) zero-FP:
  input buruk/tanpa bukti = exit 2 tanpa klaim, wajib test FP-control,
  aman di konsol cp1252.
- Jumlah berubah? Perbarui README ×3, AGENTS, SKILL, test literal, dan
  CHANGELOG di PR yang sama — `tests/test_doc_counts_truth.py` menunjuk
  baris yang basi. Lock agent-shield di-pin ulang oleh maintainer.
- Jalankan `python -m pytest tests/ -q` sebelum membuka PR.
