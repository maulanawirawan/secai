# secai v0.2.0 — release notes (draft)

*Draft for the maintainer to tag. Covers everything since `v0.1.0`
(2026-11-03, commit `113a037`): 241 commits. Full detail per wave is in
[CHANGELOG.md](../CHANGELOG.md).*

## In one paragraph

secai grew from 92 registered detection skills and ~40 tools to **113
skills and 227 offline tools**, gained a network guard, an exploit-lab
tier behind an environment gate, and four escalation/auth playbooks. The
last wave was spent on dependability: every evidence-only skill is now
proven not to claim anything from missing evidence, malformed inputs fail
closed instead of crashing, and the README quickstart is executed by the
test suite so it cannot silently break again.

## Highlights

**Trust (zero false positives)**
- Six header-family skills no longer report "header absent" when their
  evidence file does not exist; a test runs every evidence-only skill with
  missing evidence and fails on any claim.
- `cookie-scope` works on real scan evidence (it crashed on every scan).
- 14 CLIs that raised Python tracebacks on bad input now exit 2 with a
  message; Windows `cp1252` consoles no longer crash `--help` or output.

**Getting started**
- The 60-second quickstart works as written (it targeted the wrong port
  and an evidence-less skill before) and is executed in CI for all three
  README languages, together with four examples in
  [docs/QUICKSTART.md](QUICKSTART.md).
- `tools/lab_target.py --port/--bind` (default 8777 as documented);
  `secai.py validate` accepts skill output without building Rust.
- Public counts are derived from the repo and test-checked.

**Capability**
- Exploit-lab tier: `jwt_lab` (alg:none, RS256→HS256 confusion, kid
  traversal) and `ssrf_metadata_lab` (SSRF → IMDSv1, stops at the role
  name). Gate: `LAB=1`, loopback or a written `LAB_REMOTE_ACK`; tier0 never
  selects them.
- `container_escape_check`: runtime escape preconditions from `/proc`.
- Playbooks: Linux / Windows / cloud escalation, auth attack chains.
- Waves 2–11: 180+ offline triage tools (Windows/Linux DFIR, cloud and
  container config, supply chain, AI/LLM posture), net-guard (request
  budget, scope default-deny, IP pinning), active-probe skills behind
  `--lab`.

## Upgrade notes

- **Behaviour change:** header-family skills and `banner_posture` /
  `js_endpoints` / `tech_fingerprint` / `cookie_scope` exit **2** when
  their evidence is missing (previously: claims or a traceback). In a
  scan the runner records this as a failed skill run with zero findings.
- `python tools/lab_target.py` now binds **127.0.0.1:8777** by default
  (was a random port). `--port 0` restores the old behaviour;
  `SECAI_LAB_PORT` still wins (Docker sandbox unchanged).
- `secai.py validate` (no Rust build) prints one summary line per file.

## Verification at the release commit

- `python -m pytest tests/ -q` — 3,794+ passed, zero network.
- `cargo test --manifest-path core-rs/Cargo.toml` — 68 passed.
- `python tools/agent_shield.py verify` — CLEAN.
- CI: test, coverage, docker-smoke green.

## Tagging (maintainer)

```bash
git tag -a v0.2.0 -m "secai v0.2.0" <release-commit>
git push origin v0.2.0
```

Then paste this file into the GitHub release and update the README
release badge.
