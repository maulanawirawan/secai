# AGENTS.md — guidance for AI coding agents (and humans who read code)

secai is an evidence-first security assessment engine: skills collect
evidence, a quorum (FAO) verifies it, and the engine refuses to report
anything it cannot prove. "No proof, no report" is the contract — the
proof tier builds gated PoCs to turn a lead into evidence, but a lead
that cannot be proven never ships.

## Repo map

- `secai.py` — one-command mode board (`scan | validate | scout | night
  | intel | fresh | contrib | ledger | report | mcp | skills | lab |
  guard | shield | gate`);
  every mode has its own `--help`. Start here.
- `SKILL.md` — the agent manual: safe playbook + guardrails (also mounted
  as `.claude/skills/secai/`).
- `skills/` — 113 standalone Python CLIs, one detection skill each
  (`--url` / `--target` ... `--out result.json`). This is what users run.
  Registry entries with `"tier": "exploit-lab"` (`jwt_lab`,
  `ssrf_metadata_lab`) are lab-only exploit proofs: they refuse to run
  unless env `LAB=1` (gate in `core/lab_gate.py`; non-loopback targets
  also need `LAB_REMOTE_ACK=<written reason>`; refusal = exit 2).
- `core-rs/` — native Rust core (`secai validate | scan ...`).
  Build: `cargo build --release --manifest-path core-rs/Cargo.toml`
- `tools/` — helpers (227 offline triage tools, incl. quishing/doc-bait wave-2: `qr_vcard_triage`, `doc_beacon_triage`, `capture_triage`, `evtx_hunt`; wave-3: `html_smuggling_triage`, `unquoted_service_path_triage`, `vm_artifact_triage`; wave-4: `defender_tamper_triage`, `gpp_cpassword_triage`, `rdp_enable_triage`; wave-5: `lnk_triage`, `hidden_account_triage`, `llmnr_pcap_scan`; wave-6: `script_assoc_audit`, `link_spoof_triage`, `scom_artifact_triage`; wave-7: `whoami_priv_triage`, `systeminfo_triage`, `usb_device_triage`, `translate_proxy_triage`, `cme_log_triage`, `pingcastle_report_triage`, `sigma_rule_triage`, `nessus_report_triage`; wave-8: `dom_sink_scan`; wave-9: `retest_ledger`, `coverage_ledger`, `snaffler_log_triage`, `seatbelt_output_triage`; wave-10: `patch_guard_triage`; wave-12: `container_escape_check`): lab target (`tools/lab_target.py`), planner,
  benchmarks, self-update, MCP server (`tools/mcp_server.py`), scout,
  session ledger, contribution pipeline (`cve_sweep`, `antidup_check`),
  agent-safety (`injection_guard`, `agent_shield`), audit engines
  (`audit_phases` multi-phase fail-closed, `insecure_defaults` config
  scanner), verify gate (`verify_gate` — claims need fresh evidence), leak-claim triage (`leak_triage`), parallel job dispatch (`fleet_dispatch`), skill vetting gate (`skill_vet`), CVSS v3.1 calculator (`cvss_score`), DFIR, config & intel triage (28+ tools triage: maldoc/pdf/mft/netflow/deauth/dpapi/packer/web-log/dns-log/eml/k8s/cloudtrail/IAM/sysmon/win-logon/waf/lolbin/CT-baseline/IOC-defang/SARIF-ingest/dsb. — lihat git log).
- `tests/` — pytest suite (3806 tests + 205 subtests with the Rust release build present; without it 5 core-binary tests skip; POSIX-only tests skip automatically on Windows). Run: `python -m pytest tests/ -q`
- `docs/` — policies: exploit tier, egress, install, nightrun, legion
  method (`docs/LEGION-METHOD.md`), agent playbook utk kelas kerentanan
  aktif yang butuh penalaran LLM (`docs/HUNT-ACTIVE-CLASSES.md` —
  file-upload/race/MFA-ATO/business-logic, contoh request + gate),
  escalation playbooks (`docs/ESCALATION-LINUX.md`,
  `docs/ESCALATION-WINDOWS.md`, `docs/ESCALATION-CLOUD.md`) and
  auth chains (`docs/AUTH-ATTACK-CHAINS.md`) — patterns + detection
  commands + lab gate per technique, no weaponised code. Runnable
  examples: `docs/QUICKSTART.md` (executed by `tests/test_quickstart_docs.py`
  — keep every `<!-- example -->` block runnable). Contribution contracts:
  `CONTRIBUTING.md`.

## Ground rules (non-negotiable)

1. Authorized targets only — own assets, explicit written permission, or
   a local lab. This is a tool for learning and for sanctioned testing,
   not for hitting systems you have no right to touch.
2. Evidence is the product. A finding only counts when it carries
   verifiable evidence; if it cannot be proven, the verdict stays quiet
   (fail-closed). "No proof, no report."
3. The proof tier (`tools/exploit_*`) builds reproducible PoCs to turn a
   lead into proof — but only under its gates: `exploit_allowed` per
   target, lab/staging by default, three keys for anything destructive.
   The NEVER-LIST (DoS, persistence/backdoor, worms, ransomware-sim,
   mass exfiltration) is refused no matter what flags are passed — do
   not add techniques from it, and do not weaken the gates. Exploit-lab
   skills add a fourth key on top: env `LAB=1` (no flag can replace it).
4. License is PolyForm NC: free for noncommercial use, commercial use by
   arrangement with the owner. Contributions follow the same license.

## Commands

- run all tests: `python -m pytest tests/ -q`
- run one skill: `python skills/banner_posture.py --url https://example.com --out banner.json`
- validate an output: `core-rs/target/release/secai validate banner.json`
- local playground: `python tools/lab_target.py` (safe target for skills)

## Adding a skill (the most common contribution)

1. Copy the reference shape: `skills/banner_posture.py` (small, argparse,
   evidence dict out).
2. Your output must satisfy the contract (`secai validate` decides).
3. Add a unit test under `tests/` mirroring the naming scheme.
4. Run the full suite — green before the PR. Small and focused PRs win.

## Style

- Python: stdlib-first, match the surrounding code, type hints where
  already present.
- Docs/messages: plain and honest. English or Indonesian, both fine.
- PRs: include before/after evidence for any behavior change.
