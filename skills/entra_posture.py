"""[SAFETY: bounded-requests] entra-posture — inventori/paparan identity
Microsoft Entra ID (Azure AD) / dependensi M365 dari target URL
(POSTURE identity enterprise). Read-only, maks 3 GET ke
/.well-known/openid-configuration, /, /adfs/ls/idpinitiatedsignon.htm.

Signature ketat (zero-FP): issuer di discovery berbasis
login.microsoftonline.com / token eksplisit "Microsoft Entra"/"Azure
Active Directory"/"AADSTS"/"Office 365" — frasa generik "cloud identity"
TIDAK dihitung. Tenant id di path issuer dicatat sebagai fakta.

Sinyal:
  - entra-issuer-detected : discovery issuer Entra (inventori verdict 0,
    tenant id di evidence).
  - entra-legacy-adfs     : path ADFS merespons dgn marker ADFS —
    permukaan federasi legacy pada host (lead medium, verifikasi
    endpoint konsumen manual).
  - entra-dep-marker      : body halaman utama memuat referensi
    login.microsoftonline.com / Office 365 (inventori).
Fail-closed jaringan (tanpa klaim AMAN).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 3
TIMEOUT_S = 10.0
PROBES = ("/.well-known/openid-configuration", "/",
          "/adfs/ls/idpinitiatedsignon.htm")
_RE_MS_ISSUER = re.compile(
    r"https://login\.microsoftonline(?:\.us|de)?\.com/([0-9a-fA-F-]{36}|[a-z0-9\-]+)",
    re.I)
_RE_ENTRA = re.compile(
    r"Microsoft Entra|Azure Active Directory|AADSTS|Office 365|"
    r"login\.microsoftonline", re.I)
_RE_ADFS = re.compile(r"\bADFS\b|Active Directory Federation Services", re.I)


def _fetch(base: str, path: str) -> dict:
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent": "secai-entra-posture"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"path": path, "status": r.status,
                    "headers": dict(r.headers.items()),
                    "body": r.read(32_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"path": path, "status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": (e.read(8_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:
        return {"path": path, "status": None, "headers": {}, "body": "",
                "error": "%s: %s" % (type(exc).__name__, exc)[:120]}


def audit(url: str, results: list[dict]) -> tuple[list[dict], dict]:
    """Murni: hasil probe -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    by = {r.get("path"): r for r in results}
    oconf = by.get("/.well-known/openid-configuration") or {}
    home = by.get("/") or {}
    adfs = by.get("/adfs/ls/idpinitiatedsignon.htm") or {}

    issuer = None
    tenant = None
    try:
        disc = json.loads(oconf.get("body") or "{}")
        issuer = disc.get("issuer")
    except Exception:
        disc = {}
    m = _RE_MS_ISSUER.search(str(issuer or ""))
    if m:
        tenant = m.group(1)

    blob_all = " ".join((r.get("body") or "")[:4000] for r in results) + \
        " " + str(issuer)
    entra_marker = bool(_RE_ENTRA.search(blob_all))
    detected = bool(tenant) or entra_marker

    adfs_body = (adfs.get("body") or "")
    adfs_lead = adfs.get("status") == 200 and bool(_RE_ADFS.search(adfs_body))

    rows: list[dict] = []
    if detected:
        rows.append(make_finding(
            tool="entra-posture",
            title="Dependensi Microsoft Entra ID/M365 terdeteksi di %s" % base,
            severity="info",
            description="Issuer=%s%s; inventori identity surface — cek "
                        "kebijakan conditional access, tenant health, dan "
                        "konsolidasi aplikasi yang memercayai tenant."
                        % (issuer or "(discovery tidak eksplisit)",
                           " tenant=%s" % tenant if tenant else ""),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "SURFACE", "safety_class": "bounded-requests",
                   "issuer": issuer, "tenant": tenant}))
    if adfs_lead:
        rows.append(make_finding(
            tool="entra-posture",
            title="Endpoint ADFS terpapar di %s (federasi legacy)" % base,
            severity="medium",
            description="Path idpinitiatedsignon merespons 200 dgn marker "
                        "ADFS — permukaan federasi legacy tetap hidup di "
                        "host (jalur serangan identity klasik: token "
                        "signing, relay, ekspos endpoint).",
            recommendation="Migrasi/retire ADFS ke Entra native; "
                           "patch + audit ADFS per advisory; batasi "
                           "eksplos endpoint federation publik.",
            target_url=base + "/adfs/ls/idpinitiatedsignon.htm",
            evidence_kind="request-response", finding_class="posture",
            confidence=0.8, status="confirmed", verdict=1,
            extra={"category": "LEAD", "safety_class": "bounded-requests"}))
    if not rows:
        net_fail = all(r.get("status") is None for r in results)
        rows.append(make_finding(
            tool="entra-posture",
            title=("Gagal jaringan pada %s — tanpa klaim AMAN" if net_fail
                   else "Tidak ada marker Entra/M365 di %s") % base,
            severity="info",
            description=("Semua GET gagal jaringan (fail-closed)."
                         if net_fail else
                         "Discovery/marker Entra/M365 tidak teramati "
                         "(AMAN/inventaris — signature ketat)."),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "network_error": net_fail,
                   "error": (results[0].get("error") if results else "") or ""}))

    meta = {"url": base, "requests": len(results), "detected": detected,
            "issuer": issuer, "tenant": tenant, "adfs": adfs_lead}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="entra_posture.json")
    args = ap.parse_args()
    base = args.url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base
    results = []
    for p in PROBES:
        if len(results) >= MAX_GETS:
            break
        results.append(_fetch(base, p))
    rows, meta = audit(args.url, results)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print("entra-posture: detected=%s tenant=%s adfs=%s -> %s"
          % (meta["detected"], meta["tenant"], meta["adfs"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
