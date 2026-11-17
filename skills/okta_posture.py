"""[SAFETY: bounded-requests] okta-posture — inventori/paparan identity
provider Okta dari target URL (POSTURE identity; kelas identity-provider
enterprise). Read-only, maks 3 GET ke /.well-known/openid-configuration,
/admin, /.

Signature ketat (zero-FP): token "okta" di issuer/audience/body OKTA
(via discovery JSON) — frasa generik "identity" TIDAK dihitung. Admin
console /admin yang merespons 200 tanpa auth = lead paparan; 401/302 ke
login = terlindungi. Versi tak berlaku utk SaaS — tidak ada klaim CVE.
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
PROBES = ("/.well-known/openid-configuration", "/admin", "/")
_RE_OKTA = re.compile(r"okta(?:-emea|-au|-eu)?\.com|\"okta\"", re.I)
_RE_ADMIN_BLOCK = re.compile(
    r"login\.okta|signin|sign-in|<title>.*(login|sign in)", re.I)


def _fetch(base: str, path: str) -> dict:
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent": "secai-okta-posture"})
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
    admin = by.get("/admin") or {}

    issuer = None
    okta_detected = False
    try:
        disc = json.loads(oconf.get("body") or "{}")
        issuer = disc.get("issuer")
    except Exception:
        disc = {}
    blob_all = " ".join(
        (r.get("body") or "")[:4000] for r in results) + " " + str(issuer)
    okta_detected = bool(_RE_OKTA.search(blob_all))

    admin_open = admin.get("status") == 200 and not _RE_ADMIN_BLOCK.search(
        admin.get("body") or "")

    rows: list[dict] = []
    if okta_detected:
        rows.append(make_finding(
            tool="okta-posture",
            title="Okta identity provider terdeteksi di %s" % base,
            severity="info",
            description="Token okta eksplisit pada discovery/badge "
                        "(issuer=%s) — inventori identity surface; cek "
                        "kebijakan MFA/session + health-check tenant."
                        % (issuer or "?"),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "SURFACE", "safety_class": "bounded-requests",
                   "issuer": issuer}))
    if admin_open:
        rows.append(make_finding(
            tool="okta-posture",
            title="/admin merespons 200 tanpa redirect login di %s" % base,
            severity="medium",
            description="Path /admin merespons 200 tanpa indikasi halaman "
                        "login (lead paparan konsol admin; bisa aplikasi "
                        "lain di path itu — verifikasi konten manual).",
            recommendation="Pastikan /admin hanya terakses via auth+"
                           "allowlist; cek konten respons.",
            target_url=base + "/admin", evidence_kind="request-response",
            finding_class="posture", confidence=0.6, status="confirmed",
            verdict=1,
            extra={"category": "LEAD", "safety_class": "bounded-requests"}))
    if not rows:
        net_fail = all(r.get("status") is None for r in results)
        rows.append(make_finding(
            tool="okta-posture",
            title=("Gagal jaringan pada %s — tanpa klaim AMAN" if net_fail
                   else "Tidak ada marker Okta di %s") % base,
            severity="info",
            description=("Semua GET gagal jaringan (fail-closed)."
                         if net_fail else
                         "Discovery/marker Okta tidak teramati "
                         "(AMAN/inventaris — signature ketat)."),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "network_error": net_fail,
                   "error": (results[0].get("error") if results else "") or ""}))

    meta = {"url": base, "requests": len(results),
            "detected": okta_detected, "issuer": issuer,
            "admin_open": admin_open}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="okta_posture.json")
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
    print("okta-posture: detected=%s issuer=%s admin_open=%s -> %s"
          % (meta["detected"], meta["issuer"], meta["admin_open"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
