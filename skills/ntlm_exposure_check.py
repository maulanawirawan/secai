"""[SAFETY: bounded-requests] ntlm-exposure-check — cek apakah target
mengiklankan autentikasi NTLM/Negotiate lewat HTTP POLos (WWW-Authenticate
terkirim TANPA TLS — token NTLM bisa disadap jaringan; kelas relay/
intercept). Read-only, maks 3 GET ke /, /rpc, /autodiscover/autodiscover.xml.
Beda ranah dari win_auth_triage (parser event log offline).

Sinyal (semua deterministik dari header respons):
  - ntlm-advertised-plain-http : WWW-Authenticate memuat NTLM/Negotiate
    pada koneksi http:// — kredensial challenge-response dapat
    disadap (high lead).
  - ntlm-https-inventory       : header NTLM pada https:// (inventori —
    lazy; NTLM tetap kelas lama tapi tidak terintersep di jalur).
  - negotiate-only-https       : hanya Negotiate/Kerberos pada https
    (info — tak ada NTLM teriklan).
Fail-closed jaringan; target yang tidak mengiklankan NTLM sama sekali =
AMAN/inventaris.
"""
from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 3
TIMEOUT_S = 10.0
PROBES = ("/", "/rpc", "/autodiscover/autodiscover.xml")
_RE_WWA = re.compile(r"WWW-Authenticate", re.I)
_RE_NTLM = re.compile(r"^\s*NTLM\b", re.M | re.I)
_RE_NEGO = re.compile(r"^\s*Negotiate\b", re.M | re.I)


def _fetch(base: str, path: str) -> dict:
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent":
                                          "secai-ntlm-exposure-check"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"path": path, "status": r.status,
                    "scheme": base.split("://")[0].lower(),
                    "headers": dict(r.headers.items()), "body": ""}
    except urllib.error.HTTPError as e:
        return {"path": path, "status": e.code,
                "scheme": base.split("://")[0].lower(),
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": ""}
    except Exception as exc:
        return {"path": path, "status": None, "scheme":
                base.split("://")[0].lower(), "headers": {}, "body": "",
                "error": "%s: %s" % (type(exc).__name__, exc)[:120]}


def _auth_blob(headers: dict) -> str:
    """Gabung SEMUA nilai WWW-Authenticate (bisa multi-header)."""
    out = []
    for k, v in (headers or {}).items():
        if k.lower() == "www-authenticate":
            out.append(str(v))
    return "\n".join(out)


def audit(url: str, results: list[dict]) -> tuple[list[dict], dict]:
    """Murni: hasil probe -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    scheme = base.split("://")[0].lower() if "://" in base else "https"
    rows: list[dict] = []
    ntlm_paths: "list[str]" = []
    nego_paths: "list[str]" = []
    plain_ntlm = False

    for r in results:
        blob = _auth_blob(r.get("headers") or {})
        if not blob:
            continue
        has_ntlm = bool(_RE_NTLM.search(blob))
        has_nego = bool(_RE_NEGO.search(blob))
        if has_ntlm or has_nego:
            if r.get("scheme") == "http":
                plain_ntlm = True
            if has_ntlm:
                ntlm_paths.append(str(r.get("path")))
            elif has_nego:
                nego_paths.append(str(r.get("path")))

    if plain_ntlm and ntlm_paths:
        signals = ["ntlm-advertised-plain-http"]
        rows.append(make_finding(
            tool="ntlm-exposure-check",
            title="NTLM diiklankan lewat HTTP polos di %s" % base,
            severity="high",
            description="WWW-Authenticate: NTLM pada koneksi tanpa TLS "
                        "(path %s) — challenge/response NTLM dapat "
                        "disadap dan diputar (relay) di jalur jaringan."
                        % ", ".join(ntlm_paths[:3]),
            recommendation="Wajibkan HTTPS (HSTS), nonaktifkan NTLMv1, "
                           "migrasi Kerberos/OIDC; pasang signing/ "
                           "channel binding.",
            target_url=base,
            request="GET %s (http)" % ", ".join(ntlm_paths[:3]),
            response=_auth_blob((results[0] or {}).get("headers") or {})[:160],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "LEAD", "safety_class": "bounded-requests",
                   "signals": signals, "ntlm-paths": ntlm_paths[:6],
                   "scheme": scheme}))
    elif ntlm_paths:
        rows.append(make_finding(
            tool="ntlm-exposure-check",
            title="NTLM diiklankan di %s (HTTPS — inventori)" % base,
            severity="info",
            description="WWW-Authenticate: NTLM pada %s lewat TLS "
                        "(inventori — NTLM tetap kelas protokol lama; "
                        "pertimbangkan migrasi)." % ", ".join(ntlm_paths[:3]),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "ntlm-paths": ntlm_paths[:6], "scheme": scheme}))
    elif nego_paths:
        rows.append(make_finding(
            tool="ntlm-exposure-check",
            title="Hanya Negotiate/Kerberos di %s (tanpa NTLM)" % base,
            severity="info",
            description="WWW-Authenticate: Negotiate pada %s; NTLM tidak "
                        "diiklankan (postur baik)." % ", ".join(nego_paths[:3]),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "scheme": scheme}))
    else:
        net_fail = all(r.get("status") is None for r in results)
        rows.append(make_finding(
            tool="ntlm-exposure-check",
            title=("Gagal jaringan pada %s — tanpa klaim AMAN" if net_fail
                   else "Tidak ada NTLM/Negotiate diiklankan di %s") % base,
            severity="info",
            description=("Semua GET gagal jaringan (fail-closed)."
                         if net_fail else
                         "Tidak ada header WWW-Authenticate NTLM/"
                         "Negotiate pada probe (AMAN/inventaris)."),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "network_error": net_fail,
                   "error": (results[0].get("error") if results else "") or ""}))

    meta = {"url": base, "requests": len(results),
            "ntlm-paths": ntlm_paths[:6], "negotiate-paths": nego_paths[:6],
            "plain-http": plain_ntlm, "scheme": scheme}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="ntlm_exposure_check.json")
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
    print("ntlm-exposure-check: ntlm=%s plain-http=%s -> %s"
          % (meta["ntlm-paths"], meta["plain-http"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
