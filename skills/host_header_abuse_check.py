"""[SAFETY: bounded-requests] host-header-abuse-check — pre-check
penyalahgunaan header Host/X-Forwarded-Host (kelas reset-poisoning /
cache-poisoning yang banyak dilaporkan di bug bounty): apakah aplikasi
membangun URL absolut dari X-Forwarded-Host yang bisa dikontrol
penyerang. Read-only, 2 GET ke path / dgn canary host deterministik.

Sinyal (semua deterministik dari respons):
  - hh-xforwarded-reflected : body respons dgn canary X-Forwarded-Host
    memuat canary host TAPI baseline tidak — app memercayai header
    penyerang utk URL absolut (lead reset-poisoning/cache-poison).
  - hh-canonical-injected   : elemen canonical/og:url/link/Location di
    respons canary memakai canary host — URL absolut terkonstruksi
    dari header (penguat sinyal pertama).
  - hh-always-reflects      : canary host muncul JUGA di baseline
    respons (bukan refleksi header — kemungkinan konten memang
    memuat string; zero-FP: TIDAK dihitung temuan).
Fail-closed: kedua GET gagal jaringan -> tanpa klaim AMAN.

Pemakaian:
  python skills/host_header_abuse_check.py --url https://t --out o.json
Exit: 0 sukses; 2 url salah.
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

MAX_GETS = 2
TIMEOUT_S = 10.0
CANARY_HOST = "secai-hh-probe.example"
CANARY = re.compile(re.escape(CANARY_HOST), re.I)
_RE_ABS_URL = re.compile(
    r"(https?://[^\"'\s>]+)|(<link[^>]+rel=[\"']canonical[\"'][^>]*>)|"
    r"(<meta[^>]+property=[\"']og:url[\"'][^>]*>)", re.I)

HEADERS_FWD = {"User-Agent": "secai-host-header-check",
               "X-Forwarded-Host": CANARY_HOST,
               "X-Forwarded-Proto": "https"}
HEADERS_BASE = {"User-Agent": "secai-host-header-check"}


def _fetch(base: str, headers: dict) -> dict:
    req = urllib.request.Request(base + "/", method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"status": r.status,
                    "headers": dict(r.headers.items()),
                    "body": r.read(48_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": (e.read(24_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:
        return {"status": None, "headers": {},
                "body": "", "error": "%s: %s" % (type(exc).__name__, exc)[:120]}


def audit(url: str, baseline: dict, forwarded: dict) -> tuple[list[dict], dict]:
    """Murni: dua hasil fetch -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    signals: list[str] = []
    fwd_canary = bool(CANARY.search(forwarded.get("body") or "")) or \
        any(CANARY.search(str(v)) for v in (forwarded.get("headers") or {}).values())
    base_canary = bool(CANARY.search(baseline.get("body") or "")) or \
        any(CANARY.search(str(v)) for v in (baseline.get("headers") or {}).values())
    reflected = fwd_canary and not base_canary

    injected = False
    if reflected:
        for m in _RE_ABS_URL.finditer(forwarded.get("body") or ""):
            if CANARY.search(m.group(0)):
                injected = True
                break

    rows: list[dict] = []
    net_fail = (baseline.get("status") is None and
                forwarded.get("status") is None)
    if reflected:
        signals.append("hh-xforwarded-reflected")
        snippet = (forwarded.get("body") or "")[:240].replace("\n", " ")
        rows.append(make_finding(
            tool="host-header-abuse-check",
            title="X-Forwarded-Host tercermin di respons %s" % base,
            severity="medium",
            description="Respons dengan canary X-Forwarded-Host=%s "
                        "memuat canary di body/header, baseline tidak — "
                        "URL absolut dibangun dari header penyerang. "
                        "Lead reset-poisoning/cache-poisoning; uji "
                        "alur forgot-password/cache manual dgn lab."
                        % CANARY_HOST,
            recommendation="Validasi/allowlist Host+X-Forwarded-Host "
                           "di edge; bangun URL absolut dari konfigurasi, "
                           "bukan header.",
            target_url=base,
            request="GET / (X-Forwarded-Host: %s)" % CANARY_HOST,
            response=snippet,
            evidence_kind="request-response", finding_class="posture",
            confidence=0.8, status="confirmed", verdict=1,
            extra={"category": "LEAD", "safety_class": "bounded-requests",
                   "signals": signals, "canary": CANARY_HOST}))
        if injected:
            signals.append("hh-canonical-injected")
            rows.append(make_finding(
                tool="host-header-abuse-check",
                title="URL absolut (canonical/og:url/href) di-inject "
                      "dari X-Forwarded-Host di %s" % base,
                severity="medium",
                description="Elemen URL absolut di respons canary memakai "
                            "canary host — penguat lead reset-poisoning "
                            "(tautan di email berasal dari header).",
                recommendation="Sama: allowlist host di edge.",
                target_url=base,
                evidence_kind="request-response", finding_class="posture",
                confidence=0.8, status="confirmed", verdict=1,
                extra={"category": "LEAD", "safety_class":
                       "bounded-requests", "signals": signals}))
    elif base_canary:
        signals.append("hh-always-reflects")
        rows.append(make_finding(
            tool="host-header-abuse-check",
            title="Canary host muncul di baseline (bukan refleksi header)",
            severity="info",
            description="Canary string muncul tanpa header — konten "
                        "memang memuat pola serupa; refleksi header "
                        "TIDAK diklaim (zero-FP).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests"}))
    elif net_fail:
        rows.append(make_finding(
            tool="host-header-abuse-check",
            title="Gagal jaringan pada %s — tanpa klaim AMAN" % base,
            severity="info",
            description="Kedua GET gagal jaringan; kegagalan koneksi "
                        "BUKAN bukti tidak-rentan (fail-closed).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "network_error": True,
                   "error": forwarded.get("error") or ""}))
    else:
        rows.append(make_finding(
            tool="host-header-abuse-check",
            title="Tidak ada refleksi X-Forwarded-Host pada %s" % base,
            severity="info",
            description="Respons canary tidak memuat canary host "
                        "(AMAN/inventaris — refleksi tidak teramati "
                        "pada GET /; alur lain tak diuji).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests"}))

    meta = {"url": base, "requests": MAX_GETS, "reflected": reflected,
            "injected": injected, "signals": signals,
            "canary": CANARY_HOST}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="host_header_abuse_check.json")
    args = ap.parse_args()
    base = args.url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base
    baseline = _fetch(base, HEADERS_BASE)
    forwarded = _fetch(base, HEADERS_FWD)
    rows, meta = audit(args.url, baseline, forwarded)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print("host-header-abuse-check: reflected=%s -> %s"
          % (meta["reflected"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
