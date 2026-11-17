"""[SAFETY: bounded-requests] aspx-trace-surface — deteksi artefak debug
ASP.NET yang terpapar publik (trace.axd, ELMAH error log, header versi
ASP.NET — kelas info-leak klasik). Read-only, maks 3 GET.

Marker ketat (zero-FP):
  - /trace.axd : 200 + token "Application Trace" (halaman trace asli).
  - /elmah.axd : 200 + token "ELMAH" (error log asli).
  - header X-AspNet-Version / X-AspNetMvc-Version (inventori).
Sinyal: aspx-trace-exposed (high — trace membocorkan request/session/
querystring), elmah-exposed (high — error log berisi stacktrace +
cookie), aspnet-version-header (info). Fail-closed jaringan.
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
PROBES = ("/trace.axd", "/elmah.axd", "/")
_RE_TRACE = re.compile(r"Application Trace|__ASPXTRACE", re.I)
_RE_ELMAH = re.compile(r"\bELMAH\b")
_RE_VERSION = re.compile(r"X-AspNet(?:Mvc)?-Version\s*:\s*([0-9.]+)", re.I)


def _fetch(base: str, path: str) -> dict:
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent": "secai-aspx-surface"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"path": path, "status": r.status,
                    "headers": dict(r.headers.items()),
                    "body": r.read(24_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"path": path, "status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": (e.read(6_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:
        return {"path": path, "status": None, "headers": {}, "body": "",
                "error": "%s: %s" % (type(exc).__name__, exc)[:120]}


def audit(url: str, results: list[dict]) -> tuple[list[dict], dict]:
    """Murni: hasil probe -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    by = {r.get("path"): r for r in results}
    trace = by.get("/trace.axd") or {}
    elmah = by.get("/elmah.axd") or {}
    home = by.get("/") or {}

    trace_ok = trace.get("status") == 200 and bool(
        _RE_TRACE.search(trace.get("body") or ""))
    elmah_ok = elmah.get("status") == 200 and bool(
        _RE_ELMAH.search(elmah.get("body") or ""))
    versions = sorted({m.group(1) for m in
                       _RE_VERSION.finditer(_blob(home.get("headers") or {}))})

    rows: list[dict] = []
    if trace_ok:
        rows.append(make_finding(
            tool="aspx-trace-surface",
            title="trace.axd terpapar di %s" % base,
            severity="high",
            description="Halaman Application Trace merespons 200 — "
                        "request terakhir (querystring, session, header) "
                        "terbaca publik.",
            recommendation="Matikan <trace> di web.config produksi; "
                           "blokir path trace.axd.",
            target_url=base + "/trace.axd", evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=1,
            extra={"category": "SURFACE", "safety_class": "bounded-requests"}))
    if elmah_ok:
        rows.append(make_finding(
            tool="aspx-trace-surface",
            title="ELMAH error log terpapar di %s" % base,
            severity="high",
            description="Halaman ELMAH merespons 200 — log error (stacktrace "
                        "+ cookie/session) terbaca publik.",
            recommendation="Require auth untuk elmah.axd; rotasi sesi "
                           "yang terekspos.",
            target_url=base + "/elmah.axd", evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=1,
            extra={"category": "SURFACE", "safety_class": "bounded-requests"}))
    if versions:
        rows.append(make_finding(
            tool="aspx-trace-surface",
            title="Versi ASP.NET terungkap via header di %s" % base,
            severity="info",
            description="X-AspNet-Version/X-AspNetMvc-Version: %s — "
                        "inventori (bantu pemetaan versi)."
                        % ", ".join(versions),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "SURFACE", "safety_class": "bounded-requests",
                   "versions": versions}))

    responded = [p for p in results if p.get("status") is not None]
    if not rows and not responded:
        rows.append(make_finding(
            tool="aspx-trace-surface",
            title="Gagal jaringan pada %s — tanpa klaim AMAN" % base,
            severity="info",
            description="Semua GET gagal jaringan (fail-closed).",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "network_error": True,
                   "error": (results[0].get("error") if results else "") or ""}))
    elif not rows:
        rows.append(make_finding(
            tool="aspx-trace-surface",
            title="Tidak ada artefak debug ASP.NET terpapar di %s" % base,
            severity="info",
            description="Probe trace.axd/elmah.axd tidak memenuhi marker "
                        "(AMAN/inventaris).",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests"}))

    meta = {"url": base, "requests": len(results), "trace": trace_ok,
            "elmah": elmah_ok, "versions": versions}
    return rows, meta


def _blob(headers: dict) -> str:
    return " ".join("%s: %s" % (k, v) for k, v in (headers or {}).items())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="aspx_trace_surface.json")
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
    print("aspx-trace-surface: trace=%s elmah=%s versions=%s -> %s"
          % (meta["trace"], meta["elmah"], meta["versions"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
