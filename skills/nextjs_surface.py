"""[SAFETY: bounded-requests] nextjs-surface — inventori permukaan
Next.js (framework React server-rendered): marker framework, buildId
dalam __NEXT_DATA__, dan indikasi dev-server di produksi. Read-only,
maks 2 GET (/, /_next/ dihindari).

Marker ketat (zero-FP): header X-Powered-By berisi "Next.js" ATAU body
memuat script /_next/static/ + __NEXT_DATA__ JSON.

Sinyal:
  - nextjs-detected      : framework marker (info/inventori).
  - nextjs-buildid-exposed : buildId di __NEXT_DATA__ (info — dipakai
    enumerasi /_next/data/<buildId>/... route).
  - nextjs-dev-indicator : body/header memuat indikasi development
    (buildId "development" / webpack-hmr) di produksi (medium — dev
    server harusnya tidak pernah di produksi).
Fail-closed utk kegagalan jaringan.
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

MAX_GETS = 1
TIMEOUT_S = 10.0
PROBES = ("/",)
_RE_POWERED = re.compile(r"next\.js", re.I)
_RE_NEXTDATA = re.compile(r"__NEXT_DATA__[^>]*>\s*(\{.*?\})\s*</script>", re.S)
_RE_BUILDID = re.compile(r'"buildId"\s*:\s*"([^"]+)"')
_RE_STATIC = re.compile(r"/_next/static/")
_RE_DEV = re.compile(r'"buildId"\s*:\s*"development"|_next/webpack-hmr'
                     r"|development-mode", re.I)


def _fetch(base: str, path: str) -> dict:
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent": "secai-nextjs-surface"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"path": path, "status": r.status,
                    "headers": dict(r.headers.items()),
                    "body": r.read(64_000).decode("utf-8", "replace")}
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
    home = results[0] if results else {}
    blob = (home.get("body") or "") + " " + _hdrblob(home.get("headers") or {})
    detected = bool(_RE_POWERED.search(blob)) or (
        _RE_STATIC.search(home.get("body") or "") and
        "__NEXT_DATA__" in (home.get("body") or ""))

    buildid = None
    m = _RE_NEXTDATA.search(home.get("body") or "")
    if m:
        try:
            buildid = (_RE_BUILDID.search(m.group(1)) or [None, None])[1]
        except Exception:
            buildid = None

    dev = bool(_RE_DEV.search(blob))

    rows: list[dict] = []
    if detected and dev:
        rows.append(make_finding(
            tool="nextjs-surface",
            title="Next.js dev-server indikasi di produksi %s" % base,
            severity="medium",
            description="Indikasi mode development (buildId 'development'/"
                        "webpack-hmr) — dev server di produksi "
                        "mengekspos source-map/route internals.",
            recommendation="Deploy build produksi; matikan dev server.",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=0.9, status="confirmed",
            verdict=1,
            extra={"category": "SURFACE", "safety_class": "bounded-requests"}))
    if detected:
        rows.append(make_finding(
            tool="nextjs-surface",
            title="Next.js terdeteksi di %s%s" % (
                base,
                " (buildId: %s)" % buildid if buildid else ""),
            severity="info",
            description="Marker framework Next.js teramati (posture/"
                        "inventori; buildId berguna utk enumerasi "
                        "route _next/data).",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "SURFACE", "safety_class": "bounded-requests",
                   "buildid": buildid}))
    if not detected:
        net_fail = home.get("status") is None
        rows.append(make_finding(
            tool="nextjs-surface",
            title=("Gagal jaringan pada %s — tanpa klaim AMAN" if net_fail
                   else "Tidak ada marker Next.js di %s") % base,
            severity="info",
            description=("Semua GET gagal jaringan (fail-closed)."
                         if net_fail else
                         "Marker Next.js tidak teramati (AMAN/inventaris)."),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "network_error": net_fail,
                   "error": home.get("error") or ""}))

    meta = {"url": base, "requests": len(results), "detected": detected,
            "buildid": buildid, "dev": dev}
    return rows, meta


def _hdrblob(headers: dict) -> str:
    return " ".join("%s: %s" % (k, v) for k, v in (headers or {}).items())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="nextjs_surface.json")
    args = ap.parse_args()
    base = args.url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base
    results = [_fetch(base, p) for p in PROBES[:MAX_GETS]]
    rows, meta = audit(args.url, results)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print("nextjs-surface: detected=%s buildid=%s dev=%s -> %s"
          % (meta["detected"], meta["buildid"], meta["dev"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
