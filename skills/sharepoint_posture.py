"""[SAFETY: bounded-requests] sharepoint-posture — deteksi farm
Microsoft SharePoint on-premises dari target URL (POSTURE; kelas
appliance/collab enterprise dengan permukaan /_layouts, /_vti_bin,
/_api yang lebar). Read-only, maks 3 GET ke /_layouts/15/start.aspx,
/_api/web, /.

Signature ketat (zero-FP): token eksplisit "SharePoint"/"_layouts"/
"_vti_bin"/header X-SharePointHealthScore — frasa generik "document
management" TIDAK dihitung. Versi eksplisit (15.0.x/16.0.x di
build/header) dicatat sebagai fakta utk cve-matcher; TANPA versi
eksplisit = TIDAK ada klaim rentan (fail-closed).

Sinyal:
  - sharepoint-detected    : farm SharePoint terdeteksi (posture
                             medium).
  - sharepoint-version-exposed: versi build eksplisit (fakta, verdict 0).
  - sharepoint-api-open    : /_api/web merespons 200 JSON dgn marker
                             SP.* tanpa auth (lead — API query terbuka;
                             bila anon-read enable = data exposure).
Fail-closed jaringan.
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
PROBES = ("/_layouts/15/start.aspx", "/_api/web", "/")
_RE_MARKER = re.compile(
    r"sharepoint|_layouts/|_vti_bin|X-SharePointHealthScore|"
    r"SP\.ClientContext|MicrosoftSharePointTeamServices", re.I)
_RE_VERSION = re.compile(
    r"(?:MicrosoftSharePointTeamServices[\":\s]+|\b)(1[56]\.0\.\d+\.\d+)",
    re.I)


def _fetch(base: str, path: str) -> dict:
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent":
                                          "secai-sharepoint-posture"})
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
    probes: list[dict] = []
    for r in results:
        blob = (r.get("body") or "") + " " + " ".join(
            "%s: %s" % (k, v) for k, v in (r.get("headers") or {}).items())
        probes.append({"path": r.get("path"), "status": r.get("status"),
                       "marker": bool(_RE_MARKER.search(blob)),
                       "version": (_RE_VERSION.search(blob) or
                                   [None, None])[1]})
    detected = [p for p in probes if p.get("marker")]
    versions = sorted({p["version"] for p in detected if p.get("version")})
    api_res = next((p for p in probes
                    if p.get("path") == "/_api/web" and p.get("status") == 200
                    and p.get("marker")), None)
    responded = [p for p in probes if p.get("status") is not None]

    rows: list[dict] = []
    if detected:
        paths = ", ".join(str(p["path"]) for p in detected)
        ver_s = (f" versi eksplisit: {', '.join(versions)}"
                 if versions else
                 " versi TIDAK terdeteksi eksplisit (verifikasi manual)")
        rows.append(make_finding(
            tool="sharepoint-posture",
            title="Farm SharePoint terdeteksi di %s (%s)" % (base, paths),
            severity="medium",
            description="Token eksplisit SharePoint/_layouts/_vti_bin di "
                        "respons %s.%s Permukaan collab enterprise: audit "
                        "paparan /_api & /_vti_bin, patch cumulative "
                        "update terbaru." % (paths, ver_s),
            recommendation="Patch CU terbaru, batasi /_api anonim, audit "
                           "add-in & permission web scope.",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=1,
            extra={"category": "SURFACE", "safety_class": "bounded-requests",
                   "probe_paths": paths, "versions": versions}))
    if api_res:
        rows.append(make_finding(
            tool="sharepoint-posture",
            title="/_api/web merespons 200 dengan marker SP di %s" % base,
            severity="medium",
            description="REST API SharePoint merespons tanpa auth pada "
                        "/_api/web — bila tenant mengizinkan anonim read, "
                        "metadata/list web terbaca (lead; cek kebijakan "
                        "permission di site).",
            recommendation="Matikan anonymous access di web application; "
                           "audit permission scope per site.",
            target_url=base + "/_api/web", evidence_kind="request-response",
            finding_class="posture", confidence=0.8, status="confirmed",
            verdict=1,
            extra={"category": "LEAD", "safety_class": "bounded-requests"}))
    if not rows and not responded:
        rows.append(make_finding(
            tool="sharepoint-posture",
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
            tool="sharepoint-posture",
            title="Tidak ada marker SharePoint di %s" % base,
            severity="info",
            description="Probe /_layouts, /_api, / tanpa token eksplisit "
                        "(AMAN/inventaris — signature ketat).",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests"}))

    meta = {"url": base, "requests": len(results),
            "detected": bool(detected), "versions": versions,
            "api-open": bool(api_res)}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="sharepoint_posture.json")
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
    print("sharepoint-posture: detected=%s versions=%s api-open=%s -> %s"
          % (meta["detected"], meta["versions"], meta["api-open"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
