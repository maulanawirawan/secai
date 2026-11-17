"""[SAFETY: bounded-requests] vcenter-posture — deteksi appliance
VMware vCenter/vSphere dari target URL (POSTURE; latar: vCenter berulang
jadi target eksploitasi appliance-enterprise — jalur web UI/SDK yang
terpapar adalah permukaan nomor satu). Read-only, maks 3 GET ke /ui,
/sdk, /.

Signature ketat (zero-FP): token eksplisit "vmware"/"vcenter"/"vsphere"
di body/header. Versi eksplisit (token bersebelahan angka x.y.z)
dicatat sebagai fakta utk cve-matcher; TANPA versi eksplisit = TIDAK
ada klaim rentan (fail-closed, tidak ada fabrikasi rentang).
401/403 di /sdk = layanan ada namun terlindungi (posture, bukan lead).
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
PROBES = ("/ui", "/sdk", "/")
_RE_MARKER = re.compile(r"vmware|vcenter|vsphere", re.I)
_RE_VERSION = re.compile(r"(?:vcenter|vsphere|vmware)[ /v]*(\d+\.\d+"
                         r"(?:\.\d+)?)", re.I)


def _fetch(base: str, path: str) -> dict:
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent": "secai-vcenter-posture"})
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
    responded = [p for p in probes if p.get("status") is not None]

    rows: list[dict] = []
    if detected:
        paths = ", ".join(str(p["path"]) for p in detected)
        ver_s = (f" versi eksplisit: {', '.join(versions)}"
                 if versions else
                 " versi TIDAK terdeteksi eksplisit (verifikasi manual)")
        rows.append(make_finding(
            tool="vcenter-posture",
            title="Appliance VMware vCenter/vSphere terdeteksi di %s (%s)"
                  % (base, paths),
            severity="medium",
            description="Token eksplisit vmware/vcenter/vsphere di "
                        "respons %s.%s L1 lead — cek paparan /ui & /sdk "
                        "dari internet + versi vs advisory." % (paths, ver_s),
            recommendation="Isolasi vCenter dari internet, patch sesuai "
                           "advisory terbaru, audit SSO/admin akun.",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=1,
            extra={"category": "SURFACE", "safety_class": "bounded-requests",
                   "probe_paths": paths, "versions": versions}))
    elif not responded:
        rows.append(make_finding(
            tool="vcenter-posture",
            title="Gagal jaringan pada %s — tanpa klaim AMAN" % base,
            severity="info",
            description="Semua GET gagal jaringan (fail-closed).",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "network_error": True,
                   "error": (results[0].get("error") if results else "") or ""}))
    else:
        rows.append(make_finding(
            tool="vcenter-posture",
            title="Tidak ada marker VMware/vCenter di %s" % base,
            severity="info",
            description="Probe /ui, /sdk, / tanpa token eksplisit "
                        "(AMAN/inventaris — signature ketat).",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests"}))

    meta = {"url": base, "requests": len(results),
            "detected": bool(detected), "versions": versions}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="vcenter_posture.json")
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
    print("vcenter-posture: detected=%s versions=%s -> %s"
          % (meta["detected"], meta["versions"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
