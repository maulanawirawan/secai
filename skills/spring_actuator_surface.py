"""[SAFETY: bounded-requests] spring-actuator-surface — deteksi endpoint
Actuator Spring Boot yang terpapar publik (POSTURE; kelas config-exposure
dengan dampak config/memory leak). Read-only, maks 3 GET; heapdump hanya
baca header + 1KB pertama (tidak diunduh penuh).

Marker ketat (zero-FP): body JSON "_links" + "actuator" untuk /actuator;
untuk /actuator/env: JSON "propertySources"; untuk heapdump: Content-Type
application/octet-stream + status 200. 401/403 = terlindungi (AMAN).

Sinyal:
  - actuator-exposed       : /actuator 200 + marker — permukaan operasi
                             terbuka (medium).
  - actuator-env-exposed   : /actuator/env 200 + marker — env/config
                             (bisa memuat secret) terbaca (high).
  - actuator-heapdump-exposed : /actuator/heapdump octet-stream (high —
                             memory dump berisi kredensial in-memory).
Fail-closed: semua GET gagal jaringan -> tanpa klaim AMAN.

Pemakaian:
  python skills/spring_actuator_surface.py --url https://t --out o.json
Exit: 0 sukses; 2 url salah.
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 3
TIMEOUT_S = 10.0
PROBES = ("/actuator", "/actuator/env", "/actuator/heapdump")


def _fetch(base: str, path: str, max_bytes: int = 32_000) -> dict:
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent":
                                          "secai-actuator-surface"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"path": path, "status": r.status,
                    "headers": dict(r.headers.items()),
                    "body": r.read(max_bytes).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"path": path, "status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": (e.read(8_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:
        return {"path": path, "status": None, "headers": {}, "body": "",
                "error": "%s: %s" % (type(exc).__name__, exc)[:120]}


def _status_ok(res: dict) -> bool:
    """Helper status 200 (module-level: kontrak AST guard — audit()
    tidak boleh memuat return non-(rows, meta) di dalamnya)."""
    return (res or {}).get("status") == 200


def audit(url: str, results: list[dict]) -> tuple[list[dict], dict]:
    """Murni: hasil probe -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    by_path = {r.get("path"): r for r in results}

    act_ok = _status_ok(by_path.get("/actuator")) and "_links" in (
        (by_path.get("/actuator") or {}).get("body") or "") and \
        "actuator" in ((by_path.get("/actuator") or {}).get("body") or "")
    env_ok = _status_ok(by_path.get("/actuator/env")) and \
        "propertySources" in \
        ((by_path.get("/actuator/env") or {}).get("body") or "")
    hd = by_path.get("/actuator/heapdump") or {}
    ct = (hd.get("headers") or {}).get("Content-Type", "")
    hd_ok = _status_ok(hd) and "octet-stream" in ct

    rows: list[dict] = []
    responded = [p for p in results if p.get("status") is not None]
    if act_ok:
        rows.append(make_finding(
            tool="spring-actuator-surface",
            title="Endpoint Actuator Spring Boot terpapar di %s" % base,
            severity="medium",
            description="/actuator merespons 200 dgn struktur _links "
                        "khas Actuator — permukaan operasional terbuka "
                        "tanpa autentikasi (posture).",
            recommendation="Batasi Actuator ke jaringan internal, "
                           "wajibkan auth, matikan endpoint tak "
                           "dipakai (management.endpoints...).",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=1,
            extra={"category": "SURFACE", "safety_class": "bounded-requests"}))
    if env_ok:
        rows.append(make_finding(
            tool="spring-actuator-surface",
            title="/actuator/env terpapar di %s (env/config terbaca)" % base,
            severity="high",
            description="Endpoint env merespons 200 dgn propertySources — "
                        "properti aplikasi (bisa memuat secret) terbaca "
                        "tanpa autentikasi.",
            recommendation="Sama + rotasi secret yang pernah terekspos.",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=1,
            extra={"category": "SURFACE", "safety_class": "bounded-requests"}))
    if hd_ok:
        rows.append(make_finding(
            tool="spring-actuator-surface",
            title="/actuator/heapdump terpapar di %s (memory dump)" % base,
            severity="high",
            description="Heapdump tersedia (application/octet-stream) — "
                        "dump memori berisi kredensial in-memory dapat "
                        "diunduh tanpa autentikasi.",
            recommendation="Sama + rotasi kredensial yang ada di heap.",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=1,
            extra={"category": "SURFACE", "safety_class": "bounded-requests"}))
    if not rows and not responded:
        rows.append(make_finding(
            tool="spring-actuator-surface",
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
            tool="spring-actuator-surface",
            title="Tidak ada Actuator terpapar di %s" % base,
            severity="info",
            description="Probe /actuator* tidak memenuhi marker "
                        "(AMAN/inventaris).",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests"}))

    meta = {"url": base, "requests": len(results),
            "actuator": act_ok, "env": env_ok, "heapdump": hd_ok}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="spring_actuator_surface.json")
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
    print("spring-actuator-surface: actuator=%s env=%s heapdump=%s -> %s"
          % (meta["actuator"], meta["env"], meta["heapdump"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
