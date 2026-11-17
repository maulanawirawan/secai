"""[SAFETY: bounded-requests] laravel-surface — deteksi paparan artefak
framework Laravel/PHP di publik (.env, Ignition debug, Telescope,
Horizon — kelas config/debug exposure). Read-only, maks 4 GET.

Marker ketat (zero-FP):
  - /.env       : 200 + baris APP_NAME=/APP_KEY=/APP_ENV= (file konfig
                  asli, bukan halaman 404 SPA).
  - /_ignition/health-check : 200 + JSON "canExecuteCommands" (Ignition
                  debug bar — jalur RCE terdokumentasi bila enable).
  - /telescope  : 200 + token "Telescope" di body.
  - /horizon    : 200 + token "Horizon" di body.
Sinyal: laravel-env-exposed (critical: APP_KEY + secret DB), 
laravel-ignition-health (high), laravel-telescope-exposed (medium),
laravel-horizon-exposed (medium). Fail-closed utk kegagalan jaringan.
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

MAX_GETS = 4
TIMEOUT_S = 10.0
PROBES = ("/.env", "/_ignition/health-check", "/telescope", "/horizon")
_RE_ENV = re.compile(r"^(APP_NAME|APP_KEY|APP_ENV|DB_PASSWORD)=", re.M)
_RE_IGNITION = re.compile(r"canExecuteCommands|ignition", re.I)
_RE_TELESCOPE = re.compile(r"\bTelescope\b")
_RE_HORIZON = re.compile(r"\bHorizon\b")


def _fetch(base: str, path: str, max_bytes: int = 16_000) -> dict:
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent": "secai-laravel-surface"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"path": path, "status": r.status,
                    "headers": dict(r.headers.items()),
                    "body": r.read(max_bytes).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"path": path, "status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": (e.read(4_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:
        return {"path": path, "status": None, "headers": {}, "body": "",
                "error": "%s: %s" % (type(exc).__name__, exc)[:120]}


def audit(url: str, results: list[dict]) -> tuple[list[dict], dict]:
    """Murni: hasil probe -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    by = {r.get("path"): r for r in results}
    env = by.get("/.env") or {}
    ign = by.get("/_ignition/health-check") or {}
    tel = by.get("/telescope") or {}
    hor = by.get("/horizon") or {}

    env_ok = env.get("status") == 200 and bool(_RE_ENV.search(env.get("body") or ""))
    ign_ok = ign.get("status") == 200 and bool(_RE_IGNITION.search(ign.get("body") or ""))
    tel_ok = tel.get("status") == 200 and bool(_RE_TELESCOPE.search(tel.get("body") or ""))
    hor_ok = hor.get("status") == 200 and bool(_RE_HORIZON.search(hor.get("body") or ""))

    rows: list[dict] = []
    if env_ok:
        keys = _RE_ENV.findall(env.get("body") or "")
        rows.append(make_finding(
            tool="laravel-surface",
            title="File .env Laravel terpapar di %s" % base,
            severity="critical",
            description="/.env terbaca (marker: %s) — berisi APP_KEY dan "
                        "kredensial DB/mail; APP_KEY bocor = dekripsi "
                        "data terenkripsi aplikasi + jalur RCE terdokumen."
                        % ", ".join(k + "=" for k in keys[:4]),
            recommendation="Blokir /.env di web server; rotasi APP_KEY, "
                           "kredensial DB/mail; audit akun.",
            target_url=base + "/.env", evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=1,
            extra={"category": "SURFACE", "safety_class": "bounded-requests",
                   "keys-seen": keys[:6]}))
    if ign_ok:
        rows.append(make_finding(
            tool="laravel-surface",
            title="Ignition health-check terpapar di %s" % base,
            severity="high",
            description="/_ignition/health-check merespons dgn marker "
                        "Ignition — debug bar aktif di publik (jalur "
                        "RCE terdokumentasi pada versi rentan).",
            recommendation="Nonaktifkan Ignition/Flare di produksi, "
                           "blokir path _ignition, patch paket.",
            target_url=base + "/_ignition/health-check",
            evidence_kind="request-response", finding_class="posture",
            confidence=0.8, status="confirmed", verdict=1,
            extra={"category": "SURFACE", "safety_class": "bounded-requests"}))
    if tel_ok:
        rows.append(make_finding(
            tool="laravel-surface",
            title="Laravel Telescope terpapar di %s" % base,
            severity="medium",
            description="Dashboard Telescope merespons 200 dgn marker — "
                        "request/exception log aplikasi terbaca tanpa auth.",
            recommendation="Require auth + blokir di produksi.",
            target_url=base + "/telescope", evidence_kind="request-response",
            finding_class="posture", confidence=0.9, status="confirmed",
            verdict=1,
            extra={"category": "SURFACE", "safety_class": "bounded-requests"}))
    if hor_ok:
        rows.append(make_finding(
            tool="laravel-surface",
            title="Laravel Horizon terpapar di %s" % base,
            severity="medium",
            description="Dashboard Horizon merespons 200 dgn marker — "
                        "queue/job monitoring terbaca tanpa auth.",
            recommendation="Require auth + blokir di produksi.",
            target_url=base + "/horizon", evidence_kind="request-response",
            finding_class="posture", confidence=0.9, status="confirmed",
            verdict=1,
            extra={"category": "SURFACE", "safety_class": "bounded-requests"}))

    responded = [p for p in results if p.get("status") is not None]
    if not rows and not responded:
        rows.append(make_finding(
            tool="laravel-surface",
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
            tool="laravel-surface",
            title="Tidak ada artefak Laravel terpapar di %s" % base,
            severity="info",
            description="Probe .env/_ignition/telescope/horizon tidak "
                        "memenuhi marker (AMAN/inventaris).",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests"}))

    meta = {"url": base, "requests": len(results), "env": env_ok,
            "ignition": ign_ok, "telescope": tel_ok, "horizon": hor_ok}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="laravel_surface.json")
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
    print("laravel-surface: env=%s ignition=%s telescope=%s horizon=%s -> %s"
          % (meta["env"], meta["ignition"], meta["telescope"],
             meta["horizon"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
