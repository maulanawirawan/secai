"""[SAFETY: bounded-requests] java-console-surface — deteksi konsol
manajemen Java app-server yang terpapar publik (Tomcat manager,
JBoss jmx/web-console, WebLogic console — kelas deployment-console
dampak deploy-remote bila tidak terlindungi). Read-only, maks 4 GET,
signature token ketat per produk (zero-FP).

Marker ketat:
  - /manager/html      : "Tomcat Web Application Manager" / "Tomcat
                         Web Application Manager" style marker token
                         "Tomcat" + "Manager".
  - /jmx-console/      : "JBoss" + "JMX Console".
  - /web-console/      : "JBoss Web Console" / "JBoss".
  - /console/login/LoginForm.jsp : "WebLogic Server Console" /
                         "Oracle WebLogic".
401/403 = terlindungi (tidak diklaim paparan). Fail-closed jaringan.
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
PROBES = ("/manager/html", "/jmx-console/", "/web-console/",
          "/console/login/LoginForm.jsp")
_CONSOLES = (
    ("/manager/html", re.compile(r"Tomcat Web Application Manager|"
                                 r"Tomcat.{0,40}Manager", re.I | re.S),
     "tomcat-manager", "Tomcat Manager"),
    ("/jmx-console/", re.compile(r"JBoss.{0,40}JMX Console|JMX Console",
                                 re.I | re.S),
     "jboss-jmx-console", "JBoss JMX Console"),
    ("/web-console/", re.compile(r"JBoss.{0,60}Web Console", re.I | re.S),
     "jboss-web-console", "JBoss Web Console"),
    ("/console/login/LoginForm.jsp",
     re.compile(r"WebLogic Server Console|Oracle WebLogic", re.I | re.S),
     "weblogic-console", "WebLogic Console"),
)


def _fetch(base: str, path: str) -> dict:
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent":
                                          "secai-java-console-surface"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"path": path, "status": r.status,
                    "headers": dict(r.headers.items()),
                    "body": r.read(16_000).decode("utf-8", "replace")}
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
    rows: list[dict] = []
    exposed: list[str] = []

    for path, rx, key, label in _CONSOLES:
        r = by.get(path) or {}
        if r.get("status") == 200 and rx.search(r.get("body") or ""):
            exposed.append(label)
            rows.append(make_finding(
                tool="java-console-surface",
                title="%s terpapar publik di %s" % (label, base),
                severity="high",
                description="%s merespons 200 dgn signature khas di %s — "
                            "konsol deployment/management terbuka (bila "
                            "login default/guessable = jalur deploy)."
                            % (label, path),
                recommendation="Blokir dari internet, require auth kuat "
                               "+ IP allowlist, hapus default akun.",
                target_url=base + path, evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=1,
                extra={"category": "SURFACE",
                       "safety_class": "bounded-requests", "console": key}))

    responded = [p for p in results if p.get("status") is not None]
    if not rows and not responded:
        rows.append(make_finding(
            tool="java-console-surface",
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
            tool="java-console-surface",
            title="Tidak ada konsol Java terpapar di %s" % base,
            severity="info",
            description="Probe konsol (Tomcat/JBoss/WebLogic) tidak "
                        "memenuhi signature (AMAN/inventaris; 401/403 "
                        "dianggap terlindungi).",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests"}))

    meta = {"url": base, "requests": len(results), "exposed": exposed}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="java_console_surface.json")
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
    print("java-console-surface: exposed=%s -> %s"
          % (meta["exposed"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
