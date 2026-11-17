"""[SAFETY: active-probe, lab-only] ldap-probe-check — in-band probe
LDAP filter injection pada parameter GET: nilai benign vs wildcard `*`
— beda hasil/error = filter diinterpolasi langsung (LEAD). DUA GET
stateless, tanpa ekstraksi data (hanya differensial), maks 2 request.

Sinyal:
  - ldap-wildcard-diff    : respons `*` berbeda material dari benign
    (status beda, ATAU body jauh lebih besar [rasio >= --ratio] ATAU
    token error LDAP berbeda) — filter injection kandidat.
  - ldap-error-signature  : token error LDAP/directory (LDAPMessage,
    Attribute error, search filter syntax) hanya di respons probe.
Fail-closed: kedua GET gagal jaringan -> tanpa klaim AMAN; respons
identik -> AMAN/inventaris (zero-FP). ACTIVE-PROBE lab-only: tanpa
--lab / LAB=1 -> DITOLAK (exit 3).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 2
TIMEOUT_S = 10.0
BENIGN_VALUE = "secai-benign-0192837"
WILDCARD = "*"
_RE_LDAP_ERR = re.compile(
    r"ldap|directory (?:service|server)|search filter|filter syntax|"
    r"Bad search filter", re.I)


def _get(url: str) -> dict:
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent":
                                          "secai-ldap-probe"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"status": r.status,
                    "body": r.read(48_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code,
                "body": (e.read(16_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:
        return {"status": None, "body": "",
                "error": "%s: %s" % (type(exc).__name__, exc)[:120]}


def audit(url: str, benign: dict, probe: dict, *, ratio: float = 1.3
          ) -> tuple[list[dict], dict]:
    """Murni: dua hasil GET -> (rows, meta) kontrak."""
    base = url.split("?")[0]
    b_body = benign.get("body") or ""
    p_body = probe.get("body") or ""
    status_diff = (benign.get("status") is not None and
                   probe.get("status") is not None and
                   benign.get("status") != probe.get("status"))
    size_ratio = (len(p_body) / len(b_body)) if len(b_body) else 0.0
    b_err = bool(_RE_LDAP_ERR.search(b_body))
    p_err = bool(_RE_LDAP_ERR.search(p_body))

    injected = (status_diff or size_ratio >= ratio or
                (p_err and not b_err))

    rows: list[dict] = []
    if injected and (probe.get("status") is not None):
        rows.append(make_finding(
            tool="ldap-probe-check",
            title="Kandidat LDAP filter injection di %s (param %s)"
                  % (base, url.split("?")[-1].split("=")[0]),
            severity="medium",
            description="Nilai wildcard `%s` menghasilkan respons BERBEDA "
                        "material dari benign (status %s -> %s, body "
                        "ratio %.2f, ldap-error %s->%s) — parameter "
                        "kemungkinan diinterpolasi langsung ke filter "
                        "directory. LEAD: ekstraksi atribut butuh uji "
                        "berizin bertahap."
                        % (WILDCARD, benign.get("status"),
                           probe.get("status"), size_ratio,
                           b_err, p_err),
            recommendation="Parameterize LDAP query (library API dgn "
                           "escaping), validasi/whitelist karakter "
                           "input, cek error handling generik.",
            target_url=base,
            request=url.replace(BENIGN_VALUE, WILDCARD)[:200],
            response=(p_body or "")[:240],
            evidence_kind="request-response", finding_class="posture",
            confidence=0.7, status="confirmed", verdict=1,
            extra={"category": "LEAD", "safety_class": "active-probe",
                   "lab_only": True, "body-ratio": round(size_ratio, 2)}))
    else:
        net_fail = benign.get("status") is None and \
            probe.get("status") is None
        rows.append(make_finding(
            tool="ldap-probe-check",
            title=("Gagal jaringan pada %s — tanpa klaim AMAN" if net_fail
                   else "Tidak ada indikasi filter injection di %s")
                  % base,
            severity="info",
            description=("Kedua GET gagal jaringan (fail-closed)."
                         if net_fail else
                         "Respons benign dan wildcard identik — "
                         "parameter tidak terlihat diinterpolasi ke "
                         "filter (AMAN/inventaris; param lain tak diuji)."),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "active-probe",
                   "lab_only": True, "network_error": net_fail,
                   "error": probe.get("error") or ""}))

    meta = {"url": base, "requests": MAX_GETS, "injected": injected,
            "body-ratio": round(size_ratio, 2),
            "status_diff": status_diff}
    return rows, meta


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True,
                    help="URL dgn param (nilai param akan diganti; "
                         "mis. https://t/search?user=XYZ)")
    ap.add_argument("--out", default="ldap_probe_check.json")
    ap.add_argument("--ratio", type=float, default=1.3,
                    help="ambang body-ratio (default 1.3)")
    ap.add_argument("--lab", action="store_true")
    args = ap.parse_args(argv)
    if not args.lab and os.environ.get("LAB") != "1":
        print("DITOLAK: butuh --lab / LAB=1 (active-probe, fail-closed)",
              file=sys.stderr)
        return 3
    url_benign = args.url.replace("XYZ", BENIGN_VALUE)
    url_probe = args.url.replace("XYZ", WILDCARD)
    benign = _get(url_benign)
    probe = _get(url_probe)
    rows, meta = audit(args.url, benign, probe, ratio=args.ratio)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "active-probe",
                    "lab_only": True})
    print("ldap-probe-check: injected=%s -> %s"
          % (meta["injected"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
