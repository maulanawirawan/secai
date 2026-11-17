"""[SAFETY: active-probe, lab-only] xxe-probe-check — in-band probe XML
entity processing pada endpoint yang menerima XML (XXE surface).
DUA POST stateless: payload benign vs payload dgn entity yang
mereferensikan path TIDAK ADA (file:///nonexistent-secai-canary-...) —
beda respons = parser memproses entitas (LEAD). TIDAK membaca file
target (path canary nonexistent), TIDAK ada OOB callback, TIDAK
state-changing. Maks 2 POST per run.

Sinyal:
  - xxe-entities-processed : respons probe memuat canary path di pesan
    error ATAU error-signature XML berbeda dari benign — DOCTYPE/entitas
    diproses (lead; bukti ekstraksi data butuh jalur exploit-tier/lab).
  - xxe-error-signature    : token parser XML umum (SAXParse, xml
    parse error, simplexml) hanya muncul di probe.
Fail-closed: kedua POST gagal jaringan -> tanpa klaim AMAN; respons
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

MAX_POSTS = 2
TIMEOUT_S = 10.0
CANARY_PATH = "file:///nonexistent-secai-canary-0192837"
BENIGN = ('<?xml version="1.0"?><secai><data>benign-0192837</data>'
          "</secai>")
PROBE = ('<?xml version="1.0"?><!DOCTYPE secai [<!ENTITY xxe SYSTEM "'
         + CANARY_PATH + '"]><secai><data>&xxe;</data></secai>')
_RE_PARSER_ERR = re.compile(
    r"saxparse|xml parse|simplexml|lxml|xerces|entity|doctype|"
    r"undefined (?:entity|prefix)", re.I)


def _post(url: str, body: str) -> dict:
    req = urllib.request.Request(
        url, data=body.encode("utf-8"), method="POST",
        headers={"User-Agent": "secai-xxe-probe",
                 "Content-Type": "application/xml"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"status": r.status,
                    "body": r.read(24_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code,
                "body": (e.read(12_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:
        return {"status": None, "body": "",
                "error": "%s: %s" % (type(exc).__name__, exc)[:120]}


def audit(url: str, benign: dict, probe: dict) -> tuple[list[dict], dict]:
    """Murni: dua hasil POST -> (rows, meta) kontrak."""
    base = url
    canary_echoed = CANARY_PATH.split("/")[-1] in (probe.get("body") or "")
    b_err = bool(_RE_PARSER_ERR.search(benign.get("body") or ""))
    p_err = bool(_RE_PARSER_ERR.search(probe.get("body") or ""))
    status_diff = (benign.get("status") is not None and
                   probe.get("status") is not None and
                   benign.get("status") != probe.get("status"))
    processed = (canary_echoed or (p_err and not b_err) or
                 (status_diff and p_err))

    rows: list[dict] = []
    if processed:
        rows.append(make_finding(
            tool="xxe-probe-check",
            title="Entitas XML diproses pada %s (XXE surface)" % base,
            severity="medium",
            description="POST dgn DOCTYPE+entity ke path nonexistent "
                        "menghasilkan respons BERBEDA dari payload benign "
                        "(canary echoed=%s, parser-error=%s, status %s -> "
                        "%s) — parser memproses entitas eksternal. LEAD: "
                        "ekstraksi file/OOB butuh jalur exploit-tier "
                        "berizin." % (canary_echoed, p_err and not b_err,
                                      benign.get("status"),
                                      probe.get("status")),
            recommendation="Nonaktifkan external entity (libxml "
                           "XML_PARSE_NOENT off / setFeature "
                           "disallow-doctype-decl), parse JSON bila bisa.",
            target_url=base,
            request=PROBE[:200], response=(probe.get("body") or "")[:240],
            evidence_kind="request-response", finding_class="posture",
            confidence=0.8, status="confirmed", verdict=1,
            extra={"category": "LEAD", "safety_class": "active-probe",
                   "lab_only": True}))
    else:
        net_fail = benign.get("status") is None and \
            probe.get("status") is None
        rows.append(make_finding(
            tool="xxe-probe-check",
            title=("Gagal jaringan pada %s — tanpa klaim AMAN" if net_fail
                   else "Tidak ada indikasi entity processing di %s")
                  % base,
            severity="info",
            description=("Kedua POST gagal jaringan (fail-closed)."
                         if net_fail else
                         "Respons benign dan probe identik/tidak memuat "
                         "parser error — entitas tidak terlihat diproses "
                         "(AMAN/inventaris; endpoint lain tak diuji)."),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "active-probe",
                   "lab_only": True, "network_error": net_fail,
                   "error": probe.get("error") or ""}))

    meta = {"url": base, "requests": MAX_POSTS,
            "processed": processed,
            "status_diff": status_diff, "canary_echoed": canary_echoed}
    return rows, meta


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True, help="endpoint XML (POST)")
    ap.add_argument("--out", default="xxe_probe_check.json")
    ap.add_argument("--lab", action="store_true")
    args = ap.parse_args(argv)
    if not args.lab and os.environ.get("LAB") != "1":
        print("DITOLAK: butuh --lab / LAB=1 (active-probe, fail-closed)",
              file=sys.stderr)
        return 3
    benign = _post(args.url, BENIGN)
    probe = _post(args.url, PROBE)
    rows, meta = audit(args.url, benign, probe)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "active-probe",
                    "lab_only": True})
    print("xxe-probe-check: processed=%s -> %s"
          % (meta["processed"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
