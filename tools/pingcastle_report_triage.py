r"""[SAFETY: read-only] pingcastle_report_triage — wave-7 triase OFFLINE
laporan kesehatan Active Directory bergaya PingCastle (ekspor XML /
HTML berisi skor kesehatan + aturan risiko; parser schema-light dari
nol, stdlib murni, tanpa jaringan). Nilai: memprioritaskan temuan AD
tanpa perlu membuka laporan lengkap.

Input: satu file XML/HTML/JSON ekspor. Yang dibaca (schema-light —
bekerja di beberapa varian versi):
  - skor kesehatan: <HealthcheckRiskScore>NN</...> (XML/JSON) ATAU
    "Health score: NN" (HTML);
  - aturan risiko: <RiskId>...</RiskId> / "RiskId" tokens dgn points
    bila ada (<Points>NN</Points>).

Sinyal per artefak (semua deterministik dari data):
  - ad-score-critical : skor < 30 — kondisi AD kritis (empirik: skor
                        rendah = banyak indikator risiko).
  - ad-score-low      : skor < 50 — kesehatan rendah.
  - ad-rules-listed   : >= --min-rules (default 5) RiskId ter-ekstrak —
                        inventori aturan risiko (daftar RiskId selalu
                        masuk evidence walau di bawah ambang).
  - ad-points-heavy   : total points >= 200 (ambang --min-points) —
                        bobot risiko besar menurut aturan.
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info. Laporan
AD sehat (skor >= 50, aturan sedikit/points kecil) -> 0 sinyal
(zero-FP).

Fail-closed: file tanpa konteks laporan AD-health (HealthcheckRiskScore
/ Health score / RiskId) sama sekali -> exit 2; file tidak ada ->
exit 2. Temuan = LEAD (skor = titik awal review, bukan keputusan).

Pemakaian:
  python tools/pingcastle_report_triage.py --file report.xml --out r.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEMA = "secai.pingcastle-report-triage/1"

_RE_CTX = re.compile(
    r"HealthcheckRiskScore|Health\s*score|RiskId|PingCastle", re.I)
_RE_SCORE_XML = re.compile(r"<HealthcheckRiskScore>\s*(\d{1,3})\s*<",
                           re.I)
_RE_SCORE_HTML = re.compile(r"Health\s*score\s*[:=]?\s*(\d{1,3})", re.I)
_RE_SCORE_JSON = re.compile(r'"HealthcheckRiskScore"\s*:\s*(\d{1,3})', re.I)
_RE_RISK_ID = re.compile(r"<RiskId>\s*([A-Za-z0-9_\-\.]+)\s*</RiskId>", re.I)
_RE_RISK_JSON = re.compile(r'"RiskId"\s*:\s*"([A-Za-z0-9_\-\.]+)"')
_RE_POINTS = re.compile(r"<Points>\s*(\d{1,5})\s*</Points>", re.I)
_RE_POINTS_JSON = re.compile(r'"Points"\s*:\s*(\d{1,5})')


def _extract(text: str) -> "tuple[int | None, list[str], int]":
    score = None
    m = (_RE_SCORE_XML.search(text) or _RE_SCORE_JSON.search(text) or
         _RE_SCORE_HTML.search(text))
    if m:
        score = int(m.group(1))

    ids = [i for i in _RE_RISK_ID.findall(text) if i]
    if not ids:
        ids = [i for i in _RE_RISK_JSON.findall(text) if i]

    pts = [int(p) for p in _RE_POINTS.findall(text)] or \
          [int(p) for p in _RE_POINTS_JSON.findall(text)]
    return score, ids, sum(pts)


def triage_text(text: str, *, min_points: int = 200,
                min_rules: int = 5) -> dict:
    """Triase laporan AD-health -> dict hasil. Raise ValueError bila
    tanpa konteks."""
    if not _RE_CTX.search(text):
        raise ValueError("file tidak mengandung laporan kesehatan AD "
                         "(HealthcheckRiskScore/Health score/RiskId)")

    try:
        ET.fromstring(text)
        fmt = "xml"
    except ET.ParseError:
        fmt = "html/json"

    score, ids, total_points = _extract(text)

    signals: "list[str]" = []
    evidence: dict[str, str] = {}

    if score is not None:
        evidence["score"] = str(score)
        if score < 30:
            signals.append("ad-score-critical")
        elif score < 50:
            signals.append("ad-score-low")

    if ids:
        evidence["risk-ids"] = ", ".join(sorted(set(ids))[:10])[:300]
        evidence["risk-count"] = str(len(set(ids)))
        if len(set(ids)) >= min_rules:
            signals.append("ad-rules-listed")

    if total_points >= min_points:
        signals.append("ad-points-heavy")
        evidence["total-points"] = str(total_points)

    seen: set[str] = set()
    signals = [s for s in signals if not (s in seen or seen.add(s))]

    n_signals = len(signals)
    severity = ("high" if n_signals >= 3 else
                "medium" if n_signals == 2 else
                "low" if n_signals == 1 else "info")
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    counts[severity] = 1
    return {
        "schema": SCHEMA,
        "score": n_signals,
        "severity": severity,
        "signals": signals,
        "evidence": evidence,
        "format": fmt,
        "risk_ids": sorted(set(ids))[:40],
        "total_points": total_points,
        "health_score": score,
        "severity_counts": counts,
        "finding_count": 1 if n_signals > 0 else 0,
        "findings": ([{"type": "ad-health", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if n_signals > 0 else []),
        "clean_count": 0 if n_signals > 0 else 1,
        "note": "skor kesehatan AD = titik awal review (ambang 30/50 "
                "empirik) — baca aturan risiko aslinya sebelum "
                "tindakan; laporan bisa lama (cek tanggal generate)",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="ekspor XML/HTML laporan kesehatan AD")
    ap.add_argument("--min-points", type=int, default=200,
                    help="ambang ad-points-heavy (default 200)")
    ap.add_argument("--min-rules", type=int, default=5,
                    help="ambang ad-rules-listed (default 5)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        result = triage_text(text, min_points=args.min_points,
                             min_rules=args.min_rules)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
