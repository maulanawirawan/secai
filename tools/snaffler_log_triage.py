r"""[SAFETY: read-only] snaffler_log_triage — wave-9 triase OFFLINE output
Snaffler (pemindai file/share AD yang menyusun temuan dgn tag warna
{BLACK}/{RED}/{YELLOW}/{GREEN} — semakin gelap semakin bernilai): ringkas
temuan kredensial/file sensitif per kelas. Parser toleran-format dari
nol (varian output antar versi berbeda), stdlib murni, tanpa jaringan.

Sinyal per artefak (semua deterministik dari data):
  - snaffler-black-red : baris tag {BLACK}/{RED} — kelas temuan
                         bernilai tinggi menurut taksonomi tool asal
                         (kredensial/keys) — LEAD (high).
  - snaffler-cred-marker : konten matched memuat marker kredensial
                         deterministik (password=, BEGIN PRIVATE KEY,
                         PFX/kdbx/id_rsa/unattend) — penguat.
  - snaffler-file-class  : path file yang di-match memuat ekstensi/nama
                         kelas sensitif (.kdbx/.pem/.pfx/id_rsa/unattend/
                         web.config/.env) — lead.
  - snaffler-low-tier    : HANYA tag {YELLOW}/{GREEN} — inventori temuan
                         rendah (low).
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info. Log yang
hanya berisi header tool / file bersih tanpa tag warna -> exit 2
(bukan output Snaffler).

Fail-closed: teks tanpa tag warna Snaffler sama sekali -> exit 2; file
tidak ada -> exit 2. Temuan = LEAD (nilai match bisa false-positive dari
tool asal — konfirmasi file sebelum klaim).

Pemakaian:
  python tools/snaffler_log_triage.py --file snaffler.log --out o.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.snaffler-log-triage/1"

_RE_CTX = re.compile(r"\{(BLACK|RED|YELLOW|GREEN)\}", re.I)
_RE_TAG = re.compile(r"\{(BLACK|RED|YELLOW|GREEN)\}([^\r\n]*)", re.I)
_RE_PATH = re.compile(
    r"((?:[A-Za-z]:[\\/]{1,2}|\\\\{1,2}[\w.\-]+[\\/]{1,2})[^\r\n\",]+)")
_RE_CRED = re.compile(
    r"password\s*=|passwd\s*=|BEGIN (?:RSA )?PRIVATE KEY|BEGIN Trusted"
    r"|An unattend|PWD=|pwd lastset", re.I)
_RE_FILE_CLASS = re.compile(
    r"\.(kdbx|pem|pfx|p12|ppk|env)$|id_rsa|unattend|web\.config|"
    r"credentials|vnc\.ini", re.I)


def triage_text(text: str) -> dict:
    """Triase output Snaffler -> dict hasil. Raise ValueError bila
    tanpa konteks tag warna."""
    if not _RE_CTX.search(text):
        raise ValueError("teks tidak mengandung tag warna Snaffler "
                         "({BLACK}/{RED}/{YELLOW}/{GREEN})")

    signals: "list[str]" = []
    evidence: dict[str, str] = {}
    tag_counts = {"BLACK": 0, "RED": 0, "YELLOW": 0, "GREEN": 0}
    black_red_lines: "list[str]" = []
    cred_lines: "list[str]" = []
    file_class: "list[str]" = []

    for m in _RE_TAG.finditer(text):
        tag = m.group(1).upper()
        rest = m.group(2)
        tag_counts[tag] += 1
        line = (tag + rest).strip()[:200]
        if tag in ("BLACK", "RED"):
            black_red_lines.append(line)
        if _RE_CRED.search(rest):
            cred_lines.append(line)
        pm = _RE_PATH.search(rest)
        if pm and _RE_FILE_CLASS.search(pm.group(1)):
            file_class.append(line)

    if black_red_lines:
        signals.append("snaffler-black-red")
        evidence["black-red-sample"] = black_red_lines[0][:180]
        evidence["black-red-count"] = str(len(black_red_lines))
    if cred_lines:
        signals.append("snaffler-cred-marker")
        evidence["cred-sample"] = cred_lines[0][:180]
    if file_class:
        signals.append("snaffler-file-class")
        evidence["file-class-sample"] = file_class[0][:180]
    if not black_red_lines and (tag_counts["YELLOW"] + tag_counts["GREEN"]):
        signals.append("snaffler-low-tier")
        evidence["low-tier-count"] = str(tag_counts["YELLOW"] +
                                         tag_counts["GREEN"])

    seen: set[str] = set()
    signals = [s for s in signals if not (s in seen or seen.add(s))]

    score = len(signals)
    severity = ("high" if score >= 3 else
                "medium" if score == 2 else
                "low" if score == 1 else "info")
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    counts[severity] = 1
    return {
        "schema": SCHEMA,
        "score": score,
        "severity": severity,
        "signals": signals,
        "evidence": evidence,
        "tag_counts": tag_counts,
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "snaffler-finding", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "taksonomi warna milik tool asal (semakin gelap semakin "
                "bernilai) — match bisa false-positive; konfirmasi file "
                "asli sebelum klaim; parser toleran-format",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True, help="output/log Snaffler")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        result = triage_text(text)
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
