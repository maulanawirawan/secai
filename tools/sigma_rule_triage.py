r"""[SAFETY: read-only] sigma_rule_triage — wave-7 linter OFFLINE aturan
deteksi format Sigma (YAML) — satu atau banyak dokumen (`---`) dalam
satu file — untuk cacat yang membuat rule diam, rapuh, atau terlalu
luas (lint berbasis struktur baris, bukan parser YAML umum; stdlib
murni, tanpa jaringan; subset di luar pola -> diabaikan aman).

Sinyal per dokumen-rule (semua deterministik dari data):
  - sigma-no-detection     : section detection: tidak ada.
  - sigma-no-condition     : detection: ada tapi `condition:` hilang.
  - sigma-condition-broad  : condition pola "1 of them"/"any of them"/
                             "all of them" — match SEMUA selection.
  - sigma-wildcard-value   : nilai field berupa wildcard tunggal
                             (`field: '*'`) — match semua nilai.
  - sigma-status-deprecated: status: deprecated / unsupported.
  - sigma-no-level         : `level:` hilang pada rule yang punya title.
  - sigma-no-logsource     : `logsource:` hilang (tidak bisa dinormalisasi
                             ke backend).
  - sigma-title-placeholder: title kosong / TODO / placeholder.
Skor = jumlah sinyal pada rule TERBURUK; >= 3 high, == 2 medium,
== 1 low, 0 info. Rule lengkap (condition spesifik, nilai konkrit,
level+logsource ada) -> 0 sinyal (zero-FP).

Fail-closed: file tanpa field khas Sigma (detection:/title:/logsource:)
sama sekali -> exit 2; file tidak ada -> exit 2. Temuan = LEAD
(rule wide bisa disengaja; konfirmasi use-case).

Pemakaian:
  python tools/sigma_rule_triage.py --file rules.yml --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.sigma-rule-triage/1"

_RE_DOC_SPLIT = re.compile(r"^---\s*$", re.M)
_RX = {
    "title": re.compile(r"^\s*title\s*:", re.M),
    "detection": re.compile(r"^\s*detection\s*:", re.M),
    "condition": re.compile(r"^\s*condition\s*:", re.M),
    "logsource": re.compile(r"^\s*logsource\s*:", re.M),
    "level": re.compile(r"^\s*level\s*:", re.M),
    "status": re.compile(r"^\s*status\s*:\s*(\S+)", re.M),
    "title_value": re.compile(r"^\s*title\s*:\s*(.*)$", re.M),
    "condition_value": re.compile(r"^\s*condition\s*:\s*(.*)$", re.M),
}
_RE_BROAD = re.compile(r"\b(?:1 of them|any of them|all of them)\b", re.I)
_RE_WILDCARD_VAL = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_.\-]*\s*:\s*['\"]?\*{1,2}['\"]?\s*$", re.M)
_RE_PLACEHOLDER = re.compile(r"\b(?:todo|placeholder|xxx)\b", re.I)


def _lint_doc(text: str) -> "list[str]":
    """Lint satu dokumen Sigma (potongan teks). Return daftar sinyal."""
    sig: "list[str]" = []
    has_detection = bool(_RX["detection"].search(text))
    has_condition = bool(_RX["condition"].search(text))

    if not has_detection:
        sig.append("sigma-no-detection")
    elif not has_condition:
        sig.append("sigma-no-condition")

    if has_condition:
        cv = _RX["condition_value"].search(text)
        if cv and _RE_BROAD.search(cv.group(1)):
            sig.append("sigma-condition-broad")

    if has_detection and _RE_WILDCARD_VAL.search(text):
        sig.append("sigma-wildcard-value")

    m = _RX["status"].search(text)
    if m and m.group(1).strip().strip('"\'').lower() in (
            "deprecated", "unsupported"):
        sig.append("sigma-status-deprecated")

    has_title = bool(_RX["title"].search(text))
    if has_title and not _RX["level"].search(text):
        sig.append("sigma-no-level")

    if has_detection and not _RX["logsource"].search(text):
        sig.append("sigma-no-logsource")

    if has_title:
        tv = _RX["title_value"].search(text)
        val = (tv.group(1) if tv else "").strip().strip('"\'')
        if not val or _RE_PLACEHOLDER.search(val):
            sig.append("sigma-title-placeholder")

    seen: set[str] = set()
    return [s for s in sig if not (s in seen or seen.add(s))]


def triage_text(text: str) -> dict:
    """Triase file Sigma -> dict hasil. Raise ValueError bila tanpa
    konteks."""
    if not (_RX["detection"].search(text) or _RX["title"].search(text) or
            _RX["logsource"].search(text)):
        raise ValueError("file tidak mengandung field khas Sigma "
                         "(detection:/title:/logsource:)")

    chunks = [c for c in _RE_DOC_SPLIT.split(text) if c.strip()]
    per_rule: "list[dict]" = []
    all_signals: "list[str]" = []
    for i, c in enumerate(chunks):
        sig = _lint_doc(c)
        tm = _RX["title_value"].search(c)
        title = (tm.group(1) if tm else "").strip().strip('"\'')[:80]
        per_rule.append({"rule": i + 1, "title": title, "signals": sig})
        all_signals.extend(sig)

    seen: set[str] = set()
    uniq = [s for s in all_signals if not (s in seen or seen.add(s))]

    worst = max((len(r["signals"]) for r in per_rule), default=0)
    severity = ("high" if worst >= 3 else
                "medium" if worst == 2 else
                "low" if worst == 1 else "info")
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    counts[severity] = 1
    return {
        "schema": SCHEMA,
        "score": worst,
        "severity": severity,
        "signals": uniq,
        "evidence": {"rules": str(len(per_rule)),
                     "worst-rule": str(worst)},
        "rules": per_rule[:20],
        "severity_counts": counts,
        "finding_count": 1 if worst > 0 else 0,
        "findings": ([{"type": "sigma-rule-lint", "severity": severity,
                       "signals": uniq,
                       "evidence": {"rules": str(len(per_rule))}}
                      ] if worst > 0 else []),
        "clean_count": 0 if worst > 0 else 1,
        "note": "lint statik — rule broad bisa disengaja utk deteksi "
                "wide; konfirmasi use-case; lint berbasis struktur "
                "baris, bukan parser YAML lengkap",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="file YAML Sigma (satu/lebih dokumen)")
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
