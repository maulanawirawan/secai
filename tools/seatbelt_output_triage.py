r"""[SAFETY: read-only] seatbelt_output_triage — wave-9 triase OFFLINE
output enumerasi host gaya-Seatbelt (konsol dgn section
`====== <command> ======`): ringkas konfigurasi host yang membuka jalur
privesc/persistence dari hasil enum yang diperbolehkan. Parser section-
aware dari nol, stdlib murni, tanpa jaringan. Beda ranah dari
win_audit_coverage (cakupan audit) dan linux_privesc_audit (Linux).

Sinyal per artefak (semua deterministik dari data):
  - sb-autologon-creds   : section autologon memuat DefaultPassword=
                           terisi — kredensial plaintext (high).
  - sb-alwayselevated    : AlwaysInstallElevated = 1 di KEDUA hive
                           utk privesc MSI (di satu hive saja = lead)
                           (high/medium).
  - sb-uac-weak          : EnableLUA=0 (UAC mati) atau
                           LocalAccountTokenFilterPolicy=1 (UAC remote
                           bypass) (medium).
  - sb-lsa-unprotected   : LSA Protection/RunAsPPL tidak aktif
                           (medium — kredensial dapat diekstrak).
  - sb-admin-context     : section localgroup/localgroupmemberships
                           menempatkan user aktif di BUILTIN\
                           Administrators (konteks, low).
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info. Enum
dgn konfigurasi aman (tidak ada marker) -> 0 sinyal (zero-FP).

Fail-closed: teks tanpa section marker `======` gaya enum sama sekali
-> exit 2; file tidak ada -> exit 2. Temuan = LEAD (host bisa lab/
hardened-berbeda-kebijakan).

Pemakaian:
  python tools/seatbelt_output_triage.py --file sb.txt --out o.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.seatbelt-output-triage/1"

_RE_CTX = re.compile(r"^={3,}\s*\S.*={3,}\s*$", re.M)
_RE_SECTION = re.compile(r"^={3,}\s*([^\r\n=]+?)\s*={3,}\s*$", re.M)

_RE_AUTOLOGON_PW = re.compile(
    r"DefaultPassword\s*[:=]\s*(\S+)", re.I)
_RE_AIE = re.compile(
    r"AlwaysInstallElevated\s*[:=]?\s*(\d+)", re.I)
_RE_UAC = re.compile(
    r"EnableLUA\s*[:=]?\s*(0x)?(0|1)|LocalAccountTokenFilterPolicy"
    r"\s*[:=]?\s*(0x)?(1)\b", re.I)
_RE_LSA = re.compile(
    r"RunAsPPL\s*[:=]?\s*(0x)?0\b|LSA Protection\s*[:=]?\s*(not|off|0)",
    re.I)
_RE_ADMIN = re.compile(
    r"BUILTIN\\\\?Administrators", re.I)


def _sections(text: str) -> "list[tuple[str, str]]":
    out: "list[tuple[str, str]]" = []
    heads = list(_RE_SECTION.finditer(text))
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        out.append((m.group(1).lower(), text[m.end():end]))
    return out


def triage_text(text: str) -> dict:
    """Triase output enum gaya-Seatbelt -> dict hasil. Raise ValueError
    bila tanpa konteks section."""
    if not _RE_CTX.search(text):
        raise ValueError("teks tidak mengandung section marker "
                         "`====== ... ======` gaya enum host")
    sections = dict(_sections(text))

    signals: "list[str]" = []
    evidence: dict[str, str] = {}

    def find_section(*needles: str) -> str:
        for name, body in sections.items():
            if all(n in name for n in needles):
                return body
        return ""

    auto = find_section("autologon")
    if auto and "DefaultUserName" in auto:
        m = _RE_AUTOLOGON_PW.search(auto)
        if m and m.group(1).strip("\"\x27"):
            signals.append("sb-autologon-creds")
            evidence["autologon"] = ("DefaultPassword terisi (%d char, "
                                     "isi tidak dicetak)"
                                     % len(m.group(1)))

    aie = _RE_AIE.findall(text)
    ones = [v for v in aie if v in ("1", "0x1")]
    if len(aie) >= 2 and len(ones) == len(aie):
        signals.append("sb-alwayselevated")
        evidence["alwayselevated"] = "1 pada %d hive (privesc MSI penuh)" \
                                     % len(aie)
    elif len(ones) == 1:
        signals.append("sb-alwayselevated")
        evidence["alwayselevated"] = ("1 pada 1 hive (lead — kedua hive "
                                      "wajib utk privesc MSI penuh)")

    for name, b in sections.items():
        if "uac" in name or "tokenfilter" in name:
            m = _RE_UAC.search(b)
            if m and (m.group(2) == "0" or m.group(4)):
                signals.append("sb-uac-weak")
                evidence.setdefault("uac", m.group(0)[:60])
                break

    for name, b in sections.items():
        if "lsa" in name or "ppl" in name:
            m = _RE_LSA.search(b)
            if m:
                signals.append("sb-lsa-unprotected")
                evidence.setdefault("lsa", m.group(0)[:60])
                break

    for name, b in sections.items():
        if ("localgroup" in name or "administrators" in name) and \
                _RE_ADMIN.search(b):
            signals.append("sb-admin-context")
            evidence.setdefault("admin-group",
                                name[:60] + " memuat BUILTIN\\"
                                "Administrators member")
            break

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
        "sections": sorted(sections.keys())[:40],
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "host-enum-posture", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "enum host bisa dari hardening-check sah — konfirmasi "
                "pemilik host; nilai DefaultPassword TIDAK pernah "
                "dicetak ke evidence",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="output enum host gaya-Seatbelt")
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
