r"""[SAFETY: read-only] scom_artifact_triage — wave-6 triase OFFLINE
artefak System Center Operations Manager (SCOM) untuk indikasi
kredensial yang dapat diekstrak/didekripsi offline (referensi tool
"SCOMDecrypt" dari pustaka referensi — blob SecureData SCOM dapat
didekripsi dengan kunci mesin; tool ini MENDETEKSI artefaknya, bukan
mendekripsi; kode dibangun dari nol, stdlib murni, tanpa jaringan).

Sumber artefak: XML Management Pack / ekspor registry / command line /
log yang menyebut SCOM.

Sinyal per file (semua deterministik dari data):
  - scom-securedata-blob   : elemen <SecureData>/<SecureString>/
    <SecureStorageId> pada XML MP — blob kredensial terenkripsi yang
    jadi target dekripsi offline (perlu kunci mesin, di luar scope).
  - scom-plaintext-password: field <Password>/<UserName> terisi teks
    polos (tanpa enkripsi) di artefak — rahasia hidup, prioritas.
  - scom-runas-registry    : path registry Microsoft Operations Manager
    dengan komponen RunAs/SecureStorage.
  - scom-decrypt-usage     : command/artefak yang MEMAKAI tool dekripsi
    (SCOMDecrypt, Get-SCOMRunAsAccount + export) — konteks penyerang
    atau operasi kredensial.
  - scom-runas-mp          : elemen <RunAsAccount>/<RunAsProfile> pada
    XML MP — MP memakai kredensial (konteks, bukan temuan berdiri).
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info. Teks
SCOM (dok monitoring) TANPA artefak kredensial -> 0 sinyal (clean,
zero-FP).

Fail-closed: file tanpa konteks SCOM ("scom" / "Microsoft Operations
Manager" / "Operations Manager") sama sekali -> exit 2; file tidak
ada -> exit 2. Temuan = LEAD (ekspor MP RunAs sah ada di pipeline
deploy — konfirmasi pemilik artefak).

Pemakaian:
  python tools/scom_artifact_triage.py --file mp.xml --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.scom-artifact-triage/1"

_RE_CTX = re.compile(
    r"\bscom\b|SCOMDecrypt|Get-SCOM|Microsoft Operations Manager"
    r"|Operations Manager|System\s*Center", re.I)
_RE_SECURE = re.compile(
    r"<\s*(?:SecureData|SecureString|SecureStorageId|SecureReference)\b",
    re.I)
_RE_PLAIN_PW = re.compile(
    r"<\s*(?:Password)\s*>\s*([^<\s][^<]{0,180}?)\s*<\s*/\s*Password\s*>",
    re.I)
_RE_RUNAS_REG = re.compile(
    r"Microsoft\s+Operations\s+Manager[^;\r\n]{0,160}"
    r"(RunAs|SecureStorage|Config\.\d+)", re.I)
_RE_DECRYPT = re.compile(
    r"\bSCOMDecrypt\b|"
    r"Get-SCOMRunAsAccount[^;\r\n]{0,120}(export|dump|Out-File|ConvertTo-)",
    re.I)
_RE_RUNAS_MP = re.compile(
    r"<\s*(?:RunAsAccount|RunAsProfile|SecureInput)\b", re.I)


def triage_text(text: str) -> dict:
    """Triase artefak SCOM -> dict hasil. Raise ValueError bila tanpa
    konteks SCOM."""
    if not _RE_CTX.search(text):
        raise ValueError("artefak tidak mengandung konteks SCOM — bukan "
                         "target triase ini")

    signals: "list[str]" = []
    evidence: dict[str, str] = {}

    m = _RE_SECURE.search(text)
    if m:
        signals.append("scom-securedata-blob")
        evidence["blob"] = m.group(0)

    m = _RE_PLAIN_PW.search(text)
    if m:
        signals.append("scom-plaintext-password")
        val = m.group(1)
        evidence["plaintext-pw"] = ("<terisi %d char, isi tidak dicetak>"
                                    % len(val))

    if _RE_RUNAS_REG.search(text):
        signals.append("scom-runas-registry")
        evidence["runas-reg"] = _RE_RUNAS_REG.search(text).group(0)[:140]

    m = _RE_DECRYPT.search(text)
    if m:
        signals.append("scom-decrypt-usage")
        evidence["decrypt"] = m.group(0)[:140]

    if _RE_RUNAS_MP.search(text):
        signals.append("scom-runas-mp")
        evidence["runas-mp"] = _RE_RUNAS_MP.search(text).group(0)

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
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "scom-credential-exposure",
                       "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "blob SecureData butuh kunci mesin (DPAPI/registry host) "
                "untuk dekripsi — tool ini hanya mendeteksi keberadaan "
                "artefaknya; ekspor MP RunAs sah ada di pipeline deploy",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="XML MP / ekspor registry / command log SCOM")
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
