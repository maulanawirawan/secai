r"""[SAFETY: read-only] hidden_account_triage — wave-5 deteksi OFFLINE
ekspor registry (.reg), output `reg query`, atau perintah PowerShell
terhadap penyembunyian akun lokal dari layar logon Windows via kunci
`HKLM\...\Winlogon\SpecialAccounts\UserList` (referensi teknik "Hiding
the local admin account" dari pustaka referensi; kode dibangun dari
nol, stdlib murni, tanpa jaringan).

Mekanisme: section-aware — file .reg dipecah per seksi `[HKEY_...]`
dan dump reg query per header `HKEY_...`; hanya entri di bawah seksi
UserList/SpecialAccounts yang dinilai, sehingga DWORD 0 milik kunci
lain TIDAK terhitung.

Sinyal per file (semua deterministik dari data):
  - userlist-hidden-entry : nilai DWORD 0 di bawah [...\UserList] —
                            akun bernama disembunyikan dari Welcome
                            screen (entri dword:00000000).
  - hidden-admin-name     : salah satu nama akun tersembunyi berpola
                            admin-ish (admin/svc/support/backup/
                            helpdesk/tech/it/ghost/remote).
  - hide-action           : perintah yang menyembunyikan (reg add ... /
                            d 0, New-ItemProperty/Set-ItemProperty
                            -Value 0 pada path UserList).
  - specialaccounts-key   : path UserList/SpecialAccounts hadir TANPA
                            satu pun entri nilai ter-parse (kunci
                            baru dibuat / dump hanya enumerasi kunci).
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info (dump
UserList yang semua entrinya dword:1 — akun dibuat TERLIHAT — TIDAK
dihitung; zero-FP).

Fail-closed: file tanpa konteks UserList/SpecialAccounts sama sekali
-> exit 2; file tidak ada -> exit 2. Temuan = LEAD (menyembunyikan
akun juga tweak sah OEM/personalisasi — caveat di note).

Pemakaian:
  python tools/hidden_account_triage.py --file dump.reg --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.hidden-account-triage/1"

_RE_CTX = re.compile(r"(SpecialAccounts|UserList)", re.I)
_RE_SECTION = re.compile(r"^\[([^\]]+)\]", re.M)
_RE_HKEY_LINE = re.compile(r"^\s*(HKEY_[^\r\n]+?)\s*$", re.M)
_RE_REG_ENTRY = re.compile(r'"([^"]+)"\s*=\s*dword:([0-9a-fA-F]{8})')
_RE_QUERY_ENTRY = re.compile(r"^\s{2,}(\S+)\s+REG_DWORD\s+0x([0-9a-fA-F]+)",
                             re.M)
_RE_HIDE_ACTION = re.compile(
    r"(reg\s+add[^;\n]{0,180}UserList[^;\n]{0,80}/d\s+0\b|"
    r"New-ItemProperty[^;\n]{0,180}(SpecialAccounts|UserList)"
    r"[^;\n]{0,160}-Value\s+0\b|"
    r"Set-ItemProperty[^;\n]{0,180}(SpecialAccounts|UserList)"
    r"[^;\n]{0,80}-Value\s+0\b)", re.I)
_RE_ADMINISH = re.compile(
    r"(admin|svc\b|support|backup|helpdesk|it[_\-\d]|tech|service|"
    r"remote|ghost)", re.I)


def _is_userlist_path(path: str) -> bool:
    return bool(re.search(r"(SpecialAccounts[\\/]+UserList|UserList)",
                          path, re.I))


def _sections(text: str) -> "list[tuple[str, str]]":
    """(path, body) per seksi [HKEY_...]; body = teks sampai header
    berikutnya. Fallback reg-query: header HKEY_... per baris."""
    out: "list[tuple[str, str]]" = []
    heads = list(_RE_SECTION.finditer(text))
    if heads:
        for i, m in enumerate(heads):
            end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
            out.append((m.group(1), text[m.end():end]))
        return out
    qheads = list(_RE_HKEY_LINE.finditer(text))
    for i, m in enumerate(qheads):
        end = qheads[i + 1].start() if i + 1 < len(qheads) else len(text)
        out.append((m.group(1), text[m.end():end]))
    return out


def triage_text(text: str) -> dict:
    """Triase dump -> dict hasil. Raise ValueError bila tanpa konteks."""
    if not _RE_CTX.search(text):
        raise ValueError("dump tidak mengandung konteks UserList/"
                         "SpecialAccounts — bukan artefak yang relevan")

    signals: "list[str]" = []
    evidence: dict[str, str] = {}
    hidden: "list[str]" = []
    has_userlist_path = False
    parsed_entries = 0

    for path, body in _sections(text):
        if not _is_userlist_path(path):
            continue
        has_userlist_path = True
        entries = _RE_REG_ENTRY.findall(body)
        if not entries:
            for name, hexv in _RE_QUERY_ENTRY.findall(body):
                entries.append((name, hexv))
        parsed_entries += len(entries)
        for name, hexv in entries:
            if int(hexv, 16) == 0:
                if name not in hidden:
                    hidden.append(name)

    if hidden:
        signals.append("userlist-hidden-entry")
        evidence["hidden-accounts"] = ", ".join(hidden[:8])
        for name in hidden:
            if _RE_ADMINISH.search(name):
                signals.append("hidden-admin-name")
                evidence["adminish"] = name
                break

    if _RE_HIDE_ACTION.search(text):
        signals.append("hide-action")
        m = _RE_HIDE_ACTION.search(text)
        if m:
            evidence["action"] = m.group(0)[:140]

    if has_userlist_path and parsed_entries == 0 and "hide-action" not in signals:
        signals.append("specialaccounts-key")
        evidence["key"] = "path UserList/SpecialAccounts hadir tanpa " \
                          "entri nilai ter-parse"

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
        "hidden_accounts": hidden,
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "hidden-local-account", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "menyembunyikan akun dari Welcome screen juga tweak sah "
                "(OEM/personalisasi) — konfirmasi pemilik host sebelum "
                "ditindak; cek anggota grup Administrators via live host",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="ekspor .reg / output reg query / teks perintah")
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
