r"""[SAFETY: read-only] whoami_priv_triage — wave-7 triase OFFLINE output
`whoami /priv` (+ opsional `whoami /groups`) Windows: identifikasi
privilege bernilai-tinggi yang tersedia pada konteks token dan status
Enabled/Disabled (pola enumerasi privesc standar pada penilaian
Windows; parser dibangun dari nol, stdlib murni, tanpa jaringan).

Format didukung: tabel default `whoami /priv`, output `/fo csv`, dan
section `GROUPS INFORMATION` dari `whoami /groups`.

Sinyal per artefak (semua deterministik dari data):
  - priv-dangerous-enabled : privilege berbahaya dgn State Enabled.
    Daftar berbahaya: SeImpersonate, SeAssignPrimaryToken, SeDebug,
    SeBackup, SeRestore, SeLoadDriver, SeTakeOwnership, SeManageVolume,
    SeEnableDelegation, SeCreateSymbolicLink, SeTrustedCredManAccess.
  - priv-dangerous-disabled: privilege berbahaya hadir tapi Disabled
    (bisa di-enable ulang via mekanisme tertentu — lead, bukan bukti).
  - group-admin-enabled    : section GROUPS INFORMATION memuat grup
    BUILTIN\Administrators (atau SID S-1-5-32-544) dgn status "Enabled
    group" — konteks token adalah admin lokal.
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info. Output
user standar (SeChangeNotify/SeUndock/SeShutdown dll.) TIDAK dihitung
(zero-FP) — daftar di evidence tetap dilaporkan sebagai inventaris.

Fail-closed: teks tanpa section PRIVILEGES INFORMATION / Privilege Name
/ Se*Privilege sama sekali -> exit 2; file tidak ada -> exit 2.
Temuan = LEAD (status token bisa sah; konfirmasi konteks host).

Pemakaian:
  python tools/whoami_priv_triage.py --file priv.txt --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.whoami-priv-triage/1"

# privilege berbahaya (nama tanpa suffix Privilege) -> deskripsi singkat
DANGEROUS = {
    "SeImpersonate": "impersonate client (potato-family privesc)",
    "SeAssignPrimaryToken": "assign primary token (potato-family)",
    "SeDebug": "debug arbitrary process (inject into SYSTEM)",
    "SeBackup": "backup (read any file via backup semantics)",
    "SeRestore": "restore (write any file via backup semantics)",
    "SeLoadDriver": "load kernel driver",
    "SeTakeOwnership": "take ownership of arbitrary objects",
    "SeManageVolume": "manage volume (setzero/erase primitives)",
    "SeEnableDelegation": "enable delegation (AD privilege escalation)",
    "SeCreateSymbolicLink": "create symlinks (arbitrary read paths)",
    "SeTrustedCredManAccess": "credential manager access",
}

_RE_CTX = re.compile(
    r"PRIVILEGES INFORMATION|Privilege Name|GROUPS INFORMATION|"
    r"\bSe[A-Za-z]+Privilege\b", re.I)
# tabel: "SeImpersonatePrivilege   Impersonate a client...   Enabled"
_RE_TABLE = re.compile(
    r"^\s*(Se[A-Za-z]+?Privilege)\s{2,}.*?\s(Enabled|Disabled)\s*$", re.M)
# csv: "SeImpersonatePrivilege","...","Enabled"
_RE_CSV = re.compile(r'"(Se[A-Za-z]+?Privilege)","[^"]*","(Enabled|Disabled)"')
# header section priv dgn kolom State utk validasi tabel
_RE_PRIV_HEADER = re.compile(r"Privilege Name.*State", re.S)
# groups: "BUILTIN\Administrators  ...  Enabled group  Local Group"
_RE_GROUP = re.compile(
    r"^\s*(BUILTIN\\Administrators|NT AUTHORITY\\.*?|.*?)\s{2,}.*?"
    r"\s(Enabled group|Disabled group|Enabled for delegation group)\s+.*$",
    re.M)
_RE_ADMIN_GROUP = re.compile(
    r"BUILTIN\\Administrators|S-1-5-32-544", re.I)


def _enabled_admin_group(text: str) -> bool:
    """True bila section GROUPS INFORMATION memuat baris Administrators
    dengan status enabled group."""
    m = re.search(r"GROUPS INFORMATION(.*?)(?:PRIVILEGES INFORMATION|\Z)",
                  text, re.S)
    if not m:
        return False
    body = m.group(1)
    for line in body.splitlines():
        if _RE_ADMIN_GROUP.search(line) and re.search(
                r"\bEnabled group\b", line, re.I):
            return True
    return False


def triage_text(text: str) -> dict:
    """Triase output whoami -> dict hasil. Raise ValueError bila tanpa
    konteks."""
    if not _RE_CTX.search(text):
        raise ValueError("teks tidak mengandung output whoami "
                         "(PRIVILEGES INFORMATION / Se*Privilege)")

    signals: "list[str]" = []
    evidence: dict[str, str] = {}

    pairs = _RE_CSV.findall(text)
    if pairs:
        fmt = "csv"
    elif _RE_PRIV_HEADER.search(text) or _RE_TABLE.search(text):
        pairs = _RE_TABLE.findall(text)
        fmt = "table"
    else:
        pairs = []

    priv_state: dict[str, str] = {}
    for name, state in pairs:
        priv_state[name] = state

    if not priv_state and "PRIVILEGES INFORMATION" not in text:
        raise ValueError("tidak ada privilege ter-parse — bukan output "
                         "whoami /priv yang valid")

    enabled_dangerous: "list[str]" = []
    disabled_dangerous: "list[str]" = []
    for name, state in priv_state.items():
        base = name[:-len("Privilege")] if name.endswith("Privilege") else name
        if base in DANGEROUS:
            (enabled_dangerous if state.lower() == "enabled"
             else disabled_dangerous).append(name)

    if enabled_dangerous:
        signals.append("priv-dangerous-enabled")
        evidence["enabled"] = ", ".join(enabled_dangerous)[:200]
        evidence["enabled-detail"] = "; ".join(
            "%s=%s" % (n, DANGEROUS[n[:-len("Privilege")]])
            for n in enabled_dangerous)[:300]
    if disabled_dangerous:
        signals.append("priv-dangerous-disabled")
        evidence["disabled"] = ", ".join(disabled_dangerous)[:200]
    if _enabled_admin_group(text):
        signals.append("group-admin-enabled")
        evidence["group"] = "BUILTIN\\Administrators enabled"

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
        "format": fmt,
        "privileges": priv_state,
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "dangerous-privilege", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "status privilege bisa sah per host/peran — SeImpersonate "
                "bawaan IIS/service account, SeDebug butuh SeDebug "
                "privilege policy; disabled tetap lead karena bisa "
                "di-enable kembali",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="output whoami /priv dan/atau /groups")
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
