r"""[SAFETY: read-only] cme_log_triage — wave-7 triase OFFLINE output/
log tool eksekusi-lateral keluarga SMB-execution ("CrackMapExec" /
"netexec / nxc" — format output konsol yang banyak dipakai di kampanye
lateral; parser dibangun dari nol, stdlib murni, tanpa jaringan).
Nilai DFIR: baris keberhasilan autentikasi, marker akses admin, dan
indikasi dumping kredensial di konsol operator.

Sinyal per artefak (semua deterministik dari data):
  - cme-admin-access : marker admin ("Pwn3d!") pada baris auth sukses —
                       kredensial yang dipakai punya hak admin.
  - cme-auth-success : baris [+] autentikasi sukses (domain\user:...).
  - cme-cred-dump    : indikasi dumping (Dumped NTLM/LSA/SAM hashes,
                       NTDS.dit, drsuapi, --sam/--lsa/--ntds) — kredensial
                       dikumpulkan.
  - cme-smb-signing  : temuan "SMB signing is disabled" — konteks
                       relay/intercept.
  - cme-lateral-hosts: >= --many host berbeda menerima sukses (default
                       3) — pergerakan lateral luas.
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info. Output
yang SEMUA barisnya kegagalan [-] -> 0 sinyal (zero-FP; percobaan
gagal tidak dihitung temuan).

Fail-closed: teks tanpa konteks output CME/nxc (pola host-port-SMB /
bracket marker / nama tool) sama sekali -> exit 2; file tidak ada ->
exit 2. Temuan = LEAD (log bisa lab/kursus — konfirmasi perizinan).

Pemakaian:
  python tools/cme_log_triage.py --file cme.txt --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.cme-log-triage/1"

_RE_TOOL = re.compile(r"\b(?:crackmapexec|netexec|nxc)\b", re.I)
_RE_HOSTLINE = re.compile(
    r"(?:SMB|HTTP|SSH|WINRM|MSSQL|LDAP|FTP|RDP)\s+\d{1,3}(?:\.\d{1,3}){3}"
    r"\s+\d{2,5}\s+\S+", re.I)
_RE_BRACKET = re.compile(r"[\[\(][+\-\*x][\]\)]")
_RE_OK_MARK = re.compile(r"[\[\(][+\*x][\]\)]")  # sukses saja ([-] gagal)
_RE_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_RE_CTX = re.compile(r"\b(?:crackmapexec|netexec|nxc)\b|"
                     r"(?:SMB|WINRM|HTTP)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d{2,5}",
                     re.I)

_RE_ADMIN = re.compile(r"Pwn3d!", re.I)
_RE_AUTH_OK = re.compile(
    r"[\[\(][+\*x][\]\)][^\r\n]{0,120}?"
    r"[A-Za-z0-9_.\-]+\\[A-Za-z0-9_$.\-]+:[^\s:]{1,60}")
_RE_DUMP = re.compile(
    r"Dumped\s+[^\r\n]{0,60}hashes|NTDS\.dit|drsuapi|"
    r"--sam\b|--lsa\b|--ntds\b|LSA\s+hashes|SAM\s+hashes", re.I)
_RE_SIGNING = re.compile(r"SMB signing (?:is )?disabled", re.I)


def triage_text(text: str, *, many: int = 3) -> dict:
    """Triase output CME/nxc -> dict hasil. Raise ValueError bila tanpa
    konteks."""
    if not (_RE_TOOL.search(text) or _RE_CTX.search(text) or
            (_RE_HOSTLINE.search(text) and _RE_BRACKET.search(text))):
        raise ValueError("teks tidak mengandung konteks output eksekusi "
                         "lateral (CME/nxc) — bukan target triase ini")

    signals: "list[str]" = []
    evidence: dict[str, str] = {}

    admin_lines = [ln.strip() for ln in text.splitlines()
                   if _RE_ADMIN.search(ln)]
    ok_lines = _RE_AUTH_OK.findall(text)

    hosts_ok: "list[str]" = []
    for ln in text.splitlines():
        if _RE_OK_MARK.search(ln):
            hosts_ok.extend(_RE_IP.findall(ln))

    if admin_lines:
        signals.append("cme-admin-access")
        evidence["pwn3d"] = admin_lines[0][:160]
        evidence["pwn3d-count"] = str(len(admin_lines))
    if ok_lines:
        signals.append("cme-auth-success")
        evidence["auth-sample"] = ok_lines[0].strip()[:160]
        evidence["auth-count"] = str(len(ok_lines))

    m = _RE_DUMP.search(text)
    if m:
        signals.append("cme-cred-dump")
        evidence["dump"] = m.group(0)[:120]

    if _RE_SIGNING.search(text):
        signals.append("cme-smb-signing")
        evidence["signing"] = _RE_SIGNING.search(text).group(0)

    hosts_ok = sorted(set(hosts_ok))
    if len(hosts_ok) >= many:
        signals.append("cme-lateral-hosts")
        evidence["hosts-ok"] = ", ".join(hosts_ok[:10])[:200]
        evidence["hosts-count"] = str(len(hosts_ok))

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
        "findings": ([{"type": "lateral-execution-log", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "output CME/nxc bisa dari lab/kursus/red-team berizin — "
                "konfirmasi perizinan; baris [-] (gagal) tidak dihitung "
                "temuan, hanya konteks",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="output konsol / log CME, netexec, nxc")
    ap.add_argument("--many", type=int, default=3,
                    help="ambang cme-lateral-hosts (default 3)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        result = triage_text(text, many=args.many)
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
