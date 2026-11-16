"""[SAFETY: read-only] rdp_enable_triage — wave-4 RDP: skor OFFLINE dump
registry/event/perintah terhadap pola pengaktifan/pelemahan RDP
(referensi teknik "Enable multiple RDP sessions per user" / "Enabling
RDP" dari pustaka referensi, kode dibangun dari nol).

Sinyal per dump (semua deterministik dari data):
  - rdp-allow-state    : fDenyTSConnections = 0 pada dump keadaan
                         (host mengizinkan RDP)
  - rdp-enable-action  : aksi meng-enable (Set-ItemProperty/reg add
                         fDenyTSConnections -Value 0 ATAU
                         Enable-NetFirewallRule RemoteDesktop*)
  - nla-disabled       : UserAuthentication = 0 (NLA mati — permukaan
                         serangan pre-auth melebar)
  - fw-3389-open       : aturan firewall 3389 dibuka (netsh/PowerShell)
  - rdp-session-success: EventID 1149 (session connection succeeded,
                         listener RDS) ATAU Logon Type 10
  - port-nonstandard   : PortNumber != 3389 (listener dipindah untuk
                         menghindari deteksi)
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info (dump
registry normal dengan fDenyTSConnections = 1 — RDP memang mati —
TIDAK dihitung; zero-FP).

Fail-closed: dump tanpa konteks RDP/terminal sama sekali -> exit 2.
Temuan = LEAD untuk direview manual.

Pemakaian:
  python tools/rdp_enable_triage.py --file regdump.json --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.rdp-enable-triage/1"

_RE_RDP_CTX = re.compile(
    r"(fDenyTSConnections|rdp|remote\s*desktop|TermService|"
    r"TerminalServices|3389|UserAuthentication)", re.I)

_RE_ALLOW_STATE = re.compile(
    r"fDenyTSConnections[^0-9]{0,40}(0x0\b|\b0\b)", re.I)
_RE_ENABLE_ACTION = re.compile(
    r"(Set-ItemProperty[^;\n]{0,80}fDenyTSConnections[^;\n]{0,20}(-Value\s+)?0\b|"
    r"reg add[^;\n]{0,80}fDenyTSConnections[^;\n]{0,12}/d\s+0\b|"
    r"Enable-NetFirewallRule[^;\n]{0,60}RemoteDesktop)", re.I)
_RE_NLA_OFF = re.compile(
    r"UserAuthentication[^0-9]{0,40}(0x0\b|\b0\b)", re.I)
_RE_FW_OPEN = re.compile(
    r"(netsh\s+advfirewall[^;\n]{0,120}(add|set)[^;\n]{0,120}(3389|RemoteDesktop)|"
    r"New-NetFirewallRule[^;\n]{0,120}3389|"
    r"Enable-NetFirewallRule[^;\n]{0,60}RemoteDesktop)", re.I)
_RE_SESSION_OK = re.compile(
    r"(EventID[\"':= ]+1149\b|Logon\s*Type[\"':= ]+10\b)", re.I)
_RE_PORT_CUSTOM = re.compile(
    r"PortNumber[^\n]{0,45}?(?:0x([0-9a-fA-F]{4,5})|(?<!\w)(\d{4,5}))",
    re.I)
_RE_PORT_STD = re.compile(r"PortNumber[^0-9A-Za-z]{0,40}(0xd3d\b|3389\b)", re.I)


def audit_dump(text: str) -> dict | None:
    """Skor satu dump. None = tanpa konteks RDP/terminal sama sekali."""
    if not _RE_RDP_CTX.search(text):
        return None
    signals: list[str] = []
    evidence: dict[str, str] = {}

    if _RE_ALLOW_STATE.search(text):
        signals.append("rdp-allow-state")
        m = re.search(r"fDenyTSConnections[^0-9]{0,12}\d", text, re.I)
        if m:
            evidence["value"] = m.group(0)[:60]
    if _RE_ENABLE_ACTION.search(text):
        signals.append("rdp-enable-action")
        m = re.search(r"(Set-ItemProperty[^;\n]{0,100}fDenyTSConnections"
                      r"[^;\n]{0,20}0|reg add[^;\n]{0,100}0\b|"
                      r"Enable-NetFirewallRule[^;\n]{0,60}RemoteDesktop)",
                      text, re.I)
        if m:
            evidence["cmd"] = m.group(0)[:160]
    if _RE_NLA_OFF.search(text):
        signals.append("nla-disabled")
        m = re.search(r"UserAuthentication[^0-9]{0,12}\d", text, re.I)
        if m:
            evidence["value"] = m.group(0)[:60]
    if _RE_FW_OPEN.search(text):
        signals.append("fw-3389-open")
        m = re.search(r"(netsh|New-NetFirewallRule|Enable-NetFirewallRule)"
                      r"[^\n]{0,120}", text, re.I)
        if m:
            evidence["cmd"] = m.group(0)[:120]
    if _RE_SESSION_OK.search(text):
        signals.append("rdp-session-success")
        m = re.search(r"(EventID[\"':= ]+1149|Logon\s*Type[\"':= ]+10)",
                      text, re.I)
        if m:
            evidence["marker"] = m.group(0)[:40]
    port_m = _RE_PORT_CUSTOM.search(text)
    if port_m:
        if port_m.group(1):  # hex (0x dikonsumsi prefix di regex)
            value = int(port_m.group(1), 16)
        else:
            value = int(port_m.group(2))
        if value != 3389:
            signals.append("port-nonstandard")
            evidence["port"] = str(value)

    seen: set[str] = set()
    signals = [s2 for s2 in signals if not (s2 in seen or seen.add(s2))]

    return {"signals": signals, "score": len(signals), "evidence": evidence}


def triage_text(text: str) -> dict:
    res = audit_dump(text)
    if res is None:
        raise ValueError("dump tidak mengandung konteks RDP/terminal — "
                         "bukan artefak yang relevan")
    score = res["score"]
    severity = ("high" if score >= 3 else
                "medium" if score == 2 else
                "low" if score == 1 else "info")
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    counts[severity] = 1
    return {
        "schema": SCHEMA,
        "score": score,
        "severity": severity,
        "signals": res["signals"],
        "evidence": res["evidence"],
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "rdp-enable", "severity": severity,
                       "signals": res["signals"],
                       "evidence": res["evidence"]}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "skor heuristik pengaktifan/pelemahan RDP — konfirmasi via "
                "host asli sebelum ditindak",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="dump registry / event RDS / teks perintah")
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
