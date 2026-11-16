"""[SAFETY: read-only] defender_tamper_triage — wave-4 Defender: skor OFFLINE
dump event log Windows Defender / MPLog / teks perintah terhadap pola
tampering AV (menonaktifkan/melumpuhkan proteksi sebelum eksekusi payload).

Sinyal per dump (semua deterministik dari data):
  - rtp-disabled       : EventID 5001 (real-time protection dimatikan)
                         ATAU MPLog "Real-Time Scan ... disabled"
  - config-tamper      : EventID 5007 (konfigurasi Defender diubah) +
                         teks Set-MpPreference yang mematikan fitur
                         (DisableRealtimeMonitoring/DisableBehavior
                         Monitoring/DisableIOAVProtection/DisableScript
                         Scanning) ATAU Remove-MpPreference -Exclusion*
  - exclusion-add      : Add-MpPreference -Exclusion* (mengecualikan
                         path/proses dari pemindaian — pola pra-eksekusi
                         payload)
  - av-suspend         : PsSuspend/Suspend terhadap proses AV (MsMpEng,
                         NisSrv) atau service stop (Stop-Service windefend)
  - sig-store-removed  : penghapusan aset signature (folder
                         Definition Updates / mpengine / mpasbase*.vdm)
                         — "cripple defender by deleting signatures"
  - tamper-protect-off : Set-MpPreference -DisableTamperProtection 1 /
                         registry DisableAntiSpyware/DisableAntiVirus = 1
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info (log
Defender normal — scan completed, signature update sukses, definition
download — TIDAK dihitung; zero-FP).

Fail-closed: dump tanpa kata kunci Defender sama sekali -> exit 2.
Temuan = LEAD untuk direview manual (konfirmasi via host asli, bukan
dari dump).

Pemakaian:
  python tools/defender_tamper_triage.py --file events.txt --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.defender-tamper-triage/1"

_RE_DEFENDER_CTX = re.compile(
    r"(defender|microsoft.{0,3}antimalware|mpeng|mplog|nissrv|mssense)",
    re.I)

_RE_RTP_OFF = re.compile(
    r"(EventID[\"':= ]+5001\b|event\s*5001\b|"
    r"Real-?[Tt]ime .{0,20}(disabled|off)\b|"
    r"RealTimeProtectionAvailable\s*[:=]\s*false|"
    r"DisableRealtimeMonitoring\s*[=:]?\s*(1|true|\$true))", re.I)
_RE_CFG_TAMPER = re.compile(
    r"(EventID[\"':= ]+5007\b|event\s*5007\b|"
    r"Set-MpPreference\s+[^;\n]*Disable(RealtimeMonitoring|Behavior"
    r"Monitoring|IOAVProtection|ScriptScanning|ArchiveMaxFileSize)|"
    r"Remove-MpPreference\s+[^;\n]*-Exclusion)", re.I)
_RE_EXCL_ADD = re.compile(
    r"Add-MpPreference\s+[^;\n]*-Exclusion(path|process|extension|IpAddress)",
    re.I)
_RE_AV_SUSPEND = re.compile(
    r"(PsSuspend|Suspend-Process)[^;\n]{0,40}(MsMpEng|NisSrv)|"
    r"Stop-Service\s+[^;\n]*(windefend|MsMpSvc)|"
    r"sc\s+config\s+(windefend|MsMpSvc)\s+start=\s*disabled", re.I)
_RE_SIG_REMOVED = re.compile(
    r"(Definition Updates|mpengine\.dll|mpasbase|mpavbase|mpsigstub)"
    r"[^;\n]{0,40}(delete|removed|removed|rmdir)|"
    r"Remove-Item\s+[^;\n]*(Definition Updates|mpengine|mpasbase)", re.I)
_RE_TAMPER_OFF = re.compile(
    r"(DisableTamperProtection\s*[=:]?\s*(1|true|\$true)|"
    r"DisableAntiSpyware\s*[=:]?\s*(1|true)|"
    r"DisableAntiVirus\s*[=:]?\s*(1|true))", re.I)

# kalimat normal yang TIDAK boleh dianggap sinyal (zero-FP)
_RE_BENIGN_RTP = re.compile(
    r"(Real-?[Tt]ime .{0,20}(enabled|running|active)\b|"
    r"signature (update|version) (succeeded|completed|ok)|"
    r"scan (completed|started)|EngineVersion)", re.I)


def audit_dump(text: str) -> dict | None:
    """Skor satu dump. None = bukan artefak Defender (tanpa konteks)."""
    if not _RE_DEFENDER_CTX.search(text):
        return None
    signals: list[str] = []
    evidence: dict[str, str] = {}

    if _RE_RTP_OFF.search(text) and not (
            _RE_BENIGN_RTP.search(text) and not _RE_RTP_OFF.pattern):
        pass  # pola disable spesifik sudah cukup presisi
    if re.search(r"(EventID[\"':= ]+5001\b|\b5001\b.{0,60}defender|"
                 r"defender.{0,60}\b5001\b)", text, re.I):
        signals.append("rtp-disabled")
        evidence["rtp_off_marker"] = "5001"
    elif _RE_RTP_OFF.search(text) and _RE_DEFENDER_CTX.search(text):
        # non-event teks yang eksplisit mematikan RTP
        if re.search(r"(disabled|off|false)", text, re.I) and not \
                _RE_BENIGN_RTP.search(text):
            signals.append("rtp-disabled")
    if _RE_CFG_TAMPER.search(text):
        signals.append("config-tamper")
        m = re.search(r"Set-MpPreference\s+[^;\n]{0,160}", text, re.I)
        if m:
            evidence["cmd"] = m.group(0)[:160]
    if _RE_EXCL_ADD.search(text):
        signals.append("exclusion-add")
        m = re.search(r"Add-MpPreference\s+[^;\n]{0,160}", text, re.I)
        if m:
            evidence["cmd"] = m.group(0)[:160]
    if _RE_AV_SUSPEND.search(text):
        signals.append("av-suspend")
        m = re.search(r"(PsSuspend|Stop-Service|sc config)[^\n]{0,120}",
                      text, re.I)
        if m:
            evidence["cmd"] = m.group(0)[:120]
    if _RE_SIG_REMOVED.search(text):
        signals.append("sig-store-removed")
    if _RE_TAMPER_OFF.search(text):
        signals.append("tamper-protect-off")
        m = re.search(r"(DisableTamperProtection\s*[=:]\s*\w+|"
                      r"DisableAnti(Spyware|Virus)\s*[=:]\s*\w+)", text, re.I)
        if m:
            evidence["registry"] = m.group(0)[:80]

    seen: set[str] = set()
    signals = [s2 for s2 in signals if not (s2 in seen or seen.add(s2))]

    return {"signals": signals, "score": len(signals), "evidence": evidence}


def triage_text(text: str) -> dict:
    res = audit_dump(text)
    if res is None:
        raise ValueError("dump tidak mengandung konteks Defender — "
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
        "findings": ([{"type": "defender-tamper", "severity": severity,
                       "signals": res["signals"],
                       "evidence": res["evidence"]}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "skor heuristik pola tampering AV — konfirmasi via host "
                "asli sebelum ditindak",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="dump event Defender / MPLog / teks perintah")
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
