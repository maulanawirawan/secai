r"""[SAFETY: read-only] systeminfo_triage — wave-7 triase OFFLINE output
`systeminfo` Windows: kelas host, platform VM, kepadatan patch
(hotfix), dan uptime (pola enumerasi privesc standar; parser dibangun
dari nol, stdlib murni, tanpa jaringan).

Sinyal per artefak (semua deterministik dari data):
  - sys-is-dc        : OS Configuration menyebut Domain Controller
                       (Primary/Backup) — host kelas tinggi.
  - sys-vm-platform  : System Manufacturer/Model cocok daftar platform
                       VM (VMware/VirtualBox/KVM/QEMU/Xen/Hyper-V/
                       Bochs/Parallels/Anolis/Virtual Machine).
  - sys-hotfix-absent: section Hotfix(s) melaporkan 0 patch (atau
                       section tidak ada pada output penuh) — permukaan
                       patch sangat tipis (lead privesc klasik).
  - sys-hotfix-thin  : jumlah hotfix <= --min-hotfix (default 3).
  - sys-uptime-long  : System Boot Time lebih lama dari
                       --max-uptime-days (default 30) dihitung dari
                       --now (default: hari ini) — tidak reboot sejak
                       tanggal itu.
  - sys-domain-joined: Domain bukan WORKGROUP (konteks, low).
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info.
Systeminfo stok (workgroup, hotfix cukup, boot baru, hardware fisik)
-> 0 sinyal (zero-FP).

Fail-closed: teks tanpa field kunci systeminfo (Host Name + OS Name/
Hotfix) sama sekali -> exit 2; file tidak ada -> exit 2.
Temuan = LEAD (VM/uptime/patch-tipis bisa sah — lab, embedded, host
terisolasi).

Pemakaian:
  python tools/systeminfo_triage.py --file sysinfo.txt --out hasil.json
  python tools/systeminfo_triage.py --file sysinfo.txt --now 2026-11-18
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.systeminfo-triage/1"

_RE_VM = re.compile(
    r"VMware|VirtualBox|KVM|QEMU|Xen|Hyper-V|Bochs|Parallels|Anolis|"
    r"Virtual Machine", re.I)

_RE_FIELDS = {
    "hostname": re.compile(r"^Host Name:\s*(.+)$", re.M),
    "os_name": re.compile(r"^OS Name:\s*(.+)$", re.M),
    "os_version": re.compile(r"^OS Version:\s*(.+)$", re.M),
    "os_config": re.compile(r"^OS Configuration:\s*(.+)$", re.M),
    "sys_manufacturer": re.compile(r"^System Manufacturer:\s*(.+)$", re.M),
    "sys_model": re.compile(r"^System Model:\s*(.+)$", re.M),
    "domain": re.compile(r"^Domain:\s*(.+)$", re.M),
    "boot_time": re.compile(r"^System Boot Time:\s*(.+)$", re.M),
}
_RE_HOTFIX_COUNT = re.compile(r"^Hotfix\(s\):\s*(\d+)\s+Hotfix", re.M)
_RE_HOTFIX_LIST = re.compile(r"^\[(\d+)\]:\s*(KB\d+)", re.M)
_RE_HOTFIX_HEADER = re.compile(r"Hotfix", re.I)


def _parse_boot(text: str) -> "datetime.datetime | None":
    raw = _RE_FIELDS["boot_time"]
    m = raw.search(text)
    if not m:
        return None
    val = m.group(1).strip()
    for fmt in ("%d/%m/%Y, %H:%M:%S", "%m/%d/%Y, %H:%M:%S",
                "%Y-%m-%d, %H:%M:%S", "%d/%m/%Y %H:%M:%S",
                "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.datetime.strptime(val, fmt)
        except ValueError:
            continue
    return None


def triage_text(text: str, *, now: "datetime.datetime | None" = None,
                min_hotfix: int = 3, max_uptime_days: int = 30) -> dict:
    """Triase output systeminfo -> dict hasil. Raise ValueError bila
    tanpa konteks."""
    has_host = bool(_RE_FIELDS["hostname"].search(text))
    has_os = bool(_RE_FIELDS["os_name"].search(text) or
                  _RE_FIELDS["os_version"].search(text))
    if not (has_host and (has_os or _RE_HOTFIX_HEADER.search(text))):
        raise ValueError("teks tidak mengandung field systeminfo kunci "
                         "(Host Name + OS/Hotfix)")

    signals: "list[str]" = []
    evidence: dict[str, str] = {}
    fields: dict[str, str] = {}
    for k, rx in _RE_FIELDS.items():
        m = rx.search(text)
        if m:
            fields[k] = m.group(1).strip()

    os_config = fields.get("os_config", "")
    if "Domain Controller" in os_config:
        signals.append("sys-is-dc")
        evidence["os-config"] = os_config[:120]

    hw = " ".join([fields.get("sys_manufacturer", ""),
                   fields.get("sys_model", "")])
    vm = _RE_VM.search(hw)
    if vm:
        signals.append("sys-vm-platform")
        evidence["vm-marker"] = vm.group(0)

    m = _RE_HOTFIX_COUNT.search(text)
    kb_list = _RE_HOTFIX_LIST.findall(text)
    if m:
        n = int(m.group(1))
        if n == 0:
            signals.append("sys-hotfix-absent")
            evidence["hotfix-count"] = "0"
        elif n <= min_hotfix:
            signals.append("sys-hotfix-thin")
            evidence["hotfix-count"] = str(n)
        if kb_list:
            evidence["hotfix-list"] = ", ".join(k[1] for k in kb_list[:12])
    elif has_host and has_os and "Hotfix" not in text:
        signals.append("sys-hotfix-absent")
        evidence["hotfix-count"] = "section tidak ada"

    if fields.get("domain", "") and "WORKGROUP" not in fields["domain"]:
        signals.append("sys-domain-joined")
        evidence["domain"] = fields["domain"][:80]

    boot = _parse_boot(text)
    now = now or datetime.datetime.now()
    if boot:
        age_days = (now - boot).total_seconds() / 86400.0
        fields["boot_age_days"] = str(int(max(age_days, 0)))
        if age_days > max_uptime_days:
            signals.append("sys-uptime-long")
            evidence["boot-time"] = boot.isoformat(sep=" ")
            evidence["uptime-days"] = str(int(age_days))

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
        "fields": fields,
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "host-posture", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "VM/uptime-panjang/patch-tipis bisa sah (lab, embedded, "
                "host terisolasi) — konfirmasi pemilik host; angka "
                "hotfix rendah di Windows segar juga normal",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True, help="output systeminfo")
    ap.add_argument("--now", help="tanggal acuan ISO utk uptime "
                                  "(default: sekarang)")
    ap.add_argument("--min-hotfix", type=int, default=3,
                    help="ambang sys-hotfix-thin (default 3)")
    ap.add_argument("--max-uptime-days", type=int, default=30,
                    help="ambang sys-uptime-long hari (default 30)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    now = None
    if args.now:
        try:
            now = datetime.datetime.strptime(args.now, "%Y-%m-%d")
        except ValueError:
            print(f"ERROR: --now bukan format YYYY-MM-DD: {args.now}",
                  file=sys.stderr)
            return 2
    try:
        result = triage_text(text, now=now, min_hotfix=args.min_hotfix,
                             max_uptime_days=args.max_uptime_days)
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
