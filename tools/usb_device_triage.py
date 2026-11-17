r"""[SAFETY: read-only] usb_device_triage — wave-7 inventaris OFFLINE
perangkat USB dari artefak host: ekspor registry USBSTOR / Enum\USB
(.reg atau dump reg query) dan/atau log setupapi.dev.log (pola DFIR
inventori removable storage; parser dibangun dari nol, stdlib murni,
tanpa jaringan).

Sumber artefak:
  - [HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\<dev>\<serial>\...]
    dgn nilai FriendlyName; section-aware per HKEY_.
  - setupapi.dev.log: blok "Device Install (Hardware initiated)" /
    "Device Install (DiInstallDriver)" yang menyebut usb\vid_...&pid_...

Sinyal per artefak (semua deterministik dari data):
  - usbstor-entry      : >= 1 entri USBSTOR — ada riwayat removable
                         storage (inventori, low).
  - usb-friendlyname   : FriendlyName ter-parse (evidence, low).
  - setupapi-usb-install: blok install USB di setupapi (inventori,
                         low) — dgn tanggal ter-parse bila ada.
  - usb-install-recent : entri install USB dalam --days terakhir
                         (default 30; acuan --now, default hari ini)
                         — lead penggunaan terkini.
  - usb-serial-many    : >= --many serial unik (default 8) — frekuensi
                         tukar-cabut tinggi (lead).
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info.
Dump registry tanpa USB sama sekali -> exit 2 (fail-closed), sehingga
host tanpa riwayat USB TIDAK dilaporkan "bersih palsu".

Fail-closed: artefak tanpa konteks USB (USBSTOR / usb\vid_ / setupapi
Device Install) sama sekali -> exit 2; file tidak ada -> exit 2.
Temuan = LEAD (penggunaan USB bisa kebijakan sah).

Pemakaian:
  python tools/usb_device_triage.py --file usbstor.reg --out hasil.json
  python tools/usb_device_triage.py --file setupapi.dev.log --now 2026-11-18
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.usb-device-triage/1"

_RE_SECTION = re.compile(r"^\[([^\]]+)\]", re.M)
_RE_HKEY_LINE = re.compile(r"^\s*(HKEY_[^\r\n]+?)\s*$", re.M)
_RE_USBSTOR_PATH = re.compile(r"USBSTOR[\\/]", re.I)
_RE_REG_SZ = re.compile(r'"FriendlyName"\s*=\s*"((?:\\.|[^"])*)"', re.M)
_RE_QUERY_SZ = re.compile(
    r"^\s{2,}FriendlyName\s+REG_SZ\s+(.+)$", re.M | re.I)
_RE_USBVID = re.compile(r"usb\\vid_([0-9a-f]{4})&pid_([0-9a-f]{4})\\?([^\\\s]*)",
                        re.I)
_RE_INSTALL_BLOCK = re.compile(
    r"Device Install (?:\(Hardware initiated\)|\(DiInstallDriver\))"
    r"(.{0,800}?)(?=Device Install|\Z)", re.S | re.I)
_RE_DATE = re.compile(
    r"\b(\d{4})[-/](\d{2})[-/](\d{2})\b|\b(\d{1,2})/(\d{1,2})/(\d{4})\b")


def _sections(text: str) -> "list[tuple[str, str]]":
    out: "list[tuple[str, str]]" = []
    heads = list(_RE_SECTION.finditer(text))
    if heads:
        for i, m in enumerate(heads):
            end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
            out.append((m.group(1), text[m.end():end]))
        return out
    qheads = list(_RE_HKEY_LINE.finditer(text))
    for i, m in enumerate(qheads):
        end = qheads[i + 1].start() if i + 1 < len(heads) else len(text)
        out.append((m.group(1), text[m.end():end]))
    return out


def _parse_dates(chunk: str) -> "list[datetime.date]":
    out: "list[datetime.date]" = []
    for m in _RE_DATE.finditer(chunk):
        try:
            if m.group(1):
                out.append(datetime.date(int(m.group(1)), int(m.group(2)),
                                         int(m.group(3))))
            else:
                out.append(datetime.date(int(m.group(6)), int(m.group(4)),
                                         int(m.group(5))))
        except ValueError:
            continue
    return out


def triage_text(text: str, *, now: "datetime.date | None" = None,
                days: int = 30, many: int = 8) -> dict:
    """Triase artefak USB -> dict hasil. Raise ValueError bila tanpa
    konteks USB."""
    has_usbstor = _RE_USBSTOR_PATH.search(text)
    has_vid = _RE_USBVID.search(text)
    if not (has_usbstor or has_vid):
        raise ValueError("artefak tidak mengandung konteks USB (USBSTOR/"
                         "usb\\vid_) — bukan target triase ini")

    signals: "list[str]" = []
    evidence: dict[str, str] = {}

    serials: "list[str]" = []
    friendly: "list[str]" = []
    for path, body in _sections(text):
        p = path.replace("/", "\\")
        if not _RE_USBSTOR_PATH.search(p):
            continue
        # serial = komponen terakhir path USBSTOR yang mengandung & atau
        # bentuk serial (bukan kunci nilai)
        parts = [x for x in p.split("\\") if x]
        if parts and parts[-1] not in ("Control", "Properties"):
            s = parts[-1]
            if s not in serials:
                serials.append(s)
        m = _RE_REG_SZ.search(body) or _RE_QUERY_SZ.search(body)
        if m:
            friendly.append(m.group(1).strip() if m.lastindex and
                            m.group(1) else (m.group(1) or "").strip())

    setup_serials: "list[str]" = []
    install_dates: "list[datetime.date]" = []
    if not heads_present(text) or has_vid:
        for m in _RE_INSTALL_BLOCK.finditer(text):
            chunk = m.group(0)
            for vm in _RE_USBVID.finditer(chunk):
                sid = vm.group(0)
                if sid not in setup_serials:
                    setup_serials.append(sid)
            install_dates.extend(_parse_dates(chunk))

    all_serials = [s for s in serials + setup_serials if s]

    if serials:
        signals.append("usbstor-entry")
        evidence["usbstor-serials"] = "; ".join(serials[:6])[:220]
    if friendly:
        signals.append("usb-friendlyname")
        evidence["friendly-names"] = "; ".join(friendly[:6])[:220]
    if setup_serials:
        signals.append("setupapi-usb-install")
        evidence["setupapi-vids"] = "; ".join(setup_serials[:6])[:220]

    now = now or datetime.date.today()
    if install_dates:
        recent = [d for d in install_dates
                  if (now - d).days <= days and (now - d).days >= 0]
        if recent:
            signals.append("usb-install-recent")
            evidence["recent-count"] = str(len(recent))
            evidence["recent-dates"] = ", ".join(
                d.isoformat() for d in sorted(recent)[:8])

    if len(all_serials) >= many:
        signals.append("usb-serial-many")
        evidence["serial-count"] = str(len(all_serials))

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
        "serials": all_serials[:40],
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "usb-inventory", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "penggunaan USB bisa kebijakan sah — nilai utama tool "
                "adalah inventori perangkat utk investigasi exfil/"
                "baselining; tanggal install bergantung akurasi log",
        "read_only": True,
    }


def heads_present(text: str) -> bool:
    return bool(_RE_SECTION.search(text) or _RE_HKEY_LINE.search(text))


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help=".reg USBSTOR / dump reg query / setupapi.dev.log")
    ap.add_argument("--now", help="tanggal acuan ISO YYYY-MM-DD "
                                  "(default: hari ini)")
    ap.add_argument("--days", type=int, default=30,
                    help="ambang usb-install-recent (default 30)")
    ap.add_argument("--many", type=int, default=8,
                    help="ambang usb-serial-many (default 8)")
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
            now = datetime.date.fromisoformat(args.now)
        except ValueError:
            print(f"ERROR: --now bukan format YYYY-MM-DD: {args.now}",
                  file=sys.stderr)
            return 2
    try:
        result = triage_text(text, now=now, days=args.days, many=args.many)
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
