r"""[SAFETY: read-only] lnk_triage — wave-5+7 triase OFFLINE file .lnk
(Windows Shell Link) terhadap pola penyalahgunaan shortcut:
target lolbin/scripting, argumen interpreter/encoded cradle, icon UNC
(ikon dirender -> kredensial SMB bocor ke host jauh), dan target di
share jaringan (pola penyamaran shortcut klasik; format di-parse dari
nol per MS-SHLLINK, stdlib murni).

Enrichment (wave-7): TrackerDataBlock (signature 0xA0000003) di-parse —
MachineID NetBIOS + droid GUID pembuat shortcut bocor dari mesin asal.
Ini EVIDENCE IR, bukan sinyal penyalahgunaan (Explorer normal membuatnya)
— field tracker_machine/tracker_droid di output, skor tidak berubah.

Sinyal per file (semua deterministik dari data):
  - lolbin-target   : target/base path shortcut adalah interpreter/
                      lolbin (cmd, powershell, mshta, wscript, cscript,
                      rundll32, regsvr32, msiexec, certutil, bitsadmin,
                      wmic) — shortcut yang menjalankan interpreter.
  - args-lolbin     : command line arguments memuat interpreter/lolbin
                      atau cradle unduhan (DownloadString/Invoke-
                      Expression/IEX/FromBase64String/WinHttp).
  - encoded-args    : argumen memuat pola encoded (-enc/-e jGS/-nop
                      -w hidden/-W Hidden/[System.Convert]) — payload
                      tersembunyi di argumen.
  - icon-unc        : IconLocation di share UNC (\\host\share\...) —
                      ikon dirender saat Explorer membuka folder ->
                      NetNTLM kredensial terkirim; teknik penyalahgunaan
                      shortcut klasik.
  - target-unc      : base path target di share UNC (lateral/exec dari
                      share).
  - icon-disguise   : icon location meminjam biner tampak-benar
                      (mspaint/notepad/calc/explorer) PADAHAL ada sinyal
                      lolbin/encoded lain — pola penyamaran ikon.
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info (shortcut
normal: firefox.exe tanpa argumen, icon lokal — TIDAK dihitung;
zero-FP).

Fail-closed: file bukan LNK valid (header/CLSID salah) -> exit 2;
file tidak ada -> exit 2. Temuan = LEAD untuk review manual.

Pemakaian:
  python tools/lnk_triage.py --file payload.lnk --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

SCHEMA = "secai.lnk-triage/1"

HEADER_SIZE = 0x4C
LINK_CLSID = bytes.fromhex("0114020000000000C000000000000046")

FLAG_IDLIST = 0x01
FLAG_LINKINFO = 0x02
FLAG_HAS_NAME = 0x04
FLAG_HAS_REL_PATH = 0x08
FLAG_HAS_WORKDIR = 0x10
FLAG_HAS_ARGS = 0x20
FLAG_HAS_ICON = 0x40
FLAG_UNICODE = 0x80

TRACKER_SIG = 0xA0000003

_RE_LOLBIN = re.compile(
    r"(cmd(?:\.exe)?\b|powershell|pwsh\b|mshta\b|wscript|cscript|rundll32|"
    r"regsvr32|msiexec|certutil|bitsadmin|wmic\b)", re.I)
_RE_CRADLE = re.compile(
    r"(DownloadString|Invoke-Expression|\bIEX\b|FromBase64String|"
    r"WinHttp|Net\.WebClient|http[s]?://[^\s\"']{6,})", re.I)
_RE_ENCODED = re.compile(
    r"(-enc(odedcommand)?\b|[A-Za-z0-9+/]{40,}|-nop\b|-NonI\b|"
    r"-w\s+hidden\b|\[System\.Convert\])", re.I)
_RE_DISGUISE = re.compile(
    r"(mspaint|notepad|calc|explorer|svchost|taskhost)", re.I)

LOLBIN_NAMES = {
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "mshta", "mshta.exe", "wscript", "wscript.exe", "cscript",
    "cscript.exe", "rundll32", "rundll32.exe", "regsvr32", "regsvr32.exe",
    "msiexec", "msiexec.exe", "certutil", "certutil.exe", "bitsadmin",
    "bitsadmin.exe", "wmic", "wmic.exe",
}


def _read_string(data: bytes, off: int, unicode_: bool) -> "tuple[str, int] | None":
    """Baca StringData: u16 count + karakter. None = struktur rusak."""
    if off + 2 > len(data):
        return None
    (count,) = struct.unpack_from("<H", data, off)
    off += 2
    nbytes = count * (2 if unicode_ else 1)
    if count > 0 and (off + nbytes > len(data) or count > 4096):
        return None
    raw = data[off:off + nbytes]
    off += nbytes
    if unicode_:
        return raw.decode("utf-16-le", errors="replace"), off
    return raw.decode("latin-1"), off


def parse_lnk(data: bytes) -> dict:
    """Parse Shell Link (MS-SHLLINK) -> field relevan.

    Raise ValueError bila bukan LNK valid (fail-closed)."""
    if len(data) < 76:
        raise ValueError("terlalu pendek untuk header Shell Link (76 byte)")
    (hsize,) = struct.unpack_from("<I", data, 0)
    if hsize != HEADER_SIZE:
        raise ValueError(f"HeaderSize bukan 0x4C: {hsize:#x}")
    if data[4:20] != LINK_CLSID:
        raise ValueError("LinkCLSID bukan Shell Link GUID")
    (flags,) = struct.unpack_from("<I", data, 0x14)
    (attr,) = struct.unpack_from("<I", data, 0x18)

    off = HEADER_SIZE
    if flags & FLAG_IDLIST:
        if off + 2 > len(data):
            raise ValueError("IDList terpotong")
        (idlist_size,) = struct.unpack_from("<H", data, off)
        off += 2 + idlist_size
        if off > len(data):
            raise ValueError("IDList size melebihi file")
    if flags & FLAG_LINKINFO:
        if off + 4 > len(data):
            raise ValueError("LinkInfo terpotong")
        (li_size,) = struct.unpack_from("<I", data, off)
        li_size &= 0xFFFFFF  # 24-bit per spec; bit tinggi dipakai beberapa writer
        off += 4 + max(li_size - 4, 0)
        if off > len(data):
            raise ValueError("LinkInfo size melebihi file")
    strings: dict[str, str] = {}
    unicode_ = bool(flags & FLAG_UNICODE)
    for flag, key in ((FLAG_HAS_NAME, "name"), (FLAG_HAS_REL_PATH, "relpath"),
                      (FLAG_HAS_WORKDIR, "workdir"), (FLAG_HAS_ARGS, "args"),
                      (FLAG_HAS_ICON, "icon")):
        if flags & flag:
            got = _read_string(data, off, unicode_)
            if got is None:
                raise ValueError(f"StringData '{key}' terpotong")
            strings[key], off = got

    tracker = _parse_tracker(data, off)
    return {"flags": flags, "attr": attr, **strings, **tracker}


def _parse_tracker(data: bytes, off: int) -> dict:
    """Jalan ExtraDataBlock best-effort: cari TrackerDataBlock
    (signature 0xA0000003) — MachineID (NetBIOS, 16 byte) + droid
    GUIDs bocor dari mesin asal pembuat shortcut. Bukan sinyal
    penyalahgunaan (blok ini normal dibuat Explorer) — enrichment
    evidence IR. Block malformed/truncated -> diabaikan aman."""
    machine = ""
    droid = ""
    while off + 8 <= len(data):
        (bsize,) = struct.unpack_from("<I", data, off)
        if bsize < 4 or off + bsize > len(data):
            break  # truncated/malformed — stop (best-effort)
        (sig,) = struct.unpack_from("<I", data, off + 4)
        if sig == TRACKER_SIG and bsize >= 0x3C:
            raw = data[off + 12:off + 12 + 16]
            machine = raw.split(b"\x00")[0].decode("ascii",
                                                   errors="replace").strip()
            droid = data[off + 28:off + 28 + 32].hex()
            break
        if bsize == 4:
            break  # TerminusBlock
        off += bsize
    out: dict[str, str] = {}
    if machine:
        out["tracker_machine"] = machine
    if droid:
        out["tracker_droid"] = droid
    return out


def triage_bytes(data: bytes) -> dict:
    lnk = parse_lnk(data)
    signals: "list[str]" = []
    evidence: dict[str, str] = {}

    target = (lnk.get("name") or lnk.get("relpath") or "").strip()
    args = (lnk.get("args") or "").strip()
    icon = (lnk.get("icon") or "").strip()
    relpath = (lnk.get("relpath") or "").strip()

    enc_m = _RE_ENCODED.search(args)
    if enc_m:
        signals.append("encoded-args")
        evidence["encoded"] = enc_m.group(0)[:80]
    interp_m = _RE_LOLBIN.search(args) or _RE_CRADLE.search(args)
    if interp_m:
        signals.append("args-lolbin")
        evidence["args-interpreter"] = interp_m.group(0)[:80]

    # target: nama executable pertama pada name/relpath
    tgt = relpath or target
    tgt_name = tgt.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].strip().lower()
    if tgt_name in LOLBIN_NAMES:
        signals.append("lolbin-target")
        evidence["target"] = tgt[:120]

    if icon.startswith("\\\\"):
        signals.append("icon-unc")
        evidence["icon"] = icon[:120]
    if tgt.startswith("\\\\"):
        signals.append("target-unc")
        evidence["target-unc"] = tgt[:120]
    if (_RE_DISGUISE.search(icon) and
            ({"args-lolbin", "encoded-args", "lolbin-target"} & set(signals))):
        signals.append("icon-disguise")
        evidence["icon-disguise"] = icon[:120]

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
        "fields": {k: v[:160] for k, v in lnk.items()
                   if k in ("name", "relpath", "workdir", "args", "icon",
                            "tracker_machine", "tracker_droid")},
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "lnk-abuse", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "triase heuristik penyalahgunaan shortcut — konfirmasi "
                "target dan host ikon sebelum ditindak",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True, help="file .lnk untuk ditriase")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    data = path.read_bytes()
    try:
        result = triage_bytes(data)
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
