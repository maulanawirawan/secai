r"""[SAFETY: read-only] script_assoc_audit — wave-6 audit OFFLINE artefak
asosiasi berkas Windows (ekspor .reg, output `reg query`, atau teks
perintah `assoc`/`ftype`/`reg add`) untuk mendeteksi handler script yang
diambil alih (referensi teknik "Prevent Script Execution via Double
Click" + pola assoc-hijack dari pustaka referensi; kode dibangun dari
nol, stdlib murni, tanpa jaringan).

Mekanisme: section-aware — file .reg dipecah per seksi `[HKEY_...]`
dan dump reg query per header `HKEY_...`. Ekstensi script yang diawasi:
.js .jse .vbs .vbe .wsf .wsh .hta .bat .cmd .scr .chm .ps1. Untuk tiap
`HKCR\<.ext>` dibaca ProgId (default value), lalu handler diambil dari
`HKCR\<ProgId>\shell\open\command` (atau `<.ext>\shell\open\command`
langsung). Handler stok dikenal dari allowlist per ekstensi (wscript/
cscript utk keluarga WS, mshta utk .hta, cmd "%1" %* utk .bat/.cmd,
hh.exe utk .chm, "%1" /S utk .scr, notepad/none utk .ps1).

Sinyal per file (semua deterministik dari data):
  - assoc-handler-override : handler ekstensi terawasi BEDA dari stok
    (termasuk .vbs->notepad: hardening ganda-diartikan, lihat note).
  - assoc-unexpected-binary: binary handler di luar allowlist global
    (wscript/cscript/mshta/cmd/notepad/hh/conhost/powershell/"%1").
  - assoc-external-path    : path handler di luar direktori \Windows\
    (mis. \Users\, \ProgramData\, \Temp\, UNC) — kandidat payload.
  - assoc-lolbin-handler   : handler LOLBIN klasik utk eksekusi proxy
    (rundll32/regsvr32/msiexec/installutil/csc, atau mshta pada
    ekstensi non-.hta).
  - assoc-mutation-command : perintah yang mengubah asosiasi (reg add
    /ve, ftype, assoc) pada ekstensi terawasi dgn nilai non-stok.
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info.
Ekspor HKCR lengkap yang SEMUA handler-nya stok -> 0 sinyal (clean,
zero-FP); asosiasi aplikasi non-script (\.myapp -> app.exe) TIDAK
dinilai.

Fail-closed: file tanpa konteks ekstensi terawasi sama sekali -> exit
2; file tidak ada -> exit 2. Temuan = LEAD (hardening sah "Prevent
Script Execution via Double Click" juga memakai notepad — caveat di
note).

Pemakaian:
  python tools/script_assoc_audit.py --file dump.reg --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.script-assoc-audit/1"

# ekstensi script/scriplet yang handler-nya menarik untuk di-hijack
WATCHED_EXTS = ("js", "jse", "vbs", "vbe", "wsf", "wsh", "hta",
                "bat", "cmd", "scr", "chm", "ps1")

# handler stok per keluarga ekstensi (basename, lowercase)
_STOCK = {
    "js": {"wscript.exe", "cscript.exe"},
    "jse": {"wscript.exe", "cscript.exe"},
    "vbs": {"wscript.exe", "cscript.exe"},
    "vbe": {"wscript.exe", "cscript.exe"},
    "wsf": {"wscript.exe", "cscript.exe"},
    "wsh": {"wscript.exe", "cscript.exe"},
    "hta": {"mshta.exe"},
    "bat": {"%1"},   # stock: "%1" %*  (dieksekusi langsung via cmd)
    "cmd": {"%1"},
    "scr": {"%1"},   # stock: "%1" /S
    "chm": {"hh.exe"},
    "ps1": {"notepad.exe", "none"},  # stok: tidak dieksekusi (notepad)
}
_GLOBAL_OK = {"wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe",
              "notepad.exe", "hh.exe", "conhost.exe", "powershell.exe"}
_LOLBIN = {"rundll32.exe", "regsvr32.exe", "msiexec.exe",
           "installutil.exe", "csc.exe"}

_RE_CTX = re.compile(
    r"HKEY_CLASSES_ROOT[\\/]\.(?:" + "|".join(WATCHED_EXTS) + r")\b"
    r"|HKCR[\\/]\.(?:" + "|".join(WATCHED_EXTS) + r")\b"
    r"|\bassoc\s+\.(?:" + "|".join(WATCHED_EXTS) + r")\b"
    r"|\bftype\s+\w*"
    r"|\b(?:VBSFile|JSFile|JSEFile|VBEFile|WSFFile|WSHFile|htafile|"
    r"cmdfile|batfile|scrfile|chm\.file)\b",
    re.I)
_RE_SECTION = re.compile(r"^\[([^\]]+)\]", re.M)
_RE_HKEY_LINE = re.compile(r"^\s*(HKEY_[^\r\n]+?)\s*$", re.M)
# .reg entry escape-aware: @="\"C:\\...\" \"%1\" %*" (nilai .reg memakai
# backslash-quote) — regex harus tidak berhenti di \" pertama.
_RE_REG_AT = re.compile(r'^@="((?:\\.|[^"])*)"', re.M)
_RE_REG_VALUE = re.compile(r'"(?:@|Default|)"?\s*=\s*"((?:\\.|[^"])*)"')
# reg query entry: (Default) REG_SZ JSFile
_RE_QUERY_VALUE = re.compile(
    r"^\s{2,}\((?:Default|default)\)\s+REG_SZ\s+(.+)$", re.M)
# ProgId -> ekstensi (fallback tanpa seksi <.ext>, format reg query)
_PROGID_MAP = {
    "jsfile": "js", "jsefile": "jse", "vbsfile": "vbs", "vbefile": "vbe",
    "wsffile": "wsf", "wshfile": "wsh", "htafile": "hta",
    "cmdfile": "cmd", "batfile": "bat", "scrfile": "scr",
    "chm.file": "chm",
}
_RE_EXTPATH = re.compile(r"\\\.(" + "|".join(WATCHED_EXTS) + r")$", re.I)
_RE_PROGID_CMD = re.compile(
    r"\\((?:[A-Za-z0-9_.\-]+))\\shell\\open\\command$", re.I)
_RE_EXT_CMD = re.compile(
    r"\\\.(?:" + "|".join(WATCHED_EXTS) + r")\\shell\\open\\command$",
    re.I)
_RE_MUTATION = re.compile(
    r"reg\s+add[^;\n]{0,200}\.(?:js|jse|vbs|vbe|wsf|wsh|hta|bat|cmd|scr|"
    r"chm|ps1)\b[^;\n]{0,160}|"
    r"\bftype\s+[A-Za-z0-9_.\-]+[^;\n]{0,160}|"
    r"\bassoc\s+\.(?:" + "|".join(WATCHED_EXTS) + r")\s*=", re.I)


def _sections(text: str) -> "list[tuple[str, str]]":
    """(path, body) per seksi [HKEY_...]; fallback reg query."""
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


def _value_of(body: str) -> str:
    """Default value dari body seksi .reg atau reg query (escape-aware:
    \\\\ -> \\ dan \\" -> ", sesuai format .reg)."""
    m = _RE_REG_AT.search(body)
    if m:
        return re.sub(r"\\(.)", r"\1", m.group(1))
    m = _RE_QUERY_VALUE.search(body)
    if m:
        return m.group(1).strip().strip('"')
    m = _RE_REG_VALUE.search(body)
    if m:
        return re.sub(r"\\(.)", r"\1", m.group(1))
    return ""


def _handler_bin(cmd: str) -> str:
    """Basename binary handler dari command string."""
    first = cmd.strip().strip('"').split('"')[0] if cmd else ""
    if not first:
        return ""
    if "%1" in first and not first.lower().endswith(".exe"):
        return "%1"
    base = Path(first.replace("/", "\\")).name.lower()
    return base


def _is_external(cmd: str) -> bool:
    low = cmd.lower()
    if low.startswith("\\\\"):
        return True
    if not re.search(r"[a-z]:\\|^\\\\", low):
        return False  # tanpa path absolut (mis. "%1" %*) — bukan path
    if re.search(r"[a-z]:\\windows\\", low):
        return False
    if re.search(r"[a-z]:\\(users|programdata|temp|appdata|perflogs|"
                 r"program files)", low):
        return True
    return True  # path absolut di luar \Windows\


def triage_text(text: str) -> dict:
    """Triase dump asosiasi -> dict hasil. Raise ValueError bila tanpa
    konteks ekstensi terawasi."""
    if not _RE_CTX.search(text):
        raise ValueError("dump tidak mengandung konteks asosiasi ekstensi "
                         "script terawasi — bukan artefak yang relevan")

    signals: "list[str]" = []
    evidence: dict[str, str] = {}
    checked: "list[str]" = []
    mutated = _RE_MUTATION.findall(text)

    # Kumpulkan handler per ekstensi: ProgId dari <.ext>, lalu command
    # dari <ProgId>\shell\open\command atau <.ext>\shell\open\command.
    handlers: "dict[str, str]" = {}
    progid_of: "dict[str, str]" = {}
    for path, body in _sections(text):
        p = path.replace("/", "\\")
        m_ext = _RE_EXTPATH.search(p)
        if m_ext:
            ext = m_ext.group(1).lower()
            val = _value_of(body)
            if val:
                progid_of[ext] = val
            continue
        m_extcmd = _RE_EXT_CMD.search(p)
        if m_extcmd:
            # path .ext\shell\open\command — cari ekstensi asal
            low = p.lower()
            for e in WATCHED_EXTS:
                if low.endswith("\\." + e + "\\shell\\open\\command"):
                    cmd = _value_of(body)
                    if cmd:
                        handlers.setdefault(e, cmd)
                    break
            continue
        m_pid = _RE_PROGID_CMD.search(p)
        if m_pid:
            pid = m_pid.group(1).lower()
            exts = [e for e, v in progid_of.items() if v.lower() == pid]
            if not exts and pid in _PROGID_MAP:
                exts = [_PROGID_MAP[pid]]
            for e in exts:
                cmd = _value_of(body)
                if cmd:
                    handlers.setdefault(e, cmd)
                break

    # command text: ftype X="..." / assoc .js=Y (fallback tanpa seksi)
    for m in re.finditer(r"\bftype\s+([A-Za-z0-9_.\-]+)\s*=\s*(.+)",
                         text, re.I):
        pass  # nilai ftype tanpa pemetaan ext->progid tidak dinilai

    for ext in WATCHED_EXTS:
        cmd = handlers.get(ext)
        if not cmd:
            continue
        checked.append(ext)
        binname = _handler_bin(cmd)
        stock = _STOCK[ext]
        if binname not in stock:
            signals.append("assoc-handler-override")
            evidence["override"] = f".{ext} -> {cmd[:120]}"
        if binname and binname != "%1" and binname not in _GLOBAL_OK:
            signals.append("assoc-unexpected-binary")
            evidence["unexpected-bin"] = f".{ext} -> {binname}"
        if binname in _LOLBIN and not (ext == "hta" and
                                       binname == "mshta.exe"):
            signals.append("assoc-lolbin-handler")
            evidence["lolbin"] = f".{ext} -> {binname}"
        if binname not in ("", "%1") and _is_external(cmd):
            signals.append("assoc-external-path")
            evidence["external-path"] = f".{ext} -> {cmd[:140]}"

    if mutated:
        # perintah mutasi dgn nilai non-stok pada ekstensi terawasi
        interesting = [x for x in mutated
                       if re.search(r"\.(js|jse|vbs|vbe|wsf|wsh|hta|bat|"
                                    r"cmd|scr|chm|ps1)\b", x, re.I)
                       or re.search(r"\bassoc\b", x, re.I)]
        if interesting:
            signals.append("assoc-mutation-command")
            evidence["mutation"] = interesting[0][:140]

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
        "checked_exts": checked,
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "script-assoc-hijack", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "handler notepad pada ekstensi script juga hardening sah "
                "(\"Prevent Script Execution via Double Click\") — "
                "konfirmasi pemilik host; override handler utk .hta/.chm "
                "yang jarang dipakai sering jadi jalur persistensi",
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
