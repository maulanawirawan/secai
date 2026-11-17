r"""[SAFETY: read-only] dom_sink_scan — wave-8 triase OFFLINE artefak
JS/HTML terhadap pola DOM-XSS (sisi klien — sumber yang tak terlihat
server: URL fragment, postMessage lintas-window; pola lintas kasus
dilaporkan publik di bug bounty). Parser statik konjunktif dari nol,
stdlib murni, tanpa jaringan. Melengkapi kelas reflected-XSS (dugaan
server) — kelas ini justru lolos filter server/WAF karena payload tak
pernah dikirim.

Sinyal per artefak (semua deterministik dari data):
  - postmessage-no-origin : handler `addEventListener("message"...)`/
    `onmessage=` yang memakai event.data menuju sink (innerHTML/
    outerHTML/document.write/eval/script-src/location) TANPA validasi
    event.origin di blok handler — kelas modern dominan.
  - postmessage-origin-weak: handler validasi event.origin tapi dgn
    pola bypassable (indexOf/endsWith/search tanpa anchor) — lead.
  - url-source-to-sink    : data dari location.search/hash/href/
    URLSearchParams(document.location) mengalir ke sink tanpa
    encoding di dekat aliran (window dalam satu blok).
  - sink-gated-only       : sink berbahaya (eval/innerHTML) hadir dengan
    sumber yang jelas TAPI taint tak bisa dipastikan statik — inventori
    (low, tak berdiri).
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info.
JS tanpa handler message/sink berbahaya -> exit 2 (bukan target);
handler dgn validasi origin ketat (=== / != comparison ke literal /
allowlist includes) + tanpa sumber URL -> 0 sinyal (zero-FP).

Fail-closed: artefak tanpa konteks (tidak ada sink berbahaya maupun
addEventListener/onmessage) -> exit 2; file tidak ada -> exit 2.
Temuan = LEAD — taint statik tak menggantikan konfirmasi runtime di
browser (lab/berizin).

Pemakaian:
  python tools/dom_sink_scan.py --file app.js --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.dom-sink-scan/1"

_RE_CTX = re.compile(
    r"addEventListener\s*\(\s*[\"']message[\"']|onmessage\s*=|"
    r"innerHTML|outerHTML|document\.write|\beval\s*\(|\.srcdoc|"
    r"location\.hash|location\.search|URLSearchParams", re.I)
_RE_MSG_HANDLER = re.compile(
    r"(addEventListener\s*\(\s*[\"']message[\"']|"
    r"onmessage\s*=\s*(?:function|\()|\bonmessage\s*=\s*\w+)", re.I)
_RE_EVENT_DATA = re.compile(
    r"event\.data|ev\.data|msg\.data|message\.data|e\.data")
_RE_ORIGIN_STRICT = re.compile(
    r"(?:event|ev|e|msg|message)\.origin\s*(?:===|!==|==|!=)\s*|"
    r"\.origin\s*(?:===|!==|==|!=)|"
    r"ORIGIN(?:_)?ALLOWLIST|allowed[_-]?origins?", re.I)
_RE_ORIGIN_WEAK = re.compile(
    r"\.origin[^;\n]{0,80}(?:indexOf|endsWith|startsWith|search\(|match\()"
    r"|indexOf\([^)]*\.origin", re.I)
_RE_SINK = re.compile(
    r"innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|\beval\s*\(|"
    r"\.srcdoc\s*=|insertAdjacentHTML\s*\(|\$\([^)]*\)\.html\s*\(|"
    r"location\s*=\s*|location\.href\s*=|\.src\s*=\s*[\"'][^\"']*script",
    re.I)
_RE_URL_SOURCE = re.compile(
    r"location\.hash|location\.search|location\.href|"
    r"URLSearchParams\s*\(\s*(?:document\.)?location|window\.name|"
    r"document\.referrer|\.getAttribute\s*\(\s*[\"']href[\"']", re.I)
_RE_DECODE = re.compile(
    r"decodeURI(?:Component)?\s*\(|atob\s*\(|fromCharCode|unescape\s*\(")

_BLOK_LINES = 40  # jendela baris handler utk cek origin di dekat sumber


def _handler_blocks(text: str) -> "list[tuple[int, str]]":
    """(line_no, blok teks handler) — jendela N baris setelah awal
    handler (statik, best-effort; bukan parse AST)."""
    out: "list[tuple[int, str]]" = []
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if _RE_MSG_HANDLER.search(ln):
            blok = "\n".join(lines[i:i + _BLOK_LINES])
            out.append((i + 1, blok))
    return out


def _has_sink(blok: str) -> bool:
    return bool(_RE_SINK.search(blok))


def triage_text(text: str) -> dict:
    """Triase JS/HTML -> dict hasil. Raise ValueError bila tanpa
    konteks."""
    if not _RE_CTX.search(text):
        raise ValueError("artefak tidak mengandung sink DOM/handler "
                         "message — bukan target triase ini")

    signals: "list[str]" = []
    evidence: dict[str, str] = {}

    handlers = _handler_blocks(text)
    no_origin = 0
    weak_origin = 0
    strict_origin = 0
    for line_no, blok in handlers:
        uses_data = bool(_RE_EVENT_DATA.search(blok))
        if not uses_data:
            continue
        if not _has_sink(blok) and not _RE_URL_SOURCE.search(blok):
            continue
        weak = bool(_RE_ORIGIN_WEAK.search(blok))
        strict = bool(_RE_ORIGIN_STRICT.search(blok))
        if weak:
            # validasi ada tapi bypassable (indexOf/endsWith/...) — lead
            weak_origin += 1
            evidence.setdefault(
                "weak-origin",
                "line %d: %s" % (line_no, blok.strip().splitlines()[0])[:160])
            continue
        if strict:
            strict_origin += 1
            continue
        if _RE_SINK.search(blok):
            no_origin += 1
            evidence.setdefault(
                "no-origin-handler",
                "line %d: %s" % (line_no, blok.strip().splitlines()[0])[:160])

    if no_origin:
        signals.append("postmessage-no-origin")
    if weak_origin:
        signals.append("postmessage-origin-weak")

    # aliran sumber URL -> sink (jendela baris: sumber lalu sink <= 25
    # baris di kemudian, blok script sama — approximasi statik)
    lines = text.splitlines()
    src_lines = [(i, ln) for i, ln in enumerate(lines)
                 if _RE_URL_SOURCE.search(ln)]
    url_flow = False
    for i, _ln in src_lines:
        window = "\n".join(lines[i:i + 25])
        if _RE_SINK.search(window):
            url_flow = True
            break
    if url_flow:
        signals.append("url-source-to-sink")
        evidence.setdefault("url-flow", src_lines[0][1].strip()[:120])

    decoded_flow = bool(_RE_DECODE.search(text)) and (
        url_flow or bool(_RE_EVENT_DATA.search(text)))
    if decoded_flow and not (no_origin or weak_origin or url_flow):
        signals.append("sink-gated-only")

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
        "handler_count": len(handlers),
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "dom-xss-pattern", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "statik heuristik — taint tak menggantikan konfirmasi "
                "runtime; validasi origin ketat (===/allowlist) dan "
                "encoding di sink dianggap mitigasi (zero-FP)",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="artefak JS/HTML bundle (read-only)")
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
