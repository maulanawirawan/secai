r"""[SAFETY: read-only] translate_proxy_triage — wave-7 triase OFFLINE
daftar URL / log web / lampiran email terhadap pola phishing via
proxy-terjemahan (teknik menyembunyikan host jahat di balik domain
translation service yang dipercaya; parser dibangun dari nol, stdlib
murni, tanpa jaringan).

Pola yang didukung:
  - host proxy : <target-hyphenated>.translate.goog dengan parameter
                 _x_tr_sl/_x_tr_tl/_x_tr_hl (isi asli dilayani dari
                 target yang di-encode ke hostname).
  - redirect lama: translate.google.com/translate?...&u=<url> atau
                 /translate_a/...?u=<url> — wrapper open-redirect.

Sinyal per artefak (semua deterministik dari data):
  - translate-proxy-host   : URL dgn host *.translate.goog — konten
                             asli disajikan lewat domain dipercaya.
  - translate-target-host  : target asli yang di-encode di hostname
                             proxy ter-parse (dipasangkan dgn sinyal
                             proxy — evidence tambahan, tidak berdiri).
  - translate-redirect-param: URL translate.google.com dgn parameter
                             u=<url> — wrapper redirect.
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info. URL
translate.google.com polos (tanpa u=) -> 0 sinyal (zero-FP).

Fail-closed: artefak tanpa URL ter-translation-service sama sekali ->
exit 2; file tidak ada -> exit 2. Temuan = LEAD (proxy sah dipakai
pembaca lintas-bahasa — periksa target asli sebelum ditindak).

Pemakaian:
  python tools/translate_proxy_triage.py --file urls.txt --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.translate-proxy-triage/1"

_RE_CTX = re.compile(
    r"translate\.goog|translate\.google\w*\.com|_x_tr_sl=|_x_tr_tl=", re.I)
_RE_PROXY_HOST = re.compile(
    r"https?://([a-z0-9\-]+(?:\.[a-z0-9\-]+)*)\.translate\.goog"
    r"(/[^\s\"'<>]*)?(?:\?([^\s\"'<>]*))?", re.I)
_RE_XTR = re.compile(r"_x_tr_sl=([^&\s]+)", re.I)
_RE_REDIRECT = re.compile(
    r"https?://translate\.google(?:\w{2})?\.com/translate[^\s\"'<>]*"
    r"[?&]u=([^&\s\"<>]+)", re.I)


def _proxy_target(host_label: str) -> str:
    """Label hostname proxy diputar kembali: tanda '-' menandai '.'."""
    return host_label.replace("-", ".")


def triage_text(text: str) -> dict:
    """Triase artefak URL -> dict hasil. Raise ValueError bila tanpa
    konteks."""
    if not _RE_CTX.search(text):
        raise ValueError("artefak tidak mengandung URL translation-service "
                         "sama sekali")

    signals: "list[str]" = []
    evidence: dict[str, str] = {}

    proxies = _RE_PROXY_HOST.findall(text)
    if proxies:
        signals.append("translate-proxy-host")
        labels = [h[0] for h in proxies]
        evidence["proxy-hosts"] = ", ".join(
            "%s.translate.goog" % l for l in labels[:4])[:220]
        targets = sorted({_proxy_target(l) for l in labels})
        signals.append("translate-target-host")
        evidence["proxy-targets"] = ", ".join(targets[:4])[:220]
        q = _RE_XTR.findall(text)
        if q:
            evidence["x-tr-sl"] = ", ".join(sorted(set(q))[:6])

    redirects = _RE_REDIRECT.findall(text)
    if redirects:
        signals.append("translate-redirect-param")
        evidence["redirect-targets"] = ", ".join(redirects[:4])[:220]

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
        "findings": ([{"type": "translate-proxy-phish", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "proxy translation sah dipakai pembaca lintas-bahasa — "
                "verifikasi target asli dan konteks distribusi link "
                "sebelum ditindak",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="daftar URL / access log / teks lampiran")
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
