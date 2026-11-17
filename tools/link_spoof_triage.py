r"""[SAFETY: read-only] link_spoof_triage — wave-6 deteksi OFFLINE
artefak HTML/JS phishing dgn teknik link spoofing: anchor click handler
memanggil `event.preventDefault()` lalu mengarahkan navigasi ke URL
BERBEDA dari href yang tampil (referensi teknik "Link spoofing with
PreventDefault JavaScript method" dari pustaka referensi; kode dibangun
dari nol, stdlib murni, tanpa jaringan).

Mekanisme: statik-konjunktif — sinyal inti HANYA ketika preventDefault
dan mutasi navigasi ke URL ABSOLUT (string literal `http(s)://`)
hadir bersamaan di artefak; navigasi relatif (router SPA/modul) TIDAK
dianggap, sehingga pola SPA yang sah tidak tersentuh (zero-FP).

Sinyal per file (semua deterministik dari data):
  - preventdefault-redirect : preventDefault() + mutasi navigasi URL
    absolut (location[.href|]= / location.assign/replace / window.open)
    — kombinasi inti teknik spoof.
  - href-target-mismatch    : domain URL absolut tujuan TIDAK ada di
    antara href anchor pada artefak yang sama (hanya dinilai saat
    preventdefault-redirect ada — mencegah FP router/SPA).
  - inline-onclick-nav      : atribut onclick pada <a> yang berisi
    mutasi location/window.open langsung (tanpa href jujur).
  - status-bar-spoof        : `window.status=` / `self.status=` diisi
    URL absolut (spoof status bar gaya lama).
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info.
Halaman dgn preventDefault untuk modal/form TANPA navigasi absolut ->
0 sinyal (clean, zero-FP).

Fail-closed: file tanpa konteks sama sekali (tidak ada preventDefault,
mutasi location, onclick, maupun anchor) -> exit 2; file tidak ada ->
exit 2. Temuan = LEAD (redirect absolut sah ada di SSO/analytics —
konfirmasi domain tujuan sebelum ditindak).

Pemakaian:
  python tools/link_spoof_triage.py --file page.html --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.link-spoof-triage/1"

_RE_ANCHOR = re.compile(r"<a\b[^>]*\bhref\s*=\s*[\"']([^\"']*)[\"']", re.I)
_RE_PD = re.compile(r"\.\s*preventDefault\s*\(", re.I)
_RE_NAV_ABS = re.compile(
    r"(?:window\s*\.\s*)?location(?:\s*\.\s*(?:href|assign|replace)\s*|\s*"
    r"=\s*)[=(]?\s*[\"'](https?://[^\"']+)[\"']"
    r"|\bwindow\s*\.\s*open\s*\(\s*[\"'](https?://[^\"']+)[\"']", re.I)
_RE_ONCLICK_NAV = re.compile(
    r"<a\b[^>]*\bonclick\s*=\s*[\"'][^\"']*(?:location|window\.open)"
    r"[^\"']*[\"']", re.I)
_RE_STATUS = re.compile(
    r"(?:window|self)\s*\.\s*status\s*=\s*[\"'][^\"']*https?://", re.I)
_RE_CTX = re.compile(
    r"preventDefault|location\s*\.\s*(href|assign|replace)|window\s*\.\s*"
    r"open|onclick\s*=|addEventListener\s*\(\s*[\"']click|"
    r"(?:window|self)\s*\.\s*status\s*=", re.I)


def _url_domain(url: str) -> str:
    m = re.match(r"https?://([^/:?#]+)", url, re.I)
    return m.group(1).lower() if m else ""


def triage_text(text: str) -> dict:
    """Triase HTML/JS -> dict hasil. Raise ValueError bila tanpa
    konteks (bukan artefak navigasi/handler)."""
    if not _RE_CTX.search(text) or not _RE_ANCHOR.search(text):
        raise ValueError("artefak tidak mengandung konteks handler/"
                         "navigasi + anchor — bukan target triase ini")

    signals: "list[str]" = []
    evidence: dict[str, str] = {}

    hrefs = [h for h in _RE_ANCHOR.findall(text) if h.strip()]
    href_domains = {d for d in (_url_domain(h) for h in hrefs) if d}

    nav_abs = _RE_NAV_ABS.findall(text)
    nav_urls: "list[str]" = []
    for tup in nav_abs:
        nav_urls.append(tup[0] if tup[0] else tup[1])

    has_pd = bool(_RE_PD.search(text))

    if has_pd and nav_urls:
        signals.append("preventdefault-redirect")
        evidence["redirect"] = nav_urls[0][:140]
        nav_domains = {d for d in (_url_domain(u) for u in nav_urls) if d}
        baited = href_domains - nav_domains
        if href_domains and baited:
            signals.append("href-target-mismatch")
            evidence["bait-href"] = ", ".join(sorted(baited)[:4])[:160]
            evidence["nav-domain"] = ", ".join(sorted(nav_domains)[:4])

    if _RE_ONCLICK_NAV.search(text):
        signals.append("inline-onclick-nav")
        evidence["onclick"] = _RE_ONCLICK_NAV.search(text).group(0)[:140]

    if _RE_STATUS.search(text):
        signals.append("status-bar-spoof")

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
        "anchor_count": len(hrefs),
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "link-spoof", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "redirect absolut sah ada di SSO/analytics/kampanye — "
                "verifikasi domain tujuan dgn reputasi sebelum "
                "ditindak; statik satu artefak, bukan analisa runtime",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="artefak HTML/JS (lampiran phishing, landing page)")
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
