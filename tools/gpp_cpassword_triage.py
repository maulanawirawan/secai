"""[SAFETY: read-only] gpp_cpassword_triage — wave-4 GPP: deteksi OFFLINE
kredensial ter-embed di Group Policy Preferences (referensi teknik
Crassus / Get-GPPPassword dari pustaka referensi, kode dibangun dari
nol).

Sinyal per dump (semua deterministik dari data):
  - cpassword-embedded : atribut cpassword ditemukan di XML GPP
                         (groups.xml / drives.xml / scheduledtasks.xml /
                         services.xml / printers.xml / datasources.xml)
                         — kredensial ter-embed yang bisa didekripsi siapa
                         pun dengan AES key statis yang diterbitkan MS
  - user-context       : atribut userName/guestName/acctName di elemen
                         yang sama (target kredensial ter-identifikasi)
  - aes-key-referenced : teks menyebut key statis MS32 {31B2F340-...}
                         (analisis/eksploitasi yang sedang dijalankan)
  - plaintext-recovered: dekripsi AES-256-CBC berhasil (hanya bila paket
                         kripto opsional tersedia; tanpa paket, sinyal
                         utama tetap high)
Skor = jumlah sinyal; >= 2 high, == 1 medium. Zero-FP: XML GPP tanpa
cpassword (policy biasa tanpa kredensial) -> 0 sinyal, clean.

Fail-closed: teks tanpa markup/tag XML sama sekali -> exit 2. Temuan =
LEAD (kredensial ter-embed GPP adalah temuan nyata; ganti password
terkait setelah konfirmasi).

Pemakaian:
  python tools/gpp_cpassword_triage.py --file groups.xml --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.gpp-cpassword-triage/1"

# Key AES statis MS GPP (diterbitkan publik di MS-GPPREF) — dipakai
# untuk memverifikasi panjang/format; dekripsi opsional.
_AES_KEY_HEX = (
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)

_RE_XML_TAG = re.compile(r"<[a-zA-Z!/]")
_RE_CPASSWORD = re.compile(
    r'cpassword\s*=\s*["\']([A-Za-z0-9+/=]{8,})["\']')
_RE_USER_CTX = re.compile(
    r'(userName|guestName|acctName|runAs|name)\s*=\s*["\']([^"\']{1,64})["\']',
    re.I)
_RE_GPP_CTX = re.compile(
    r"(groups\.xml|drives\.xml|scheduledtasks\.xml|services\.xml|"
    r"printers\.xml|datasources\.xml|GPP|GroupPolicy|Group Policy)", re.I)
_RE_AES_KEY_REF = re.compile(
    r"(31B2F340-016D-11D2-945F-00C04FB984F9|4e99081e8ecb789f)", re.I)


def _try_decrypt(cpassword_b64: str) -> str | None:
    """Dekripsi AES-256-CBC cpassword (opsional — butuh paket kripto
    pihak ketiga; tanpa itu kembalikan None, sinyal utama tetap jalan)."""
    try:
        from Crypto.Cipher import AES  # type: ignore
    except Exception:
        return None
    key = bytes.fromhex(_AES_KEY_HEX)
    try:
        raw = base64.b64decode(cpassword_b64 + "=" * (-len(cpassword_b64) % 4))
        cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16)
        dec = cipher.decrypt(raw)
        return dec[: -dec[-1]].decode("utf-16-le", errors="replace").rstrip(
            "\x00")
    except Exception:
        return None


def audit_xml(text: str) -> dict | None:
    """Skor satu dump GPP XML. None = bukan XML/teks terstruktur."""
    if not _RE_XML_TAG.search(text) and "cpassword" not in text:
        return None
    signals: list[str] = []
    evidence: dict[str, str] = {}

    cps = _RE_CPASSWORD.findall(text)
    if cps:
        signals.append("cpassword-embedded")
        evidence["cpassword_b64_len"] = str(max(len(c) for c in cps))
        users = _RE_USER_CTX.findall(text)
        if users:
            signals.append("user-context")
            evidence["users"] = ", ".join(
                u[1] for u in users[:5] if u[1].strip())[:160]
    if _RE_AES_KEY_REF.search(text):
        signals.append("aes-key-referenced")

    dec = _try_decrypt(cps[0]) if cps else None
    if dec:
        signals.append("plaintext-recovered")
        evidence["plaintext_password"] = dec[:64]

    seen: set[str] = set()
    signals = [s2 for s2 in signals if not (s2 in seen or seen.add(s2))]

    return {"signals": signals, "score": len(signals), "evidence": evidence}


def triage_text(text: str) -> dict:
    res = audit_xml(text)
    if res is None:
        raise ValueError("bukan dump XML/terstruktur — tidak ada tag atau "
                         "kata kunci GPP")
    score = res["score"]
    severity = ("high" if score >= 2 else
                "medium" if score == 1 else "info")
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
        "findings": ([{"type": "gpp-cpassword", "severity": severity,
                       "signals": res["signals"],
                       "evidence": res["evidence"]}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "cpassword GPP = kredensial ter-embed yang didekripsi siapa "
                "pun dengan key statis MS — ganti kredensial terkait setelah "
                "konfirmasi",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="dump XML GPP (groups/drives/scheduledtasks/...)")
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
