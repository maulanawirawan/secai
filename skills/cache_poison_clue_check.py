"""[SAFETY: bounded-requests] cache-poison-clue-check — clue-level
deteksi web cache poisoning (kelas berdampak massal yang sering
dilaporkan di bug bounty): apakah respons cacheable dan apakah marker
via header yang bisa dikontrol penyerang tercermin di respons yang
kemungkinan ter-cache. Read-only, 3 GET ke path / (baseline, canary,
canary-ulang), tanpa payload aktif — hasil = LEAD, bukan proof.

Sinyal (semua deterministik dari respons):
  - cp-cacheable-response : respons baseline cacheable (Cache-Control
    public/max-age tanpa no-store/private, ATAU X-Cache/CF-Cache-Status
    hadir) — prasyarat kelas ini.
  - cp-header-reflected   : respons canary memuat canary host (dari
    X-Forwarded-Host) — header penyerang masuk konten.
  - cp-replay-still-marked: GET canary kedua (identik) tetap memuat
    canary DAN indikasi cache (X-Cache: HIT / Age>0 / CF-Cache-Status
    HIT) — canary masuk salinan yang disajikan ulang; clue kuat.
Fail-closed: semua GET gagal jaringan -> tanpa klaim AMAN. Respons
tidak-cacheable -> temuan tidak diklaim (zero-FP).
"""
from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 3
TIMEOUT_S = 10.0
CANARY_HOST = "secai-cp-probe.example"
CANARY = re.compile(re.escape(CANARY_HOST), re.I)
_RE_CACHEABLE = re.compile(
    r"cache-control:\s*(?!.*no-store)(?!.*private)[^\r\n]*(public|max-age|s-maxage)"
    r"|x-cache:|cf-cache-status:|age:\s*[1-9]", re.I)
_RE_CACHE_HIT = re.compile(
    r"x-cache:\s*hit|cf-cache-status:\s*hit|age:\s*[1-9]", re.I)

HEADERS_BASE = {"User-Agent": "secai-cache-clue"}
HEADERS_FWD = {"User-Agent": "secai-cache-clue",
               "X-Forwarded-Host": CANARY_HOST}


def _fetch(base: str, headers: dict) -> dict:
    req = urllib.request.Request(base + "/", method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"status": r.status,
                    "headers": dict(r.headers.items()),
                    "body": r.read(48_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": (e.read(24_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:
        return {"status": None, "headers": {}, "body": "",
                "error": "%s: %s" % (type(exc).__name__, exc)[:120]}


def _hdr_blob(res: dict) -> str:
    return " ".join("%s: %s" % (k, v)
                    for k, v in (res.get("headers") or {}).items())


def audit(url: str, baseline: dict, marked: dict, replay: dict
          ) -> tuple[list[dict], dict]:
    """Murni: tiga hasil fetch -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    signals: list[str] = []
    rows: list[dict] = []
    net_fail = all(r.get("status") is None for r in
                   (baseline, marked, replay))

    blob_base = _hdr_blob(baseline)
    cacheable = bool(_RE_CACHEABLE.search(blob_base))
    marked_canary = bool(CANARY.search(marked.get("body") or ""))
    blob_replay = _hdr_blob(replay)
    replay_canary = bool(CANARY.search(replay.get("body") or ""))
    replay_hit = bool(_RE_CACHE_HIT.search(blob_replay))

    if cacheable:
        signals.append("cp-cacheable-response")
        if marked_canary and not CANARY.search(baseline.get("body") or ""):
            signals.append("cp-header-reflected")
        if marked_canary and replay_canary and replay_hit:
            signals.append("cp-replay-still-marked")

    if signals and "cp-header-reflected" in signals:
        sev = "high" if "cp-replay-still-marked" in signals else "medium"
        rows.append(make_finding(
            tool="cache-poison-clue-check",
            title="Kandidat cache poisoning (clue) di %s" % base,
            severity=sev,
            description="Canary X-Forwarded-Host tercermin di respons "
                        "cacheable%s. Ini CLUE statik — bukti poisoning "
                        "butuh verifikasi dari klien lain (cache key "
                        "berbeda per user-agent/cookie) sebelum klaim."
                        % (" dan replay tetap canary dgn cache HIT"
                           if "cp-replay-still-marked" in signals else ""),
            recommendation="Audit cache key (semua header yang "
                           "mempengaruhi origin request); normalisasi/"
                           "allowlist Host; pertimbangkan no-store utk "
                           "respons personal.",
            target_url=base,
            request="GET / (X-Forwarded-Host: %s) x2" % CANARY_HOST,
            response=(marked.get("body") or "")[:240].replace("\n", " "),
            evidence_kind="request-response", finding_class="posture",
            confidence=0.6 if sev == "medium" else 0.8,
            status="confirmed", verdict=1,
            extra={"category": "LEAD", "safety_class": "bounded-requests",
                   "signals": signals, "canary": CANARY_HOST}))
    elif net_fail:
        rows.append(make_finding(
            tool="cache-poison-clue-check",
            title="Gagal jaringan pada %s — tanpa klaim AMAN" % base,
            severity="info",
            description="Semua GET gagal jaringan; kegagalan koneksi "
                        "BUKAN bukti tidak-rentan (fail-closed).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "network_error": True,
                   "error": marked.get("error") or ""}))
    else:
        rows.append(make_finding(
            tool="cache-poison-clue-check",
            title="Tidak ada clue cache poisoning pada %s" % base,
            severity="info",
            description="Tidak ada kombinasi cacheable + refleksi canary "
                        "(AMAN/inventaris — clue tidak teramati pada GET "
                        "/ dgn header satu arah; kelas lain tak diuji).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "signals": signals}))

    meta = {"url": base, "requests": MAX_GETS, "cacheable": cacheable,
            "signals": signals, "canary": CANARY_HOST}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="cache_poison_clue_check.json")
    args = ap.parse_args()
    base = args.url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base
    baseline = _fetch(base, HEADERS_BASE)
    marked = _fetch(base, HEADERS_FWD)
    replay = _fetch(base, HEADERS_FWD)
    rows, meta = audit(args.url, baseline, marked, replay)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print("cache-poison-clue-check: signals=%s -> %s"
          % (meta["signals"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
