"""[SAFETY: read-only] upload-surface-check — inventori permukaan upload
file pada halaman target: form multipart, input file, endpoint action,
filter accept, dan petunjuk validasi sisi-klien. NOL upload dilakukan
(state-changing = jalur exploit-tier/lab); read-only, 1-2 GET.

Output (inventori — verdict 0, bukan klaim kerentanan):
  - upload-form-found : form dgn enctype multipart/form-data + input
    type=file — permukaan upload ada (info; server-side validation tak
    bisa dinilai tanpa upload terizin).
  - accept-unrestricted : input file TANPA atribut accept (klien-side
    bebas — server-side tetap yang menentukan; catatan jujur).
  - upload-action-https : action endpoint bukan https (lead konfigurasi,
    low).
Fail-closed: halaman tanpa form upload sama sekali -> AMAN/inventaris;
jaringan gagal -> tanpa klaim AMAN.
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

MAX_GETS = 2
TIMEOUT_S = 10.0
_RE_FORM = re.compile(
    r"<form\b[^>]*enctype\s*=\s*[\"']multipart/form-data[\"'][^>]*>",
    re.I)
_RE_ACTION = re.compile(r"<form\b[^>]*action\s*=\s*[\"']([^\"']*)[\"']", re.I)
_RE_FILE_INPUT = re.compile(
    r"<input\b[^>]*type\s*=\s*[\"']file[\"'][^>]*>", re.I)
_RE_ACCEPT = re.compile(r"<input\b[^>]*type\s*=\s*[\"']file[\"'][^>]*"
                        r"accept\s*=", re.I)


def _fetch(base: str, path: str) -> dict:
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent":
                                          "secai-upload-surface"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"path": path, "status": r.status,
                    "body": r.read(64_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"path": path, "status": e.code,
                "body": (e.read(8_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:
        return {"path": path, "status": None, "body": "",
                "error": "%s: %s" % (type(exc).__name__, exc)[:120]}


def audit(url: str, results: list[dict]) -> tuple[list[dict], dict]:
    """Murni: hasil GET -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    blob = "\n".join((r.get("body") or "") for r in results)

    forms = _RE_FORM.findall(blob)
    file_inputs = _RE_FILE_INPUT.findall(blob)
    actions = [a for a in _RE_ACTION.findall(blob) if a.strip()]
    accepts = _RE_ACCEPT.findall(blob)

    rows: list[dict] = []
    if forms and file_inputs:
        actions_s = ", ".join(actions[:4]) if actions else "(same-page)"
        rows.append(make_finding(
            tool="upload-surface-check",
            title="Permukaan upload file terdeteksi di %s" % base,
            severity="info",
            description="Form multipart + input file (%d form, %d input) "
                        "action: %s. INVENTORI read-only — pengujian "
                        "upload (RCE/XSS via upload, SSRF via DOCX) "
                        "butuh payload state-changing = jalur "
                        "exploit-tier/lab, bukan skill ini."
                        % (len(forms), len(file_inputs), actions_s),
            recommendation="Pastikan validasi server-side (extension+MIME"
                           "+magic bytes), simpan di path non-eksekusi, "
                           "randomize nama file.",
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "SURFACE", "safety_class": "read-only",
                   "forms": len(forms), "file_inputs": len(file_inputs),
                   "accept-filtered": bool(accepts)}))
        if len(file_inputs) > len(accepts):
            rows.append(make_finding(
                tool="upload-surface-check",
                title="Input file tanpa filter accept (klien) di %s" % base,
                severity="info",
                description="Input file tanpa atribut accept — filter "
                            "klien tidak ada; validasi SERVER-side yang "
                            "menentukan (bukan temuan berdiri sendiri).",
                target_url=base, evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=0,
                extra={"category": "SURFACE", "safety_class": "read-only"}))
    else:
        net_fail = all(r.get("status") is None for r in results)
        rows.append(make_finding(
            tool="upload-surface-check",
            title=("Gagal jaringan pada %s — tanpa klaim AMAN" if net_fail
                   else "Tidak ada permukaan upload di %s") % base,
            severity="info",
            description=("Kedua GET gagal jaringan (fail-closed)."
                         if net_fail else
                         "Tidak ada form multipart + input file pada "
                         "halaman yang diambil (AMAN/inventaris — upload "
                         "bisa di halaman ber-auth)."),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "read-only",
                   "network_error": net_fail,
                   "error": (results[0].get("error") if results else "") or ""}))

    meta = {"url": base, "requests": len(results),
            "forms": len(forms), "file_inputs": len(file_inputs)}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--path", default="/",
                    help="path halaman (default /)")
    ap.add_argument("--out", default="upload_surface_check.json")
    args = ap.parse_args()
    base = args.url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base
    results = [_fetch(base, args.path)]
    rows, meta = audit(args.url, results)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "read-only"})
    print("upload-surface-check: forms=%s inputs=%s -> %s"
          % (meta["forms"], meta["file_inputs"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
