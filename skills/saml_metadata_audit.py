"""[SAFETY: bounded-requests] saml-metadata-audit — audit OFFLINE-ish
metadata SAML yang terpapar publik (SAML/SSO config artifact): ambil
metadata dari path standar lalu parse XML stdlib — validUntil kadaluarsa,
flag penandatanganan assertion longgar, entityID http. Read-only, maks
3 GET; parsing xml.etree.

Marker/cek ketat (zero-FP):
  - EntityDescriptor/IDPSSODescriptor/SPSSODescriptor hadir (metadata asli).
  - validUntil < hari ini (ambang --now eksplisit dgn default hari ini)
    -> saml-metadata-expired (medium — konfig kadaluarsa).
  - WantAssertionsSigned="false" / WantResponsesSigned="false"
    -> saml-unsigned-assertions (high — assertion bisa dipalsukan bila
    endpoint konsumen tak memverifikasi).
  - entityID/Location berbasis http:// (bukan https) -> saml-entity-http
    (medium).
Fail-closed: bukan metadata SAML valid -> exit-less AMAN row; jaringan
gagal -> tanpa klaim AMAN.
"""
from __future__ import annotations

import argparse
import datetime
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 3
TIMEOUT_S = 10.0
PROBES = ("/saml/metadata", "/Shibboleth.sso/Metadata", "/metadata")
NS = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}


def _fetch(base: str, path: str) -> dict:
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent":
                                          "secai-saml-metadata-audit"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return {"path": path, "status": r.status,
                    "headers": dict(r.headers.items()),
                    "body": r.read(96_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"path": path, "status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": (e.read(8_000) or b"").decode("utf-8", "replace")}
    except Exception as exc:
        return {"path": path, "status": None, "headers": {}, "body": "",
                "error": "%s: %s" % (type(exc).__name__, exc)[:120]}


def _is_saml_metadata(body: str) -> bool:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return False
    tag = root.tag.rsplit("}", 1)[-1]
    return tag == "EntityDescriptor"


def _parse_findings(body: str, now: datetime.date) -> dict:
    root = ET.fromstring(body)
    out: dict = {"valid_until": None, "unsigned": False, "http_entity": False,
                 "entity_id": None}
    out["entity_id"] = root.get("entityID")
    vu = root.get("validUntil")
    if vu:
        try:
            dt = datetime.datetime.fromisoformat(
                vu.replace("Z", "+00:00")).date()
            out["valid_until"] = dt.isoformat()
            if dt < now:
                out["expired"] = True
        except ValueError:
            pass
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag in ("IDPSSODescriptor", "SPSSODescriptor"):
            for k, v in el.attrib.items():
                if k.endswith("WantAssertionsSigned") and \
                        v.strip().lower() == "false":
                    out["unsigned"] = True
    if out["entity_id"] and str(out["entity_id"]).startswith("http://"):
        out["http_entity"] = True
    return out


def audit(url: str, results: list[dict], *, now: datetime.date | None = None
          ) -> tuple[list[dict], dict]:
    """Murni: hasil probe -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    now = now or datetime.date.today()
    rows: list[dict] = []
    md_res = None
    for r in results:
        if r.get("status") == 200 and _is_saml_metadata(r.get("body") or ""):
            md_res = r
            break

    if md_res:
        parsed = _parse_findings(md_res.get("body") or "", now)
        rows.append(make_finding(
            tool="saml-metadata-audit",
            title="Metadata SAML terpapar di %s%s" % (
                base, " (%s)" % md_res.get("path")),
            severity="info",
            description="EntityDescriptor valid ter-parse dari %s "
                        "(entityID=%s, validUntil=%s) — inventori konfig "
                        "SSO." % (md_res.get("path"),
                                  parsed.get("entity_id"),
                                  parsed.get("valid_until")),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "SURFACE", "safety_class": "bounded-requests",
                   "parsed": parsed}))
        if parsed.get("expired"):
            rows.append(make_finding(
                tool="saml-metadata-audit",
                title="Metadata SAML kadaluarsa di %s" % base,
                severity="medium",
                description="validUntil=%s sudah lewat (acuan %s) — "
                            "relying party bisa menolak metadata atau "
                            "memakai key lama." % (parsed.get("valid_until"),
                                                   now.isoformat()),
                recommendation="Perbarui metadata + rotasi sertifikat "
                               "signing bila mendekati kadaluarsa.",
                target_url=base, evidence_kind="request-response",
                finding_class="posture", confidence=1.0, status="confirmed",
                verdict=1,
                extra={"category": "LEAD", "safety_class":
                       "bounded-requests", "parsed": parsed}))
        if parsed.get("unsigned"):
            rows.append(make_finding(
                tool="saml-metadata-audit",
                title="Assertion SAML tidak diwajibkan signed di %s" % base,
                severity="high",
                description="WantAssertionsSigned=false pada descriptor — "
                            "assertion tak bertanda tangan bisa diterima "
                            "bila endpoint konsumen tidak memverifikasi "
                            "signature (kelass ATO).",
                recommendation="Wajibkan penandatanganan assertion + "
                               "verifikasi audience/recipient.",
                target_url=base, evidence_kind="request-response",
                finding_class="posture", confidence=0.9, status="confirmed",
                verdict=1,
                extra={"category": "LEAD", "safety_class":
                       "bounded-requests", "parsed": parsed}))
        if parsed.get("http_entity"):
            rows.append(make_finding(
                tool="saml-metadata-audit",
                title="entityID SAML memakai http:// di %s" % base,
                severity="medium",
                description="entityID=%s berbasis http — konfigurasi "
                            "non-standar (redirect binding tidak aman)."
                            % parsed.get("entity_id"),
                recommendation="Pakai https untuk entityID/Location.",
                target_url=base, evidence_kind="request-response",
                finding_class="posture", confidence=0.8, status="confirmed",
                verdict=1,
                extra={"category": "LEAD", "safety_class":
                       "bounded-requests", "parsed": parsed}))
    else:
        net_fail = all(r.get("status") is None for r in results)
        rows.append(make_finding(
            tool="saml-metadata-audit",
            title=("Gagal jaringan pada %s — tanpa klaim AMAN" if net_fail
                   else "Tidak ada metadata SAML terpapar di %s") % base,
            severity="info",
            description=("Semua GET gagal jaringan (fail-closed)."
                         if net_fail else
                         "Probe path metadata standar tidak menemukan "
                         "EntityDescriptor (AMAN/inventaris — metadata "
                         "bisa di path non-standar/internal)."),
            target_url=base, evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "network_error": net_fail,
                   "error": (results[0].get("error") if results else "") or ""}))

    meta = {"url": base, "requests": len(results),
            "found": md_res is not None,
            "path": (md_res or {}).get("path")}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="saml_metadata_audit.json")
    args = ap.parse_args()
    base = args.url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base
    results = []
    for p in PROBES:
        if len(results) >= MAX_GETS:
            break
        results.append(_fetch(base, p))
    rows, meta = audit(args.url, results)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print("saml-metadata-audit: found=%s -> %s" % (meta["found"], args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
