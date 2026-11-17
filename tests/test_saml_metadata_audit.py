"""Test saml_metadata_audit — NOL jaringan, probe di-mock.

Kontrak: EntityDescriptor valid -> inventori; validUntil lewat ->
medium; WantAssertionsSigned=false -> high; entityID http -> medium;
bukan metadata -> clean; network fail -> fail-closed.
"""
from __future__ import annotations

import datetime
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import saml_metadata_audit as sm  # noqa: E402

MD_TMPL = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{eid}" validUntil="{vu}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
      WantAssertionsSigned="{was}">
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""

NOW = datetime.date(2026, 11, 18)


def res(path, status, body, error=None):
    return {"path": path, "status": status, "headers": {}, "body": body,
            "error": error}


class SamlMetadataAuditTest(unittest.TestCase):
    def test_valid_metadata_inventory(self):
        md = MD_TMPL.format(eid="https://idp.example/metadata",
                            vu="2027-01-01T00:00:00Z", was="true")
        rows, meta = sm.audit("https://t.example", [
            res("/saml/metadata", 200, md)], now=NOW)
        self.assertTrue(meta["found"])
        inv = [r for r in rows if r["verdict"] == 0]
        self.assertEqual(len(inv), 1)
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_expired_medium(self):
        md = MD_TMPL.format(eid="https://idp.example/metadata",
                            vu="2025-01-01T00:00:00Z", was="true")
        rows, meta = sm.audit("https://t.example", [
            res("/saml/metadata", 200, md)], now=NOW)
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(lead[0]["severity"], "medium")

    def test_unsigned_high(self):
        md = MD_TMPL.format(eid="https://idp.example/metadata",
                            vu="2027-01-01T00:00:00Z", was="false")
        rows, meta = sm.audit("https://t.example", [
            res("/saml/metadata", 200, md)], now=NOW)
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(lead[0]["severity"], "high")

    def test_http_entity_medium(self):
        md = MD_TMPL.format(eid="http://idp.example/metadata",
                            vu="2027-01-01T00:00:00Z", was="true")
        rows, meta = sm.audit("https://t.example", [
            res("/saml/metadata", 200, md)], now=NOW)
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(lead[0]["severity"], "medium")

    def test_no_metadata_clean(self):
        rows, meta = sm.audit("https://t.example", [
            res("/saml/metadata", 404, ""),
            res("/Shibboleth.sso/Metadata", 404, ""),
            res("/metadata", 404, ""),
        ], now=NOW)
        self.assertFalse(meta["found"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = sm.audit("https://t.example", [
            res("/saml/metadata", None, "", error="Err"),
            res("/Shibboleth.sso/Metadata", None, "", error="Err"),
            res("/metadata", None, "", error="Err"),
        ], now=NOW)
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
