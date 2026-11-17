"""Test entra_posture — NOL jaringan, probe di-mock.

Kontrak: issuer login.microsoftonline -> inventori verdict 0 + tenant
id di evidence; /adfs/ls marker ADFS -> lead medium; IdP generik ->
zero-FP; network fail -> fail-closed.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import entra_posture as ep  # noqa: E402

DISC = json.dumps({
    "issuer": "https://login.microsoftonline.com/11111111-2222-3333-"
              "4444-555555555555/v2.0"})
ADFS = "<html><title>Active Directory Federation Services</title></html>"
GENERIC_DISC = json.dumps({"issuer": "https://sso.corp.example"})


def res(path, status, body, error=None):
    return {"path": path, "status": status, "headers": {}, "body": body,
            "error": error}


class EntraPostureTest(unittest.TestCase):
    def test_entra_detected_inventory(self):
        rows, meta = ep.audit("https://t.example", [
            res("/.well-known/openid-configuration", 200, DISC),
            res("/", 200, "<html>App</html>"),
            res("/adfs/ls/idpinitiatedsignon.htm", 404, ""),
        ])
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["tenant"], "11111111-2222-3333-4444-555555555555")
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_adfs_lead_medium(self):
        rows, meta = ep.audit("https://t.example", [
            res("/.well-known/openid-configuration", 200, DISC),
            res("/", 200, "<html>App</html>"),
            res("/adfs/ls/idpinitiatedsignon.htm", 200, ADFS),
        ])
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(len(lead), 1)
        self.assertEqual(lead[0]["severity"], "medium")

    def test_generic_idp_zero_fp(self):
        rows, meta = ep.audit("https://t.example", [
            res("/.well-known/openid-configuration", 200, GENERIC_DISC),
            res("/", 200, "<html>Cloud identity portal</html>"),
            res("/adfs/ls/idpinitiatedsignon.htm", 404, ""),
        ])
        self.assertFalse(meta["detected"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = ep.audit("https://t.example", [
            res("/.well-known/openid-configuration", None, "", error="Err"),
            res("/", None, "", error="Err"),
            res("/adfs/ls/idpinitiatedsignon.htm", None, "", error="Err"),
        ])
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
