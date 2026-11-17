"""Test okta_posture — NOL jaringan, probe di-mock.

Kontrak: issuer okta.com di discovery -> inventori verdict 0; /admin
200 tanpa indikasi login -> lead medium; frasa generik "identity" ->
zero-FP; network fail -> fail-closed.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import okta_posture as ok  # noqa: E402

DISC = json.dumps({"issuer": "https://corp.okta.com",
                   "authorization_endpoint":
                       "https://corp.okta.com/oauth2/v1/authorize"})
GENERIC_DISC = json.dumps({"issuer": "https://sso.corp.example"})


def res(path, status, body, error=None):
    return {"path": path, "status": status, "headers": {}, "body": body,
            "error": error}


class OktaPostureTest(unittest.TestCase):
    def test_okta_detected_inventory(self):
        rows, meta = ok.audit("https://t.example", [
            res("/.well-known/openid-configuration", 200, DISC),
            res("/admin", 401, ""),
            res("/", 200, "<html>App</html>"),
        ])
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["issuer"], "https://corp.okta.com")
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_admin_open_lead(self):
        rows, meta = ok.audit("https://t.example", [
            res("/.well-known/openid-configuration", 200, DISC),
            res("/admin", 200, "<html>Admin Panel</html>"),
            res("/", 200, "<html>App</html>"),
        ])
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(len(lead), 1)
        self.assertEqual(lead[0]["severity"], "medium")
        self.assertTrue(meta["admin_open"])

    def test_admin_login_redirect_clean(self):
        # /admin 200 tapi isi halaman login -> terlindungi, bukan lead
        rows, meta = ok.audit("https://t.example", [
            res("/.well-known/openid-configuration", 200, DISC),
            res("/admin", 200, "<html>Sign in to login.okta.com</html>"),
            res("/", 200, "<html>App</html>"),
        ])
        self.assertFalse(meta["admin_open"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_generic_idp_zero_fp(self):
        # IdP non-okta -> marker tidak menyala
        rows, meta = ok.audit("https://t.example", [
            res("/.well-known/openid-configuration", 200, GENERIC_DISC),
            res("/admin", 401, ""),
            res("/", 200, "<html>Identity portal</html>"),
        ])
        self.assertFalse(meta["detected"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = ok.audit("https://t.example", [
            res("/.well-known/openid-configuration", None, "", error="Err"),
            res("/admin", None, "", error="Err"),
            res("/", None, "", error="Err"),
        ])
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
