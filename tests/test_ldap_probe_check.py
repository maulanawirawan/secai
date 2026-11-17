"""Test ldap_probe_check — NOL jaringan, GET di-mock.

Kontrak: wildcard -> status diff / body-ratio / ldap-error -> lead;
identik -> clean zero-FP; tanpa --lab -> exit 3; network fail ->
fail-closed.
"""
from __future__ import annotations

import io
import os
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import ldap_probe_check as lp  # noqa: E402

BENIGN_RESP = '<users><user>jdoe</user></users>'
WILD_RESP = ('<users><user>jdoe</user><user>admin</user>'
             '<user>svc-backup</user><user>hr-01</user></users>')


def res(status, body, error=None):
    return {"status": status, "body": body, "error": error}


class LdapProbeCheckTest(unittest.TestCase):
    def test_status_diff_lead(self):
        rows, meta = lp.audit("https://t/search?user=XYZ",
                              res(200, BENIGN_RESP), res(500, "error"))
        self.assertTrue(meta["injected"])
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertEqual(rows[0]["severity"], "medium")

    def test_body_ratio_lead(self):
        rows, meta = lp.audit("https://t/search?user=XYZ",
                              res(200, BENIGN_RESP), res(200, WILD_RESP))
        self.assertTrue(meta["injected"])
        self.assertGreaterEqual(meta["body-ratio"], 1.3)

    def test_ldap_error_signature_lead(self):
        rows, meta = lp.audit("https://t/search?user=XYZ",
                              res(200, BENIGN_RESP),
                              res(200, "LDAP search filter syntax error"))
        self.assertTrue(meta["injected"])

    def test_identical_clean_zero_fp(self):
        rows, meta = lp.audit("https://t/search?user=XYZ",
                              res(200, BENIGN_RESP), res(200, BENIGN_RESP))
        self.assertFalse(meta["injected"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = lp.audit("https://t/search?user=XYZ",
                              res(None, "", error="Err"),
                              res(None, "", error="Err"))
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))

    def test_lab_gate_refusal(self):
        assert os.environ.get("LAB") != "1"
        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = lp.main(["--url", "https://t/search?user=XYZ",
                          "--out", str(Path("_unused_gate.json"))])
        self.assertEqual(rc, 3)
        self.assertIn("DITOLAK", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
