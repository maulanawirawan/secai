"""Test host_header_abuse_check — NOL jaringan, hasil fetch di-mock.

Kontrak: refleksi canary di forwarded TIDAK di baseline -> lead;
canary di baseline juga -> zero-FP (bukan refleksi); semua fetch gagal
-> fail-closed tanpa klaim AMAN.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import host_header_abuse_check as hh  # noqa: E402

BASE_BODY = '<html><link rel="canonical" href="https://t.example/"></html>'
REFLECT_BODY = ('<html><link rel="canonical" '
                'href="https://secai-hh-probe.example/"></html>')


def res(status, body, error=None):
    return {"status": status, "headers": {}, "body": body,
            "error": error}


class HostHeaderAbuseCheckTest(unittest.TestCase):
    def test_reflection_lead_medium(self):
        rows, meta = hh.audit(
            "https://t.example", res(200, BASE_BODY), res(200, REFLECT_BODY))
        self.assertTrue(meta["reflected"])
        self.assertIn("hh-xforwarded-reflected", meta["signals"])
        self.assertTrue(any(r["verdict"] == 1 for r in rows))
        self.assertTrue(any(r["severity"] == "medium" for r in rows))

    def test_canonical_injection_second_row(self):
        rows, meta = hh.audit(
            "https://t.example", res(200, BASE_BODY), res(200, REFLECT_BODY))
        self.assertTrue(meta["injected"])
        self.assertIn("hh-canonical-injected", meta["signals"])
        self.assertEqual(len([r for r in rows if r["verdict"] == 1]), 2)

    def test_baseline_canary_zero_fp(self):
        rows, meta = hh.audit(
            "https://t.example", res(200, REFLECT_BODY), res(200, REFLECT_BODY))
        self.assertFalse(meta["reflected"])
        self.assertIn("hh-always-reflects", meta["signals"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_clean_no_reflection(self):
        rows, meta = hh.audit(
            "https://t.example", res(200, BASE_BODY), res(200, BASE_BODY))
        self.assertFalse(meta["reflected"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = hh.audit(
            "https://t.example", res(None, "", error="ConnError"),
            res(None, "", error="ConnError"))
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
