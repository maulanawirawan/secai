"""Test ntlm_exposure_check — NOL jaringan, probe di-mock.

Kontrak: WWW-Authenticate NTLM pada http:// -> high lead; NTLM pada
https -> inventori verdict 0; Negotiate saja -> postur baik; tanpa
header -> clean; network fail -> fail-closed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import ntlm_exposure_check as nx  # noqa: E402


def res(path, status, headers, scheme="https", error=None):
    return {"path": path, "status": status, "headers": headers,
            "scheme": scheme, "body": "", "error": error}


class NtlmExposureCheckTest(unittest.TestCase):
    def test_ntlm_plain_http_high(self):
        rows, meta = nx.audit("http://t.example", [
            res("/", 401, {"WWW-Authenticate": "NTLM"}, scheme="http"),
            res("/rpc", 401, {"WWW-Authenticate": "Negotiate, NTLM"},
                scheme="http"),
            res("/autodiscover/autodiscover.xml", 401, {},
                scheme="http"),
        ])
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(len(lead), 1)
        self.assertEqual(lead[0]["severity"], "high")
        self.assertTrue(meta["plain-http"])
        self.assertIn("/", meta["ntlm-paths"])

    def test_ntlm_https_inventory(self):
        rows, meta = nx.audit("https://t.example", [
            res("/", 401, {"WWW-Authenticate": "NTLM"}),
            res("/rpc", 401, {}),
            res("/autodiscover/autodiscover.xml", 401, {}),
        ])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))
        self.assertIn("/", meta["ntlm-paths"])

    def test_negotiate_only_good_posture(self):
        rows, meta = nx.audit("https://t.example", [
            res("/", 401, {"WWW-Authenticate": "Negotiate"}),
            res("/rpc", 401, {}),
            res("/autodiscover/autodiscover.xml", 401, {}),
        ])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))
        self.assertEqual(meta["ntlm-paths"], [])

    def test_no_header_clean(self):
        rows, meta = nx.audit("https://t.example", [
            res("/", 200, {}),
            res("/rpc", 404, {}),
            res("/autodiscover/autodiscover.xml", 404, {}),
        ])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = nx.audit("https://t.example", [
            res("/", None, {}, error="Err"),
            res("/rpc", None, {}, error="Err"),
            res("/autodiscover/autodiscover.xml", None, {}, error="Err"),
        ])
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
