"""Test vcenter_posture — NOL jaringan, probe di-mock.

Kontrak: token vmware/vcenter eksplisit -> lead medium + versi fakta;
frasa generik -> zero-FP; 401 tanpa token -> clean; network fail ->
fail-closed (pola beyondtrust_posture).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import vcenter_posture as vc  # noqa: E402

VC_BODY = '<html><title>vSphere Client (VMware vCenter 8.0.1)</title></html>'
GENERIC = "<html>Virtual infrastructure management console</html>"


def res(path, status, body, error=None):
    return {"path": path, "status": status, "headers": {}, "body": body,
            "error": error}


class VcenterPostureTest(unittest.TestCase):
    def test_detected_with_version(self):
        rows, meta = vc.audit("https://t.example", [
            res("/ui", 200, VC_BODY),
            res("/sdk", 200, "<soapenv>vim</soapenv>"),
            res("/", 200, ""),
        ])
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["versions"], ["8.0.1"])
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(len(lead), 1)
        self.assertEqual(lead[0]["severity"], "medium")

    def test_generic_phrase_zero_fp(self):
        # frasa generik "virtual infrastructure" BUKAN marker
        rows, meta = vc.audit("https://t.example", [
            res("/ui", 404, GENERIC),
            res("/sdk", 404, GENERIC),
            res("/", 200, GENERIC),
        ])
        self.assertFalse(meta["detected"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_401_clean(self):
        rows, meta = vc.audit("https://t.example", [
            res("/ui", 401, ""),
            res("/sdk", 401, ""),
            res("/", 401, ""),
        ])
        self.assertFalse(meta["detected"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = vc.audit("https://t.example", [
            res("/ui", None, "", error="Err"),
            res("/sdk", None, "", error="Err"),
            res("/", None, "", error="Err"),
        ])
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
