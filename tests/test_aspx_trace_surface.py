"""Test aspx_trace_surface — NOL jaringan, probe di-mock.

Kontrak: trace.axd marker -> high; elmah marker -> high;
X-AspNet-Version header -> inventori; tanpa marker -> clean;
network fail -> fail-closed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import aspx_trace_surface as ax  # noqa: E402

TRACE = "<html><h1>Application Trace</h1></html>"
ELMAH = "<html><h1>ELMAH Error Log</h1></html>"


def res(path, status, body, headers=None, error=None):
    return {"path": path, "status": status, "headers": headers or {},
            "body": body, "error": error}


class AspxTraceSurfaceTest(unittest.TestCase):
    def test_trace_exposed_high(self):
        rows, meta = ax.audit("https://t.example", [
            res("/trace.axd", 200, TRACE),
            res("/elmah.axd", 404, ""),
            res("/", 200, "", headers={"X-AspNet-Version": "4.0.30319"}),
        ])
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(len(lead), 1)
        self.assertEqual(lead[0]["severity"], "high")
        self.assertTrue(meta["trace"])

    def test_elmah_exposed_high(self):
        rows, meta = ax.audit("https://t.example", [
            res("/trace.axd", 404, ""),
            res("/elmah.axd", 200, ELMAH),
            res("/", 200, ""),
        ])
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(lead[0]["severity"], "high")

    def test_version_header_inventory(self):
        rows, meta = ax.audit("https://t.example", [
            res("/trace.axd", 404, ""),
            res("/elmah.axd", 404, ""),
            res("/", 200, "", headers={"X-AspNet-Version": "4.0.30319"}),
        ])
        self.assertEqual(meta["versions"], ["4.0.30319"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_clean_zero_fp(self):
        rows, meta = ax.audit("https://t.example", [
            res("/trace.axd", 404, ""),
            res("/elmah.axd", 404, ""),
            res("/", 200, ""),
        ])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = ax.audit("https://t.example", [
            res("/trace.axd", None, "", error="Err"),
            res("/elmah.axd", None, "", error="Err"),
            res("/", None, "", error="Err"),
        ])
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
