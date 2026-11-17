"""Test nextjs_surface — NOL jaringan, fetch di-mock.

Kontrak: X-Powered-By Next.js + __NEXT_DATA__ buildId -> detected
(inventori verdict 0); buildId "development"/webpack-hmr -> dev
medium verdict 1; tanpa marker -> clean; network fail -> fail-closed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import nextjs_surface as nj  # noqa: E402

PROD = ('<script id="__NEXT_DATA__" type="application/json">'
        '{"buildId":"b7Xy-abc","runtimeConfig":{}}</script>')
DEV = ('<script id="__NEXT_DATA__" type="application/json">'
       '{"buildId":"development"}</script>_next/webpack-hmr')


def res(status, body, headers=None, error=None):
    return {"path": "/", "status": status, "headers": headers or {},
            "body": body, "error": error}


class NextjsSurfaceTest(unittest.TestCase):
    def test_prod_detected_inventory(self):
        rows, meta = nj.audit("https://t.example", [
            res(200, PROD, {"X-Powered-By": "Next.js"})])
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["buildid"], "b7Xy-abc")
        self.assertFalse(meta["dev"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_dev_mode_lead(self):
        rows, meta = nj.audit("https://t.example", [
            res(200, DEV, {"X-Powered-By": "Next.js"})])
        self.assertTrue(meta["dev"])
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(len(lead), 1)
        self.assertEqual(lead[0]["severity"], "medium")

    def test_no_marker_clean(self):
        rows, meta = nj.audit("https://t.example", [res(200, "<html></html>")])
        self.assertFalse(meta["detected"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = nj.audit("https://t.example", [res(None, "", error="E")])
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
