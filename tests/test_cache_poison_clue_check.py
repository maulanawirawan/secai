"""Test cache_poison_clue_check — NOL jaringan, fetch di-mock.

Kontrak: cacheable + refleksi canary -> lead; replay HIT + canary ->
high clue; tidak cacheable / tanpa refleksi -> clean zero-FP; network
fail -> fail-closed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import cache_poison_clue_check as cp  # noqa: E402

PLAIN = '<html>static page</html>'
MARKED = '<html>canary secai-cp-probe.example injected</html>'


def res(status, body, headers=None, error=None):
    return {"status": status, "headers": headers or {}, "body": body,
            "error": error}


CACHE_HDRS = {"Cache-Control": "public, max-age=300"}
HIT_HDRS = {"X-Cache": "HIT", "Age": "12"}


class CachePoisonClueTest(unittest.TestCase):
    def test_full_clue_high(self):
        rows, meta = cp.audit(
            "https://t.example",
            res(200, PLAIN, CACHE_HDRS),
            res(200, MARKED, CACHE_HDRS),
            res(200, MARKED, HIT_HDRS))
        self.assertIn("cp-cacheable-response", meta["signals"])
        self.assertIn("cp-header-reflected", meta["signals"])
        self.assertIn("cp-replay-still-marked", meta["signals"])
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["verdict"], 1)

    def test_reflection_medium(self):
        rows, meta = cp.audit(
            "https://t.example",
            res(200, PLAIN, CACHE_HDRS),
            res(200, MARKED, CACHE_HDRS),
            res(200, MARKED, CACHE_HDRS))
        self.assertNotIn("cp-replay-still-marked", meta["signals"])
        self.assertEqual(rows[0]["severity"], "medium")

    def test_not_cacheable_zero_fp(self):
        # canary reflected tapi respons no-store -> tidak diklaim
        rows, meta = cp.audit(
            "https://t.example",
            res(200, PLAIN, {"Cache-Control": "no-store"}),
            res(200, MARKED, {"Cache-Control": "no-store"}),
            res(200, MARKED, {"Cache-Control": "no-store"}))
        self.assertNotIn("cp-cacheable-response", meta["signals"])
        self.assertNotIn("cp-header-reflected", meta["signals"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_plain_clean(self):
        rows, meta = cp.audit(
            "https://t.example",
            res(200, PLAIN, CACHE_HDRS),
            res(200, PLAIN, CACHE_HDRS),
            res(200, PLAIN, CACHE_HDRS))
        self.assertNotIn("cp-header-reflected", meta["signals"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = cp.audit(
            "https://t.example", res(None, "", error="Err"),
            res(None, "", error="Err"), res(None, "", error="Err"))
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
