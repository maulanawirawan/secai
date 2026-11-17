"""Test xxe_probe_check — NOL jaringan, POST di-mock.

Kontrak: canary echoed / parser-error diff -> lead; respons identik ->
clean zero-FP; tanpa --lab -> DITOLAK exit 3; network fail -> fail-
closed.
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

import xxe_probe_check as xp  # noqa: E402

BENIGN_RESP = '<result>ok</result>'


def res(status, body, error=None):
    return {"status": status, "body": body, "error": error}


class XxeProbeCheckTest(unittest.TestCase):
    def test_canary_echoed_lead(self):
        probe_body = ('<error>SAXParse: entity "xxe" references '
                      'nonexistent-secai-canary-0192837</error>')
        rows, meta = xp.audit("https://t/xml", res(500, BENIGN_RESP),
                              res(500, probe_body))
        self.assertTrue(meta["processed"])
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertEqual(rows[0]["severity"], "medium")

    def test_parser_error_diff_lead(self):
        rows, meta = xp.audit("https://t/xml", res(200, BENIGN_RESP),
                              res(200, "<error>simplexml parse error"
                                       "</error>"))
        self.assertTrue(meta["processed"])

    def test_identical_clean_zero_fp(self):
        rows, meta = xp.audit("https://t/xml", res(200, BENIGN_RESP),
                              res(200, BENIGN_RESP))
        self.assertFalse(meta["processed"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = xp.audit("https://t/xml", res(None, "", error="Err"),
                              res(None, "", error="Err"))
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))

    def test_lab_gate_refusal(self):
        # tanpa --lab dan env LAB tidak '1' -> exit 3 (fail-closed)
        assert os.environ.get("LAB") != "1"
        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = xp.main(["--url", "https://t/xml",
                          "--out", str(Path("_unused_gate.json"))])
        self.assertEqual(rc, 3)
        self.assertIn("DITOLAK", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
