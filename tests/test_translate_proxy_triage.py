"""Test translate_proxy_triage — NOL jaringan, URL/log di-mock.

Kontrak yang dikunci:
  - URL proxy translate.goog -> translate-proxy-host +
    translate-target-host (target dari hostname hyphen dipulihkan);
  - redirect lama translate.google.com?...u= -> translate-redirect-param
    (proxy + redirect = high);
  - zero-FP: translate.google.com polos tanpa u= -> 0 sinyal clean;
  - fail-closed: daftar URL tanpa translation-service -> exit 2;
    file hilang -> 2.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys_path = str(ROOT / "tools")
if sys_path not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_path)

import translate_proxy_triage as tpt  # noqa: E402

PROXY_URL = """https://secure-bank-login-com.translate.goog/session?_x_tr_sl=en&_x_tr_tl=id&_x_tr_hl=en
"""

REDIRECT_URL = """https://translate.google.com/translate?sl=en&tl=id&u=https://phish.example/pay
"""

CLEAN_URL = """https://translate.google.com/?sl=en&tl=id
https://example.com/page
"""

NO_CONTEXT = """https://example.com/page
https://other.example.org/other
"""


class TranslateProxyTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.txt"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = tpt.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_proxy_host_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), PROXY_URL)
            self.assertIn("translate-proxy-host", d["signals"])
            self.assertIn("secure.bank.login.com",
                          d["evidence"]["proxy-targets"])
            self.assertEqual(d["severity"], "medium")

    def test_proxy_plus_redirect_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), PROXY_URL + "\n" + REDIRECT_URL)
            for sig in ("translate-proxy-host", "translate-target-host",
                        "translate-redirect-param"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["evidence"]["redirect-targets"],
                             "https://phish.example/pay")
            self.assertEqual(d["severity"], "high")

    def test_clean_translate_url_zero_fp(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), CLEAN_URL)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)

    def test_no_context_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_CONTEXT, encoding="utf-8")
            rc = tpt.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = tpt.main(["--file", r"D:/nonexistent/__no__.txt"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
