"""Test coverage_ledger — NOL jaringan, scope + findings di-mock.

Kontrak: temuan di luar scope -> oos-target-hit high; coverage < ambang
-> coverage-thin; semua in-scope + full coverage -> clean zero-FP;
wildcard scope *.example; fail-closed scope/targets kosong.
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

import coverage_ledger as cl  # noqa: E402

SCOPE = """
# program scope
example.com
*.corp.example
https://api.example.com/v2
"""

FINDINGS_OOS = {"ok": True, "data": {}, "findings": [
    {"tool": "wp-posture", "title": "A", "target_url": "https://example.com"},
    {"tool": "wp-posture", "title": "B", "target_url": "https://app.corp.example"},
    {"tool": "wp-posture", "title": "C", "target_url": "https://evil.example.net"},
    {"tool": "wp-posture", "title": "D", "target_url": "https://api.example.com/v2/x"},
], "requests": 0}

FINDINGS_FULL = {"ok": True, "data": {}, "findings": [
    {"tool": "wp-posture", "title": "A", "target_url": "https://example.com"},
    {"tool": "wp-posture", "title": "B", "target_url": "https://app.corp.example"},
    {"tool": "wp-posture", "title": "D", "target_url": "https://api.example.com"},
], "requests": 0}


class CoverageLedgerTest(unittest.TestCase):
    def _run(self, tmp: Path, findings, extra: "list[str]" = None,
             scope: str = None) -> dict:
        ps = tmp / "scope.txt"
        ps.write_text(scope if scope is not None else SCOPE,
                      encoding="utf-8")
        pf = tmp / "f.json"
        if isinstance(findings, str):
            pf.write_text(findings, encoding="utf-8")
        else:
            pf.write_text(json.dumps(findings), encoding="utf-8")
        out = tmp / "o.json"
        argv = ["--scope", str(ps), "--targets", str(pf), "--out", str(out)]
        if extra:
            argv = argv + extra
        rc = cl.main(argv)
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_oos_hit_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), FINDINGS_OOS)
            self.assertIn("oos-target-hit", d["signals"])
            self.assertIn("evil.example.net", d["evidence"]["oos-hosts"])
            self.assertEqual(d["out_of_scope"], ["evil.example.net"])
            # coverage 3/3 scope host tercover -> tidak thin
            self.assertNotIn("coverage-thin", d["signals"])
            self.assertEqual(d["severity"], "low")  # 1 sinyal = low

    def test_oos_plus_thin_high(self):
        # scope 4 host (1 tak tersentuh) + 1 OOS + min-ratio 0.9 ->
        # ratio 3/4 = 0.75 < 0.9 -> 2 sinyal = medium
        scope = "example.com\n*.corp.example\nhttps://api.example.com/v2\nunused.scope.example\n"
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), FINDINGS_OOS,
                          extra=["--min-ratio", "0.9"], scope=scope)
            self.assertIn("oos-target-hit", d["signals"])
            self.assertIn("coverage-thin", d["signals"])
            self.assertEqual(d["severity"], "medium")

    def test_full_coverage_clean(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), FINDINGS_FULL)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["coverage_ratio"], 1.0)
            self.assertEqual(d["clean_count"], 1)

    def test_urls_file_supported(self):
        with tempfile.TemporaryDirectory() as td:
            ps = Path(td) / "scope.txt"
            ps.write_text("example.com\n", encoding="utf-8")
            pu = Path(td) / "urls.txt"
            pu.write_text("https://example.com/a\nhttps://off.example.org\n",
                          encoding="utf-8")
            out = Path(td) / "o.json"
            rc = cl.main(["--scope", str(ps), "--targets", str(pu),
                          "--out", str(out)])
            self.assertEqual(rc, 0)
            d = json.loads(out.read_text(encoding="utf-8"))
            self.assertIn("oos-target-hit", d["signals"])
            self.assertIn("off.example.org", d["evidence"]["oos-hosts"])

    def test_empty_scope_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            ps = Path(td) / "scope.txt"
            ps.write_text("# only comments\n", encoding="utf-8")
            pf = Path(td) / "f.json"
            pf.write_text(json.dumps(FINDINGS_FULL), encoding="utf-8")
            rc = cl.main(["--scope", str(ps), "--targets", str(pf),
                          "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            rc = cl.main(["--scope", str(Path(td) / "no.txt"),
                          "--targets", str(Path(td) / "no2.json")])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
