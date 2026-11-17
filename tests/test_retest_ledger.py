"""Test retest_ledger — NOL jaringan, findings.json di-mock.

Kontrak: persisted / persisted-changed / fixed / new-lead / new-info
akurat; fixed_ratio dari lead lama; fail-closed: file rusak/hilang
-> exit 2.
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

import retest_ledger as rl  # noqa: E402


def doc(rows):
    return {"ok": True, "data": {}, "findings": rows, "requests": 0}


def row(tool, title, target, severity="medium", verdict=1):
    return {"tool": tool, "title": title, "target_url": target,
            "severity": severity, "verdict": verdict}


OLD = doc([
    row("wp-posture", "WP terdeteksi", "https://a.example"),
    row("header-reflection-matrix", "Refleksi XFF", "https://a.example",
        "high", 2),
    row("cors-checker", "CORS lebar", "https://b.example"),
    row("wp-posture", "Info saja", "https://c.example", "info", 0),
])

NEW = doc([
    row("wp-posture", "WP terdeteksi", "https://a.example"),
    row("header-reflection-matrix", "Refleksi XFF", "https://a.example",
        "medium", 1),  # berubah severity
    # cors-checker HILANG di run baru -> fixed
    row("nuclei-runner", "Temuan baru", "https://a.example", "high", 2),
    row("wp-posture", "Info baru", "https://d.example", "info", 0),
])


class RetestLedgerTest(unittest.TestCase):
    def _run(self, tmp: Path, old, new) -> dict:
        po = tmp / "old.json"
        pn = tmp / "new.json"
        po.write_text(json.dumps(old), encoding="utf-8")
        pn.write_text(json.dumps(new), encoding="utf-8")
        out = tmp / "o.json"
        rc = rl.main(["--old", str(po), "--new", str(pn), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_states_complete(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), OLD, NEW)
            c = d["counts"]
            self.assertEqual(c["persisted"], 1)          # wp-posture sama
            self.assertEqual(c["persisted-changed"], 1)  # severity berubah
            self.assertEqual(c["fixed"], 1)              # cors hilang
            self.assertEqual(c["new-lead"], 1)           # nuclei high
            self.assertEqual(c["new-info"], 1)           # info verdict 0

    def test_fixed_ratio(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), OLD, NEW)
            # lead lama = 3 (verdict>=1); fixed 1 -> 0.33
            self.assertEqual(d["fixed_ratio"], 0.33)
            self.assertEqual(d["old_count"], 4)
            self.assertEqual(d["new_count"], 4)

    def test_ledger_states_present(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), OLD, NEW)
            states = {r["state"] for r in d["ledger"]}
            self.assertIn("persisted-changed", states)
            self.assertIn("fixed", states)
            self.assertIn("new-lead", states)

    def test_bare_list_supported(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), OLD["findings"], NEW["findings"])
            self.assertEqual(d["old_count"], 4)

    def test_broken_json_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            po = Path(td) / "old.json"
            po.write_text("not json {{{", encoding="utf-8")
            pn = Path(td) / "new.json"
            pn.write_text(json.dumps(NEW), encoding="utf-8")
            rc = rl.main(["--old", str(po), "--new", str(pn),
                          "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            rc = rl.main(["--old", str(Path(td) / "no1.json"),
                          "--new", str(Path(td) / "no2.json")])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
