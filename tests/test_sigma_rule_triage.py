"""Test sigma_rule_triage — NOL jaringan, rule Sigma di-mock.

Kontrak yang dikunci:
  - rule cacat lengkap (tanpa detection, tanpa condition, wildcard '*',
    status deprecated, tanpa level+logsource, title TODO) -> 6+ sinyal
    di satu dokumen = high;
  - multi-dokumen: dokumen ke-2 cacat, dokumen ke-1 bersih -> worst-rule
    menentukan severity; signals di-uniq;
  - zero-FP: rule lengkap kondisi spesifik -> 0 sinyal clean;
  - fail-closed: file bukan Sigma -> exit 2; file hilang -> 2.
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

import sigma_rule_triage as srt  # noqa: E402

BROKEN_RULE = """
title: TODO write a better title
id: 11111111-2222-3333-4444-555555555555
status: deprecated
description: broken rule sample
logsource:
    product: windows
    service: security
detection:
    sel1:
        EventID: 4625
        TargetUserName: '*'
    condition: 1 of them
"""

GOOD_RULE = """
title: Failed logon burst for a single account
id: 66666666-7777-8888-9999-000000000000
status: stable
description: detects repeated failed logons
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        LogonType: 10
        TargetUserName|endswith: '-adm'
    timeframe: 5m
    condition: selection | count() > 10
level: medium
"""

NO_DETECTION = """
title: Missing detection section
id: 99999999-0000-0000-0000-000000000000
level: high
logsource:
    product: windows
"""

MULTI = GOOD_RULE + "\n---\n" + BROKEN_RULE

NO_CONTEXT = """
random notes: detection logic discussed verbally.
no yaml rules in this file at all.
"""


class SigmaRuleTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.yml"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = srt.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_broken_rule_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), BROKEN_RULE)
            for sig in ("sigma-condition-broad", "sigma-wildcard-value",
                        "sigma-status-deprecated", "sigma-no-level",
                        "sigma-title-placeholder"):
                self.assertIn(sig, d["signals"])
            # logsource ada, detection ada + condition ada
            self.assertNotIn("sigma-no-logsource", d["signals"])
            self.assertNotIn("sigma-no-detection", d["signals"])
            self.assertNotIn("sigma-no-condition", d["signals"])
            self.assertGreaterEqual(d["score"], 5)
            self.assertEqual(d["severity"], "high")

    def test_good_rule_zero_fp(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), GOOD_RULE)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)

    def test_missing_detection_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), NO_DETECTION)
            self.assertIn("sigma-no-detection", d["signals"])
            # title + level ada; logsource ada
            self.assertNotIn("sigma-no-logsource", d["signals"])

    def test_multi_doc_worst_rule(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), MULTI)
            self.assertEqual(len(d["rules"]), 2)
            self.assertEqual(d["evidence"]["rules"], "2")
            self.assertIn("sigma-condition-broad", d["signals"])
            # dokumen pertama bersih
            first = [r for r in d["rules"] if r["rule"] == 1][0]
            self.assertEqual(first["signals"], [])
            self.assertEqual(d["severity"], "high")

    def test_no_context_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_CONTEXT, encoding="utf-8")
            rc = srt.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = srt.main(["--file", r"D:/nonexistent/__no__.yml"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
