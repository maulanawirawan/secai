"""Test pingcastle_report_triage — NOL jaringan, laporan di-mock.

Kontrak yang dikunci:
  - XML skor 22 + RiskId rules + points >= 200 -> ad-score-critical +
    ad-rules-listed + ad-points-heavy (high);
  - skor 42 -> ad-score-low + rules (medium);
  - zero-FP: laporan sehat skor 85 tanpa aturan -> 0 sinyal clean;
  - HTML format ("Health score: 42") ter-parse;
  - fail-closed: tanpa konteks AD-health -> exit 2; file hilang -> 2.
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

import pingcastle_report_triage as prt  # noqa: E402

REPORT_BAD_XML = """<?xml version="1.0" encoding="utf-8"?>
<HealthcheckData>
  <Level>Healthcheck</Level>
  <DomainFQDN>corp.lab.local</DomainFQDN>
  <HealthcheckRiskScore>22</HealthcheckRiskScore>
  <RiskRules>
    <RiskRule><RiskId>A-oldPre2000</RiskId><Points>45</Points></RiskRule>
    <RiskRule><RiskId>S-AutoLogon</RiskId><Points>30</Points></RiskRule>
    <RiskRule><RiskId>M-AnonymousAdminCheck</RiskId><Points>25</Points></RiskRule>
    <RiskRule><RiskId>P-DelegatedAccount</RiskId><Points>50</Points></RiskRule>
    <RiskRule><RiskId>T-AltsSvcLookback</RiskId><Points>20</Points></RiskRule>
    <RiskRule><RiskId>S-AdminLogonNotProtected</RiskId><Points>40</Points></RiskRule>
    <RiskRule><RiskId>A-DNSDelegation</RiskId><Points>30</Points></RiskRule>
    <RiskRule><RiskId>A-LAPS-Uninstalled</RiskId><Points>25</Points></RiskRule>
  </RiskRules>
</HealthcheckData>
"""

REPORT_MID_XML = """<?xml version="1.0" encoding="utf-8"?>
<HealthcheckData>
  <DomainFQDN>corp.lab.local</DomainFQDN>
  <HealthcheckRiskScore>42</HealthcheckRiskScore>
  <RiskRules>
    <RiskRule><RiskId>S-AutoLogon</RiskId><Points>30</Points></RiskRule>
    <RiskRule><RiskId>T-AltsSvcLookback</RiskId><Points>20</Points></RiskRule>
  </RiskRules>
</HealthcheckData>
"""

REPORT_GOOD_XML = """<?xml version="1.0" encoding="utf-8"?>
<HealthcheckData>
  <DomainFQDN>corp.lab.local</DomainFQDN>
  <HealthcheckRiskScore>85</HealthcheckRiskScore>
  <RiskRules>
    <RiskRule><RiskId>T-AltsSvcLookback</RiskId><Points>5</Points></RiskRule>
  </RiskRules>
</HealthcheckData>
"""

REPORT_HTML = """
<div class="report">PingCastle report for corp.lab.local
Health score: 42
Rules: S-AutoLogon, T-AltsSvcLookback
</div>
"""

NO_CONTEXT = """
Quarterly ops memo: servers healthy, no findings, no score.
"""


class PingcastleReportTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str, extra: "list[str]" = None) -> dict:
        src = tmp / "in.xml"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        argv = ["--file", str(src), "--out", str(out)]
        if extra:
            argv = argv + extra
        rc = prt.main(argv)
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_bad_score_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), REPORT_BAD_XML)
            for sig in ("ad-score-critical", "ad-rules-listed",
                        "ad-points-heavy"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["health_score"], 22)
            self.assertEqual(d["severity"], "high")
            self.assertEqual(d["format"], "xml")

    def test_mid_score_low(self):
        # 2 rules < ambang min-rules 5 -> ad-rules-listed TIDAK menyala;
        # daftar RiskId tetap masuk evidence
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), REPORT_MID_XML)
            self.assertIn("ad-score-low", d["signals"])
            self.assertNotIn("ad-rules-listed", d["signals"])
            self.assertIn("S-AutoLogon", d["evidence"]["risk-ids"])
            self.assertEqual(d["severity"], "low")

    def test_good_score_zero_fp(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), REPORT_GOOD_XML)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)

    def test_html_format_parsed(self):
        # div laporan well-formed -> xml.etree sanggup parse -> fmt xml
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), REPORT_HTML)
            self.assertEqual(d["format"], "xml")
            self.assertEqual(d["health_score"], 42)
            self.assertIn("ad-score-low", d["signals"])

    def test_points_threshold_arg(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), REPORT_MID_XML,
                          extra=["--min-points", "40"])
            self.assertIn("ad-points-heavy", d["signals"])

    def test_no_context_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_CONTEXT, encoding="utf-8")
            rc = prt.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = prt.main(["--file", r"D:/nonexistent/__no__.xml"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
