"""Test nessus_report_triage — NOL jaringan, laporan .nessus di-mock.

Kontrak yang dikunci:
  - report dgn critical (sev 4) + high dense + uncredentialed + 50 host
    -> 4 sinyal (high); agregasi per severity akurat;
  - zero-FP: report bersih credentialed -> 0 sinyal clean;
  - --min-high threshold arg; fail-closed: bukan XML Nessus -> exit 2;
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

import nessus_report_triage as nrt  # noqa: E402

REPORT_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<NessusClientData_v2>
<Report name="test">
{hosts}
</Report>
</NessusClientData_v2>
"""


def make_host(name: str, high: int = 0, critical: int = 0,
              credentialed: str = "false") -> str:
    items = []
    for i in range(high):
        items.append('<ReportItem port="443" severity="3" pluginID="%d" '
                     'pluginName="High vuln %d" svc_name="https"/>'
                     % (100000 + i, i))
    for i in range(critical):
        items.append('<ReportItem port="445" severity="4" pluginID="%d" '
                     'pluginName="Critical SMB vuln %d" svc_name="cifs"/>'
                     % (200000 + i, i))
    return ('<ReportHost name="%s"><HostProperties>'
            '<tag name="HOST_START">2026-11-15T10:00:00.000</tag>'
            '<tag name="Credentialed_Scan">%s</tag>'
            '</HostProperties>%s</ReportHost>'
            % (name, credentialed, "".join(items)))


REPORT_BAD = REPORT_TEMPLATE.format(hosts="".join([
    make_host("10.0.0.%d" % i, high=6) for i in range(50)
]) + make_host("10.0.0.200", critical=2, high=4))

REPORT_CLEAN = REPORT_TEMPLATE.format(hosts="".join([
    make_host("10.0.1.%d" % i, high=1, credentialed="true")
    for i in range(3)
]))


class NessusReportTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str, extra: "list[str]" = None) -> dict:
        src = tmp / "in.nessus"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        argv = ["--file", str(src), "--out", str(out)]
        if extra:
            argv = argv + extra
        rc = nrt.main(argv)
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_bad_report_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), REPORT_BAD)
            for sig in ("scan-critical-present", "scan-high-dense",
                        "scan-uncredentialed", "scan-many-hosts"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["severity"], "high")
            self.assertEqual(d["host_count"], 51)
            self.assertEqual(d["severity_totals"]["critical"], 2)
            self.assertGreaterEqual(d["severity_totals"]["high"], 300)
            self.assertIn("Critical SMB vuln", d["evidence"]["critical"])

    def test_clean_report_zero_fp(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), REPORT_CLEAN)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)
            self.assertEqual(d["avg_high_per_host"], 1.0)

    def test_min_high_threshold(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), REPORT_CLEAN, extra=["--min-high", "1"])
            self.assertIn("scan-high-dense", d["signals"])

    def test_invalid_xml_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text("not xml at all <<<>>>", encoding="utf-8")
            rc = nrt.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = nrt.main(["--file", r"D:/nonexistent/__no__.nessus"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
