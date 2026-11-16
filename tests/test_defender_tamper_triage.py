"""Test defender_tamper_triage — NOL jaringan, dump di-mock.

Kontrak yang dikunci:
  - dump tampering lengkap (RTP off + Set-MpPreference + exclusion +
    tamper-protection off) terskor high;
  - zero-FP: log Defender normal (scan completed, signature update
    sukses, RTP enabled) -> 0 sinyal, clean;
  - tiap sinyal deterministik (rtp-disabled/config-tamper/exclusion-add/
    av-suspend/sig-store-removed/tamper-protect-off);
  - fail-closed: dump tanpa konteks Defender -> exit 2 via main; file
    hilang -> 2.
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

import defender_tamper_triage as dt  # noqa: E402

TAMPER = r"""
Microsoft-Windows-Windows Defender/Operational
EventID: 5001
Real-time protection is disabled.

EventID: 5007
Windows Defender configuration has changed.
Old value: DisableAntiSpyware = 0
New value: DisableAntiSpyware = 1

PS> Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true
PS> Add-MpPreference -ExclusionPath "C:\Users\public\payload" -ExclusionProcess "rundll32.exe"
PS> Set-MpPreference -DisableTamperProtection 1
PS> Stop-Service windefend
"""

SUSPEND_ONLY = r"""
operation done with PsSuspend MsMpEng.exe on the lab host
"""

SIG_REMOVE_ONLY = r"""
Remove-Item -Path "C:\ProgramData\Microsoft\Windows Defender\Definition Updates\*" -Recurse
mpasbase.vdm deleted from the definition updates folder
"""

CLEAN = r"""
Microsoft-Windows-Windows Defender/Operational
EventID: 1006
Scan completed: quick scan, no threats detected.
Signature update succeeded, EngineVersion 1.1.24050.0, Antimalware signature updated.
Real-time protection is enabled and running.
EventID: 1150
Resource usage scan finished normally.
"""

NO_DEFENDER = r"""
generic linux syslog dump: sshd accepted publickey for deploy
from 10.0.0.5 port 22; cron daily jobs ran fine; nginx reloaded.
"""


class DefenderTamperTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.txt"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = dt.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_tamper_scores_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), TAMPER)
            self.assertEqual(d["severity"], "high")
            self.assertGreaterEqual(d["score"], 4)
            for sig in ("rtp-disabled", "config-tamper", "exclusion-add",
                        "tamper-protect-off", "av-suspend"):
                self.assertIn(sig, d["signals"])

    def test_each_signal_deterministic(self):
        for text, sig in ((SUSPEND_ONLY, "av-suspend"),
                          (SIG_REMOVE_ONLY, "sig-store-removed")):
            with tempfile.TemporaryDirectory() as td:
                d = self._run(Path(td), text)
                self.assertIn(sig, d["signals"])
                self.assertEqual(d["finding_count"], 1)

    def test_clean_log_is_zero_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), CLEAN)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)
            self.assertEqual(d["finding_count"], 0)

    def test_fail_closed_non_defender(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_DEFENDER, encoding="utf-8")
            self.assertEqual(dt.main(["--file", str(src)]), 2)

    def test_fail_closed_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(
                dt.main(["--file", str(Path(td) / "missing.txt")]), 2)


if __name__ == "__main__":
    unittest.main()
