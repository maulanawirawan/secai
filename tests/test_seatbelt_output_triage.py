"""Test seatbelt_output_triage — NOL jaringan, output enum di-mock.

Kontrak: autologon dgn DefaultPassword -> high-tier signal (isi tidak
dicetak); AlwaysInstallElevated 1 di 2 hive -> high penuh / 1 hive ->
lead; EnableLUA=0 / LATFP=1 -> sb-uac-weak; RunAsPPL=0 -> sb-lsa;
admin group -> konteks low; konfigurasi aman -> clean zero-FP;
tanpa section marker -> exit 2.
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

import seatbelt_output_triage as sbt  # noqa: E402

SB_BAD = """
====== autologon ======
DefaultUserName: svc-backup
DefaultDomain: corp.lab
DefaultPassword: Sup3rSecret1

====== alwayselevatedon ======
HKLM: AlwaysInstallElevated = 1
HKCU: AlwaysInstallElevated = 1

====== uacsettings ======
EnableLUA = 0

====== lsaprotection ======
RunAsPPL = 0

====== localgroupmemberships ======
CORP\\svc-backup - BUILTIN\\Administrators
"""

SB_CLEAN = """
====== autologon ======
DefaultUserName: (empty)
DefaultDomain: corp.lab

====== alwayselevatedon ======
HKLM: AlwaysInstallElevated = 0
HKCU: AlwaysInstallElevated = 0

====== uacsettings ======
EnableLUA = 1

====== lsaprotection ======
RunAsPPL = 1

====== localgroupmemberships ======
corp\\jdoe - BUILTIN\\Users
"""

NO_SECTION = """
random console output without section markers
DefaultPassword: xyz
"""


class SeatbeltOutputTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.txt"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = sbt.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_bad_config_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SB_BAD)
            for sig in ("sb-autologon-creds", "sb-alwayselevated",
                        "sb-uac-weak", "sb-lsa-unprotected",
                        "sb-admin-context"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["severity"], "high")
            # isi password TIDAK pernah dicetak
            self.assertIn("tidak dicetak", d["evidence"]["autologon"])
            self.assertNotIn("Sup3rSecret1", json.dumps(d))

    def test_clean_zero_fp(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SB_CLEAN)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["clean_count"], 1)
            self.assertNotIn("sb-admin-context", d["signals"])

    def test_aie_single_hive_lead(self):
        text = SB_CLEAN.replace("HKCU: AlwaysInstallElevated = 0",
                                "HKCU: AlwaysInstallElevated = 1")
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), text)
            self.assertIn("sb-alwayselevated", d["signals"])
            self.assertIn("1 hive", d["evidence"]["alwayselevated"])

    def test_no_section_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_SECTION, encoding="utf-8")
            rc = sbt.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = sbt.main(["--file", r"D:/nonexistent/__no__.txt"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
