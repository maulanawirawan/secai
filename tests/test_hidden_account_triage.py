"""Test hidden_account_triage — NOL jaringan, dump registry di-mock.

Kontrak yang dikunci:
  - .reg dengan dua akun DWORD 0 (satu berpola admin-ish) di bawah
    [...UserList] -> sinyal userlist-hidden-entry + hidden-admin-name
    (medium), daftar nama akurat;
  - hide-action (New-ItemProperty -Value 0 / reg add /d 0) -> sinyal
    hide-action; gabungan .reg + command -> high;
  - zero-FP: dump UserList yang SEMUA entrinya dword:1 (akun dibuat
    terlihat) -> 0 sinyal, clean; DWORD 0 di kunci LAIN tidak dihitung;
  - path UserList tanpa entri ter-parse -> specialaccounts-key (low);
  - fail-closed: tanpa konteks UserList/SpecialAccounts -> exit 2;
    file hilang -> 2;
  - format reg query (HKEY_... + REG_DWORD 0x0) juga ter-parse.
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

import hidden_account_triage as hat  # noqa: E402

UL = ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\"
      "CurrentVersion\\Winlogon\\SpecialAccounts\\UserList")

HIDE_REG = f"""
Windows Registry Editor Version 5.00

[{UL}]
"Support388945a0"=dword:00000000
"Administrator"=dword:00000000

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Other]
"SomeUser"=dword:00000000
"""

CLEAN_REG = f"""
Windows Registry Editor Version 5.00

[{UL}]
"MyUser"=dword:00000001
"Spouse"=dword:00000001
"""

HIDE_CMD = r"""
PS> New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name "ghostadmin" -PropertyType DWord -Value 0
"""

HIDE_CMD_REGADD = r"""
C:\> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v HiddenSvc /t REG_DWORD /d 0 /f
"""

QUERY_STYLE = f"""
reg query {UL}

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList
    HiddenTech    REG_DWORD    0x0
"""

KEY_ONLY = f"""
reg query "{UL}" /k

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList
"""

NO_CONTEXT = """
nginx access log: 200 GET /health from 10.0.0.9.
Nothing about registry, winlogon, or accounts here.
"""


class HiddenAccountTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.txt"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = hat.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_hide_reg_two_accounts_medium(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), HIDE_REG)
            for sig in ("userlist-hidden-entry", "hidden-admin-name"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["hidden_accounts"],
                             ["Support388945a0", "Administrator"])
            self.assertEqual(d["severity"], "medium")
            self.assertEqual(d["finding_count"], 1)

    def test_other_section_dword0_not_counted(self):
        # "SomeUser"=dword:0 ada di kunci lain -> tidak masuk daftar
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), HIDE_REG)
            self.assertNotIn("SomeUser", d["hidden_accounts"])

    def test_hide_action_low_and_combo_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), HIDE_CMD)
            self.assertEqual(d["signals"], ["hide-action"])
            self.assertEqual(d["severity"], "low")
        with tempfile.TemporaryDirectory() as td:
            combined = HIDE_REG + "\n" + HIDE_CMD
            d = self._run(Path(td), combined)
            self.assertGreaterEqual(d["score"], 3)
            self.assertEqual(d["severity"], "high")
            for sig in ("userlist-hidden-entry", "hidden-admin-name",
                        "hide-action"):
                self.assertIn(sig, d["signals"])

    def test_regadd_action_detected(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), HIDE_CMD_REGADD)
            self.assertIn("hide-action", d["signals"])

    def test_query_style_parsed(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), QUERY_STYLE)
            self.assertIn("userlist-hidden-entry", d["signals"])
            self.assertIn("HiddenTech", d["hidden_accounts"])
            self.assertIn("hidden-admin-name", d["signals"])

    def test_clean_visible_entries_zero_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), CLEAN_REG)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)

    def test_key_only_low(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), KEY_ONLY)
            self.assertEqual(d["signals"], ["specialaccounts-key"])
            self.assertEqual(d["severity"], "low")

    def test_fail_closed_no_context(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_CONTEXT, encoding="utf-8")
            self.assertEqual(hat.main(["--file", str(src)]), 2)

    def test_fail_closed_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(
                hat.main(["--file", str(Path(td) / "missing.txt")]), 2)


if __name__ == "__main__":
    unittest.main()
