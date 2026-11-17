"""Test whoami_priv_triage — NOL jaringan, output whoami di-mock.

Kontrak yang dikunci:
  - tabel /priv dengan SeImpersonate+SeDebug Enabled + SeBackup
    Disabled -> priv-dangerous-enabled + priv-dangerous-disabled;
  - /groups dengan BUILTIN\\Administrators "Enabled group" ->
    group-admin-enabled (kombinasi = high);
  - zero-FP: user standar (SeChangeNotify/SeUndock/SeShutdown disabled)
    -> 0 sinyal clean; daftar privilege tetap ter-inventaris;
  - format csv (/fo csv) ter-parse;
  - fail-closed: teks tanpa konteks whoami -> exit 2; file hilang -> 2.
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

import whoami_priv_triage as wpt  # noqa: E402

PRIV_TABLE = """
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                           State
============================= ===================================== ========
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process    Disabled
SeSecurityPrivilege           Manage auditing and security log      Disabled
SeTakeOwnershipPrivilege      Take ownership of files               Disabled
SeBackupPrivilege             Back up files and directories         Disabled
SeRestorePrivilege            Restore files and directories         Disabled
SeSystemEnvironmentPrivilege  Modify firmware environment values    Disabled
SeImpersonatePrivilege        Impersonate a client after auth       Enabled
SeDebugPrivilege              Debug programs                        Enabled
SeAssignPrimaryTokenPrivilege  Replace a process-level token        Enabled
"""

PRIV_USER = """
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                           State
============================= ===================================== ========
SeShutdownPrivilege           Shut down the system                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking              Enabled
SeUndockPrivilege             Remove computer from docking station  Disabled
SeIncreaseWorkingSetPrivilege  Increase a process working set       Disabled
"""

GROUPS_ADMIN = """
GROUPS INFORMATION
------------------

Group Name                             Type             Attributes
====================================== ================ ==================
BUILTIN\\Administrators                Alias            Enabled group
Everyone                               Well-known group Mandatory group
"""

PRIV_CSV = '''
"Privilege Name","Description","State"
"SeImpersonatePrivilege","Impersonate a client after auth","Enabled"
"SeBackupPrivilege","Back up files and directories","Disabled"
'''

NO_CONTEXT = """
nginx access log: 200 GET /health from 10.0.0.9.
Nothing about privileges, tokens, or groups here.
"""


class WhoamiPrivTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.txt"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = wpt.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_table_privileges_parsed(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), PRIV_TABLE)
            self.assertEqual(d["format"], "table")
            self.assertIn("priv-dangerous-enabled", d["signals"])
            self.assertIn("priv-dangerous-disabled", d["signals"])
            self.assertEqual(d["evidence"]["enabled"],
                             "SeImpersonatePrivilege, SeDebugPrivilege, "
                             "SeAssignPrimaryTokenPrivilege")
            self.assertEqual(d["severity"], "medium")

    def test_admin_group_combo_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), PRIV_TABLE + "\n" + GROUPS_ADMIN)
            for sig in ("priv-dangerous-enabled", "priv-dangerous-disabled",
                        "group-admin-enabled"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["severity"], "high")

    def test_standard_user_zero_fp(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), PRIV_USER)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)
            # inventaris tetap lengkap
            self.assertEqual(len(d["privileges"]), 4)

    def test_csv_format_parsed(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), PRIV_CSV)
            self.assertEqual(d["format"], "csv")
            self.assertIn("priv-dangerous-enabled", d["signals"])
            self.assertIn("priv-dangerous-disabled", d["signals"])

    def test_no_context_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_CONTEXT, encoding="utf-8")
            rc = wpt.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = wpt.main(["--file", r"D:/nonexistent/__no__.txt"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
