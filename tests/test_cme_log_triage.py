"""Test cme_log_triage — NOL jaringan, output konsol di-mock.

Kontrak yang dikunci:
  - output CME sukses + Pwn3d! + Dumped NTLM + SMB signing -> 4 sinyal
    (high); host sukses >= 3 -> cme-lateral-hosts;
  - zero-FP: output CME semua kegagalan [-] -> 0 sinyal clean;
  - fail-closed: teks tanpa konteks CME/nxc -> exit 2; file hilang -> 2;
  - baris [-] tidak pernah menjadi temuan.
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

import cme_log_triage as clt  # noqa: E402

CME_SUCCESS = """
SMB         10.0.0.5      445    DC01           [+] corp.lab\\jdoe:Passw0rd! (Pwn3d!)
SMB         10.0.0.6      445    SRV01          [+] corp.lab\\jdoe:Passw0rd!
SMB         10.0.0.7      445    SRV02          [+] corp.lab\\jdoe:Passw0rd! (Pwn3d!)
SMB         10.0.0.5      445    DC01           [+] Dumped NTLM hashes to: /tmp/ntlm.txt
SMB         10.0.0.6      445    SRV01          [-] SMB signing is disabled on this host
"""

CME_FAIL = """
SMB         10.0.0.5      445    DC01           [-] corp.lab\\jdoe:WrongPass STATUS_LOGON_FAILURE
SMB         10.0.0.6      445    SRV01          [-] corp.lab\\jdoe:WrongPass STATUS_LOGON_FAILURE
SMB         10.0.0.7      445    SRV02          [-] corp.lab\\jdoe:WrongPass STATUS_ACCOUNT_LOCKED_OUT
"""

CME_NXC = """
SMB         10.0.0.5      445    DC01           [+] nxc\\svc-backup:Backup123! (Pwn3d!)
LDAP        10.0.0.5      389    DC01           [+] NTDS.dit secretsdump
"""

NO_CONTEXT = """
nginx access log: 200 GET /health from 10.0.0.9.
2026-11-18 user jdoe logged in successfully via console.
"""


class CmeLogTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str, extra: "list[str]" = None) -> dict:
        src = tmp / "in.txt"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        argv = ["--file", str(src), "--out", str(out)]
        if extra:
            argv = argv + extra
        rc = clt.main(argv)
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_success_admin_dump_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), CME_SUCCESS)
            for sig in ("cme-auth-success", "cme-admin-access",
                        "cme-cred-dump", "cme-smb-signing",
                        "cme-lateral-hosts"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["severity"], "high")
            self.assertEqual(d["evidence"]["pwn3d-count"], "2")
            self.assertEqual(d["evidence"]["hosts-count"], "3")

    def test_failures_only_zero_fp(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), CME_FAIL)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)

    def test_nxc_short_form(self):
        # auth sukses + Pwn3d! + NTDS.dit = 3 sinyal (high)
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), CME_NXC)
            for sig in ("cme-auth-success", "cme-admin-access",
                        "cme-cred-dump"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["severity"], "high")

    def test_lateral_threshold_arg(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), CME_SUCCESS, extra=["--many", "5"])
            self.assertNotIn("cme-lateral-hosts", d["signals"])

    def test_no_context_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_CONTEXT, encoding="utf-8")
            rc = clt.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = clt.main(["--file", r"D:/nonexistent/__no__.txt"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
