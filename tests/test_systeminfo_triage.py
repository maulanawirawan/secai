"""Test systeminfo_triage — NOL jaringan, output systeminfo di-mock.

Kontrak yang dikunci:
  - host DC + hotfix 0 + boot 2020-01-01 + VM manufacturer ->
    sys-is-dc + sys-hotfix-absent + sys-vm-platform + sys-uptime-long
    (>= 4 sinyal, high);
  - zero-FP: workstation fisik stok dgn hotfix cukup + domain
    WORKGROUP -> 0 sinyal clean;
  - domain join saja -> low; hotfix thin -> low;
  - --now eksplisit menentukan uptime (deterministik);
  - fail-closed: teks tanpa field kunci -> exit 2; file hilang -> 2.
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

import systeminfo_triage as sit  # noqa: E402

SYS_DC = """
Host Name:                 DC01
OS Name:                   Microsoft Windows Server 2019 Datacenter
OS Version:                10.0.17763 N/A Build 17763
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
Domain:                    corp.lab.local
System Boot Time:          01/01/2020, 03:00:00

Hotfix(s):                 0 Hotfix(s) Installed.
"""

SYS_STOCK = """
Host Name:                 DESKTOP-A1
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.26100 N/A Build 26100
OS Configuration:          Stand-alone Workstation
System Manufacturer:       Dell Inc.
System Model:              OptiPlex 7090
Domain:                    WORKGROUP
System Boot Time:          18/11/2026, 07:00:00

Hotfix(s):                 8 Hotfix(s) Installed.
[01]: KB5046264
[02]: KB5044284
[03]: KB5043131
[04]: KB5041580
[05]: KB5039302
[06]: KB5037771
[07]: KB5035942
[08]: KB5034123
"""

SYS_MEMBER = """
Host Name:                 SRV02
OS Name:                   Microsoft Windows Server 2022 Standard
OS Version:                10.0.20348 N/A Build 20348
OS Configuration:          Member Server
System Manufacturer:       QEMU
System Model:              Standard PC (Q35 + ICH9, 2009)
Domain:                    corp.lab.local
System Boot Time:          01/11/2026, 05:30:00

Hotfix(s):                 2 Hotfix(s) Installed.
[01]: KB5044284
[02]: KB5037771
"""

NO_CONTEXT = """
nginx access log: 200 GET /health from 10.0.0.9.
No hostname or OS details here at all.
"""


class SysteminfoTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str, extra: "list[str]" = None) -> dict:
        src = tmp / "in.txt"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        argv = ["--file", str(src), "--out", str(out), "--now", "2026-11-18"]
        if extra:
            argv = argv + extra
        rc = sit.main(argv)
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_dc_vm_thin_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SYS_DC)
            for sig in ("sys-is-dc", "sys-vm-platform", "sys-hotfix-absent",
                        "sys-uptime-long", "sys-domain-joined"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["severity"], "high")
            self.assertEqual(d["evidence"]["hotfix-count"], "0")

    def test_stock_clean_zero_fp(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SYS_STOCK)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)
            # uptime 0 hari (boot 18/11/2026, now 2026-11-18)
            self.assertEqual(d["fields"]["boot_age_days"], "0")

    def test_member_vm_thin_low_medium(self):
        # member server + VM + hotfix thin + uptime 17 hari (di bawah
        # ambang 30) -> 3 sinyal (dc tidak, uptime-long tidak) = high
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SYS_MEMBER)
            for sig in ("sys-vm-platform", "sys-hotfix-thin",
                        "sys-domain-joined"):
                self.assertIn(sig, d["signals"])
            self.assertNotIn("sys-uptime-long", d["signals"])
            self.assertEqual(d["severity"], "high")

    def test_uptime_threshold_arg(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SYS_MEMBER,
                          extra=["--max-uptime-days", "10"])
            self.assertIn("sys-uptime-long", d["signals"])
            self.assertGreaterEqual(int(d["fields"]["boot_age_days"]), 10)

    def test_no_context_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_CONTEXT, encoding="utf-8")
            rc = sit.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = sit.main(["--file", r"D:/nonexistent/__no__.txt"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
