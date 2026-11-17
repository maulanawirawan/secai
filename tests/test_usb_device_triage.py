"""Test usb_device_triage — NOL jaringan, artefak USB di-mock.

Kontrak yang dikunci:
  - .reg USBSTOR 3 device + setupapi install minggu ini -> usbstor-entry
    + usb-friendlyname + setupapi-usb-install + usb-install-recent =
    high; serial ter-inventaris;
  - zero-FP: dump registry tanpa USB -> exit 2 (fail-closed), host
    tanpa riwayat USB tidak dilaporkan "bersih palsu";
  - --days/--many/--now eksplisit (deterministik);
  - setupapi VID/PID parse; serial >= --many -> usb-serial-many;
  - file hilang -> 2.
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

import usb_device_triage as udt  # noqa: E402

USB_REG = r"""
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0\60A44C4F2B9E1&0]
"FriendlyName"="Kingston DataTraveler 3.0 USB Device"
"Class"="DiskDrive"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade\200525391118F1A2A0D1&0]
"FriendlyName"="SanDisk Cruzer Blade USB Device"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_0951&PID_1666\60A44C4F2B9E1]
"FriendlyName"="DataTraveler 3.0"
"""

SETUPAPI = r"""
[Device Install (Hardware initiated) - USB\VID_0781&PID_5583\4C5300012345]
>>>  Section start 2026-11-10 09:12:44.500
     dvi: {Build Driver List}
<<<  Section end 2026-11-10 09:12:45.112
[Device Install (Hardware initiated) - USB\VID_0951&PID_1666\60A44C4F2B9E1]
>>>  Section start 2026-11-15 14:02:01.100
<<<  Section end 2026-11-15 14:02:02.033
"""

MANY_SERIALS = "\n".join(
    r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_X&Prod_Y\SERIAL%d&0]" % i
    for i in range(10))

NO_USB_REG = r"""
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"LastUsedUsername"="admin"
"""


class UsbDeviceTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str, extra: "list[str]" = None) -> dict:
        src = tmp / "in.txt"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        argv = ["--file", str(src), "--out", str(out), "--now", "2026-11-18"]
        if extra:
            argv = argv + extra
        rc = udt.main(argv)
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_reg_plus_setupapi_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), USB_REG + "\n" + SETUPAPI)
            for sig in ("usbstor-entry", "usb-friendlyname",
                        "setupapi-usb-install", "usb-install-recent"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["severity"], "high")
            self.assertIn("Kingston DataTraveler 3.0 USB Device",
                          d["evidence"]["friendly-names"])

    def test_reg_only_medium(self):
        # 2 sinyal inventori (entry + friendlyname) = medium
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), USB_REG)
            for sig in ("usbstor-entry", "usb-friendlyname"):
                self.assertIn(sig, d["signals"])
            self.assertNotIn("setupapi-usb-install", d["signals"])
            self.assertEqual(d["severity"], "medium")

    def test_recent_days_threshold(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td, ), SETUPAPI, extra=["--days", "7"])
            # install 15 Nov (3 hari lalu) -> recent; 10 Nov (8 hari) tidak
            self.assertIn("usb-install-recent", d["signals"])
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SETUPAPI, extra=["--days", "2"])
            self.assertNotIn("usb-install-recent", d["signals"])

    def test_many_serials_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), MANY_SERIALS)
            self.assertIn("usb-serial-many", d["signals"])
            self.assertGreaterEqual(int(d["evidence"]["serial-count"]), 10)

    def test_no_usb_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_USB_REG, encoding="utf-8")
            rc = udt.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = udt.main(["--file", r"D:/nonexistent/__no__.reg"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
