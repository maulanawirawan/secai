"""Test lnk_triage — NOL jaringan, file .lnk dibangun sintetis.

Kontrak yang dikunci:
  - LNK penyalahgunaan lengkap (target cmd.exe + argumen powershell
    encoded + icon UNC mspaint) terskor high dengan semua sinyal;
  - zero-FP: shortcut normal firefox.exe tanpa argumen, icon lokal
    -> 0 sinyal, clean;
  - LNK dengan icon UNC saja -> low; argumen encoded saja -> medium;
  - deterministik: parsing MS-SHLLINK (header/CLSID/flags/StringData);
  - fail-closed: file bukan LNK (header salah/CLSID salah) -> exit 2;
    file hilang -> 2.
"""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys_path = str(ROOT / "tools")
if sys_path not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_path)

import lnk_triage as lt  # noqa: E402

LINK_CLSID = bytes.fromhex("0114020000000000C000000000000046")

F_NAME, F_RELPATH, F_WORKDIR, F_ARGS, F_ICON, F_UNICODE = (
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80)


def build_lnk(flags: int, strings: "list[str]") -> bytes:
    """Shell Link minimal: header 76 byte + StringData unicode sesuai
    urutan spec (name, relpath, workdir, args, icon)."""
    hdr = b"".join([
        struct.pack("<I", 0x4C),
        LINK_CLSID,
        struct.pack("<I", flags),
        struct.pack("<I", 0),          # FileAttributes
        b"\x00" * 24,                  # Creation/Access/WriteTime
        struct.pack("<IIHHIII", 0, 0, 1, 0, 0, 0, 0),  # Size..Reserved3
    ])
    assert len(hdr) == 76, len(hdr)
    body = b""
    for val in strings:
        data = val.encode("utf-16-le")
        body += struct.pack("<H", len(val)) + data
    return hdr + body


class LnkTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, data: bytes) -> dict:
        src = tmp / "x.lnk"
        src.write_bytes(data)
        out = tmp / "o.json"
        rc = lt.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_full_abuse_scores_high(self):
        b64 = "jGS9y2hE3pKq7bZw1mXv8cR5tN4uL6oP" * 2  # 64 char base64-ish
        data = build_lnk(F_NAME | F_RELPATH | F_ARGS | F_ICON | F_UNICODE, [
            "Annual Report 2026",                       # label penyamaran
            "C:\\Windows\\System32\\cmd.exe",           # target lolbin
            "cmd.exe /c powershell -nop -w hidden -enc " + b64,
            "\\\\10.0.0.66\\share\\mspaint.ico",        # ikon UNC mspaint
        ])
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), data)
            self.assertEqual(d["severity"], "high")
            for sig in ("lolbin-target", "args-lolbin", "encoded-args",
                        "icon-unc", "icon-disguise"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["finding_count"], 1)
            self.assertEqual(d["evidence"]["target"],
                             "C:\\Windows\\System32\\cmd.exe")

    def test_encoded_args_only_is_medium(self):
        data = build_lnk(F_RELPATH | F_ARGS | F_UNICODE, [
            "tool.lnk",
            "powershell -nop -w hidden -enc " + "jGS9y2hE3pKq7bZw" * 5,
        ])
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), data)
            self.assertIn("encoded-args", d["signals"])
            self.assertIn("args-lolbin", d["signals"])
            self.assertEqual(d["severity"], "medium")

    def test_icon_unc_alone_is_low(self):
        data = build_lnk(F_NAME | F_ICON | F_UNICODE, [
            "shortcut.lnk",
            "\\\\fileserver\\share\\icon.ico",
        ])
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), data)
            self.assertEqual(d["signals"], ["icon-unc"])
            self.assertEqual(d["severity"], "low")

    def test_clean_shortcut_zero_signal(self):
        data = build_lnk(F_NAME | F_RELPATH | F_ICON | F_UNICODE, [
            "Mozilla Firefox",
            "Program Files\\Mozilla Firefox\\firefox.exe",
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe,1",
        ])
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), data)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)
            self.assertEqual(d["findings"], [])

    def test_fail_closed_not_a_lnk(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "notlnk.bin"
            src.write_bytes(b"hello world this is not a shell link")
            self.assertEqual(lt.main(["--file", str(src)]), 2)

    def test_fail_closed_bad_header_size(self):
        hdr = struct.pack("<I", 0x48) + LINK_CLSID + \
            struct.pack("<I", F_NAME | F_UNICODE) + b"\x00" * 56
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "badsize.lnk"
            src.write_bytes(hdr)
            self.assertEqual(lt.main(["--file", str(src)]), 2)

    def test_fail_closed_bad_clsid(self):
        hdr = struct.pack("<I", 0x4C) + b"\x00" * 16 + \
            struct.pack("<I", F_NAME | F_UNICODE) + b"\x00" * 56
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "badclsid.lnk"
            src.write_bytes(hdr + struct.pack("<H", 5) + b"hello")
            self.assertEqual(lt.main(["--file", str(src)]), 2)

    def test_fail_closed_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(
                lt.main(["--file", str(Path(td) / "missing.lnk")]), 2)

    def test_tracker_block_enrichment(self):
        """TrackerDataBlock (0xA0000003): MachineID + droid GUID ter-parse
        sebagai EVIDENCE — skor shortcut normal tetap 0 (bukan sinyal)."""
        def tracker_block(machine: str) -> bytes:
            blk = struct.pack("<II", 0x5C, 0xA0000003) + struct.pack("<I", 0)
            blk += machine.encode("ascii").ljust(16, b"\x00")
            blk += b"\x11" * 16 + b"\x22" * 16   # droid (2 GUID)
            blk += b"\x33" * 16 + b"\x44" * 16   # droidBirth (2 GUID)
            assert len(blk) == 0x5C
            return blk

        data = build_lnk(F_RELPATH | F_UNICODE,
                         ["C:\\Program Files\\Mozilla Firefox\\firefox.exe"])
        data += tracker_block("WORKSTATION-42")
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), data)
            self.assertEqual(d["score"], 0)          # shortcut normal
            self.assertEqual(d["clean_count"], 1)    # tetap clean
            self.assertEqual(d["fields"]["tracker_machine"],
                             "WORKSTATION-42")
            self.assertEqual(d["fields"]["tracker_droid"],
                             "11" * 16 + "22" * 16)

    def test_no_tracker_no_fields(self):
        data = build_lnk(F_RELPATH | F_UNICODE,
                         ["C:\\Windows\\System32\\calc.exe"])
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), data)
            self.assertNotIn("tracker_machine", d["fields"])
            self.assertNotIn("tracker_droid", d["fields"])


if __name__ == "__main__":
    unittest.main()
