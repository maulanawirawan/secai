"""Test snaffler_log_triage — NOL jaringan, output Snaffler di-mock.

Kontrak: {RED}/{BLACK} -> snaffler-black-red high tier; cred marker ->
penguat; file-class path -> lead; hanya {GREEN} -> low-tier inventory;
tanpa tag warna -> exit 2.
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

import snaffler_log_triage as st  # noqa: E402

SNF_BAD = """
{RED}[Found Password in text file]#password=Sup3rS3cret!  C:\\Share\\configs\\web.config (12KB)
{BLACK}[Found Private Key]#-----BEGIN RSA PRIVATE KEY-----  C:\\Share\\keys\\id_rsa (1KB)
{YELLOW}[Found Interesting File]#readme.txt  C:\\Share\\docs\\readme.txt
"""

SNF_GREEN_ONLY = """
{GREEN}[Found Interesting File]#notes  C:\\Share\\docs\\notes.txt
{GREEN}[Found Interesting File]#list  C:\\Share\\docs\\list.txt
"""

NO_SNAFFLER = """
plain file listing:
C:\\Share\\docs\\readme.txt
no color tags in this log at all
"""


class SnafflerLogTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.log"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = st.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_red_black_cred_file_class_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SNF_BAD)
            for sig in ("snaffler-black-red", "snaffler-cred-marker",
                        "snaffler-file-class"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["severity"], "high")
            self.assertEqual(d["tag_counts"]["BLACK"], 1)
            self.assertEqual(d["tag_counts"]["RED"], 1)

    def test_green_only_low_tier(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SNF_GREEN_ONLY)
            self.assertEqual(d["signals"], ["snaffler-low-tier"])
            self.assertEqual(d["severity"], "low")
            self.assertNotIn("snaffler-black-red", d["signals"])

    def test_no_tag_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_SNAFFLER, encoding="utf-8")
            rc = st.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = st.main(["--file", r"D:/nonexistent/__no__.log"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
