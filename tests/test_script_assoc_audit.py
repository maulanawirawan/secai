"""Test script_assoc_audit — NOL jaringan, dump registry di-mock.

Kontrak yang dikunci:
  - .reg hijack .vbs -> exe di \\Users\\pub\\evil.exe -> 4 sinyal
    (override + unexpected-bin + lolbin? tidak — evil.exe bukan lolbin
    list; override + unexpected + external = 3) -> high;
  - hijack .hta -> rundll32.exe System32 -> override + unexpected +
    lolbin = 3 (tanpa external) -> high;
  - .vbs -> notepad.exe (hardening "Prevent Script Execution") ->
    override saja = low + evidence, zero-FP utk handler stok;
  - ekspor HKCR stok (JSFile -> wscript, htafile -> mshta, cmdfile
    "%1" %*) -> 0 sinyal clean;
  - asosiasi aplikasi non-script (.myapp -> app.exe) -> exit 2
    (fail-closed, bukan target);
  - format reg query ((Default) REG_SZ ...) juga ter-parse;
  - mutasi reg add /ve pada .js -> assoc-mutation-command;
  - file hilang -> exit 2.
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

import script_assoc_audit as saa  # noqa: E402

HIJACK_VBS = r"""
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\.vbs]
@="VBSFile"

[HKEY_CLASSES_ROOT\VBSFile\shell\open\command]
@="\"C:\\Users\\pub\\evil.exe\" \"%1\" %*"

[HKEY_CLASSES_ROOT\.js]
@="JSFile"

[HKEY_CLASSES_ROOT\JSFile\shell\open\command]
@="\"C:\\Windows\\System32\\wscript.exe\" \"%1\" %*"
"""

HIJACK_HTA_LOLBIN = r"""
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\.hta]
@="htafile"

[HKEY_CLASSES_ROOT\htafile\shell\open\command]
@="\"C:\\Windows\\System32\\rundll32.exe\" \"%1\" %*"
"""

HARDENING_NOTEPAD = r"""
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\VBSFile\shell\open\command]
@="\"C:\\Windows\\System32\\NOTEPAD.EXE\" \"%1\""
"""

STOCK_EXPORT = r"""
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\.js]
@="JSFile"

[HKEY_CLASSES_ROOT\JSFile\shell\open\command]
@="\"C:\\Windows\\System32\\WScript.exe\" \"%1\" %*"

[HKEY_CLASSES_ROOT\.hta]
@="htafile"

[HKEY_CLASSES_ROOT\htafile\shell\open\command]
@="\"C:\\Windows\\System32\\mshta.exe\" \"%1\" {if ne}"

[HKEY_CLASSES_ROOT\.cmd]
@="cmdfile"

[HKEY_CLASSES_ROOT\cmdfile\shell\open\command]
@="\"%1\" %*"

[HKEY_CLASSES_ROOT\.myapp]
@="myappfile"

[HKEY_CLASSES_ROOT\myappfile\shell\open\command]
@="\"C:\\Program Files\\MyApp\\app.exe\" \"%1\""
"""

QUERY_STYLE = r"""
reg query HKEY_CLASSES_ROOT\VBSFile\shell\open\command

HKEY_CLASSES_ROOT\VBSFile\shell\open\command
    (Default)    REG_SZ    "C:\ProgramData\svc\runner.exe" "%1" %*
"""

MUTATION_CMD = r"""
C:\> reg add "HKCR\.js" /ve /d "BadFile" /t REG_SZ /f
C:\> reg add "HKCR\BadFile\shell\open\command" /ve /d "\"C:\Windows\System32\mshta.exe\" \"%1\"" /f
"""

NO_CONTEXT = r"""
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\.myapp]
@="myappfile"

[HKEY_CLASSES_ROOT\myappfile\shell\open\command]
@="\"C:\\Program Files\\MyApp\\app.exe\" \"%1\""
"""


class ScriptAssocAuditTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.txt"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = saa.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_hijack_vbs_external_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), HIJACK_VBS)
            for sig in ("assoc-handler-override", "assoc-unexpected-binary",
                        "assoc-external-path"):
                self.assertIn(sig, d["signals"])
            self.assertNotIn("assoc-lolbin-handler", d["signals"])
            self.assertEqual(d["severity"], "high")
            # .js tetap stok — tidak menambah sinyal
            self.assertNotIn(".js", json.dumps(d["evidence"]))

    def test_hta_lolbin_high_no_external(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), HIJACK_HTA_LOLBIN)
            for sig in ("assoc-handler-override", "assoc-unexpected-binary",
                        "assoc-lolbin-handler"):
                self.assertIn(sig, d["signals"])
            self.assertNotIn("assoc-external-path", d["signals"])
            self.assertEqual(d["severity"], "high")

    def test_notepad_hardening_low_with_note(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), HARDENING_NOTEPAD)
            self.assertEqual(d["signals"], ["assoc-handler-override"])
            self.assertEqual(d["severity"], "low")
            self.assertIn("hardening", d["note"])

    def test_stock_export_zero_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), STOCK_EXPORT)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)
            # .myapp (non-script) TIDAK dinilai
            self.assertNotIn("myapp", d["checked_exts"])

    def test_query_style_parsed_external(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), QUERY_STYLE)
            self.assertIn("assoc-handler-override", d["signals"])
            self.assertIn("assoc-unexpected-binary", d["signals"])
            self.assertIn("assoc-external-path", d["signals"])
            self.assertEqual(d["severity"], "high")

    def test_mutation_command_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), MUTATION_CMD)
            self.assertIn("assoc-mutation-command", d["signals"])
            self.assertIn("reg add", d["evidence"]["mutation"])

    def test_mutation_only_low(self):
        with tempfile.TemporaryDirectory() as td:
            text = (MUTATION_CMD + "\n[HKEY_CLASSES_ROOT\\.js]\n@=\"JSFile\""
                    "\n[HKEY_CLASSES_ROOT\\JSFile\\shell\\open\\command]\n"
                    "@=\"\\\"C:\\\\Windows\\\\System32\\\\wscript.exe\\\" "
                    "\\\"%1\\\" %*\"\n")
            d = self._run(Path(td), text)
            self.assertEqual(d["signals"], ["assoc-mutation-command"])
            self.assertEqual(d["severity"], "low")

    def test_no_context_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_CONTEXT, encoding="utf-8")
            rc = saa.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = saa.main(["--file", r"D:/nonexistent/__no__.reg"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
