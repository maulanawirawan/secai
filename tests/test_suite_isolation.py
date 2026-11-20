"""Regression lock for the order-dependent failure found 2026-11-20.

Reproduction before the fix (deterministic):
    python -m pytest tests/test_fp_regression.py tests/test_f37_ops.py
    -> FAILED test_f37_ops.py::ReportPackProgramsTest::test_empty_selection_exit
       FileNotFoundError: 'programs\\index.json'
Cause: test_fp_regression left sys.argv = ["intel_sync.py"]; the victim
calls report_pack.main() with no argv, so argparse read that leaked argv
and fell through to the CWD-relative default programs/index.json.
Fix: tests/conftest.py restores sys.argv around every test; report_pack
fails closed (exit 2) on an unreadable programs file and only creates its
output directory once the input is valid.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import report_pack  # noqa: E402

_ARGV_AT_START = list(sys.argv)


class ArgvIsolationTest(unittest.TestCase):
    # unittest runs methods alphabetically: a_ leaks, b_ must not see it
    def test_a_leaks_argv_on_purpose(self):
        sys.argv = ["leaked-by-test_a.py"]

    def test_b_sees_original_argv(self):
        self.assertNotEqual(sys.argv, ["leaked-by-test_a.py"])
        self.assertEqual(sys.argv, _ARGV_AT_START)


class ReportPackFailClosedTest(unittest.TestCase):
    def _main(self, argv):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return report_pack.main(argv)

    def test_no_accepted_program_returns_2_without_output_dir(self):
        # what test_f37_ops' test_empty_selection_exit intends to check,
        # through the real path (its cfg is never passed to main())
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "programs.json"
            cfg.write_text(json.dumps({"programs": [
                {"id": "b", "domain": "b.example", "accepted": False}]}),
                encoding="utf-8")
            out = Path(td) / "out"
            self.assertEqual(self._main(["--programs", str(cfg),
                                         "--out", str(out)]), 2)
            self.assertFalse(out.exists(), "refused run must not mkdir")

    def test_missing_or_malformed_programs_file_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            bad = Path(td) / "bad.json"
            bad.write_bytes(bytes(range(256)))
            for path in (Path(td) / "nope" / "index.json", bad):
                with self.subTest(path=path.name):
                    self.assertEqual(self._main(["--programs", str(path),
                                                 "--out", str(out)]), 2)
                    self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
