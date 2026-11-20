"""Suite-wide test isolation.

`sys.argv` is process-global. Several tests drive a CLI's argument-less
main() by assigning sys.argv, and one restored it to a fixed value
instead of the original (tests/test_fp_regression.py), which made
tests/test_f37_ops.py::ReportPackProgramsTest::test_empty_selection_exit
fail whenever it ran AFTER that file (reproduced: reversed file order,
2026-11-20 — see docs/KNOWN-ISSUES.md). Snapshotting and restoring argv
around every test removes the whole class of order dependence without
editing any existing test.
"""
from __future__ import annotations

import sys

import pytest


@pytest.fixture(autouse=True)
def _isolate_sys_argv():
    saved = list(sys.argv)
    try:
        yield
    finally:
        sys.argv[:] = saved
