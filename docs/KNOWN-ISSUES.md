# Known issues

Honest list of test-suite behaviour that is not fully explained or not
yet fixed. Each entry: what was observed, the exact commands, status.

## KI-1 — order-dependent failure via leaked `sys.argv` — RESOLVED 2026-11-20

- **Observed:** reversed-file-order full run
  `python -m pytest $(ls tests/test_*.py | sort -r) --tb=short -q` →
  `FAILED tests/test_f37_ops.py::ReportPackProgramsTest::test_empty_selection_exit`
  (`FileNotFoundError: 'programs\index.json'`). Normal order passed.
- **Deterministic reproduction:**
  `python -m pytest tests/test_fp_regression.py tests/test_f37_ops.py`
  failed; the opposite file order passed.
- **Cause:** `tests/test_fp_regression.py` resets `sys.argv` to
  `["intel_sync.py"]` instead of the original value. The victim calls
  `report_pack.main()` without arguments, so argparse read the leaked argv
  and opened the CWD-relative default `programs/index.json`; that path
  also created an empty `findings/reports/<date>` folder in the checkout.
- **Fix:** `tests/conftest.py` restores `sys.argv` around every test
  (no existing test edited); `tools/report_pack.py` takes `argv`, exits 2
  on an unreadable programs file, and creates its output folder only after
  the input is valid. Locked by `tests/test_suite_isolation.py` (its argv
  check fails when run with `--noconftest`, i.e. the guard is real).

## KI-2 — `test_empty_selection_exit` depends on how pytest was started — RESOLVED 2026-11-21

- **Proof:** the test writes a `programs.json` but never passes it to
  `report_pack.main()`; it can only pass because argparse *rejects* the
  argv pytest was launched with and raises `SystemExit`. Through the real
  path (`--programs <cfg>`), `main()` returns `2` without raising — see
  `tests/test_suite_isolation.py::ReportPackFailClosedTest`.
- **Commands:** `python -m pytest tests/test_f37_ops.py` → passes;
  `python -c "import sys,pytest; sys.exit(pytest.main(['tests/test_f37_ops.py']))"`
  → fails, both before the KI-1 fix (`FileNotFoundError`) and after it
  (`SystemExit not raised`). CI and the documented command pass.
- **Resolved 2026-11-21 (owner approved):** the test now drives the real
  path — `report_pack.main(["--programs", str(cfg), "--out", td])` with
  `assertEqual(..., 2)`, same pattern as
  `tests/test_suite_isolation.py::ReportPackFailClosedTest`; the
  SystemExit reliance is gone.

## KI-3 — one unidentified failure in a normal-order run — UNREPRODUCED as of 2026-11-20, watched

- **Observed:** one full run during the wave-12 pass (normal order,
  `python -m pytest tests/ -q -p no:cacheprovider`, Windows 11,
  Python 3.12.x, local Rust release build present) reported
  `1 failed, 3801 passed, 33 skipped, 203 subtests`. The failing test's
  name was not captured (the run's output was truncated to its summary
  line).
- **Not reproduced in:** five later normal-order full runs (3802 passed
  each) and the reversed-order run (whose only failure was KI-1, which
  cannot occur in normal order because `test_f37_ops` runs before
  `test_fp_regression`).
- **No named suspect.** Candidates are tests that depend on wall-clock
  timing or real sockets on a loaded machine, but there is no evidence for
  any one of them, so no fix is attempted. If it recurs, run with
  `--tb=short -rf` and add the test name here.
