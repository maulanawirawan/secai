"""Test patch_guard_triage — NOL jaringan, unified diff di-mock.

Kontrak: guard bounds/overflow/lock + CVE ref -> multi-sinyal high;
diff refactor tanpa guard -> clean zero-FP; dangerous call removed ->
sinyal; bukan unified diff -> exit 2; file hilang -> 2.
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

import patch_guard_triage as pgt  # noqa: E402

FIX_PATCH = """--- a/src/buffer.c
+++ b/src/buffer.c
@@ -10,7 +10,9 @@ int copy(char *dst, char *src)
     // fix for CVE-2026-130001
-    memcpy(dst, src, len);
+    if (len > buf_size) {
+        return -1;
+    }
+    if (__builtin_add_overflow(len, 4, &total)) {
+        return -2;
+    }
+    pthread_mutex_lock(&g_lock);
+    memcpy(dst, src, len);
"""

REFACTOR_PATCH = """--- a/src/util.c
+++ b/src/util.c
@@ -3,5 +3,6 @@ int helper(int x)
-    return x * 2;
+    return x * 2 + 1;
 }
"""

DANGEROUS_REMOVED = """--- a/src/old.c
+++ b/src/old.c
@@ -20,3 +20,2 @@
-    sprintf(buf, user_input);
+    snprintf(buf, sizeof(buf), "%s", user_input);
"""

NOT_DIFF = """
random changelog text
no diff markers here
"""


class PatchGuardTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.patch"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = pgt.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_guards_multi_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), FIX_PATCH)
            for sig in ("pg-guard-bounds", "pg-guard-overflow",
                        "pg-guard-lock", "pg-cve-ref"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["severity"], "high")
            self.assertIn("bounds", d["inferred_classes"])
            self.assertIn("overflow", d["inferred_classes"])

    def test_refactor_clean_zero_fp(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), REFACTOR_PATCH)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["clean_count"], 1)

    def test_dangerous_removed_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), DANGEROUS_REMOVED)
            self.assertIn("pg-dangerous-removed", d["signals"])
            self.assertIn("sprintf", d["evidence"]["dangerous-removed"])
            self.assertEqual(d["severity"], "low")

    def test_not_diff_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NOT_DIFF, encoding="utf-8")
            rc = pgt.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = pgt.main(["--file", r"D:/nonexistent/__no__.patch"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
