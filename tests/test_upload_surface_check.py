"""Test upload_surface_check — NOL jaringan, GET di-mock.

Kontrak: form multipart + input file -> inventori verdict 0; input
tanpa accept -> catatan klien-side; tanpa form -> clean; network fail
-> fail-closed. NOL upload (verdict selalu 0).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import upload_surface_check as us  # noqa: E402

UPLOAD_PAGE = """
<form action="/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="f">
  <input type="submit" value="go">
</form>
<form action="/upload2" method="POST" enctype="multipart/form-data">
  <input type="file" name="g" accept="image/png">
</form>
"""

PLAIN_PAGE = "<html><p>no forms here</p></html>"


def res(status, body, error=None):
    return {"path": "/", "status": status, "body": body, "error": error}


class UploadSurfaceCheckTest(unittest.TestCase):
    def test_upload_inventory(self):
        rows, meta = us.audit("https://t.example", [res(200, UPLOAD_PAGE)])
        self.assertEqual(meta["forms"], 2)
        self.assertEqual(meta["file_inputs"], 2)
        self.assertTrue(all(r["verdict"] == 0 for r in rows))
        found = [r for r in rows if "Permukaan upload" in r["title"]]
        self.assertEqual(len(found), 1)
        self.assertIn("/upload", found[0]["description"])

    def test_no_accept_filter_note(self):
        rows, meta = us.audit("https://t.example", [res(200, UPLOAD_PAGE)])
        note = [r for r in rows if "tanpa filter accept" in r["title"]]
        self.assertEqual(len(note), 1)
        self.assertTrue(meta["file_inputs"] > len([1]))  # 2 input, 1 accept

    def test_no_form_clean(self):
        rows, meta = us.audit("https://t.example", [res(200, PLAIN_PAGE)])
        self.assertEqual(meta["forms"], 0)
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_never_claims_vulnerability(self):
        # kontrak: tool read-only inventori — TIDAK ada verdict 1
        rows, meta = us.audit("https://t.example", [res(200, UPLOAD_PAGE)])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = us.audit("https://t.example",
                              [res(None, "", error="Err")])
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
