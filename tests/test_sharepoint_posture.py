"""Test sharepoint_posture — NOL jaringan, probe di-mock.

Kontrak: token SharePoint eksplisit -> lead medium + versi fakta;
frasa generik -> zero-FP; /_api/web 200 SP -> lead; 401 tanpa token ->
clean; network fail -> fail-closed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import sharepoint_posture as sp  # noqa: E402

SP_BODY = ("<html><title>SharePoint</title>"
           "<script src=/_layouts/15/init.js></script></html>")
API_JSON = '{"d":{"__type":"SP.Web","Title":"Home"}}'


def res(path, status, body, headers=None, error=None):
    return {"path": path, "status": status, "headers": headers or {},
            "body": body, "error": error}


class SharepointPostureTest(unittest.TestCase):
    def test_detected_with_version(self):
        rows, meta = sp.audit("https://t.example", [
            res("/_layouts/15/start.aspx", 200, SP_BODY,
                headers={"MicrosoftSharePointTeamServices": "16.0.10398.20009"}),
            res("/_api/web", 403, ""),
            res("/", 200, ""),
        ])
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["versions"], ["16.0.10398.20009"])
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(len(lead), 1)
        self.assertEqual(lead[0]["severity"], "medium")

    def test_api_open_lead(self):
        rows, meta = sp.audit("https://t.example", [
            res("/_layouts/15/start.aspx", 200, SP_BODY),
            res("/_api/web", 200, API_JSON,
                headers={"X-SharePointHealthScore": "0"}),
            res("/", 200, ""),
        ])
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(len(lead), 2)
        self.assertTrue(meta["api-open"])

    def test_generic_doc_mgmt_zero_fp(self):
        rows, meta = sp.audit("https://t.example", [
            res("/_layouts/15/start.aspx", 404,
                "<html>document management portal</html>"),
            res("/_api/web", 404, ""),
            res("/", 200, "<html>portal</html>"),
        ])
        self.assertFalse(meta["detected"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_401_clean(self):
        rows, meta = sp.audit("https://t.example", [
            res("/_layouts/15/start.aspx", 401, ""),
            res("/_api/web", 401, ""),
            res("/", 401, ""),
        ])
        self.assertFalse(meta["detected"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = sp.audit("https://t.example", [
            res("/_layouts/15/start.aspx", None, "", error="Err"),
            res("/_api/web", None, "", error="Err"),
            res("/", None, "", error="Err"),
        ])
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
