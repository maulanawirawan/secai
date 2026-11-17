"""Test laravel_surface — NOL jaringan, probe di-mock.

Kontrak: /.env dgn APP_KEY= -> critical; ignition health-check ->
high; telescope/horizon 200 + token -> medium; halaman SPA 404-style
200 tanpa marker -> clean zero-FP; network fail -> fail-closed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import laravel_surface as ls  # noqa: E402

ENV_FILE = 'APP_NAME=Laravel\nAPP_KEY=base64:AbCdEf123=\nAPP_ENV=production\n'
IGN = '{"canExecuteCommands":false}'
TELE = '<html><title>Telescope</title></html>'
HORI = '<html><title>Horizon Dashboard</title></html>'
SPA = '<html><div id="app"></div></html>'


def res(path, status, body, error=None):
    return {"path": path, "status": status, "headers": {}, "body": body,
            "error": error}


class LaravelSurfaceTest(unittest.TestCase):
    def test_env_critical(self):
        rows, meta = ls.audit("https://t.example", [
            res("/.env", 200, ENV_FILE),
            res("/_ignition/health-check", 404, ""),
            res("/telescope", 404, ""),
            res("/horizon", 404, ""),
        ])
        top = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(len(top), 1)
        self.assertEqual(top[0]["severity"], "critical")
        self.assertIn("APP_KEY", top[0]["description"])

    def test_ignition_high(self):
        rows, meta = ls.audit("https://t.example", [
            res("/.env", 404, ""),
            res("/_ignition/health-check", 200, IGN),
            res("/telescope", 404, ""),
            res("/horizon", 404, ""),
        ])
        top = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(top[0]["severity"], "high")

    def test_telescope_horizon_medium(self):
        rows, meta = ls.audit("https://t.example", [
            res("/.env", 404, ""),
            res("/_ignition/health-check", 404, ""),
            res("/telescope", 200, TELE),
            res("/horizon", 200, HORI),
        ])
        sevs = [r["severity"] for r in rows if r["verdict"] == 1]
        self.assertEqual(sevs, ["medium", "medium"])

    def test_spa_page_zero_fp(self):
        # 200 halaman SPA tanpa marker env -> tidak diklaim
        rows, meta = ls.audit("https://t.example", [
            res("/.env", 200, SPA),
            res("/_ignition/health-check", 200, SPA),
            res("/telescope", 404, ""),
            res("/horizon", 404, ""),
        ])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = ls.audit("https://t.example", [
            res("/.env", None, "", error="Err"),
            res("/_ignition/health-check", None, "", error="Err"),
            res("/telescope", None, "", error="Err"),
            res("/horizon", None, "", error="Err"),
        ])
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
