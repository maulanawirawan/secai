"""Test spring_actuator_surface — NOL jaringan, probe di-mock.

Kontrak: /actuator 200 + _links -> medium; env 200 + propertySources ->
high; heapdump 200 + octet-stream -> high; 401 = terlindungi clean;
network fail -> fail-closed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import spring_actuator_surface as sa  # noqa: E402

ACT = '{"_links":{"self":{"href":"http://localhost/actuator"}}}'
ENV = '{"propertySources":[{"name":"s1"}]}'


def res(path, status, body, headers=None, error=None):
    return {"path": path, "status": status,
            "headers": headers or {}, "body": body, "error": error}


class SpringActuatorSurfaceTest(unittest.TestCase):
    def test_all_exposed_high(self):
        rows, meta = sa.audit("https://t.example", [
            res("/actuator", 200, ACT),
            res("/actuator/env", 200, ENV),
            res("/actuator/heapdump", 200, "MZ",
                headers={"Content-Type": "application/octet-stream"}),
        ])
        self.assertTrue(meta["actuator"] and meta["env"] and meta["heapdump"])
        sevs = [r["severity"] for r in rows if r["verdict"] == 1]
        self.assertIn("high", sevs)
        self.assertEqual(len(sevs), 3)

    def test_only_actuator_medium(self):
        rows, meta = sa.audit("https://t.example", [
            res("/actuator", 200, ACT),
            res("/actuator/env", 401, ""),
            res("/actuator/heapdump", 401, ""),
        ])
        self.assertTrue(meta["actuator"])
        self.assertFalse(meta["env"])
        self.assertEqual([r["severity"] for r in rows if r["verdict"] == 1],
                         ["medium"])

    def test_protected_clean(self):
        rows, meta = sa.audit("https://t.example", [
            res("/actuator", 401, ""),
            res("/actuator/env", 401, ""),
            res("/actuator/heapdump", 401, ""),
        ])
        self.assertFalse(meta["actuator"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_wrong_body_zero_fp(self):
        # 200 tapi tanpa marker _links -> tidak diklaim
        rows, meta = sa.audit("https://t.example", [
            res("/actuator", 200, "<html>some page</html>"),
            res("/actuator/env", 200, "{}"),
            res("/actuator/heapdump", 200, "x",
                headers={"Content-Type": "text/html"}),
        ])
        self.assertFalse(meta["actuator"])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = sa.audit("https://t.example", [
            res("/actuator", None, "", error="Err"),
            res("/actuator/env", None, "", error="Err"),
            res("/actuator/heapdump", None, "", error="Err"),
        ])
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
