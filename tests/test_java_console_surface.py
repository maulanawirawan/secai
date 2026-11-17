"""Test java_console_surface — NOL jaringan, probe di-mock.

Kontrak: marker konsol (Tomcat/JBoss/WebLogic) 200 -> high per konsol;
401 = terlindungi clean; body tanpa signature -> clean zero-FP;
network fail -> fail-closed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import java_console_surface as jc  # noqa: E402

TOMCAT = "<html><title>Tomcat Web Application Manager</title></html>"
JBOSS = "<html><h1>Welcome to the JBoss JMX Console</h1></html>"
WEBLOGIC = "<html><title>Oracle WebLogic Server Console</title></html>"


def res(path, status, body, error=None):
    return {"path": path, "status": status, "headers": {}, "body": body,
            "error": error}


class JavaConsoleSurfaceTest(unittest.TestCase):
    def test_tomcat_manager_high(self):
        rows, meta = jc.audit("https://t.example", [
            res("/manager/html", 200, TOMCAT),
            res("/jmx-console/", 404, ""),
            res("/web-console/", 404, ""),
            res("/console/login/LoginForm.jsp", 404, ""),
        ])
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(len(lead), 1)
        self.assertEqual(lead[0]["severity"], "high")
        self.assertIn("Tomcat Manager", lead[0]["title"])

    def test_multiple_consoles(self):
        rows, meta = jc.audit("https://t.example", [
            res("/manager/html", 401, ""),
            res("/jmx-console/", 200, JBOSS),
            res("/web-console/", 404, ""),
            res("/console/login/LoginForm.jsp", 200, WEBLOGIC),
        ])
        lead = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(len(lead), 2)
        self.assertTrue(meta["exposed"])

    def test_401_protected_clean(self):
        rows, meta = jc.audit("https://t.example", [
            res("/manager/html", 401, ""),
            res("/jmx-console/", 401, ""),
            res("/web-console/", 404, ""),
            res("/console/login/LoginForm.jsp", 401, ""),
        ])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_generic_page_zero_fp(self):
        # 200 dengan body generik tanpa signature -> tidak diklaim
        rows, meta = jc.audit("https://t.example", [
            res("/manager/html", 200, "<html>Dashboard</html>"),
            res("/jmx-console/", 200, "<html>Index</html>"),
            res("/web-console/", 404, ""),
            res("/console/login/LoginForm.jsp", 404, ""),
        ])
        self.assertTrue(all(r["verdict"] == 0 for r in rows))

    def test_network_fail_fail_closed(self):
        rows, meta = jc.audit("https://t.example", [
            res("/manager/html", None, "", error="Err"),
            res("/jmx-console/", None, "", error="Err"),
            res("/web-console/", None, "", error="Err"),
            res("/console/login/LoginForm.jsp", None, "", error="Err"),
        ])
        self.assertTrue(any("tanpa klaim AMAN" in r["title"] for r in rows))


if __name__ == "__main__":
    unittest.main()
