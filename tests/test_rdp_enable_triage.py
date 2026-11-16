"""Test rdp_enable_triage — NOL jaringan, dump di-mock.

Kontrak yang dikunci:
  - dump pengaktifan RDP lengkap (enable action + NLA off + firewall
    3389 + session success) terskor high;
  - zero-FP: registry dump dengan fDenyTSConnections = 1 (RDP memang
    mati, port 3389, tanpa log session) -> 0 sinyal, clean;
  - sinyal deterministik (rdp-allow-state/rdp-enable-action/nla-disabled/
    fw-3389-open/rdp-session-success/port-nonstandard);
  - fail-closed: dump tanpa konteks RDP -> exit 2 via main; file hilang
    -> 2.
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

import rdp_enable_triage as rt  # noqa: E402

ENABLE = r"""
PS> Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
PS> reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /d 0 /f
PS> netsh advfirewall firewall add rule name="RDP" dir=in action=allow protocol=TCP localport=3389
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
EventID: 1149
User: LAB\admin — Source Network Address: 10.20.0.9 — session connection succeeded.
"""

STATE_DUMP = r"""
reg query HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections
    fDenyTSConnections    REG_DWORD    0x0
reg query "HKLM\...\RDP-Tcp" /v UserAuthentication
    UserAuthentication    REG_DWORD    0x0
"""

CLEAN = r"""
reg query HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections
    fDenyTSConnections    REG_DWORD    0x1
reg query "HKLM\...\RDP-Tcp" /v PortNumber
    PortNumber    REG_DWORD    0xd3d
Security log: EventID 4624 Logon Type 3 network logon from 10.0.4.1.
"""

CUSTOM_PORT = r"""
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber
    PortNumber    REG_DWORD    0x2ee0
reg query HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections
    fDenyTSConnections    REG_DWORD    0x0
"""

NO_RDP = r"""
docker compose logs: container started, healthcheck passed, nginx reloaded.
Nothing in this dump mentions remote administration at all.
"""


class RdpEnableTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.txt"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = rt.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_enable_scores_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), ENABLE)
            self.assertEqual(d["severity"], "high")
            self.assertGreaterEqual(d["score"], 3)
            for sig in ("rdp-enable-action", "nla-disabled", "fw-3389-open",
                        "rdp-session-success"):
                self.assertIn(sig, d["signals"])

    def test_state_dump_signals(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), STATE_DUMP)
            for sig in ("rdp-allow-state", "nla-disabled"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["finding_count"], 1)

    def test_clean_dump_is_zero_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), CLEAN)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)

    def test_nonstandard_port_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), CUSTOM_PORT)
            self.assertIn("port-nonstandard", d["signals"])
            self.assertIn("port", d["evidence"])

    def test_fail_closed_no_rdp(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_RDP, encoding="utf-8")
            self.assertEqual(rt.main(["--file", str(src)]), 2)

    def test_fail_closed_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(
                rt.main(["--file", str(Path(td) / "missing.txt")]), 2)


if __name__ == "__main__":
    unittest.main()
