"""Test scom_artifact_triage — NOL jaringan, artefak SCOM di-mock.

Kontrak yang dikunci:
  - MP XML dgn <SecureData> + <RunAsAccount> + usage SCOMDecrypt ->
    3 sinyal (high): blob + runas-mp + decrypt-usage;
  - <Password> plaintext terisi -> scom-plaintext-password (isi TIDAK
    dicetak ke evidence, hanya panjang);
  - registry RunAs -> scom-runas-registry;
  - konteks SCOM tanpa artefak kredensial (dok monitoring) -> 0 sinyal
    clean (zero-FP);
  - file tanpa konteks SCOM -> exit 2; file hilang -> exit 2.
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

import scom_artifact_triage as sat  # noqa: E402

MP_FULL = """<?xml version="1.0" encoding="utf-8"?>
<!-- System Center Operations Manager Management Pack export -->
<ManagementPack>
  <TypeDefinitions>
    <Secureable>
      <SecureData ID="Cred.DC">
        <Description>Domain creds</Description>
      </SecureData>
      <RunAsAccount ID="acct.das" AccountType="Simple">
        <Name>Domain Action Account</Name>
      </RunAsAccount>
    </Secureable>
  </TypeDefinitions>
  <Monitoring />
</ManagementPack>
"""

MP_PLAIN_PW = """<?xml version="1.0"?>
<ManagementPack xmlns="http://Schema.Microsoft.Com/SystemCenter/2010/MP">
  <!-- exported sample: RunAs account sample (SCOM) -->
  <Credentials>
    <UserName>SVC-SCOM-Action</UserName>
    <Password>S3cr3t-P4ss!</Password>
  </Credentials>
</ManagementPack>
"""

REG_RUNAS = r"""
reg query "HKLM\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Config.10"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Config.10
    SecureStorageRoot    REG_SZ    ...
"""

DECRYPT_CMD = r"""
C:\tools> SCOMDecrypt.exe --mpfile C:\temp\App.MP.xml --all
PS> Get-SCOMRunAsAccount | Export-Clixml C:\temp\runas.xml
"""

MONITORING_DOC = """
SCOM health service: the Operations Manager agent reports heartbeats
every 60 seconds. Alerts route to the operations console. No secrets
are stored in this document.
"""

NO_CONTEXT = """
nginx access log: 200 GET /health from 10.0.0.9.
Nothing relevant to this triage target in this file at all.
"""


class ScomArtifactTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.xml"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = sat.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_mp_blob_runas_decrypt_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), MP_FULL)
            for sig in ("scom-securedata-blob", "scom-runas-mp"):
                self.assertIn(sig, d["signals"])
            # MP_FULL tidak memuat command decrypt — pakai gabungan
            self.assertEqual(d["severity"], "medium")
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), MP_FULL + "\n" + DECRYPT_CMD)
            for sig in ("scom-securedata-blob", "scom-runas-mp",
                        "scom-decrypt-usage"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["severity"], "high")

    def test_plaintext_password_detected_redacted(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), MP_PLAIN_PW)
            self.assertIn("scom-plaintext-password", d["signals"])
            ev = d["evidence"]["plaintext-pw"]
            self.assertIn("tidak dicetak", ev)
            self.assertNotIn("S3cr3t", json.dumps(d))
            self.assertEqual(d["severity"], "low")

    def test_registry_runas_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), REG_RUNAS)
            self.assertIn("scom-runas-registry", d["signals"])
            self.assertEqual(d["severity"], "low")

    def test_decrypt_usage_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), DECRYPT_CMD)
            self.assertIn("scom-decrypt-usage", d["signals"])
            self.assertEqual(d["severity"], "low")

    def test_monitoring_doc_zero_fp(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), MONITORING_DOC)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)

    def test_no_context_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_CONTEXT, encoding="utf-8")
            rc = sat.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = sat.main(["--file", r"D:/nonexistent/__no__.xml"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
