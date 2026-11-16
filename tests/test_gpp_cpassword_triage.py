"""Test gpp_cpassword_triage — NOL jaringan, XML di-mock.

Kontrak yang dikunci:
  - XML GPP dengan cpassword + userName terskor high (cpassword-embedded
    + user-context);
  - zero-FP: XML GPP tanpa cpassword (policy biasa) -> 0 sinyal, clean;
  - sinyal deterministik (cpassword-embedded/user-context/aes-key-
    referenced; plaintext-recovered hanya bila paket kripto tersedia);
  - fail-closed: teks tanpa tag XML/kata kunci GPP -> exit 2 via main;
    file hilang -> 2.
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

import gpp_cpassword_triage as gc  # noqa: E402

# cpassword dummy base64 (bukan kredensial asli; struktur sama)
VULN_XML = r"""<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E9EB-EB46-4A82-BC93-4CBA40FCB9AA}">
  <User clsid="{DF5F1855-51E5-4d24-8A1C-A5B9D2E3B8C3}" name="svc_backup"
        image="0" changed="2026-11-01 12:00:00" uid="{00000001}">
    <Properties action="C" name="svc_backup" fullName="" description=""
                cpassword="nJF2WQ0cV1xbJ5oPQ1Z4b2a1c3e4r5t6y7u8i9o0pQ="
                failWhenChanged="false" changeLogon="false" neverExpires="true"
                acctDisabled="false" userName="svc_backup"/>
  </User>
</Groups>
"""

CLEAN_XML = r"""<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E9EB-EB46-4A82-BC93-4CBA40FCB9AA}">
  <User clsid="{DF5F1855-51E5-4d24-8A1C-A5B9D2E3B8C3}" name="dev_admin"
        image="0" changed="2026-11-01 12:00:00" uid="{00000002}">
    <Properties action="U" name="dev_admin" fullName="" description=""
                failWhenChanged="false" changeLogon="false"
                neverExpires="false" acctDisabled="false"/>
  </User>
</Groups>
"""

KEYREF_ONLY = r"""
analysis note: GPP cpassword values decrypt with the static AES key
{31B2F340-016D-11D2-945F-00C04FB984F9} published in MS-GPPREF.
"""

NO_GPP = r"""
plain web server access log: GET /healthz 200, POST /api/session 401
"""


class GppCpasswordTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.xml"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = gc.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_cpassword_scores_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), VULN_XML)
            self.assertEqual(d["severity"], "high")
            self.assertGreaterEqual(d["score"], 2)
            for sig in ("cpassword-embedded", "user-context"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["evidence"]["users"].find("svc_backup"), 0)

    def test_clean_gpp_is_zero_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), CLEAN_XML)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)

    def test_key_reference_signal(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), KEYREF_ONLY)
            self.assertIn("aes-key-referenced", d["signals"])

    def test_optional_decrypt_never_breaks(self):
        # plaintext-recovered boleh ada/tidak (tergantung paket kripto),
        # tapi skema tetap konsisten dan tidak pernah error.
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), VULN_XML)
            self.assertIn("schema", d)
            if "plaintext-recovered" in d["signals"]:
                self.assertIn("plaintext_password", d["evidence"])

    def test_fail_closed_no_gpp(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.txt"
            src.write_text(NO_GPP, encoding="utf-8")
            self.assertEqual(gc.main(["--file", str(src)]), 2)

    def test_fail_closed_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(
                gc.main(["--file", str(Path(td) / "missing.xml")]), 2)


if __name__ == "__main__":
    unittest.main()
