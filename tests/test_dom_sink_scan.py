"""Test dom_sink_scan — NOL jaringan, artefak JS di-mock.

Kontrak yang dikunci:
  - handler message tanpa origin check + event.data -> innerHTML ->
    postmessage-no-origin (medium/dengan url-flow = high);
  - origin check ketat (===) -> 0 sinyal clean (zero-FP);
  - origin check bypassable (indexOf) -> postmessage-origin-weak;
  - location.hash -> innerHTML dalam satu blok -> url-source-to-sink;
  - fail-closed: JS tanpa sink/handler -> exit 2; file hilang -> 2.
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

import dom_sink_scan as dss  # noqa: E402

VULN_POSTMESSAGE = """
window.addEventListener("message", function(ev) {
  document.getElementById("status").innerHTML = ev.data;
});
"""

VULN_POSTMESSAGE_ORIGIN_WEAK = """
window.addEventListener("message", function(ev) {
  if (trustedSites.indexOf(ev.origin) !== -1) {
    document.getElementById("status").innerHTML = ev.data;
  }
});
var trustedSites = ["https://app.example"];
"""

SAFE_POSTMESSAGE = """
window.addEventListener("message", function(ev) {
  if (ev.origin === "https://app.example") {
    document.getElementById("status").textContent = ev.data;
  }
});
"""

URL_FLOW = """
function render() {
  var name = location.hash.slice(1);
  document.getElementById("out").innerHTML = name;
}
window.onload = render;
"""

NO_CONTEXT = """
function add(a, b) { return a + b; }
document.getElementById("btn").onclick = function() { add(1, 2); };
"""


class DomSinkScanTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.js"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = dss.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_postmessage_no_origin_low(self):
        # satu sinyal = low (count-based)
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), VULN_POSTMESSAGE)
            self.assertIn("postmessage-no-origin", d["signals"])
            self.assertEqual(d["severity"], "low")

    def test_postmessage_weak_origin(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), VULN_POSTMESSAGE_ORIGIN_WEAK)
            self.assertIn("postmessage-origin-weak", d["signals"])
            self.assertNotIn("postmessage-no-origin", d["signals"])

    def test_safe_handler_zero_fp(self):
        # origin === literal + textContent (bukan sink) -> clean
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SAFE_POSTMESSAGE)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["clean_count"], 1)

    def test_url_source_to_sink(self):
        # satu sinyal = low (count-based)
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), URL_FLOW)
            self.assertIn("url-source-to-sink", d["signals"])
            self.assertEqual(d["severity"], "low")

    def test_combo_high(self):
        # 2 sinyal independen = medium
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), URL_FLOW + "\n" + VULN_POSTMESSAGE)
            self.assertGreaterEqual(d["score"], 2)
            self.assertEqual(d["severity"], "medium")

    def test_no_context_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.js"
            src.write_text(NO_CONTEXT, encoding="utf-8")
            rc = dss.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = dss.main(["--file", r"D:/nonexistent/__no__.js"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
