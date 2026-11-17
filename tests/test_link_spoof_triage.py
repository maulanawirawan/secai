"""Test link_spoof_triage — NOL jaringan, artefak HTML/JS di-mock.

Kontrak yang dikunci:
  - halaman spoof klasik: <a href="https://bank.example"> + handler
    preventDefault() + window.location = "https://phish.example" ->
    preventdefault-redirect + href-target-mismatch (medium);
  - + inline onclick nav + status-bar spoof -> >= 3 (high);
  - zero-FP SPA: preventDefault utk modal/router dgn navigasi RELATIF
    ("/dashboard") -> 0 sinyal clean;
  - zero-FP halaman anchor biasa tanpa handler -> fail-closed exit 2
    (bukan konteks handler);
  - window.open absolut + PD -> preventdefault-redirect;
  - status-bar spoof berdiri sendiri -> low;
  - file hilang / tanpa konteks -> exit 2.
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

import link_spoof_triage as lst  # noqa: E402

SPOOF_PAGE = """
<html><body>
<a href="https://bank.example/login" id="go">Continue to your bank</a>
<script>
document.getElementById('go').addEventListener('click', function(ev) {
  ev.preventDefault();
  window.location = "https://phish.example/collect?u=x";
});
</script>
</body></html>
"""

SPOOF_FULL = """
<html><body>
<a href="https://mail.example/inbox" onclick="track();">Open inbox</a>
<a href="https://mail.example/addr" onclick="window.open('https://evil.example/x')">Add</a>
<script>
document.querySelectorAll('a').forEach(function(a) {
  a.addEventListener('click', function(ev) {
    ev.preventDefault();
    location.href = "https://evil.example/harvest";
  });
});
window.status = "https://mail.example/inbox";
</script>
</body></html>
"""

SPA_CLEAN = """
<html><body>
<a href="#" id="openModal">Settings</a>
<form id="f"><a href="/docs" id="d">Docs</a></form>
<script>
document.getElementById('openModal').addEventListener('click', function(ev) {
  ev.preventDefault();  // modal UI, tidak ada navigasi absolut
  showModal();
});
document.getElementById('f').addEventListener('submit', function(ev) {
  ev.preventDefault();
  router.push('/dashboard');
});
</script>
</body></html>
"""

STATUS_ONLY = """
<html><body>
<a href="https://ok.example/page">Home</a>
<script>
self.status = "https://appearing.example/nowhere";
</script>
</body></html>
"""

OPEN_ONLY = """
<html><body>
<a href="https://portal.example/start">Start</a>
<script>
document.getElementById('x') && document.addEventListener('click', function(ev) {
  ev.preventDefault();
  window.open("https://tracker.example/pixel");
});
</script>
</body></html>
"""

PLAIN_ANCHOR = """
<html><body><a href="https://example.com/x">plain link</a>
<p>no javascript at all</p></body></html>
"""


class LinkSpoofTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.html"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = lst.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_classic_spoof_medium(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SPOOF_PAGE)
            for sig in ("preventdefault-redirect", "href-target-mismatch"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["severity"], "medium")
            self.assertEqual(d["evidence"]["nav-domain"], "phish.example")
            self.assertEqual(d["evidence"]["bait-href"], "bank.example")

    def test_full_spoof_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SPOOF_FULL)
            for sig in ("preventdefault-redirect", "href-target-mismatch",
                        "inline-onclick-nav", "status-bar-spoof"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["severity"], "high")

    def test_spa_router_zero_fp(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SPA_CLEAN)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["clean_count"], 1)

    def test_window_open_variant(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), OPEN_ONLY)
            self.assertIn("preventdefault-redirect", d["signals"])
            # domain nav tidak ada bait berbeda: tracker.example vs
            # portal.example — mismatch terdeteksi
            self.assertIn("href-target-mismatch", d["signals"])
            self.assertEqual(d["severity"], "medium")

    def test_status_only_low(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), STATUS_ONLY)
            self.assertEqual(d["signals"], ["status-bar-spoof"])
            self.assertEqual(d["severity"], "low")

    def test_plain_anchor_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.html"
            src.write_text(PLAIN_ANCHOR, encoding="utf-8")
            rc = lst.main(["--file", str(src), "--out", str(Path(td) / "o")])
            self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = lst.main(["--file", r"D:/nonexistent/__no__.html"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
