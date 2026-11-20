"""Docs that run — every `<!-- example:NAME -->` block in README.md and
docs/QUICKSTART.md is executed exactly as written.

Per command line the test:
  - honours a leading `VAR=value` environment prefix (e.g. `LAB=1`);
  - rewrites the documented ports to the ephemeral ports of the fixtures
    it started itself (8777 = tools/lab_target.py, 8778 = the JWT
    fixture), so parallel CI runs never collide;
  - resolves repo-relative paths (`skills/`, `tools/`, `tests/`,
    `secai.py`) against the repo root and runs in a temp dir, so the docs'
    output files never litter the checkout;
  - checks the exit code (`# -> exit N`, default 0) and every
    `expect: <substring>` against stdout+stderr.
The 60-second quickstart was broken for several waves (wrong port, a
skill run without evidence, a validator that rejected its own output);
this test makes that class of drift impossible. Zero external network.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "exploit_lab"))

import jwt_verifier  # noqa: E402
import lab_target  # noqa: E402

BLOCK_RE = re.compile(
    r"<!-- example:([\w-]+) -->\s*```bash\n(.*?)```\s*<!-- /example -->",
    re.S)
REPO_PREFIXES = ("skills/", "tools/", "tests/", "secai.py")


def parse_blocks(text: str) -> dict[str, list[dict]]:
    blocks = {}
    for name, body in BLOCK_RE.findall(text):
        cmds = []
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cmd, _, comment = line.partition("#")
            m = re.search(r"->\s*exit\s+(\d+)", comment)
            cmds.append({
                "line": line, "cmd": cmd.strip(),
                "exit": int(m.group(1)) if m else 0,
                "expect": [e.strip() for e in
                           re.findall(r"expect:\s*([^|]+)", comment)]})
        blocks[name] = cmds
    return blocks


class QuickstartDocsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab, cls.lab_url = lab_target.start_lab()
        cls.jwt, cls.jwt_url = jwt_verifier.start()
        cls.ports = {"127.0.0.1:8777": cls.lab_url.split("//")[1],
                     "127.0.0.1:8778": cls.jwt_url.split("//")[1]}

    @classmethod
    def tearDownClass(cls):
        lab_target.stop_lab(cls.lab)
        jwt_verifier.stop(cls.jwt)

    def _run_block(self, cmds: list[dict]) -> None:
        with tempfile.TemporaryDirectory() as td:
            for c in cmds:
                text = c["cmd"]
                for doc_port, real in self.ports.items():
                    text = text.replace(doc_port, real)
                argv = shlex.split(text)
                env = {k: v for k, v in os.environ.items()
                       if k not in ("LAB", "LAB_REMOTE_ACK")}
                env.update(PYTHONIOENCODING="utf-8")
                while argv and re.fullmatch(r"[A-Z_]+=\S*", argv[0]):
                    k, _, v = argv.pop(0).partition("=")
                    env[k] = v
                self.assertEqual(argv[0], "python", c["line"])
                argv = [sys.executable] + [
                    str(ROOT / a) if a.startswith(REPO_PREFIXES) else a
                    for a in argv[1:]]
                p = subprocess.run(argv, cwd=td, env=env,
                                   capture_output=True, timeout=120,
                                   stdin=subprocess.DEVNULL)
                out = (p.stdout + p.stderr).decode("utf-8", "replace")
                with self.subTest(cmd=c["line"]):
                    self.assertEqual(p.returncode, c["exit"], out[-500:])
                    for e in c["expect"]:
                        self.assertIn(e, out)

    def test_quickstart_md_examples_run(self):
        blocks = parse_blocks((ROOT / "docs" / "QUICKSTART.md")
                              .read_text(encoding="utf-8"))
        self.assertEqual(sorted(blocks), ["exploit-lab", "no-evidence",
                                          "offline-triage", "quickstart"])
        for name, cmds in blocks.items():
            with self.subTest(example=name):
                self.assertTrue(cmds)
                self._run_block(cmds)

    def test_readme_quickstart_runs_in_every_language(self):
        for doc in ("README.md", "README.es.md", "README.zh.md"):
            blocks = parse_blocks((ROOT / doc).read_text(encoding="utf-8"))
            with self.subTest(doc=doc):
                self.assertIn("readme-quickstart", blocks)
                self._run_block(blocks["readme-quickstart"])

    def test_parser_reads_exit_and_expect(self):
        b = parse_blocks("<!-- example:x -->\n```bash\n"
                         "LAB=1 python a.py --x 1   # -> exit 2 | "
                         "expect: foo | expect: bar\n```\n"
                         "<!-- /example -->")
        self.assertEqual(b["x"][0]["exit"], 2)
        self.assertEqual(b["x"][0]["expect"], ["foo", "bar"])


if __name__ == "__main__":
    unittest.main()
