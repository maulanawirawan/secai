"""Doc truth — every count claim in the public docs matches the repo.

The counts drifted for several waves (README said 95 skills / 200 tools /
301 or 336 scripts while the registry held 111 skills and tools/ held 226
tools; SKILL.md said 93). This test derives the truth from the repo and
checks every recognised count phrase in README.md, README.es.md,
README.zh.md, AGENTS.md and SKILL.md, so a count-changing commit cannot
land without updating the docs in the same commit.

Definitions (the same ones the docs use):
  skills  = entries in skills/registry.json (the allowlist)
  tools   = tools/*.py excluding private helper modules (leading "_")
  scripts = skills + tools  (every user-facing command-line entry point)
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def truth() -> dict[str, int]:
    reg = json.loads((ROOT / "skills" / "registry.json")
                     .read_text(encoding="utf-8"))
    skills = len(reg["skills"])
    tools = len([p for p in (ROOT / "tools").glob("*.py")
                 if not p.name.startswith("_")])
    return {"skills": skills, "tools": tools, "scripts": skills + tools}


# (regex with one numeric group, which count it must equal)
PATTERNS: list[tuple[str, str]] = [
    (r"badge/skills-(\d+)-", "skills"),
    (r"badge/tools-(\d+)-", "tools"),
    (r"badge/capabilities-(\d+)-", "scripts"),
    (r"\b(\d+) (?:registered )?detection skills", "skills"),
    (r"\b(\d+) offline triage tools", "tools"),
    (r"\b(\d+) scripts\b", "scripts"),
    (r"\b(\d+) standalone", "skills"),
    (r"list the (\d+) skills", "skills"),
    (r"\b(\d+) skills de\b", "skills"),
    (r"\b(\d+) herramientas offline", "tools"),
    (r"(\d+) 个注册检测技能", "skills"),
    (r"(\d+) 个离线工具", "tools"),
    (r"(\d+) 个能力脚本", "scripts"),
    (r"tools/ 下共 (\d+) 个", "tools"),
]
DOCS = ["README.md", "README.es.md", "README.zh.md", "AGENTS.md",
        "SKILL.md"]


class DocCountsTruthTest(unittest.TestCase):
    def test_every_count_claim_matches_repo(self):
        t = truth()
        problems = []
        for doc in DOCS:
            text = (ROOT / doc).read_text(encoding="utf-8")
            hits = 0
            for rx, key in PATTERNS:
                for m in re.finditer(rx, text):
                    hits += 1
                    if int(m.group(1)) != t[key]:
                        line = text.count("\n", 0, m.start()) + 1
                        problems.append(f"{doc}:{line}: '{m.group(0)}' "
                                        f"but {key} = {t[key]}")
            # each doc must actually carry a count claim (non-vacuous)
            self.assertGreater(hits, 0, f"{doc}: no count claim found")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_definitions_are_sane(self):
        t = truth()
        self.assertGreater(t["skills"], 100)
        self.assertGreater(t["tools"], 200)
        # registry is an allowlist: every entry points at a real file
        reg = json.loads((ROOT / "skills" / "registry.json")
                         .read_text(encoding="utf-8"))
        for e in reg["skills"]:
            self.assertTrue((ROOT / e["cmd"][1]).is_file(), e["name"])

    def test_cli_skill_listing_matches_registry(self):
        import io
        import sys
        from contextlib import redirect_stdout
        sys.path.insert(0, str(ROOT))
        import secai
        buf = io.StringIO()
        with redirect_stdout(buf):
            secai.dispatch(["skills"])
        self.assertIn(f"{truth()['skills']} skill", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
