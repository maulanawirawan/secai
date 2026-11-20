# Growth research — why security repositories get adopted

What makes a cybersecurity repository on GitHub widely adopted, measured
on 19 well-known anchors across eight categories, and what secai applied
from it. Written for the maintainer and contributors deciding where
distribution effort goes.

## Method and limits

- **Captured:** 2026-11-20 (UTC). Numbers move daily; treat them as a
  snapshot, not a ranking.
- **Sources, per repo** (all public, fetched without credentials):
  1. `https://api.github.com/repos/<owner>/<repo>` — stars, forks,
     creation date, licence, homepage, topics;
  2. the default-branch `README` and `CONTRIBUTING.md` via
     `https://raw.githubusercontent.com/<owner>/<repo>/<branch>/…`;
  3. `https://github.com/<owner>/<repo>/releases.atom` — the ten most
     recent releases and their dates.
  The repository link in the table is the page each row was taken from.
- **README structure** was measured by regex over the raw file (badges in
  the first 60 lines, demo media, install/quickstart headings, one-line
  package installs, Discord/Slack mentions). It is a heuristic: a demo
  embedded as an SVG cast or hosted image can be missed, so the
  "demo media" count is a floor, not an exact figure.
- **Licence `NOASSERTION`** means GitHub's licence detector could not
  classify the file (custom or annotated licences), not that there is
  none.
- **Two anchors needed correction:** `mitre/caldera` now redirects to
  `apache/caldera` (the API returned the Apache repository; that is what
  the row shows). `Azure/PyRIT` turned out to be a different, recent
  repository (created 2026, 128★); the project the mission meant is
  [microsoft/PyRIT](https://github.com/microsoft/PyRIT) — 4,966★, 1,085
  forks, created 2023-12, homepage `microsoft.github.io/PyRIT` (API
  only; its README was not analysed, so it is excluded from the
  aggregates below).
- **Not measured:** traffic, downloads, contributor counts, star
  history. Nothing here claims causation — these are the habits the
  adopted projects share.

## The anchors

| Repo | Category | Stars | Forks | Created | Licence | Docs/home site | CONTRIBUTING | Badges (top) | Latest release (feed) |
|---|---|---:|---:|---|---|---|---|---:|---|
| [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | knowledge | 82,804 | 17,618 | 2016 | MIT | yes | yes | 3 | 2025-07-26 |
| [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework) | exploitation | 39,620 | 15,055 | 2011 | NOASSERTION | yes | yes | 0 | 2026-11-18 |
| [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) | exploitation | 38,988 | 6,456 | 2012 | NOASSERTION | yes | yes | 7 | 2026-10-30 |
| [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | scanner | 33,127 | 4,039 | 2020 | MIT | yes | yes | 6 | 2026-08-08 |
| [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | secrets | 31,196 | 2,395 | 2018 | MIT | yes | yes | 7 | 2026-03-21 |
| [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | secrets | 29,537 | 2,787 | 2016 | AGPL-3.0 | yes | yes | 4 | 2026-11-19 |
| [enaqx/awesome-pentest](https://github.com/enaqx/awesome-pentest) | knowledge | 27,794 | 5,023 | 2014 | — | no | yes | 0 | none in feed |
| [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) | ai-security | 27,467 | 2,796 | 2023 | MIT | yes | yes | 5 | 2026-11-18 |
| [semgrep/semgrep](https://github.com/semgrep/semgrep) | sast | 17,833 | 1,200 | 2019 | LGPL-2.1 | yes | yes | 12 | 2026-11-18 |
| [Gallopsled/pwntools](https://github.com/Gallopsled/pwntools) | exploitation | 13,873 | 1,881 | 2013 | NOASSERTION | yes | yes | 9 | 2026-11-17 |
| [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | scanner | 13,371 | 3,762 | 2020 | MIT | yes | yes | 5 | 2026-11-12 |
| [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) | offense-automation | 12,889 | 3,272 | 2017 | MIT | no | no | 5 | none in feed |
| [HackTricks-wiki/hacktricks](https://github.com/HackTricks-wiki/hacktricks) | knowledge | 12,792 | 3,231 | 2020 | — | yes | no | 0 | 2025-10-01 |
| [github/codeql](https://github.com/github/codeql) | sast | 10,389 | 2,147 | 2018 | MIT | yes | yes | 0 | 2026-11-19 |
| [NVIDIA/garak](https://github.com/NVIDIA/garak) | ai-security | 10,106 | 1,494 | 2023 | Apache-2.0 | yes | yes | 15 | 2026-10-16 |
| [wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) | cms | 9,861 | 1,350 | 2012 | NOASSERTION | yes | yes | 3 | 2026-11-19 |
| [mitre/caldera](https://github.com/apache/caldera) | offense-automation | 7,542 | 1,420 | 2017 | Apache-2.0 | yes | yes | 6 | 2025-04-24 |
| [protectai/llm-guard](https://github.com/protectai/llm-guard) | ai-security | 3,220 | 478 | 2023 | MIT | yes | yes | 8 | 2025-05-19 |
| [Tuhinshubhra/CMSeeK](https://github.com/Tuhinshubhra/CMSeeK) | cms | 2,596 | 515 | 2018 | GPL-3.0 | no | no | 7 | 2020-07-24 |

### Shared habits (counted over the 19)

| Habit | Repos | Share |
|---|---:|---:|
| Homepage / docs site set on the repository | 16 | 84 % |
| `CONTRIBUTING.md` present | 16 | 84 % |
| ≥ 3 badges in the first 60 README lines | 15 | 79 % |
| Discord or Slack linked from the README | 11 | 58 % |
| A release published in the last 90 days | 10 | 53 % |
| Install / quick-start / usage heading | 10 | 53 % |
| One-line package install shown (brew, pip/pipx, docker, npm, go, gem) | 8 | 42 % |
| `hacktoberfest` topic | 6 | 32 % |
| Demo media detected (GIF / video / asciinema) — floor, see limits | 3 | 16 % |

## Success factors per anchor

Only what the fetched README / metadata show; no guesses about intent.

**Knowledge bases**
- **PayloadsAllTheThings** (82.8k★, the most-starred anchor) — a
  catalogue, not a tool. One sentence of purpose, a browsable web
  version, a fixed per-chapter structure and a `_template_vuln` folder
  so contributors know exactly what to add; CONTRIBUTING linked up top.
- **awesome-pentest** (27.8k★) — a curated list: no code, no releases,
  pure discovery value. Contribution = one line in a list.
- **HackTricks** (12.8k★) — the README is a single line; readers are sent
  to the project's homepage instead.

**Exploitation frameworks**
- **sqlmap** (39.0k★) — one-sentence value proposition, screenshot near
  the top, `git clone` install, "works out of the box" with Python, a
  recorded sample run (asciinema), steady releases.
- **metasploit-framework** (39.6k★) — README is short and points
  outward (docs site); ten releases in the feed between 2026-08-13 and
  2026-11-18 (about one every ten days).
- **pwntools** (13.9k★) — nine badges, first code block at README line 15,
  install section, recent release.

**Scanners & templates**
- **nuclei** (33.1k★) — cover image, README offered in nine languages, badges to
  docs / template library / Discord, a feature list that names **false
  positive reduction** ("simulating real-world steps to verify a
  vulnerability"), table of contents, one-line `go install`.
- **nuclei-templates** (13.4k★) — the content ecosystem as its own repo:
  contributions are templates, not engine code.

**Secrets**
- **gitleaks** (31.2k★) — the **real output of a run** (a found secret
  with rule and entropy) is the first thing on the page, six badges,
  `brew` / `docker` one-liners, docs site.
- **trufflehog** (29.5k★) — three-word tagline, a **live count badge**
  ("Total Detectors" computed from the repo's detector directory), the
  pitch structured as Discovery → Classification → **Validation** →
  Analysis (it proves a found secret is live), demo SVG, `docker run`
  and `brew` one-liners, Slack + Discord.

**Offense automation**
- **atomic-red-team** (12.9k★) — small, portable tests mapped to MITRE
  ATT&CK; the mapping to a shared framework is the hook.
- **caldera** (7.5k★, now Apache) — `docker run` one-liner, docs site.

**SAST**
- **semgrep** (17.8k★) — logo, one-line promise, Homebrew / PyPI / docs
  badges, `pipx` and `brew` installs, very frequent releases.
- **codeql** (10.4k★) — the queries are the product; docs site; a release
  in the feed the day before capture.

**AI security**
- **promptfoo** (27.5k★) — a **two-command quick start** (`npm install -g`
  + `init --example`) before anything else, five badges incl. downloads,
  links bar (website / getting started / red teaming / docs / Discord),
  frequent releases.
- **garak** (10.1k★) — fifteen badges incl. tests on **Linux, Windows and
  macOS**, docs site, PyPI downloads, and an **arXiv paper** badge.
- **llm-guard** (3.2k★) — `pip install` one-liner, docs site.

**CMS**
- **wpscan** (9.9k★) — `brew` and `gem` one-liners, recent releases,
  product page as homepage.
- **CMSeeK** (2.6k★) — seven badges and a clear install section, but no
  release since 2020 and no docs site — the lowest adoption in its
  category here.

## Top 10 patterns, ranked by likely adoption impact

Ranking = how often the pattern appears among the anchors × how directly
it removes a step between "found the repo" and "got value".

| # | Pattern | Evidence | secai |
|---|---|---|---|
| 1 | **A first command that works, with its real output shown** | gitleaks opens with real output; promptfoo's quick start is two commands; sqlmap "works out of the box" | **Applied.** The README quickstart was broken (wrong port, skill run without evidence, validator rejecting its own output). Fixed, real transcript shown, and `tests/test_quickstart_docs.py` executes the README (en/es/zh) and `docs/QUICKSTART.md` blocks on every push. |
| 2 | **One sharp differentiator, stated as a contrast** | nuclei names false-positive reduction; trufflehog's "Validation" step | **Applied.** "What makes it different" table (en/es/zh): no evidence → no claim, offline, deterministic, gated, agent-native, docs that run. |
| 3 | **Content people can use without installing anything** | PayloadsAllTheThings is the most-starred anchor; awesome-pentest; HackTricks | **Applied.** Four new playbooks (Linux / Windows / cloud escalation, auth chains) + a Playbooks section in the README. |
| 4 | **A docs / home site set on the repo** | 16 / 19 | **Partly.** `docs/QUICKSTART.md` is the landing page; the repository *homepage field* and a Pages site need the owner (see below). |
| 5 | **Low-friction install channel** | 8 / 19 show brew / pip / docker / npm one-liners | **Partly.** Documented the CI-tested `docker build` path; publishing to PyPI / Homebrew / a registry needs owner accounts → roadmap. |
| 6 | **A clear contribution path with a template** | 16 / 19 have CONTRIBUTING; PayloadsAllTheThings' `_template_vuln` | **Applied.** CONTRIBUTING rewritten for outsiders: four skill contracts, the tool contract, the bookkeeping list, reference files to copy. |
| 7 | **Truthful badges, including a live count** | 15 / 19 use ≥ 3 badges; trufflehog's computed detector count | **Applied (truth).** Badges existed but showed stale counts (95 skills); counts are now derived and test-checked (`tests/test_doc_counts_truth.py`). |
| 8 | **Visible release cadence** | 10 / 19 released in the last 90 days | **Prepared, not tagged.** One tag exists (v0.1.0); release notes for v0.2.0 are in `docs/RELEASE-NOTES-v0.2.0.md`; tagging is the owner's call (below). |
| 9 | **Community channel** | 11 / 19 link Discord or Slack | **Skipped** — needs the owner to create and moderate one. |
| 10 | **Demo media** | sqlmap asciinema, trufflehog SVG cast, promptfoo GIF (heuristic floor: 3 / 19) | **Skipped** — a text transcript of real output is in place; a recorded cast is on the roadmap. |

Also observed, already present in secai: multi-language READMEs (nuclei
offers nine languages; secai three, now in sync), CI badge, licence badge,
star-history chart.

## secai today (same method, same day)

[maulanawirawan/secai](https://github.com/maulanawirawan/secai) —
1★, 0 forks, created 2026-11-02, 20 topics, **no homepage**. Its GitHub
"About" text still reads *"272 capability scripts (93 detection skills
+ 176 tools …)"* — stale against the repository (113 skills + 227 tools
= 340 entry points). That text is repository metadata, not a file, so
it is not changed by this work.

## Owner actions (need the account, not the code)

1. Update the repository **About** description (suggested: *"Evidence-
   first security engine: 113 detection skills + 227 offline tools, one
   findings contract, lab-gated proofs, MCP. No proof, no report."*).
2. Set the **homepage** to the QUICKSTART page or a Pages site.
3. Tag **v0.2.0** from `docs/RELEASE-NOTES-v0.2.0.md` once the CI run for
   the release commit is green.
4. Consider `hacktoberfest` and `ctf` / `security-scanner` topics, and a
   community channel (Discussions is the zero-maintenance option).
5. Record a 20-second cast of `docs/QUICKSTART.md` §1 for the README.
