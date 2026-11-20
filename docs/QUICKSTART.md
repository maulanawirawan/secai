# secai quickstart — four runnable examples

Everything here runs on your own machine against targets that ship with
the repo. No API keys, no account, no cloud, Python 3.10+ standard
library only. Every command block below is **executed by the test suite**
(`tests/test_quickstart_docs.py`) exactly as written, so if this page
says it works, CI has just checked that it does.

```bash
git clone https://github.com/maulanawirawan/secai && cd secai
```

> **Output language:** status lines are partly Indonesian:
> `temuan` = findings, `AMAN` = clear/safe, `bukti` = evidence,
> `tidak ada klaim` = no claim. Findings files are plain JSON.

---

## 1. See the evidence ladder (60 seconds)

Start the bundled practice target in one terminal — it binds
`127.0.0.1` only:

```bash
python tools/lab_target.py
# lab target aktif: http://127.0.0.1:8777
```

In a second terminal: collect evidence with **one** request, judge it
with **zero** requests, then check the result against the contract.

<!-- example:quickstart -->
```bash
python skills/banner_posture.py --url http://127.0.0.1:8777/ --save-raw evidence.html --out banner.json
python skills/http_security_headers.py --url http://127.0.0.1:8777/ --from-raw evidence.html --out headers.json   # expect: 8 temuan (2 AMAN) (0 request)
python secai.py validate headers.json   # expect: 8 findings valid
```
<!-- /example -->

Real output:

```console
banner-posture: 1 temuan (0 AMAN) (1 request) -> banner.json
http-security-headers: 8 temuan (2 AMAN) (0 request) -> headers.json
[OK      ] headers.json: 8 findings valid against the contract
```

Inside `headers.json`, every row carries its own verdict — and none of
them is reportable, because a missing header is a lead, not a proven
vulnerability:

```
L1 SUSPECTED  low   Security header absent: Content-Security-Policy   reportable: false
L1 SUSPECTED  low   Security header absent: X-Frame-Options           reportable: false
L1 SUSPECTED  low   Security header absent: X-Content-Type-Options    reportable: false
L1 SUSPECTED  info  Security header absent: Referrer-Policy           reportable: false
L1 SUSPECTED  info  Security header absent: Permissions-Policy        reportable: false
L0 OBSERVED   info  No version leak via Server                        reportable: false
L0 OBSERVED   info  No version leak via X-Powered-By                  reportable: false
L1 SUSPECTED  low   Security headers posture: 0/5 present             reportable: false
```

Only `L3`+ (a working, reproduced proof) is ever reportable.

## 2. No evidence, no claim

Ask the same skill to judge evidence that was never captured. Many
scanners would report five "missing headers" here. secai refuses:

<!-- example:no-evidence -->
```bash
python skills/http_security_headers.py --url http://127.0.0.1:8777/ --from-raw never-captured.html --out nothing.json   # -> exit 2 | expect: tidak ada klaim
```
<!-- /example -->

```console
http-security-headers: tidak ada bukti header (.headers) -> tidak ada klaim (fail-closed; ...)
```

Exit code 2, no output file, no findings. A test runs **every**
evidence-only skill this way and fails if any of them claims anything.

## 3. Offline triage — evidence in, verdict out, zero network

Most of secai's 227 tools never touch a network: you hand them an
artefact, they return deterministic findings. Here: is this container
one step away from the host?

<!-- example:offline-triage -->
```bash
python tools/container_escape_check.py --root tests/fixtures/exploit_lab/container/privileged --out privileged.json   # -> exit 1 | expect: privileged-capset
python tools/container_escape_check.py --root tests/fixtures/exploit_lab/container/hardened --out hardened.json   # expect: 0 precondition(s)
```
<!-- /example -->

```console
container-escape-check: 4 precondition(s) ['cgroup-v1-release-agent', 'kernel-fs-writable', 'privileged-capset', 'seccomp-disabled'] -> privileged.json
container-escape-check: 0 precondition(s) [] -> hardened.json
```

The hardened snapshot is the false-positive control: same tool, a
correctly configured container, nothing reported. To check a real
container, copy four files from inside it (recipe in the tool's
docstring) and point `--root` at the copy.

## 4. Proof, behind a lab gate

The exploit-lab tier turns a lead into proof — but only in a lab. Start
the deliberately vulnerable JWT verifier that ships as a test fixture:

```bash
python tests/fixtures/exploit_lab/jwt_verifier.py
# jwt fixture (deliberately vulnerable): http://127.0.0.1:8778
```

<!-- example:exploit-lab -->
```bash
python skills/jwt_lab.py --url http://127.0.0.1:8778/none-vuln --out jwt.json   # -> exit 2 | expect: REFUSED
LAB=1 python skills/jwt_lab.py --url http://127.0.0.1:8778/none-vuln --out jwt.json   # expect: proven=['alg-none'
LAB=1 python skills/jwt_lab.py --url http://127.0.0.1:8778/strict --out jwt-strict.json   # expect: proven=[]
```
<!-- /example -->

```console
[jwt-lab] REFUSED: exploit-lab script: LAB=1 is not set - refusing (lab-only tier, fail-closed). ...
jwt-lab: 3 row(s), proven=['alg-none', 'alg-None', 'alg-NONE'] (9 request) -> jwt.json
jwt-lab: 1 row(s), proven=[] (6 request) -> jwt-strict.json
```

1. Without `LAB=1` the script refuses before sending a single request.
   There is no flag that can replace the variable.
2. Against the vulnerable route, a forged unsigned token is accepted
   **twice** while a no-token request and a random-key token are both
   rejected — that differential is the L3 proof.
3. Against the strict route (the false-positive control) nothing is
   proven.

A non-loopback target additionally needs `LAB_REMOTE_ACK=<written
reason>`, which is recorded in the output. Rules and the full list of
what the tier refuses: [EXPLOIT-TIER.md](EXPLOIT-TIER.md).

---

## Run it in Docker instead

The image is built and smoke-tested in CI on every push:

```bash
docker build -t secai .
docker run --rm secai info
docker run --rm -v "$PWD:/work" secai validate /work/headers.json
```

## Where next

| You are… | Start with |
|---|---|
| hunting bugs on an authorized program | `python secai.py` (mode board), `docs/HUNT-ACTIVE-CLASSES.md` |
| a developer checking your own staging app | `python secai.py skills --class read-only`, then the full engine in [INSTALL.md](INSTALL.md) |
| on a blue team / doing DFIR | the offline tools in `tools/` (`--help` on any of them) |
| escalating in a lab or reviewing hardening | [ESCALATION-LINUX](ESCALATION-LINUX.md), [ESCALATION-WINDOWS](ESCALATION-WINDOWS.md), [ESCALATION-CLOUD](ESCALATION-CLOUD.md), [AUTH-ATTACK-CHAINS](AUTH-ATTACK-CHAINS.md) |
| wiring an AI agent | [SKILL.md](../SKILL.md), [AGENTS.md](../AGENTS.md), `python tools/mcp_server.py` |
| contributing | [CONTRIBUTING.md](../CONTRIBUTING.md) |
