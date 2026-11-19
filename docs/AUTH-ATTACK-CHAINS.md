# Authentication & session attack chains

Playbook for agents and analysts. Each entry has the same five parts:
**preconditions → probe → escalation step → hardening → lab gate /
fixture**. Patterns only: the probes are request *shapes*, and the proofs
live in gated code that already exists in this repo (exploit-engine
playbooks proven against `tools/lab_target.py`, the `jwt-lab` skill
proven against its fixture) — nothing here is a standalone attack tool.

**Lab gates used below**

| Gate | Where | How it opens |
|---|---|---|
| exploit engine | `tools/exploit_engine.py` + `tools/exploit_playbooks.py` | target config `exploit_allowed: true`, mode `proof`/`mutate` (tier-2 = canary objects + guaranteed cleanup), NEVER-LIST always enforced — see [EXPLOIT-TIER.md](EXPLOIT-TIER.md) |
| exploit-lab skill | `skills/jwt_lab.py`, `skills/ssrf_metadata_lab.py` | env `LAB=1`; non-loopback also `LAB_REMOTE_ACK=<written reason>`; refusal = exit 2 before any request |
| active-probe skill | e.g. `skills/rate_limit_validator.py` | `--lab` / `LAB=1`, never selected in tier0 |

Accounts used in any probe are **your own test accounts**. Real users'
credentials, sessions or mailboxes are never touched — that is the line
between testing an auth system and attacking its users.

---

## 1. JWT classes

### 1a. `alg: none` accepted
- **Preconditions:** verifier reads the algorithm from the token header.
- **Probe:** same claims, header `{"alg":"none"}`, empty signature;
  baseline without token and a random-key control must both be rejected.
- **Escalation:** claims become attacker-chosen (`sub`, `role`).
- **Hardening:** pin the algorithm server-side; reject `none` in any case.
- **Gate / fixture:** `LAB=1 python skills/jwt_lab.py --url <lab endpoint>`
  · fixture `tests/fixtures/exploit_lab/jwt_verifier.py` route
  `/none-vuln` · engine playbook `jwt-alg-confusion` on `lab_target`.

### 1b. RS256 → HS256 key confusion
- **Preconditions:** one key object verifies every algorithm; the RSA
  public key (public by definition — JWKS, certificate) is accepted as an
  HMAC secret.
- **Probe:** HS256 token signed with the exact public-key PEM bytes
  (and the no-trailing-newline variant).
- **Escalation:** forge any claims with public information only.
- **Hardening:** bind algorithm to key type; pass the expected algorithm
  explicitly to the library.
- **Gate / fixture:** `jwt_lab.py --pubkey server.pem` · route
  `/confusion-vuln` · offline maths first: `tools/jwt_crypto_attack.py
  --token <t> --pubkey server.pem`.

### 1c. `kid` path traversal / injection
- **Preconditions:** `kid` is used as a file path (or SQL key) to fetch
  the verification key.
- **Probe:** `kid: ../../../../../../../../dev/null` with an HMAC over an
  empty key.
- **Escalation:** attacker-predictable key → forged tokens.
- **Hardening:** `kid` is an opaque ID looked up in an allowlist/keystore;
  reject empty keys.
- **Gate / fixture:** `jwt_lab.py` · route `/kid-vuln` (virtual
  filesystem, identical on Windows and Linux).

### 1d. Weak HMAC secret
- **Preconditions:** HS256 with a guessable secret.
- **Probe:** offline only — `tools/jwt_crypto_attack.py --token <t>
  --wordlist <file>` (secret is redacted in every output).
- **Escalation:** sign arbitrary claims.
- **Hardening:** ≥ 256-bit random secret from a KMS; rotate; prefer
  asymmetric keys for multi-service setups.
- **Gate / fixture:** engine playbook `jwt-weak-secret` on `lab_target`.

Static hygiene of captured tokens (expiry, missing `aud`, sensitive
claims): `tools/jwt_token_audit.py --token <t>`.

## 2. OAuth 2.0 / OIDC misuse

### 2a. `state` not bound to the session (login CSRF)
- **Preconditions:** callback accepts a code with an arbitrary `state`.
- **Probe:** baseline callback with the correct state succeeds; the same
  flow with an unrelated state must be rejected.
- **Escalation:** victim's browser is logged into the attacker's account
  (data entered by the victim lands in the attacker's account).
- **Hardening:** `state` (and OIDC `nonce`) bound to the pre-auth session,
  single use; PKCE for public clients.
- **Gate / fixture:** engine playbook `oauth-state` (tier-1) on
  `lab_target`'s simulated provider.

### 2b. Loose `redirect_uri` matching
- **Preconditions:** prefix/substring/subdomain matching, open redirect
  on an allowed host, or `redirect_uri` not re-checked at token exchange.
- **Probe:** a matrix of `redirect_uri` variants captured from your own
  authorized test client; the canonical one must succeed first (control).
- **Escalation:** authorization code or token delivered to an attacker
  origin → account takeover.
- **Hardening:** exact-string match of pre-registered URIs; re-validate at
  the token endpoint; PKCE.
- **Gate / fixture:** `tools/oauth_redirect_audit.py --matrix` prints the
  probe plan; `--evidence <captured.json>` classifies results offline and
  refuses (exit 2) without a passing canonical control.

### 2c. Over-privileged grants
- **Preconditions:** third-party apps with tenant-wide (admin-consented)
  or application permissions beyond need.
- **Probe:** export grants (e.g. Microsoft Graph
  `oauth2PermissionGrants`) → `tools/oauth_grant_audit.py --grants`.
- **Escalation:** a compromised or malicious app reads all mailboxes/files.
- **Hardening:** admin-consent workflow, app allowlist, periodic review.

## 3. Session handling flaws

### 3a. Session fixation
- **Preconditions:** session ID set before login survives authentication.
- **Probe:** force a pre-login session ID on your own test account, log
  in, check whether that ID is now authenticated.
- **Escalation:** attacker-planted session ID becomes the victim's
  authenticated session.
- **Hardening:** regenerate the session ID on every privilege change.
- **Gate / fixture:** engine playbook `session-fixation` (tier-1).

### 3b. Session not invalidated on logout
- **Preconditions:** server keeps the session alive after logout.
- **Probe:** log out your test account, replay the old cookie to a
  whoami endpoint.
- **Escalation:** stolen cookies outlive the user's logout.
- **Hardening:** server-side session revocation; short idle timeouts.
- **Gate / fixture:** engine playbook `session-invalidation` (tier-2).

### 3c. Cookie scope and flags
- **Detect (read-only, from saved headers):** `skills/cookie_flags_aggregate.py`,
  `skills/cookie_scope.py` (Domain attribute wider than needed, `Path=/`
  on session cookies).
- **Hardening:** `__Host-` prefix, `Secure; HttpOnly; SameSite=Lax`.

### 3d. Password-reset poisoning
- **Preconditions:** reset link built from the request `Host` header.
- **Probe:** reset for your own test account with a modified `Host`;
  check the token in the generated link is valid.
- **Hardening:** build links from configuration, never from headers.
- **Gate / fixture:** engine playbook `host-header-poison`.

## 4. SAML

### 4a. Signature wrapping (XSW) and unsigned-assertion acceptance
- **Preconditions:** SP verifies *a* signature in the document but reads
  the assertion from a different (unsigned) element; or accepts
  assertions with no signature at all; or trusts comments/whitespace
  normalisation differences in `NameID`.
- **Probe:** only against an SP you run in a lab: replay your own valid
  assertion with a duplicated, modified, unsigned `Assertion` placed so
  that signature lookup and data lookup diverge.
- **Escalation:** log in as any `NameID` the attacker writes.
- **Hardening:** strict schema validation, verify the exact element you
  consume (reference ID == consumed ID), reject multiple assertions, keep
  the SAML library patched.
- **Detect (read-only):** `skills/saml_metadata_audit.py --url` (metadata
  posture: signing requirements, weak algorithms, expired certificates).
- **Gate:** no automated SAML exploit ships in this repo by design; this
  remains a manual lab exercise with an SP you deploy yourself.

## 5. Account lockout economics

- **Question:** what does the lockout policy cost the attacker vs. the
  legitimate user?
- **No lockout** (CWE-307): online guessing is bounded only by rate
  limiting → credential stuffing at scale.
  *Probe:* N wrong passwords then the correct one on **your own canary
  account** (bounded ≤ 10) — engine playbook `lockout-canary` (tier-2).
- **Hard lockout per account:** stops guessing but lets anyone lock any
  user out (a DoS lever) — do not test this against real users at all;
  it is on the NEVER-LIST side of the line.
- **Better:** per-account *and* per-source throttling with exponential
  back-off, breached-password checks, MFA, CAPTCHA after a threshold.
- *Measure rate limiting:* `skills/rate_limit_validator.py --url <lab>
  --lab` (active-probe, lab-only).
- **Enumeration side channels:** `reset-enum`, `register-enum` engine
  playbooks (differential only, zero real emails sent).

## Evidence contract

Preconditions from configuration or captured traffic = **L1**. A
forgery / session result reproduced twice against your own lab or test
account with a rejecting control = **L3** (`poc-exploit`), recorded with
the exact requests. Anything involving real users' accounts is out of
scope, whatever the result would prove.
