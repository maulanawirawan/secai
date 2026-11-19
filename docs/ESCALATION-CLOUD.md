# Cloud escalation — IAM confusion, role trust, metadata chains

Detection and hardening playbook. **Patterns only, no targeting**: every
technique is analysed from artefacts the account owner exports
themselves (IAM authorization details, CloudTrail, org policies), or
proven against a local fixture. Nothing here calls a cloud API.

**Lab gate:** the only live step in this document is the SSRF → metadata
proof, run with `skills/ssrf_metadata_lab.py`, which refuses to start
without `LAB=1` and refuses non-loopback targets without
`LAB_REMOTE_ACK=<written reason>`. Every other step is offline analysis.

## Tree

```
start: you own/administer the cloud account (or have written scope)
 ├─ 1. IAM policy → one-step escalation?   iam_escalation_scan   → §1
 ├─ 2. role trust → multi-hop chain?       iam_assume_chain      → §2
 ├─ 3. workload → metadata credentials?    ssrf_metadata_map/lab → §3
 ├─ 4. Kubernetes RBAC → cluster-admin?    k8s_rbac_audit        → §4
 └─ 5. evidence of abuse?                  cloudtrail_scan       → §5
```

Export once (the owner runs this in their own account):

```bash
aws iam get-account-authorization-details > auth.json
python tools/iam_escalation_scan.py --auth auth.json --fail-on high
python tools/iam_assume_chain.py   --auth auth.json --fail-on high
```

---

## §1 IAM policy confusion (one step)

- **Preconditions:** a principal holds an action that lets it raise its
  own privileges: `iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion`
  on a policy attached to itself, `iam:AttachUserPolicy` /
  `iam:PutUserPolicy` on itself, `iam:PassRole` + a compute-create action
  (`lambda:CreateFunction`, `ec2:RunInstances`, `glue:CreateDevEndpoint`)
  toward a more privileged role, `iam:UpdateAssumeRolePolicy`,
  `iam:CreateAccessKey` on another user.
- **Detect:** `tools/iam_escalation_scan.py --auth auth.json`
  (deterministic Allow-statement evaluation per principal).
- **Escalation idea:** the principal writes or borrows a stronger policy;
  `PassRole` hands a privileged role to compute the principal controls.
- **Hardening:** scope `iam:*` write actions to admins; `PassRole` with
  `iam:PassedToService` + explicit role ARNs; permission boundaries; SCPs
  denying IAM writes outside a break-glass role.

## §2 Role-trust misuse (multi-hop)

- **Preconditions:** a trust policy allows a broad principal
  (`"AWS": "*"` with weak conditions, a whole account root, a wildcard
  role path) and a chain of `sts:AssumeRole` hops reaches an
  admin-equivalent role; cross-account trust without `sts:ExternalId`.
- **Detect:** `tools/iam_assume_chain.py --auth auth.json` builds the
  principal → principal graph and reports paths of ≥ 2 hops to admin
  (L2 REPRODUCED with the path in `poc`).
- **Escalation idea:** each hop is individually "allowed"; the chain is
  the vulnerability (confused deputy).
- **Hardening:** trust specific role ARNs, require `sts:ExternalId` for
  third parties, `aws:PrincipalOrgID` conditions, review trust policies
  as code.

## §3 Metadata-endpoint chains (SSRF → instance credentials)

- **Preconditions:** a workload fetches attacker-influenced URLs
  server-side (SSRF, CWE-918), runs on an instance with an attached role,
  and the metadata service accepts tokenless GETs (AWS IMDSv1). GCP and
  Azure metadata require a custom request header (`Metadata-Flavor:
  Google`, `Metadata: true`), so a plain-GET SSRF usually cannot reach
  them — header-controlling SSRF can.
- **Detect (offline):** given a confirmed primitive, map reachable
  endpoints: `python tools/ssrf_metadata_map.py --provider aws
  --capability plain-get` (sends nothing).
- **Prove (lab):** `LAB=1 python skills/ssrf_metadata_lab.py --url
  http://127.0.0.1:<port>/fetch --param url`. Closed-port control,
  listing reproduced twice, then the IAM role **name** only — the script
  has no code path that requests the credentials document.
  Fixture: `tests/fixtures/exploit_lab/ssrf_app.py` (IMDSv1, IMDSv2,
  fixed fetcher, and an echo honeypot as FP-controls).
- **Escalation idea:** role name → temporary credentials → the role's
  permissions (then §1/§2 decide how far that goes).
- **Hardening:** IMDSv2 required (`HttpTokens=required`, hop limit 1);
  fetchers resolve-then-block link-local/private ranges (and re-check
  after redirects); least-privilege instance roles; alert on instance
  credentials used from outside the instance (§5).

## §4 Kubernetes RBAC

- **Preconditions:** a service account/user can `create pods` (mount a
  privileged pod / hostPath), `escalate`/`bind` roles, `impersonate`, or
  read `secrets` cluster-wide.
- **Detect:** `kubectl get clusterroles,clusterrolebindings,roles,rolebindings
  -A -o json > rbac.json` → `tools/k8s_rbac_audit.py --source rbac.json`;
  pod specs → `tools/k8s_podsec_audit.py`; running containers →
  `tools/container_escape_check.py` (see ESCALATION-LINUX §8).
- **Hardening:** no wildcard verbs/resources; Pod Security "restricted";
  separate namespaces for privileged workloads.

## §5 Evidence of abuse

- `tools/cloudtrail_scan.py --log <trail.json>` — AccessDenied bursts,
  IAM writes, console logins without MFA, root usage.
- GCP: `tools/gcp_orgpolicy_audit.py --policies`, `tools/gcp_fw_audit.py`.
- Azure/Entra: `skills/entra_posture.py` (tenant posture), OAuth grants →
  `tools/oauth_grant_audit.py --grants`.

## Evidence contract

A path computed from the owner's own export = **L2** (deterministic,
reproducible from the same file). The SSRF → metadata proof in the lab =
**L3** (`poc-exploit`). Nothing in this playbook claims live access to a
real cloud account.
