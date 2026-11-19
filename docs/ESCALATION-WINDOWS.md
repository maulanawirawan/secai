# Windows privilege escalation — misconfiguration decision tree

Playbook for agents and analysts. **Patterns only**: preconditions, a
read-only detection command, the secai tool that triages the captured
output offline, the escalation idea in one sentence, and the hardening.
No weaponised code; no exploit binaries are referenced or shipped.

**Lab gate (applies to every "escalate" step):** only on a Windows VM
you own and snapshotted first (a lab domain or a throwaway VM), with
`LAB=1` set in the session environment (`$env:LAB = "1"`). On any other
machine stop at *detect* and report an L1 lead. NEVER-LIST applies:
prove SYSTEM/admin with a marker (`whoami` output, read a canary file you
placed), never by creating persistence, accounts, or services that stay.

## Tree

```
start: interactive/session as user U (authorized)
 ├─ 1. token privileges?        whoami /priv              → §1
 ├─ 2. service misconfig?       sc qc / sc sdshow         → §2, §3
 ├─ 3. AlwaysInstallElevated?   reg query ...Installer    → §4
 ├─ 4. stored credentials?      SYSVOL GPP / cmdkey /list → §5
 ├─ 5. UAC posture?             reg query ...\System      → §6
 └─ 6. missing patches?         systeminfo                → §7
```

Offline-first: capture once, triage anywhere:

```powershell
whoami /priv  > whoami-priv.txt
whoami /groups >> whoami-priv.txt
systeminfo    > systeminfo.txt
Get-CimInstance Win32_Service | Select Name,PathName,StartMode,StartName |
  ConvertTo-Json > services.json
```

```bash
python tools/whoami_priv_triage.py --file whoami-priv.txt
python tools/unquoted_service_path_triage.py --file services.json
python tools/systeminfo_triage.py --file systeminfo.txt
python tools/seatbelt_output_triage.py --file seatbelt.txt   # if Seatbelt was run
```

---

## §1 Token privileges

- **Preconditions:** `SeImpersonatePrivilege` or
  `SeAssignPrimaryTokenPrivilege` (typical for service accounts: IIS app
  pools, SQL Server), `SeBackupPrivilege`/`SeRestorePrivilege`,
  `SeDebugPrivilege`, `SeLoadDriverPrivilege`, `SeTakeOwnershipPrivilege`,
  `SeManageVolumePrivilege`.
- **Detect:** `whoami /priv` → `tools/whoami_priv_triage.py --file`
  (flags dangerous privileges and whether they are Enabled).
- **Escalate (pattern):** impersonation privileges + coercing a SYSTEM
  service to authenticate to a local endpoint the attacker controls
  ("potato" family, publicly documented) yields a SYSTEM token;
  `SeBackup` reads the SAM/SYSTEM hives; `SeDebug` opens SYSTEM processes.
- **Hardening:** run services as virtual/managed service accounts with
  the minimum privileges; remove `SeImpersonate` from accounts that do not
  need it; patch the coercion paths; Credential Guard / LSA protection.

## §2 Unquoted service paths

- **Preconditions:** a service `ImagePath` with spaces and no quotes, and a
  user-writable directory at one of the split points
  (e.g. `C:\Program Files\Vendor App\svc.exe` with `C:\Program Files\Vendor`
  writable). Service runs as LocalSystem and can be restarted by the user
  (or the host reboots).
- **Detect:** `sc qc <svc>` / the `services.json` capture →
  `tools/unquoted_service_path_triage.py --file` (lists candidate
  executable names per split point).
- **Escalate (pattern):** Windows tries each space-split candidate path
  in order; a binary at the first writable candidate runs as the service
  account.
- **Hardening:** quote every `ImagePath`; remove user write access from
  `Program Files` subdirectories; audit with the same tool in CI images.

## §3 Weak service permissions / binary ACLs

- **Preconditions:** the user can reconfigure a service (`SERVICE_CHANGE_CONFIG`
  in its security descriptor) or write its binary / its directory.
- **Detect:** `sc sdshow <svc>` (look for write/config rights granted to
  `AU`, `BU`, `WD`, or the user's SID); `icacls "<binary path>"`.
  Seatbelt output covering services is triaged by
  `tools/seatbelt_output_triage.py --file`.
- **Escalate (pattern):** point `binPath` at a command, or replace the
  binary, then start the service → runs as its account.
- **Hardening:** default service DACLs; binaries owned by
  TrustedInstaller/Administrators, not writable by users.

## §4 AlwaysInstallElevated

- **Preconditions:** both `HKLM` and `HKCU`
  `\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1`.
- **Detect:** `reg query HKLM\Software\Policies\Microsoft\Windows\Installer`
  and the same under `HKCU`.
- **Escalate (pattern):** any MSI the user runs installs with SYSTEM rights.
- **Hardening:** never enable this policy; enforce via GPO set to 0.

## §5 Stored credentials

- **Preconditions:** Group Policy Preferences XML in SYSVOL with a
  `cpassword` attribute (AES key published by Microsoft — MS14-025),
  saved credentials (`cmdkey /list`), unattended install files.
- **Detect:** search SYSVOL for `cpassword` → `tools/gpp_cpassword_triage.py
  --file <Groups.xml>`; `cmdkey /list`; look for `unattend.xml`,
  `sysprep.inf`.
- **Escalate (pattern):** recovered credentials of a local admin or
  service account are reused.
- **Hardening:** delete GPP password items (MS14-025), rotate the exposed
  passwords, LAPS for local admin accounts.

## §6 UAC posture

- **Preconditions:** user is a member of local Administrators but runs
  filtered (medium integrity); `ConsentPromptBehaviorAdmin = 0` or
  `EnableLUA = 0`, or auto-elevating binaries reachable.
- **Detect:** `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System`;
  `whoami /groups` (Mandatory Label = Medium + Administrators group present).
- **Escalate (pattern):** UAC is a convenience boundary, not a security
  boundary: an admin-group user reaches high integrity via auto-elevation
  or no prompt.
- **Hardening:** `EnableLUA=1`, `ConsentPromptBehaviorAdmin=2` (secure
  desktop), separate admin accounts; no daily use of admin-group users.

## §7 Missing patches

- **Preconditions:** a publicly documented local privilege escalation
  (kernel/driver/service) without its KB installed.
- **Detect:** `systeminfo` → `tools/systeminfo_triage.py --file`
  (hotfix count/age, uptime); version facts → `tools/cve_matcher.py`.
- **Escalate (pattern):** N-day exploitation — lab only, against a VM you
  installed at the vulnerable build.
- **Hardening:** patch cadence; driver blocklist; WDAC/HVCI.

## Detection side (blue team)

`tools/win_auth_triage.py`, `tools/kerberos_log_triage.py`,
`tools/sysmon_triage.py`, `tools/lolbin_scan.py` triage the event logs
these techniques leave (service creation/changes, privilege use, token
manipulation, LOLBin launches).

## Evidence contract

Precondition in captured output = **L1 lead**. Escalation demonstrated
twice on your own snapshotted lab VM with `whoami` as marker = **L3**,
recorded with the exact sequence and snapshot ID.
