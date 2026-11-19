# Linux privilege escalation — misconfiguration decision tree

Playbook for agents and analysts. **Patterns only** — every technique
names its preconditions, a read-only detection command, the secai tool
that triages the evidence offline, the escalation idea in one sentence,
and the hardening. There is no weaponised code here on purpose: proving
an escalation happens only on a host you own, in a lab, under the gate
below.

**Lab gate (applies to every "escalate" step):** run escalation steps
only on your own lab VM/container (e.g. a throwaway VM you created), with
`LAB=1` exported in that shell, and with a snapshot taken first. On any
other machine stop at *detect* and report the precondition as an L1 lead.
The NEVER-LIST (persistence, backdoors, destruction) is out of scope at
every step — prove root with a marker (`id`, read a canary file you
placed), never by changing the system.

## How to use the tree

```
start: shell as user U on host H (authorized)
 ├─ 1. sudo rights?           sudo -l -n                → §1
 ├─ 2. SUID/SGID binaries?    find / -perm -4000 ...   → §2
 ├─ 3. file capabilities?     getcap -r / 2>/dev/null  → §3
 ├─ 4. writable cron/units?   ls -l /etc/cron* ...     → §4
 ├─ 5. PATH hijack?           echo $PATH; ls -ld ...   → §5
 ├─ 6. root-equivalent group? id                       → §6
 ├─ 7. NFS no_root_squash?    cat /etc/exports         → §7
 └─ 8. inside a container?    /proc/self/status, mounts → §8
```

Offline-first: collect the evidence once, then triage it without
touching the host again:

```bash
# on H (read-only collection, as U)
sudo -l -n > sudo-l.txt 2>&1
find / -xdev -perm -4000 -type f 2>/dev/null > suid.txt
getcap -r / 2>/dev/null > caps.txt
tar czf etc-snap.tgz /etc/sudoers.d /etc/crontab /etc/cron.d /etc/exports \
    /etc/passwd /etc/group /etc/systemd/system 2>/dev/null

# anywhere, offline (tar stored paths as etc/..., so extract into a root dir)
mkdir snap && tar xzf etc-snap.tgz -C snap
python tools/linux_privesc_audit.py --root snap --suid-list suid.txt \
    --cap-list caps.txt --fail-on high
```

`tools/linux_privesc_audit.py` covers §1–§7 deterministically (sudoers
NOPASSWD/wildcards, UID-0 duplicates, docker/lxd groups, SUID in odd or
writable places, risky capabilities, `no_root_squash`, world-writable
cron targets and units, writable PATH entries).

---

## §1 sudo rules

- **Preconditions:** `sudo -l` lists a command runnable as root, often
  `NOPASSWD`, that can spawn a shell, write files or load code (editors,
  pagers, interpreters, `tar`/`zip`/`find` with exec options, `env`,
  wildcard arguments like `/usr/bin/rsync *`).
- **Detect:** `sudo -l -n` · offline: `linux_privesc_audit.py --root`
  (checks `sudoers-nopasswd-dangerous`, wildcard, `runas ALL`).
- **Escalate (pattern):** the allowed program's own feature (shell escape,
  exec hook, arbitrary write) runs as root. Look the binary up in a public
  reference of shell-escape features; prove with `id` only.
- **Hardening:** allow exact command + exact args, never wildcards; no
  interpreters/editors/pagers; `Defaults use_pty, !visiblepw`; prefer a
  wrapper script owned by root with fixed behaviour.

## §2 SUID / SGID binaries

- **Preconditions:** a SUID-root binary that is (a) non-standard, (b) in a
  user-writable directory, or (c) a standard tool with an escape feature.
- **Detect:** `find / -xdev -perm -4000 -type f 2>/dev/null` ·
  offline: `--suid-list suid.txt` (flags unusual paths and writable dirs).
- **Escalate (pattern):** the binary keeps EUID 0 while doing something
  the user controls (spawning a program via relative name, reading a
  user-chosen file, loading a library from a writable path).
- **Hardening:** remove the SUID bit unless required (`chmod u-s`); mount
  user-writable filesystems `nosuid`; audit SUID inventory in CI images.

## §3 File capabilities

- **Preconditions:** `cap_setuid`, `cap_dac_read_search`, `cap_sys_admin`,
  `cap_sys_ptrace` (or `+ep` on an interpreter) on a binary the user runs.
- **Detect:** `getcap -r / 2>/dev/null` · offline: `--cap-list caps.txt`.
- **Escalate (pattern):** an interpreter with `cap_setuid+ep` can call
  `setuid(0)`; `cap_dac_read_search` reads any file (shadow, keys).
- **Hardening:** never grant capabilities to interpreters or general
  tools; grant the minimal capability to a single-purpose binary.

## §4 Cron jobs and systemd units

- **Preconditions:** a root cron job or unit executes a file/dir the user
  can write, or uses a wildcard (`tar czf backup.tgz *`) in a
  user-writable directory.
- **Detect:** `ls -l /etc/crontab /etc/cron.* /var/spool/cron 2>/dev/null`;
  `systemctl list-timers`; check `ExecStart=` targets' permissions ·
  offline: `linux_privesc_audit.py --root` (writable cron target,
  wildcard injection, world-writable units).
- **Escalate (pattern):** modify the executed file, or plant file names
  that the wildcard expands into options (`--checkpoint-action`-style).
- **Hardening:** root jobs execute only root-owned, non-writable paths;
  no wildcards in privileged jobs; `ProtectSystem=strict` in units.

## §5 PATH abuse

- **Preconditions:** a privileged script/binary calls a program by bare
  name, and a directory earlier in its `PATH` is user-writable (including
  `.` or an empty `PATH` element).
- **Detect:** `echo "$PATH" | tr ':' '\n' | xargs -I{} ls -ld {}`; for
  sudo, `Defaults secure_path` absence · offline: writable PATH check in
  `linux_privesc_audit.py`.
- **Escalate (pattern):** a same-named program in the writable directory
  is executed with the caller's privileges.
- **Hardening:** absolute paths in privileged scripts; `secure_path` in
  sudoers; never `.` in root's PATH.

## §6 Root-equivalent groups

- **Preconditions:** user is in `docker`, `lxd`, `disk`, `adm`+writable
  logs, or `shadow`.
- **Detect:** `id` · offline: group membership check in
  `linux_privesc_audit.py` (`etc/group`).
- **Escalate (pattern):** `docker`/`lxd` = start a container with the host
  root mounted (the daemon runs as root); `disk` = raw block device read.
- **Hardening:** treat these groups as root; use rootless Docker or a
  scoped API proxy.

## §7 NFS `no_root_squash`

- **Preconditions:** an export with `no_root_squash` that the attacker can
  mount as root from another machine they control.
- **Detect:** `cat /etc/exports`; `showmount -e <server>` from an
  authorized host · offline: `--root` exports check.
- **Escalate (pattern):** a SUID-root file created over NFS by remote root
  is SUID-root on the server.
- **Hardening:** `root_squash` (default), `nosuid` on clients, export to
  named hosts only.

## §8 Container boundary

- **Preconditions:** the shell is inside a container that runs
  privileged, has the runtime socket or host root mounted, has
  `CAP_SYS_ADMIN` with writable cgroup v1, or shares the host PID ns.
- **Detect (read-only):** snapshot `/proc/self/status`,
  `/proc/self/mountinfo`, `/proc/self/uid_map`, `/proc/1/cmdline` (recipe
  in the tool's docstring), then
  `python tools/container_escape_check.py --root ./snap`.
- **Escalate (pattern):** runtime socket → start a privileged container
  with `/` mounted; cgroup v1 `release_agent` + `CAP_SYS_ADMIN` → host
  command execution (CVE-2022-0492 class); host root mount → write to
  host files.
- **Hardening:** never `--privileged`; `cap_drop: [ALL]`; default seccomp
  and AppArmor/SELinux; no runtime socket; user-namespace remapping;
  cgroup v2.
- **Fixtures:** `tests/fixtures/exploit_lab/container/{privileged,socket,
  hardened}` — the hardened one is the false-positive control.

## Evidence contract

A precondition seen in collected evidence = **L1 lead**. A demonstrated
escalation on your own lab host, reproduced twice, with `id` output as
the marker = **L3**, recorded with the exact command sequence and the
snapshot ID. Anything you could not reproduce stays a lead.
