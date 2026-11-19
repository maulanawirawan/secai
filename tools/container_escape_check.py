r"""[SAFETY: read-only, NOL jaringan] container_escape_check — runtime
posture of a container from INSIDE evidence: which publicly documented
escape preconditions are present (privileged capability set, runtime
socket mounted, host root / sensitive host paths mounted, writable
/proc/sys or cgroup v1 with CAP_SYS_ADMIN, seccomp off, host PID ns).

Not gated: it only READS files under --root (a copied snapshot, or "/"
when run inside the container on Linux). It exploits nothing, writes
nothing, opens no socket.

Niche vs existing tools (anti-duplication): docker_audit.py lints the
Dockerfile/daemon.json/compose *config*, k8s_podsec_audit.py lints pod
*manifests*. Neither sees the RUNNING container: a privileged flag set
by an orchestrator, a socket mounted by a sidecar injector, or a
capability added at run time only shows up in /proc. This tool reads it.

Input (paths relative to --root, platform-agnostic):
  proc/self/status     CapEff / Seccomp / NoNewPrivs        (REQUIRED)
  proc/self/mountinfo  mounts: sockets, host paths, rw /proc/sys, cgroup
  proc/self/uid_map    user-namespace remap (context)
  proc/1/cmdline       init-like PID 1 = host PID namespace lead
Snapshot recipe (inside the container):
  mkdir -p snap/proc/self snap/proc/1 && for f in status mountinfo \
  uid_map; do cat /proc/self/$f > snap/proc/self/$f; done && \
  cat /proc/1/cmdline > snap/proc/1/cmdline

Verdicts: every hit is an L1 LEAD (a precondition observed in runtime
evidence, not an escape performed); clean checks are L0 rows. Missing
proc/self/status = cannot conclude = exit 2 (fail-closed, no "clean").

Exit: 0 nothing >= --fail-on; 1 findings >= --fail-on (default high);
2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

TOOL = "container-escape-check"
SCHEMA = "secai.container-escape-check/1"
MAX_FILE_BYTES = 4 * 1024 * 1024
SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# capability bit -> (name, severity when present, why)
DANGEROUS_CAPS = {
    21: ("CAP_SYS_ADMIN", "high",
         "mount/cgroup/namespace administration — basis of most escapes"),
    16: ("CAP_SYS_MODULE", "critical", "load kernel modules = host kernel"),
    17: ("CAP_SYS_RAWIO", "high", "raw I/O ports and /dev/mem access"),
    2: ("CAP_DAC_READ_SEARCH", "high",
        "open_by_handle_at() host file read (the 'shocker' class)"),
    19: ("CAP_SYS_PTRACE", "medium",
         "ptrace other processes (host processes if host PID ns)"),
    39: ("CAP_BPF", "high", "load BPF programs into the host kernel"),
    12: ("CAP_NET_ADMIN", "medium", "reconfigure (host) network stack"),
}
FULL_CAPSET_MIN_BITS = 36  # Docker default grants 14; privileged grants all
RUNTIME_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock",
                   "podman.sock", "dockershim.sock")
SENSITIVE_HOST_ROOTS = ("/etc", "/root", "/var/run", "/run", "/proc",
                        "/sys", "/var/lib/kubelet", "/var/lib/docker",
                        "/home", "/boot", "/dev")
BLOCK_FSTYPES = ("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs")
_INIT_RE = re.compile(r"(^|/)(systemd|init)$")


def _read(root: Path, rel: str) -> "str | None":
    p = root.joinpath(*re.split(r"[\\/]+", rel))
    if not p.is_file():
        return None
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{p} larger than {MAX_FILE_BYTES} bytes")
    return p.read_bytes().decode("utf-8", "replace")


def parse_status(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip()] = v.strip()
    return out


def _unescape(field: str) -> str:
    # mountinfo octal escapes: \040 space, \011 tab, \012 nl, \134 backslash
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def parse_mountinfo(text: str) -> list[dict]:
    """proc(5) mountinfo: id parent maj:min root mountpoint opts [optional
    fields...] - fstype source superopts."""
    mounts = []
    for line in text.splitlines():
        parts = line.split()
        if "-" not in parts or len(parts) < 7:
            continue
        sep = parts.index("-")
        if sep < 6 or len(parts) < sep + 3:
            continue
        mounts.append({
            "root": _unescape(parts[3]), "mountpoint": _unescape(parts[4]),
            "opts": parts[5].split(","), "fstype": parts[sep + 1],
            "source": _unescape(parts[sep + 2]),
            "superopts": parts[sep + 3].split(",")
            if len(parts) > sep + 3 else []})
    return mounts


def cap_bits(hexval: str) -> set[int]:
    try:
        v = int(hexval, 16)
    except (TypeError, ValueError):
        raise ValueError(f"CapEff is not hex: {hexval!r}")
    return {b for b in range(64) if v >> b & 1}


def audit(root_label: str, ev: dict) -> tuple[list[dict], dict]:
    """Pure: evidence texts -> (rows, meta). ev keys: status (required),
    mountinfo, uid_map, pid1_cmdline (each str or None)."""
    st = parse_status(ev["status"])
    if "CapEff" not in st:
        raise ValueError("proc/self/status has no CapEff line")
    caps = cap_bits(st["CapEff"])
    mounts = parse_mountinfo(ev.get("mountinfo") or "")
    rows: list[dict] = []
    hits: list[str] = []

    def lead(check, sev, title, desc, rec, cwe="CWE-250", evidence=""):
        hits.append(check)
        rows.append(make_finding(
            tool=TOOL, title=title, severity=sev, description=desc,
            recommendation=rec, cwe=cwe, file_path=root_label,
            response=evidence[:300], evidence_kind="artifact-parse",
            finding_class="weakness", confidence=1.0, status="confirmed",
            verdict=1, extra={"category": "LEAD", "check": check,
                              "safety_class": "read-only"}))

    privileged = len(caps) >= FULL_CAPSET_MIN_BITS
    if privileged:
        lead("privileged-capset", "critical",
             f"Full capability set ({len(caps)} caps) — container runs "
             "privileged",
             f"CapEff={st['CapEff']} grants {len(caps)} capabilities "
             "(Docker default grants 14). A privileged container can "
             "mount host devices and load modules.",
             "Drop --privileged; grant only named capabilities "
             "(cap_drop: [ALL] + minimal cap_add).",
             evidence=f"CapEff:\t{st['CapEff']}")
    else:
        for bit, (name, sev, why) in sorted(DANGEROUS_CAPS.items()):
            if bit in caps:
                lead(f"cap-{name.lower()}", sev,
                     f"{name} in effective capability set", why + ".",
                     f"Remove {name} (cap_drop) unless strictly required.",
                     evidence=f"CapEff:\t{st['CapEff']}")
    if st.get("Seccomp") == "0":
        lead("seccomp-disabled", "medium", "Seccomp filter disabled",
             "Seccomp: 0 — no syscall filter (unconfined); kernel attack "
             "surface fully exposed.",
             "Run with the default seccomp profile (never "
             "seccomp=unconfined).", cwe="CWE-693",
             evidence=f"Seccomp:\t{st['Seccomp']}")
    for m in mounts:
        mp, base = m["mountpoint"], m["mountpoint"].rsplit("/", 1)[-1]
        if base in RUNTIME_SOCKETS or (m["root"].rsplit("/", 1)[-1]
                                       in RUNTIME_SOCKETS):
            lead("runtime-socket-mounted", "critical",
                 f"Container runtime socket mounted at {mp}",
                 "Access to the runtime API socket = start a privileged "
                 "container with the host filesystem mounted (host root "
                 "by design, no exploit needed).",
                 "Never mount the runtime socket; use a scoped API proxy "
                 "if a tool truly needs it.",
                 evidence=f"{m['root']} {mp} {','.join(m['opts'])}")
        elif mp != "/" and m["root"] == "/" and \
                m["fstype"] in BLOCK_FSTYPES:
            lead("host-root-mounted", "critical",
                 f"Host root filesystem mounted at {mp}",
                 f"{m['source']} ({m['fstype']}) root '/' bind-mounted at "
                 f"{mp} ({'rw' if 'rw' in m['opts'] else 'ro'}).",
                 "Do not mount the host root; mount only the specific "
                 "directory needed, read-only.",
                 evidence=f"{m['root']} {mp} {','.join(m['opts'])} - "
                          f"{m['fstype']} {m['source']}")
        elif m["root"] in SENSITIVE_HOST_ROOTS and \
                m["fstype"] in BLOCK_FSTYPES:
            # only binds from a real host filesystem count: the runtime's
            # own proc/sysfs sub-mounts (root "/sys" on /proc/sys, fstype
            # proc) are NOT host paths (FP-control: hardened fixture)
            lead("sensitive-host-path", "high" if "rw" in m["opts"]
                 else "medium",
                 f"Host path {m['root']} mounted at {mp}",
                 f"Sensitive host directory {m['root']} is visible in the "
                 f"container ({'rw' if 'rw' in m['opts'] else 'ro'}).",
                 "Remove the host-path mount or narrow it to a "
                 "non-sensitive subdirectory, read-only.",
                 evidence=f"{m['root']} {mp} {','.join(m['opts'])}")
        if mp in ("/proc/sys", "/sys") and "rw" in m["opts"] and \
                m["fstype"] in ("proc", "sysfs"):
            lead("kernel-fs-writable", "high",
                 f"{mp} mounted read-write",
                 f"{mp} is writable ({m['fstype']}); default runtimes "
                 "mount it read-only (kernel tunables, uevent_helper).",
                 "Restore the read-only mount (drop privileged / "
                 "systempaths=unconfined).",
                 evidence=f"{mp} {','.join(m['opts'])} - {m['fstype']}")
        if m["fstype"] == "cgroup" and "rw" in m["opts"] and 21 in caps:
            lead("cgroup-v1-release-agent", "critical",
                 f"cgroup v1 hierarchy {mp} writable with CAP_SYS_ADMIN",
                 "Writable cgroup v1 + CAP_SYS_ADMIN = the documented "
                 "release_agent escape class (cf. CVE-2022-0492).",
                 "Use cgroup v2 / read-only cgroup mount; drop "
                 "CAP_SYS_ADMIN; keep seccomp+AppArmor on.",
                 evidence=f"{mp} {','.join(m['opts'])} - cgroup")
    cmd = (ev.get("pid1_cmdline") or "").split("\x00")[0].strip()
    if cmd and _INIT_RE.search(cmd):
        lead("host-pid-namespace", "medium",
             f"PID 1 is '{cmd}' — possible host PID namespace",
             "An init/systemd PID 1 inside a container usually means "
             "--pid=host (host processes visible; with CAP_SYS_PTRACE "
             "they can be injected). LEAD: systemd-in-container images "
             "also show this.",
             "Do not share the host PID namespace.", cwe="CWE-653",
             evidence=f"/proc/1/cmdline: {cmd}")
    uid_map = (ev.get("uid_map") or "").split()
    userns_remap = bool(uid_map[:3]) and uid_map[:2] != ["0", "0"]
    if not hits:
        rows.append(make_finding(
            tool=TOOL, title="No container escape precondition observed",
            severity="info", file_path=root_label,
            description=f"{len(caps)} capabilities, seccomp="
                        f"{st.get('Seccomp', '?')}, {len(mounts)} mounts "
                        "checked; none matched a documented escape "
                        "precondition.", evidence_kind="artifact-parse",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0, extra={"category": "AMAN",
                              "safety_class": "read-only"}))
    meta = {"schema": SCHEMA, "root": root_label, "cap_count": len(caps),
            "privileged": privileged, "seccomp": st.get("Seccomp"),
            "no_new_privs": st.get("NoNewPrivs"), "mounts": len(mounts),
            "userns_remapped": userns_remap,
            "mountinfo_present": ev.get("mountinfo") is not None,
            "checks_hit": sorted(set(hits)), "requests": 0}
    return rows, meta


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="[SAFETY: read-only] container escape-precondition "
                    "check from /proc evidence (snapshot dir or live /)")
    ap.add_argument("--root", required=True,
                    help="snapshot directory containing proc/self/status "
                         "(or / inside a Linux container)")
    ap.add_argument("--out", default="container_escape_check.json")
    ap.add_argument("--fail-on", default="high",
                    choices=["none", "info", "low", "medium", "high",
                             "critical"])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    root = Path(args.root)
    try:
        status = _read(root, "proc/self/status")
        if status is None:
            raise ValueError(f"{root}/proc/self/status missing — cannot "
                             "conclude anything (fail-closed)")
        ev = {"status": status,
              "mountinfo": _read(root, "proc/self/mountinfo"),
              "uid_map": _read(root, "proc/self/uid_map"),
              "pid1_cmdline": _read(root, "proc/1/cmdline")}
        rows, meta = audit(root.as_posix(), ev)
    except (OSError, ValueError) as exc:
        print(f"[{TOOL}] input error: {exc}", file=sys.stderr)
        return 2
    write_findings(args.out, rows, {**meta, "safety_class": "read-only"})
    if args.json:
        print(json.dumps({"meta": meta, "findings": rows}, indent=2))
    else:
        print(f"{TOOL}: {len(meta['checks_hit'])} precondition(s) "
              f"{meta['checks_hit']} -> {args.out}")
    if args.fail_on == "none":
        return 0
    thr = SEV_ORDER[args.fail_on]
    return 1 if any(r["verdict"] >= 1 and SEV_ORDER[r["severity"]] >= thr
                    for r in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
