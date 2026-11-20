"""Lab gate for the exploit-lab tier — refuse before the first request.

Every exploit-lab script calls `check(target_url)` FIRST, before any
socket is opened. The gate is an ADDITION to the existing safety layers
(NEVER-LIST, exploit_allowed, tier0/lab modes); it relaxes nothing.

Rules (fail-closed, in order):
  1. Environment variable LAB must be exactly "1". Anything else -> refuse.
     There is deliberately NO command-line flag that can stand in for it:
     an agent cannot talk its way past the gate by adding an argument.
  2. The target host must be loopback (127.0.0.0/8, ::1, "localhost").
     The host is judged from the URL literally — names are NOT resolved
     (no DNS lookup, and no DNS-rebinding loophole).
  3. A non-loopback target additionally needs LAB_REMOTE_ACK=<reason>,
     a non-empty, human-written reason (e.g. "staging, ticket SEC-142,
     written approval from owner"). The reason is returned so the caller
     records it in the output metadata — the acknowledgment is on file.

Refusal = message on stderr + exit code 2 (the caller returns it).
Pure stdlib, zero network.
"""
from __future__ import annotations

import ipaddress
import os
import sys
from urllib.parse import urlsplit

REFUSED = 2
ACK_MIN_LEN = 8  # "ok"/"yes" is not a reason


class LabGateError(Exception):
    """Raised by evaluate() when the run must be refused."""


def is_loopback_host(host: str) -> bool:
    """True only for literal loopback: localhost / 127.0.0.0/8 / ::1."""
    h = (host or "").strip().strip("[]").lower().rstrip(".")
    if not h:
        return False
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False  # a name we refuse to resolve = not provably loopback


def evaluate(target_url: str, env: "dict | None" = None,
             allow_remote: bool = True) -> dict:
    """Decide; return gate metadata or raise LabGateError(reason).

    allow_remote=False makes the gate loopback-ONLY: no acknowledgment
    can open a non-loopback target (used by high-volume tools such as
    the lab fuzzer)."""
    env = os.environ if env is None else env
    if env.get("LAB") != "1":
        raise LabGateError(
            "exploit-lab script: LAB=1 is not set - refusing (lab-only "
            "tier, fail-closed). Run only against your own lab target.")
    try:
        parts = urlsplit(target_url)
    except ValueError as exc:
        raise LabGateError(f"target URL unparseable: {exc}") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise LabGateError(
            f"target must be an http(s) URL with a host: {target_url!r}")
    host = parts.hostname
    if is_loopback_host(host):
        return {"lab_gate": "loopback", "target_host": host,
                "remote_ack": None}
    if not allow_remote:
        raise LabGateError(
            f"target host {host!r} is not loopback. This tool is "
            "loopback-only; LAB_REMOTE_ACK cannot open it - refusing.")
    ack = (env.get("LAB_REMOTE_ACK") or "").strip()
    if len(ack) < ACK_MIN_LEN:
        raise LabGateError(
            f"target host {host!r} is not loopback. Non-loopback lab "
            "targets need LAB_REMOTE_ACK=<written reason, e.g. 'own "
            "staging, approval ticket SEC-142'> - refusing.")
    return {"lab_gate": "remote-acknowledged", "target_host": host,
            "remote_ack": ack[:300]}


def check(target_url: str, tool: str, allow_remote: bool = True
          ) -> "tuple[int | None, dict]":
    """CLI helper: (None, meta) when allowed, (2, {}) after printing why."""
    try:
        return None, evaluate(target_url, allow_remote=allow_remote)
    except LabGateError as exc:
        print(f"[{tool}] REFUSED: {exc}", file=sys.stderr)
        return REFUSED, {}
