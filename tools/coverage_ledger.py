r"""[SAFETY: read-only] coverage_ledger — wave-9 akuntansi cakupan OFFLINE:
cocokkan target yang BENAR-BENAR disentuh (dari findings.json kontrak
atau daftar URL) terhadap DAFTAR SCOPE yang diizinkan. Nilai utama:
menemukan temuan di LUAR scope (pelanggaran lingkup — konsep scope-gate
penilaian berizin) dan scope yang belum tersentuh. Dibangun dari nol,
stdlib murni, tanpa jaringan. Beda domain dari attack_coverage (MITRE)
dan scope_gate (gate runtime).

Input:
  --scope   : file scope, satu entri per baris (domain, *.domain, atau
              URL penuh — host-nya yang dipakai; komentar # diabaikan).
  --targets : findings.json kontrak ATAU file URL satu-per-baris (opsi
              boleh berulang).

Sinyal (semua deterministik dari data):
  - oos-target-hit    : host target di findings TIDAK match scope
                        manapun (exact / suffix ".entry" / wildcard
                        "*.entry") — temuan di luar lingkup (high,
                        masalah kepatuhan, bukan klaim kerentanan).
  - coverage-thin     : rasio host in-scope yang tercover < --min-ratio
                        (default 0.5) — penilaian belum lengkap (low).
Inventori (bukan sinyal): daftar in-scope tercover, scope tak tersentuh.
Zero-FP: semua target in-scope + coverage >= ambang -> clean.

Fail-closed: scope kosong / targets kosong / file tak ada -> exit 2.
Pemakaian:
  python tools/coverage_ledger.py --scope scope.txt --targets f.json --out o.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

SCHEMA = "secai.coverage-ledger/1"
_RE_HOST = re.compile(r"^[a-z0-9]([a-z0-9\-_.]*[a-z0-9])?$", re.I)


def _read_lines(path: str) -> "list[str]":
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"file tidak ada: {path}")
    out = []
    for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.append(ln)
    return out


def _host_of(entry: str) -> str:
    entry = entry.strip()
    if "://" in entry:
        try:
            return (urlparse(entry).hostname or "").lower()
        except ValueError:
            return ""
    # domain wildcard *.example.com -> example.com
    if entry.startswith("*."):
        return entry[2:].lower()
    return entry.lower()


def _hosts_from_targets(path: str) -> "list[str]":
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"file tidak ada: {path}")
    text = p.read_text(encoding="utf-8", errors="replace")
    hosts: "list[str]" = []
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    rows: "list[str]" = []
    if isinstance(doc, dict) and "findings" in doc:
        for r in doc.get("findings") or []:
            if not isinstance(r, dict):
                continue
            rows.append(str(r.get("target_url") or r.get("file_path") or ""))
    elif isinstance(doc, list):
        for r in doc:
            if isinstance(r, dict):
                rows.append(str(r.get("target_url") or r.get("file_path") or ""))
            else:
                rows.append(str(r))
    else:
        rows = text.splitlines()
    for t in rows:
        t = t.strip()
        if not t or t.startswith("#"):
            continue
        h = _host_of(t)
        if h and _RE_HOST.match(h) and h not in hosts:
            hosts.append(h)
    return hosts


def _in_scope(host: str, scope_hosts: "list[str]") -> bool:
    for s in scope_hosts:
        if host == s or host.endswith("." + s):
            return True
    return False


def triage(scope_file: str, targets_files: "list[str]", *,
           min_ratio: float = 0.5) -> dict:
    scope_lines = _read_lines(scope_file)
    if not scope_lines:
        raise ValueError("scope kosong — tidak ada lingkup utk diakui")
    scope_hosts = sorted({h for h in (_host_of(x) for x in scope_lines) if h})
    if not scope_hosts:
        raise ValueError("scope tidak memuat host valid")

    target_hosts: "list[str]" = []
    for tf in targets_files:
        for h in _hosts_from_targets(tf):
            if h not in target_hosts:
                target_hosts.append(h)
    if not target_hosts:
        raise ValueError("targets kosong — tidak ada bukti penyentuhan")

    oos = [h for h in target_hosts if not _in_scope(h, scope_hosts)]
    covered = [h for h in target_hosts if _in_scope(h, scope_hosts)]
    scope_covered = [s for s in scope_hosts
                     if any(h == s or h.endswith("." + s)
                            for h in target_hosts)]
    scope_uncovered = [s for s in scope_hosts if s not in scope_covered]
    ratio = len(scope_covered) / len(scope_hosts) if scope_hosts else 0.0

    signals: "list[str]" = []
    evidence: dict[str, str] = {}
    if oos:
        signals.append("oos-target-hit")
        evidence["oos-hosts"] = ", ".join(oos[:10])[:240]
        evidence["oos-count"] = str(len(oos))
    if ratio < min_ratio:
        signals.append("coverage-thin")
        evidence["coverage-ratio"] = "%.2f" % ratio

    seen: set[str] = set()
    signals = [s for s in signals if not (s in seen or seen.add(s))]
    score = len(signals)
    severity = ("high" if score >= 3 else
                "medium" if score == 2 else
                "low" if score == 1 else "info")
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    counts[severity] = 1
    return {
        "schema": SCHEMA,
        "score": score,
        "severity": severity,
        "signals": signals,
        "evidence": evidence,
        "scope_hosts": scope_hosts[:60],
        "covered_in_scope": covered[:60],
        "out_of_scope": oos[:40],
        "scope_uncovered": scope_uncovered[:60],
        "coverage_ratio": round(ratio, 2),
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "coverage-accounting", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "oos-target-hit = masalah KEPATUHAN lingkup (bukan "
                "temuan kerentanan); coverage-thin = status pekerjaan; "
                "granularitas host-level (path tidak dihitung)",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scope", required=True, help="file scope (1/baris)")
    ap.add_argument("--targets", required=True, action="append",
                    help="findings.json / file URL (boleh berulang)")
    ap.add_argument("--min-ratio", type=float, default=0.5,
                    help="ambang coverage-thin (default 0.5)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)
    try:
        result = triage(args.scope, args.targets, min_ratio=args.min_ratio)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
