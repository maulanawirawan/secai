r"""[SAFETY: read-only] patch_guard_triage — wave-10 triase OFFLINE diff
patch vendor (unified diff `diff -u`/git) untuk memulihkan KELAS BUG
N-day dari perubahan perbaikan: guard yang ditambahkan di versi patched
mengungkap kelas bug di versi lama (bounds check = OOB, lock = race,
zeroing = info leak, access check = missing authz, dst — tabel
guard->kelas standar patch-diffing). Parser dari nol, stdlib murni,
tanpa jaringan. Beda ranah dari diff_risk_scan (audit risiko diff repo
sendiri) — ini arah N-day: patch vendor -> infer versi rentan.

Sinyal per artefak (semua deterministik dari baris ADDED '+'):
  - pg-guard-bounds   : pengecekan batas baru (idx >= MAX, len > buf,
                        MIN/clamp/arraybounds) -> OOB.
  - pg-guard-overflow : aritmetika ter-check (__builtin_*_overflow,
                        checked/saturating add, a + b < a) -> int
                        overflow.
  - pg-guard-lock     : mutex/spinlock/lock_guard baru -> race/TOCTOU/
                        double-free.
  - pg-guard-zeroing  : memset-0/zeroize/SecureZeroMemory baru ->
                        uninitialized info leak.
  - pg-guard-refcount : refcount dec + check (kref/InterlockedDecrement)
                        -> UAF.
  - pg-guard-authz    : access/permission/capability check baru ->
                        missing authorization.
  - pg-dangerous-removed : pemanggilan berbahaya DIHAPUS (strcpy/
                        sprintf/gets/system/eval) -> kelas
                        overflow/injection di versi lama.
  - pg-cve-ref        : pesan commit/header diff menyebut CVE-/GHSA —
                        fakta identitas patch.
Skor = jumlah sinyal kelas; >= 3 high, == 2 medium, == 1 low, 0 info
(diff tanpa guard keamanan — refactor biasa -> clean, zero-FP).

Fail-closed: teks bukan unified diff (tanpa marker ---/+++ /@@ /diff
--git) -> exit 2; file tidak ada -> exit 2. Temuan = LEAD — kelas bug
di-infer dari guard, bukan dibuktikan; konfirmasi PoC di versi lama
berizin sebelum klaim.

Pemakaian:
  python tools/patch_guard_triage.py --file fix.patch --out o.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.patch-guard-triage/1"

_RE_CTX = re.compile(r"^diff --git |^--- a/|^--- [^\r\n]+\t|^\+\+\+ b/|^@@ -\d+",
                     re.M)
_RE_ADDED = re.compile(r"^\+(?!\+\+)[^\r\n]*", re.M)
_RE_REMOVED = re.compile(r"^-(?!-)[^\r\n]*", re.M)

_GAURDS = (
    ("pg-guard-bounds", re.compile(
        r"if\s*\(\s*\w+\s*>=\s*\w*(?:MAX|SIZE|LEN|count)|"
        r"if\s*\(\s*\w*?(?:len|size|idx|count)\s*[<>]|"
        r"(?:MIN|CLAMP|min|max)\s*\(|"
        r"arraybounds|__builtin_object_size", re.I)),
    ("pg-guard-overflow", re.compile(
        r"__builtin_(?:u)?(?:add|sub|mul)_overflow|checked_(?:add|mul)|"
        r"saturating_(?:add|mul)|if\s*\(\s*\w+\s*\+\s*\w+\s*<\s*\w+|"
        r"INT_MAX|UINT_MAX", re.I)),
    ("pg-guard-lock", re.compile(
        r"mutex_lock|spin_lock|lock_guard\s*<|KeAcquireSpinLock|"
        r"pthread_mutex_lock|std::unique_lock|acquire\s*\(\s*\)", re.I)),
    ("pg-guard-zeroing", re.compile(
        r"RtlZeroMemory|SecureZeroMemory|explicit_bzero|memset\s*\("
        r"[^)]*,\s*0|zeroize|ZeroMemory\s*\(", re.I)),
    ("pg-guard-refcount", re.compile(
        r"InterlockedDecrement|kref_put|refcount_dec(?:_and_test)?|"
        r"Release\(\)\s*;?\s*(?:if|return).*ref|atomic_dec", re.I)),
    ("pg-guard-authz", re.compile(
        r"SeAccessCheck|AccessCheck\(|acl_check|has_permission|"
        r"check_permission|permission_check|require_permission|"
        r"authorize|current_user_can", re.I)),
)
_RE_DANGEROUS = re.compile(
    r"\b(strcpy|strcat|sprintf|gets|lstrcpy|system\s*\(|eval\s*\(|"
    r"exec\s*\(|unserialize\s*\(|pickle\.loads)", re.I)
_RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}",
                     re.I)


def triage_text(text: str) -> dict:
    """Triase diff patch -> dict hasil. Raise ValueError bila bukan
    unified diff."""
    if not _RE_CTX.search(text):
        raise ValueError("teks bukan unified diff (tidak ada marker "
                         "diff --git / --- a/ / @@)")

    added = "\n".join(_RE_ADDED.findall(text))
    removed = "\n".join(_RE_REMOVED.findall(text))

    signals: "list[str]" = []
    evidence: dict[str, str] = {}
    classes: "list[str]" = []

    for name, rx in _GAURDS:
        m = rx.search(added)
        if m:
            signals.append(name)
            evidence[name] = m.group(0)[:100]
            classes.append(name.replace("pg-guard-", ""))

    dm = _RE_DANGEROUS.search(removed)
    if dm:
        signals.append("pg-dangerous-removed")
        evidence["dangerous-removed"] = dm.group(0)[:80]
        classes.append("overflow/injection")

    cm = _RE_CVE.search(text)
    if cm:
        signals.append("pg-cve-ref")
        evidence["cve-ref"] = cm.group(0)

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
        "inferred_classes": classes,
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "patch-guard", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "kelas bug DI-INFER dari guard patched (tabel "
                "guard->kelas standar patch-diffing) — bukan bukti; "
                "PoC di versi lama berizin wajib sebelum klaim; diff "
                "tanpa guard keamanan = refactor biasa",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="unified diff patch vendor (git/diff -u)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        result = triage_text(text)
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
