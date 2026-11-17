r"""[SAFETY: read-only] retest_ledger — wave-9 bandingkan DUA findings.json
kontrak secai (run lama vs run baru) utk siklus retest: temuan apa yang
PERSISTEN, FIXED, NEW, dan yang berubah severitas/verdict (mengikuti
konsep siklus retest "masih reproduksi / fixed / tak bisa konfirmasi";
diff dibangun dari nol, stdlib murni, tanpa jaringan).

Input: dua file findings.json (kontrak: {"ok","data","findings","requests"}
atau bare-list). Identitas temuan = tool + target_url/file_path + title
(judul drift = tampil sebagai fixed+new pasangan — jujur di-dokumentasi).

Output (bukan sinyal temuan — LEDGER keadaan):
  - persisted : ada di keduanya; bila severity/verdict berubah ->
                sub-status "changed".
  - fixed     : ada di run lama dgn verdict >= 1, hilang di run baru.
  - new       : baru di run baru; dgn verdict >= 1 = "new-lead",
                verdict 0 = "new-info".
Ringkasan: hitungan tiap keadaan + rasio fixed dari lead lama.
Tidak ada klaim AMAN/rentan tambahan — ledger murni delta antar run.

Fail-closed: file tidak ada / JSON rusak / bukan format findings ->
exit 2. Pemakaian:
  python tools/retest_ledger.py --old run1.json --new run2.json --out o.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "secai.retest-ledger/1"


def _load(path: str) -> list[dict]:
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"file tidak ada: {path}")
    try:
        doc = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON rusak di {path}: {exc}")
    if isinstance(doc, dict) and "findings" in doc:
        rows = doc.get("findings") or []
    elif isinstance(doc, list):
        rows = doc
    else:
        raise ValueError(f"{path} bukan findings.json kontrak")
    return [r for r in rows if isinstance(r, dict)]


def _key(row: dict) -> str:
    tgt = row.get("target_url") or row.get("file_path") or ""
    return "%s|%s|%s" % (row.get("tool", ""), tgt, row.get("title", ""))


def _load_pairs(path: str) -> dict:
    out = {}
    for row in _load(path):
        out.setdefault(_key(row), row)
    return out


def diff(old_path: str, new_path: str) -> dict:
    old = _load_pairs(old_path)
    new = _load_pairs(new_path)
    ledger: "list[dict]" = []
    counts = {"persisted": 0, "persisted-changed": 0, "fixed": 0,
              "new-lead": 0, "new-info": 0}

    for key, orow in old.items():
        if key in new:
            nrow = new[key]
            changed = (orow.get("severity") != nrow.get("severity") or
                       orow.get("verdict") != nrow.get("verdict"))
            state = "persisted-changed" if changed else "persisted"
            counts[state] += 1
            ledger.append({"state": state,
                           "tool": orow.get("tool", ""),
                           "target": orow.get("target_url") or
                           orow.get("file_path") or "",
                           "title": orow.get("title", "")[:120],
                           "old": {"severity": orow.get("severity"),
                                   "verdict": orow.get("verdict")},
                           "new": {"severity": nrow.get("severity"),
                                   "verdict": nrow.get("verdict")}})
        elif (orow.get("verdict") or 0) >= 1:
            counts["fixed"] += 1
            ledger.append({"state": "fixed",
                           "tool": orow.get("tool", ""),
                           "target": orow.get("target_url") or
                           orow.get("file_path") or "",
                           "title": orow.get("title", "")[:120],
                           "old": {"severity": orow.get("severity"),
                                   "verdict": orow.get("verdict")},
                           "new": None})
    for key, nrow in new.items():
        if key in old:
            continue
        state = "new-lead" if (nrow.get("verdict") or 0) >= 1 else "new-info"
        counts[state] += 1
        ledger.append({"state": state,
                       "tool": nrow.get("tool", ""),
                       "target": nrow.get("target_url") or
                       nrow.get("file_path") or "",
                       "title": nrow.get("title", "")[:120],
                       "old": None,
                       "new": {"severity": nrow.get("severity"),
                               "verdict": nrow.get("verdict")}})

    old_leads = sum(1 for r in old.values() if (r.get("verdict") or 0) >= 1)
    fixed_ratio = (counts["fixed"] / old_leads) if old_leads else 0.0
    return {
        "schema": SCHEMA,
        "old_source": old_path,
        "new_source": new_path,
        "old_count": len(old),
        "new_count": len(new),
        "counts": counts,
        "fixed_ratio": round(fixed_ratio, 2),
        "ledger": ledger,
        "note": "identitas = tool+target+judul — judul yang berubah "
                "tampil sebagai pasangan fixed+new (drift, bukan "
                "klaim); delta antar run TIDAK menambah klaim baru",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--old", required=True, help="findings.json run lama")
    ap.add_argument("--new", required=True, help="findings.json run baru")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)
    try:
        result = diff(args.old, args.new)
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
