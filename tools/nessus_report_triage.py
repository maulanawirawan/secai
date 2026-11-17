r"""[SAFETY: read-only] nessus_report_triage — wave-7 agregasi OFFLINE
laporan hasil pemindaian kerentanan format Nessus v2 (.nessus XML):
ringkas temuan per host/severity, tandai temuan kritikal, hitung
kerapatan temuan tinggi, dan catat status credentialed-scan (parser
xml.etree dari nol, stdlib murni, tanpa jaringan).

Struktur input (Nessus v2):
  <NessusClientData_v2><Report><ReportHost name="...">
    <HostProperties><tag name="HOST_START">...</tag>
    <tag name="Credentialed_Scan">true|false</tag>...</HostProperties>
    <ReportItem severity="0..4" pluginID=".." pluginName=".." />

Sinyal per report (semua deterministik dari data):
  - scan-critical-present : >= 1 temuan severity 4 (critical).
  - scan-high-dense       : rata-rata temuan severity 3 per host >=
                            --min-high (default 5) — permukaan terbuka.
  - scan-uncredentialed   : flag Credentialed_Scan=false (atau tidak
                            ada) — kedalaman scan terbatas (caveat
                            untuk semua severity rendah yang muncul).
  - scan-many-hosts       : >= --many host dipindai (default 50) —
                            konteks lingkungan besar.
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info. Report
sehat (tanpa critical, high per-host rendah, credentialed=true) ->
0 sinyal (zero-FP).

Fail-closed: file bukan XML .nessus (root NessusClientData_v2/
ReportHost) -> exit 2; file tidak ada -> exit 2.
Temuan = LEAD — severity milik scanner asli, bukan verifikasi kita;
cek tanggal scan (evidence HOST_START) sebelum menindak.

Pemakaian:
  python tools/nessus_report_triage.py --file report.nessus --out r.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEMA = "secai.nessus-report-triage/1"

SEV_NAMES = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _host_tags(host: ET.Element) -> dict:
    tags: dict[str, str] = {}
    props = host.find("HostProperties")
    if props is not None:
        for tag in props.findall("tag"):
            name = (tag.get("name") or "").strip()
            if name:
                tags[name] = (tag.text or "").strip()
    return tags


def triage_text(text: str, *, min_high: int = 5, many: int = 50) -> dict:
    """Triase laporan .nessus -> dict hasil. Raise ValueError bila
    bukan XML Nessus valid."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("XML tidak valid: %s" % exc)

    hosts = root.findall(".//ReportHost")
    if not hosts and not root.findall(".//Report"):
        raise ValueError("XML bukan laporan Nessus v2 (tidak ada "
                         "ReportHost/Report)")

    signals: "list[str]" = []
    evidence: dict[str, str] = {}
    sev_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    host_high: dict[str, int] = {}
    uncredentialed = 0
    host_start_min = None
    critical_items: "list[str]" = []

    for host in hosts:
        hname = host.get("name") or ""
        tags = _host_tags(host)
        if tags.get("HOST_START"):
            hs = tags["HOST_START"]
            host_start_min = hs if host_start_min is None else min(
                host_start_min, hs)
        if str(tags.get("Credentialed_Scan", "false")).lower() != "true":
            uncredentialed += 1
        n_high = 0
        for item in host.findall("ReportItem"):
            try:
                sev = int(item.get("severity", "0"))
            except ValueError:
                sev = 0
            sev = max(0, min(4, sev))
            sev_counts[sev] += 1
            if sev == 3:
                n_high += 1
            if sev == 4:
                critical_items.append(
                    "%s: %s" % (hname or "?",
                                item.get("pluginName", ""))[:120])
        host_high[hname or "?"] = n_high

    total_high = sev_counts[3]
    avg_high = total_high / len(hosts) if hosts else 0.0

    if sev_counts[4]:
        signals.append("scan-critical-present")
        evidence["critical"] = "; ".join(critical_items[:5])[:300]
        evidence["critical-count"] = str(sev_counts[4])
    if avg_high >= min_high:
        signals.append("scan-high-dense")
        evidence["avg-high-per-host"] = "%.1f" % avg_high
        evidence["total-high"] = str(total_high)
    if uncredentialed:
        signals.append("scan-uncredentialed")
        evidence["uncredentialed-hosts"] = "%d/%d" % (
            uncredentialed, len(hosts))
    if len(hosts) >= many:
        signals.append("scan-many-hosts")
        evidence["host-count"] = str(len(hosts))

    seen: set[str] = set()
    signals = [s for s in signals if not (s in seen or seen.add(s))]

    n_signals = len(signals)
    severity = ("high" if n_signals >= 3 else
                "medium" if n_signals == 2 else
                "low" if n_signals == 1 else "info")
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    counts[severity] = 1
    return {
        "schema": SCHEMA,
        "score": n_signals,
        "severity": severity,
        "signals": signals,
        "evidence": evidence,
        "host_count": len(hosts),
        "severity_totals": {SEV_NAMES[k]: v for k, v in sev_counts.items()},
        "avg_high_per_host": round(avg_high, 2),
        "scan_start": host_start_min,
        "severity_counts": counts,
        "finding_count": 1 if n_signals > 0 else 0,
        "findings": ([{"type": "scan-report-aggregate", "severity": severity,
                       "signals": signals,
                       "evidence": evidence}] if n_signals > 0 else []),
        "clean_count": 0 if n_signals > 0 else 1,
        "note": "severity milik scanner asli (bukan verifikasi); scan "
                "tanpa kredensial cenderung melewatkan banyak temuan — "
                "flag uncredentialed adalah caveat; cek tanggal scan",
        "read_only": True,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True, help="ekspor .nessus (XML v2)")
    ap.add_argument("--min-high", type=int, default=5,
                    help="ambang avg temuan high per host (default 5)")
    ap.add_argument("--many", type=int, default=50,
                    help="ambang scan-many-hosts (default 50)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        result = triage_text(text, min_high=args.min_high, many=args.many)
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
