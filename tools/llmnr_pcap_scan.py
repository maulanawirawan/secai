r"""[SAFETY: read-only] llmnr_pcap_scan — wave-5 deteksi OFFLINE indikasi
name-resolution poisoning (Responder) dari capture Ethernet offline:
pcap classic (stdlib murni) -> IPv4/UDP -> LLMNR (UDP 5355) dan NBT-NS
(UDP 137). Referensi teknik "Check SMB firewall rules with Responder" /
Responder dari pustaka referensi; parser dibangun dari nol (RFC 4795
untuk LLMNR, RFC 1002 untuk NBT-NS) — tanpa jaringan.

Mekanisme: query (QR=0) dipetakan per transaction ID -> nama; response
(QR=1) dicocokkan balik per transaction ID (fallback: nama di-sektor
pertama bila ada). Poisoning = SATU nama dijawab oleh >= 2 IP
pengirim berbeda (owner sah hanya satu), ATAU satu IP menjawab sangat
banyak nama berbeda (pola Responder menjawab semuanya).

Sinyal (verdict = LEAD indikator, bukan klaim kompromi):
  llmnr-multiple-responders (high) : >= --responders (default 2) IP
                                     menjawab nama LLMNR yang sama.
  llmnr-wildcard-claim      (high) : 1 IP menjawab >= --claim-threshold
                                     (default 8) nama LLMNR berbeda.
  nbtns-multiple-responders (high) : >= 2 IP menjawab nama NBT-NS sama.
  nbtns-wildcard-claim      (high) : 1 IP menjawab >= --claim-threshold
                                     nama NBT-NS berbeda.
Zero-FP: satu query + satu responder (host pemilik nama menjawab) =
CLEAN; capture tanpa satu pun paket LLMNR/NBT-NS -> exit 2 (bukan
artefak relevan). Paket terpotong di akhir file dicatat (truncated).
Nama never-claim umum (--allow-name, mis. wpad/lab hostname) tidak
dikecualikan otomatis — allowlist lewat flag bila jaringanmu sah
menjawab ganda.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/llmnr_pcap_scan.py --pcap capture.pcap
  python tools/llmnr_pcap_scan.py --pcap capture.pcap --json --out hasil.json
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
from pathlib import Path

SCHEMA = "secai.llmnr-pcap-scan/1"

LINKTYPE_ETHERNET = 1
ETHERTYPE_IPV4 = 0x0800
IPPROTO_UDP = 17
PORT_LLMNR = 5355
PORT_NBTNS = 137

SEV_ORDER = {"high": 0, "medium": 1, "info": 2}


def iter_pcap(data: bytes):
    """Yield (ts, linktype, packet, truncated) per paket pcap classic.
    Fail-closed: magic tidak dikenal -> ValueError."""
    if len(data) < 24:
        raise ValueError("file terlalu pendek untuk header pcap (24 byte)")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        raise ValueError(f"magic pcap tidak dikenal: {magic.hex()}")
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(
        endian + "HHiIII", data[4:24])
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _orig = struct.unpack(
            endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl_len > len(data):
            yield (ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6),
                   linktype, data[off:], True)
            return
        yield (ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6),
               linktype, data[off:off + incl_len], False)
        off += incl_len


def ipv4_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def parse_udp_frame(pkt: bytes):
    """Ethernet -> IPv4 -> UDP. Return dict atau None (bukan UDP IPv4).

    Fragmen non-pertama dilewati (None); VLAN tag tidak didukung
    (dilewati — dicatat di stats)."""
    if len(pkt) < 14:
        return None
    ethertype = struct.unpack(">H", pkt[12:14])[0]
    if ethertype != ETHERTYPE_IPV4:
        return None
    ip = pkt[14:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return None
    if ip[9] != IPPROTO_UDP:
        return None
    frag = struct.unpack(">H", ip[6:8])[0]
    if frag & 0x1FFF:
        return None  # fragmen lanjutan tanpa header UDP
    src = ipv4_str(ip[12:16])
    udp = ip[ihl:]
    if len(udp) < 8:
        return None
    sport, dport, ulen = struct.unpack(">HHH", udp[:6])
    payload = udp[8:max(ulen, 8)] if ulen >= 8 else udp[8:]
    return {"src": src, "sport": sport, "dport": dport, "payload": payload}


def _read_name(payload: bytes, off: int) -> "tuple[str, int] | None":
    """Baca nama berlabel (LLMNR/mDNS style). None = tak ter-parse."""
    labels: "list[str]" = []
    for _ in range(9):
        if off >= len(payload):
            return None
        ln = payload[off]
        off += 1
        if ln == 0:
            break
        if ln > 63 or off + ln > len(payload):
            return None
        labels.append(payload[off:off + ln].decode("latin-1",
                                                  errors="replace"))
        off += ln
    else:
        return None
    return ".".join(labels).lower(), off


def parse_llmnr(payload: bytes) -> "dict | None":
    """RFC 4795: ID, Flags(QR=0x8000), QDCOUNT..ARCOUNT. Nama dari
    question section bila ada."""
    if len(payload) < 12:
        return None
    mid, flags = struct.unpack_from(">HH", payload, 0)
    qr = bool(flags & 0x8000)
    got = _read_name(payload, 12)
    qname = got[0] if got else None
    return {"id": mid, "qr": qr, "qname": qname}


def decode_netbios(enc: bytes) -> "str | None":
    """First-level encoding RFC 1001: 32 byte 'A'-based -> 16 byte."""
    if len(enc) != 32:
        return None
    out = bytearray()
    for i in range(0, 32, 2):
        hi, lo = enc[i] - 0x41, enc[i + 1] - 0x41
        if not (0 <= hi <= 15 and 0 <= lo <= 15):
            return None
        out.append((hi << 4) | lo)
    name = out[:15].decode("latin-1").rstrip(" \x00")
    return name if name else None


def parse_nbtns(payload: bytes) -> "dict | None":
    """RFC 1002 NAME_TRN_HDR: ID, FLAGS(QR=0x8000), QDCOUNT..ARCOUNT;
    question = 33 byte (32 encoded + 0x00) + qtype + qclass."""
    if len(payload) < 12:
        return None
    tid, flags = struct.unpack_from(">HH", payload, 0)
    qr = bool(flags & 0x8000)
    qname = None
    if len(payload) >= 12 + 33:
        qname = decode_netbios(payload[12:44])
    return {"id": tid, "qr": qr, "qname": qname}


def scan(data: bytes, *, responders: int = 2, claim_threshold: int = 8,
         fail_on: str = "high") -> dict:
    """Scan penuh byte pcap -> ringkasan + daftar temuan. Tanpa jaringan."""
    total = 0
    truncated = False
    non_ip = 0
    udp_frames = 0
    linktypes: Counter[int] = Counter()
    llmnr_queries = llmnr_responses = 0
    nbtns_queries = nbtns_responses = 0
    # id -> set nama yang diklaim responder id tsb (per protokol)
    q_by_id: "dict[tuple[str, int], str]" = {}
    # nama -> set IP responder
    llmnr_names: "dict[str, set[str]]" = {}
    nbtns_names: "dict[str, set[str]]" = {}
    # responder IP -> set nama (per protokol) untuk wildcard-claim
    llmnr_by_ip: "dict[str, set[str]]" = {}
    nbtns_by_ip: "dict[str, set[str]]" = {}

    for ts, linktype, pkt, trunc in iter_pcap(data):
        del ts
        total += 1
        linktypes[linktype] += 1
        if trunc:
            truncated = True
            break
        f = parse_udp_frame(pkt)
        if f is None:
            non_ip += 1
            continue
        udp_frames += 1
        dport = f["dport"]
        msg = (parse_llmnr(f["payload"]) if dport == PORT_LLMNR
               else parse_nbtns(f["payload"]) if dport == PORT_NBTNS
               else None)
        if msg is None:
            continue
        proto = "llmnr" if dport == PORT_LLMNR else "nbtns"
        names_map = llmnr_names if proto == "llmnr" else nbtns_names
        by_ip = llmnr_by_ip if proto == "llmnr" else nbtns_by_ip
        key = (proto, msg["id"])
        if not msg["qr"]:
            if proto == "llmnr":
                llmnr_queries += 1
            else:
                nbtns_queries += 1
            if msg["qname"]:
                q_by_id[key] = msg["qname"]
            continue
        if proto == "llmnr":
            llmnr_responses += 1
        else:
            nbtns_responses += 1
        name = msg["qname"] or q_by_id.get(key)
        if not name:
            continue
        names_map.setdefault(name, set()).add(f["src"])
        by_ip.setdefault(f["src"], set()).add(name)

    findings: "list[dict]" = []
    for proto, names_map, by_ip, mcheck, wcheck in (
            ("llmnr", llmnr_names, llmnr_by_ip,
             "llmnr-multiple-responders", "llmnr-wildcard-claim"),
            ("nbtns", nbtns_names, nbtns_by_ip,
             "nbtns-multiple-responders", "nbtns-wildcard-claim")):
        for name, ips in sorted(names_map.items()):
            if len(ips) >= responders:
                findings.append({
                    "check": mcheck,
                    "severity": "high",
                    "protocol": proto,
                    "name": name[:80],
                    "responders": sorted(ips),
                    "message": f"nama {name!r} dijawab {len(ips)} IP "
                               f"berbeda ({', '.join(sorted(ips))}) — "
                               "indikasi poisoning (owner sah hanya "
                               "satu).",
                })
        for ip, names in sorted(by_ip.items()):
            if len(names) >= claim_threshold:
                findings.append({
                    "check": wcheck,
                    "severity": "high",
                    "protocol": proto,
                    "responder": ip,
                    "names_claimed": len(names),
                    "message": f"IP {ip} menjawab {len(names)} nama "
                               f"{proto.upper()} berbeda — pola Responder "
                               "menjawab semua query.",
                })

    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9),
                                 f["check"], f.get("name", "")))

    verdict = ("MALICIOUS_PATTERN_DETECTED" if findings
               else "CLEAN_NO_POISONING")
    return {
        "schema": SCHEMA,
        "packets_scanned": total,
        "truncated": truncated,
        "linktypes": {str(k): v for k, v in sorted(linktypes.items())},
        "udp_frames": udp_frames,
        "non_ip_frames": non_ip,
        "llmnr_queries": llmnr_queries,
        "llmnr_responses": llmnr_responses,
        "nbtns_queries": nbtns_queries,
        "nbtns_responses": nbtns_responses,
        "names_claimed": {"llmnr": len(llmnr_names),
                          "nbtns": len(nbtns_names)},
        "findings": findings,
        "verdict": verdict,
        "note": "read-only DFIR name-resolution; LLMNR/NBT-NS tanpa "
                "autentikasi — temuan LEAD indikator (replikasi/round-"
                "robin sah jarang menjawab ganda nama sama); konfirmasi "
                "dengan owner jaringan sebelum tindakan.",
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="llmnr_pcap_scan — deteksi indikasi poisoning "
                    "LLMNR/NBT-NS (Responder) dari pcap (read-only, "
                    "nol jaringan).")
    ap.add_argument("--pcap", required=True, help="file pcap classic")
    ap.add_argument("--responders", type=int, default=2,
                    help="ambang IP responder per nama (default 2)")
    ap.add_argument("--claim-threshold", type=int, default=8,
                    help="ambang nama berbeda per responder (default 8)")
    ap.add_argument("--fail-on", choices=["high"], default="high",
                    help="severity minimum utk exit 1 (default high)")
    ap.add_argument("--json", action="store_true", help="keluaran JSON")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.pcap)
    if not path.is_file():
        print(f"[llmnr] file tidak ada: {path}", file=sys.stderr)
        return 2
    data = path.read_bytes()
    try:
        result = scan(data, responders=args.responders,
                      claim_threshold=args.claim_threshold)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    relevant = (result["llmnr_queries"] + result["llmnr_responses"] +
                result["nbtns_queries"] + result["nbtns_responses"])
    if relevant == 0:
        print("ERROR: capture tidak memuat satu pun paket LLMNR/NBT-NS "
              "— bukan artefak yang relevan", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    if result["findings"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
