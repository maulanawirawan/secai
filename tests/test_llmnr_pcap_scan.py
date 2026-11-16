"""Test llmnr_pcap_scan — NOL jaringan, pcap dibangun sintetis di
memori (byte Ethernet II + IPv4 + UDP + LLMNR RFC 4795 / NBT-NS
RFC 1002); tidak ada capture file asli dan tidak ada trafik.

Kontrak yang dikunci:
  - clean: satu query LLMNR + satu responder (pemilik nama sah)
    -> 0 temuan, verdict CLEAN, exit 0;
  - poisoning: satu nama dijawab 2 IP -> llmnr-multiple-responders
    (high), exit 1 via main (fail-on high);
  - wildcard: satu IP menjawab >= 8 nama -> llmnr-wildcard-claim;
  - NBT-NS: nama encoded RFC 1001 ter-decode, poisoning terdeteksi;
  - fail-closed: capture tanpa LLMNR/NBT-NS sama sekali -> exit 2;
    magic pcap tidak dikenal -> 2; file hilang -> 2;
  - paket terpotong -> truncated tercatat.
"""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys_path = str(ROOT / "tools")
if sys_path not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_path)

import llmnr_pcap_scan as lps  # noqa: E402


def _ip(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def _mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def eth_udp(src_mac: str, src_ip: str, sport: int, dport: int,
            payload: bytes, dst_mac: str = "ff:ff:ff:ff:ff:ff") -> bytes:
    eth = _mac(dst_mac) + _mac(src_mac) + struct.pack(">H", 0x0800)
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                     _ip(src_ip), _ip("224.0.0.252"))
    return eth + ip + udp


def llmnr_query(mid: int, name: str) -> bytes:
    q = struct.pack(">HHHHHH", mid, 0x0000, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack(">HH", 1, 1)


def llmnr_response(mid: int, name: str) -> bytes:
    return struct.pack(">HHHHHH", mid, 0x8000, 1, 0, 0, 0) + \
        llmnr_query(mid, name)[12:-4]


def nb_encoded(name: str, suffix: int = 0x20) -> bytes:
    raw = name.encode("latin-1")[:15].ljust(15, b" ") + bytes([suffix])
    out = bytearray()
    for b in raw:
        out.append(0x41 + (b >> 4))
        out.append(0x41 + (b & 0x0F))
    return bytes(out)


def nbtns_query(tid: int, name: str) -> bytes:
    return struct.pack(">HHHHHH", tid, 0x0000, 1, 0, 0, 0) + \
        nb_encoded(name) + b"\x00" + struct.pack(">HH", 0x0020, 0x0001)


def nbtns_response(tid: int, name: str) -> bytes:
    return struct.pack(">HHHHHH", tid, 0x8000, 1, 0, 0, 0) + \
        nb_encoded(name) + b"\x00" + struct.pack(">HH", 0x0020, 0x0001)


def pcap_bytes(packets: "list[bytes]") -> bytes:
    out = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, 1)
    for i, pkt in enumerate(packets):
        ts = i + 1
        out += struct.pack("<IIII", ts, 0, len(pkt), len(pkt)) + pkt
    return out


CLIENT = "10.0.0.50"
RESP1 = "10.0.0.1"
RESP2 = "10.0.0.66"
MAC_A = "02:00:00:00:aa:01"
MAC_B = "02:00:00:00:aa:02"
MAC_C = "02:00:00:00:bb:66"


class LlmnrPcapScanTest(unittest.TestCase):
    def test_clean_single_responder(self):
        pcap = pcap_bytes([
            eth_udp(MAC_A, CLIENT, 5355, 5355, llmnr_query(0x11, "wpad")),
            eth_udp(MAC_B, RESP1, 5355, 5355, llmnr_response(0x11, "wpad")),
        ])
        r = lps.scan(pcap)
        self.assertEqual(r["verdict"], "CLEAN_NO_POISONING")
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["llmnr_queries"], 1)
        self.assertEqual(r["llmnr_responses"], 1)
        self.assertEqual(r["names_claimed"]["llmnr"], 1)

    def test_llmnr_multiple_responders(self):
        pcap = pcap_bytes([
            eth_udp(MAC_A, CLIENT, 5355, 5355, llmnr_query(0x22, "wpad")),
            eth_udp(MAC_B, RESP1, 5355, 5355, llmnr_response(0x22, "wpad")),
            eth_udp(MAC_C, RESP2, 5355, 5355, llmnr_response(0x22, "wpad")),
        ])
        r = lps.scan(pcap)
        self.assertEqual(len(r["findings"]), 1)
        f = r["findings"][0]
        self.assertEqual(f["check"], "llmnr-multiple-responders")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["name"], "wpad")
        self.assertEqual(f["responders"], [RESP1, RESP2])
        self.assertEqual(r["verdict"], "MALICIOUS_PATTERN_DETECTED")
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "c.pcap"
            src.write_bytes(pcap)
            self.assertEqual(lps.main(["--pcap", str(src)]), 1)

    def test_wildcard_claim(self):
        pkts = []
        mid = 0x100
        for i in range(8):
            name = f"host{i:02d}"
            pkts.append(eth_udp(MAC_A, CLIENT, 5355, 5355,
                                llmnr_query(mid, name)))
            pkts.append(eth_udp(MAC_B, RESP2, 5355, 5355,
                                llmnr_response(mid, name)))
            mid += 1
        r = lps.scan(pcap_bytes(pkts))
        checks = {f["check"] for f in r["findings"]}
        self.assertIn("llmnr-wildcard-claim", checks)
        wf = next(f for f in r["findings"]
                  if f["check"] == "llmnr-wildcard-claim")
        self.assertEqual(wf["responder"], RESP2)
        self.assertEqual(wf["names_claimed"], 8)
        # tidak ada multiple-responders (tiap nama satu responder)
        self.assertNotIn("llmnr-multiple-responders", checks)

    def test_nbtns_poisoning(self):
        pcap = pcap_bytes([
            eth_udp(MAC_A, CLIENT, 137, 137, nbtns_query(0x33, "NASFILE")),
            eth_udp(MAC_B, RESP1, 137, 137, nbtns_response(0x33, "NASFILE")),
            eth_udp(MAC_C, RESP2, 137, 137, nbtns_response(0x33, "NASFILE")),
        ])
        r = lps.scan(pcap)
        self.assertEqual(len(r["findings"]), 1)
        f = r["findings"][0]
        self.assertEqual(f["check"], "nbtns-multiple-responders")
        self.assertEqual(f["name"], "NASFILE")
        self.assertEqual(r["nbtns_queries"], 1)
        self.assertEqual(r["nbtns_responses"], 2)

    def test_truncated_packet_recorded(self):
        pcap = pcap_bytes([
            eth_udp(MAC_A, CLIENT, 5355, 5355, llmnr_query(0x44, "wpad")),
        ])
        # record header baru yang mengklaim 100 byte tanpa isi lengkap
        pcap += struct.pack("<IIII", 5, 0, 100, 100)
        r = lps.scan(pcap)
        self.assertTrue(r["truncated"])
        self.assertEqual(r["findings"], [])

    def test_fail_closed_no_llmnr_at_all(self):
        # frame IPv4 UDP ke port lain (bukan 5355/137)
        pkt = eth_udp(MAC_A, CLIENT, 9999, 80, b"\x00" * 8)
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "c.pcap"
            src.write_bytes(pcap_bytes([pkt]))
            self.assertEqual(lps.main(["--pcap", str(src)]), 2)

    def test_fail_closed_bad_magic(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "c.pcap"
            src.write_bytes(b"NOTPCAPDATA" * 4)
            self.assertEqual(lps.main(["--pcap", str(src)]), 2)

    def test_fail_closed_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(
                lps.main(["--pcap", str(Path(td) / "missing.pcap")]), 2)


if __name__ == "__main__":
    unittest.main()
