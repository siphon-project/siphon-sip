#!/usr/bin/env python3
"""
HEP3 → pcap bridge for the LCR SIPp test.

Listens for siphon's HEP (Homer) SIP-message trace on a UDP port and writes a
real, Wireshark-openable pcap (Ethernet/IPv4/UDP frames synthesized from each
HEP packet's src/dst/timestamp + SIP payload). Needs no capture privilege
(CAP_NET_RAW), so it works where tcpdump/dumpcap can't open `lo`.

Run in the background, then SIGTERM/SIGINT it to flush the pcap:
    LCR_PCAP_OUT=/tmp/lcr.pcap python3 scripts/hep_to_pcap.py &
"""
import os
import signal
import socket
import struct
import sys

LISTEN = ("127.0.0.1", int(os.environ.get("HEP_PORT", "9060")))
OUT = os.environ.get("LCR_PCAP_OUT", "/tmp/lcr_failover.pcap")

packets = []  # (ts_sec, ts_usec, src_ip4, dst_ip4, sport, dport, payload)


def parse_hep3(data):
    """Decode one HEP3 datagram → dict of the fields we need, or None."""
    if len(data) < 6 or data[:4] != b"HEP3":
        return None
    fields = {}
    offset = 6  # skip "HEP3" + total length
    while offset + 6 <= len(data):
        _vendor, type_id, length = struct.unpack("!HHH", data[offset:offset + 6])
        if length < 6:
            break
        value = data[offset + 6:offset + length]
        fields[type_id] = value
        offset += length
    try:
        return {
            "src_ip": fields[0x0003],                       # IPv4 src (4 bytes)
            "dst_ip": fields[0x0004],                       # IPv4 dst (4 bytes)
            "sport": struct.unpack("!H", fields[0x0007])[0],
            "dport": struct.unpack("!H", fields[0x0008])[0],
            "ts_sec": struct.unpack("!I", fields[0x0009])[0],
            "ts_usec": struct.unpack("!I", fields[0x000a])[0],
            "payload": fields[0x000f],
        }
    except (KeyError, struct.error):
        return None


def ip_checksum(header):
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def build_frame(src_ip, dst_ip, sport, dport, payload):
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    total_len = 20 + udp_len
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total_len, 0, 0, 64, 17, 0) + src_ip + dst_ip
    ip = ip[:10] + struct.pack("!H", ip_checksum(ip)) + ip[12:]
    eth = b"\x00" * 12 + b"\x08\x00"  # dst+src mac zeroed, ethertype IPv4
    return eth + ip + udp


def write_pcap(path):
    with open(path, "wb") as handle:
        # Global header: magic, ver 2.4, tz 0, sigfigs 0, snaplen, LINKTYPE_ETHERNET(1)
        handle.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts_sec, ts_usec, src_ip, dst_ip, sport, dport, payload in packets:
            frame = build_frame(src_ip, dst_ip, sport, dport, payload)
            handle.write(struct.pack("!IIII", ts_sec, ts_usec, len(frame), len(frame)))
            handle.write(frame)
    print(f"wrote {len(packets)} packets to {path}", file=sys.stderr)


def flush_and_exit(*_):
    write_pcap(OUT)
    sys.exit(0)


def main():
    signal.signal(signal.SIGTERM, flush_and_exit)
    signal.signal(signal.SIGINT, flush_and_exit)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(LISTEN)
    print(f"HEP listening on {LISTEN}, pcap -> {OUT}", file=sys.stderr)
    while True:
        data, _ = sock.recvfrom(65535)
        hep = parse_hep3(data)
        if hep:
            packets.append((hep["ts_sec"], hep["ts_usec"], hep["src_ip"],
                            hep["dst_ip"], hep["sport"], hep["dport"], hep["payload"]))


if __name__ == "__main__":
    main()
