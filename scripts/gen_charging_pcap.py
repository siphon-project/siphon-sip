#!/usr/bin/env python3
"""Generate a reference pcap of a full Ro online-charging call flow.

Produces a Wireshark-openable capture of a prepaid B2BUA voice call that runs
out of credit mid-call and is torn down by siphon:

  Diameter (TCP/3868):  CER/CEA -> CCR-I/CCA-I(grant 30s)
                        -> CCR-U/CCA-U(grant) -> CCR-U/CCA-U(4012 deny)
                        -> CCR-T/CCA-T
  SIP (UDP/5060):       caller->siphon->callee INVITE/180/200/ACK,
                        then siphon BYEs BOTH legs on the 4012.

Every Diameter message is hand-encoded to the exact codes siphon emits
(RFC 8506 / 3GPP TS 32.299), so the capture is a faithful review artifact.

  python3 scripts/gen_charging_pcap.py [out.pcap]
"""
import struct
import sys

# ─────────────────────────── link/net framing ──────────────────────────────

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF

def eth(dst_mac: bytes, src_mac: bytes) -> bytes:
    return dst_mac + src_mac + b"\x08\x00"

def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, ident, 0x4000, 64, proto, 0) + src_b + dst_b
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload

def _l4_checksum(src: str, dst: str, proto: int, seg: bytes) -> int:
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, proto, len(seg))
    return checksum(pseudo + seg)

def udp(sport: int, dport: int, payload: bytes, src: str, dst: str) -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ck = _l4_checksum(src, dst, 17, seg) or 0xFFFF
    return seg[:6] + struct.pack("!H", ck) + seg[8:]

def tcp(sport, dport, seq, ack, flags, payload, src, dst) -> bytes:
    off = (5 << 4)
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags, 65535, 0, 0) + payload
    ck = _l4_checksum(src, dst, 6, seg)
    return seg[:16] + struct.pack("!H", ck) + seg[18:]

MAC = {
    "10.0.0.1": b"\x02\x00\x00\x00\x00\x01",
    "10.0.0.2": b"\x02\x00\x00\x00\x00\x02",
    "10.0.0.10": b"\x02\x00\x00\x00\x00\x10",
    "10.0.0.30": b"\x02\x00\x00\x00\x00\x30",
}
_ident = [0]
_packets = []  # (ts_float, frame_bytes)

def _emit(ts, src, dst, l4):
    _ident[0] += 1
    frame = eth(MAC[dst], MAC[src]) + ipv4(src, dst, l4[0], l4[1], _ident[0])
    _packets.append((ts, frame))

def sip(ts, src, dst, text: str):
    _emit(ts, src, dst, (17, udp(5060, 5060, text.replace("\n", "\r\n").encode(), src, dst)))

# minimal TCP stream state for the Diameter connection (siphon <-> OCS)
_tcp = {"cseq": 1000, "sseq": 5000}
def diam_tcp(ts, from_siphon: bool, payload: bytes, flags=0x18):  # PSH|ACK
    src, dst = ("10.0.0.10", "10.0.0.30") if from_siphon else ("10.0.0.30", "10.0.0.10")
    sport, dport = (41000, 3868) if from_siphon else (3868, 41000)
    if from_siphon:
        seq, ack = _tcp["cseq"], _tcp["sseq"]
        _tcp["cseq"] += len(payload)
    else:
        seq, ack = _tcp["sseq"], _tcp["cseq"]
        _tcp["sseq"] += len(payload)
    _emit(ts, src, dst, (6, tcp(sport, dport, seq, ack, flags, payload, src, dst)))

def tcp_handshake(ts):
    global _tcp
    _emit(ts, "10.0.0.10", "10.0.0.30", (6, tcp(41000, 3868, 1000, 0, 0x02, b"", "10.0.0.10", "10.0.0.30")))       # SYN
    _emit(ts + 0.001, "10.0.0.30", "10.0.0.10", (6, tcp(3868, 41000, 5000, 1001, 0x12, b"", "10.0.0.30", "10.0.0.10")))  # SYN-ACK
    _emit(ts + 0.002, "10.0.0.10", "10.0.0.30", (6, tcp(41000, 3868, 1001, 5001, 0x10, b"", "10.0.0.10", "10.0.0.30")))  # ACK
    _tcp = {"cseq": 1001, "sseq": 5001}

# ─────────────────────────── Diameter encoding ─────────────────────────────

TGPP = 10415
def avp(code: int, data: bytes, mandatory=True, vendor=0) -> bytes:
    flags = (0x80 if vendor else 0) | (0x40 if mandatory else 0)
    hlen = 8 + (4 if vendor else 0)
    length = hlen + len(data)
    out = struct.pack("!I", code) + bytes([flags]) + struct.pack("!I", length)[1:]
    if vendor:
        out += struct.pack("!I", vendor)
    out += data
    out += b"\x00" * ((4 - len(out) % 4) % 4)
    return out

def u32(v): return struct.pack("!I", v)
def s(x): return x.encode()
def grp(*avps): return b"".join(avps)
def ntime(unix): return struct.pack("!I", (unix + 2208988800) & 0xFFFFFFFF)

def msg(cmd, app, flags, hbh, e2e, *avps) -> bytes:
    body = b"".join(avps)
    total = 20 + len(body)
    return (bytes([1]) + struct.pack("!I", total)[1:] + bytes([flags])
            + struct.pack("!I", cmd)[1:] + struct.pack("!I", app)
            + struct.pack("!I", hbh) + struct.pack("!I", e2e) + body)

# AVP codes (RFC 8506 base = vendor 0; 3GPP = vendor 10415)
SESSION_ID, ORIGIN_HOST, ORIGIN_REALM, DEST_REALM, DEST_HOST = 263, 264, 296, 283, 293
HOST_IP, RESULT_CODE, AUTH_APP_ID, VENDOR_ID, PRODUCT_NAME = 257, 268, 258, 266, 269
FIRMWARE_REV, SUPPORTED_VENDOR, EVENT_TS, TERM_CAUSE = 267, 265, 55, 295
SERVICE_CTX, CC_REQ_TYPE, CC_REQ_NUM, SUB_ID, SUB_ID_TYPE, SUB_ID_DATA = 461, 416, 415, 443, 450, 444
MSI, MSCC, RSU, USU, GSU, CC_TIME, RATING_GROUP = 455, 456, 437, 446, 431, 420, 432
SERVICE_INFO, IMS_INFO, CALLING, CALLED, ROLE_NODE, NODE_FUNC, USER_SESS = 873, 876, 831, 832, 829, 862, 830

def host_ip(ip: str) -> bytes:  # Address = 2-byte family(1=IPv4) + 4 bytes
    return b"\x00\x01" + bytes(int(x) for x in ip.split("."))

def subscription(sip_uri: str) -> bytes:
    return avp(SUB_ID, grp(avp(SUB_ID_TYPE, u32(2)),          # END_USER_SIP_URI
                           avp(SUB_ID_DATA, s(sip_uri))))

def ims_info() -> bytes:
    inner = grp(
        avp(ROLE_NODE, u32(0), vendor=TGPP),                  # ORIGINATING_ROLE
        avp(NODE_FUNC, u32(6), vendor=TGPP),                  # AS
        avp(USER_SESS, s("call-abc@ims.example.org"), vendor=TGPP),
        avp(CALLING, s("sip:alice@ims.example.org"), vendor=TGPP),
        avp(CALLED, s("sip:bob@ims.example.org"), vendor=TGPP),
    )
    return avp(SERVICE_INFO, avp(IMS_INFO, inner, vendor=TGPP), vendor=TGPP)

CCR, CER, CEA_CMD = 272, 257, 257
SIPHON_H, SIPHON_R = "scscf.ims.example.org", "ims.example.org"
OCS_H, OCS_R = "ocs.example.org", "example.org"
SID = f"{SIPHON_H};3735928559;1"
CTX = "32260@3gpp.org"

def cer():
    return msg(CER, 0, 0x80, 1, 1,
               avp(ORIGIN_HOST, s(SIPHON_H)), avp(ORIGIN_REALM, s(SIPHON_R)),
               avp(HOST_IP, host_ip("10.0.0.10")), avp(VENDOR_ID, u32(0)),
               avp(PRODUCT_NAME, s("SIPhon"), mandatory=False), avp(FIRMWARE_REV, u32(1), mandatory=False),
               avp(SUPPORTED_VENDOR, u32(TGPP)),
               avp(AUTH_APP_ID, u32(4)))       # Ro = Auth-Application-Id 4 (the CER fix: no VSAI, no Acct)

def cea():
    return msg(CEA_CMD, 0, 0, 1, 1,
               avp(RESULT_CODE, u32(2001)), avp(ORIGIN_HOST, s(OCS_H)), avp(ORIGIN_REALM, s(OCS_R)),
               avp(HOST_IP, host_ip("10.0.0.30")), avp(VENDOR_ID, u32(0)),
               avp(PRODUCT_NAME, s("CGRateS"), mandatory=False), avp(AUTH_APP_ID, u32(4)))

def ccr(hbh, e2e, req_type, req_num, unix, rsu=None, usu=None, initial=False, term=False):
    avps = [avp(SESSION_ID, s(SID)), avp(ORIGIN_HOST, s(SIPHON_H)), avp(ORIGIN_REALM, s(SIPHON_R)),
            avp(DEST_REALM, s(OCS_R)), avp(AUTH_APP_ID, u32(4)), avp(SERVICE_CTX, s(CTX)),
            avp(CC_REQ_TYPE, u32(req_type)), avp(CC_REQ_NUM, u32(req_num)),
            subscription("sip:alice@ims.example.org"), avp(EVENT_TS, ntime(unix))]
    if initial:
        avps.append(avp(MSI, u32(1)))                          # MULTIPLE_SERVICES_SUPPORTED
    mscc_children = [avp(RATING_GROUP, u32(100))]
    if rsu is not None:
        mscc_children.append(avp(RSU, grp(avp(CC_TIME, u32(rsu)))))
    if usu is not None:
        mscc_children.append(avp(USU, grp(avp(CC_TIME, u32(usu)))))
    avps.append(avp(MSCC, grp(*mscc_children)))               # base vendor-0 MSCC
    if term:
        avps.append(avp(TERM_CAUSE, u32(1)))                  # DIAMETER_LOGOUT
    else:
        avps.append(ims_info())
    return msg(CCR, 4, 0xC0, hbh, e2e, *avps)

def cca(hbh, e2e, req_type, req_num, result, granted=None):
    avps = [avp(SESSION_ID, s(SID)), avp(RESULT_CODE, u32(result)),
            avp(ORIGIN_HOST, s(OCS_H)), avp(ORIGIN_REALM, s(OCS_R)),
            avp(CC_REQ_TYPE, u32(req_type)), avp(CC_REQ_NUM, u32(req_num))]
    if granted is not None:
        avps.append(avp(MSCC, grp(avp(GSU, grp(avp(CC_TIME, u32(granted)))))))
    return msg(CCR, 4, 0x40, hbh, e2e, *avps)

# ─────────────────────────── the call flow ─────────────────────────────────

def sdp(user, ip, port):
    return (f"v=0\no={user} 1 1 IN IP4 {ip}\ns=-\nc=IN IP4 {ip}\nt=0 0\n"
            f"m=audio {port} RTP/AVP 0 8\na=rtpmap:0 PCMU/8000\na=rtpmap:8 PCMA/8000\n")

def invite(frm, to, cid, cseq, ruri, contact, ip, body):
    return (f"INVITE {ruri} SIP/2.0\nVia: SIP/2.0/UDP {ip}:5060;branch=z9hG4bK{cseq}{cid[:6]}\n"
            f"From: <sip:alice@ims.example.org>;tag=a1\nTo: <{to}>\nCall-ID: {cid}\n"
            f"CSeq: {cseq} INVITE\nContact: <{contact}>\nMax-Forwards: 70\n"
            f"Content-Type: application/sdp\nContent-Length: {len(body.replace(chr(10),chr(13)+chr(10)))}\n\n{body}")

def resp(code, reason, cid, cseq, totag, contact, body=""):
    cl = len(body.replace(chr(10), chr(13)+chr(10))) if body else 0
    ct = "Content-Type: application/sdp\n" if body else ""
    return (f"SIP/2.0 {code} {reason}\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1abc\n"
            f"From: <sip:alice@ims.example.org>;tag=a1\nTo: <sip:bob@ims.example.org>;tag={totag}\n"
            f"Call-ID: {cid}\nCSeq: {cseq}\n{('Contact: <'+contact+'>'+chr(10)) if contact else ''}{ct}Content-Length: {cl}\n\n{body}")

def bye(cid, cseq, totag, src_ip, ruri, reason):
    return (f"BYE {ruri} SIP/2.0\nVia: SIP/2.0/UDP {src_ip}:5060;branch=z9hG4bK{cseq}bye\n"
            f"From: <sip:alice@ims.example.org>;tag=a1\nTo: <sip:bob@ims.example.org>;tag={totag}\n"
            f"Call-ID: {cid}\nCSeq: {cseq} BYE\nReason: Q.850;cause=16;text=\"credit limit reached\"\n"
            f"Max-Forwards: 70\nContent-Length: 0\n\n")

ACID, BCID = "call-abc@ims.example.org", "bleg-xyz@ims.example.org"

tcp_handshake(-0.020)
diam_tcp(0.00, True, cer())
diam_tcp(0.01, False, cea())

sip(1.00, "10.0.0.1", "10.0.0.10", invite("alice", "sip:bob@ims.example.org", ACID, 1,
        "sip:bob@ims.example.org", "sip:alice@10.0.0.1:5060", "10.0.0.1", sdp("alice", "10.0.0.1", 40000)))
sip(1.01, "10.0.0.10", "10.0.0.2", invite("alice", "sip:bob@ims.example.org", BCID, 1,
        "sip:bob@10.0.0.2:5060", "sip:siphon@10.0.0.10:5060", "10.0.0.10", sdp("siphon", "10.0.0.10", 41000)))
sip(1.02, "10.0.0.2", "10.0.0.10", resp("100", "Trying", BCID, "1 INVITE", "", ""))
sip(1.05, "10.0.0.2", "10.0.0.10", resp("180", "Ringing", BCID, "1 INVITE", "b1", "sip:bob@10.0.0.2:5060"))
sip(1.06, "10.0.0.10", "10.0.0.1", resp("180", "Ringing", ACID, "1 INVITE", "s1", "sip:siphon@10.0.0.10:5060"))
sip(2.00, "10.0.0.2", "10.0.0.10", resp("200", "OK", BCID, "1 INVITE", "b1", "sip:bob@10.0.0.2:5060", sdp("bob", "10.0.0.2", 42000)))
sip(2.01, "10.0.0.10", "10.0.0.1", resp("200", "OK", ACID, "1 INVITE", "s1", "sip:siphon@10.0.0.10:5060", sdp("siphon", "10.0.0.10", 41000)))
sip(2.02, "10.0.0.1", "10.0.0.10", f"ACK sip:siphon@10.0.0.10:5060 SIP/2.0\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1ack\nFrom: <sip:alice@ims.example.org>;tag=a1\nTo: <sip:bob@ims.example.org>;tag=s1\nCall-ID: {ACID}\nCSeq: 1 ACK\nMax-Forwards: 70\nContent-Length: 0\n\n")
sip(2.03, "10.0.0.10", "10.0.0.2", f"ACK sip:bob@10.0.0.2:5060 SIP/2.0\nVia: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK1ackb\nFrom: <sip:alice@ims.example.org>;tag=a1\nTo: <sip:bob@ims.example.org>;tag=b1\nCall-ID: {BCID}\nCSeq: 1 ACK\nMax-Forwards: 70\nContent-Length: 0\n\n")

# Reserve at answer, re-auth every 30s, deny on the second update, then tear down.
diam_tcp(2.10, True, ccr(2, 2, req_type=1, req_num=0, unix=1_700_000_000, rsu=30, initial=True))
diam_tcp(2.15, False, cca(2, 2, req_type=1, req_num=0, result=2001, granted=30))
diam_tcp(32.15, True, ccr(3, 3, req_type=2, req_num=1, unix=1_700_000_030, rsu=30, usu=30))
diam_tcp(32.20, False, cca(3, 3, req_type=2, req_num=1, result=2001, granted=30))
diam_tcp(62.20, True, ccr(4, 4, req_type=2, req_num=2, unix=1_700_000_060, rsu=30, usu=30))
diam_tcp(62.25, False, cca(4, 4, req_type=2, req_num=2, result=4012))          # CREDIT_LIMIT_REACHED

sip(62.26, "10.0.0.10", "10.0.0.1", bye(ACID, 2, "s1", "10.0.0.10", "sip:alice@10.0.0.1:5060", "credit limit reached"))
sip(62.27, "10.0.0.10", "10.0.0.2", bye(BCID, 2, "b1", "10.0.0.10", "sip:bob@10.0.0.2:5060", "credit limit reached"))
sip(62.30, "10.0.0.1", "10.0.0.10", resp("200", "OK", ACID, "2 BYE", "s1", ""))
sip(62.31, "10.0.0.2", "10.0.0.10", resp("200", "OK", BCID, "2 BYE", "b1", ""))

diam_tcp(62.32, True, ccr(5, 5, req_type=3, req_num=3, unix=1_700_000_060, usu=0, term=True))  # final USU ~0
diam_tcp(62.36, False, cca(5, 5, req_type=3, req_num=3, result=2001))

# ─────────────────────────── write the pcap ────────────────────────────────

out = sys.argv[1] if len(sys.argv) > 1 else "charging_flow.pcap"
with open(out, "wb") as f:
    f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, frame in _packets:
        f.write(struct.pack("!IIII", int(ts) if ts >= 0 else 0,
                            int((ts % 1) * 1_000_000) if ts >= 0 else 0, len(frame), len(frame)))
        f.write(frame)
print(f"wrote {len(_packets)} packets -> {out}")
