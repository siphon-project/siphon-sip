#!/usr/bin/env python3
"""
Minimal, self-contained SIP/UDP probe for the HA demo. No external deps, no sipp.

It sends a single REGISTER / INVITE / OPTIONS and prints the status code of the
FIRST response received (or 000 on timeout). That's all the demo needs:

  - REGISTER -> 200 means the binding was accepted.
  - INVITE   -> 404 means the node does NOT know the AoR;
                1xx/2xx/4xx-other means the node DID find the binding and relayed
                (we don't complete the call — we only care that lookup succeeded).
  - OPTIONS  -> 200 means the node is up (readiness).

Usage:
  sipcli.py register <host> <port> <user> <contact_host> <contact_port>
  sipcli.py invite   <host> <port> <user>
  sipcli.py options  <host> <port>

Exit code 0 if a response arrived, 1 on timeout. The status code is printed to
stdout (three digits).
"""
import socket
import sys
import time

DOMAIN = "example.com"
TIMEOUT_S = 3.0


def _rand(n=8):
    # Cheap unique-ish token without importing random (deterministic enough; the
    # nanosecond clock varies per call).
    return f"{time.time_ns():x}"[-n:]


def _send(host, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT_S)
    # connect() so the kernel selects a route-correct source address (works for
    # both loopback and inter-pod/k8s). getsockname() then yields the real source
    # IP we put in Via/Contact, so the reply finds its way back to us.
    sock.connect((host, int(port)))
    local_host, local_port = sock.getsockname()
    wire = message.format(local_host=local_host, local_port=local_port).encode()
    sock.send(wire)
    try:
        data = sock.recv(65535)
    except socket.timeout:
        return None
    finally:
        sock.close()
    first = data.split(b"\r\n", 1)[0].decode(errors="replace")
    # "SIP/2.0 200 OK" -> "200"
    parts = first.split(" ", 2)
    return parts[1] if len(parts) >= 2 else "000"


def register(host, port, user, contact_host, contact_port):
    branch = _rand()
    call_id = _rand(12)
    tag = _rand()
    msg = (
        f"REGISTER sip:{DOMAIN} SIP/2.0\r\n"
        "Via: SIP/2.0/UDP {local_host}:{local_port};branch=z9hG4bK" + branch + "\r\n"
        "Max-Forwards: 70\r\n"
        f"From: <sip:{user}@{DOMAIN}>;tag={tag}\r\n"
        f"To: <sip:{user}@{DOMAIN}>\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{user}@{contact_host}:{contact_port}>\r\n"
        "Expires: 3600\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )
    return _send(host, port, msg)


def invite(host, port, user):
    branch = _rand()
    call_id = _rand(12)
    tag = _rand()
    msg = (
        f"INVITE sip:{user}@{DOMAIN} SIP/2.0\r\n"
        "Via: SIP/2.0/UDP {local_host}:{local_port};branch=z9hG4bK" + branch + "\r\n"
        "Max-Forwards: 70\r\n"
        f"From: <sip:caller@{DOMAIN}>;tag={tag}\r\n"
        f"To: <sip:{user}@{DOMAIN}>\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:caller@{local_host}:{local_port}>\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )
    return _send(host, port, msg)


def options(host, port):
    branch = _rand()
    call_id = _rand(12)
    tag = _rand()
    msg = (
        f"OPTIONS sip:{DOMAIN} SIP/2.0\r\n"
        "Via: SIP/2.0/UDP {local_host}:{local_port};branch=z9hG4bK" + branch + "\r\n"
        "Max-Forwards: 70\r\n"
        f"From: <sip:probe@{DOMAIN}>;tag={tag}\r\n"
        f"To: <sip:{DOMAIN}>\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )
    return _send(host, port, msg)


def main(argv):
    if len(argv) < 4:
        print("usage: sipcli.py <register|invite|options> <host> <port> [...]", file=sys.stderr)
        return 2
    cmd, host, port = argv[1], argv[2], argv[3]
    if cmd == "register":
        code = register(host, port, argv[4], argv[5], argv[6])
    elif cmd == "invite":
        code = invite(host, port, argv[4])
    elif cmd == "options":
        code = options(host, port)
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        return 2
    if code is None:
        print("000")
        return 1
    print(code)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
