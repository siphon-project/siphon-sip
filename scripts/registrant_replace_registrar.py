#!/usr/bin/env python3
"""A registrar that keeps one binding per AoR, for scripts/registrant_restart_test.sh.

    registrant_replace_registrar.py serve PORT LOG_FILE USERNAME PASSWORD
    registrant_replace_registrar.py register PORT AOR CONTACT USERNAME PASSWORD

`serve` is a UDP registrar that challenges every REGISTER with a digest (RFC
3261 §22) and keeps ONE binding per AoR: a REGISTER with a Contact replaces
whatever the AoR held (RFC 3261 §10.3 calls for adding to the set, so this is
the replace-semantics registrar the restart clean-up has to be safe against),
`Expires: 0` on a Contact removes the AoR's binding if it is that Contact, and
a REGISTER with no Contact is a fetch (§10.2.3) answered with the binding the
AoR holds. Every authenticated request is appended to LOG_FILE as one JSON line
(method, CSeq, Call-ID, Contact, Expires, and the binding held afterwards).

`register` is another node: one authenticated REGISTER of CONTACT for AoR.

Standard library only.
"""

import hashlib
import json
import re
import socket
import sys
import uuid

REALM = "registrar.test"


def md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def parse(data: bytes):
    head, _, _ = data.decode("latin-1").partition("\r\n\r\n")
    lines = head.split("\r\n")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return lines[0], headers


def digest_ok(headers, username: str, password: str, nonce: str) -> bool:
    values = headers.get("authorization", [])
    if not values:
        return False
    fields = {
        name: quoted or bare
        for name, quoted, bare in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', values[0])
    }
    if fields.get("username") != username or fields.get("nonce") != nonce:
        return False
    ha1 = md5(f"{username}:{REALM}:{password}")
    ha2 = md5(f"REGISTER:{fields.get('uri', '')}")
    if fields.get("qop") == "auth":
        expected = md5(f"{ha1}:{nonce}:{fields.get('nc')}:{fields.get('cnonce')}:auth:{ha2}")
    else:
        expected = md5(f"{ha1}:{nonce}:{ha2}")
    return fields.get("response") == expected


def contact_uri(value: str) -> str:
    match = re.search(r"<([^>]*)>", value)
    return match.group(1) if match else value.split(";")[0].strip()


def response(status: str, headers, extra=()):
    lines = [f"SIP/2.0 {status}"]
    lines += [f"Via: {via}" for via in headers.get("via", [])]
    lines.append(f"From: {headers['from'][0]}")
    to = headers["to"][0]
    lines.append(f"To: {to}" if "tag=" in to else f"To: {to};tag=replace-registrar")
    lines.append(f"Call-ID: {headers['call-id'][0]}")
    lines.append(f"CSeq: {headers['cseq'][0]}")
    lines += list(extra)
    lines.append("Content-Length: 0")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def serve(port: int, log_file: str, username: str, password: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    bindings = {}  # AoR -> Contact URI: one per AoR
    nonce = uuid.uuid4().hex
    while True:
        data, peer = sock.recvfrom(65535)
        try:
            start, headers = parse(data)
        except (UnicodeDecodeError, KeyError):
            continue
        if not start.startswith("REGISTER "):
            continue
        if not digest_ok(headers, username, password, nonce):
            challenge = f'WWW-Authenticate: Digest realm="{REALM}", nonce="{nonce}", algorithm=MD5, qop="auth"'
            sock.sendto(response("401 Unauthorized", headers, [challenge]), peer)
            continue
        aor = contact_uri(headers["to"][0])
        contacts = headers.get("contact", [])
        expires = headers.get("expires", [""])[0]
        if contacts:
            uri = contact_uri(contacts[0])
            zero = expires == "0" or re.search(r"expires=0\b", contacts[0])
            if zero:
                if bindings.get(aor) == uri:
                    del bindings[aor]
            else:
                bindings[aor] = uri  # replace, never add
        with open(log_file, "a", encoding="utf-8") as log:
            log.write(json.dumps({
                "call_id": headers["call-id"][0],
                "cseq": headers["cseq"][0],
                "contact": contacts[0] if contacts else None,
                "expires": expires or None,
                "binding_after": bindings.get(aor),
            }) + "\n")
        extra = []
        if aor in bindings:
            extra.append(f"Contact: <{bindings[aor]}>;expires=600")
        sock.sendto(response("200 OK", headers, extra), peer)


def register(port: int, aor: str, contact: str, username: str, password: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.bind(("127.0.0.1", 0))
    local = sock.getsockname()[1]
    call_id = uuid.uuid4().hex
    authorization = None
    for cseq in (1, 2):
        lines = [
            f"REGISTER sip:{REALM} SIP/2.0",
            f"Via: SIP/2.0/UDP 127.0.0.1:{local};branch=z9hG4bK{uuid.uuid4().hex[:12]}",
            f"From: <{aor}>;tag=other-node",
            f"To: <{aor}>",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq} REGISTER",
            f"Contact: <{contact}>",
            "Expires: 600",
            "Max-Forwards: 70",
        ]
        if authorization:
            lines.append(authorization)
        lines.append("Content-Length: 0")
        sock.sendto(("\r\n".join(lines) + "\r\n\r\n").encode(), ("127.0.0.1", port))
        data, _ = sock.recvfrom(65535)
        start, headers = parse(data)
        if " 200 " in start:
            return
        if " 401 " not in start:
            sys.exit(f"unexpected answer: {start}")
        challenge = headers["www-authenticate"][0]
        nonce = re.search(r'nonce="([^"]*)"', challenge).group(1)
        uri = f"sip:{REALM}"
        cnonce = uuid.uuid4().hex[:8]
        ha1 = md5(f"{username}:{REALM}:{password}")
        ha2 = md5(f"REGISTER:{uri}")
        answer = md5(f"{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}")
        authorization = (
            f'Authorization: Digest username="{username}", realm="{REALM}", nonce="{nonce}", '
            f'uri="{uri}", response="{answer}", algorithm=MD5, qop=auth, nc=00000001, cnonce="{cnonce}"'
        )
    sys.exit("the registrar did not accept the REGISTER")


def main() -> None:
    mode = sys.argv[1]
    if mode == "serve":
        serve(int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5])
    elif mode == "register":
        register(int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
