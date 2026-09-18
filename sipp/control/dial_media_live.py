#!/usr/bin/env python3
"""Real SIPp + siphon-rtp proof of profiled dial and voicemail fallback.

Run with --siphon pointing to the locally built binary. Requires Docker, SIPp,
websockets and cryptography (test tools only). Uses loopback and isolated ports;
never connects to an existing deployment. Artifacts remain in a temporary dir.
The SRTP peer uses OpenSSL through cryptography, independent of the Rust engine;
its KDF is checked against the published RFC 3711 vectors before any call.
"""

import argparse
import asyncio
import base64
import hashlib
import hmac
import pathlib
import re
import socket
import struct
import subprocess
import tempfile
import time
import wave

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from websockets.asyncio.server import serve

from control_app import Session

MASTER = bytes.fromhex("E1F97A0D3E018BE0D64FA32C06DE41390EC675AD498AFEEBB6960B3AABE6")
PAYLOAD = bytes([0x80] * 8 + [0x00] * 8) * 10


class Srtp:
    def __init__(self, master):
        def derive(label, length):
            counter = bytearray(master[16:] + b"\0\0")
            counter[7] ^= label
            return Cipher(algorithms.AES(master[:16]), modes.CTR(bytes(counter))).encryptor().update(bytes(length))
        self.key, self.auth, self.salt = derive(0, 16), derive(1, 20), derive(2, 14)

    def transform(self, packet):
        sequence = struct.unpack("!H", packet[2:4])[0]
        counter = int.from_bytes(self.salt + b"\0\0", "big")
        counter ^= int.from_bytes(packet[8:12], "big") << 64
        counter ^= sequence << 16
        stream = Cipher(algorithms.AES(self.key), modes.CTR(counter.to_bytes(16, "big"))).encryptor()
        return packet[:12] + stream.update(packet[12:])

    def protect(self, packet):
        encrypted = self.transform(packet)
        return encrypted + hmac.digest(self.auth, encrypted + bytes(4), hashlib.sha1)[:10]

    def unprotect(self, packet):
        expected = hmac.digest(self.auth, packet[:-10] + bytes(4), hashlib.sha1)[:10]
        assert hmac.compare_digest(expected, packet[-10:]), "engine emitted invalid SRTP authentication"
        return self.transform(packet[:-10])


def caller_xml(case):
    return f'''<?xml version="1.0"?><scenario name="profiled dial {case}">
<send retrans="500"><![CDATA[
INVITE sip:{case}@[remote_ip]:[remote_port] SIP/2.0
Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
From: <sip:caller@example.com>;tag=[pid]-[call_number]
To: <sip:{case}@example.com>
Call-ID: [call_id]
CSeq: 1 INVITE
Contact: <sip:caller@[local_ip]:[local_port]>
Max-Forwards: 70
Content-Type: application/sdp
Content-Length: [len]

v=0
o=- 1 1 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
m=audio 36108 RTP/AVP 0
a=rtpmap:0 PCMU/8000
]]></send>
<recv response="100" optional="true"/>
<recv response="180" optional="true"/>
<recv response="200" rrs="true" timeout="15000"/>
<send><![CDATA[
ACK [next_url] SIP/2.0
Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
From: <sip:caller@example.com>;tag=[pid]-[call_number]
To: <sip:{case}@example.com>[peer_tag_param]
Call-ID: [call_id]
CSeq: 1 ACK
Content-Length: 0

]]></send>
<pause milliseconds="4500"/>
<send retrans="500"><![CDATA[
BYE [next_url] SIP/2.0
Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
From: <sip:caller@example.com>;tag=[pid]-[call_number]
To: <sip:{case}@example.com>[peer_tag_param]
Call-ID: [call_id]
CSeq: 2 BYE
Content-Length: 0

]]></send>
<recv response="200" timeout="5000"/>
</scenario>'''


def phone_xml(reject):
    code = "488 Not Acceptable Here" if reject else "200 OK"
    body = "" if reject else f'''v=0
o=- 2 2 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
m=audio 36208 RTP/SAVP 0
a=rtpmap:0 PCMU/8000
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{base64.b64encode(MASTER).decode()}
'''
    bye = "" if reject else '''<recv request="BYE" timeout="15000"/><send><![CDATA[
SIP/2.0 200 OK
[last_Via:]
[last_From:]
[last_To:]
[last_Call-ID:]
[last_CSeq:]
Content-Length: 0

]]></send>'''
    return f'''<?xml version="1.0"?><scenario name="SRTP-only phone">
<recv request="INVITE" timeout="15000"><action>
<ereg regexp="RTP/SAVP" search_in="msg" check_it="true" assign_to="1"/>
<ereg regexp="a=crypto:" search_in="msg" check_it="true" assign_to="2"/>
</action></recv>
<send><![CDATA[
SIP/2.0 {code}
[last_Via:]
[last_From:]
[last_To:];tag=phone
[last_Call-ID:]
[last_CSeq:]
Contact: <sip:phone@127.0.0.1:35088>
Content-Type: application/sdp
Content-Length: [len]

{body}]]></send>
<recv request="ACK" timeout="15000"/>
{bye}
<Reference variables="1,2"/>
</scenario>'''


async def media(directory, case):
    traces = [directory / f"{case}-caller.messages", directory / f"{case}-phone.messages"]
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        caller = traces[0].read_text(errors="replace") if traces[0].exists() else ""
        phone = traces[1].read_text(errors="replace") if traces[1].exists() else ""
        answer = caller.split("SIP/2.0 200 OK", 1)[-1] if "SIP/2.0 200 OK" in caller else ""
        if "m=audio" in answer and "a=crypto:" in phone:
            break
        await asyncio.sleep(0.03)
    else:
        raise AssertionError("no completed SDP exchange")
    caller_port = int(re.search(r"m=audio (\d+)", answer)[1])
    phone_port = int(re.search(r"m=audio (\d+)", phone)[1])
    assert "RTP/AVP" in answer and "a=crypto:" not in answer, "caller must receive plain RTP"
    master = base64.b64decode(re.search(r"a=crypto:\d+ AES_CM_128_HMAC_SHA1_80 inline:([^\s|]+)", phone)[1])
    decrypt = Srtp(master)
    encrypt = Srtp(MASTER)
    near, far = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    near.bind(("127.0.0.1", 36108))
    far.bind(("127.0.0.1", 36208))
    near.setblocking(False)
    far.setblocking(False)
    counts = [0, 0]
    try:
        for sequence in range(1, 151):
            packet = struct.pack("!BBHII", 0x80, 0, sequence, sequence * 160, 0x11223344) + PAYLOAD
            near.sendto(packet, ("127.0.0.1", caller_port))
            if case == "secure":
                far.sendto(encrypt.protect(packet), ("127.0.0.1", phone_port))
            await asyncio.sleep(0.02)
            for index, endpoint in enumerate((near, far)):
                while True:
                    try:
                        received = endpoint.recv(2048)
                    except BlockingIOError:
                        break
                    if case == "fallback":
                        continue
                    if index:
                        received = decrypt.unprotect(received)
                    assert received[12:] == PAYLOAD, "bridged audio differs from sent tone"
                    counts[index] += 1
        if case == "secure":
            assert min(counts) >= 100, f"two-way decrypted audio missing: {counts}"
        print(f"MEDIA {case}: received {counts}", flush=True)
    finally:
        near.close()
        far.close()


async def main(binary):
    reference = Srtp(MASTER)
    assert reference.key.hex() == "c61e7a93744f39ee10734afe3ff7a087"
    assert reference.auth.hex() == "cebe321f6ff7716b6fd4ab49af256a156d38baa4"
    assert reference.salt.hex() == "30cbbc08863d8c85d49db34a9ae1"
    directory = pathlib.Path(tempfile.mkdtemp(prefix="control-dial-media-"))
    print(f"Artifacts: {directory}", flush=True)
    container = directory.name
    processes = []
    completions = {}

    async def connected(websocket):
        session = Session(websocket, "media-proof")

        async def started(session, event):
            case = "fallback" if "fallback" in event["payload"]["invite"]["ruri"] else "secure"
            future = completions[case]
            target = {"channel": event["channel"]}
            try:
                reply = await session.command("dial", {"targets": ["sip:phone@127.0.0.1:35088"], "profile": "rtp_to_srtp", "timeout": 5}, target=target)
                assert reply["status"] == "ok", reply
                if case == "fallback":
                    failure = await session.wait_event(lambda item: item.get("event") == "DialFailed")
                    assert failure["payload"]["code"] == 488, failure
                    reply = await session.command("answer", {"profile": "rtp_passthrough"}, target=target)
                    assert reply["status"] == "ok", reply
                    reply = await session.command("record_start", {"path": "/recordings/fallback.wav", "direction": "ingress", "channels": "mono", "max_duration_ms": 3500}, target=target)
                    assert reply["status"] == "ok", reply
                await session.wait_event(lambda item: item.get("event") == "StasisEnd", timeout=15)
                future.set_result(True)
            except Exception as error:
                future.set_exception(error)

        await session.reader(started)

    (directory / "empty.py").write_text("# No INVITE routing script.\n")
    (directory / "siphon.yaml").write_text(f'''listen:
  udp: ["127.0.0.1:35068"]
advertised_address: "127.0.0.1"
domain:
  local: ["example.com", "127.0.0.1"]
script:
  path: "{directory}/empty.py"
control:
  apps:
    - name: media-proof
      token: test-token
      per_call_connect: true
      connect_url: ws://127.0.0.1:38090/siphon
  inbound:
    app: media-proof
    mode: deferred
media:
  backend: siphon-rtp
  siphon_rtp:
    address: "127.0.0.1:38080"
    timeout_ms: 2000
log:
  level: info
''')
    try:
        subprocess.run(["docker", "run", "--rm", "-d", "--name", container, "--network", "host", "-v", f"{directory}:/recordings", "ghcr.io/siphon-project/siphon-rtp:0.7.2", "--control", "127.0.0.1:38080", "--relay-bind-ip", "127.0.0.1", "--port-min", "37000", "--port-max", "37100", "--metrics-addr", "127.0.0.1:39091"], check=True)
        async with serve(connected, "127.0.0.1", 38090, subprotocols=["siphon-control.v1"]):
            log = (directory / "siphon.log").open("w")
            processes.append(await asyncio.create_subprocess_exec(binary, "--config", str(directory / "siphon.yaml"), stdout=log, stderr=log))
            await asyncio.sleep(2)
            for case in ("secure", "fallback"):
                completions[case] = asyncio.get_running_loop().create_future()
                running = []
                for peer, port, xml in [("phone", "35088", phone_xml(case == "fallback")), ("caller", "35078", caller_xml(case))]:
                    path = directory / f"{case}-{peer}.xml"
                    path.write_text(xml)
                    output = (directory / f"{case}-{peer}.log").open("w")
                    arguments = ["sipp", "-sf", str(path), "-i", "127.0.0.1", "-p", port, "-m", "1", "-timeout", "20", "-trace_err", "-trace_msg", "-message_file", str(directory / f"{case}-{peer}.messages"), "-nostdin"]
                    if peer == "caller":
                        arguments.append("127.0.0.1:35068")
                    process = await asyncio.create_subprocess_exec(*arguments, cwd=directory, stdout=output, stderr=output)
                    running.append(process)
                    processes.append(process)
                    await asyncio.sleep(0.1)
                await media(directory, case)
                for process in running:
                    assert await process.wait() == 0, f"SIPp failed; see {directory}"
                await asyncio.wait_for(completions[case], 5)
            with wave.open(str(directory / "fallback.wav")) as recording:
                frames = recording.readframes(recording.getnframes())
                assert recording.getnframes() >= recording.getframerate(), "less than one second recorded"
                assert recording.getsampwidth() == 2
                loud = sum(abs(sample[0]) > 20000 for sample in struct.iter_unpack("<h", frames))
                assert loud >= recording.getframerate(), "less than one second of non-silent voicemail audio"
            await asyncio.sleep(0.2)
            # Two dial offers; voicemail answer_local has its own counter.
            subprocess.run(["python3", str(pathlib.Path(__file__).parents[1] / "assert_media.py"), "metrics", "--url", "http://127.0.0.1:39091/metrics", "--min-offers", "2", "--max-offers", "2", "--min-deletes", "3", "--max-control-errors", "0"], check=True)
            print("PASS: RTP/SRTP two-way audio and failed-dial voicemail recording", flush=True)
    finally:
        for process in reversed(processes):
            if process.returncode is None:
                process.terminate()
                await process.wait()
        subprocess.run(["docker", "rm", "-f", container], check=False)


if __name__ == "__main__":
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--siphon", required=True)
    asyncio.run(main(arguments.parse_args().siphon))
