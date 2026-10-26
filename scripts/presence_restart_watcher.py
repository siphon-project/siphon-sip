#!/usr/bin/env python3
"""Reg-event watchers for scripts/presence_restart_test.sh.

Each watcher is a UE on its own UDP port: it registers, subscribes to its own
reg event, and answers every NOTIFY 200.

  subscribe <state.json>  register and subscribe every UE, take the initial
                          NOTIFY, and write each dialog to state.json
  deregister <state.json> after the notifier restarted: re-REGISTER every UE,
                          then de-REGISTER them, and check each watcher gets
                          its NOTIFY in the dialog it had, CSeq and reginfo
                          version one above what it last saw

Standard library only, so the harness needs nothing but python3.
"""
import json
import os
import re
import selectors
import socket
import sys
import time
import uuid

NOTIFIER = ("127.0.0.1", 0)  # set from argv
DOMAIN = "example.test"
BASE_PORT = 0


def header(message, name):
    match = re.search(rf"^{name}:\s*(.*?)\r$", message, re.MULTILINE | re.IGNORECASE)
    return match.group(1) if match else None


def tag(value):
    match = re.search(r";tag=([^;>\s]+)", value or "")
    return match.group(1) if match else None


class Ue:
    def __init__(self, index):
        self.index = index
        self.aor = f"sip:ue{index}@{DOMAIN}"
        self.port = BASE_PORT + index
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", self.port))
        self.socket.setblocking(False)
        self.register_cseq = 0
        self.register_call_id = f"reg-{index}-{uuid.uuid4().hex[:8]}"
        self.subscribe_call_id = f"sub-{index}-{uuid.uuid4().hex[:8]}"
        self.from_tag = f"w{index}"
        self.notifies = []

    def contact(self):
        return f"<sip:ue{self.index}@127.0.0.1:{self.port}>"

    def send(self, text):
        self.socket.sendto(text.encode(), NOTIFIER)

    def register(self, expires):
        self.register_cseq += 1
        self.send(
            f"REGISTER sip:{DOMAIN} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP 127.0.0.1:{self.port};branch=z9hG4bK{uuid.uuid4().hex}\r\n"
            "Max-Forwards: 70\r\n"
            f"From: <{self.aor}>;tag=r{self.index}\r\n"
            f"To: <{self.aor}>\r\n"
            f"Call-ID: {self.register_call_id}\r\n"
            f"CSeq: {self.register_cseq} REGISTER\r\n"
            f"Contact: {self.contact()}\r\n"
            f"Expires: {expires}\r\n"
            "Content-Length: 0\r\n\r\n"
        )

    def subscribe(self):
        self.send(
            f"SUBSCRIBE {self.aor} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP 127.0.0.1:{self.port};branch=z9hG4bK{uuid.uuid4().hex}\r\n"
            "Max-Forwards: 70\r\n"
            f"From: <{self.aor}>;tag={self.from_tag}\r\n"
            f"To: <{self.aor}>\r\n"
            f"Call-ID: {self.subscribe_call_id}\r\n"
            "CSeq: 1 SUBSCRIBE\r\n"
            f"Contact: {self.contact()}\r\n"
            "Event: reg\r\n"
            "Accept: application/reginfo+xml\r\n"
            "Expires: 600\r\n"
            "Content-Length: 0\r\n\r\n"
        )

    def answer(self, request):
        lines = []
        for name in ("Via", "From", "To", "Call-ID", "CSeq"):
            for value in re.findall(rf"^{name}:\s*(.*?)\r$", request, re.MULTILINE):
                lines.append(f"{name}: {value}\r\n")
        response = "SIP/2.0 200 OK\r\n" + "".join(lines) + "Content-Length: 0\r\n\r\n"
        self.socket.sendto(response.encode(), NOTIFIER)
        self.dump(request, response)

    def dump(self, request, response):
        """Keep UE 0's NOTIFYs and answers for a decoder, when asked to."""
        directory = os.environ.get("PRESENCE_WIRE_DIR")
        if not directory or self.index != 0:
            return
        stamp = time.time_ns()
        with open(os.path.join(directory, f"{stamp}-notify.sip"), "w") as handle:
            handle.write(request)
        with open(os.path.join(directory, f"{stamp}-response.sip"), "w") as handle:
            handle.write(response)

    def receive(self, responses):
        while True:
            try:
                data, _ = self.socket.recvfrom(65535)
            except BlockingIOError:
                return
            message = data.decode(errors="replace")
            if message.startswith("NOTIFY "):
                self.answer(message)
                cseq = int(header(message, "CSeq").split()[0])
                version = re.search(r'<reginfo[^>]*\sversion="(\d+)"', message)
                self.notifies.append({
                    "call_id": header(message, "Call-ID"),
                    "cseq": cseq,
                    "to_tag": tag(header(message, "To")),
                    "from_tag": tag(header(message, "From")),
                    "version": int(version.group(1)) if version else None,
                    "state": "terminated" if 'state="terminated"' in message else "active",
                })
            elif message.startswith("SIP/2.0 "):
                responses.append((self.index, int(message.split()[1]), header(message, "CSeq")))


def pump(ues, until, timeout):
    selector = selectors.DefaultSelector()
    for ue in ues:
        selector.register(ue.socket, selectors.EVENT_READ, ue)
    responses = []
    deadline = time.time() + timeout
    while time.time() < deadline and not until(responses):
        for key, _ in selector.select(timeout=0.2):
            key.data.receive(responses)
    selector.close()
    return responses


def final(responses, method):
    return [r for r in responses if r[2] and r[2].endswith(method) and r[1] >= 200]


def registered_all(ues, expires, timeout=30):
    """REGISTER every UE until each is answered 200."""
    pending = {ue.index for ue in ues}
    for _ in range(int(timeout / 2)):
        for ue in ues:
            if ue.index in pending:
                ue.register(expires)
        answered = pump(ues, lambda r: len(final(r, "REGISTER")) >= len(pending), 2)
        for index, status, _ in final(answered, "REGISTER"):
            if status == 200:
                pending.discard(index)
        if not pending:
            return
    sys.exit(f"FAIL: {len(pending)} UEs never got a 200 to REGISTER")


def settle(ues, quiet=1.0):
    """Answer NOTIFYs until none has arrived for `quiet` seconds."""
    while True:
        seen = sum(len(ue.notifies) for ue in ues)
        pump(ues, lambda r: False, quiet)
        if sum(len(ue.notifies) for ue in ues) == seen:
            return


def subscribe(count, state_path):
    ues = [Ue(index) for index in range(count)]
    registered_all(ues, 600)
    # The registration's own change event runs after the 200; let it pass
    # before subscribing, so the dialog starts from its initial NOTIFY.
    settle(ues)
    for ue in ues:
        ue.subscribe()
    responses = pump(ues, lambda r: all(ue.notifies for ue in ues), 30)
    settle(ues)
    accepted = [r for r in final(responses, "SUBSCRIBE") if r[1] == 200]
    if len(accepted) != count or not all(ue.notifies for ue in ues):
        sys.exit(f"FAIL: {len(accepted)}/{count} SUBSCRIBEs accepted, "
                 f"{sum(1 for ue in ues if ue.notifies)}/{count} initial NOTIFYs")
    state = [{
        "index": ue.index,
        "register_call_id": ue.register_call_id,
        "register_cseq": ue.register_cseq,
        "subscribe_call_id": ue.subscribe_call_id,
        "last": ue.notifies[-1],
    } for ue in ues]
    with open(state_path, "w") as handle:
        json.dump(state, handle)
    print(f"subscribed {count}/{count}: initial NOTIFY CSeq "
          f"{ues[0].notifies[-1]['cseq']} version {ues[0].notifies[-1]['version']}")


def deregister(count, state_path):
    with open(state_path) as handle:
        state = {entry["index"]: entry for entry in json.load(handle)}
    ues = [Ue(index) for index in range(count)]
    for ue in ues:
        ue.register_call_id = state[ue.index]["register_call_id"]
        ue.register_cseq = state[ue.index]["register_cseq"]
    # The bench's order: wait for the re-registrations, then de-register.
    registered_all(ues, 600)
    print(f"re-registered {count}/{count} after the restart")
    before = {ue.index: len(ue.notifies) for ue in ues}
    for ue in ues:
        ue.register(0)
    pump(ues, lambda r: all(len(ue.notifies) > before[ue.index] for ue in ues), 30)

    good = 0
    failures = []
    for ue in ues:
        last = state[ue.index]["last"]
        # Everything since the restart, the re-registration's included.
        fresh = ue.notifies
        notify = next((n for n in fresh if n["state"] == "terminated"), None)
        if notify is None:
            failures.append(f"ue{ue.index}: no NOTIFY after the de-REGISTER")
            continue
        problems = []
        if notify["call_id"] != state[ue.index]["subscribe_call_id"]:
            problems.append(f"Call-ID {notify['call_id']}")
        if notify["to_tag"] != f"w{ue.index}" or notify["from_tag"] != last["from_tag"]:
            problems.append(f"tags {notify['from_tag']}/{notify['to_tag']}")
        # Every NOTIFY since the restart continues the dialog: CSeq above the
        # last one seen, versions consecutive from the last one seen.
        cseqs = [last["cseq"]] + [n["cseq"] for n in fresh]
        if any(later <= earlier for earlier, later in zip(cseqs, cseqs[1:])):
            problems.append(f"CSeq {cseqs} not increasing")
        versions = [n["version"] for n in fresh]
        if versions != list(range(last["version"] + 1, last["version"] + 1 + len(fresh))):
            problems.append(f"versions {versions} after {last['version']}")
        if problems:
            failures.append(f"ue{ue.index}: " + ", ".join(problems))
        else:
            good += 1
    print(f"in-dialog NOTIFY after the restart: {good}/{count}")
    if good:
        sample = next(n for n in ues[0].notifies if n["state"] == "terminated")
        print(f"ue0: CSeq {state[0]['last']['cseq']} -> {sample['cseq']}, "
              f"version {state[0]['last']['version']} -> {sample['version']}")
    for failure in failures[:10]:
        print("  " + failure)
    sys.exit(0 if good == count else 1)


if __name__ == "__main__":
    command, count, state_path, notifier_port, base_port = sys.argv[1:6]
    NOTIFIER = ("127.0.0.1", int(notifier_port))
    BASE_PORT = int(base_port)
    {"subscribe": subscribe, "deregister": deregister}[command](int(count), state_path)
