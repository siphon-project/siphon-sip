"""Mock control-plane application for the functional test stack.

The out-of-process half of siphon's application rail. It stands in for a real
controller: it speaks `siphon-control.v1` over a WebSocket, drives a scripted
sequence of verbs against whatever call is handed to it, and **records every
frame it sent and received** as one JSON line on stdout.

That recording is the point. Most of what this rail does is invisible to SIPp:
a call answered by the controller and a call answered by an in-process script
look identical on the wire, and a media verb that was *accepted* looks identical
to one that was *performed*. So the SIPp scenarios assert the SIP side, this app
asserts the rail side, and the two together are the acceptance criteria. It is
the control-plane analogue of sipp/siphon-rtp/mock_siphon_rtp.py, which does the
same job for the media rail.

Both connection modes are supported, because they are genuinely different code
paths in siphon and a given app can only reach one of them:

  * ``CONTROL_MODE=outbound`` — per-call-connect, the multi-pod default. This
    app runs the WebSocket **server** and siphon dials it once per handed-over
    call. There is no ``hello``; the first frame on a fresh socket is
    ``StasisStart`` and that socket owns exactly that one call.
  * ``CONTROL_MODE=inbound`` — persistent. This app dials siphon's
    ``control.listen`` with ``CONTROL_CONNECTIONS`` sockets, each saying
    ``hello``, and siphon round-robins handed-over calls across them. Only this
    mode has the concepts the exactly-one-owner and ``resync`` cases test.

Which behaviour to run for a call is read off the ``vars.case`` seeded by
``call.handover(vars=…)`` in the routing script, so the compose profile drives
every case through one long-running app rather than one container per case.

Output contract (both greppable, both with `json.dumps`'s ``"key": "value"``
spacing — a pattern written without the space matches nothing and passes
vacuously):

  CONTROL-FRAME   {"dir": "recv"|"send", "conn": "<label>", "frame": {…}}
  CONTROL-VERDICT {"case": "<case>", "pass": true|false, "checks": […]}

A case that never runs prints no verdict at all, which the runner treats as a
failure — that is what catches the app never being reached.

There is deliberately no reconnect loop: a real controller has one, but here a
socket that goes away is either the `resync` case dropping it on purpose or
siphon having restarted, and both should be visible rather than papered over.
Instead the ready file is a heartbeat that stops while the app cannot take a
call, so the container reports unhealthy.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import sys
import time

import websockets

try:  # websockets >= 13
    from websockets.asyncio.server import serve as ws_serve
except ImportError:  # pragma: no cover — legacy fallback
    from websockets.server import serve as ws_serve  # type: ignore[no-redef]

SUBPROTOCOL = "siphon-control.v1"

MODE = os.environ.get("CONTROL_MODE", "inbound")
APP_NAME = os.environ.get("CONTROL_APP", "ivr-app")
TOKEN = os.environ.get("CONTROL_TOKEN", "")
CONTROL_URL = os.environ.get("CONTROL_URL", "ws://172.20.0.160:9092/control/ws")
CONNECTIONS = int(os.environ.get("CONTROL_CONNECTIONS", "2"))
LISTEN_HOST = os.environ.get("CONTROL_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("CONTROL_LISTEN_PORT", "8090"))
READY_FILE = os.environ.get("CONTROL_READY_FILE", "/tmp/control-app-ready")

# RFC 5737 TEST-NET-2 — the answer this app hands siphon for a parked call. The
# SIPp scenarios assert this exact address in the 200 OK body, which is what
# proves the controller's SDP reached the wire rather than something siphon
# synthesised.
ANSWER_MEDIA_IP = os.environ.get("CONTROL_ANSWER_IP", "198.51.100.20")
ANSWER_SDP = (
    "v=0\r\n"
    f"o=- 20260101 20260101 IN IP4 {ANSWER_MEDIA_IP}\r\n"
    "s=control-app\r\n"
    f"c=IN IP4 {ANSWER_MEDIA_IP}\r\n"
    "t=0 0\r\n"
    "m=audio 41000 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=sendrecv\r\n"
)

PROMPT_FILE = os.environ.get("CONTROL_PROMPT", "/prompts/control-harness.wav")
# Carried on the BYE's RFC 3326 Reason header, so the resync SIPp scenario can
# tell the reattached controller's hangup apart from the on_lost teardown that
# would fire if the grace window had lapsed instead.
HANGUP_REASON = os.environ.get("CONTROL_HANGUP_REASON", "resync-hangup")

HEARTBEAT_SECS = float(os.environ.get("CONTROL_HEARTBEAT_SECS", "2"))
EVENT_TIMEOUT = float(os.environ.get("CONTROL_EVENT_TIMEOUT", "40"))
COMMAND_TIMEOUT = float(os.environ.get("CONTROL_COMMAND_TIMEOUT", "10"))


def record(direction: str, label: str, frame: dict) -> None:
    """One JSON line per frame, so a test can assert on the actual exchange."""
    print(
        "CONTROL-FRAME "
        + json.dumps({"dir": direction, "conn": label, "frame": frame}),
        flush=True,
    )


def note(message: str) -> None:
    print(f"control-app[{MODE}/{APP_NAME}]: {message}", flush=True)


class Verdict:
    """Accumulates one case's checks and prints the single greppable line."""

    def __init__(self, case: str) -> None:
        self.case = case
        self.checks: list[dict] = []

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.checks.append({"check": name, "pass": bool(passed), "detail": detail})
        return bool(passed)

    def emit(self) -> None:
        passed = bool(self.checks) and all(check["pass"] for check in self.checks)
        print(
            "CONTROL-VERDICT "
            + json.dumps({"case": self.case, "pass": passed, "checks": self.checks}),
            flush=True,
        )


class Session:
    """One control connection: request/reply correlation + an event backlog."""

    def __init__(self, socket, label: str) -> None:
        self.socket = socket
        self.label = label
        self.closed = False
        self.started_channels: set[str] = set()
        self.commanded_channels: set[str] = set()
        self._pending: dict[str, asyncio.Future] = {}
        self._events: list[dict] = []
        self._signal = asyncio.Event()
        self._next_id = 0

    async def send(self, frame: dict) -> None:
        record("send", self.label, frame)
        await self.socket.send(json.dumps(frame))

    async def command(
        self,
        verb: str,
        args: dict | None = None,
        module: str | None = "sip",
        target: dict | None = None,
        timeout: float = COMMAND_TIMEOUT,
    ) -> dict:
        self._next_id += 1
        request_id = f"{self.label}-{self._next_id}"
        frame: dict = {"id": request_id, "type": "command", "verb": verb}
        if module is not None:
            frame["module"] = module
        if target is not None:
            frame["target"] = target
            channel = target.get("channel")
            if channel:
                self.commanded_channels.add(channel)
        frame["args"] = args if args is not None else {}
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        await self.send(frame)
        return await asyncio.wait_for(future, timeout)

    async def wait_event(self, predicate, timeout: float = EVENT_TIMEOUT) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            # Clear BEFORE scanning: an event appended after the scan re-sets the
            # flag, so a wakeup can never be lost between the two.
            self._signal.clear()
            for index, event in enumerate(self._events):
                if predicate(event):
                    return self._events.pop(index)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"{self.label}: no matching event in {timeout}s")
            try:
                await asyncio.wait_for(self._signal.wait(), remaining)
            except asyncio.TimeoutError:
                pass

    async def reader(self, on_start) -> None:
        try:
            async for raw in self.socket:
                try:
                    frame = json.loads(raw)
                except ValueError:
                    note(f"{self.label}: unparseable frame {raw!r}")
                    continue
                record("recv", self.label, frame)
                kind = frame.get("type")
                if kind == "reply":
                    future = self._pending.pop(frame.get("id"), None)
                    if future is not None and not future.done():
                        future.set_result(frame)
                elif kind == "event":
                    if frame.get("event") == "StasisStart":
                        channel = frame.get("channel")
                        if channel:
                            self.started_channels.add(channel)
                        asyncio.create_task(on_start(self, frame))
                    self._events.append(frame)
                    self._signal.set()
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as error:  # noqa: BLE001 — a reader crash must be visible
            note(f"{self.label}: reader stopped: {error!r}")
        finally:
            self.closed = True
            self._signal.set()
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(ConnectionError(f"{self.label} closed"))

    def take_events(self, predicate) -> list[dict]:
        """Remove and return the backlogged events matching `predicate`.

        For a check that asserts an event was *not* delivered: `wait_event`
        cannot express "and nothing else matched", so the case takes what is
        left over and inspects it. Only matching events are removed — draining
        the whole backlog would swallow the `StasisEnd` a later check waits for.
        """
        taken = [event for event in self._events if predicate(event)]
        self._events = [event for event in self._events if not predicate(event)]
        return taken

    async def close(self) -> None:
        self.closed = True
        await self.socket.close()


class App:
    """Everything the cases need: the live sessions, and how to make another."""

    def __init__(self) -> None:
        self.sessions: list[Session] = []

    async def connect_inbound(self, label: str) -> Session:
        headers = {"Authorization": f"Bearer {TOKEN}"}
        try:
            connector = websockets.connect(
                CONTROL_URL, subprotocols=[SUBPROTOCOL], additional_headers=headers
            )
        except TypeError:  # websockets < 14
            connector = websockets.connect(
                CONTROL_URL, subprotocols=[SUBPROTOCOL], extra_headers=headers
            )
        socket = await connector
        session = Session(socket, label)
        self.sessions.append(session)
        asyncio.create_task(session.reader(self.on_stasis_start))
        hello = await session.command(
            "hello", {"app": APP_NAME, "protocol": 1}, module=None
        )
        if hello.get("status") != "ok":
            raise RuntimeError(f"{label}: hello rejected: {json.dumps(hello)}")
        note(f"{label}: connected + hello ok")
        return session

    async def on_stasis_start(self, session: Session, event: dict) -> None:
        payload = event.get("payload") or {}
        case = (payload.get("vars") or {}).get("case", "unknown")
        handler = CASES.get(case)
        channel = event.get("channel")
        if handler is None:
            note(f"{session.label}: no handler for case {case!r} — hanging up")
            if channel:
                await session.command(
                    "hangup", {"reason": "unhandled case"}, target={"channel": channel}
                )
            return
        note(f"{session.label}: StasisStart case={case} channel={channel}")
        # The verdict is owned here, not by the case, so a case that raises
        # part-way still reports the checks it had already made — otherwise the
        # only thing left is "it threw", which does not say what broke.
        verdict = Verdict(case)
        try:
            await handler(self, session, event, verdict)
        except Exception as error:  # noqa: BLE001 — the verdict is the report
            verdict.check("case_ran_to_completion", False, repr(error))
        finally:
            verdict.emit()


# ── helpers shared by the cases ────────────────────────────────────────────


def invite_headers(event: dict) -> dict:
    """The StasisStart's INVITE headers as a lowercased name → value map."""
    invite = (event.get("payload") or {}).get("invite") or {}
    return {
        str(name).lower(): str(value)
        for name, value in (invite.get("headers") or [])
    }


def assert_sip_context(verdict: Verdict, event: dict, expected_user: str) -> None:
    """The contract of the start event: the app gets the full SIP context and
    the stable id triple, so it needs no mapping table to join CDR / HEP."""
    payload = event.get("payload") or {}
    invite = payload.get("invite") or {}
    headers = invite_headers(event)

    verdict.check(
        "start_event_carries_the_ruri",
        f"{expected_user}@" in str(invite.get("ruri") or ""),
        str(invite.get("ruri")),
    )
    verdict.check(
        "start_event_carries_the_invite_headers",
        bool(headers.get("from")) and bool(headers.get("to")) and bool(headers.get("call-id")),
        json.dumps(sorted(headers)),
    )
    verdict.check(
        "sip_call_id_matches_the_invite",
        headers.get("call-id") == event.get("sip_call_id"),
        f"{headers.get('call-id')!r} vs {event.get('sip_call_id')!r}",
    )
    verdict.check(
        "id_triple_is_complete",
        bool(event.get("channel")) and bool(event.get("call_id")) and bool(event.get("sip_call_id")),
        json.dumps({key: event.get(key) for key in ("channel", "call_id", "sip_call_id")}),
    )
    body = invite.get("body") or {}
    verdict.check(
        "start_event_carries_the_offer",
        "m=audio" in str(body.get("text") or ""),
        str(body.get("content_type")),
    )
    verdict.check(
        "start_event_carries_the_source",
        bool(payload.get("source_ip")) and payload.get("transport") == "udp",
        json.dumps({"source_ip": payload.get("source_ip"), "transport": payload.get("transport")}),
    )


async def answer_with_our_sdp(session: Session, channel: str) -> dict:
    return await session.command(
        "answer",
        {
            "code": 200,
            "reason": "OK",
            "body": ANSWER_SDP,
            "content_type": "application/sdp",
        },
        target={"channel": channel},
    )


def is_end(channel: str):
    return lambda event: event.get("event") == "StasisEnd" and event.get("channel") == channel


# ── the cases ──────────────────────────────────────────────────────────────


async def case_handover(app: App, session: Session, event: dict, verdict: Verdict) -> None:
    """Deferred handover: siphon holds the INVITE un-dialed, the app gets the
    SIP context, answers, and the call completes."""
    channel = event.get("channel") or ""
    assert_sip_context(verdict, event, "handover")

    reply = await answer_with_our_sdp(session, channel)
    result = reply.get("result") or {}
    verdict.check(
        "answer_accepted",
        reply.get("status") == "ok" and result.get("state") == "answered",
        json.dumps(reply),
    )

    end = await session.wait_event(is_end(channel))
    verdict.check("stasis_end_delivered", True, json.dumps(end.get("payload")))


async def case_progress(app: App, session: Session, event: dict, verdict: Verdict) -> None:
    """Ringing and early media are two verbs, driven on the app's own clock.

    RFC 3261 §13.2.1 makes the 180 the "callee is being alerted" signal with no
    session semantics; RFC 3960 §3.1 puts early media on the response carrying
    the SDP. This case rings, holds the ring for an interval **it** chooses, then
    opens early media, then answers — and checks that each verb reported what it
    actually put on the wire. The SIPp scenario asserts the SIP side (a body-less
    180 then a 183 with this app's SDP); these checks assert the rail side.
    """
    channel = event.get("channel") or ""

    ring = await session.command("ring", {}, target={"channel": channel})
    result = ring.get("result") or {}
    verdict.check(
        "ring_sent_a_plain_180",
        ring.get("status") == "ok"
        and result.get("code") == 180
        and result.get("state") == "ringing"
        and result.get("early_media") is False,
        json.dumps(ring),
    )

    # The negative: `ring` promises alerting only, so a body has to be refused
    # rather than quietly put an early-media offer on the wire under that name.
    with_body = await session.command(
        "ring",
        {"body": ANSWER_SDP, "content_type": "application/sdp"},
        target={"channel": channel},
    )
    error = with_body.get("error") or {}
    verdict.check(
        "ring_with_a_body_is_refused",
        with_body.get("status") == "error"
        and error.get("code") == "bad_request"
        and "progress" in str(error.get("message") or ""),
        json.dumps(with_body),
    )

    # The application's own ring interval — the whole point of splitting the two.
    await asyncio.sleep(1.0)

    early = await session.command(
        "progress",
        {
            "code": 183,
            "reason": "Session Progress",
            "body": ANSWER_SDP,
            "content_type": "application/sdp",
        },
        target={"channel": channel},
    )
    result = early.get("result") or {}
    verdict.check(
        "progress_reports_early_media_not_ringing",
        early.get("status") == "ok"
        and result.get("code") == 183
        and result.get("state") == "progress"
        and result.get("early_media") is True,
        json.dumps(early),
    )

    reply = await answer_with_our_sdp(session, channel)
    verdict.check("answer_accepted", reply.get("status") == "ok", json.dumps(reply))

    end = await session.wait_event(is_end(channel))
    verdict.check("stasis_end_delivered", True, json.dumps(end.get("payload")))


async def case_deadline(app: App, session: Session, event: dict, verdict: Verdict) -> None:
    """The handoff deadline: the controller deliberately does nothing, and
    siphon must apply its safe default rather than hang the call."""
    channel = event.get("channel") or ""
    parked_at = time.monotonic()

    end = await session.wait_event(is_end(channel))
    elapsed = time.monotonic() - parked_at

    verdict.check(
        "controller_sent_no_command",
        channel not in session.commanded_channels,
        json.dumps(sorted(session.commanded_channels)),
    )
    payload = end.get("payload") or {}
    verdict.check(
        "stasis_end_names_the_deadline",
        payload.get("reason") == "No Controller Response",
        json.dumps(payload),
    )
    # The teardown's SIP status, not just its cause. An app branches on both, and
    # `reason` alone cannot say whether the caller got a 503 it may retry
    # elsewhere or a final refusal. RFC 3261 §8.1.3.4 leaves the meaning to the
    # code plus the reason phrase, so both must be on the frame.
    verdict.check(
        "stasis_end_carries_the_sip_response_code",
        payload.get("code") == 503 and bool(payload.get("response")),
        json.dumps(payload),
    )
    # The configured deadline is 2s. Anything past ~10s means some other timer
    # ended the call (the 408 answer timeout, a sweep), not the handoff deadline.
    verdict.check(
        "default_applied_within_the_deadline",
        elapsed < 10.0,
        f"{elapsed:.3f}s after StasisStart",
    )


async def case_media(app: App, session: Session, event: dict, verdict: Verdict) -> None:
    """A media verb round trip on an answer-first (already connected) channel.

    The replies here only prove the commands were *accepted*; that they were
    *performed* is asserted on the media engine's own recorded commands, which
    is the half SIPp cannot see.
    """
    channel = event.get("channel") or ""

    # The negative first, and before any real play, so a start event seen later
    # can only have come from the accepted one: a source the adapter refuses
    # never starts, so it must push no PlayStarted at all.
    refused = await session.command(
        "play", {"file": PROMPT_FILE, "db_id": 7}, target={"channel": channel}
    )
    verdict.check(
        "play_with_two_sources_is_refused",
        refused.get("status") == "error"
        and (refused.get("error") or {}).get("code") == "bad_request",
        json.dumps(refused),
    )

    play = await session.command("play", {"file": PROMPT_FILE}, target={"channel": channel})
    result = play.get("result") or {}
    verdict.check(
        "play_accepted",
        play.get("status") == "ok" and result.get("state") == "playing",
        json.dumps(play),
    )

    # The start event: an app that watchdogs a source which may never produce
    # audio, or ramps gain on a running prompt, drives that off the event stream
    # and has nothing to hang it on without this. It must correlate with the
    # accept, which is what `play_id` is for.
    started = await session.wait_event(
        lambda event: event.get("event") == "PlayStarted" and event.get("channel") == channel,
        timeout=10,
    )
    started_payload = started.get("payload") or {}
    verdict.check(
        "play_start_event_delivered",
        started_payload.get("source") == "file",
        json.dumps(started_payload),
    )
    verdict.check(
        "play_start_event_correlates_with_the_accept",
        started_payload.get("play_id") is not None
        and started_payload.get("play_id") == result.get("play_id"),
        json.dumps({"accept": result.get("play_id"), "event": started_payload.get("play_id")}),
    )

    # Exactly one — the refused play above must not have produced a second.
    extra_starts = session.take_events(
        lambda frame: frame.get("event") == "PlayStarted" and frame.get("channel") == channel
    )
    verdict.check(
        "a_refused_play_produced_no_start_event",
        not extra_starts,
        json.dumps(extra_starts),
    )

    await asyncio.sleep(0.2)

    stop = await session.command("stop", {}, target={"channel": channel})
    verdict.check(
        "stop_accepted",
        stop.get("status") == "ok" and (stop.get("result") or {}).get("state") == "stopped",
        json.dumps(stop),
    )

    end = await session.wait_event(is_end(channel))
    verdict.check("stasis_end_delivered", True, json.dumps(end.get("payload")))


async def case_owner(app: App, session: Session, event: dict, verdict: Verdict) -> None:
    """Exactly-one-owner dispatch: with several connections of the same app up,
    exactly one is given the call and the others cannot command it."""
    channel = event.get("channel") or ""

    others = [other for other in app.sessions if other is not session and not other.closed]
    verdict.check(
        "more_than_one_connection_was_up",
        len(others) >= 1,
        f"{len(others) + 1} live connections",
    )

    # Give any second delivery time to land before concluding there wasn't one.
    await asyncio.sleep(0.5)
    duplicates = [other.label for other in app.sessions
                  if other is not session and channel in other.started_channels]
    verdict.check(
        "exactly_one_connection_got_the_call",
        not duplicates,
        json.dumps({"owner": session.label, "also_started": duplicates}),
    )

    for other in others:
        reply = await other.command(
            "answer", {"code": 200}, target={"channel": channel}
        )
        code = (reply.get("error") or {}).get("code")
        verdict.check(
            f"non_owner_is_forbidden[{other.label}]",
            reply.get("status") == "error" and code == "forbidden",
            json.dumps(reply),
        )

    reply = await answer_with_our_sdp(session, channel)
    verdict.check(
        "owner_can_answer",
        reply.get("status") == "ok",
        json.dumps(reply),
    )

    end = await session.wait_event(is_end(channel))
    verdict.check("stasis_end_delivered", True, json.dumps(end.get("payload")))


async def case_resync(app: App, session: Session, event: dict, verdict: Verdict) -> None:
    """`resync` after the owning connection drops and the controller reconnects
    inside the grace window — and the reattached connection can really drive the
    call, not merely list it."""
    channel = event.get("channel") or ""
    sip_call_id = event.get("sip_call_id")

    reply = await answer_with_our_sdp(session, channel)
    verdict.check("answer_accepted", reply.get("status") == "ok", json.dumps(reply))

    await asyncio.sleep(0.3)
    note(f"{session.label}: dropping the owning socket mid-call")
    await session.close()

    # Well inside control.limits.reattach_grace_secs, so on_lost must not have
    # fired and the call must still be there to re-claim.
    await asyncio.sleep(1.5)

    resumed = await app.connect_inbound("in-resync")
    result = await resumed.command("resync", {}, module=None)
    channels = ((result.get("result") or {}).get("channels")) or []
    match = next((entry for entry in channels if entry.get("channel") == channel), None)
    verdict.check(
        "resync_returned_the_orphaned_call",
        match is not None,
        json.dumps(channels),
    )
    verdict.check(
        "resync_reports_the_live_state",
        bool(match) and match.get("state") == "answered",
        json.dumps(match),
    )
    verdict.check(
        "resync_keeps_the_id_triple",
        bool(match) and match.get("sip_call_id") == sip_call_id,
        json.dumps({"resync": (match or {}).get("sip_call_id"), "start": sip_call_id}),
    )

    # The real test of a reattach: the new connection can command the call.
    hangup = await resumed.command(
        "hangup", {"reason": HANGUP_REASON}, target={"channel": channel}
    )
    verdict.check(
        "reattached_connection_can_command_the_call",
        hangup.get("status") == "ok",
        json.dumps(hangup),
    )

    end = await resumed.wait_event(is_end(channel))
    verdict.check("stasis_end_delivered", True, json.dumps(end.get("payload")))


CASES = {
    "handover": case_handover,
    "progress": case_progress,
    "deadline": case_deadline,
    "media": case_media,
    "owner": case_owner,
    "resync": case_resync,
}


# ── connection modes ───────────────────────────────────────────────────────


async def heartbeat(is_serviceable) -> None:
    """Refresh the ready file only while the app can actually take a call.

    A one-shot ready file cannot tell a live application from one whose sockets
    died when siphon restarted underneath it — and a controller with no live
    connection is handed nothing, so every case would fail in a way that reads
    like siphon's fault. The healthcheck keys on this file's mtime, so a stale
    app goes unhealthy instead of quietly passing for the wrong reason.
    """
    path = pathlib.Path(READY_FILE)
    announced = False
    while True:
        if is_serviceable():
            path.write_text("ready\n", encoding="utf-8")
            if not announced:
                note(f"ready ({READY_FILE})")
                announced = True
        else:
            path.unlink(missing_ok=True)
            if announced:
                note("no longer serviceable — ready file withdrawn")
                announced = False
        await asyncio.sleep(HEARTBEAT_SECS)


async def run_inbound() -> None:
    """Persistent mode: dial siphon and hold `CONTROL_CONNECTIONS` sockets."""
    app = App()
    for index in range(1, CONNECTIONS + 1):
        await app.connect_inbound(f"in-{index}")

    def serviceable() -> bool:
        return sum(1 for session in app.sessions if not session.closed) >= CONNECTIONS

    await heartbeat(serviceable)


async def run_outbound() -> None:
    """Per-call-connect mode: be the server siphon dials, once per call."""
    app = App()

    async def handler(socket) -> None:
        label = f"out-{id(socket) & 0xffff:04x}"
        headers = getattr(getattr(socket, "request", None), "headers", None)
        if headers is None:  # pragma: no cover — legacy websockets
            headers = getattr(socket, "request_headers", {})
        presented = headers.get("Authorization") if headers is not None else None
        if presented != f"Bearer {TOKEN}":
            # A mock that accepts anything would hide a real auth regression.
            note(f"{label}: rejecting dial with bad Authorization {presented!r}")
            await socket.close(code=1008, reason="unauthorized")
            return
        note(f"{label}: siphon dialled in (per-call connect)")
        session = Session(socket, label)
        app.sessions.append(session)
        # No `hello` in this direction — the first frame is StasisStart.
        await session.reader(app.on_stasis_start)
        if session in app.sessions:
            app.sessions.remove(session)

    async with ws_serve(handler, LISTEN_HOST, LISTEN_PORT, subprotocols=[SUBPROTOCOL]):
        note(f"listening for per-call dials on {LISTEN_HOST}:{LISTEN_PORT}")
        # Sockets here are per call, so "serviceable" is just "still accepting".
        await heartbeat(lambda: True)


async def main() -> int:
    if MODE == "outbound":
        await run_outbound()
    elif MODE == "inbound":
        await run_inbound()
    else:
        note(f"unknown CONTROL_MODE {MODE!r} (expected 'inbound' or 'outbound')")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
