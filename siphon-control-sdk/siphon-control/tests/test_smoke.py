"""Smoke tests for the ``siphon_control`` PyO3 bindings.

Drives the real extension module against an in-process ``websockets`` stub that
speaks the ``siphon-control.v1`` handshake, echoes correlated replies, and can
push events. Covers BOTH connection modes:

* **Inbound-persistent** (``ControlClient``) — the app dials the stub: build a
  client, connect + hello, a command round-trip, a typed ``ControlError`` on an
  error reply, and the ``@client.on_call`` async dispatch.
* **Per-call-connect** (``ControlServer``) — the stub (playing siphon) dials the
  app: the app listens, siphon connects and pushes ``StasisStart``, the
  ``@server.on_call`` handler fires and a ``Call`` verb round-trips.

Run: ``python -m pytest tests/`` (needs ``websockets`` installed).
"""

import asyncio
import contextlib
import json
import time

import pytest
import websockets

from siphon_control import (
    Call,
    ControlClient,
    ControlError,
    ControlServer,
    is_transfer_final,
    transfer_outcome,
)

APP = "ivr-app"
TOKEN = "s3cr3t"
SUBPROTOCOL = "siphon-control.v1"


async def _reply_ok(websocket, frame_id, result):
    await websocket.send(
        json.dumps({"id": frame_id, "type": "reply", "status": "ok", "result": result})
    )


async def _reply_error(websocket, frame_id, code, message):
    await websocket.send(
        json.dumps(
            {
                "id": frame_id,
                "type": "reply",
                "status": "error",
                "error": {"code": code, "message": message},
            }
        )
    )


async def _stub_handler(websocket):
    """A minimal stand-in for siphon's control listener."""
    auth = websocket.request.headers.get("Authorization", "")
    if auth != f"Bearer {TOKEN}":
        await websocket.close(code=1008, reason="unauthorized")
        return

    said_hello = False
    async for message in websocket:
        frame = json.loads(message)
        frame_id = frame.get("id")
        verb = frame.get("verb")

        if not said_hello:
            assert verb == "hello", "first frame must be hello"
            await _reply_ok(
                websocket,
                frame_id,
                {"app": APP, "protocol": 1, "subprotocol": SUBPROTOCOL},
            )
            said_hello = True
            continue

        if verb == "describe":
            await _reply_ok(
                websocket,
                frame_id,
                {"adapters": [{"module": "sip", "verbs": [], "events": []}]},
            )
        elif verb == "boom":
            await _reply_error(websocket, frame_id, "not_found", "no such channel")
        elif verb in ("stream_start", "stream_stop"):
            await _reply_error(
                websocket,
                frame_id,
                "unsupported_verb",
                "ws_tee is only supported by the siphon-rtp backend",
            )
        elif verb in ("get_header", "get_var"):
            await _reply_ok(websocket, frame_id, {"value": "203.0.113.7"})
        elif verb == "test_push_stasis":
            await websocket.send(
                json.dumps(
                    {
                        "type": "event",
                        "event": "StasisStart",
                        "channel": "ch1",
                        "app": APP,
                        "call_id": "call-uuid",
                        "sip_call_id": "sipcid@host",
                        "payload": {"source_ip": "203.0.113.7"},
                    }
                )
            )
            await _reply_ok(websocket, frame_id, {})
        elif verb == "test_push_app_event":
            # Application-level: no channel, no call ids.
            await websocket.send(
                json.dumps(
                    {
                        "type": "event",
                        "event": "DialogStateChanged",
                        "app": APP,
                        "payload": {
                            "aor": "sip:201@example.com",
                            "state": "early",
                            "direction": "recipient",
                            "leg_id": "leg-1",
                            "call_id": "b1@host",
                            "local_tag": "phone-tag",
                            "remote_tag": "server-tag",
                            "remote_identity": {
                                "uri": "sip:15550100042@example.com",
                                "display_name": None,
                            },
                        },
                    }
                )
            )
            await _reply_ok(websocket, frame_id, {})
        else:
            await _reply_ok(websocket, frame_id, {"state": "answered"})


@contextlib.asynccontextmanager
async def _serve_stub():
    async with websockets.serve(
        _stub_handler, "127.0.0.1", 0, subprotocols=[SUBPROTOCOL]
    ) as server:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}/control/ws"


def test_module_surface():
    assert hasattr(ControlClient, "on_call")
    assert hasattr(ControlClient, "on_app_event")
    assert hasattr(ControlServer, "on_call")
    assert hasattr(ControlServer, "serve")
    assert hasattr(ControlServer, "run")
    assert hasattr(Call, "answer")
    assert hasattr(Call, "route")
    # The media / header / REFER verbs that shipped server-side.
    for verb in (
        "play",
        "stop",
        "dtmf",
        "hold",
        "unhold",
        "stream_start",
        "stream_stop",
        "remove_header",
        "accept_refer",
        "reject_refer",
        "bridge",
        "unbridge",
        "answer_anchored",
        "dial",
        "record_start",
        "record_stop",
    ):
        assert hasattr(Call, verb), f"Call is missing {verb}"
    assert issubclass(ControlError, Exception)


def test_command_roundtrip_and_typed_error():
    async def scenario():
        async with _serve_stub() as url:
            client = ControlClient(app=APP, token=TOKEN, url=url)
            await client.connect()

            schema = await client.describe()
            assert schema["adapters"][0]["module"] == "sip"

            with pytest.raises(ControlError) as excinfo:
                await client.command("boom", module="sip", target={"channel": "ch1"})
            assert excinfo.value.code == "not_found"

            client.shutdown()

    asyncio.run(scenario())


def test_on_call_async_dispatch():
    async def scenario():
        async with _serve_stub() as url:
            client = ControlClient(app=APP, token=TOKEN, url=url)
            fired = asyncio.get_event_loop().create_future()

            @client.on_call
            async def handle(call):
                await call.answer()
                header = await call.get_header("P-Asserted-Identity")
                if not fired.done():
                    fired.set_result((call.channel_id, call.is_reattached, header))

            await client.connect()
            run_task = asyncio.ensure_future(client.run())
            # Let run() install the Python handler bridge before triggering.
            await asyncio.sleep(0.3)
            await client.command("test_push_stasis")

            channel, reattached, header = await asyncio.wait_for(fired, timeout=5)
            assert channel == "ch1"
            assert reattached is False
            assert header == "203.0.113.7"

            client.shutdown()
            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(run_task, timeout=5)

    asyncio.run(scenario())


def test_on_app_event_dispatch():
    """An application-level event (no channel) reaches `@client.on_app_event`."""

    async def scenario():
        async with _serve_stub() as url:
            client = ControlClient(app=APP, token=TOKEN, url=url)
            fired = asyncio.get_event_loop().create_future()

            @client.on_app_event
            async def handle(event, payload):
                if not fired.done():
                    fired.set_result((event, payload))

            await client.connect()
            run_task = asyncio.ensure_future(client.run())
            await asyncio.sleep(0.3)
            await client.command("test_push_app_event")

            event, payload = await asyncio.wait_for(fired, timeout=5)
            assert event == "DialogStateChanged"
            assert payload["aor"] == "sip:201@example.com"
            assert payload["state"] == "early"
            assert payload["remote_identity"]["display_name"] is None

            client.shutdown()
            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(run_task, timeout=5)

    asyncio.run(scenario())


def test_route_verb_roundtrip():
    """`call.route(...)` emits the `route` command and returns the routing result."""

    async def scenario():
        recorded = {}

        async def route_stub(websocket):
            auth = websocket.request.headers.get("Authorization", "")
            if auth != f"Bearer {TOKEN}":
                await websocket.close(code=1008, reason="unauthorized")
                return
            said_hello = False
            async for message in websocket:
                frame = json.loads(message)
                frame_id = frame.get("id")
                verb = frame.get("verb")
                if not said_hello:
                    assert verb == "hello", "first frame must be hello"
                    await _reply_ok(
                        websocket,
                        frame_id,
                        {"app": APP, "protocol": 1, "subprotocol": SUBPROTOCOL},
                    )
                    said_hello = True
                elif verb == "test_push_stasis":
                    await websocket.send(
                        json.dumps(
                            {
                                "type": "event",
                                "event": "StasisStart",
                                "channel": "ch1",
                                "app": APP,
                                "call_id": "call-uuid",
                                "sip_call_id": "sipcid@host",
                                "payload": {},
                            }
                        )
                    )
                    await _reply_ok(websocket, frame_id, {})
                elif verb == "route":
                    recorded["frame"] = frame
                    await _reply_ok(
                        websocket,
                        frame_id,
                        {"channel": "ch1", "state": "routing", "targets": 2},
                    )
                else:
                    await _reply_ok(websocket, frame_id, {"state": "answered"})

        async with websockets.serve(
            route_stub, "127.0.0.1", 0, subprotocols=[SUBPROTOCOL]
        ) as server:
            port = server.sockets[0].getsockname()[1]
            url = f"ws://127.0.0.1:{port}/control/ws"
            client = ControlClient(app=APP, token=TOKEN, url=url)
            done = asyncio.get_event_loop().create_future()

            @client.on_call
            async def handle(call):
                result = await call.route(
                    [
                        "sip:carrier1@gw1",
                        {
                            "uri": "sip:carrier2@gw2",
                            "next_hop": "sip:1.2.3.4:5060",
                            "headers": {"X-Foo": "bar"},
                            "timeout": 30,
                        },
                        {
                            "uri": "sip:carrier3@gw3",
                            "timeout": 6,
                            "reroute_after_progress": True,
                        },
                        {"uri": "sip:carrier4@gw4", "reroute_after_progress": False},
                    ],
                    strategy="sequential",
                    headers={"X-Trace": "abc"},
                )
                # A policy flag that is not a bool is refused before anything
                # is sent, as the server refuses it.
                try:
                    call.route(
                        [{"uri": "sip:carrier5@gw5", "reroute_after_progress": "yes"}]
                    )
                except TypeError as error:
                    recorded["refused"] = str(error)
                if not done.done():
                    done.set_result(result)

            await client.connect()
            run_task = asyncio.ensure_future(client.run())
            await asyncio.sleep(0.3)
            await client.command("test_push_stasis")

            result = await asyncio.wait_for(done, timeout=5)
            assert result == {"channel": "ch1", "state": "routing", "targets": 2}

            frame = recorded["frame"]
            assert frame["module"] == "sip"
            assert frame["verb"] == "route"
            assert frame["target"]["channel"] == "ch1"
            assert frame["args"] == {
                "targets": [
                    "sip:carrier1@gw1",
                    {
                        "uri": "sip:carrier2@gw2",
                        "next_hop": "sip:1.2.3.4:5060",
                        "headers": {"X-Foo": "bar"},
                        "timeout": 30,
                    },
                    {
                        "uri": "sip:carrier3@gw3",
                        "timeout": 6,
                        "reroute_after_progress": True,
                    },
                    # Off is the server's default and stays off the wire, so a
                    # target with nothing else set goes out as a bare URI.
                    "sip:carrier4@gw4",
                ],
                "strategy": "sequential",
                "headers": {"X-Trace": "abc"},
            }
            assert "reroute_after_progress" in recorded.get("refused", ""), recorded

            client.shutdown()
            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(run_task, timeout=5)

    asyncio.run(scenario())


def test_media_header_refer_verbs_roundtrip():
    """The media / header / REFER / bridge verbs emit the exact server-side frames."""

    async def scenario():
        recorded = []

        async def verb_stub(websocket):
            auth = websocket.request.headers.get("Authorization", "")
            if auth != f"Bearer {TOKEN}":
                await websocket.close(code=1008, reason="unauthorized")
                return
            said_hello = False
            async for message in websocket:
                frame = json.loads(message)
                frame_id = frame.get("id")
                verb = frame.get("verb")
                if not said_hello:
                    await _reply_ok(
                        websocket,
                        frame_id,
                        {"app": APP, "protocol": 1, "subprotocol": SUBPROTOCOL},
                    )
                    said_hello = True
                elif verb == "test_push_stasis":
                    await websocket.send(
                        json.dumps(
                            {
                                "type": "event",
                                "event": "StasisStart",
                                "channel": "ch1",
                                "app": APP,
                                "call_id": "call-uuid",
                                "sip_call_id": "sipcid@host",
                                "payload": {},
                            }
                        )
                    )
                    await _reply_ok(websocket, frame_id, {})
                else:
                    recorded.append(frame)
                    await _reply_ok(websocket, frame_id, {"channel": "ch1"})

        async with websockets.serve(
            verb_stub, "127.0.0.1", 0, subprotocols=[SUBPROTOCOL]
        ) as server:
            port = server.sockets[0].getsockname()[1]
            url = f"ws://127.0.0.1:{port}/control/ws"
            client = ControlClient(app=APP, token=TOKEN, url=url)
            done = asyncio.get_event_loop().create_future()

            @client.on_call
            async def handle(call):
                await call.play(file="/prompts/welcome.wav", repeat=2)
                await call.play(blob=b"hi", duration_ms=5000)
                await call.stop()
                await call.dtmf("123#", duration_ms=100, volume_dbm0=-8)
                await call.hold()
                await call.unhold()
                await call.remove_header("X-Foo")
                await call.accept_refer(
                    target="sip:c@pbx", next_hop="sip:sbc", mode="terminate"
                )
                await call.reject_refer(603, "Decline")
                # `with` is a Python keyword, so the wire's `with` is passed as
                # `with_channel`; an unset policy is omitted so the server's
                # "hangup" default applies.
                await call.bridge("ch2", on_peer_hangup="hold")
                await call.bridge("ch3")
                await call.unbridge("supervisor took over")
                await call.unbridge()
                # replace_peer: every optional argument reaches the wire
                # under its wire name, and omitted ones stay off it so the
                # server's defaults apply rather than being nulled out.
                await call.replace_peer(
                    "sip:operator@pbx",
                    next_hop="sip:sbc",
                    replace_a_leg=True,
                    profile="ims_to_trunk",
                    timeout=45,
                )
                await call.replace_peer("sip:agent@pbx")
                # answer_anchored: `anchor` is always on the wire, so calling
                # it with no arguments still means "answer through the media
                # engine on its default profile" rather than a plain answer.
                await call.answer_anchored()
                await call.answer_anchored(
                    profile="voice_ai", ws_uri="wss://ai.test/{call_id}"
                )
                # A policy the server would refuse is refused locally instead,
                # before anything touches the two live calls.
                with pytest.raises(ValueError):
                    await call.bridge("ch2", on_peer_hangup="park")
                if not done.done():
                    done.set_result(True)

            await client.connect()
            run_task = asyncio.ensure_future(client.run())
            await asyncio.sleep(0.3)
            await client.command("test_push_stasis")

            await asyncio.wait_for(done, timeout=5)

            by_verb = {frame["verb"]: frame["args"] for frame in recorded}
            assert by_verb["play"] in (
                {"file": "/prompts/welcome.wav", "repeat": 2},
                {"blob": "aGk=", "duration_ms": 5000},
            )
            # Both play frames were sent (file first, blob second).
            play_args = [frame["args"] for frame in recorded if frame["verb"] == "play"]
            assert play_args[0] == {"file": "/prompts/welcome.wav", "repeat": 2}
            assert play_args[1] == {"blob": "aGk=", "duration_ms": 5000}
            assert by_verb["stop"] == {}
            assert by_verb["dtmf"] == {
                "digits": "123#",
                "duration_ms": 100,
                "volume_dbm0": -8,
            }
            assert by_verb["hold"] == {}
            assert by_verb["unhold"] == {}
            assert by_verb["remove_header"] == {"name": "X-Foo"}
            assert by_verb["accept_refer"] == {
                "target": "sip:c@pbx",
                "next_hop": "sip:sbc",
                "mode": "terminate",
            }
            assert by_verb["reject_refer"] == {"code": 603, "reason": "Decline"}
            bridge_args = [f["args"] for f in recorded if f["verb"] == "bridge"]
            assert bridge_args[0] == {"with": "ch2", "on_peer_hangup": "hold"}
            assert bridge_args[1] == {"with": "ch3"}
            unbridge_args = [f["args"] for f in recorded if f["verb"] == "unbridge"]
            assert unbridge_args[0] == {"reason": "supervisor took over"}
            assert unbridge_args[1] == {}
            replace_args = [
                f["args"] for f in recorded if f["verb"] == "replace_peer"
            ]
            assert replace_args[0] == {
                "target": "sip:operator@pbx",
                "next_hop": "sip:sbc",
                "replace_a_leg": True,
                "profile": "ims_to_trunk",
                "timeout": 45,
            }
            assert replace_args[1] == {"target": "sip:agent@pbx"}
            answer_args = [f["args"] for f in recorded if f["verb"] == "answer"]
            assert answer_args[0] == {"anchor": True}
            assert answer_args[1] == {
                "anchor": True,
                "profile": "voice_ai",
                "ws_uri": "wss://ai.test/{call_id}",
            }
            for frame in recorded:
                assert frame["module"] == "sip"
                assert frame["target"]["channel"] == "ch1"

            client.shutdown()
            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(run_task, timeout=5)

    asyncio.run(scenario())


def test_dtmf_event_delivered_to_call():
    """A pushed ChannelDtmfReceived event surfaces via `call.next_event()`."""

    async def scenario():
        async def dtmf_stub(websocket):
            auth = websocket.request.headers.get("Authorization", "")
            if auth != f"Bearer {TOKEN}":
                await websocket.close(code=1008, reason="unauthorized")
                return
            said_hello = False
            async for message in websocket:
                frame = json.loads(message)
                frame_id = frame.get("id")
                verb = frame.get("verb")
                if not said_hello:
                    await _reply_ok(
                        websocket,
                        frame_id,
                        {"app": APP, "protocol": 1, "subprotocol": SUBPROTOCOL},
                    )
                    said_hello = True
                elif verb == "test_push_stasis":
                    await websocket.send(
                        json.dumps(
                            {
                                "type": "event",
                                "event": "StasisStart",
                                "channel": "ch1",
                                "app": APP,
                                "call_id": "call-uuid",
                                "sip_call_id": "sipcid@host",
                                "payload": {},
                            }
                        )
                    )
                    # Immediately follow with a DTMF event for the same channel.
                    await websocket.send(
                        json.dumps(
                            {
                                "type": "event",
                                "event": "ChannelDtmfReceived",
                                "channel": "ch1",
                                "app": APP,
                                "call_id": "call-uuid",
                                "sip_call_id": "sipcid@host",
                                "payload": {
                                    "digit": "5",
                                    "duration_ms": 100,
                                    "volume": -8,
                                    "from_tag": "alice-tag",
                                },
                            }
                        )
                    )
                    await _reply_ok(websocket, frame_id, {})
                else:
                    await _reply_ok(websocket, frame_id, {})

        async with websockets.serve(
            dtmf_stub, "127.0.0.1", 0, subprotocols=[SUBPROTOCOL]
        ) as server:
            port = server.sockets[0].getsockname()[1]
            url = f"ws://127.0.0.1:{port}/control/ws"
            client = ControlClient(app=APP, token=TOKEN, url=url)
            got = asyncio.get_event_loop().create_future()

            @client.on_call
            async def handle(call):
                event = await call.next_event()
                if not got.done():
                    got.set_result(event)

            await client.connect()
            run_task = asyncio.ensure_future(client.run())
            await asyncio.sleep(0.3)
            await client.command("test_push_stasis")

            event = await asyncio.wait_for(got, timeout=5)
            assert event["kind"] == "ChannelDtmfReceived"
            assert event["payload"] == {
                "digit": "5",
                "duration_ms": 100,
                "volume": -8,
                "from_tag": "alice-tag",
            }

            client.shutdown()
            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(run_task, timeout=5)

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Per-call-connect mode (ControlServer) — siphon dials the app.
# ---------------------------------------------------------------------------


async def _push_stasis(siphon):
    """Push the ownership-conferring StasisStart as siphon's first frame."""
    await siphon.send(
        json.dumps(
            {
                "type": "event",
                "event": "StasisStart",
                "channel": "ch-out",
                "app": APP,
                "call_id": "call-uuid",
                "sip_call_id": "sipcid@out",
                "payload": {"from": "sip:alice@example.com"},
            }
        )
    )


def test_server_mode_on_call_dispatch_and_verb_roundtrip():
    async def scenario():
        server = ControlServer(app=APP, token=TOKEN, bind="127.0.0.1:0")
        # Bind first so the ephemeral port is known before siphon dials in.
        addr = await server.bind()
        assert addr == server.local_addr
        assert addr.startswith("127.0.0.1:")

        fired = asyncio.get_event_loop().create_future()

        @server.on_call
        async def handle(call):
            await call.answer()  # sends a command; resolves on the stub's reply
            if not fired.done():
                fired.set_result((call.channel_id, call.sip_call_id, call.is_reattached))

        serve_task = asyncio.ensure_future(server.serve())
        # Let serve() install the handler bridge and reach the accept loop.
        await asyncio.sleep(0.3)

        # The stub plays siphon: dial the app, present the token + subprotocol.
        uri = f"ws://{addr}/siphon"
        async with websockets.connect(
            uri,
            additional_headers={"Authorization": f"Bearer {TOKEN}"},
            subprotocols=[SUBPROTOCOL],
        ) as siphon:
            await _push_stasis(siphon)

            # The handler's call.answer() sends a command over THIS connection.
            command = json.loads(await asyncio.wait_for(siphon.recv(), timeout=5))
            assert command["type"] == "command"
            assert command["verb"] == "answer"
            assert command["module"] == "sip"
            assert command["target"]["channel"] == "ch-out"
            await siphon.send(
                json.dumps(
                    {
                        "id": command["id"],
                        "type": "reply",
                        "status": "ok",
                        "result": {"state": "answered"},
                    }
                )
            )

            channel, sip_call_id, reattached = await asyncio.wait_for(fired, timeout=5)
            assert channel == "ch-out"
            assert sip_call_id == "sipcid@out"
            assert reattached is False

        serve_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
            await asyncio.wait_for(serve_task, timeout=5)

    asyncio.run(scenario())


def test_server_mode_rejects_bad_token():
    async def scenario():
        server = ControlServer(app=APP, token=TOKEN, bind="127.0.0.1:0")
        addr = await server.bind()
        serve_task = asyncio.ensure_future(server.serve())
        await asyncio.sleep(0.3)

        uri = f"ws://{addr}/siphon"
        with pytest.raises(websockets.exceptions.InvalidStatus) as excinfo:
            async with websockets.connect(
                uri,
                additional_headers={"Authorization": "Bearer wrong"},
                subprotocols=[SUBPROTOCOL],
            ):
                pass
        assert excinfo.value.response.status_code == 401

        serve_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
            await asyncio.wait_for(serve_task, timeout=5)

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Shutdown behaviour
# ---------------------------------------------------------------------------
#
# The Rust side drives Python from detached tokio tasks that nothing joins: a
# handover is dispatched with `tokio::spawn`, and every awaitable is resolved
# through the asyncio loop captured when `run()` was called. The runtime
# outlives both the loop and the interpreter, so a task waking after the app has
# finished used to re-enter a Python that was no longer there -- as a
# `tokio-rt-worker` panic telling the reader to call `Python::initialize()`,
# printed after the app's own clean exit and easily read as its cause.


def test_module_exposes_close_and_async_context_manager():
    """The deterministic teardown path exists on both connection modes."""
    for cls in (ControlClient, ControlServer):
        assert hasattr(cls, "close"), cls
        assert hasattr(cls, "__aenter__"), cls
        assert hasattr(cls, "__aexit__"), cls


def test_close_stops_dispatching_into_python():
    """After close(), a handover already on the wire is not handed to the handler.

    This is what makes teardown deterministic: an app that closes has nothing in
    flight for the interpreter/loop guards to decline later. The stub keeps
    pushing handovers on a timer, so the events keep arriving after close() —
    the client has to be the thing that stops, not the sender.
    """
    async def scenario():
        pushing = asyncio.Event()

        async def pushing_stub(websocket):
            said_hello = False
            sequence = 0

            async def push_forever():
                nonlocal sequence
                while True:
                    sequence += 1
                    try:
                        await websocket.send(json.dumps({
                            "type": "event", "event": "StasisStart",
                            "channel": f"ch{sequence}", "app": APP,
                            "call_id": f"call-{sequence}",
                            "sip_call_id": f"sip{sequence}@host", "payload": {},
                        }))
                    except Exception:
                        return
                    await asyncio.sleep(0.02)

            async for message in websocket:
                frame = json.loads(message)
                if not said_hello:
                    await _reply_ok(websocket, frame.get("id"), {
                        "app": APP, "protocol": 1, "subprotocol": SUBPROTOCOL,
                    })
                    said_hello = True
                    asyncio.ensure_future(push_forever())
                    pushing.set()
                    continue
                await _reply_ok(websocket, frame.get("id"), {"state": "answered"})

        async with websockets.serve(
            pushing_stub, "127.0.0.1", 0, subprotocols=[SUBPROTOCOL]
        ) as server:
            url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/control/ws"
            client = ControlClient(app=APP, token=TOKEN, url=url)
            calls = []

            @client.on_call
            async def handle(call):
                calls.append(call.channel_id)

            await client.connect()
            run_task = asyncio.ensure_future(client.run())
            await asyncio.wait_for(pushing.wait(), timeout=5)
            await asyncio.sleep(0.3)
            assert calls, "handler must run while the client is open"

            client.close()
            settled = len(calls)
            await asyncio.sleep(0.3)
            assert len(calls) == settled, "close() must stop dispatching into Python"

            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(run_task, timeout=5)

    asyncio.run(scenario())


def test_async_context_manager_closes_on_exit():
    """`async with` closes on the way out, including when the body raises."""
    async def scenario():
        async with _serve_stub() as url:
            client = ControlClient(app=APP, token=TOKEN, url=url)

            @client.on_call
            async def handle(call):
                pass

            with contextlib.suppress(RuntimeError):
                async with client as entered:
                    assert entered is client
                    await client.connect()
                    run_task = asyncio.ensure_future(client.run())
                    await asyncio.sleep(0.3)
                    raise RuntimeError("the app blew up")

            # __aexit__ closed the client despite the exception, so the
            # connection is gone and a further command has nowhere to go.
            with pytest.raises(ControlError) as excinfo:
                await client.command("test_push_stasis")
            assert "closed" in str(excinfo.value)

            run_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(run_task, timeout=5)

    asyncio.run(scenario())


def test_shutdown_teardown_is_quiet(capfd):
    """A finished app exits without a traceback, closed or not.

    Handlers still in flight are cancelled when the loop closes; a cancelled
    handler is teardown, not a failure, and printing one traceback per in-flight
    call is the same "the exit reason is buried" problem as the panic. Handovers
    that arrive after the loop is gone are dropped rather than dispatched onto a
    closed loop, which the dependency would report as `RuntimeError: Event loop
    is closed`.
    """
    async def scenario():
        async with _serve_stub() as url:
            client = ControlClient(app=APP, token=TOKEN, url=url)
            entered = asyncio.get_event_loop().create_future()

            @client.on_call
            async def handle(call):
                if not entered.done():
                    entered.set_result(True)
                await asyncio.sleep(60)   # still in flight at teardown

            await client.connect()
            asyncio.ensure_future(client.run())
            await asyncio.sleep(0.3)
            await client.command("test_push_stasis")
            await asyncio.wait_for(entered, timeout=5)

    asyncio.run(scenario())
    # asyncio.run has now cancelled the in-flight handler and closed the loop,
    # but the reaction to that lands on a tokio worker, not on this thread —
    # give it time to print whatever it is going to print. Without this wait the
    # assertions below race past the noise and pass even on the unfixed build.
    time.sleep(1.0)
    err = capfd.readouterr().err
    assert "CancelledError" not in err, err
    assert "Event loop is closed" not in err, err
    assert "panicked" not in err, err


def test_transfer_outcome_helpers():
    """The module-level twins of the Rust client's `CallEvent` helpers.

    `next_event()` hands back a plain dict, so there is no event object to hang
    methods off — but an application still should not have to hardcode the wire
    strings, which is exactly what rots in silence when the event set grows.
    """
    # Exactly one terminal verdict arrives per refer (RFC 3515 §2.4.4), so this
    # is the signal to stop waiting; a 2xx to the REFER is only "accepted for
    # processing" and reaches the app as TransferProgress.
    assert is_transfer_final("TransferCompleted") is True
    assert is_transfer_final("TransferFailed") is True
    assert is_transfer_final("TransferProgress") is False
    assert is_transfer_final("TransferRequested") is False
    assert is_transfer_final("StasisEnd") is False

    completed = transfer_outcome(
        {
            "kind": "TransferCompleted",
            "payload": {"stage": "transferred", "code": 200, "reason": "OK"},
        }
    )
    assert completed == {"stage": "transferred", "code": 200, "reason": "OK"}
    assert transfer_outcome({"kind": "TransferProgress", "payload": {"stage": "accepted"}}) == {
        "stage": "accepted"
    }

    # TransferRequested is an *inbound* REFER somebody else asked for, not a
    # verdict on one of ours — reading it as an outcome would report a transfer
    # this app never started.
    assert transfer_outcome({"kind": "TransferRequested", "payload": {}}) is None
    assert transfer_outcome({"kind": "StasisEnd", "payload": {}}) is None
    assert transfer_outcome({"kind": "TransferFailed"}) is None


def test_originate_verb_roundtrip():
    """`client.originate(...)` emits the module-level `originate` command with the
    exact args the server parses, the session timer among them, and refuses what
    the server would refuse before anything is sent."""

    async def scenario():
        frames = []

        async def originate_stub(websocket):
            auth = websocket.request.headers.get("Authorization", "")
            if auth != f"Bearer {TOKEN}":
                await websocket.close(code=1008, reason="unauthorized")
                return
            said_hello = False
            async for message in websocket:
                frame = json.loads(message)
                frame_id = frame.get("id")
                if not said_hello:
                    assert frame.get("verb") == "hello", "first frame must be hello"
                    await _reply_ok(
                        websocket,
                        frame_id,
                        {"app": APP, "protocol": 1, "subprotocol": SUBPROTOCOL},
                    )
                    said_hello = True
                    continue
                frames.append(frame)
                await _reply_ok(
                    websocket,
                    frame_id,
                    {
                        "channel": frame["args"]["channel"],
                        "call_id": "call-uuid",
                        "sip_call_id": "sipcid@host",
                        "state": "calling",
                    },
                )

        async with websockets.serve(
            originate_stub, "127.0.0.1", 0, subprotocols=[SUBPROTOCOL]
        ) as server:
            port = server.sockets[0].getsockname()[1]
            client = ControlClient(
                app=APP, token=TOKEN, url=f"ws://127.0.0.1:{port}/control/ws"
            )
            await client.connect()

            placed = await client.originate(
                "out-1",
                "sip:1001@pbx.example",
                media=True,
                from_uri="sip:alarm@pbx.example",
                timeout=20,
                session_timer={"expires": 90, "refresher": "UAC"},
            )
            assert placed == {
                "channel": "out-1",
                "call_id": "call-uuid",
                "sip_call_id": "sipcid@host",
            }
            await client.originate(
                "out-2", "sip:1001@pbx.example", sdp="v=0\r\n"
            )

            # What the server would refuse is refused here, before a frame goes
            # out: a timer siphon cannot run, and a media plan that is not
            # exactly one.
            for session_timer in ({"refresher": "sometimes"}, {"interval": 90}):
                with pytest.raises(ValueError, match="session_timer|refresher"):
                    await client.originate(
                        "out-3",
                        "sip:1001@pbx.example",
                        media=True,
                        session_timer=session_timer,
                    )
            with pytest.raises(ValueError, match="media"):
                await client.originate("out-4", "sip:1001@pbx.example")
            with pytest.raises(ValueError, match="media"):
                await client.originate(
                    "out-5", "sip:1001@pbx.example", media=True, sdp="v=0\r\n"
                )

            assert [frame["args"]["channel"] for frame in frames] == ["out-1", "out-2"]
            first = frames[0]
            assert first["module"] == "sip"
            assert first["verb"] == "originate"
            assert first.get("target") is None
            assert first["args"] == {
                "channel": "out-1",
                "to": "sip:1001@pbx.example",
                "media": True,
                "from": "sip:alarm@pbx.example",
                "timeout": 20,
                "session_timer": {"expires": 90, "refresher": "uac"},
            }
            # No timer asked for: nothing sent, so the configured one runs.
            assert frames[1]["args"] == {
                "channel": "out-2",
                "to": "sip:1001@pbx.example",
                "sdp": "v=0\r\n",
            }

            client.close()

    asyncio.run(scenario())


def _verb_stub(verb_names, replies, frames):
    """A stub that records every frame for `verb_names` and answers from `replies`.

    `replies` is called with the recorded frame and returns the reply result.
    """

    async def stub(websocket):
        auth = websocket.request.headers.get("Authorization", "")
        if auth != f"Bearer {TOKEN}":
            await websocket.close(code=1008, reason="unauthorized")
            return
        said_hello = False
        async for message in websocket:
            frame = json.loads(message)
            frame_id = frame.get("id")
            verb = frame.get("verb")
            if not said_hello:
                assert verb == "hello", "first frame must be hello"
                await _reply_ok(
                    websocket,
                    frame_id,
                    {"app": APP, "protocol": 1, "subprotocol": SUBPROTOCOL},
                )
                said_hello = True
            elif verb == "test_push_stasis":
                await websocket.send(
                    json.dumps(
                        {
                            "type": "event",
                            "event": "StasisStart",
                            "channel": "ch1",
                            "app": APP,
                            "call_id": "call-uuid",
                            "sip_call_id": "sipcid@host",
                            "payload": {},
                        }
                    )
                )
                await _reply_ok(websocket, frame_id, {})
            elif verb in verb_names:
                frames.append(frame)
                await _reply_ok(websocket, frame_id, replies(frame))
            else:
                await _reply_ok(websocket, frame_id, {"state": "answered"})

    return stub


def test_dial_verb_roundtrip():
    """`call.dial(...)` emits the `dial` command with the exact target shapes the
    server parses, and refuses an ambiguous target before anything is sent."""

    async def scenario():
        frames = []
        refused = []

        def reply(_frame):
            return {
                "channel": "ch1",
                "state": "dialing",
                "targets": 3,
                "strategy": "sequential",
                "timeout": 20,
            }

        stub = _verb_stub({"dial"}, reply, frames)
        async with websockets.serve(
            stub, "127.0.0.1", 0, subprotocols=[SUBPROTOCOL]
        ) as server:
            port = server.sockets[0].getsockname()[1]
            url = f"ws://127.0.0.1:{port}/control/ws"
            client = ControlClient(app=APP, token=TOKEN, url=url)
            done = asyncio.get_event_loop().create_future()

            @client.on_call
            async def handle(call):
                result = await call.dial(
                    [
                        {"aor": "sip:204@pbx.example"},
                        {
                            "uri": "sip:+15550177@trunk.example",
                            "next_hop": "sip:192.0.2.9:5060",
                            "headers": {"X-Carrier": "a"},
                        },
                    ],
                    strategy="sequential",
                    timeout=20,
                    headers={"X-Trace": "abc"},
                )
                # Nothing else asked for: the server's own parallel / 30 s
                # defaults apply rather than a copy of them pinned here.
                await call.dial([{"uri": "sip:1001@pbx.example"}])
                # Each of these would place a different call than the one that
                # was written down, so each is refused before a frame goes out.
                for bad in (
                    # Ambiguous: the server reads a bare string as a URI, which
                    # reaches none of an AoR's registered contacts.
                    "sip:204@pbx.example",
                    # The server reads `aor` first and ignores the `uri`.
                    {"uri": "sip:1001@pbx.example", "aor": "sip:204@pbx.example"},
                    {"next_hop": "sip:192.0.2.9:5060"},
                    # An AoR branch routes over each contact's captured flow, so
                    # a next_hop beside it is silently dropped server-side.
                    {"aor": "sip:204@pbx.example", "next_hop": "sip:192.0.2.9:5060"},
                ):
                    try:
                        call.dial([bad])
                    except ValueError as error:
                        refused.append(str(error))
                try:
                    call.dial([{"aor": "sip:204@pbx.example"}], strategy="hunt")
                except ValueError as error:
                    refused.append(str(error))
                if not done.done():
                    done.set_result(result)

            await client.connect()
            run_task = asyncio.ensure_future(client.run())
            await asyncio.sleep(0.3)
            await client.command("test_push_stasis")

            result = await asyncio.wait_for(done, timeout=5)
            assert result == {
                "channel": "ch1",
                "targets": 3,
                "strategy": "sequential",
                "timeout": 20,
            }

            first = frames[0]
            assert first["module"] == "sip"
            assert first["verb"] == "dial"
            assert first["target"]["channel"] == "ch1"
            assert first["args"] == {
                "targets": [
                    {"aor": "sip:204@pbx.example"},
                    {
                        "uri": "sip:+15550177@trunk.example",
                        "next_hop": "sip:192.0.2.9:5060",
                        "headers": {"X-Carrier": "a"},
                    },
                ],
                "strategy": "sequential",
                "timeout": 20,
                "headers": {"X-Trace": "abc"},
            }
            # A bare URI target with no overrides goes out as a plain string.
            assert frames[1]["args"] == {"targets": ["sip:1001@pbx.example"]}
            assert len(refused) == 5, refused
            assert "aor" in refused[0] and "uri" in refused[0], refused[0]
            assert "strategy" in refused[4], refused[4]

            client.shutdown()
            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(run_task, timeout=5)

    asyncio.run(scenario())


def test_record_verbs_roundtrip():
    """`call.record_start(...)` / `call.record_stop(...)` emit the exact args the
    server parses, and the start's reply carries the id a stop addresses."""

    async def scenario():
        frames = []
        refused = []

        def reply(frame):
            if frame["verb"] == "record_start":
                return {
                    "channel": "ch1",
                    "state": "recording",
                    "recording_id": "rec-1",
                }
            return {
                "channel": "ch1",
                "state": "stopping",
                "recording_id": frame["args"].get("recording_id"),
            }

        stub = _verb_stub({"record_start", "record_stop"}, reply, frames)
        async with websockets.serve(
            stub, "127.0.0.1", 0, subprotocols=[SUBPROTOCOL]
        ) as server:
            port = server.sockets[0].getsockname()[1]
            url = f"ws://127.0.0.1:{port}/control/ws"
            client = ControlClient(app=APP, token=TOKEN, url=url)
            done = asyncio.get_event_loop().create_future()

            @client.on_call
            async def handle(call):
                started = await call.record_start(
                    direction="both",
                    channels="stereo",
                    max_duration_ms=60_000,
                    silence_ms=4_000,
                    path="/var/spool/siphon/greeting.wav",
                )
                await call.record_stop(recording_id=started["recording_id"])
                await call.record_start()
                await call.record_stop()
                for kwargs in ({"direction": "inbound"}, {"channels": "quad"}):
                    try:
                        call.record_start(**kwargs)
                    except ValueError as error:
                        refused.append(str(error))
                if not done.done():
                    done.set_result(started)

            await client.connect()
            run_task = asyncio.ensure_future(client.run())
            await asyncio.sleep(0.3)
            await client.command("test_push_stasis")

            started = await asyncio.wait_for(done, timeout=5)
            assert started == {"channel": "ch1", "recording_id": "rec-1"}

            assert frames[0]["module"] == "sip"
            assert frames[0]["verb"] == "record_start"
            assert frames[0]["target"]["channel"] == "ch1"
            assert frames[0]["args"] == {
                "direction": "both",
                "channels": "stereo",
                "max_duration_ms": 60_000,
                "silence_ms": 4_000,
                "path": "/var/spool/siphon/greeting.wav",
            }
            assert frames[1]["verb"] == "record_stop"
            assert frames[1]["args"] == {"recording_id": "rec-1"}
            # ingress + mono are the server's defaults, so an unshaped start
            # sends neither and keeps tracking the server it talks to.
            assert frames[2]["args"] == {}
            # Absent, not null — which is what makes the server stop every
            # recording on the call rather than one named `null`.
            assert frames[3]["args"] == {}
            assert len(refused) == 2, refused

            client.shutdown()
            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(run_task, timeout=5)

    asyncio.run(scenario())
