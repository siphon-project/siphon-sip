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

import pytest
import websockets

from siphon_control import Call, ControlClient, ControlError, ControlServer

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
                    ],
                    strategy="sequential",
                    headers={"X-Trace": "abc"},
                )
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
                ],
                "strategy": "sequential",
                "headers": {"X-Trace": "abc"},
            }

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
