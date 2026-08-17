"""Smoke tests for the ``siphon_control`` PyO3 bindings.

Drives the real extension module against an in-process ``websockets`` stub that
speaks the ``siphon-control.v1`` handshake, echoes correlated replies, and can
push events. Covers: build a client, connect + hello, a command round-trip, a
typed ``ControlError`` on an error reply, and the ``@client.on_call`` async
dispatch.

Run: ``python -m pytest tests/`` (needs ``websockets`` installed).
"""

import asyncio
import contextlib
import json

import pytest
import websockets

from siphon_control import Call, ControlClient, ControlError

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
        elif verb in ("play", "dtmf"):
            await _reply_error(
                websocket, frame_id, "unsupported_verb", "not implemented in this build"
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
    assert hasattr(Call, "answer")
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
