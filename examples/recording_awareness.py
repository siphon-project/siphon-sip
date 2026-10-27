"""RFC 7866 recording awareness on the caller's leg of a B2BUA call.

A record-aware caller (`Supported: record-aware`) asks for its call to be
recorded with `a=recordpref:on` on its audio stream, in the INVITE or in a
re-INVITE later, and stops it with `off` (`pause` is read as `off`: the media
engine has no pause, and a resumed recording is a new file). Every answer the
caller gets carries `a=record:on` or `off`, the state as it is and not as it was
asked for, and a recording that ends by itself (a cap, an error) is reported in
an offer of siphon's own. A routing answer can ask for the call to be recorded
too (`call.active_route.record`).

The recording is the engine's: both parties decoded, caller left and callee
right, in Ogg Opus. Config this runs with: `media.backend: siphon-rtp` and
`media.sdp_strip_attributes: ["recordpref"]`, so the far party never sees the
caller's preference.
"""

import asyncio
import os
import random

from siphon import b2bua, log, rtpengine, sdp

SPOOL = os.environ.get("RECORDING_SPOOL", "/var/spool/siphon/recordings")
TARGET = os.environ.get("RECORDING_TARGET", "sip:callee@127.0.0.1:5094")
# A cap on each recording, in ms; unset records until stopped or the call ends.
MAX_DURATION_MS = int(os.environ.get("RECORDING_MAX_DURATION_MS", "0")) or None

# Per call, by SIP Call-ID: whether the caller is record-aware, and the
# recording running on the call, if any.
CALLS = {}


def record_aware(call):
    supported = call.get_header("Supported") or ""
    return "record-aware" in (tag.strip().lower() for tag in supported.split(","))


def preference(description):
    """The `a=recordpref` of the first audio stream, or None (RFC 7866 §7.1)."""
    if not description:
        return None
    for media in sdp.parse(description).media:
        if media.media_type == "audio":
            value = media.get_attr("recordpref")
            return value.strip().lower() if value else None
    return None


def with_record(description, state):
    """`description` with `a=record:<state>` on every audio stream (§7.2)."""
    parsed = sdp.parse(description)
    for media in parsed.media:
        if media.media_type == "audio":
            media.set_attr("record", state)
    return str(parsed)


def state_of(call_id):
    return "on" if CALLS.get(call_id, {}).get("recording") else "off"


async def start(call):
    entry = CALLS.setdefault(call.call_id, {"aware": False, "recording": None})
    if entry["recording"]:
        return
    # One file per recording: a caller that stops and starts again gets two.
    entry["count"] = entry.get("count", 0) + 1
    try:
        entry["recording"] = await rtpengine.start_recording(
            call, format="ogg_opus", channels="stereo", direction="both",
            max_duration_ms=MAX_DURATION_MS,
            path=f"{SPOOL}/{call.call_id}-{entry['count']}.opus")
    except RuntimeError as error:
        log.warn(f"{call.call_id}: recording not started: {error}")


async def stop(call):
    recording = CALLS.get(call.call_id, {}).get("recording")
    if recording:
        CALLS[call.call_id]["recording"] = None
        await rtpengine.stop_recording(call, recording)


@b2bua.on_invite
async def new_call(call):
    # The caller's offer, before the media engine rewrites it for the callee.
    CALLS[call.call_id] = {
        "aware": record_aware(call),
        "recording": None,
        "asked": preference(call.body.decode() if call.body else None) == "on",
    }
    await rtpengine.offer(call)
    call.dial(TARGET)


@b2bua.on_answer
async def answered(call, reply):
    await rtpengine.answer(reply, call=call)
    entry = CALLS.get(call.call_id, {})
    route = call.active_route
    if entry.get("asked") or (route is not None and route.record):
        await start(call)
    if entry.get("aware"):
        answer = sdp.parse(reply)
        for media in answer.media:
            if media.media_type == "audio":
                media.set_attr("record", state_of(call.call_id))
        answer.apply(reply)


@b2bua.on_reoffer
async def reoffered(call, offer):
    entry = CALLS.get(call.call_id)
    if offer.side != "a" or not entry or not entry["aware"]:
        return
    wanted = preference(offer.sdp)
    if wanted == "on":
        await start(call)
    elif wanted in ("off", "pause"):
        await stop(call)
    # Nothing but the preference changed: answer from the session in force with
    # the state, and the callee is told nothing. Anything else is relayed, and
    # the state reaches the caller in the next offer either side makes.
    if offer.kind == "refresh" and offer.session_sdp:
        offer.answer(with_record(offer.session_sdp, state_of(call.call_id)))


@rtpengine.on_recording_finished
async def recording_closed(call_id, from_tag, recording_id, path, reason, duration_ms):
    log.info(f"{call_id}: recording {recording_id} closed ({reason}, {duration_ms} ms): {path}")
    entry = CALLS.get(call_id)
    if not entry or entry.get("recording") != recording_id:
        return
    entry["recording"] = None
    # Ended by itself on a call that is still up: tell the caller (§7.2).
    if entry["aware"] and reason in ("max_duration", "silence", "error"):
        session = b2bua.session_sdp(call_id)
        if session is None:
            return
        for _ in range(2):
            status = await b2bua.reoffer(call_id, sdp=with_record(session, "off"))
            if status != 491:
                break
            # RFC 3261 §14.1: the owner of the Call-ID waits 2.1 to 4 s.
            await asyncio.sleep(random.uniform(2.1, 4.0))


@b2bua.on_bye
async def ended(call, initiator):
    CALLS.pop(call.call_id, None)
    await rtpengine.delete(call)
