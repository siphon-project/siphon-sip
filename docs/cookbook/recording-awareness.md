# Recording awareness (RFC 7866)

A caller that is *record-aware* can ask for its own call to be recorded and be
told whether it is. RFC 7866 does it in the SDP of the ordinary offer/answer
exchange: the caller puts `a=recordpref:on` (or `off`, `pause`,
`nopreference`) on its audio stream, in the INVITE or in a re-INVITE later, and
every answer it gets carries `a=record:on` or `off`, the state as it is and not
as it was asked for. A recording that stops by itself is reported in an offer of
siphon's own.

The recording is the media engine's (`media.backend: siphon-rtp`): both parties
decoded, the caller on the left channel and the callee on the right, in Ogg
Opus. Nothing here needs the caller's carrier, or the callee, to know.

```yaml
media:
  backend: siphon-rtp
  # The caller's preference is not the far party's business.
  sdp_strip_attributes: ["recordpref"]
  siphon_rtp:
    address: "127.0.0.1:8080"
```

## The four pieces

- **Asking at setup.** The caller's offer is read in `@b2bua.on_invite`, before
  the media engine rewrites it for the callee, and its `Supported` header says
  whether it is record-aware. The recording starts in `@b2bua.on_answer`, and
  the 200 the caller gets has `a=record` set on its audio stream.
- **Toggling mid-call.** A re-INVITE that changes nothing but the preference is
  a `"refresh"` to `@b2bua.on_reoffer`: the streams, addresses, directions,
  keys and ICE credentials are as they were. The script starts or stops the
  recording and answers from `offer.session_sdp`, the session in force toward
  the caller, with `a=record` set. The callee is told nothing, and neither is
  the media engine. This works on a WebRTC leg too, keyed, ICE and bundled,
  because the session in force is repeated rather than renegotiated; an ICE
  restart or new keys make the offer a `"change"`, which is relayed as usual.
- **Stopping by itself.** A recording that reaches its cap, or fails, ends with
  `@rtpengine.on_recording_finished`. The caller is then re-offered the session
  in force with `a=record:off`: `b2bua.session_sdp()` reads it, and
  `b2bua.reoffer()` sends it and resolves to the caller's final status, so a
  crossing offer's `491` can be retried after RFC 3261 §14.1's 2.1 to 4 s.
- **Asked for by routing.** A routing answer that sets `"record": true` on a
  route has the call recorded whichever party asked, read off
  `call.active_route.record` in `@b2bua.on_answer`.

## The script

```python
import asyncio
import random

from siphon import b2bua, log, rtpengine, sdp

SPOOL = "/var/spool/siphon/recordings"
CALLS = {}   # by SIP Call-ID: record-aware, the running recording, asked at setup


def record_aware(call):
    supported = call.get_header("Supported") or ""
    return "record-aware" in (tag.strip().lower() for tag in supported.split(","))


def preference(description):
    """The `a=recordpref` of the first audio stream, or None."""
    if not description:
        return None
    for media in sdp.parse(description).media:
        if media.media_type == "audio":
            value = media.get_attr("recordpref")
            return value.strip().lower() if value else None
    return None


def with_record(description, state):
    parsed = sdp.parse(description)
    for media in parsed.media:
        if media.media_type == "audio":
            media.set_attr("record", state)
    return str(parsed)


def state_of(call_id):
    return "on" if CALLS.get(call_id, {}).get("recording") else "off"


async def start(call):
    entry = CALLS.setdefault(call.call_id, {"aware": False, "recording": None})
    if not entry["recording"]:
        entry["count"] = entry.get("count", 0) + 1
        entry["recording"] = await rtpengine.start_recording(
            call, format="ogg_opus", channels="stereo", direction="both",
            path=f"{SPOOL}/{call.call_id}-{entry['count']}.opus")


async def stop(call):
    recording = CALLS.get(call.call_id, {}).get("recording")
    if recording:
        CALLS[call.call_id]["recording"] = None
        await rtpengine.stop_recording(call, recording)


@b2bua.on_invite
async def new_call(call):
    CALLS[call.call_id] = {
        "aware": record_aware(call),
        "recording": None,
        "asked": preference(call.body.decode() if call.body else None) == "on",
    }
    await rtpengine.offer(call)
    call.dial("sip:callee@192.0.2.20")


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
    if offer.kind == "refresh" and offer.session_sdp:
        offer.answer(with_record(offer.session_sdp, state_of(call.call_id)))


@rtpengine.on_recording_finished
async def recording_closed(call_id, from_tag, recording_id, path, reason, duration_ms):
    entry = CALLS.get(call_id)
    if not entry or entry.get("recording") != recording_id:
        return
    entry["recording"] = None
    if entry["aware"] and reason in ("max_duration", "silence", "error"):
        session = b2bua.session_sdp(call_id)
        if session is None:
            return
        for _ in range(2):
            if await b2bua.reoffer(call_id, sdp=with_record(session, "off")) != 491:
                break
            await asyncio.sleep(random.uniform(2.1, 4.0))


@b2bua.on_bye
async def ended(call, initiator):
    CALLS.pop(call.call_id, None)
    await rtpengine.delete(call)
```

`@rtpengine.on_recording_finished` is also where a finished file is picked up:
moved, archived, or handed to whatever stores it. `call_id` there is the SIP
Call-ID, the key the call's CDR carries.

## Things worth knowing

- **`pause` is `off`.** The media engine has no pause; a recording stopped and
  started again is two files, and the answer says `off` while paused rather
  than `paused`, which is the truth about the file.
- **A preference on an offer that changes the media** (a hold, a codec, an
  address) is acted on, but the offer is relayed to the callee as usual and the
  answer comes back from there without `a=record`. The state reaches the caller
  in the next answer siphon gives it.
- **A crossing offer.** `b2bua.reoffer()` resolves to `491` without sending
  anything when an INVITE toward the caller is already in progress, and to the
  caller's own `491` when its offer crossed ours. Either way the session is
  unchanged; send again after the wait.
- **The recipe tracks its calls in a module dict**, which is fine for one
  siphon process. A fleet that moves calls between nodes needs it somewhere
  shared.

The script on this page is
[`examples/recording_awareness.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/recording_awareness.py),
with its config in
[`examples/recording_awareness.yaml`](https://github.com/siphon-project/siphon-sip/blob/main/examples/recording_awareness.yaml).
