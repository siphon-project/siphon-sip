# A conference focus with mixing

A conference focus (RFC 4579) is the user agent every participant of a
conference has a dialog with. siphon can be that focus with the media
engine doing the mixing: the script answers each participant's INVITE itself,
the engine seats the participant in a room and hands back the answer SDP, and
every seat hears the room minus itself.

Mixing needs the native **siphon-rtp** engine (`media.backend: siphon-rtp`).
rtpengine and rtpproxy have no mixer, and every `conference_*` verb raises
`RuntimeError` naming the backend on them.

```yaml
media:
  backend: siphon-rtp
  siphon_rtp:
    address: "127.0.0.1:8080"
```

## Rooms and seats

- **A room** is named by an id the script chooses. The engine creates it on its
  first `conference_join` and ends it with its last `conference_leave`, so the
  script owns the id space: one room per conference URI.
- **A seat** is a participant's call, addressed by its From-tag. That is the
  name `@rtpengine.on_active_speaker` and a room's `@rtpengine.on_dtmf` hand
  back.
- A room holds at most 64 seats. Bridged rooms (`conference_bridge`) each hear
  the other's participants.

## The focus

The factory URI (RFC 4579 section 5.2) mints a room; an INVITE to a conference
URI joins it. A BYE leaves. The roster is just what joined and has not left.

```python
import uuid

from siphon import b2bua, proxy, rtpengine, log

FACTORY = "conference-factory"

# room id -> {call_id: participant URI}
ROSTER = {}
# call_id -> room id, since a factory INVITE's own URI names no room
ROOM_OF_CALL = {}


def room_of(call):
    """The room an INVITE names: a fresh one for the factory URI."""
    user = call.ruri.user
    if user == FACTORY:
        return f"room-{uuid.uuid4().hex[:12]}"
    return user


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
async def on_invite(call):
    room = room_of(call)
    try:
        sdp = await rtpengine.conference_join(room, call)
    except ValueError as error:
        # The room cannot mix the participant's codec (RFC 3264 section 6).
        log.warn(f"{room}: {error}")
        call.reject(488, "Not Acceptable Here")
        return
    call.answer(200, "OK", body=sdp, content_type="application/sdp")
    ROOM_OF_CALL[call.call_id] = room
    ROSTER.setdefault(room, {})[call.call_id] = str(call.from_uri)
    log.info(f"{room}: {call.from_uri} joined, {len(ROSTER[room])} seated")
    # RFC 4575: a <user> joined the roster; NOTIFY the subscribers here.


@b2bua.on_bye
async def on_bye(call, initiator):
    room = ROOM_OF_CALL.pop(call.call_id, None)
    if room is None:
        return
    # `rtpengine.delete(call)` would leave the room as well.
    await rtpengine.conference_leave(room, call)
    seats = ROSTER.get(room, {})
    seats.pop(call.call_id, None)
    if not seats:
        ROSTER.pop(room, None)
    # RFC 4575: a <user> left the roster; NOTIFY the subscribers here.


@rtpengine.on_active_speaker
def floor(conference_id, from_tag):
    # `from_tag` is None when the floor goes silent. RFC 4575 carries the
    # speaker as a <media> status; a focus would NOTIFY it from here.
    log.info(f"{conference_id}: {from_tag or 'nobody'} has the floor")
```

A factory-minted room needs its conference URI handed back to the participant
(the focus's Contact, with the `isfocus` feature parameter of RFC 4579
section 5.1), so that later participants can dial it; that part of the
signalling is not shown here. Nor is the RFC 4575 event package itself: the
comments mark where its NOTIFYs would go.

With five participants the room has five seats and each hears the other four.
`rtpengine.delete(call)` on a seated call leaves its room as well, so a script
that already deletes media on BYE does not need a second call.

## Who hears whom

`role=` on `conference_join`, or later on `conference_route`, places a seat in
the room's routing matrix, live and without a re-INVITE:

| role | hears | is heard by |
|---|---|---|
| `talker` | the room minus itself | everyone (default) |
| `listener` | the room | no one |
| `muted` | the room | no one |
| `whisper` | the room minus itself | only `target` |
| `monitor` | `target` alone, unknown to it | no one, or `whisper_target` |

```python
from siphon import rtpengine

async def mute(room, call):
    await rtpengine.conference_route(room, call, "muted")

async def coach(room, supervisor, agent_tag):
    # The supervisor hears the agent and talks to the agent alone.
    await rtpengine.conference_route(
        room, supervisor, "monitor", target=agent_tag, whisper_target=agent_tag
    )
```

A seat can also be named by a `(call_id, from_tag)` pair, which is what an
event handler holds.

## Merging two conferences

```python
from siphon import rtpengine

async def merge(room_a, room_b):
    await rtpengine.conference_bridge(room_a, room_b)              # each hears the other
    # await rtpengine.conference_bridge(room_a, room_b, direction="a_to_b")
```

The engine has no verb to unbridge; a bridge ends with either room.

## Playing into a room

`conference_play` mixes a `file`, `blob` or `tone` into the room as a source
nobody is mixed-minus-self against, and resolves to its `play_id`. Its end
arrives as `@rtpengine.on_play_finished` with the room id as `call_id` and an
empty `from_tag`. `conference_set_play_gain` ducks it,
`conference_stop_play` ends one or all of them. Music for a lone participant:

```python
from siphon import rtpengine

MUSIC = {}           # room id -> play_id

async def seated(room, seats):
    if seats == 1:
        MUSIC[room] = await rtpengine.conference_play(room, file="/prompts/moh.wav", repeat="inf")
    elif room in MUSIC:
        await rtpengine.conference_stop_play(room, MUSIC.pop(room))


@rtpengine.on_play_finished
def ended(call_id, from_tag, play_id, reason, played_ms):
    if MUSIC.get(call_id) == play_id:
        MUSIC.pop(call_id)
```

## What the engine does not do yet

These are limits of siphon-rtp 0.14.0, not of the script API:

- **Codec choice.** A seat takes the offer's first audio codec, and the engine
  must be able to decode it and encode the mix back into it (AMR needs the
  engine's `amr` build, G.729 its `g729` build, and EVS is not implemented). A
  seat it cannot mix is refused with `ValueError`; a profile's codec policy is not
  applied to a seat, so `conference_join` refuses a profile that sets one
  rather than seating the call without it (the same goes for `ws_uri`,
  `ws_tee`, `record_call` and the DSP knobs).
- **Hold and mute by re-INVITE.** A seat is no media session of its call, so
  siphon answers a participant's re-INVITE or UPDATE that changes the media
  `488` unless `@b2bua.on_reoffer` answers it. A hold (`sendonly`) is answered
  by `offer.answer()`, after `conference_route(room, call, "listener")` or
  `"muted"` so the room stops hearing it:

  ```python
  @b2bua.on_reoffer
  async def seat_reoffer(call, offer):
      room = ROOM_OF_CALL.get(call.call_id)
      if room is None:
          return
      if offer.kind == "hold":
          await rtpengine.conference_route(room, call, "muted")
      elif offer.kind == "resume":
          await rtpengine.conference_route(room, call, "talker")
      offer.answer()
  ```
- **Re-seating.** There is no verb that updates a seat in place, and the
  engine does not report a second seat under one From-tag, so a call holds one
  seat and a second `conference_join` raises `ValueError`. A re-INVITE that
  changes the media has to leave and join again, which ends the room (and its
  playbacks and bridges) when the call was its only seat.
- **The 64-seat cap and a seat's packetization limits** are checked by the
  room after the engine has answered the join, so a 65th participant is
  answered and then not mixed. Keep the count in the roster.
- **Recording a room** (`conference_start_recording`) is not exposed yet: its
  completion has no script hook to arrive on.

The script on this page is
[`examples/conference_focus.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/conference_focus.py),
with its config in
[`examples/conference_focus.yaml`](https://github.com/siphon-project/siphon-sip/blob/main/examples/conference_focus.yaml).
