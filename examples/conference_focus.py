"""A conference focus with mixing (RFC 4579), the media engine doing the mix.

Every participant has its dialog with this focus. An INVITE to the factory URI
mints a room; an INVITE to a room's URI joins it. The engine answers each
participant's offer and seats it in the room, so every seat hears the room
minus itself. A BYE frees the seat, and the room ends with its last one.

The roster is what joined and has not left. The engine names a seat by the
participant's From-tag, which is what it reports the floor and a room's DTMF
under. The RFC 4575 conference-event package is not implemented
here; the comments mark where its NOTIFYs would go.

Needs the native siphon-rtp engine (``media.backend: siphon-rtp``); see
examples/conference_focus.yaml and docs/cookbook/conference-focus.md.
"""
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
