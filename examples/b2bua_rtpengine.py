"""
SIPhon B2BUA script with RTPEngine media anchoring.

Used for functional testing: anchors media through a mock RTPEngine
on INVITE (offer) and 200 OK (answer), deletes on BYE.
"""
from siphon import b2bua, rtpengine, log


@b2bua.on_invite
async def on_invite(call):
    log.info(f"B2BUA INVITE: {call.from_uri} -> {call.to_uri}")

    # Anchor media through RTPEngine (offer direction)
    await rtpengine.offer(call, profile="srtp_to_rtp")
    log.info(f"RTPEngine offer done for call {call.call_id}")

    # Dial the B-leg
    call.dial(str(call.ruri))


@b2bua.on_answer
async def on_answer(call, reply):
    log.info(f"B2BUA answer: call {call.call_id}")

    # Anchor media through RTPEngine (answer direction)
    # Pass `call` so RTPEngine uses the A-leg Call-ID that matched the offer.
    await rtpengine.answer(reply, profile="srtp_to_rtp", call=call)
    log.info(f"RTPEngine answer done for call {call.call_id}")


@b2bua.on_failure
async def on_failure(call, code, reason):
    log.warn(f"B-leg failed {code} {reason} for call {call.call_id}")

    # Release RTPEngine session — offer was sent but call never connected.
    # Without this, session lingers until RTPEngine's own inactivity timeout.
    # Note: if retrying to another gateway, don't delete here — the same
    # RTPEngine session can be reused for the next dial attempt.
    await rtpengine.delete(call)
    call.reject(code, reason)


@b2bua.on_bye
async def on_bye(call, initiator):
    log.info(f"B2BUA BYE: call {call.call_id}, initiator={initiator.side}")

    # Release RTPEngine session
    await rtpengine.delete(call)
    log.info(f"RTPEngine delete done for call {call.call_id}")


@b2bua.on_cancel
async def on_cancel(call):
    # Caller hung up before the call was answered (Calling/Ringing). on_answer
    # never ran and no BYE will follow, so on_bye won't fire — but the offer in
    # on_invite already anchored media. on_failure only covers a B-leg *error*
    # response, not a caller CANCEL (that is torn down in Rust), so this hook is
    # the only place to release the RTPEngine session for an abandoned call.
    log.info(f"B2BUA CANCEL: call {call.call_id} (unanswered)")
    await rtpengine.delete(call)
    log.info(f"RTPEngine delete done for cancelled call {call.call_id}")
