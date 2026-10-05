#!/usr/bin/env python3
"""Control application driving the `control-transfer` acceptance cases.

One persistent connection, one case per call. The routing script
(sipp/control/transfer_routes.py) hands each INVITE over un-answered with the
dialled user as `vars.case`, and this application runs that case's verbs. The
SIPp scenarios (sipp/control_transfer_*.xml) assert what each party saw on the
wire; this asserts what only the rail shows, the replies and the events:

  cancel-dial         — `cancel_dial` on a bridging dial: the reply, a
                        `DialBranchFailed` per phone ahead of `DialFailed` 487
                        with the cancel's reason as its cause, the second
                        cancel and a `route` mid-ring both refused, and a
                        second dial ringing for the same caller.
  refer-callee        — a REFER from the party the call was connected to:
                        `TransferRequested` names leg `b` and the Call-ID of
                        that leg's own dialog; `reject_refer`, then
                        `accept_refer` and its `PeerReplaced`.
  refer-controller    — `accept_refer {mode: "controller"}` three times over:
                        reported 200, reported 486, and left to its deadline.
  replace-aor         — `replace_peer {target: {aor}}` on an AoR with two
                        contacts: one `PeerReplaced`, no `ReplaceFailed`.
  replace-aor-refused — both contacts refuse: one `ReplaceFailed` with the
                        call kept, and both parties still on it afterwards.
  media               — `hold` refused on a call the engine only relays, and
                        `play`'s `repeat` argument.

Connection handling, frame recording and the verdict line are
sipp/control/control_app.py's: every frame is a `CONTROL-FRAME` line and every
case ends in one `CONTROL-VERDICT {"case": …, "pass": …}` line, which the
runner (sipp/control/run_transfer_case.sh) requires. A value a SIPp party has
to agree with (a Call-ID only the wire and the rail both see) is printed as a
`TRANSFER-FACT` line for the runner to compare.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from control_app import App, Session, Verdict, heartbeat, is_end, note

# The parties. Each is a SIPp scenario on the compose network.
PHONE_URI = os.environ.get("TRANSFER_PHONE", "sip:phone@172.20.0.243:5060")
SECOND_PHONE_URI = os.environ.get("TRANSFER_SECOND_PHONE", "sip:phone@172.20.0.244:5060")
# What the referring phone names in its Refer-To.
REFER_TARGET_HOST = os.environ.get("TRANSFER_REFER_TARGET_HOST", "172.20.0.245")
# Registered from two addresses before the replace cases run.
AOR = os.environ.get("TRANSFER_AOR", "sip:3001@transfer.test")
MEDIA_PROFILE = os.environ.get("TRANSFER_MEDIA_PROFILE", "transfer_relay")
TONE = os.environ.get("TRANSFER_TONE", "ringback_eu")

CANCEL_REASON = "operator_gave_up"
REJECT_CODE = 480
REJECT_REASON = "Transfer Refused"
CONTROLLER_TIMEOUT_SECS = 30
CONTROLLER_SHORT_TIMEOUT_SECS = 2

EVENT_TIMEOUT = float(os.environ.get("TRANSFER_EVENT_TIMEOUT", "30"))


def fact(case: str, name: str, value) -> None:
    """One value the runner compares with what a SIPp party logged."""
    print(
        "TRANSFER-FACT " + json.dumps({"case": case, "name": name, "value": value}),
        flush=True,
    )


def on_channel(channel: str, *names: str):
    """A predicate: one of `names`, on `channel`."""
    return lambda event: event.get("channel") == channel and event.get("event") in names


def ordered_until(channel: str, names: tuple, last: str):
    """A predicate that is true on `last`, and the list it fills on the way.

    The backlog is scanned in arrival order and the scan stops at the first
    match, so the list ends up holding the `names` events that arrived no later
    than `last`, in the order they arrived. Only `last` is consumed.
    """
    seen: list[dict] = []

    def predicate(event: dict) -> bool:
        if event.get("channel") != channel or event.get("event") not in names:
            return False
        if all(event is not earlier for earlier in seen):
            seen.append(event)
        return event.get("event") == last

    return seen, predicate


def refusal(reply: dict) -> tuple:
    """A refusal's `(code, details.reason, details)`."""
    error = reply.get("error") or {}
    details = error.get("details") or {}
    return error.get("code"), details.get("reason"), details


def check_refused(verdict: Verdict, name: str, reply: dict, code: str, reason: str) -> None:
    actual_code, actual_reason, _ = refusal(reply)
    verdict.check(
        name,
        reply.get("status") == "error" and actual_code == code and actual_reason == reason,
        json.dumps(reply),
    )


async def connect_phone(
    session: Session,
    channel: str,
    verdict: Verdict,
    profile: str | None = None,
) -> dict:
    """Ring the phone for the waiting caller and wait for it to answer.

    Returns the `DialBranch` payload: the leg's own id and the Call-ID of the
    INVITE the phone was sent.
    """
    args: dict = {"targets": [PHONE_URI], "timeout": 20}
    if profile is not None:
        args["profile"] = profile
    reply = await session.command("dial", args, target={"channel": channel})
    verdict.check(
        "dial_accepted",
        reply.get("status") == "ok" and (reply.get("result") or {}).get("state") == "dialing",
        json.dumps(reply),
    )
    branch = await session.wait_event(on_channel(channel, "DialBranch"), EVENT_TIMEOUT)
    answered = await session.wait_event(
        on_channel(channel, "DialAnswered", "DialFailed"), EVENT_TIMEOUT
    )
    verdict.check(
        "the_phone_answered",
        answered.get("event") == "DialAnswered",
        json.dumps(answered.get("payload")),
    )
    return branch.get("payload") or {}


async def case_cancel_dial(app: App, session: Session, event: dict, verdict: Verdict) -> None:
    """Give up on a ringing bridge dial, and keep the caller."""
    channel = event.get("channel") or ""
    targets = [{"uri": PHONE_URI}, {"uri": SECOND_PHONE_URI}]

    answered = await session.command(
        "answer",
        {"code": 200, "reason": "OK", "anchor": True, "profile": MEDIA_PROFILE},
        target={"channel": channel},
    )
    verdict.check("caller_answered_anchored", answered.get("status") == "ok", json.dumps(answered))

    async def ring() -> list:
        """Dial both phones and wait until one of them alerts."""
        dialled = await session.command(
            "dial",
            {"targets": targets, "on_answer": "bridge", "timeout": 30},
            target={"channel": channel},
        )
        result = dialled.get("result") or {}
        verdict.check(
            "bridge_dial_accepted",
            dialled.get("status") == "ok"
            and result.get("state") == "dialing"
            and len(result.get("branches") or []) == 2,
            json.dumps(dialled),
        )
        branches = [
            (await session.wait_event(on_channel(channel, "DialBranch"), EVENT_TIMEOUT)).get(
                "payload"
            )
            or {}
            for _ in targets
        ]
        # The ringback starts on the first 180: a phone is alerting.
        ringback = await session.wait_event(on_channel(channel, "PlayStarted"), EVENT_TIMEOUT)
        verdict.check(
            "a_phone_is_alerting",
            (ringback.get("payload") or {}).get("origin") == "ringback",
            json.dumps(ringback.get("payload")),
        )
        return branches

    async def cancelled(branches: list, reply: dict, cause: str, label: str) -> None:
        """The reply and the events of one cancelled dial."""
        result = reply.get("result") or {}
        verdict.check(
            f"{label}_reply_is_cancelled_bridge",
            reply.get("status") == "ok"
            and result.get("state") == "cancelled"
            and result.get("on_answer") == "bridge",
            json.dumps(reply),
        )
        seen, predicate = ordered_until(channel, ("DialBranchFailed", "DialFailed"), "DialFailed")
        failed = (await session.wait_event(predicate, EVENT_TIMEOUT)).get("payload") or {}
        before = [entry.get("payload") or {} for entry in seen[:-1]]
        dialled_legs = sorted(branch.get("leg_id") for branch in branches)
        verdict.check(
            f"{label}_each_phone_reported_before_the_dial_failed",
            sorted(entry.get("leg_id") for entry in before) == dialled_legs
            and all(
                entry.get("cause") == "cancelled" and entry.get("code") == 487 for entry in before
            ),
            json.dumps(before),
        )
        verdict.check(
            f"{label}_dial_failed_487_with_the_cause",
            failed.get("code") == 487
            and failed.get("cause") == cause
            and failed.get("timed_out") is False
            and sorted(entry.get("leg_id") for entry in failed.get("branches") or [])
            == dialled_legs,
            json.dumps(failed),
        )
        # The predicate left the branch reports in the backlog. Whatever is
        # there now is this dial's: two, one per phone.
        reported = session.take_events(on_channel(channel, "DialBranchFailed"))
        verdict.check(
            f"{label}_each_phone_reported_once",
            sorted((entry.get("payload") or {}).get("leg_id") for entry in reported)
            == dialled_legs,
            json.dumps(reported),
        )

    first = await ring()

    # `route` releases the channel the dial reports on, so it waits its turn.
    check_refused(
        verdict,
        "route_refused_while_the_dial_rings",
        await session.command(
            "route",
            {"targets": ["sip:nobody@198.51.100.200:5060"]},
            target={"channel": channel},
        ),
        "invalid_state",
        "dial_in_progress",
    )

    await cancelled(
        first,
        await session.command(
            "cancel_dial", {"reason": CANCEL_REASON}, target={"channel": channel}
        ),
        CANCEL_REASON,
        "first",
    )

    check_refused(
        verdict,
        "second_cancel_refused",
        await session.command("cancel_dial", {}, target={"channel": channel}),
        "invalid_state",
        "no_dial_in_progress",
    )

    # The caller is as the dial found it: dial for it again, and that one rings.
    second = await ring()
    verdict.check(
        "the_second_dial_is_new_legs",
        not {branch.get("leg_sip_call_id") for branch in first}
        & {branch.get("leg_sip_call_id") for branch in second},
        json.dumps({"first": first, "second": second}),
    )
    # No reason this time: the cause falls back to `cancelled`.
    await cancelled(
        second,
        await session.command("cancel_dial", {}, target={"channel": channel}),
        "cancelled",
        "second",
    )

    # The caller ends its quiet window with a digit, in the dialog nothing above
    # was allowed to touch.
    await session.wait_event(on_channel(channel, "ChannelDtmfReceived"), EVENT_TIMEOUT)
    ended = session.take_events(on_channel(channel, "StasisEnd", "BridgeFailed", "DialAnswered"))
    verdict.check("the_caller_is_still_up", not ended, json.dumps(ended))

    hangup = await session.command("hangup", {"reason": "done"}, target={"channel": channel})
    verdict.check("hangup_accepted", hangup.get("status") == "ok", json.dumps(hangup))
    await session.wait_event(is_end(channel), EVENT_TIMEOUT)
    # Two dials, two outcomes, and each was consumed above.
    stray = session.take_events(on_channel(channel, "DialBranchFailed", "DialFailed"))
    verdict.check("no_dial_reported_twice", not stray, json.dumps(stray))


async def transfer_requested(
    session: Session, channel: str, verdict: Verdict, branch: dict, label: str
) -> dict:
    """Wait for a REFER from the phone and check how it is described."""
    request = await session.wait_event(on_channel(channel, "TransferRequested"), EVENT_TIMEOUT)
    payload = request.get("payload") or {}
    verdict.check(
        f"{label}_refer_names_the_callee_leg_and_its_dialog",
        payload.get("referrer_leg") == "b"
        and bool(payload.get("referrer_sip_call_id"))
        and payload.get("referrer_sip_call_id") == branch.get("leg_sip_call_id")
        and payload.get("referrer_sip_call_id") != request.get("sip_call_id")
        and REFER_TARGET_HOST in str(payload.get("refer_to")),
        json.dumps({"event": payload, "branch": branch, "channel_call": request.get("sip_call_id")}),
    )
    return payload


async def case_refer_callee(app: App, session: Session, event: dict, verdict: Verdict) -> None:
    """The callee REFERs twice: declined, then carried out by siphon."""
    channel = event.get("channel") or ""
    branch = await connect_phone(session, channel, verdict)

    first = await transfer_requested(session, channel, verdict, branch, "first")
    fact("refer-callee", "referrer_sip_call_id", first.get("referrer_sip_call_id"))
    rejected = await session.command(
        "reject_refer",
        {"code": REJECT_CODE, "reason": REJECT_REASON},
        target={"channel": channel},
    )
    result = rejected.get("result") or {}
    verdict.check(
        "reject_refer_accepted",
        rejected.get("status") == "ok"
        and result.get("transfer") == "rejected"
        and result.get("code") == REJECT_CODE,
        json.dumps(rejected),
    )

    await transfer_requested(session, channel, verdict, branch, "second")
    accepted = await session.command(
        "accept_refer", {"mode": "terminate"}, target={"channel": channel}
    )
    verdict.check(
        "accept_refer_accepted",
        accepted.get("status") == "ok"
        and (accepted.get("result") or {}).get("transfer") == "accepted",
        json.dumps(accepted),
    )

    outcome = await session.wait_event(
        on_channel(channel, "PeerReplaced", "ReplaceFailed"), EVENT_TIMEOUT
    )
    payload = outcome.get("payload") or {}
    verdict.check(
        "peer_replaced_by_the_refer",
        outcome.get("event") == "PeerReplaced"
        and payload.get("origin") == "refer"
        and payload.get("replaced_leg_released") is True
        and bool(payload.get("target_sip_call_id")),
        json.dumps(outcome),
    )
    fact("refer-callee", "target_sip_call_id", payload.get("target_sip_call_id"))

    # The transfer target hangs up, which ends the caller it was joined to.
    await session.wait_event(is_end(channel), EVENT_TIMEOUT)
    extra = session.take_events(on_channel(channel, "PeerReplaced", "ReplaceFailed"))
    verdict.check("one_outcome_for_the_transfer", not extra, json.dumps(extra))


async def case_refer_controller(app: App, session: Session, event: dict, verdict: Verdict) -> None:
    """Three transfers the application carries out and reports itself."""
    channel = event.get("channel") or ""
    branch = await connect_phone(session, channel, verdict)

    async def accept(label: str, timeout: int) -> None:
        await transfer_requested(session, channel, verdict, branch, label)
        accepted = await session.command(
            "accept_refer",
            {"mode": "controller", "timeout": timeout},
            target={"channel": channel},
        )
        result = accepted.get("result") or {}
        verdict.check(
            f"{label}_accepted_for_the_controller",
            accepted.get("status") == "ok"
            and result.get("transfer") == "accepted"
            and result.get("mode") == "controller"
            and result.get("timeout") == timeout,
            json.dumps(accepted),
        )

    async def report(label: str, args: dict) -> None:
        completed = await session.command("complete_refer", args, target={"channel": channel})
        result = completed.get("result") or {}
        verdict.check(
            f"{label}_report_accepted",
            completed.get("status") == "ok"
            and result.get("transfer") == "completed"
            and result.get("code") == args["code"],
            json.dumps(completed),
        )

    async def report_refused(label: str) -> None:
        check_refused(
            verdict,
            f"{label}_refused",
            await session.command("complete_refer", {"code": 200}, target={"channel": channel}),
            "invalid_state",
            "no_transfer_pending",
        )

    # Reported as carried out. The pause is the time a controller spends moving
    # the parties, and the window in which an INVITE to the Refer-To target
    # would be on the wire had siphon dialled one.
    await accept("first", CONTROLLER_TIMEOUT_SECS)
    await asyncio.sleep(1.0)
    await report("first", {"code": 200})
    await report_refused("a_second_report_of_the_first")

    # Reported as failed, with the reason phrase the sipfrag is to carry.
    await accept("second", CONTROLLER_TIMEOUT_SECS)
    await asyncio.sleep(1.0)
    await report("second", {"code": 486, "reason": "Busy Here"})
    await report_refused("a_second_report_of_the_second")

    # Not reported at all: siphon ends the subscription at the deadline, after
    # which there is nothing left to report on.
    await accept("third", CONTROLLER_SHORT_TIMEOUT_SECS)
    await asyncio.sleep(CONTROLLER_SHORT_TIMEOUT_SECS + 2.0)
    await report_refused("a_report_after_the_deadline")

    # The phone hangs up once its third subscription has ended.
    await session.wait_event(is_end(channel), EVENT_TIMEOUT)
    moved = session.take_events(on_channel(channel, "PeerReplaced", "ReplaceFailed"))
    verdict.check("siphon_moved_no_party", not moved, json.dumps(moved))


async def replace_with_the_aor(session: Session, channel: str, verdict: Verdict) -> None:
    replaced = await session.command(
        "replace_peer", {"target": {"aor": AOR}, "timeout": 20}, target={"channel": channel}
    )
    verdict.check(
        "replace_peer_reply_is_the_local_action",
        replaced.get("status") == "ok"
        and (replaced.get("result") or {}).get("replacement") == "dialing",
        json.dumps(replaced),
    )


async def case_replace_aor(app: App, session: Session, event: dict, verdict: Verdict) -> None:
    """Replace the callee with an AoR that has two contacts; one answers."""
    channel = event.get("channel") or ""
    await connect_phone(session, channel, verdict)
    await replace_with_the_aor(session, channel, verdict)

    outcome = await session.wait_event(
        on_channel(channel, "PeerReplaced", "ReplaceFailed"), EVENT_TIMEOUT
    )
    payload = outcome.get("payload") or {}
    verdict.check(
        "peer_replaced",
        outcome.get("event") == "PeerReplaced"
        and payload.get("origin") == "siphon"
        and payload.get("replaced_leg_released") is True
        and bool(payload.get("target_sip_call_id")),
        json.dumps(outcome),
    )
    fact("replace-aor", "target_sip_call_id", payload.get("target_sip_call_id"))

    # The contact that answered hangs up, which ends the caller it now talks to.
    # By then the losing contact's CANCEL, 487 and ACK are long done, so a
    # second outcome for it would have arrived.
    await session.wait_event(is_end(channel), EVENT_TIMEOUT)
    extra = session.take_events(on_channel(channel, "PeerReplaced", "ReplaceFailed"))
    verdict.check("exactly_one_peer_replaced", not extra, json.dumps(extra))


async def case_replace_aor_refused(
    app: App, session: Session, event: dict, verdict: Verdict
) -> None:
    """Both contacts of the AoR refuse; the call stays as it was."""
    channel = event.get("channel") or ""
    await connect_phone(session, channel, verdict)
    await replace_with_the_aor(session, channel, verdict)

    # One contact answers 486 at once and the other 480 a second later. The
    # failure is reported once neither is left, with the better of the two
    # (RFC 3261 §16.7 step 6), which here is the one that came first.
    outcome = await session.wait_event(
        on_channel(channel, "PeerReplaced", "ReplaceFailed"), EVENT_TIMEOUT
    )
    payload = outcome.get("payload") or {}
    verdict.check(
        "replace_failed_with_the_call_kept",
        outcome.get("event") == "ReplaceFailed"
        and payload.get("status") == 486
        and payload.get("call_kept") is True
        and payload.get("origin") == "siphon",
        json.dumps(outcome),
    )

    # The caller sends a digit through to the phone it was connected to, after
    # both refusals: both of the original dialogs carried it.
    await session.wait_event(on_channel(channel, "ChannelDtmfReceived"), EVENT_TIMEOUT)
    ended = session.take_events(is_end(channel))
    verdict.check("the_call_is_still_up_after_the_refusals", not ended, json.dumps(ended))

    await session.wait_event(is_end(channel), EVENT_TIMEOUT)
    extra = session.take_events(on_channel(channel, "PeerReplaced", "ReplaceFailed"))
    verdict.check("exactly_one_replace_failed", not extra, json.dumps(extra))


async def case_media(app: App, session: Session, event: dict, verdict: Verdict) -> None:
    """`hold` on a relayed call, and `play`'s `repeat`."""
    channel = event.get("channel") or ""
    await connect_phone(session, channel, verdict, profile=MEDIA_PROFILE)

    # Two parties on the same codec: the engine forwards the packets and decodes
    # nothing, so there is no audio for a hold to silence.
    held = await session.command("hold", {}, target={"channel": channel})
    code, reason, details = refusal(held)
    verdict.check(
        "hold_refused_on_a_relayed_call",
        held.get("status") == "error"
        and code == "invalid_state"
        and reason == "media_not_processed"
        and details.get("verb") == "hold",
        json.dumps(held),
    )

    forever = await session.command(
        "play", {"tone": TONE, "repeat": "forever"}, target={"channel": channel}
    )
    code, reason, details = refusal(forever)
    verdict.check(
        "play_refuses_a_repeat_it_cannot_use",
        forever.get("status") == "error"
        and code == "bad_request"
        and details.get("argument") == "repeat",
        json.dumps(forever),
    )

    endless = await session.command(
        "play", {"tone": TONE, "repeat": "inf"}, target={"channel": channel}
    )
    result = endless.get("result") or {}
    verdict.check(
        "an_endless_play_is_accepted",
        endless.get("status") == "ok"
        and result.get("state") == "playing"
        and "duration_ms" not in result,
        json.dumps(endless),
    )
    started = await session.wait_event(on_channel(channel, "PlayStarted"), EVENT_TIMEOUT)
    started_payload = started.get("payload") or {}
    verdict.check(
        "play_started_for_the_endless_play",
        started_payload.get("source") == "tone"
        and started_payload.get("play_id") == result.get("play_id"),
        json.dumps({"reply": result, "event": started_payload}),
    )
    extra = session.take_events(on_channel(channel, "PlayStarted"))
    verdict.check("the_refused_play_started_nothing", not extra, json.dumps(extra))

    # Long enough that a play which was going to end by itself would have.
    await asyncio.sleep(1.5)
    early = session.take_events(on_channel(channel, "PlayFinished"))
    verdict.check("the_endless_play_is_still_playing", not early, json.dumps(early))

    stopped = await session.command("stop", {}, target={"channel": channel})
    verdict.check(
        "stop_accepted",
        stopped.get("status") == "ok" and (stopped.get("result") or {}).get("state") == "stopped",
        json.dumps(stopped),
    )
    finished = await session.wait_event(on_channel(channel, "PlayFinished"), EVENT_TIMEOUT)
    finished_payload = finished.get("payload") or {}
    verdict.check(
        "stop_ended_the_endless_play",
        finished_payload.get("play_id") == result.get("play_id")
        and finished_payload.get("completed") is False,
        json.dumps(finished_payload),
    )

    hangup = await session.command("hangup", {"reason": "done"}, target={"channel": channel})
    verdict.check("hangup_accepted", hangup.get("status") == "ok", json.dumps(hangup))
    await session.wait_event(is_end(channel), EVENT_TIMEOUT)


CASES = {
    "cancel-dial": case_cancel_dial,
    "refer-callee": case_refer_callee,
    "refer-controller": case_refer_controller,
    "replace-aor": case_replace_aor,
    "replace-aor-refused": case_replace_aor_refused,
    "media": case_media,
}


class TransferApp(App):
    """control_app.py's application, running this module's cases."""

    async def on_stasis_start(self, session: Session, event: dict) -> None:
        case = ((event.get("payload") or {}).get("vars") or {}).get("case")
        handler = CASES.get(case)
        if handler is None:
            # A channel siphon minted for a leg of a call already being driven
            # carries no case of its own.
            note(f"{session.label}: StasisStart without a case of this harness: {case!r}")
            return
        note(f"{session.label}: StasisStart case={case} channel={event.get('channel')}")
        verdict = Verdict(case)
        try:
            await handler(self, session, event, verdict)
        except Exception as error:  # noqa: BLE001 — the verdict is the report
            verdict.check("case_ran_to_completion", False, repr(error))
        finally:
            verdict.emit()


async def main() -> int:
    app = TransferApp()
    session = await app.connect_inbound("in-1")
    await heartbeat(lambda: not session.closed)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
