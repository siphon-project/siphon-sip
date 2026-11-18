"""Recording-server controller for the SIPREC control-rail acceptance test.

siphon's `srs.app` offers every SIPREC session to this application before it
answers anything. The case is picked from the Request-URI user of the SRC's
INVITE (accept-stereo, metadata-update, reject, deadline, hangup), one SIPp
scenario per case. For each case the app drives the verbs, records every event
it receives, and prints one greppable line:

  CONTROL-VERDICT {"case": "<case>", "pass": true|false, "checks": [...]}

It reuses the session / framing / verdict machinery of control_app.py (the
persistent `inbound` mode: dial siphon's control listener, say hello, take the
channels siphon offers). A case that never runs prints no verdict, which the
runner treats as a failure.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys

import control_app
from control_app import Session, Verdict, heartbeat, note

SINK_URI = os.environ.get("SRS_SINK_URI", "ws://172.20.0.69:9001/tee")
SRC_IP = os.environ.get("SRS_SRC_IP", "172.20.0.253")
RECORDINGS = os.environ.get("SRS_RECORDINGS", "/var/lib/siphon/recordings")
STEREO_PATH = f"{RECORDINGS}/stereo"
END_TIMEOUT = float(os.environ.get("SRS_END_TIMEOUT", "30"))


def user_of(event: dict) -> str:
    ruri = str(((event.get("payload") or {}).get("invite") or {}).get("ruri") or "")
    match = re.match(r"sips?:([^@;>]+)@", ruri)
    return match.group(1) if match else ""


def ordered(session: Session, channel: str) -> list[dict]:
    """Events for this channel, in arrival order, without consuming them."""
    return [e for e in session._events if e.get("channel") == channel]  # noqa: SLF001


def names(events: list[dict]) -> list[str]:
    return [str(e.get("event")) for e in events]


def payload(event: dict) -> dict:
    return event.get("payload") or {}


async def wait_for(session: Session, channel: str, name: str, timeout: float = END_TIMEOUT):
    return await session.wait_event(
        lambda e: e.get("channel") == channel and e.get("event") == name, timeout
    )


async def reply_ok(verdict: Verdict, label: str, reply: dict) -> None:
    verdict.check(label, reply.get("status") == "ok", json.dumps(reply))


def check_offer(verdict: Verdict, event: dict, user: str) -> None:
    body = payload(event)
    recording = body.get("recording_session") or {}
    verdict.check("kind_is_siprec", body.get("kind") == "siprec", str(body.get("kind")))
    verdict.check(
        "ruri_as_sent",
        str((body.get("invite") or {}).get("ruri")).startswith(f"sip:{user}@"),
        str((body.get("invite") or {}).get("ruri")),
    )
    verdict.check("source_ip_is_the_src", body.get("source_ip") == SRC_IP, str(body.get("source_ip")))
    verdict.check("transport_udp", str(body.get("transport")).lower() == "udp", str(body.get("transport")))
    verdict.check(
        "two_participants",
        len(recording.get("participants") or []) == 2,
        json.dumps(recording.get("participants")),
    )
    verdict.check(
        "two_streams",
        len(recording.get("streams") or []) == 2,
        json.dumps(recording.get("streams")),
    )
    verdict.check(
        "two_participant_stream_entries",
        len(recording.get("participant_stream") or []) == 2,
        json.dumps(recording.get("participant_stream")),
    )
    verdict.check(
        "datamode_complete", recording.get("datamode") == "complete", str(recording.get("datamode"))
    )


async def finish(session: Session, channel: str, verdict: Verdict, reason: str):
    """Wait for StasisEnd and return the channel's events in arrival order."""
    try:
        end = await wait_for(session, channel, "StasisEnd")
    except TimeoutError as error:
        verdict.check("stasis_end_arrived", False, str(error))
        return ordered(session, channel)
    events = ordered(session, channel) + [end]
    verdict.check("stasis_end_arrived", True)
    verdict.check(
        f"stasis_end_reason_{reason}", payload(end).get("reason") == reason, json.dumps(payload(end))
    )
    return events


def check_end_order(verdict: Verdict, events: list[dict]) -> None:
    sequence = names(events)
    ended = sequence.index("RecordingSessionEnded") if "RecordingSessionEnded" in sequence else -1
    stasis = sequence.index("StasisEnd") if "StasisEnd" in sequence else -1
    verdict.check(
        "session_ended_before_stasis_end",
        ended >= 0 and stasis > ended,
        json.dumps(sequence),
    )
    verdict.check(
        "recording_finished_before_session_ended",
        all(i < ended for i, name in enumerate(sequence) if name == "RecordingFinished"),
        json.dumps(sequence),
    )


async def case_accept_stereo(app, session, event, verdict) -> None:
    channel = event["channel"]
    check_offer(verdict, event, "accept-stereo")
    target = {"channel": channel}
    await reply_ok(
        verdict,
        "accept_ok",
        await session.command("accept", {"channels": "stereo", "path": STEREO_PATH}, target=target),
    )
    tee = await session.command(
        "stream_start",
        {"mode": "tee", "ws_uri": SINK_URI, "sample_rate": 16000},
        target=target,
    )
    await reply_ok(verdict, "stream_start_tee_ok", tee)
    events = await finish(session, channel, verdict, "bye")
    finished = [e for e in events if e.get("event") == "RecordingFinished"]
    verdict.check("exactly_one_recording_finished", len(finished) == 1, json.dumps(names(events)))
    if finished:
        body = payload(finished[0])
        verdict.check("finished_is_stereo", body.get("channels") == "stereo", json.dumps(body))
        verdict.check(
            "finished_has_both_streams",
            sorted(body.get("stream_ids") or []) == ["s-0", "s-1"],
            json.dumps(body.get("stream_ids")),
        )
        verdict.check(
            "finished_has_both_participants",
            sorted(body.get("participant_ids") or []) == ["p-a", "p-b"],
            json.dumps(body.get("participant_ids")),
        )
        verdict.check(
            "finished_path_in_requested_dir",
            str(body.get("path")).startswith(STEREO_PATH + "/"),
            str(body.get("path")),
        )
    ended = [e for e in events if e.get("event") == "RecordingSessionEnded"]
    verdict.check("one_session_ended", len(ended) == 1, json.dumps(names(events)))
    if ended:
        verdict.check(
            "session_ended_lists_one_recording",
            len(payload(ended[0]).get("recordings") or []) == 1,
            json.dumps(payload(ended[0]).get("recordings")),
        )
    check_end_order(verdict, events)


async def case_metadata_update(app, session, event, verdict) -> None:
    channel = event["channel"]
    check_offer(verdict, event, "metadata-update")
    await reply_ok(
        verdict, "accept_ok", await session.command("accept", {}, target={"channel": channel})
    )
    try:
        updated = await wait_for(session, channel, "RecordingMetadataUpdated")
        body = payload(updated)
        merged = body.get("metadata") or {}
        verdict.check("update_datamode_partial", body.get("datamode") == "partial", json.dumps(body)[:300])
        verdict.check(
            "merged_snapshot_has_three_participants",
            len(merged.get("participants") or []) == 3,
            json.dumps(merged.get("participants")),
        )
    except TimeoutError as error:
        verdict.check("metadata_updated_event", False, str(error))
    events = await finish(session, channel, verdict, "bye")
    finished = [e for e in events if e.get("event") == "RecordingFinished"]
    verdict.check("two_recording_finished", len(finished) == 2, json.dumps(names(events)))
    verdict.check(
        "all_finished_mono",
        all(payload(e).get("channels") == "mono" for e in finished),
        json.dumps([payload(e).get("channels") for e in finished]),
    )
    check_end_order(verdict, events)


async def case_reject(app, session, event, verdict) -> None:
    channel = event["channel"]
    check_offer(verdict, event, "reject")
    await reply_ok(
        verdict,
        "reject_ok",
        await session.command(
            "reject", {"code": 404, "reason": "No Such Tenant"}, target={"channel": channel}
        ),
    )
    await finish(session, channel, verdict, "rejected")


async def case_deadline(app, session, event, verdict) -> None:
    channel = event["channel"]
    check_offer(verdict, event, "deadline")
    # Deliberately no decision: siphon answers 503 at the handoff deadline.
    await finish(session, channel, verdict, "rejected")


async def case_hangup(app, session, event, verdict) -> None:
    channel = event["channel"]
    check_offer(verdict, event, "hangup")
    target = {"channel": channel}
    await reply_ok(verdict, "accept_ok", await session.command("accept", {}, target=target))
    await asyncio.sleep(2)
    await reply_ok(
        verdict, "hangup_ok", await session.command("hangup", {}, target=target)
    )
    events = await finish(session, channel, verdict, "hangup")
    verdict.check(
        "session_ended_present",
        "RecordingSessionEnded" in names(events),
        json.dumps(names(events)),
    )
    check_end_order(verdict, events)


CASES = {
    "accept-stereo": case_accept_stereo,
    "metadata-update": case_metadata_update,
    "reject": case_reject,
    "deadline": case_deadline,
    "hangup": case_hangup,
}


async def run() -> None:
    app = control_app.App()

    async def on_start(session: Session, event: dict) -> None:
        user = user_of(event)
        handler = CASES.get(user)
        channel = event.get("channel")
        note(f"StasisStart user={user!r} channel={channel}")
        verdict = Verdict(user or "unknown")
        if handler is None:
            verdict.check("known_case", False, f"no case for R-URI user {user!r}")
            verdict.emit()
            return
        try:
            await handler(app, session, event, verdict)
        except Exception as error:  # noqa: BLE001 - the verdict is the report
            verdict.check("case_ran_to_completion", False, repr(error))
        finally:
            verdict.emit()

    app.on_stasis_start = on_start  # type: ignore[method-assign]
    await app.connect_inbound("in-1")
    await heartbeat(lambda: any(not s.closed for s in app.sessions))


if __name__ == "__main__":
    sys.exit(asyncio.run(run()) or 0)
