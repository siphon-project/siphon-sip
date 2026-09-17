"""Tests for the typed CDR contract in ``siphon_sdk.cdr``.

The record shape lives in the Rust struct (``src/cdr/mod.rs``); this module is a
mirror of it, so the tests here are about the two things a mirror can get wrong:
losing the flattened custom fields, and drifting from the struct. The last test
is the drift guard.
"""

from __future__ import annotations

import dataclasses
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from siphon_sdk.cdr import CallDetailRecord, MediaLeg, parse_timestamp


def call_record() -> dict:
    """An answered call as the sinks write it (the sample in src/cdr/mod.rs)."""
    return {
        "timestamp": "2026-03-06T14:23:01.042Z",
        "call_id": "a84b4c76e66710@192.0.2.100",
        "from_uri": "sip:alice@example.com",
        "to_uri": "sip:bob@example.com",
        "ruri": "sip:bob@198.51.100.1:5060",
        "method": "INVITE",
        "response_code": 200,
        "timestamp_start": "2026-03-06T14:23:01.042Z",
        "timestamp_answer": "2026-03-06T14:23:03.185Z",
        "timestamp_end": "2026-03-06T14:25:47.920Z",
        "duration_secs": 164.735,
        "source_ip": "192.0.2.100",
        "destination_ip": "198.51.100.1",
        "transport": "udp",
        "user_agent": "Test UA/1.0",
        "auth_user": "alice",
        "disconnect_initiator": "caller",
        "sip_reason": None,
    }


def media_record() -> dict:
    """A MEDIA record: two legs, the far one measured, the near one relay-only."""
    return {
        "timestamp": "2026-03-06T14:25:48.003Z",
        "call_id": "a84b4c76e66710@192.0.2.100",
        "from_uri": "",
        "to_uri": "",
        "ruri": "",
        "method": "MEDIA",
        "response_code": 0,
        "timestamp_start": None,
        "timestamp_answer": None,
        "timestamp_end": None,
        "duration_secs": 164.0,
        "source_ip": "",
        "destination_ip": "",
        "transport": "",
        "user_agent": None,
        "auth_user": None,
        "disconnect_initiator": None,
        "sip_reason": None,
        "media_reason": "delete",
        "media_duration_ms": "164000",
        "near_tag": "9fd3a1",
        "near_codec": "PCMU",
        "near_packets_in": "8200",
        "near_bytes_in": "1640000",
        "near_packets_out": "8198",
        "near_bytes_out": "1639600",
        "near_packets_dropped": "2",
        "far_tag": "77c0be",
        "far_codec": "AMR-WB",
        "far_packets_in": "8199",
        "far_bytes_in": "1230000",
        "far_packets_out": "8200",
        "far_bytes_out": "1231000",
        "far_packets_dropped": "0",
        "far_ssrc": "305419896",
        "far_packets_lost": "13",
        "far_loss_percent": "0.16",
        "far_jitter_ms": "4.5",
        "far_rtt_ms": "22.75",
        "far_mos_average": "4.12",
        "far_mos_min": "3.80",
        "far_mos_max": "4.40",
        "far_mos_basis": "full",
    }


# ---------------------------------------------------------------------------
# Round-trips
# ---------------------------------------------------------------------------


def test_call_record_roundtrips():
    payload = call_record()
    record = CallDetailRecord.from_dict(payload)

    assert record.call_id == "a84b4c76e66710@192.0.2.100"
    assert record.response_code == 200
    assert record.duration_secs == pytest.approx(164.735)
    assert record.answered is True
    assert record.is_media is False
    assert record.is_register is False
    assert record.extra == {}
    assert record.to_dict() == payload


def test_media_record_roundtrips():
    payload = media_record()
    assert CallDetailRecord.from_dict(payload).to_dict() == payload


def test_from_json_matches_from_dict():
    payload = call_record()
    assert CallDetailRecord.from_json(json.dumps(payload)) == CallDetailRecord.from_dict(
        payload
    )
    assert json.loads(CallDetailRecord.from_dict(payload).to_json()) == payload


def test_missing_fields_read_as_empty_rather_than_raising():
    # The HTTP sink has no retry: a collector that raises loses the record.
    record = CallDetailRecord.from_dict({"call_id": "cid-1"})
    assert record.call_id == "cid-1"
    assert record.method == ""
    assert record.response_code == 0
    assert record.duration_secs == 0.0
    assert record.answered is False


# ---------------------------------------------------------------------------
# The flattened custom fields — the reason the type exists
# ---------------------------------------------------------------------------


def test_unknown_top_level_keys_land_in_extra():
    payload = call_record()
    payload["billing_id"] = "B-12345"
    payload["carrier_zone"] = "zone-1"

    record = CallDetailRecord.from_dict(payload)

    assert record.extra == {"billing_id": "B-12345", "carrier_zone": "zone-1"}
    # And they go back out flattened, not nested under "extra".
    assert record.to_dict() == payload
    assert "extra" not in record.to_dict()


def test_register_record_carries_the_change_in_extra():
    payload = call_record()
    payload["method"] = "REGISTER"
    payload["reg_event"] = "deregistered"

    record = CallDetailRecord.from_dict(payload)

    assert record.is_register is True
    assert record.reg_event == "deregistered"


def test_rf_fields_are_omitted_when_unset_and_present_when_set():
    payload = call_record()
    assert "rf_session_id" not in CallDetailRecord.from_dict(payload).to_dict()
    assert "rf_result_code" not in CallDetailRecord.from_dict(payload).to_dict()

    payload["rf_session_id"] = "cdf.example.com;1234;5678"
    payload["rf_result_code"] = 2001
    record = CallDetailRecord.from_dict(payload)

    assert record.rf_session_id == "cdf.example.com;1234;5678"
    assert record.rf_result_code == 2001
    # Not mistaken for a custom field.
    assert record.extra == {}
    assert record.to_dict() == payload


# ---------------------------------------------------------------------------
# Media legs
# ---------------------------------------------------------------------------


def test_media_legs_parse_into_numbers():
    record = CallDetailRecord.from_dict(media_record())

    assert record.is_media is True
    assert record.media_reason == "delete"
    assert record.media_duration_ms == 164000

    near, far = record.media_legs
    assert (near.role, near.tag, near.codec) == ("near", "9fd3a1", "PCMU")
    assert near.packets_in == 8200
    assert near.bytes_out == 1639600
    assert near.packets_dropped == 2

    assert far.role == "far"
    assert far.ssrc == 305419896
    assert far.packets_lost == 13
    assert far.loss_percent == pytest.approx(0.16)
    assert far.jitter_ms == pytest.approx(4.5)
    assert far.rtt_ms == pytest.approx(22.75)
    assert far.mos_average == pytest.approx(4.12)
    assert far.mos_basis == "full"


def test_unmeasured_leg_fields_stay_none():
    # A plain in-kernel relay leg has counters but no quality figures. They must
    # not read back as 0.0 — "not measured" is not "measured as bad".
    near = CallDetailRecord.from_dict(media_record()).media_legs[0]
    assert near.mos_average is None
    assert near.mos_min is None
    assert near.loss_percent is None
    assert near.jitter_ms is None
    assert near.packets_lost is None
    assert near.ssrc is None
    assert near.text_packets is None


def test_third_leg_uses_the_leg_n_prefix():
    payload = media_record()
    payload.update(
        {
            "leg2_tag": "confmix",
            "leg2_packets_in": "17",
            "leg2_bytes_in": "3400",
            "leg2_packets_out": "0",
            "leg2_bytes_out": "0",
            "leg2_packets_dropped": "0",
        }
    )
    legs = CallDetailRecord.from_dict(payload).media_legs

    assert [leg.role for leg in legs] == ["near", "far", "leg2"]
    assert legs[2].tag == "confmix"
    assert legs[2].packets_in == 17


def test_text_stream_counters_are_parsed():
    payload = media_record()
    payload.update(
        {
            "far_text_packets": "42",
            "far_text_characters": "310",
            "far_text_missing_markers": "1",
            "far_text_recovered_from_redundancy": "3",
        }
    )
    far = CallDetailRecord.from_dict(payload).media_legs[1]

    assert far.text_packets == 42
    assert far.text_characters == 310
    assert far.text_missing_markers == 1
    assert far.text_recovered_from_redundancy == 3


def test_media_legs_empty_on_a_call_record():
    assert CallDetailRecord.from_dict(call_record()).media_legs == []


def test_media_record_with_only_a_near_leg():
    # A call that never reached a B-leg (404/487) gets a MEDIA record with the
    # offerer's leg alone — the parse must stop there, not invent a far leg.
    payload = {
        "timestamp": "2026-03-06T14:23:01.042Z",
        "call_id": "cid-1",
        "method": "MEDIA",
        "response_code": 0,
        "duration_secs": 1.0,
        "media_reason": "delete",
        "media_duration_ms": "1000",
        "near_tag": "8f21ca",
        "near_codec": "G729",
        "near_packets_in": "0",
        "near_bytes_in": "0",
        "near_packets_out": "0",
        "near_bytes_out": "0",
        "near_packets_dropped": "0",
    }
    legs = CallDetailRecord.from_dict(payload).media_legs

    assert len(legs) == 1
    assert legs[0].role == "near"
    assert legs[0].codec == "G729"
    assert legs[0].packets_in == 0


def test_one_way_audio_is_visible_in_the_leg_counters():
    # The signature worth alerting on: one leg receives nothing while the other
    # carries a full call, so nothing is forwarded back out to it.
    payload = media_record()
    payload.update(
        {
            "near_packets_in": "0",
            "near_bytes_in": "0",
            "near_packets_out": "1601",
            "far_packets_in": "1601",
            "far_packets_out": "0",
            "far_bytes_out": "0",
        }
    )
    near, far = CallDetailRecord.from_dict(payload).media_legs

    assert near.packets_in == 0 and far.packets_out == 0
    assert far.packets_in == 1601


# ---------------------------------------------------------------------------
# LCR attempts and teardown cause
# ---------------------------------------------------------------------------


def test_lcr_attempts_decode_from_the_json_string_extra():
    payload = call_record()
    payload["lcr_attempts"] = (
        '[{"carrier_id":"carrier-a","status":500,"elapsed_ms":1359,"dialed":true},'
        '{"carrier_id":"carrier-b","status":0,"elapsed_ms":0,"dialed":false}]'
    )
    record = CallDetailRecord.from_dict(payload)

    first, second = record.lcr_attempts
    assert (first.carrier_id, first.status, first.elapsed_ms) == ("carrier-a", 500, 1359)
    assert first.dialed is True
    assert second.dialed is False
    # Still a string in extra, and still round-trips.
    assert record.to_dict() == payload


def test_lcr_attempts_absent_or_malformed_reads_empty():
    assert CallDetailRecord.from_dict(call_record()).lcr_attempts == []

    payload = call_record()
    payload["lcr_attempts"] = "not json"
    assert CallDetailRecord.from_dict(payload).lcr_attempts == []


def test_reason_header_is_parsed():
    payload = call_record()
    payload["sip_reason"] = 'Q.850;cause=102;text="Recovery on timer expiry"'
    record = CallDetailRecord.from_dict(payload)

    assert record.reason_protocol == "Q.850"
    assert record.reason_cause == 102
    assert record.reason_text == "Recovery on timer expiry"


def test_reason_header_without_text():
    payload = call_record()
    payload["sip_reason"] = "Q.850;cause=16"
    record = CallDetailRecord.from_dict(payload)

    assert record.reason_cause == 16
    assert record.reason_text is None


def test_reason_accessors_are_none_without_a_reason_header():
    record = CallDetailRecord.from_dict(call_record())
    assert record.sip_reason is None
    assert record.reason_protocol is None
    assert record.reason_cause is None
    assert record.reason_text is None


def test_unanswered_call_record():
    # A CANCELled INVITE: a final code, an end, no answer and no duration.
    payload = call_record()
    payload.update(
        {
            "response_code": 487,
            "timestamp_answer": None,
            "duration_secs": 0.0,
            "disconnect_initiator": "caller",
        }
    )
    record = CallDetailRecord.from_dict(payload)

    assert record.answered is False
    assert record.answered_at is None
    assert record.duration_secs == 0.0
    assert record.ended_at is not None


def test_unparseable_media_value_reads_as_none_not_a_crash():
    payload = media_record()
    payload["far_mos_average"] = "n/a"
    assert CallDetailRecord.from_dict(payload).media_legs[1].mos_average is None


def test_media_leg_from_extra_tolerates_a_bare_tag():
    leg = MediaLeg.from_extra("near", {"near_tag": "t"})
    assert leg.tag == "t"
    assert leg.packets_in == 0
    assert leg.codec is None


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------


def test_timestamps_parse_to_aware_utc():
    record = CallDetailRecord.from_dict(call_record())

    assert record.started_at == datetime(
        2026, 3, 6, 14, 23, 1, 42000, tzinfo=timezone.utc
    )
    assert record.answered_at == datetime(
        2026, 3, 6, 14, 23, 3, 185000, tzinfo=timezone.utc
    )
    assert record.ended_at is not None
    assert record.generated_at is not None
    assert record.ended_at.tzinfo is timezone.utc

    # Ring time is answer - start; duration_secs is conversation time only.
    ringing = record.answered_at - record.started_at
    assert ringing.total_seconds() == pytest.approx(2.143)


def test_timestamp_parsing_is_none_safe():
    record = CallDetailRecord.from_dict({"method": "INVITE"})
    assert record.started_at is None
    assert record.answered_at is None
    assert parse_timestamp(None) is None
    assert parse_timestamp("") is None
    assert parse_timestamp("not a timestamp") is None


def test_offset_form_is_tolerated():
    # A collector that re-serialized the record may hand back an offset form.
    parsed = parse_timestamp("2026-03-06T14:23:01.042+00:00")
    assert parsed == datetime(2026, 3, 6, 14, 23, 1, 42000, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Test-harness glue
# ---------------------------------------------------------------------------


def test_mock_cdr_exposes_typed_records():
    from siphon_sdk.mock_module import get_cdr
    from siphon_sdk.request import Request

    cdr = get_cdr()
    cdr.clear()
    try:
        request = Request(
            method="INVITE",
            from_uri="sip:alice@example.com",
            to_uri="sip:bob@example.com",
            ruri="sip:bob@example.com",
            call_id="cid-1",
            source_ip="192.0.2.100",
            transport="tcp",
        )
        cdr.write(request, extra={"billing_id": "B-12345"})

        record = cdr.typed_records[-1]
        assert isinstance(record, CallDetailRecord)
        assert record.call_id == "cid-1"
        assert record.transport == "tcp"
        assert record.extra["billing_id"] == "B-12345"
    finally:
        cdr.clear()


# ---------------------------------------------------------------------------
# Drift guard
# ---------------------------------------------------------------------------


def _rust_cdr_fields(source: str) -> list[str]:
    """The serialized field names of `pub struct Cdr` in src/cdr/mod.rs."""
    body = source.split("pub struct Cdr {", 1)[1].split("\n}", 1)[0]
    fields: list[str] = []
    skip_next = False
    for line in body.splitlines():
        stripped = line.strip()
        if stripped == "#[serde(skip)]":
            skip_next = True
            continue
        if stripped.startswith(("//", "#[")) or not stripped:
            continue
        match = re.match(r"(?:pub )?([a-z_][a-z0-9_]*)\s*:", stripped)
        if not match:
            continue
        if skip_next:
            skip_next = False
            continue
        fields.append(match.group(1))
    return fields


def test_dataclass_mirrors_the_rust_struct():
    rust = Path(__file__).resolve().parents[2] / "src" / "cdr" / "mod.rs"
    if not rust.exists():
        pytest.skip("Rust source not present (SDK installed standalone)")

    rust_fields = _rust_cdr_fields(rust.read_text())
    assert "answer_instant" not in rust_fields, "#[serde(skip)] field leaked in"
    assert "extra" in rust_fields, "the flattened map should be found"

    python_fields = [f.name for f in dataclasses.fields(CallDetailRecord)]
    assert python_fields == rust_fields, (
        "siphon_sdk.cdr.CallDetailRecord has drifted from src/cdr/mod.rs — "
        "a field was added, removed or reordered on one side only"
    )
