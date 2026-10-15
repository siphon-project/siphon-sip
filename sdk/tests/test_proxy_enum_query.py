"""``proxy.enum_query``: an ENUM query that says what it came to and hands
back every usable URI (RFC 6116 section 5.2)."""

from __future__ import annotations

import asyncio

import pytest

from siphon_sdk.mock_module import MockProxy


def test_a_configured_answer_is_returned_and_the_query_recorded():
    proxy = MockProxy()
    proxy.set_enum_answer(
        "+15550100106",
        uris=["sip:+15550100106@example.com", "tel:+15550100106;npdi"],
        server="192.0.2.10:53",
    )
    answer = asyncio.run(proxy.enum_query(
        "+15550100106", service="E2U+sip+pstn:tel",
        servers=["192.0.2.10:53", "192.0.2.20:53"], timeout_ms=500,
    ))
    assert answer.outcome == "ok"
    assert answer.uris == ["sip:+15550100106@example.com", "tel:+15550100106;npdi"]
    assert answer.server == "192.0.2.10:53"
    assert proxy.enum_queries[0]["servers"] == ["192.0.2.10:53", "192.0.2.20:53"]


def test_failures_are_told_apart_from_no_entry():
    proxy = MockProxy()
    proxy.set_enum_answer("+15550100107", outcome="timeout")
    assert asyncio.run(proxy.enum_query("+15550100107")).outcome == "timeout"
    assert asyncio.run(proxy.enum_query("+15550100108")).outcome == "no_such_name"


def test_an_enum_lookup_result_is_an_ok_answer():
    proxy = MockProxy()
    proxy._utils._enum_results["+15550100109"] = "sip:a@example.com"
    answer = asyncio.run(proxy.enum_query("+15550100109"))
    assert (answer.outcome, answer.uris) == ("ok", ["sip:a@example.com"])


@pytest.mark.parametrize("kwargs", [
    {"number": "+"},
    {"number": "+15550100106", "service": "SIP+D2U"},
    {"number": "+15550100106", "servers": []},
    {"number": "+15550100106", "timeout_ms": 500},
])
def test_arguments_it_cannot_act_on_raise(kwargs):
    proxy = MockProxy()
    with pytest.raises(ValueError):
        proxy.enum_query(**kwargs)
