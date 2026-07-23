"""Parity test for Request.remove_headers_matching (mirrors production)."""

from siphon_sdk.request import Request


def test_removes_by_prefix_case_insensitive():
    request = Request(
        method="INVITE",
        headers={
            "X-Trunk": "a",
            "x-account-id": "42",
            "Via": "SIP/2.0/UDP host",
            "P-Asserted-Identity": "sip:alice@example.com",
        },
    )

    request.remove_headers_matching("X-")

    # both X-* headers gone regardless of case
    assert request.get_header("X-Trunk") is None
    assert request.get_header("x-account-id") is None
    # non-matching headers untouched
    assert request.get_header("Via") == "SIP/2.0/UDP host"
    assert request.has_header("P-Asserted-Identity")


def test_no_match_is_noop():
    request = Request(method="INVITE", headers={"Via": "SIP/2.0/UDP host"})
    request.remove_headers_matching("X-")
    assert request.get_header("Via") == "SIP/2.0/UDP host"
