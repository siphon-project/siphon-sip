"""`auth.generate_nonce()` / `auth.validate_nonce()`.

A script that verifies credentials itself — rather than through a configured
`auth.backend` — has to build its own `WWW-Authenticate` header. It needs the
engine's nonce for that: mint one the engine will recognise coming back, and
reject a replayed one. Neither primitive was reachable from Python before, on
the engine or in the mock.

The mock checks freshness only. It has no shared secret, so it cannot verify
the engine's HMAC tag, and a mock-minted nonce is not interchangeable with a
real one — the shape and the expiry rules are what these tests pin.
"""

import time

from siphon_sdk.mock_module import MockAuth
from siphon_sdk.request import Request


def test_generate_nonce_has_the_engine_shape():
    nonce = MockAuth().generate_nonce()

    timestamp_hex, separator, tag = nonce.partition(".")
    assert separator == ".", nonce
    assert len(timestamp_hex) == 16, "timestamp is zero-padded 16 hex chars"
    int(timestamp_hex, 16)  # parses
    assert tag, "a nonce carries a tag"


def test_a_freshly_minted_nonce_validates():
    auth = MockAuth()
    assert auth.validate_nonce(auth.generate_nonce()) is True


def test_every_nonce_is_distinct():
    auth = MockAuth()
    assert len({auth.generate_nonce() for _ in range(50)}) == 50


def test_a_stale_nonce_is_rejected():
    """The property the primitive exists for: replay is bounded by the TTL."""
    auth = MockAuth()
    stale = f"{int(time.time()) - auth._nonce_ttl_secs - 60:016x}.deadbeef"

    assert auth.validate_nonce(stale) is False


def test_a_nonce_just_inside_the_ttl_still_validates():
    auth = MockAuth()
    recent = f"{int(time.time()) - auth._nonce_ttl_secs + 30:016x}.deadbeef"

    assert auth.validate_nonce(recent) is True


def test_an_implausibly_future_dated_nonce_is_rejected():
    """Beyond the 60s clock-skew allowance — a forged timestamp."""
    auth = MockAuth()
    future = f"{int(time.time()) + 3600:016x}.deadbeef"

    assert auth.validate_nonce(future) is False


def test_a_small_clock_skew_is_tolerated():
    auth = MockAuth()
    skewed = f"{int(time.time()) + 30:016x}.deadbeef"

    assert auth.validate_nonce(skewed) is True


def test_malformed_nonces_are_rejected_without_raising():
    auth = MockAuth()

    for bad in ["", "no-separator", "nothex.tag", ".", "..", "zzzz.tag"]:
        assert auth.validate_nonce(bad) is False, bad


def test_a_script_can_issue_and_check_its_own_challenge():
    """The shape this exists for: challenge, then bound the replay window."""
    auth = MockAuth()
    request = Request(method="REGISTER", to_uri="sip:alice@example.com")

    # Challenge with a nonce the engine will recognise coming back.
    nonce = auth.generate_nonce()
    request.set_reply_header(
        "WWW-Authenticate",
        f'Digest realm="example.com", nonce="{nonce}", algorithm=MD5, qop="auth"',
    )
    request.reply(401, "Unauthorized")

    assert request.last_action.status_code == 401
    # The credential comes back carrying that nonce; it is still fresh.
    assert auth.validate_nonce(nonce) is True
