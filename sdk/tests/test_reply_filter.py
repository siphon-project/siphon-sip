"""`@proxy.on_reply` takes the same optional method filter as `@proxy.on_request`.

The filter matches the method of the request the response answers.
`@proxy.on_register_reply` is shorthand for `@proxy.on_reply("REGISTER")`.
"""

import pytest

from siphon_sdk.request import Request
from siphon_sdk.testing import SipTestHarness

SCRIPT = """
from siphon import proxy

@proxy.on_reply
def every_reply(request, reply):
    reply.set_header("X-Every", "yes")
    reply.relay()

@proxy.on_reply("REGISTER")
def register_reply(request, reply):
    reply.set_header("X-Register", "yes")
    reply.relay()

@proxy.on_reply("INVITE|UPDATE")
def invite_or_update_reply(request, reply):
    reply.set_header("X-Invite-Or-Update", "yes")
    reply.relay()

@proxy.on_register_reply
def register_shorthand(request, reply):
    reply.set_header("X-Register-Shorthand", "yes")
    reply.relay()
"""

STAMPS = ("X-Every", "X-Register", "X-Invite-Or-Update", "X-Register-Shorthand")


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


def _stamped(harness, method, source=SCRIPT):
    harness.load_source(source)
    result = harness.send_reply(Request(method=method), 200, "OK")
    return sorted(name for name in STAMPS if result.reply.has_header(name)), result


def test_filtered_reply_handler_runs_only_for_its_method(harness):
    names, result = _stamped(harness, "REGISTER")
    assert names == ["X-Every", "X-Register", "X-Register-Shorthand"]
    assert result.was_relayed


def test_pipe_separated_filter_matches_each_method(harness):
    for method in ("INVITE", "UPDATE"):
        names, _ = _stamped(harness, method)
        assert names == ["X-Every", "X-Invite-Or-Update"], method


def test_unmatched_method_reaches_only_the_unfiltered_handler(harness):
    names, _ = _stamped(harness, "OPTIONS")
    assert names == ["X-Every"]


def test_explicit_empty_call_is_unfiltered(harness):
    source = """
from siphon import proxy

@proxy.on_reply()
def every_reply(request, reply):
    reply.set_header("X-Every", "yes")
    reply.relay()
"""
    for method in ("INVITE", "REGISTER", "MESSAGE"):
        names, _ = _stamped(harness, method, source)
        assert names == ["X-Every"], method


def test_non_string_filter_is_rejected(harness):
    with pytest.raises(TypeError, match="proxy.on_reply expects"):
        harness.load_source("""
from siphon import proxy

@proxy.on_reply(42)
def handle_reply(request, reply):
    reply.relay()
""")
