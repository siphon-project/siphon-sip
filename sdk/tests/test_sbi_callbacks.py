"""Tests for the SDK's ``siphon.sbi`` mock: the N5 AF callback hooks
``@sbi.on_event`` and ``@sbi.on_terminate``.
"""
from siphon_sdk import mock_module

mock_module.install()

from siphon import sbi  # noqa: E402  (must come after install)


def test_on_terminate_returns_the_handler_unchanged():
    def on_terminate(termination):
        return termination["resUri"]

    assert sbi.on_terminate(on_terminate) is on_terminate
    assert on_terminate({"termCause": "PDU_SESSION_TERMINATION", "resUri": "u"}) == "u"


def test_on_terminate_accepts_an_async_handler():
    async def on_terminate(termination):
        return None

    assert sbi.on_terminate(on_terminate) is on_terminate


def test_on_event_and_on_terminate_are_distinct_hooks():
    assert sbi.on_terminate is not sbi.on_event
