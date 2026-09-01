"""
Tests for the MockLi class in siphon_sdk.mock_module.

Verifies target matching, event recording, and reset behavior.
"""

import pytest
from siphon_sdk.mock_module import install, reset, get_li, MockLi


@pytest.fixture(autouse=True)
def setup_siphon():
    """Install mock siphon module and reset between tests."""
    install()
    yield
    reset()


class FakeRequest:
    """Minimal request stub for LI tests."""

    def __init__(
        self,
        from_uri: str = "sip:alice@example.com",
        to_uri: str = "sip:bob@example.com",
        ruri: str = "sip:bob@example.com",
        call_id: str = "abc-123",
    ):
        self.from_uri = from_uri
        self.to_uri = to_uri
        self.ruri = ruri
        self.call_id = call_id


class TestIsTarget:
    """Tests for li.is_target()."""

    def test_no_targets_returns_false(self):
        li = get_li()
        request = FakeRequest()
        assert li.is_target(request) is False

    def test_matching_from_uri(self):
        li = get_li()
        li.add_target("sip:alice@example.com")
        request = FakeRequest(from_uri="sip:alice@example.com")
        assert li.is_target(request) is True

    def test_matching_to_uri(self):
        li = get_li()
        li.add_target("sip:bob@example.com")
        request = FakeRequest(to_uri="sip:bob@example.com")
        assert li.is_target(request) is True

    def test_matching_ruri(self):
        li = get_li()
        li.add_target("sip:bob@example.com")
        request = FakeRequest(ruri="sip:bob@example.com")
        assert li.is_target(request) is True

    def test_no_match(self):
        li = get_li()
        li.add_target("sip:charlie@example.com")
        request = FakeRequest()
        assert li.is_target(request) is False

    def test_disabled_returns_false(self):
        li = get_li()
        li.add_target("sip:alice@example.com")
        li._enabled = False
        request = FakeRequest(from_uri="sip:alice@example.com")
        assert li.is_target(request) is False


class TestIntercept:
    """Tests for li.intercept()."""

    def test_intercept_reports_a_match_without_emitting(self):
        # Interception is enforced in the dispatcher against ADMF-provisioned
        # warrants, so `intercept()` reports rather than acts. If it still
        # emitted, a script that called it would produce a duplicate IRI
        # record for an event the dispatcher had already reported.
        li = get_li()
        li.add_target("sip:alice@example.com")
        request = FakeRequest(from_uri="sip:alice@example.com")
        result = li.intercept(request)
        assert result is True
        assert li.events == []

    def test_intercept_no_match_returns_false(self):
        li = get_li()
        li.add_target("sip:charlie@example.com")
        request = FakeRequest()
        result = li.intercept(request)
        assert result is False
        assert len(li.events) == 0

    def test_intercept_disabled_returns_false(self):
        li = get_li()
        li.add_target("sip:alice@example.com")
        li._enabled = False
        request = FakeRequest(from_uri="sip:alice@example.com")
        assert li.intercept(request) is False


class TestStopIntercept:
    """Tests for li.stop_intercept()."""

    def test_stop_intercept_reports_a_match_without_emitting(self):
        # Session teardown records come from the dispatcher when the dialog
        # ends, not from a script call.
        li = get_li()
        li.add_target("sip:alice@example.com")
        request = FakeRequest(from_uri="sip:alice@example.com")
        result = li.stop_intercept(request)
        assert result is True
        assert li.events == []

    def test_stop_intercept_no_match_returns_false(self):
        li = get_li()
        li.add_target("sip:charlie@example.com")
        request = FakeRequest()
        assert li.stop_intercept(request) is False


class TestRecord:
    """Tests for li.record() and li.stop_recording()."""

    def test_record_records_event(self):
        li = get_li()
        request = FakeRequest(call_id="call-456")
        result = li.record(request)
        assert result is True
        assert ("record", "call-456") in li.events

    def test_stop_recording_records_event(self):
        li = get_li()
        request = FakeRequest(call_id="call-789")
        result = li.stop_recording(request)
        assert result is True
        assert ("stop_recording", "call-789") in li.events

    def test_record_disabled_returns_false(self):
        li = get_li()
        li._enabled = False
        request = FakeRequest()
        assert li.record(request) is False
        assert len(li.events) == 0


class TestIsEnabled:
    """Tests for the is_enabled property."""

    def test_enabled_by_default(self):
        li = get_li()
        assert li.is_enabled is True

    def test_disabled_when_set(self):
        li = get_li()
        li._enabled = False
        assert li.is_enabled is False


class TestClear:
    """Tests for li.clear()."""

    def test_clear_resets_targets_and_events(self):
        li = get_li()
        li.add_target("sip:alice@example.com")
        # `record` is the operator-driven SIPREC path, which does still record
        # an event; `intercept` only reports.
        li.record(FakeRequest(from_uri="sip:alice@example.com"))

        assert len(li.targets) == 1
        assert len(li.events) == 1

        li.clear()

        assert len(li.targets) == 0
        assert len(li.events) == 0

    def test_provisioned_counts_are_reported(self):
        # Warrants are provisioned by the ADMF over X1, never by a script;
        # the namespace exposes the counts read-only.
        li = get_li()
        assert li.task_count == 0
        assert li.destination_count == 0
        li.set_provisioned_counts(tasks=2, destinations=1)
        assert li.task_count == 2
        assert li.destination_count == 1


class TestAddTarget:
    """Tests for li.add_target()."""

    def test_add_target_deduplicates(self):
        li = get_li()
        li.add_target("sip:alice@example.com")
        li.add_target("sip:alice@example.com")
        assert len(li.targets) == 1

    def test_add_multiple_targets(self):
        li = get_li()
        li.add_target("sip:alice@example.com")
        li.add_target("sip:bob@example.com")
        assert len(li.targets) == 2


class TestImport:
    """Test that li is accessible via the siphon module."""

    def test_import_li(self):
        from siphon import li  # type: ignore[import]
        assert isinstance(li, MockLi)
        assert li is get_li()
