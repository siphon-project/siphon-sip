"""
Tests for the ``numbers`` namespace and the ``rewrite_identities`` /
``number_policy`` identity normalization on Request and Call.
"""

import pytest

from siphon_sdk import mock_module
from siphon_sdk.call import Call
from siphon_sdk.request import Request


@pytest.fixture(autouse=True)
def _reset():
    mock_module.install()
    mock_module.reset()
    mock_module.get_numbers().configure(country_code="31")
    yield
    mock_module.reset()


class TestNumbersNamespace:
    def test_parse_formats(self):
        numbers = mock_module.get_numbers()
        n = numbers.parse("0031612345678")
        assert n.e164 == "+31612345678"
        assert n.plain == "31612345678"
        assert n.national == "0612345678"
        assert n.international == "0031612345678"
        assert n.cc == "31"
        assert n.nsn == "612345678"
        assert n.format("plain") == "31612345678"

    def test_parse_national(self):
        n = mock_module.get_numbers().parse("0612345678")
        assert n.e164 == "+31612345678"

    def test_parse_home_override(self):
        n = mock_module.get_numbers().parse("01614960000", home="44")
        assert n.e164 == "+441614960000"

    def test_parse_non_number_raises(self):
        with pytest.raises(ValueError):
            mock_module.get_numbers().parse("alice")

    def test_short_code_preserved(self):
        with pytest.raises(ValueError):
            mock_module.get_numbers().parse("112")


class TestRequestRewriteIdentities:
    def test_inline_e164(self):
        request = Request(
            method="INVITE",
            ruri="sip:0201234567@example.com",
            from_uri="sip:0612345678@example.com",
            to_uri="sip:0201234567@example.com",
        )
        changed = request.rewrite_identities(format="e164")
        assert changed == 3
        assert request.ruri.user == "+31201234567"
        assert request.from_uri.user == "+31612345678"
        assert request.to_uri.user == "+31201234567"

    def test_national_headers_subset(self):
        request = Request(
            method="INVITE",
            ruri="sip:0612345678@example.com",
            from_uri="sip:0612345678@example.com",
        )
        request.rewrite_identities(format="plain", headers=["From"])
        # From rewritten; R-URI left alone (not in the header set).
        assert request.from_uri.user == "31612345678"
        assert request.ruri.user == "0612345678"

    def test_pai_header_string_rewritten(self):
        request = Request(
            method="INVITE",
            ruri="sip:0201234567@example.com",
            from_uri="sip:0612345678@example.com",
            headers={"P-Asserted-Identity": "<sip:0612345678@example.com>"},
        )
        request.rewrite_identities(format="e164", headers=["P-Asserted-Identity"])
        assert "+31612345678" in request.get_header("P-Asserted-Identity")

    def test_non_number_left_untouched(self):
        request = Request(
            method="INVITE",
            ruri="sip:alice@example.com",
            from_uri="sip:alice@example.com",
        )
        changed = request.rewrite_identities(format="e164")
        assert changed == 0
        assert request.from_uri.user == "alice"

    def test_named_policy(self):
        mock_module.get_numbers().register_policy("teams@2026", default="e164")
        request = Request(
            method="INVITE",
            ruri="sip:0201234567@example.com",
            from_uri="sip:0612345678@example.com",
        )
        request.rewrite_identities("teams@2026")
        assert request.from_uri.user == "+31612345678"

    def test_unknown_policy_raises(self):
        request = Request(method="INVITE", ruri="sip:0201234567@example.com")
        with pytest.raises(ValueError):
            request.rewrite_identities("nope@2026")


class TestCallNumberPolicy:
    def test_dial_number_policy_normalizes_target_and_from(self):
        mock_module.get_numbers().register_policy("ims-e164@2026", default="e164")
        call = Call(
            from_uri="sip:0612345678@example.com",
            to_uri="sip:0201234567@ims.example.com",
            ruri="sip:0201234567@ims.example.com",
        )
        call.dial("sip:0201234567@ims.example.com", number_policy="ims-e164@2026")
        action = call._actions[0]
        assert action.targets == ["sip:+31201234567@ims.example.com"]
        # A-leg From normalized in place (flows to the B-leg).
        assert call.from_uri.user == "+31612345678"

    def test_dial_no_policy_leaves_target(self):
        call = Call(from_uri="sip:0612345678@example.com")
        call.dial("sip:0201234567@ims.example.com")
        assert call._actions[0].targets == ["sip:0201234567@ims.example.com"]
        assert call.from_uri.user == "0612345678"

    def test_call_rewrite_identities_inline(self):
        call = Call(
            from_uri="sip:0612345678@example.com",
            to_uri="sip:0201234567@example.com",
        )
        call.rewrite_identities(format="e164")
        assert call.from_uri.user == "+31612345678"
        assert call.to_uri.user == "+31201234567"

    def test_default_b2bua_policy(self):
        numbers = mock_module.get_numbers()
        numbers.register_policy("default-e164@2026", default="e164")
        numbers.configure(default_number_policy="default-e164@2026")
        call = Call(from_uri="sip:0612345678@example.com")
        call.dial("sip:0201234567@ims.example.com")
        assert call._actions[0].targets == ["sip:+31201234567@ims.example.com"]

    def test_fork_number_policy(self):
        mock_module.get_numbers().register_policy("e164@2026", default="e164")
        call = Call(from_uri="sip:0612345678@example.com")
        call.fork(
            ["sip:0201234567@a.example.com", "sip:0301234567@b.example.com"],
            number_policy="e164@2026",
        )
        assert call._actions[0].targets == [
            "sip:+31201234567@a.example.com",
            "sip:+31301234567@b.example.com",
        ]
