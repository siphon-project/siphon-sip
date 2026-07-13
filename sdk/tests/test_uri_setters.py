"""
Tests for the whole-URI setters — ``set_from_uri`` / ``set_to_uri`` /
``set_contact_uri`` (and ``set_contact_user``) — on both the proxy ``Request``
and the B2BUA ``Call``.
"""

from siphon_sdk.call import Call
from siphon_sdk.request import Request


class TestRequestUriSetters:
    def test_set_from_uri_replaces_uri(self):
        request = Request(from_uri="sip:alice@atlanta.com")
        request.set_from_uri("sip:+3120@tenant.example.com:5070")
        assert request.from_uri.user == "+3120"
        assert request.from_uri.host == "tenant.example.com"
        assert request.from_uri.port == 5070

    def test_set_to_uri_replaces_uri(self):
        request = Request(to_uri="sip:bob@biloxi.com")
        request.set_to_uri("sip:1000@ims.example.org")
        assert request.to_uri.user == "1000"
        assert request.to_uri.host == "ims.example.org"

    def test_set_contact_uri_replaces_contact(self):
        request = Request()
        request.set_header("Contact", "<sip:alice@10.0.0.1:5060>")
        request.set_contact_uri("sip:bob@192.0.2.9:5080;transport=tcp")
        contact = request.get_header("Contact")
        assert "bob@192.0.2.9:5080" in contact
        assert "transport=tcp" in contact
        assert "10.0.0.1" not in contact

    def test_set_contact_uri_preserves_header_params(self):
        request = Request()
        request.set_header("Contact", "<sip:alice@10.0.0.1:5060>;expires=600")
        request.set_contact_uri("sip:bob@192.0.2.9:5080")
        contact = request.get_header("Contact")
        assert "bob@192.0.2.9:5080" in contact
        assert ";expires=600" in contact

    def test_set_contact_user_rewrites_userpart_only(self):
        request = Request()
        request.set_header("Contact", "<sip:alice@10.0.0.1:5060;transport=tcp>")
        request.set_contact_user("1001")
        contact = request.get_header("Contact")
        assert "1001@10.0.0.1:5060" in contact
        assert "transport=tcp" in contact
        assert "alice@" not in contact

    def test_set_contact_user_empty_clears_userpart(self):
        request = Request()
        request.set_header("Contact", "<sip:alice@10.0.0.1:5060>")
        request.set_contact_user("")
        contact = request.get_header("Contact")
        assert "10.0.0.1:5060" in contact
        assert "alice" not in contact
        assert "@" not in contact

    def test_set_contact_uri_noop_without_contact(self):
        request = Request()
        request.set_contact_uri("sip:bob@192.0.2.9")
        assert request.get_header("Contact") is None


class TestCallUriSetters:
    def test_set_from_uri_replaces_uri(self):
        call = Call(from_uri="sip:alice@atlanta.com")
        call.set_from_uri("sip:1001@tenant.example.com:5060")
        assert call.from_uri.user == "1001"
        assert call.from_uri.host == "tenant.example.com"

    def test_set_to_uri_replaces_uri(self):
        call = Call(to_uri="sip:bob@example.com")
        call.set_to_uri("sip:1000@ims.example.org")
        assert call.to_uri.user == "1000"
        assert call.to_uri.host == "ims.example.org"

    def test_set_contact_user_records_override(self):
        call = Call()
        assert call._contact_user_override is None
        call.set_contact_user("1001")
        assert call._contact_user_override == "1001"

    def test_set_contact_uri_records_override(self):
        call = Call()
        assert call._contact_override is None
        call.set_contact_uri("sip:gruu-token@edge.example.com:5060")
        assert call._contact_override == "sip:gruu-token@edge.example.com:5060"

    def test_set_contact_user_from_from_uri(self):
        # The motivating case: carry the caller's extension into the B-leg
        # Contact userpart so a downstream that keys on "extension in Contact"
        # matches the INVITE the way it matches the REGISTER.
        call = Call(from_uri="sip:1001@tenant.example.com")
        call.set_contact_user(call.from_uri.user)
        assert call._contact_user_override == "1001"
