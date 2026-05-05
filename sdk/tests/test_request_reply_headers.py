"""Unit tests for the reply-header API on ``Request``:
``set_reply_header`` (replace), ``add_reply_header`` (append), and
``set_reply_to_tag``.

Mirrors the Rust-side semantics added to fix the bug where
``set_reply_header("To", ";tag=…")`` produced two ``To`` headers in the
response — RFC 3261 §7.3.1 (single-value headers must appear once) and
RFC 6665 §4.1.3 (UAS must add a To-tag to the dialog-establishing 2xx).
"""
from siphon_sdk.request import Request


def _subscribe_request(to: str = "<sip:bob@biloxi.com>") -> Request:
    return Request(
        method="SUBSCRIBE",
        ruri="sip:bob@biloxi.com",
        from_uri="sip:alice@atlanta.com",
        to_uri="sip:bob@biloxi.com",
        from_tag="alice",
        headers={"To": to, "Event": "reg"},
    )


def test_set_reply_header_records_replace_op():
    request = _subscribe_request()
    request.set_reply_header("To", "<sip:bob@biloxi.com>;tag=scscf-abc")
    ops = request.reply_header_ops
    assert ops == [("replace", "To", "<sip:bob@biloxi.com>;tag=scscf-abc")]


def test_add_reply_header_records_add_op():
    request = _subscribe_request()
    request.add_reply_header("Service-Route", "<sip:orig@scscf:6060;lr>")
    request.add_reply_header("Service-Route", "<sip:term@scscf:6060;lr>")
    ops = request.reply_header_ops
    assert ops == [
        ("add", "Service-Route", "<sip:orig@scscf:6060;lr>"),
        ("add", "Service-Route", "<sip:term@scscf:6060;lr>"),
    ]


def test_reply_headers_replace_clears_prior_same_name_entries():
    """Resolved view: replace wipes earlier entries of the same name."""
    request = _subscribe_request()
    request.add_reply_header("Warning", "first")
    request.add_reply_header("Warning", "second")
    request.set_reply_header("Warning", "final")
    assert request.reply_headers == [("Warning", "final")]


def test_reply_headers_replace_then_add_preserves_subsequent_add():
    """Replace then add: replace clears prior values, subsequent add
    appends on top."""
    request = _subscribe_request()
    request.set_reply_header("Warning", "alpha")
    request.add_reply_header("Warning", "beta")
    assert request.reply_headers == [
        ("Warning", "alpha"),
        ("Warning", "beta"),
    ]


def test_set_reply_to_tag_appends_tag_to_existing_to():
    request = _subscribe_request("<sip:bob@biloxi.com>")
    request.set_reply_to_tag("scscf-12345")
    ops = request.reply_header_ops
    assert len(ops) == 1
    op, name, value = ops[0]
    assert op == "replace"
    assert name == "To"
    assert ";tag=scscf-12345" in value
    assert "bob@biloxi.com" in value


def test_set_reply_to_tag_overwrites_existing_tag():
    """Mid-dialog (re-)SUBSCRIBE / re-INVITE — incoming To carries a tag
    already, our reply must overwrite, not stack ``;tag=stale;tag=fresh``."""
    request = _subscribe_request("<sip:bob@biloxi.com>;tag=stale")
    request.set_reply_to_tag("fresh")
    ops = request.reply_header_ops
    assert len(ops) == 1
    value = ops[0][2]
    assert ";tag=fresh" in value
    assert "stale" not in value


def test_set_reply_to_tag_preserves_non_tag_params():
    """Other To params (display name, transport, etc.) survive the
    rewrite."""
    request = _subscribe_request(
        '"Bob" <sip:bob@biloxi.com>;tag=stale;some=keep'
    )
    request.set_reply_to_tag("fresh")
    value = request.reply_header_ops[0][2]
    assert ";tag=fresh" in value
    assert "some=keep" in value
    assert "stale" not in value


def test_set_reply_to_tag_no_to_header_is_noop():
    request = Request(method="INVITE", ruri="sip:x@y.com")
    request.set_reply_to_tag("ignored")
    assert request.reply_header_ops == []


def test_get_reply_header_with_replace_returns_latest():
    request = _subscribe_request()
    request.set_reply_header("Expires", "3600")
    request.set_reply_header("Expires", "60")
    assert request.get_reply_header("Expires") == "60"


def test_get_reply_header_with_add_joins_values():
    request = _subscribe_request()
    request.add_reply_header("Service-Route", "<sip:orig@scscf;lr>")
    request.add_reply_header("Service-Route", "<sip:term@scscf;lr>")
    joined = request.get_reply_header("Service-Route")
    assert joined == "<sip:orig@scscf;lr>, <sip:term@scscf;lr>"
