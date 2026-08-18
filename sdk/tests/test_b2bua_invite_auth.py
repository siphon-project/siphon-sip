"""Unit tests for challenging an INVITE from ``@b2bua.on_invite``.

With any ``@b2bua.*`` handler registered, the dispatcher hands INVITE straight
to the B2BUA path — ``@proxy.on_request`` never sees it — so the digest helpers
have to work off the ``Call`` object for a B2BUA to authenticate its caller.

Mirrors the engine semantics:

- ``auth.require_www_digest`` / ``require_proxy_digest`` / ``require_digest`` /
  ``verify_digest`` accept a ``Request`` **or** a ``Call``.
- On a ``Call``, the challenge is armed as the same deferred reject
  ``call.reject()`` produces (the dispatcher turns it into the 401/407 and
  drops the call actor without dialling a B-leg).
- A verified username lands on ``call.auth_user``.
- ``require_ims_digest`` / ``require_aka_digest`` stay Request-only: IMS/AKA
  digest is a REGISTER-time procedure and REGISTER never reaches the B2BUA path.
"""
import pytest

from siphon_sdk.call import Call
from siphon_sdk.mock_module import MockAuth
from siphon_sdk.request import Request


def _invite_call(proxy_auth: str | None = None) -> Call:
    headers = {"Proxy-Authorization": proxy_auth} if proxy_auth else None
    return Call(
        call_id="b2bua-auth-1",
        from_uri="sip:alice@example.com",
        to_uri="sip:bob@example.com",
        ruri="sip:bob@example.com",
        headers=headers,
    )


def test_require_proxy_digest_on_call_arms_a_407_reject():
    auth = MockAuth()
    call = _invite_call()

    assert auth.require_proxy_digest(call, realm="example.com") is False

    # The deferred reject the dispatcher turns into the 407 — no B-leg dialled.
    assert call.last_action.kind == "reject"
    assert call.last_action.status_code == 407
    assert call.last_action.reason == "Proxy Authentication Required"
    assert call.auth_user is None


def test_require_www_digest_on_call_arms_a_401_reject():
    auth = MockAuth()
    call = _invite_call()

    assert auth.require_www_digest(call, realm="example.com") is False
    assert call.last_action.kind == "reject"
    assert call.last_action.status_code == 401
    assert call.last_action.reason == "Unauthorized"


def test_require_digest_alias_on_call_arms_a_401_reject():
    auth = MockAuth()
    call = _invite_call()

    assert auth.require_digest(call, realm="example.com") is False
    assert call.last_action.status_code == 401


def test_authenticated_call_sets_auth_user_and_arms_nothing():
    auth = MockAuth()
    auth._allow = True
    call = _invite_call()

    assert auth.require_proxy_digest(call, realm="example.com") is True
    assert call.auth_user == "alice"
    assert call.last_action is None, "no reject may be armed on success"


def test_authenticated_call_takes_username_from_the_credentials():
    auth = MockAuth()
    auth._allow = True
    call = _invite_call(
        proxy_auth='Digest username="trunk-7", realm="example.com", nonce="abc"'
    )

    assert auth.require_proxy_digest(call, realm="example.com") is True
    # _allow short-circuits to the From user; with credentials present and a
    # backend that accepts them, the username comes off the header.
    auth._allow = False
    fresh = _invite_call(
        proxy_auth='Digest username="trunk-7", realm="example.com", nonce="abc"'
    )
    auth._check_auth = lambda header, realm: True  # type: ignore[method-assign]
    assert auth.require_proxy_digest(fresh, realm="example.com") is True
    assert fresh.auth_user == "trunk-7"
    assert fresh.last_action is None


def test_verify_digest_on_call_reads_proxy_authorization():
    auth = MockAuth()
    auth._check_auth = lambda header, realm: True  # type: ignore[method-assign]

    without = _invite_call()
    assert auth.verify_digest(without, realm="example.com") is False

    with_credentials = _invite_call(
        proxy_auth='Digest username="alice", realm="example.com", nonce="abc"'
    )
    assert auth.verify_digest(with_credentials, realm="example.com") is True
    # verify_digest never challenges and never sets auth_user.
    assert with_credentials.last_action is None
    assert with_credentials.auth_user is None


def test_request_path_is_unchanged():
    auth = MockAuth()
    request = Request(method="INVITE", ruri="sip:bob@example.com")

    assert auth.require_proxy_digest(request, realm="example.com") is False
    assert request.last_action.kind == "reply"
    assert request.last_action.status_code == 407


@pytest.mark.parametrize("method", ["require_ims_digest", "require_aka_digest"])
def test_ims_and_aka_digest_reject_a_call(method):
    # REGISTER never reaches the B2BUA path, so the engine types these two on
    # Request. The mock has to refuse a Call too, or a script that passes one
    # would only fail in production.
    auth = MockAuth()
    with pytest.raises(TypeError, match="REGISTER"):
        getattr(auth, method)(_invite_call(), realm="example.com")


def test_challenging_an_unsupported_object_raises_type_error():
    auth = MockAuth()

    class NotAMessage:
        from_uri = None

        def get_header(self, name):
            return None

    with pytest.raises(TypeError, match="Request .* or a Call"):
        auth.require_proxy_digest(NotAMessage(), realm="example.com")


def test_b2bua_challenge_then_dial_flow():
    """The shape a real ``@b2bua.on_invite`` handler takes."""
    auth = MockAuth()

    def on_invite(call):
        if not auth.require_proxy_digest(call, realm="example.com"):
            return
        call.dial(call.ruri)

    # First INVITE, no credentials -> challenged, never dialled.
    first = _invite_call()
    on_invite(first)
    assert [action.kind for action in first.actions] == ["reject"]
    assert first.last_action.status_code == 407

    # Re-INVITE with credentials the backend accepts -> dialled.
    auth._allow = True
    second = _invite_call(
        proxy_auth='Digest username="alice", realm="example.com", nonce="abc"'
    )
    on_invite(second)
    assert [action.kind for action in second.actions] == ["dial"]
    assert second.auth_user == "alice"
