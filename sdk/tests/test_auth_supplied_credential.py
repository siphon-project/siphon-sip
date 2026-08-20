"""Digest verification against a credential the script supplies.

`password=` / `ha1=` short-circuit the configured credential backend, so a
deployment that can derive the credential in-process needs no credential source
configured at all — rather than standing up an HTTP endpoint for siphon to
fetch a value the script already has.

`MockAuth` does no cryptography (`_check_auth` honours `_allow`, like every
other check in it), so what these tests pin is the **signature parity** a mock
can actually prove: a script passing `password=` / `ha1=` must not raise
`TypeError` against the mock and then work on a node, and supplying both must
raise in the mock exactly as it does in the engine. The digest arithmetic is
covered by the Rust tests in `src/script/api/auth.rs`.
"""

import pytest

from siphon_sdk.mock_module import MockAuth
from siphon_sdk.request import Request

CREDENTIAL_KWARGS = [{"password": "s3cret"}, {"ha1": "deadbeef"}]
DIGEST_METHODS = [
    "verify_digest",
    "require_www_digest",
    "require_proxy_digest",
    "require_digest",
]


def _authed_request() -> Request:
    return Request(
        method="REGISTER",
        to_uri="sip:carol@example.com",
        headers={
            "Authorization": 'Digest username="carol"',
            "Proxy-Authorization": 'Digest username="carol"',
        },
    )


@pytest.mark.parametrize("method", DIGEST_METHODS)
@pytest.mark.parametrize("kwargs", CREDENTIAL_KWARGS)
def test_every_digest_method_accepts_the_credential_kwargs(method, kwargs):
    auth = MockAuth()
    auth._allow = True

    assert getattr(auth, method)(_authed_request(), realm="example.com", **kwargs) is True


@pytest.mark.parametrize("method", DIGEST_METHODS)
def test_supplying_both_is_an_error_not_a_silent_preference(method):
    """Both kwargs means one is being ignored and the author cannot tell which."""
    auth = MockAuth()
    auth._allow = True

    with pytest.raises(ValueError, match="not both"):
        getattr(auth, method)(
            _authed_request(),
            realm="example.com",
            password="s3cret",
            ha1="deadbeef",
        )


@pytest.mark.parametrize("method", DIGEST_METHODS)
def test_the_both_kwargs_check_runs_before_any_verification(method):
    """Even on the auto-allow path, so the bug surfaces in every test setup."""
    auth = MockAuth()
    auth._allow = False

    with pytest.raises(ValueError, match="not both"):
        getattr(auth, method)(
            _authed_request(),
            realm="example.com",
            password="s3cret",
            ha1="deadbeef",
        )


def test_neither_kwarg_leaves_the_existing_backend_path_untouched():
    auth = MockAuth()
    auth._allow = False
    request = Request(method="REGISTER", to_uri="sip:carol@example.com")

    assert auth.verify_digest(request, realm="example.com") is False
    assert auth.require_www_digest(request, realm="example.com") is False
    # A rejection still arms the challenge — it is not a silent False.
    assert request.last_action.kind == "reply"
    assert request.last_action.status_code == 401


def test_a_supplied_credential_rejection_still_arms_the_challenge():
    """The rejection path must behave exactly like the backend one."""
    auth = MockAuth()
    auth._allow = False
    request = _authed_request()

    assert auth.require_www_digest(request, realm="example.com", password="wrong") is False
    assert request.last_action.kind == "reply"
    assert request.last_action.status_code == 401
