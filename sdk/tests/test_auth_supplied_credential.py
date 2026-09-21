"""Digest verification against a credential the script supplies.

`password=` / `ha1=` short-circuit the configured credential backend, so a
deployment that can derive the credential in-process needs no credential source
configured at all — rather than standing up an HTTP endpoint for siphon to
fetch a value the script already has.

What these tests pin is the **signature and refusal parity** across all four
digest entry points: a script passing `password=` / `ha1=` must not raise
`TypeError` against the mock and then work on a node, supplying both must raise
exactly as the engine does, and a refusal must arm the challenge rather than
return a silent `False`.

The credential arithmetic itself lives in `test_auth_verify_digest.py`. The mock
performs it for real now — it used to answer from the preset `_allow` flag, so a
wrong password verified as readily as a right one — which is why the fixture
below is a correctly signed `Authorization` rather than a bare `username=`.
"""

import hashlib

import pytest

from siphon_sdk.mock_module import MockAuth
from siphon_sdk.request import Request

REALM = "example.com"
USERNAME = "carol"
PASSWORD = "s3cret"
NONCE = "0000000067a1b2c3.test"
DIGEST_URI = "sip:example.com"


def _md5(data: str) -> str:
    return hashlib.md5(data.encode("utf-8")).hexdigest()


HA1 = _md5(f"{USERNAME}:{REALM}:{PASSWORD}")

CREDENTIAL_KWARGS = [{"password": PASSWORD}, {"ha1": HA1}]
DIGEST_METHODS = [
    "verify_digest",
    "require_www_digest",
    "require_proxy_digest",
    "require_digest",
]


def _authed_request() -> Request:
    """A REGISTER signed with `PASSWORD`, on both auth header names."""
    response = _md5(f"{HA1}:{NONCE}:{_md5(f'REGISTER:{DIGEST_URI}')}")
    value = (
        f'Digest username="{USERNAME}", realm="{REALM}", nonce="{NONCE}", '
        f'uri="{DIGEST_URI}", algorithm=MD5, response="{response}"'
    )
    return Request(
        method="REGISTER",
        to_uri=f"sip:{USERNAME}@{REALM}",
        headers={"Authorization": value, "Proxy-Authorization": value},
    )


@pytest.mark.parametrize("method", DIGEST_METHODS)
@pytest.mark.parametrize("kwargs", CREDENTIAL_KWARGS)
def test_every_digest_method_accepts_the_credential_kwargs(method, kwargs):
    auth = MockAuth()
    # Deliberately off: a supplied credential is checked on its own merits, so
    # the verdict below comes from the arithmetic and not from the preset flag.
    auth._allow = False

    assert getattr(auth, method)(_authed_request(), realm=REALM, **kwargs) is True


@pytest.mark.parametrize("method", DIGEST_METHODS)
def test_supplying_both_is_an_error_not_a_silent_preference(method):
    """Both kwargs means one is being ignored and the author cannot tell which."""
    auth = MockAuth()
    auth._allow = True

    with pytest.raises(ValueError, match="not both"):
        getattr(auth, method)(
            _authed_request(),
            realm=REALM,
            password=PASSWORD,
            ha1=HA1,
        )


@pytest.mark.parametrize("method", DIGEST_METHODS)
def test_the_both_kwargs_check_runs_before_any_verification(method):
    """Even on the auto-allow path, so the bug surfaces in every test setup."""
    auth = MockAuth()
    auth._allow = False

    with pytest.raises(ValueError, match="not both"):
        getattr(auth, method)(
            _authed_request(),
            realm=REALM,
            password=PASSWORD,
            ha1=HA1,
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
