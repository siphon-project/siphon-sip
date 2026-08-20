"""`auth_user` is writable on both Request and Call.

The digest helpers record the username exactly as it arrived in the
``Authorization`` / ``Proxy-Authorization`` header, because that is the string
the response was computed over.  Deployments whose authentication identity is
not their subscriber identity — an IMS private identity authenticating a public
one, or any username carrying a validity prefix or tenant qualifier — reduce it
themselves, after verification, so that everything keyed on the authenticated
identity (``registrar.enforce_auth_aor_match``, the CDR's ``auth_user``) sees
the subscriber identity.
"""

from siphon_sdk.call import Call
from siphon_sdk.request import Request


def test_request_auth_user_is_writable():
    request = Request(method="REGISTER", auth_user="qualifier:alice")
    assert request.auth_user == "qualifier:alice"

    request.auth_user = request.auth_user.split(":", 1)[1]
    assert request.auth_user == "alice"


def test_request_auth_user_can_be_cleared():
    request = Request(method="REGISTER", auth_user="alice")
    request.auth_user = None
    assert request.auth_user is None


def test_request_auth_user_defaults_to_none_when_never_challenged():
    assert Request(method="REGISTER").auth_user is None


def test_call_auth_user_is_writable():
    call = Call(
        call_id="auth-user-1",
        from_uri="sip:alice@example.com",
        to_uri="sip:bob@example.com",
    )
    assert call.auth_user is None

    call.auth_user = "alice"
    assert call.auth_user == "alice"

    call.auth_user = None
    assert call.auth_user is None


def test_normalising_the_credential_is_what_lets_an_aor_check_pass():
    """The shape this exists for: reduce, then bind.

    An AoR check compares the authenticated username to the AoR userpart. A
    credential carrying anything besides the subscriber identity never matches
    until the script reduces it, so without a writable ``auth_user`` the only
    way to deploy such a scheme is to turn the anti-hijack check off.
    """
    request = Request(
        method="REGISTER",
        to_uri="sip:alice@example.com",
        auth_user="qualifier:alice",
    )

    aor_user = "alice"
    assert request.auth_user != aor_user  # unreduced: would be refused

    request.auth_user = request.auth_user.split(":", 1)[1]
    assert request.auth_user == aor_user  # reduced: matches
