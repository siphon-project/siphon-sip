"""The mock verifies a supplied credential instead of waving it through.

`MockAuth` used to answer every check from its preset `_allow` flag, so a script
that delegates verification to the engine — which is what `password=` / `ha1=`
were added for — lost every accept/reject assertion its tests could make: a
wrong password was accepted as readily as a right one, silently, while the Rust
side verified properly. That is the gap these tests close.

The fixtures below build each `Authorization` header with `hashlib` directly
rather than calling into the mock, so the test and the code under test are not
the same arithmetic. The vectors are the RFC 7616 §3.4 construction, the same one
the engine's `DigestFields::verify` implements.
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

HASHES = {
    "MD5": "md5",
    "SHA-256": "sha256",
    "SHA-512-256": "sha512_256",
}


def _hash(algorithm: str, data: str) -> str:
    digest = hashlib.new(HASHES[algorithm])
    digest.update(data.encode("utf-8"))
    return digest.hexdigest()


def _ha1(algorithm: str, password: str = PASSWORD, username: str = USERNAME) -> str:
    return _hash(algorithm, f"{username}:{REALM}:{password}")


def _signed_request(algorithm: str = "MD5", password: str = PASSWORD,
                    method: str = "REGISTER", qop: bool = False,
                    header: str = "Authorization",
                    signed_method: str | None = None) -> Request:
    """A request carrying a correctly signed `Authorization` for `password`.

    `signed_method` signs for a different method than the request carries, which
    is how the H(A2) binding is exercised.
    """
    ha1 = _ha1(algorithm, password)
    ha2 = _hash(algorithm, f"{signed_method or method}:{DIGEST_URI}")
    if qop:
        response = _hash(algorithm, f"{ha1}:{NONCE}:00000001:abc123:auth:{ha2}")
        extra = ', qop=auth, nc=00000001, cnonce="abc123"'
    else:
        response = _hash(algorithm, f"{ha1}:{NONCE}:{ha2}")
        extra = ""
    value = (
        f'Digest username="{USERNAME}", realm="{REALM}", nonce="{NONCE}", '
        f'uri="{DIGEST_URI}", algorithm={algorithm}, response="{response}"{extra}'
    )
    return Request(
        method=method,
        to_uri=f"sip:{USERNAME}@{REALM}",
        headers={header: value},
    )


@pytest.mark.parametrize("algorithm", list(HASHES))
def test_a_correctly_signed_request_verifies_with_the_password(algorithm):
    auth = MockAuth()
    auth._allow = False

    assert auth.verify_digest(
        _signed_request(algorithm), realm=REALM, password=PASSWORD
    ) is True


@pytest.mark.parametrize("algorithm", list(HASHES))
def test_a_correctly_signed_request_verifies_with_the_matching_ha1(algorithm):
    auth = MockAuth()
    auth._allow = False

    assert auth.verify_digest(
        _signed_request(algorithm), realm=REALM, ha1=_ha1(algorithm)
    ) is True


@pytest.mark.parametrize("algorithm", list(HASHES))
def test_the_wrong_password_is_refused(algorithm):
    """The assertion the mock could not make before: a bad credential fails."""
    auth = MockAuth()
    auth._allow = False

    assert auth.verify_digest(
        _signed_request(algorithm), realm=REALM, password="wrong"
    ) is False


def test_an_ha1_computed_for_the_wrong_algorithm_is_refused():
    """H(A1) is algorithm-specific by construction (RFC 7616 §3.4.3).

    An MD5 hash cannot answer a SHA-256 challenge, and that mismatch has to
    surface as a failed verification — it is exactly the mistake `ha1=` invites,
    and the reason `password=` is the easier of the two to hold correctly.
    """
    auth = MockAuth()
    auth._allow = False

    assert auth.verify_digest(
        _signed_request("SHA-256"), realm=REALM, ha1=_ha1("MD5")
    ) is False


def test_qop_auth_is_verified_with_the_nonce_count_and_cnonce():
    auth = MockAuth()
    auth._allow = False

    assert auth.verify_digest(
        _signed_request("MD5", qop=True), realm=REALM, password=PASSWORD
    ) is True
    assert auth.verify_digest(
        _signed_request("MD5", qop=True), realm=REALM, password="wrong"
    ) is False


def test_the_method_is_taken_from_the_request():
    """H(A2) is `H(method:uri)`, so a signature for one method fails another."""
    auth = MockAuth()
    auth._allow = False

    assert auth.verify_digest(
        _signed_request(method="INVITE"), realm=REALM, password=PASSWORD
    ) is True

    # Signed as a REGISTER, presented on an INVITE.
    mismatched = _signed_request(method="INVITE", signed_method="REGISTER")
    assert auth.verify_digest(mismatched, realm=REALM, password=PASSWORD) is False


def test_a_missing_authorization_header_is_refused():
    auth = MockAuth()
    auth._allow = True  # would have returned True before

    request = Request(method="REGISTER", to_uri=f"sip:{USERNAME}@{REALM}")
    assert auth.verify_digest(request, realm=REALM, password=PASSWORD) is False


def test_the_allow_flag_still_governs_when_no_credential_is_supplied():
    """The backend path is unchanged: with no kwarg there is nothing to check."""
    auth = MockAuth()
    request = _signed_request()

    auth._allow = True
    assert auth.verify_digest(request, realm=REALM) is True

    auth._allow = False
    assert auth.verify_digest(request, realm=REALM) is False


def test_proxy_authorization_is_read_when_authorization_is_absent():
    auth = MockAuth()
    auth._allow = False
    request = _signed_request(header="Proxy-Authorization")

    assert auth.verify_digest(request, realm=REALM, password=PASSWORD) is True


def test_the_realm_argument_wins_over_the_one_the_client_echoed():
    """The engine verifies against the realm the script passed.

    Otherwise a client could pick the realm its credential is checked against by
    echoing a different one back in the header.
    """
    auth = MockAuth()
    auth._allow = False

    assert auth.verify_digest(
        _signed_request(), realm="other.example", password=PASSWORD
    ) is False


def test_an_unknown_algorithm_raises_rather_than_returning_false():
    """A silent False here is the same trap as accepting everything."""
    auth = MockAuth()
    auth._allow = False
    request = Request(
        method="REGISTER",
        to_uri=f"sip:{USERNAME}@{REALM}",
        headers={"Authorization": 'Digest username="carol", algorithm=ROT13'},
    )

    with pytest.raises(ValueError, match="ROT13"):
        auth.verify_digest(request, realm=REALM, password=PASSWORD)


def test_supplying_both_still_raises_before_any_arithmetic():
    auth = MockAuth()
    auth._allow = False

    with pytest.raises(ValueError, match="not both"):
        auth.verify_digest(
            _signed_request(), realm=REALM, password=PASSWORD, ha1=_ha1("MD5")
        )


@pytest.mark.parametrize(
    "method,header,code",
    [
        ("require_www_digest", "Authorization", 401),
        ("require_proxy_digest", "Proxy-Authorization", 407),
        ("require_digest", "Authorization", 401),
    ],
)
def test_the_challenge_helpers_verify_a_supplied_credential_too(method, header, code):
    """Same gap, same fix: `require_*` also took the credential and ignored it."""
    auth = MockAuth()
    auth._allow = False

    good = _signed_request(header=header)
    assert getattr(auth, method)(good, realm=REALM, password=PASSWORD) is True
    assert good.auth_user == USERNAME

    bad = _signed_request(header=header)
    assert getattr(auth, method)(bad, realm=REALM, password="wrong") is False
    assert bad.last_action.kind == "reply"
    assert bad.last_action.status_code == code
