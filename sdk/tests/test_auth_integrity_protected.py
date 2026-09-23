"""``auth.stamp_integrity_protected`` (P-CSCF) and
``auth.verify_integrity_protected`` (S-CSCF).

The pair carries TS 24.229's trust chain for a re-/de-REGISTER that arrives
over an IPsec SA: the P-CSCF writes ``integrity-protected`` into every
``Authorization`` header (``"yes"`` only when the request came over an SA
negotiated for that header's IMPI), and the S-CSCF skips the AKA challenge only
when the header says so *and* that IMPI is the one that registered the IMPU.
Each identity check closes a hole the other leaves open, so both are tested.

Uses the 3GPP test IMSI range (MCC 001 / MNC 01) only.
"""
import asyncio
from pathlib import Path

from siphon_sdk import mock_module
from siphon_sdk.mock_module import MockSAHandle
from siphon_sdk.request import Request
from siphon_sdk.testing import SipTestHarness


def run(coro):
    return asyncio.run(coro)

REALM = "ims.example.com"
IMPI = "001010000000001@ims.example.com"
OTHER_IMPI = "001010000000002@ims.example.com"
IMPU = "sip:001010000000001@ims.example.com"
ALIAS = "sip:+15550100001@ims.example.com"
CONTACT = "<sip:001010000000001@192.0.2.10:5060>"

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SCSCF_LAB_SCRIPT = str(_REPO_ROOT / "examples" / "ims_scscf_aka_lab.py")
_PCSCF_SCRIPT = str(_REPO_ROOT / "examples" / "ims_pcscf.py")


def _harness(**kwargs) -> SipTestHarness:
    mock_module.reset()
    return SipTestHarness(local_domains=[REALM, "ims.test"], **kwargs)


def _authorization(username: str, extra: str = "") -> str:
    value = (
        f'Digest username="{username}", realm="{REALM}", nonce="", '
        f'uri="sip:{REALM}", response=""'
    )
    return f"{value}, {extra}" if extra else value


def _register(authorization=None, *, sa=None, auth_user=None, expires="600000"):
    headers = {"Contact": CONTACT, "Expires": expires}
    if authorization is not None:
        headers["Authorization"] = authorization
    request = Request(
        method="REGISTER",
        ruri=f"sip:{REALM}",
        from_uri=IMPU,
        to_uri=IMPU,
        source_ip="192.0.2.10",
        source_port=5060,
        auth_user=auth_user,
        headers=headers,
    )
    if sa is not None:
        request._matched_sa = sa
    return request


# ---------------------------------------------------------------------------
# stamp_integrity_protected (P-CSCF)
# ---------------------------------------------------------------------------


def test_stamp_without_authorization_returns_none_and_adds_nothing():
    harness = _harness()
    request = _register()
    assert harness.auth.stamp_integrity_protected(request) is None
    assert request.get_header("Authorization") is None


def test_stamp_overwrites_a_forged_yes_on_an_unprotected_request():
    harness = _harness()
    request = _register(_authorization(IMPI, 'integrity-protected="yes"'))

    assert harness.auth.stamp_integrity_protected(request) == "no"

    header = request.get_header("Authorization")
    assert header.count("integrity-protected") == 1
    assert 'integrity-protected="no"' in header


def test_stamp_says_yes_over_an_sa_negotiated_for_this_impi():
    harness = _harness()
    request = _register(_authorization(IMPI), sa=MockSAHandle(impi=IMPI))

    assert harness.auth.stamp_integrity_protected(request) == "yes"
    assert 'integrity-protected="yes"' in request.get_header("Authorization")


def test_stamp_says_no_when_the_sa_belongs_to_another_impi():
    """A UE with its own valid SA must not get protection for another IMPI."""
    harness = _harness()
    request = _register(_authorization(OTHER_IMPI), sa=MockSAHandle(impi=IMPI))

    assert harness.auth.stamp_integrity_protected(request) == "no"


def test_stamp_says_no_when_the_sa_has_no_recorded_impi():
    harness = _harness()
    request = _register(_authorization(IMPI), sa=MockSAHandle())

    assert harness.auth.stamp_integrity_protected(request) == "no"


def test_stamp_rewrites_every_authorization_header():
    harness = _harness()
    request = _register(sa=MockSAHandle(impi=IMPI))
    request._headers["Authorization"] = [
        _authorization(IMPI, 'integrity-protected="no"'),
        _authorization(OTHER_IMPI, 'integrity-protected="yes"'),
    ]

    assert harness.auth.stamp_integrity_protected(request) == "yes"

    first, second = request.get_headers("Authorization")
    assert first.count("integrity-protected") == 1
    assert 'integrity-protected="yes"' in first
    assert second.count("integrity-protected") == 1
    assert 'integrity-protected="no"' in second


def test_stamp_keeps_the_other_parameters():
    harness = _harness()
    request = _register(
        'Digest username="001010000000001@ims.example.com", '
        'realm="ims.example.com, second realm", nonce="abc", '
        'uri="sip:ims.example.com", response="def"'
    )

    harness.auth.stamp_integrity_protected(request)

    header = request.get_header("Authorization")
    assert 'realm="ims.example.com, second realm"' in header
    assert 'nonce="abc"' in header
    assert 'response="def"' in header


# ---------------------------------------------------------------------------
# verify_integrity_protected (S-CSCF)
# ---------------------------------------------------------------------------


def _registered_by(harness, impi, aliases=None):
    assert harness.registrar.save(_register(auth_user=impi), aliases=aliases or [])


def test_verify_accepts_a_protected_request_from_the_registering_impi():
    harness = _harness()
    _registered_by(harness, IMPI)
    request = _register(_authorization(IMPI, 'integrity-protected="yes"'))

    assert harness.auth.verify_integrity_protected(request) is True
    assert request.auth_user == IMPI


def test_verify_resolves_the_implicit_registration_set():
    harness = _harness()
    _registered_by(harness, IMPI, aliases=[IMPU, ALIAS])
    request = Request(
        method="REGISTER",
        ruri=f"sip:{REALM}",
        from_uri=ALIAS,
        to_uri=ALIAS,
        headers={"Authorization": _authorization(IMPI, 'integrity-protected="yes"')},
    )

    assert harness.auth.verify_integrity_protected(request) is True


def test_verify_refuses_another_impi_even_when_protected():
    """A UE with its own SA and IMPI must not de-register someone else."""
    harness = _harness()
    _registered_by(harness, IMPI)
    request = _register(_authorization(OTHER_IMPI, 'integrity-protected="yes"'))

    assert harness.auth.verify_integrity_protected(request) is False
    assert request.auth_user is None


def test_verify_refuses_an_unregistered_impu():
    harness = _harness()
    request = _register(_authorization(IMPI, 'integrity-protected="yes"'))

    assert harness.auth.verify_integrity_protected(request) is False


def test_verify_refuses_unprotected_or_unstamped_requests():
    harness = _harness()
    _registered_by(harness, IMPI)

    for authorization in (
        _authorization(IMPI, 'integrity-protected="no"'),
        _authorization(IMPI),
    ):
        request = _register(authorization)
        assert harness.auth.verify_integrity_protected(request) is False
        assert request.auth_user is None
    assert harness.auth.verify_integrity_protected(_register()) is False


def test_verify_accepts_the_other_protected_values():
    harness = _harness()
    _registered_by(harness, IMPI)

    for value in ("tls-yes", "ip-assoc-yes"):
        request = _register(_authorization(IMPI, f'integrity-protected="{value}"'))
        assert harness.auth.verify_integrity_protected(request) is True


def test_verify_refuses_a_binding_saved_without_an_authenticated_user():
    harness = _harness()
    _registered_by(harness, None)
    request = _register(_authorization(IMPI, 'integrity-protected="yes"'))

    assert harness.auth.verify_integrity_protected(request) is False


# ---------------------------------------------------------------------------
# registrar records the authenticating identity
# ---------------------------------------------------------------------------


def test_save_records_the_authenticated_user_on_the_binding():
    harness = _harness()
    _registered_by(harness, IMPI)
    (binding,) = harness.registrar.lookup(IMPU)
    assert binding.auth_user == IMPI


def test_save_without_an_authenticated_user_records_none():
    harness = _harness()
    _registered_by(harness, IMPI)
    _registered_by(harness, None)
    (binding,) = harness.registrar.lookup(IMPU)
    assert binding.auth_user is None


# ---------------------------------------------------------------------------
# Example scripts
# ---------------------------------------------------------------------------


def test_lab_scscf_accepts_a_protected_deregister_without_a_challenge():
    harness = _harness()
    harness.load_script(_SCSCF_LAB_SCRIPT)
    _registered_by(harness, IMPI)

    result = harness.send_request(
        "REGISTER", f"sip:{REALM}",
        from_uri=IMPU,
        to_uri=IMPU,
        source_ip="192.0.2.10",
        headers={
            "Contact": f"{CONTACT};expires=0",
            "Expires": "0",
            "Authorization": _authorization(IMPI, 'integrity-protected="yes"'),
        },
    )

    assert result.status_code == 200
    assert harness.registrar.lookup(IMPU) == []


def test_lab_scscf_challenges_a_protected_request_from_another_impi():
    harness = _harness()
    harness.load_script(_SCSCF_LAB_SCRIPT)
    _registered_by(harness, IMPI)

    result = harness.send_request(
        "REGISTER", f"sip:{REALM}",
        from_uri=IMPU,
        to_uri=IMPU,
        source_ip="192.0.2.10",
        headers={
            "Contact": f"{CONTACT};expires=0",
            "Expires": "0",
            "Authorization": _authorization(OTHER_IMPI, 'integrity-protected="yes"'),
        },
    )

    assert result.status_code == 401
    assert len(harness.registrar.lookup(IMPU)) == 1


def test_pcscf_stamps_no_on_an_unprotected_register_before_relaying():
    harness = _harness()
    harness.auth._allow = True
    harness.load_script(_PCSCF_SCRIPT)

    result = harness.send_request(
        "REGISTER", f"sip:{REALM}",
        from_uri=IMPU,
        source_ip="192.0.2.10",
        headers={
            "Security-Client": (
                "ipsec-3gpp;alg=hmac-sha-1-96;spi-c=1000;spi-s=1001;"
                "port-c=5064;port-s=5066"
            ),
            "Authorization": _authorization(IMPI, 'integrity-protected="yes"'),
        },
    )

    assert result.was_relayed
    header = result.request.get_header("Authorization")
    assert header.count("integrity-protected") == 1
    assert 'integrity-protected="no"' in header
