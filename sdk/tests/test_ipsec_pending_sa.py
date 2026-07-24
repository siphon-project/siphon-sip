"""Tests for ``ipsec.PendingSA`` mock — focused on the
``activate(hard_lifetime_secs=…)`` kwarg, which re-pins the kernel SA
hard-lifetime so it tracks the registrar's grant (3GPP TS 33.203 §7.4)
instead of the placeholder installed at ``ipsec.allocate`` time.
"""
import asyncio

import pytest

from siphon_sdk import mock_module
from siphon_sdk.mock_module import (
    MockAuthVectorHandle,
    MockSecurityOffer,
    _TransformEnum,
)


def _fresh_ipsec():
    mock_module.install()
    ipsec = mock_module.get_ipsec()
    ipsec.clear()
    return ipsec


def _allocate(ipsec, *, expires_secs=600_000, protocol="udp"):
    av = MockAuthVectorHandle(ck=bytes(16), ik=bytes(16))
    offer = MockSecurityOffer(
        mechanism="ipsec-3gpp",
        alg="hmac-sha-1-96",
        ealg="null",
        spi_c=11111, spi_s=22222,
        port_c=50000, port_s=50001,
        ue_addr="10.0.0.1",
    )
    return asyncio.run(
        ipsec.allocate(
            av, offer, _TransformEnum.HmacSha1_96Null,
            expires_secs=expires_secs, protocol=protocol,
        )
    )


def test_activate_without_kwarg_preserves_allocation_lifetime():
    ipsec = _fresh_ipsec()
    pending = _allocate(ipsec, expires_secs=600_000)
    assert pending.expires_secs == 600_000

    pending.activate()  # no kwarg
    assert pending.is_active
    assert pending.expires_secs == 600_000, (
        "activate() with no kwarg must not touch expires_secs"
    )


def test_activate_with_hard_lifetime_secs_repins_to_grant():
    """The fix path: 401 installed an SA with the UE's 600000 s ask, the
    200 OK arrives with grant=3600, script calls
    activate(hard_lifetime_secs=grant+32) to tighten the kernel SA so
    its expiry tracks the registrar's grant."""
    ipsec = _fresh_ipsec()
    pending = _allocate(ipsec, expires_secs=600_000)

    pending.activate(hard_lifetime_secs=3632)
    assert pending.is_active
    assert pending.expires_secs == 3632


def test_activate_kwarg_must_be_keyword_only():
    """The Rust signature is ``def activate(*, hard_lifetime_secs=None)``
    — positional usage must raise so scripts can't accidentally pass an
    arbitrary first argument."""
    ipsec = _fresh_ipsec()
    pending = _allocate(ipsec)

    with pytest.raises(TypeError):
        pending.activate(3632)  # type: ignore[misc]


def test_activate_after_cleanup_rejects_lifetime_kwarg():
    ipsec = _fresh_ipsec()
    pending = _allocate(ipsec)
    asyncio.run(pending.cleanup())

    with pytest.raises(ValueError, match="cleaned up"):
        pending.activate(hard_lifetime_secs=3632)


# -- Dual-stack: the P-CSCF SA side must match the UE's family ---------------

def _allocate_for(ipsec, ue_addr):
    av = MockAuthVectorHandle(ck=bytes(16), ik=bytes(16))
    offer = MockSecurityOffer(
        mechanism="ipsec-3gpp",
        alg="hmac-sha-1-96",
        ealg="null",
        spi_c=11111, spi_s=22222,
        port_c=50000, port_s=50001,
        ue_addr=ue_addr,
    )
    return asyncio.run(
        ipsec.allocate(
            av, offer, _TransformEnum.HmacSha1_96Null,
            expires_secs=600_000, protocol=None,
        )
    )


def test_allocate_dual_stack_serves_both_families():
    ipsec = _fresh_ipsec()  # default mock is dual-stack
    assert _allocate_for(ipsec, "10.0.0.1") is not None
    assert _allocate_for(ipsec, "2001:db8::1") is not None


def test_allocate_v6_ue_without_v6_listener_raises():
    ipsec = _fresh_ipsec()
    ipsec.set_pcscf_families(v4=True, v6=False)  # single-stack (v4-only) P-CSCF
    assert _allocate_for(ipsec, "10.0.0.1") is not None
    with pytest.raises(ValueError, match="no IPv6 P-CSCF listener"):
        _allocate_for(ipsec, "2001:db8::1")


def test_allocate_v4_ue_without_v4_listener_raises():
    ipsec = _fresh_ipsec()
    ipsec.set_pcscf_families(v4=False, v6=True)  # v6-only P-CSCF
    assert _allocate_for(ipsec, "2001:db8::1") is not None
    with pytest.raises(ValueError, match="no IPv4 P-CSCF listener"):
        _allocate_for(ipsec, "10.0.0.1")
