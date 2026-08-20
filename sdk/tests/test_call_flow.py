"""`call.flow` and Flow comparison — RFC 5626 connection reuse.

A Contact saved at REGISTER time carries the flow the registration arrived on.
`call.flow` is the same view for the INVITE, so a call can be authorised by
matching the two rather than by challenging every INVITE with a 407.

On a stream transport that comparison is an exact match on one accepted socket.
That is the whole point over a source-address check, which is worthless behind
carrier NAT where every subscriber on the network shares an address.
"""

from siphon_sdk.call import Call
from siphon_sdk.types import Flow


def flow(transport="tls", remote="192.0.2.10:41234", local="198.51.100.1:5061", cid=0xC0FFEE):
    return Flow(transport=transport, remote_addr=remote, local_addr=local, connection_id=cid)


def test_call_flow_is_none_when_no_binding_was_captured():
    # An internally-originated call has no inbound flow to describe, and a
    # script must be able to tell that apart from a flow that did not match.
    assert Call(call_id="c1").flow is None


def test_call_flow_exposes_the_captured_flow():
    call = Call(call_id="c1", flow=flow())

    assert call.flow.transport == "tls"
    assert call.flow.remote_addr == "192.0.2.10:41234"
    assert call.flow.local_addr == "198.51.100.1:5061"
    assert call.flow.connection_id == 0xC0FFEE


def test_a_call_on_the_registered_connection_matches_that_binding():
    registered = flow()
    call = Call(call_id="c1", flow=flow())

    assert call.flow == registered


def test_same_address_on_a_new_connection_does_not_match():
    registered = flow(cid=0xC0FFEE)
    reconnected = Call(call_id="c1", flow=flow(cid=0xBEEF))

    assert reconnected.flow != registered


def test_a_different_transport_does_not_match():
    registered = flow(transport="tls")
    over_tcp = Call(call_id="c1", flow=flow(transport="tcp"))

    assert over_tcp.flow != registered


def test_the_match_survives_the_ue_reusing_the_connection():
    # The connection id identifies the socket, not the transaction.
    registered = flow()

    for _ in range(3):
        assert Call(call_id="c1", flow=flow()).flow == registered


def test_flow_is_hashable_so_it_works_as_a_set_member_or_dict_key():
    assert len({flow(), flow(), flow(cid=0xBEEF)}) == 2
    assert {flow(): "registered"}[flow()] == "registered"


def test_authorising_an_invite_against_the_registered_flow():
    """The shape this exists for."""
    registered_bindings = [flow(cid=0xC0FFEE), flow(cid=0xAAAA)]

    on_registered_connection = Call(call_id="c1", flow=flow(cid=0xC0FFEE))
    assert any(binding == on_registered_connection.flow for binding in registered_bindings)

    on_fresh_connection = Call(call_id="c2", flow=flow(cid=0xDEAD))
    assert not any(binding == on_fresh_connection.flow for binding in registered_bindings)
