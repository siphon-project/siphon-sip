# SIP types

Small value objects that flow through the scripting API: parsed URIs, contact
bindings, the captured inbound flow, and the action record the test harness
uses to report what a handler did.

## `SipUri`

A parsed SIP / SIPS / tel URI. Reachable via `request.ruri`, `request.from_uri`,
`request.to_uri`, and `Contact.uri` parsing.

::: siphon_sdk.types.SipUri

## `Contact`

A registered contact binding returned by `registrar.lookup(...)`.

::: siphon_sdk.types.Contact

## `Flow`

An opaque view of the inbound flow captured at REGISTER time, used for
Path-token MT routing and for RFC 5626 connection reuse.

Flows compare by value and hash, so a call can be authorised by matching it
against the connection the registration arrived on, rather than by challenging
every INVITE with a 407:

```python
@b2bua.on_invite
def on_invite(call):
    bindings = registrar.lookup(str(call.from_uri))
    if any(contact.flow == call.flow for contact in bindings):
        call.dial(str(call.ruri))       # same connection as the REGISTER
    else:
        call.reject(403, "Forbidden")
```

Equality covers the transport, both addresses and the connection id together.
On a stream transport (TCP/TLS/WS/WSS) that is an exact match on one accepted
socket, which is why it is worth doing: a source-address check is worthless
behind carrier NAT, where every subscriber on the network shares an address. On
UDP there is no connection, so a flow carries no more assurance than the address
does — treat it as a hint, not authorisation.

The match survives the UE reusing the connection across many calls: the
connection id identifies the socket, not the transaction.

::: siphon_sdk.types.Flow

## `Action`

The record the test harness captures for each action a handler takes (reply,
relay, fork, reject, …). Scripts do not create these; assertions read them.

::: siphon_sdk.types.Action
