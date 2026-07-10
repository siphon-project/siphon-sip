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
Path-token MT routing.

::: siphon_sdk.types.Flow

## `Action`

The record the test harness captures for each action a handler takes (reply,
relay, fork, reject, …). Scripts do not create these; assertions read them.

::: siphon_sdk.types.Action
