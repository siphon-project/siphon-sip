# Migrating to 1.13.0

1.13.0 changes nothing in the Python scripting API's signatures and no
`siphon.yaml` key stops working. It does break the **Rust library API** in a few
places, and it changes what siphon puts on the wire in several, all toward what
RFC 3261 says. This page lists both: what an embedder has to change, and what an
operator should check against a running deployment.

The full list is in the 1.13.0 changelog entry.

## Rust library

Only relevant when you link `siphon-sip` as a crate.

| What | Change |
|---|---|
| `transaction::state::Action` | New variant `SendCancel`. An exhaustive `match` needs an arm: send `cancel.frame` to `cancel.hop`, the way the `SendFrame` arm sends a retransmission. |
| `proxy::fork::ForkAction` | New variant `ForwardAnother2xx`: a 2xx from a second branch, to be forwarded upstream (RFC 3261 §16.7 step 5). |
| `transaction::timer::TimerName` | New variant `C`. `IctEvent` gains `TimerC`, `TimerConfig` gains `timer_c_secs`. |
| `ReferSubscription::target_leg_call_id` | Replaced by `targets`, one record per INVITE keyed by Via branch. |
| `b2bua_complete_terminated_transfer`, `b2bua_fail_terminated_transfer` | Take the Via branch of the target's INVITE instead of a leg index. The first also takes the source the 2xx came from. |
| `DelayedOfferAck::b_leg_index` | Replaced by `branch`. `b2bua_fail_after_answer` takes a branch. |

An embedder that creates INVITE client transactions itself should record where
each INVITE went (`BranchHop`), so the CANCEL and the ACK of a failed branch
leave the same way.

## Rust control SDK

`siphon-control-proto` and `siphon-control-client` 0.8.0:

- `PlayOptions::repeat` is `Option<PlayRepeat>`. A count converts with `.into()`.
- `PlaySource` has two more variants (`Tone`, `Url`), and `PlayOptions` and
  `TransferDial` have more public fields. An exhaustive `match`, or a struct
  literal without `..Default::default()`, needs the addition.

The Python and TypeScript SDKs only gain arguments.

## Behaviour to check on a running deployment

### CANCEL

siphon no longer sends a CANCEL for an INVITE that has drawn no response (RFC
3261 §9.1). It keeps retransmitting the INVITE and sends the CANCEL on the first
provisional, on the proxy and on the B2BUA. A far end that never sends `100
Trying` and relied on an immediate CANCEL now sees the INVITE retransmitted
until Timer B.

A proxy CANCEL carries the branch's own Request-URI and Route set, not the
caller's, and only `Reason` is relayed from the caller's CANCEL.

### A second 2xx reaches the caller

The proxy forwards every 2xx to an INVITE, also one that arrives after another
branch answered, after the caller cancelled or after a script rejected (RFC 3261
§16.7 step 5). The caller's user agent is what ACKs and BYEs the extra dialog.
`@proxy.on_reply` does not run for such a 2xx and it is not an answer for CDR or
Rf.

### Ringing on a proxied call

`transaction.invite_timeout_secs` no longer ages a session that still has a
branch ringing. A proxied call that rang past it (32 s by default) used to lose
its session without a word to either side. Ringing is now bounded by Timer C,
`transaction.timer_c_secs`, 181 s by default. When it fires the branch is
cancelled and `@proxy.on_failure` runs.

`@proxy.on_failure` now also runs for a `487` the caller did not ask for. A
handler that treated every `487` as "the caller hung up" should use
`@proxy.on_cancel` for that.

### CDRs

A proxied call the caller cancels, or a script rejects, now gets its CDR: one
`487` record per cancelled call and one record per rejected call. A collector
that counted records as answered calls needs to look at `response_code`.

### Media source hints (`received_from`)

Whether a party's media ingress is pinned to its signalling source is now read
from that party's own half of the profile, on every command. Profiles that carry
the same policy on both halves are unaffected. For the others:

- A callee's re-INVITE or UPDATE is pinned by the `answer` half, the caller's by
  the `offer` half, whoever re-offers.
- `rtpengine.answer(reply)` stamps the address the reply came from. With
  `call=` it used to stamp the caller's address on the callee's SDP, and without
  it nothing. A callee that sends media from another host than it signals from,
  under a profile with `received_from` on the `answer` half, is now gated.

A re-offer is also shaped for the party it is sent to. With a direction-bound
profile (`srtp_to_rtp`, `rtp_to_srtp`) a hold from the callee used to reach the
caller in the callee's transport.

### Control plane

- The reply to `cancel_dial` arrives after `DialFailed`, once the dial has let
  go of the caller.
- A REFER that arrives while a transfer is in flight on its call is answered
  `491`. A retransmitted REFER gets the response it already got.
- `play` answers `bad_request` for an argument of the wrong type, where it used
  to play once and answer `ok`.
- `hold` on a call the engine only relays answers `invalid_state`.
- `route` is refused while a `dial` still rings.
- `accept_refer` with `timeout` in a mode other than `controller` is
  `bad_request`.
- A leg parted by `unbridge` that sends a changed offer is answered `488`.
  Bridge it again first.
