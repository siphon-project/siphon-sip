# siphon-control-client

Async Rust client for the [SIPhon](https://github.com/siphon-project/siphon-sip)
external control plane (`siphon-control.v1`) — an ARI/ESL-class rail for driving
handed-over calls out of process. Hides the wire: no manual JSON, no request-id
bookkeeping, no hand-rolled `rpc()`.

## Layering

- [`ControlClient`] / [`ControlServer`] are the **protocol-agnostic core**:
  transport, `hello`, request-id correlation, reconnect + `resync`, and a generic
  event stream. Their headline primitive is
  `ControlClient::command(module, verb, target, args)`, which works for any
  adapter (`sip`, and future `smpp`/`ss7`) with zero changes.
- [`sip`] is a **typed facade**: [`sip::Call`]'s verbs (`answer`/`hangup`/
  `refer`/…) are thin wrappers over `command("sip", …)`, and the
  `StasisStart`→`Call` dispatch lives there.

## Two connection modes

- **Inbound-persistent** (`SipClient`): the app connects to siphon and keeps one
  long-lived socket (does `hello`).
- **Per-call-connect** (`SipServer`): siphon dials the app per handed-over call
  (the app is a WS server; no `hello`).

```rust
use siphon_control_client::{ClientConfig, sip::SipClient};

# async fn demo() -> Result<(), siphon_control_client::ControlError> {
let client = SipClient::connect(
    ClientConfig::new("ws://siphon:9090/control/ws", "ivr-app", "s3cr3t"),
)
.await?;

client
    .on_call(|call| async move {
        call.answer().await?;
        call.transfer("sip:agent@pbx").await
    })
    .await?;
# Ok(())
# }
```

## `sip::Call` verbs

Every verb the server's `sip` adapter describes has a typed method:

- **Answering:** `answer`, `answer_with`, `answer_anchored` (answer and anchor
  the media on the engine in one act), `ring`, `progress`, `reject`, `hangup`,
  `drop` / `drop_and_ban`.
- **Dialling:** `dial(targets, DialOptions)` rings B-legs while the app keeps the
  channel; a `DialTarget` is a URI or a registered AoR. With
  `DialOnAnswer::bridge()` it rings phones for an answered, anchored caller.
  `cancel_dial(reason)` gives the ringing dial up and leaves the caller as the
  dial found it: the phones are CANCELled and the dial ends in `DialFailed`
  with code 487. `route` hands the call back to siphon with a routing decision.
- **Transfers:** `refer` / `transfer` / `refer_replaces` send a REFER.
  `accept_refer` and `reject_refer` decide a pending inbound one.
  `accept_refer_dialling(target, mode, profile, &TransferDial)` names who the
  transfer dials and what that leg presents: a `TransferTarget` is
  `TransferTarget::uri(..)` or `TransferTarget::aor(..)`, a registered
  address-of-record dialled over the flow its phone registered on with every
  registered contact rung, and `TransferDial` carries `next_hop`, `from`,
  `from_display`, `p_asserted_identity`, `privacy` and `headers`.
  `accept_refer_controller(timeout)` has the server answer `202` and dial
  nothing, leaving the transfer to the app, which then reports with
  `complete_refer(code, reason)`.
- **Replacing a party:** `replace_peer` swaps one leg of an answered call for a
  freshly dialled target with no REFER involved, and `replace_peer_dialling`
  takes the same `TransferTarget` and `TransferDial`.
- **Bridging:** `bridge`, `unbridge`.
- **Media:** `play(PlaySource, PlayOptions)`, `play_file`, `stop`, `dtmf`,
  `hold`, `unhold`. `PlayOptions::repeat` is a total play count, or
  `PlayRepeat::Forever` (`"inf"` on the wire) to play until stopped.
- **Streaming and recording:** `stream_start` / `stream_start_with` /
  `stream_stop` / `stream_stop_with`, `record_start` / `record_stop`.
- **Headers and variables:** `set_header`, `get_header`, `remove_header`,
  `set_var`, `get_var`. `command(verb, args)` is the generic escape hatch.

`SipClient::originate` and `SipClient::originate_aor` place a call.

## Errors

A rejected command maps to `ControlError::Command` carrying the stable
`ControlErrorCode`. `unsupported_verb` (`ControlError::is_unsupported_verb`) is
what a verb answers when the configured media backend cannot carry it out: the
stream and record verbs are siphon-rtp-only, and so is `PlayRepeat::Forever`.

## License

MIT
