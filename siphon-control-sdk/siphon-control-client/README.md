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

A rejected command maps to `ControlError::Command` carrying the stable
`ControlErrorCode`. The WebSocket-tee verbs (`stream_start`/`stream_stop`) are
siphon-rtp-only, so a non-siphon-rtp backend answers `unsupported_verb`
(`ControlError::is_unsupported_verb`).

## License

MIT
