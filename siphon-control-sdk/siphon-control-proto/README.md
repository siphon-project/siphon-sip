# siphon-control-proto

Wire-protocol DTOs for the [SIPhon](https://github.com/siphon-project/siphon-sip)
external control plane (`siphon-control.v1`) — an ARI/ESL-class remote-control
rail for driving handed-over B2BUA calls.

This crate is dependency-light on purpose (only `serde` + `serde_json`): it is
the single source of truth for the on-the-wire frames, shared by the SIPhon
server and by every client SDK.

- `CommandFrame` / `ReplyFrame` / `EventFrame` — the JSON frame envelope.
- `ReplyStatus`, `ControlErrorCode`, `ReplyError` — reply status + stable error codes.
- `HelloArgs`, `SUBPROTOCOL`, `PROTOCOL_VERSION` — the handshake contract.
- `verbs` — typed verb / module / event-kind names that serialize to the exact
  wire tokens.

The frame types serialize byte-identically to the server's inline definitions,
so the server can adopt this crate as `use siphon_control_proto as protocol;`
with no wire change.

Higher-level SDKs:

- `siphon-control-client` — async Rust client (connect / serve, request-id
  correlation, `Call` handle, reconnect + resync).
- `siphon-control` — Python bindings (PyO3) over the Rust client.

## License

MIT
