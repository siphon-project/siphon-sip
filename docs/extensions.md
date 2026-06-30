# Extensions (SMPP, …)

SIPhon's core speaks SIP. Protocol functionality **beyond SIP** — SMPP today,
HTTP route serving planned — is provided by **opt-in extension modules**. They
are not part of the default binary: you enable a module at build time and
configure it through the `extensions:` block in `siphon.yaml`. Each module adds
a scriptable Python namespace your routing scripts can use, alongside the
built-in `proxy`, `registrar`, `cache`, and friends.

## How extensions work

- **Off by default.** The standard `siphon` binary (`cargo install siphon-sip`
  or the default container image) contains no extensions.
- **Enabled at build.** An extension-capable build is produced by the
  [`siphon-bin`](https://github.com/siphon-project/siphon-sip/tree/main/siphon-bin)
  package with the module's cargo feature turned on (e.g. `--features smpp`). It
  is a drop-in `siphon` binary — same CLI, same `siphon.yaml`, plus the module.
- **Configured in `siphon.yaml`.** An `extensions:` map points each enabled
  module at its own config file:

  ```yaml
  extensions:
    smpp: /etc/siphon/smpp.yaml
  ```

- **Loud on mismatch.** If `extensions.smpp` is configured but the running
  binary was *not* built with that feature, siphon logs a warning and skips the
  module — it never silently ignores configuration. (This mirrors the optional
  `sctp` transport feature.)

## SMPP (SMS, SMPP 3.4)

The SMPP extension turns siphon into a scriptable SMPP node — it accepts ESME
binds and can hold outbound binds to upstream SMSCs. Your script decides policy;
siphon handles the wire protocol, sessions, timers, and windowing.

### 1. Build with the feature

```bash
# Native binary
cargo build -p siphon-bin --release --features smpp

# …or a container image (mount your config + script at runtime)
docker build -f siphon-bin/Dockerfile -t siphon-smpp siphon-bin/
```

### 2. Point siphon at the SMPP config

```yaml
# siphon.yaml
extensions:
  smpp: /etc/siphon/smpp.yaml
```

The `smpp.yaml` schema (inbound listener, outbound binds, routing) is documented
in the siphon-smpp repository.

### 3. Handle PDUs in your script

```python
from siphon import smpp, log

@smpp.on_bind
async def authorise(bind):
    log.info(f"bind from {bind.system_id}")
    return bind.accept()

@smpp.on_pdu("submit_sm")
async def handle(pdu, session):
    log.info(f"{pdu.source_addr} -> {pdu.destination_addr}")
    # ...route / persist / throttle...
    return pdu.reply(message_id="abc123")
```

Scripts hot-reload exactly like the SIP side — edit and the next PDU uses the new
code.

### Further reading

The full `smpp` namespace (PDU types, bind handling, outbound `submit`/`deliver`,
delivery receipts), the complete `smpp.yaml` schema, and deployment examples live
in the **siphon-smpp** repository:

➡️ <https://github.com/siphon-project/siphon-smpp>

## Available and planned modules

| Module | Feature | Status | Namespace |
| --- | --- | --- | --- |
| SMPP 3.4 | `smpp` | Available | `smpp` |
| HTTP route serving | `http` | Planned | `http` |
