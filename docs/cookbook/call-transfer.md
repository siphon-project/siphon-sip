# Call transfer (REFER)

A B2BUA sits between two dialogs, so when one party asks to transfer the call
(a `REFER`, RFC 3515 / 3891 / 5589) siphon has to decide what that means for the
*other* leg. SIPhon gives you three modes, picked per call from a single
`@b2bua.on_refer` handler:

| Mode | What siphon does | Use it for |
|---|---|---|
| **siphon-terminated** *(default)* | Answers `202` + sends the sipfrag `NOTIFY`s itself, re-resolves `Refer-To` through the dial plan as a **new** leg, re-bridges the surviving party, and BYEs the referred-away leg. | Trunk-facing SBCs and media-anchored calls — the endpoints never see the transfer, media stays anchored on siphon. |
| **transparent** | Re-emits the `REFER` on the far leg's own dialog and relays the far end's `202` + `message/sipfrag` `NOTIFY`s back to the referrer. | UA-to-UA / PBX transfers where you want the endpoints to run the transfer themselves. |
| **siphon-originated** | siphon *sends* a `REFER` to a leg — `call.refer(target)` (deferred, from a handler) or `b2bua.refer(call_id, target)` (imperative, from an event callback). | IVR / TAS offload — answer, play a prompt, then hand the caller off. |

With **no** `@b2bua.on_refer` handler registered, siphon rejects every in-dialog
`REFER` on a tracked call locally with `603 Decline` and relays nothing. That is
the loop-safe default: an in-dialog `REFER` on a bridged call must never be blind
proxy-relayed (it can loop back through the B2BUA), so you opt in to transfer
handling by registering the handler.

!!! warning "`@b2bua.on_refer` takes ONE argument"
    The handler is `def on_refer(call):` — **one argument, no `reply` object**. A
    `REFER` is a *request*, not a response, so there is nothing to answer with
    `rtpengine.answer(reply)`. Writing `def on_refer(call, reply):` and calling
    `rtpengine.answer(reply)` — the reflex from the `@b2bua.on_early_media` /
    `@b2bua.on_answer` handlers — is wrong here and will fail at call time. Read
    the transfer target off the `call` object (`call.refer_to`,
    `call.refer_replaces`) and act with `call.accept_refer()` /
    `call.reject_refer()`.

## The `call` object during a REFER

```python
call.refer_to        # str | None  — the Refer-To URI
call.refer_replaces  # dict | None — attended-transfer Replaces target, keys:
                     #   {"call_id": str, "from_tag": str,
                     #    "to_tag": str, "early_only": bool}

call.accept_refer(target=None, next_hop=None, mode=None)
    # Accept the transfer.
    #   target=   rewrite the destination (default: call.refer_to verbatim)
    #   next_hop= steer egress without changing the R-URI shape
    #   mode=     "terminate" | "transparent" | None
    #             None -> b2bua.default_refer_mode (config; default "terminate")
call.reject_refer(code, reason)      # decline the transfer (e.g. 603 Decline)
```

Config default for `mode=None`:

```yaml
# siphon.yaml
b2bua:
  default_refer_mode: terminate    # terminate | transparent  (default terminate)
```

Throughout the ladders below: **Alice** `sip:alice@example.com` (A-leg),
**Bob** `sip:bob@example.com` (B-leg), transfer target **Carol**
`sip:+15550142@example.com`, siphon at `198.51.100.1`.

## 1. Inbound blind transfer, siphon-terminated

Alice and Bob are bridged by siphon with media anchored. Alice's phone starts a
blind transfer to Carol — it sends a `REFER` (`Refer-To: Carol`) inside the
Alice-leg dialog. siphon answers it itself, dials Carol as a fresh leg, bridges
Bob onto Carol, and drops Alice.

```python
from siphon import b2bua, log

@b2bua.on_refer
def on_refer(call):
    log.info(f"[{call.id}] blind transfer to {call.refer_to}")
    call.accept_refer()          # siphon-terminated (the config default)
```

!!! warning "One argument, no reply"
    The handler is `def on_refer(call):` — one argument, no reply object
    (`REFER` is a request).

```text
Alice (A-leg)            siphon 198.51.100.1            Bob (B-leg)      Carol (target)
     |                          |                            |                |
     |<===== bridged, media anchored on siphon =============>|                |
     |                          |                            |                |
     |  REFER Refer-To:Carol    |                            |                |
     |------------------------->|                            |                |
     |  202 Accepted            |                            |                |
     |<-------------------------|                            |                |
     |  NOTIFY sipfrag 100      |   (accept_refer default)   |                |
     |<-------------------------|                            |                |
     |                          |  INVITE (new leg)          |                |
     |                          |------------------------------------------->|
     |                          |            200 OK                          |
     |                          |<-------------------------------------------|
     |                          |  ACK                                       |
     |                          |------------------------------------------->|
     |                          |  re-INVITE (re-bridge)     |                |
     |                          |<==========================>|                |
     |  NOTIFY sipfrag 200 OK   |                            |                |
     |<-------------------------|                            |                |
     |  BYE (referred away)     |                            |                |
     |<-------------------------|                            |                |
     |  200 OK                  |         Bob <===== bridged =====> Carol     |
     |------------------------->|                            |                |
```

Rewrite the destination or steer egress without touching what the endpoints see:

```python
@b2bua.on_refer
def on_refer(call):
    # Send the new leg to a specific trunk, keep the dialled URI shape intact.
    call.accept_refer(target="sip:+15550142@example.com",
                      next_hop="sip:trunk.example.com:5060")
```

### Media anchoring (terminate mode)

Terminate mode re-bridges the media plane by offering the **surviving** party's
media to the transfer target and re-INVITEing the survivor with the target's
answer (RFC 3261 §14), so both directions of RTP follow the transfer:

- **Media-anchored** (the call was anchored with rtpengine or siphon-rtp): siphon
  re-anchors the survivor↔target pair on a fresh media session — it offers the
  survivor's media to the target through the anchor, answers with the target's
  SDP, re-INVITEs the survivor onto the anchored session, and tears down the old
  survivor↔referrer anchor. The anchor stays in the media path across the
  transfer (LI, transcoding, NAT preserved). This is the normal production shape.
- **Not anchored** (a raw B2BUA where the endpoints exchange their own SDP): siphon
  offers the survivor's real SDP to the target and re-INVITEs the survivor with
  the target's answer, so media is aimed correctly end to end.

siphon also owns the SDP `o=` line per leg (a stable session-id with a monotonic
version), so a re-anchor presents a strictly greater version under the same
session identity and a strict RFC 3264 §8 answerer re-negotiates cleanly rather
than treating a changed offer as unchanged.

> The signalling plane (202, sipfrag NOTIFYs, dialog identity, teardown) is
> correct in every mode. In-repo tests cover the signalling and — for anchored
> transfers — that the media-control commands are issued; that RTP actually
> bridges survivor↔target through the anchor is validated against a real media
> engine.

## 2. Inbound attended transfer (Replaces)

Attended transfer: Alice consults Carol on a second call first, then transfers
Bob into the Alice-Carol call with a `REFER` carrying a `Replaces` header
(RFC 3891) that names the Alice-Carol dialog. siphon reads it off
`call.refer_replaces`, matches the dialog it is **already tracking**, bridges Bob
onto it, and BYEs the now-redundant old legs.

```python
from siphon import b2bua, log

@b2bua.on_refer
def on_refer(call):
    replaces = call.refer_replaces
    if replaces:
        log.info(f"[{call.id}] attended transfer replacing "
                 f"call_id={replaces['call_id']} "
                 f"from_tag={replaces['from_tag']} to_tag={replaces['to_tag']} "
                 f"early_only={replaces['early_only']}")
    call.accept_refer()          # siphon matches the replaced dialog + re-bridges
```

!!! warning "One argument, no reply"
    The handler is `def on_refer(call):` — one argument, no reply object
    (`REFER` is a request).

```text
Alice                    siphon 198.51.100.1            Bob            Carol
  |                          |                           |               |
  |<==== call 1: Alice <-> Bob (bridged) ===============>|               |
  |<==== call 2: Alice <-> Carol (consult, tracked) =====================>|
  |                          |                           |               |
  |  REFER Refer-To:Carol    |                           |               |
  |  Replaces=call2 dialog   |                           |               |
  |------------------------->|                           |               |
  |  202 Accepted            |  match Replaces -> call 2 |               |
  |<-------------------------|                           |               |
  |                          |  re-bridge Bob <-> Carol  |               |
  |                          |<==========================|==============>|
  |  NOTIFY sipfrag 200 OK   |                           |               |
  |<-------------------------|                           |               |
  |  BYE (call 1, Alice)     |     BYE (call 2, Alice)   |               |
  |<-------------------------|-------------------------->|               |
  |                          |         Bob <==== bridged ====> Carol     |
```

`early_only` is set when the `Replaces` header carried the `early-only`
parameter — the transfer must only match a dialog still in an early (pre-2xx)
state (RFC 3891 §3). siphon honours it when matching.

## 3. Inbound transparent transfer

Let the endpoints run the transfer. siphon re-emits the `REFER` on the far leg's
own dialog and relays the far end's `202` and `message/sipfrag` `NOTIFY`s back to
the referrer. Nothing is re-resolved locally — good for UA-to-UA or PBX
deployments where the far side owns the transfer logic.

```python
from siphon import b2bua

@b2bua.on_refer
def on_refer(call):
    call.accept_refer(mode="transparent")
```

!!! warning "One argument, no reply"
    The handler is `def on_refer(call):` — one argument, no reply object
    (`REFER` is a request).

```text
Alice (A-leg)            siphon 198.51.100.1            Bob (B-leg)
     |                          |                            |
     |<===== bridged ==========>|<========= bridged =========>|
     |                          |                            |
     |  REFER Refer-To:Carol    |                            |
     |------------------------->|  REFER (re-emit on B dialog)|
     |                          |--------------------------->|
     |                          |  202 Accepted              |
     |  202 Accepted            |<---------------------------|
     |<-------------------------|                            |
     |                          |  NOTIFY sipfrag 100/200    |
     |  NOTIFY sipfrag 100/200  |<---------------------------|
     |<-------------------------|                            |
     |          (Bob's UA now places the call to Carol itself)
```

## 4. No handler, or an explicit reject

With **no** `@b2bua.on_refer` handler registered, siphon answers every in-dialog
`REFER` on a tracked call with `603 Decline` locally and egresses nothing — the
loop-safe default. You never have to write anything to be safe.

To allow transfers only from a trusted source and decline the rest, register a
handler and call `reject_refer`:

```python
from siphon import b2bua

@b2bua.on_refer
def on_refer(call):
    if not call.from_gateway("trusted-pbx"):
        call.reject_refer(603, "Decline")     # same wire result as no handler
        return
    call.accept_refer()
```

!!! warning "One argument, no reply"
    The handler is `def on_refer(call):` — one argument, no reply object
    (`REFER` is a request).

```text
Alice (A-leg)            siphon 198.51.100.1
     |                          |
     |  REFER Refer-To:Carol    |
     |------------------------->|
     |  603 Decline             |   (no handler, or reject_refer(603,...))
     |<-------------------------|     nothing egresses to the far leg
     |  ACK                     |
     |------------------------->|
```

## 5. Outbound: IVR / TAS offload

siphon can also *originate* a `REFER`. Answer the call, play a prompt, then hand
the caller off to Carol by REFER-ing the caller's own leg — siphon drops out and
the caller reaches Carol directly.

Two entry points:

- `call.refer(target, replaces=None)` — **deferred**, from a `@b2bua.*` handler
  where you hold a `call`. siphon sends the REFER when the handler returns.
- `b2bua.refer(call_id, target, replaces=None)` — **imperative twin**, for event
  callbacks that get a `call_id` but no `call` object, e.g. `@rtpengine.on_dtmf`.

!!! warning "Still no reply object"
    This is the outbound path — siphon *sends* the REFER, so there is no inbound
    `@b2bua.on_refer` here. When you *do* handle an inbound REFER (scenarios 1-4),
    remember the handler is `def on_refer(call):` — one argument, no reply object
    (REFER is a request).

```python
from siphon import b2bua, rtpengine

@b2bua.on_invite
async def on_invite(call):
    call.answer(200, "OK")                                    # siphon owns the leg
    await rtpengine.play_media(call, file="/var/lib/siphon/prompts/menu.wav")

@rtpengine.on_dtmf
def on_dtmf(call_id, from_tag, digit, duration_ms, volume):
    if digit == "1":
        # Imperative — no `call` in scope here, only a call_id.
        b2bua.refer(call_id, "sip:+15550142@example.com")
```

```text
Caller (Alice)           siphon 198.51.100.1            Carol (target)
     |                          |                            |
     |  INVITE                  |                            |
     |------------------------->|                            |
     |  200 OK (siphon answers) |                            |
     |<-------------------------|                            |
     |<===== prompt / IVR media (rtpengine.play_media) ======|
     |                          |                            |
     |  RTP DTMF "1"            |                            |
     |------------------------->|  b2bua.refer(call_id, Carol)|
     |  REFER Refer-To:Carol    |                            |
     |<-------------------------|                            |
     |  202 Accepted            |                            |
     |------------------------->|                            |
     |          (Alice's UA now places the call to Carol itself)
     |  INVITE ------------------------------------------------>|
```

The **deferred** form reads the same but fires from a handler that already holds
the `call`. Use it when a transfer decision is made at answer time rather than on
a later event:

```python
@b2bua.on_answer
def on_answer(call, reply):
    # Deferred: siphon sends the REFER once the leg is up and the handler returns.
    call.refer("sip:+15550142@example.com")
```

Pass `replaces=` (a dict with `call_id` / `from_tag` / `to_tag`, optionally
`early_only`) to originate an **attended** transfer that replaces a specific
dialog.

## 6. Proxy mode (passthrough)

Everything above is B2BUA (`@b2bua.*`). In **proxy** mode there is nothing to do:
a REFER is an ordinary in-dialog request, so as long as siphon record-routed the
dialog-forming INVITE it loose-routes the REFER to the far end and relays the far
end's `202` + `message/sipfrag` NOTIFYs straight back. The transfer subscription
lives directly between the two endpoints; siphon owns no transfer state and the
`@b2bua.on_refer` handler never fires. The default proxy script already does this
with the generic in-dialog branch:

```python
@proxy.on_request
def route(request):
    # ... out-of-dialog handling (auth, registrar lookup, record_route) ...
    if request.in_dialog:
        if request.loose_route():
            request.relay()       # REFER, NOTIFY, BYE all take this path
        else:
            request.reply(404, "Not Here")
        return
```

```
  Alice (referrer)            siphon (proxy)              Bob (transferee)
     |  INVITE (record-route)    |                            |
     |-------------------------->|--------------------------->|
     |         200 OK / ACK      |     200 OK / ACK           |
     |<========================>|<==========================>|
     |  REFER (Route: siphon)    |                            |
     |-------------------------->|  loose-route to Bob        |
     |                           |--------------------------->|
     |         202 Accepted      |         202 Accepted       |
     |<--------------------------|<---------------------------|
     |     NOTIFY sipfrag ...     |     NOTIFY sipfrag ...      |
     |<--------------------------|<---------------------------|
     |          BYE / 200        |          BYE / 200         |
     |<========================>|<==========================>|
```

The REFER is loose-routed to the far end **exactly once** and never proxy-relayed
by Request-URI, so it cannot loop (this is the failure that motivated intercepting
REFER on tracked B2BUA calls in the first place). siphon does not re-anchor media
or re-resolve `Refer-To` in proxy mode; if you need any of that, run the call
through the B2BUA and use one of the modes above.

## See also

- [SBC (B2BUA)](sbc.md) — the `@b2bua.*` handlers and the `call` object.
- [Media & RTP profiles](media-rtp.md) — anchoring media so a siphon-terminated
  transfer keeps the media path on siphon, and `@rtpengine.on_dtmf`.
- [Call reference](../reference/call.md) — the full `call` API.
