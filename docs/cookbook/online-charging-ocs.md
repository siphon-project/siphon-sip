# Online charging (Diameter Ro / OCS)

Prepaid charging talks to an **Online Charging System** over Diameter Ro
(Credit-Control, RFC 8506 / 3GPP TS 32.299). For a voice call siphon **reserves**
credit at setup, **re-authorizes** on the quota the OCS grants, and **cuts the
call** when the OCS refuses further credit. For SMS/RCS it debits per message
before delivery. This works against [CGRateS](https://cgrates.org) out of the box.

Two models, both standards-defined:

| Service | Model | Flow |
|---------|-------|------|
| Voice | **SCUR** (session, reserve units) | CCR-INITIAL → CCR-UPDATE… → CCR-TERMINATION |
| SMS / RCS | **IEC** (one-shot debit) | CCR-EVENT (`Requested-Action = DIRECT_DEBITING`) |

The re-auth mechanism, the timer, and the mid-call disconnect are all Rust-side;
your script supplies the *policy* — whether to charge the call at all, which
subscriber, and what to answer on a denial. The gate is **reserve-before-connect**:
a `@b2bua.on_invite` handler calls `await call.ro_authorize()` *before*
`call.dial()`, so the B-leg is never dialed unless the OCS grants credit.

> **Ro is B2BUA-only.** Enforcement — actually *cutting the call* when credit
> runs out — needs siphon to own and be able to tear down the session, which is
> a B2BUA capability. This matches 3GPP: online charging is triggered by the
> **AS / MMTel-AS** (TS 32.275), never by the P-CSCF (a P-CSCF is an *offline*/Rf
> node). So run the charging siphon as a **B2BUA** (e.g. an MMTel-AS on ISC).
> (The one-shot SMS/RCS IEC debit below has no session to tear down, so you can
> drive it from a `@proxy.on_request` handler via the scripting API — but voice
> enforcement is B2BUA.)

## Config

Point a Diameter route at your OCS and turn on `ro:`.

```yaml
# siphon.yaml
diameter:
  origin_host: "siphon.ims.example.org"
  origin_realm: "ims.example.org"
  peers:
    - name: ocs1
      host: "10.0.0.30"
      port: 3868
      destination_realm: "cgrates.org"
  routes:
    - application: ro          # advertises Auth-Application-Id 4 in the CER
      peers: ["ocs1"]

ro:
  enabled: true
  reauth_interval_secs: 30     # fallback cadence; the OCS-granted quota wins
  requested_seconds: 30        # Requested-Service-Unit CC-Time (0 = empty RSU, OCS decides)
  service_context_id: "32260@3gpp.org"        # voice (32275 for MMTel-AS supplementary services)
  sms_service_context_id: "32274@3gpp.org"    # SMS / RCS
  node_functionality: as       # AS/MMTel-AS is the standard Ro trigger
  charge: orig                 # orig | term | both
  on_ocs_failure: terminate    # fail-closed; `continue` = fail-open (allow, uncharged)
  credit_denied_status: 402    # SIP status a script returns when denied at setup
  rating_group: 100            # optional; its presence selects the MSCC (multi-service) shape
  peer: ocs1                   # optional explicit OCS peer
```

## Voice — the reserve-before-connect gate

Reserve credit in `@b2bua.on_invite` **before** dialing the B-leg. A grant
dials; a denial rejects and no B-leg is ever created. After a grant siphon runs
the whole SCUR lifecycle itself — CCR-UPDATE on the OCS-granted cadence, mid-call
disconnect on `4012 CREDIT_LIMIT_REACHED`, CCR-TERMINATION on BYE — so the
handler is just the gate:

```python
from siphon import b2bua, log

@b2bua.on_invite
async def route(call):
    decision = await call.ro_authorize()      # CCR-INITIAL, before any B-leg
    if not decision["authorized"]:
        # 4012 no balance, OCS unreachable (fail-closed), etc.
        call.reject(402, "Payment Required")
        return
    log.info(f"reserved {decision['granted_time']}s, session {decision['session_id']}")
    call.dial(str(call.ruri))                 # credit reserved → connect
```

`call.ro_authorize()` returns `{"authorized": bool, "result_code": int|None,
"granted_time": int|None, "session_id": str|None}`. The charged party defaults to
the `ro.charge` config (orig = caller, term = callee); pass
`subscription_id="+31…"` / `subscription_id="sip:alice@…"` to override it (a
`sip:` URI is typed as a SIP URI, never mislabeled as an E.164 MSISDN). Rating
group, requested quota and Service-Context come from the `ro:` config block.
`4011 CREDIT_CONTROL_NOT_APPLICABLE` returns `authorized: True` with no session
(the call runs free of charge). Skip the `ro_authorize()` call entirely for calls
you don't want charged.

### Manual CCR (advanced)

For full control — your own re-auth loop, non-standard subscriber handling — the
raw client is available in any mode and is **async** (`await`):

```python
answer = await diameter.ro_ccr_initial(
    call.from_uri, subscription_id_type="sip",
    requested_seconds=30, rating_group=100,
    calling_party=call.from_uri, called_party=call.to_uri,
    sip_method="INVITE", role_of_node="originating", node_functionality="as",
)
sid = answer["session_id"]
# … later, on your own cadence …
await diameter.ro_ccr_update(call.from_uri, sid, 1, used_seconds=30, requested_seconds=30)
await diameter.ro_ccr_terminate(call.from_uri, sid, 2, used_seconds=12)
```

`ro_ccr_initial` returns `{result_code, session_id, request_number,
granted_time, validity_time, final_unit_action}` (or `None` when no OCS peer is
connected). Prefer `call.ro_authorize()` — it stores the session Rust-side and
runs the re-auth + teardown for you.

## Script control (SMS / RCS — one-shot IEC)

Charge a page-mode `MESSAGE` before relaying it, and reject with `402` when the
balance is empty:

```python
from siphon import proxy, diameter

@proxy.on_request("MESSAGE")
async def on_message(request):
    answer = await diameter.ro_ccr_event(
        request.from_uri,
        subscription_id_type="sip",
        service_context_id="32274@3gpp.org",     # SMS charging (TS 32.274)
        originator_address=request.from_uri,
        recipient_address=request.to_uri,
        sm_message_type=0,                        # submission
    )
    if answer and answer["result_code"] == 2001:
        request.relay()                           # debited → deliver
    else:
        request.reply(402, "Payment Required")    # no balance → reject
```

## CGRateS DiameterAgent

CGRateS runs self-contained (`data_db`/`stor_db` = `*internal`). A minimal
`diameter_agent` request-processor for the voice CCR (grant the account's
balance as CC-Time, deny with `4012` when it hits zero):

```json
{
  "diameter_agent": {
    "enabled": true, "listen": ":3868", "listen_net": "tcp",
    "origin_host": "cgrates.org", "origin_realm": "cgrates.org",
    "sessions_conns": ["*birpc_internal"],
    "request_processors": [{
      "id": "ro_initial",
      "filters": ["*string:~*vars.*cmd:CCR", "*string:~*req.CC-Request-Type:1"],
      "flags": ["*initiate", "*accounts"],
      "request_fields": [
        {"tag": "ToR", "path": "*cgreq.ToR", "type": "*constant", "value": "*voice"},
        {"tag": "OriginID", "path": "*cgreq.OriginID", "type": "*variable", "value": "~*req.Session-Id"},
        {"tag": "Account", "path": "*cgreq.Account", "type": "*variable",
         "value": "~*req.Subscription-Id.Subscription-Id-Data"},
        {"tag": "RequestType", "path": "*cgreq.RequestType", "type": "*constant", "value": "*prepaid"},
        {"tag": "Usage", "path": "*cgreq.Usage", "type": "*variable",
         "value": "~*req.Multiple-Services-Credit-Control.Requested-Service-Unit.CC-Time"}
      ],
      "reply_fields": [
        {"tag": "CCA", "type": "*template", "value": "*cca"},
        {"tag": "GrantedUnits",
         "path": "*rep.Multiple-Services-Credit-Control.Granted-Service-Unit.CC-Time",
         "type": "*variable", "value": "~*cgrep.MaxUsage{*duration_seconds}"},
        {"tag": "ResultCode", "filters": ["*eq:~*cgrep.MaxUsage:0"],
         "path": "*rep.Result-Code", "type": "*constant", "value": "4012", "blocker": true}
      ]
    }]
  }
}
```

Seed a 30-second voice balance with one JSON-RPC call — no rating CSVs needed:

```bash
curl -s http://cgrates:2080/jsonrpc -d '{"method":"ApierV2.SetBalance",
  "params":[{"Tenant":"cgrates.org","Account":"sip:alice@ims.example.org",
  "BalanceType":"*voice","Value":30000000000}],"id":1}'
```

## Observability

`siphon_ro_sessions` gauges live credit-control sessions (CCR-INITIAL without a
matching CCR-TERMINATION); under a steady completed-call workload it returns to
~0. Alert on it climbing while call rate is flat — that's a charging-session
leak.
