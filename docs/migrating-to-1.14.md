# Migrating to 1.14.0

1.14.0 brings the N5 (Npcf_PolicyAuthorization) and Nbsf_Management clients
and the flow descriptions on Rx and N5 in line with TS 29.514, TS 29.521 and
TS 29.214. One call in the Python scripting API now refuses what it accepted,
the Rust library API changes in two places, and several things change on the
wire. No `siphon.yaml` key stops working.

The full list is in the 1.14.0 changelog entry.

## Python scripting API

`sbi.create_session` needs a callback URI. `notifUri` is a required attribute
of the create, and it used to be left out unless the script passed
`notif_uri=`. A create with no callback URI now raises `ValueError` before
anything is sent.

Set the new key once and no script has to change:

```yaml
sbi:
  notif_listen: "0.0.0.0:8080"
  notif_uri: "http://192.0.2.10:8080/sbi/events"
```

`notif_uri=` on a call still works and overrides the key. A script test built
on the SDK mock gets the same behaviour: call `sbi.set_notif_uri(...)` in its
setup, or pass `notif_uri=`.

`sip_call_id=` is still accepted. It is no longer sent to the PCF (TS 29.514
has no such attribute) and shows up in siphon's own log lines for the create.

`role_of_node=` on `diameter.ro_ccr_*` and `diameter.rf_acr_*` takes
`"originating"`, `"terminating"` or `"forwarding"` (TS 32.299 V18 clause
7.2.177). `"proxy"` and `"b2bua"` raise `ValueError`: they sent 2 and 3, and
in Release 18 2 is FORWARDING_ROLE and 3 does not exist. Drop the argument to
send the session case of the request, or pass the role the node serves.

## Rust library

Only relevant when you link `siphon-sip` as a crate.

| What | Change |
|---|---|
| `sbi::npcf::AppSessionContextReqData::sip_call_id` | Removed. Drop it from the struct literal. |
| `sbi::npcf::AppSessionContextReqData::supp_feat` | `None` serialises as `"suppFeat":"0"`; the member was left out before. |
| `script::api::sbi::PySbi::new` | Takes a fourth argument, the configured callback URI (`Option<String>`). |
| `config::SbiYamlConfig` | New field `notif_uri`. |
| `diameter::DiameterClient::send_sar` | Takes a `cx::ServerAssignment` (public identity, optional User-Name, Server-Name, assignment type) where it took three arguments. |
| `diameter::cx::build_maa_success` | Takes the private identity before the public one and answers with Result-Code 2001. |
| `diameter::ro::NodeRole` | `ProxyRole` and `B2buaRole` are removed; `ForwardingRole` is new and is 2. Use the role the node serves. |
| `dispatcher::ro_authorize_b2bua` | Takes a fifth argument, the Role-Of-Node override (`Option<NodeRole>`); `None` sends the session case. |
| `diameter::cx::build_saa_success`, `build_lia_success`, `build_rta` | Answer with Result-Code 2001 where they carried Experimental-Result 2001. |

## On the wire: check before upgrading

| Interface | Before | Now |
|---|---|---|
| Rx `Flow-Description`, N5 `fDescs` | `permit out` from the UE, `permit in` to the UE | `permit in` from the UE (uplink), `permit out` to the UE (downlink), per TS 29.214 clause 5.3.8 |
| N5 create | no `suppFeat`, `notifUri` only when passed, `sipCallId` present | `suppFeat` `"0"`, `notifUri` always, no `sipCallId` |
| Nbsf discovery, IPv6 | `ipv6Prefix=<address>/64` | `ipv6Prefix=<address>/128` |
| Nbsf discovery, answer 204 | raised `sbi.BsfError` | no binding (`None`), as for 404 |
| Cx MAR of `auth.require_ims_digest`, `Public-Identity` | URI of P-Asserted-Identity, else of From | URI of the To header, per TS 24.229 clause 5.4.1.2.1 |
| Outbound TCP connection with a request pending on it | closed after 30 s of silence | kept until the client transaction ends, then closed after 30 s of silence |
| Outbound TCP connection from an IPsec protected port | closed after 30 s of silence | kept until the UE closes it, an error or the socket keepalive ends it; reset, not closed with a FIN, when siphon ends it |
| Ro CCRs of `call.ro_authorize()`, Rf ACRs of `rf.auto_emit_b2bua`, `Role-Of-Node` | 3 (B2BUA_ROLE) | the session case of the A-leg INVITE: 0 originating, 1 terminating, 2 forwarding (`sescase=orig-cdiv`), per TS 32.299 V18 clause 7.2.177 |
| Response whose TCP or TLS connection has closed | new connection to the source port of the request | new connection to the port in the `sent-by` of the Via (5060, or 5061 for TLS, when it has none), per RFC 3261 clause 18.2.2 |

The flow descriptions are the one to test against the policy function in use.
One that follows the specification built its packet filters reversed with the
old form and is correct now. One that had adapted to the old form, by reading
the addresses and ignoring the keyword or by swapping the keywords back, needs
that adaptation removed at the same time. There is no switch for the old form.

The Public-Identity of the MAR is the one to check when a REGISTER can name
another identity in From or P-Asserted-Identity than in To (a third-party
registration, or a P-CSCF that asserts a default identity): it went to the HSS
under that other identity and now goes under the one being registered.

`require_ims_digest` raises `RuntimeError` for a Multimedia-Auth-Answer with
`DIAMETER_SUCCESS` that names another scheme than `Digest-AKAv1-MD5`, or that
has no `SIP-Authenticate`, no `SIP-Authorization` or no item at all. Each used
to become a 401, the last three with a nonce made up by siphon, which no UE
can answer.

Outbound TCP connections now stay open while a call relayed over them rings,
and through any other request that is still waiting for its final response.
Expect more of them open at once than before on a proxy whose calls ring for
longer than 30 seconds: one per next hop, since requests to one destination
share a connection. A firewall or load balancer between two nodes has to let a
node open a TCP or TLS connection to the port its peer writes in its Via, which
is the port that peer listens on. That is where a late response goes when the
connection its request came on has been closed in the meantime.

A P-CSCF that serves UEs over IPsec with TCP now keeps one connection open per
registered UE it has sent a request to, from its protected client port to the
protected server port of the UE, until the UE closes it or stops answering the
keepalive. It used to close each after 30 seconds and then fail to open it
again for the next request in the same call.
