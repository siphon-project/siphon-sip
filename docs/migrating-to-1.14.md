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
| `diameter::cx::build_saa_success`, `build_lia_success`, `build_rta` | Answer with Result-Code 2001 where they carried Experimental-Result 2001. |

## On the wire: check before upgrading

| Interface | Before | Now |
|---|---|---|
| Rx `Flow-Description`, N5 `fDescs` | `permit out` from the UE, `permit in` to the UE | `permit in` from the UE (uplink), `permit out` to the UE (downlink), per TS 29.214 clause 5.3.8 |
| N5 create | no `suppFeat`, `notifUri` only when passed, `sipCallId` present | `suppFeat` `"0"`, `notifUri` always, no `sipCallId` |
| Nbsf discovery, IPv6 | `ipv6Prefix=<address>/64` | `ipv6Prefix=<address>/128` |
| Nbsf discovery, answer 204 | raised `sbi.BsfError` | no binding (`None`), as for 404 |
| Cx MAR of `auth.require_ims_digest`, `Public-Identity` | URI of P-Asserted-Identity, else of From | URI of the To header, per TS 24.229 clause 5.4.1.2.1 |

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
