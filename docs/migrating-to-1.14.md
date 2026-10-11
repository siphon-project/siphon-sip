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

## On the wire: check before upgrading

| Interface | Before | Now |
|---|---|---|
| Rx `Flow-Description`, N5 `fDescs` | `permit out` from the UE, `permit in` to the UE | `permit in` from the UE (uplink), `permit out` to the UE (downlink), per TS 29.214 clause 5.3.8 |
| N5 create | no `suppFeat`, `notifUri` only when passed, `sipCallId` present | `suppFeat` `"0"`, `notifUri` always, no `sipCallId` |
| Nbsf discovery, IPv6 | `ipv6Prefix=<address>/64` | `ipv6Prefix=<address>/128` |
| Nbsf discovery, answer 204 | raised `sbi.BsfError` | no binding (`None`), as for 404 |
| Cx MAR of `auth.require_ims_digest`, first REGISTER and repeated challenge | SIP-Authentication-Scheme `SIP Digest` | `Digest-AKAv1-MD5`, per TS 29.229 clause 6.3.9 |

The flow descriptions are the one to test against the policy function in use.
One that follows the specification built its packet filters reversed with the
old form and is correct now. One that had adapted to the old form, by reading
the addresses and ignoring the keyword or by swapping the keywords back, needs
that adaptation removed at the same time. There is no switch for the old form.

The MAR is the one to test against the HSS in use. One that follows TS 29.228
clause 6.3.1 answered the old request with
`DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED` (5006) or with SIP Digest data, and
answers the new one with an IMS-AKA vector. One that ignored the AVP is
unaffected. One that only returned a vector when asked for `SIP Digest` now
refuses, and every IMS registration fails with 403: check it before upgrading.
There is no switch for the old value. A successful answer whose item names
another scheme than `Digest-AKAv1-MD5` now raises `RuntimeError` from
`require_ims_digest` where it used to be turned into a challenge.
