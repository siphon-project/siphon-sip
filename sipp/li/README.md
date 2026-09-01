# ETSI TS 103 221 interop

Runs siphon as a **network element** against a real Administration Function and
a real Mediation and Delivery Function, rather than against a test double
written from the same reading of the specification that produced the
implementation.

All three interfaces are exercised on the wire: X1 provisioning in, X2
signalling and X3 content out, with the media engine in the path holding the
RTP that X3 delivers.

```
scripts/run-tests.sh --li
```

## The peer

[sipgate/li-simulator-x1x2x3](https://github.com/sipgate/li-simulator-x1x2x3)
(MIT), which plays both roles siphon has to talk to:

* the **ADMF**, provisioning destinations and tasks over X1;
* the **MDF**, receiving X2 IRI and X3 content.

Using somebody else's implementation is the entire point. siphon validating
against its own reader would pass whatever bug the reader and the writer share,
which is exactly the class of defect that survives a round-trip test. The same
reasoning is why [`error.rs`](../../src/li/x1/error.rs)'s clause 6.7 code table
is cross-checked against their library, why every emitted document is validated
with `xmllint`, and why the TS 103 221-2 PDU framing is additionally checked
against a third-party Wireshark dissector
([`scripts/validate_x2_pdu.sh`](../../scripts/validate_x2_pdu.sh)).

The media engine is [`siphon-rtp`](https://github.com/siphon-project/siphon-rtp),
pinned to the release siphon pins `siphon-rtp-proto` to. X3 content framing
lives there because that is where the RTP is; siphon's part is the warrant and
the attachment.

## What it checks

Two drivers, because there are two different questions.

### `li-x1-test` — is the interface conformant, and does product arrive?

1. **Provisioning** over real mutual TLS — `CreateDestination`, `ActivateTask`.
2. **Read-back** — `GetTaskDetails` reports what was provisioned.
3. **Refusals** — a duplicate XID (2010), and removing a destination a live
   task still delivers to (7010). A network element that accepted everything
   would pass a success-only test, so the refusals carry as much weight as the
   successes.
4. **Delivery** — a real call through siphon, with real RTP, and then the
   mediation function is asked what it received. The PDUs are decoded and
   checked field by field:
   * every PDU declares version 0.5 and carries the **warrant's XID** — a
     record delivered under the wrong XID is worse than a missing one, because
     it attributes traffic to somebody else's warrant;
   * **X2** is payload format 9 and the payload parses as the SIP that crossed
     the element, carrying the provisioned target;
   * **X3** is payload format 8 and every payload is a real RTP packet;
   * X2 and X3 **share a correlation ID**, which is the invariant that lets the
     mediation function tie content to the signalling that describes it — and
     it spans two binaries, because the content is framed by the media engine
     and the signalling by siphon.
5. **Teardown** — deactivate, and confirm the warrant is gone.

### `li-target-types` — does a warrant match anything?

A warrant can be accepted and then match nothing, and no provisioning test can
catch that, because provisioning succeeded. So a warrant is provisioned on each
identifier type in turn — `sipUri` (originating and terminating), `telUri`,
`e164Number` (calling and dialled), `impu`, `impi` — a call carrying that
identity is placed, and the mediation function is asked whether anything
arrived.

It ends with a **negative control**: a warrant on a number no call carries must
deliver nothing. Without it, a matcher that matched everything would pass all
seven, and the suite would be measuring nothing.

## The packet capture

```
scripts/validate_li_capture.sh
```

Everything above asks the two endpoints what they think happened. This one
captures the delivery interface with `tcpdump` and reads it back with the
third-party dissector plus Wireshark's own SIP and RTP dissectors, so the
verification path contains none of our code. It checks the PDU counts, that SIP
parses inside every X2 record (the INVITE, the 200, the ACK and the BYE), that
RTP parses inside every X3 record, and that the delivered RTP **sequence numbers
are contiguous** — a gap is a lost packet and a repeat is a duplicated one, and
neither shows up in a total.

It found a real defect the endpoint-level tests did not: the mediation
function's view of a run can be missing a record the wire plainly carries.

### Why there is a TLS tap

The media engine's X3 delivery is TLS-only — it refuses the interception
outright without a client certificate, key and CA, which is correct for an
interface carrying warranted content and not something to work around. The
certificates are ECDHE, so a capture of that hop cannot be decrypted afterwards
from the server key either.

So [`docker-compose.li-capture.yaml`](docker-compose.li-capture.yaml) puts a
TLS-terminating tap in front of the mediation function. The outer hop is exactly
what production is: siphon and the engine both dial TLS, present the
network-element certificate, and verify the mediation function against its CA.
The inner hop, tap to simulator, is plaintext on a private address where it can
be dissected. The PDU stream is the same one, a TCP hop later.

## Two identity details that are easy to get wrong

Both are exercised rather than worked around:

* **`admfIdentifier` is bound to the client certificate.** The simulator's
  bootstrap issues its certificate with `CN=simulator`, so siphon is configured
  with `admf_identifier: "simulator"`. A mismatch is answered `1030`, so
  provisioning succeeding at all is proof the binding passed.
* **`neIdentifier` is the host of the ADMF's target URI.** The simulator derives
  it that way, so the container is named `network-element` and siphon is
  configured to match. `network-element` is also a SAN on the certificate the
  bootstrap issues, which is what lets the simulator verify our server
  certificate.

## A version mismatch, on purpose

The simulator declares `v1.6.1` on the wire; siphon is built to **v1.23.1** with
the TS 103 280 v2.19.1 dictionary. That the two interoperate anyway is the point
rather than an oversight: the message set is identical across the published v1.x
range, so the declared string differs and nothing else does. siphon accepts any
well-formed `v1.x` version rather than demanding its own back.

## Certificates

`init-mutual-tls/` is vendored from the simulator (MIT), so both sides get their
PKI from the same bootstrap and neither is hand-configured to trust the other.
Two roles, each with its own CA:

| role | is | siphon uses it as |
|---|---|---|
| `simulator` | the ADMF | `tls.client_ca` — who may provision warrants |
| `network-element` | siphon | `tls.certificate` / `tls.private_key` |

The one local change is emitting a PKCS#8 copy of the key: `openssl ecparam`
writes a SEC1 `EC PRIVATE KEY` block, and siphon reads keys through
`rustls-pki-types`, which wants PKCS#8.

## Scope

X1 provisioning is covered end to end. X2 delivery is asserted through the
simulator's `/x2x3/all` endpoint when the call leg runs. X3 content requires the
real `siphon-rtp` engine and a mediation function that terminates TLS on its
X2/X3 port — the engine's X3 delivery is TLS-only by design — which this profile
does not yet stand up.
