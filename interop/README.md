# Interoperability tests

siphon against a SIP proxy that shares none of its code.

```
interop/run.sh                # every chain
interop/run.sh forward        # one chain
```

## Why this is not covered by the SIPp suite

`sipp/` proves siphon does what siphon intends. Every message on the wire is
produced by siphon and consumed by SIPp, which is a message generator rather
than a SIP element: it does not build a route set, does not match a CANCEL to a
transaction, and does not have an opinion about a Record-Route it did not write.
So a header that is subtly wrong but self-consistent passes.

That is the gap this fills. Kamailio is the oracle, not the subject: it shares
no code with siphon, so a route set the two of them build **together** only
works if siphon's half is genuinely conformant rather than merely internally
consistent.

## The chains

Two, because the bug classes differ by position in the path:

```
forward:  SIPp UAC ──▶ siphon ──▶ Kamailio ──▶ SIPp UAS
reverse:  SIPp UAC ──▶ Kamailio ──▶ siphon ──▶ SIPp UAS
```

Both proxies Record-Route, so every call builds a route set jointly. In the
forward chain siphon's Record-Route has to be loose-routable **by Kamailio**; in
the reverse chain siphon has to loose-route **Kamailio's**. Running only one
proves only one half.

| Chain | What it exercises |
|---|---|
| `forward` | INVITE → 180 → 200 → ACK → BYE → 200. siphon's Record-Route read by Kamailio; the in-dialog BYE traversing both in reverse. |
| `reverse` | The same call with the proxies swapped: Kamailio's Record-Route read by siphon. |
| `cancel` | CANCEL of an alerting call across both hops (RFC 3261 §9). |

## How the scenarios assert

They do not compare header text. The UAC sends its ACK and BYE to `[next_url]`
(the callee's Contact — the remote target, RFC 3261 §12.2.1.1) carrying
`[routes]`, the route set SIPp assembled from the Record-Route headers the two
proxies wrote. If either proxy writes a Record-Route the other cannot
loose-route, the BYE does not arrive and the scenario fails on the missing 200.

That is a sharper test than string comparison and it is the failure an operator
actually sees. The same goes for CANCEL: it is matched by the topmost Via
branch, which every hop rewrites, so the 487 only comes back if each proxy
cancelled the branch it *sent* rather than the one it received.

## The false-green guard

`run.sh` requires each chain to report **at least one successful call**, not
just a zero exit code. SIPp exits 0 when no call *failed*, which includes the
case where no call ever completed — so a run torn down early (by
`--abort-on-container-exit` firing on some other container) reads as green while
proving nothing. This is not hypothetical: it happened while building this
harness, and the run looked passing.

Verified by negative control — pointing the UAC at an address nothing listens on
gives `FAIL forward: exit=255 successful_calls=0`.

## Layout

```
interop/
  run.sh                     the entry point; gates on successful calls
  docker-compose.yaml        both chains, on their own subnet (172.28.0.0/24)
  configs/                   siphon config for its hop
  scripts/                   the siphon routing script (Record-Route + relay)
  kamailio/kamailio.cfg      the independent proxy, kept as small as it can be
  scenarios/                 SIPp UAC/UAS scenarios
```

The subnet is deliberately its own, so this stack runs alongside `sipp/`
(172.20.0.0/24) and the MTU stack (172.30.0.0/24).

## Adding a peer

The two chains are the shape; a second implementation is a third and fourth. To
add OpenSIPS, Asterisk or FreeSWITCH, add a service with a config that
Record-Routes and forwards to `INTEROP_NEXT_HOP`, and reuse the scenarios
unchanged — they assert nothing implementation-specific. The most valuable next
peers, roughly in order: OpenSIPS (same class of element, different codebase),
Asterisk or FreeSWITCH (a B2BUA rather than a proxy, so re-INVITE and transfer
come into scope), and a WebRTC stack over WSS.

## What is not covered yet

Named so nobody reads a green run as more than it is:

- TLS and WebSocket transports — UDP only today.
- Forking, re-INVITE, session timers, PRACK, REFER across the chain.
- Authentication between the proxies.
- Any peer other than Kamailio.
- Load. These are one-call correctness runs, not throughput.
