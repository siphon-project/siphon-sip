# Cookbook

Build real things, fast. Each recipe is a complete, working starting point —
the YAML config, the Python script, and how to test it — for a common SIP role.
They're deliberately small (usually under 60 lines of Python) so you can read the
whole thing and adapt it.

Every recipe is grounded in a real script in the repo (linked at the bottom of each
page); none of the APIs here are invented.

## What SIPhon does, and what's yours

SIPhon is open source (MIT) and free to run in production. It gives you the
protocol side: the transports, the RFC 3261 transaction and dialog state
machines, the registrar, media control. The parts that take years to get right
and tend to break at 3am.

What it deliberately doesn't do is your business logic. The LCR cost decision,
the LNP dip, which carrier wins tonight, how your customers map onto trunks. That
stays yours. That's the whole promise: the hard protocol parts are handled so you
spend your time on the logic that's actually specific to you. Wherever a recipe
needs your data, it leaves you a small function to fill in.

If you'd rather not build or run that integration alone, commercial support is
available from [Real Time Telecom](../support.md).

## The recipes

| Recipe | What you build | Key ideas |
|---|---|---|
| [Registrar](registrar.md) | A SIP registrar with digest auth | `auth.require_digest`, `registrar.save`/`lookup`, NAT fixups |
| [Stateful proxy](proxy.md) | A residential/edge proxy | `request.fork`, `loose_route`, `record_route`, sanity checks |
| [SIP & SDP manipulation](manipulation.md) | Header/SDP rewrite at a boundary (HMR) | `set_header`/`remove_headers_matching`, `re`, the `sdp` namespace |
| [Number routing](number-routing.md) | LNP correction + a redirect (3xx) server | `set_ruri` (`rn`/`npdi`), `add_reply_header`, `reply(3xx)` |
| [Quick recipes](snippets.md) | Common one-off building blocks | scanner drop, `from_gateway`, `rate_limit`, prefix routing |
| [Load balancer](load-balancer.md) | A front LB over a backend pool | `gateway.select`, health probing, subscriber affinity |
| [Least-Cost Routing](least-cost-routing.md) | Carrier LCR driven by an external API | `lcr.route`, `call.route` sequential failover, gateway pools, CDR |
| [SBC (B2BUA)](sbc.md) | A topology-hiding SBC with media | `@b2bua.*`, `call.dial`/`fork`, **header policies**, RTPEngine |
| [Number normalization](number-normalization.md) | E.164 identity rewriting at a trunk↔IMS edge | `numbers.parse`, `rewrite_identities`, **number policies**, diversion family |
| [Media & RTP profiles](media-rtp.md) | SRTP↔RTP, WebRTC, transcoding, hold | `rtpengine.offer`/`answer`, profiles, the `sdp` namespace |
| [Online charging (OCS)](online-charging-ocs.md) | Prepaid voice + SMS/RCS over Diameter Ro | `ro:` config, `diameter.ro_ccr_*`, SCUR reserve/re-auth/disconnect, IEC, CGRateS |
| [Hardening & security](security.md) | A locked-down edge | rate-limit, scanner/auth bans, TLS/mTLS, STIR/SHAKEN, IPsec |
| [Monitoring & observability](monitoring.md) | Metrics, CDRs, tracing, probes | custom Prometheus metrics, `/admin/*`, CDR, HEP/Homer |
| [Multi-file scripts](multi-file-scripts.md) | Splitting a script into helper modules | sibling `import`, `include_paths`, helper hot-reload |

## How to run any recipe

Each recipe is a `siphon.yaml` + a Python script. Point the config at the script and
run siphon:

```yaml
# siphon.yaml
script:
  path: "/etc/siphon/myscript.py"
```

```bash
siphon --config /etc/siphon/siphon.yaml
```

Scripts **hot-reload** — edit and save, no restart (except `listen:` changes). Test
your script logic without a running server using the
[`siphon-sip` mock SDK](https://github.com/siphon-project/siphon-sip/tree/main/sdk).

## Mixing roles

A single script can be several of these at once — the dispatcher routes INVITEs to
your `@b2bua.on_invite` handler and everything else to `@proxy.on_request`. So a
"proxy for REGISTER/OPTIONS + SBC for calls" is one script, one process (see the
[SBC recipe](sbc.md) and the README's hybrid-mode section).

For running more than one node, see [Scaling & redundancy](../scaling-and-redundancy.md)
and [Deployment & operations](../deployment.md).
