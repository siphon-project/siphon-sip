# Kernel firewall (nf_tables)

By default SIPhon drops banned sources in **userspace**: the transport ACL rejects
them at `recv()`/`accept()`, before any SIP parsing. That protects your handlers,
but the packet still travels NIC → kernel → SIPhon before being dropped, so it does
nothing against volume.

`security.firewall` mirrors SIPhon's bans into a **kernel nf_tables set** so the
kernel drops the traffic before it reaches SIPhon's socket. It's self-contained
(no `nft` shell-out, no daemon, no log scraping) — SIPhon programs the set directly
over netlink and the kernel auto-expires each ban via a per-element timeout.

## What gets dropped

The same sources SIPhon already bans, now enforced in the kernel:

- **Auto-ban** — the confidence-weighted [`failed_auth_ban`](cookbook/security.md#how-the-scoring-works)
  store. Each ban is pushed to the kernel with the **same TTL** as the in-memory
  ban, so both expire in lockstep.
- **APIBAN** — every IP from the [APIBAN](https://apiban.org) community blocklist,
  added with the `apiban.ban_ttl_secs` TTL (default 7 days, matching the interval
  after which the feed itself releases an address) as a per-element timeout, so
  the kernel expires them without SIPhon acting. Set `ban_ttl_secs: 0` to add
  them permanently instead.

`trusted_cidrs` are never banned, so they're never in the set. That applies to
both sources: the auto-ban store exempts trusted sources before scoring, and
APIBAN drops trusted addresses as the feed is ingested, before either the
userspace ACL or the kernel set sees them. This matters more for the feed than
it looks — the kernel drop is port-agnostic, so a management address that landed
on a community blocklist would take ssh down with the trunk.

Because the poll only fetches *forward* from the last seen id, an address whose
TTL expires while it is still abusive returns to the set when the feed re-lists
it, not immediately. That is how the feed publishes; it isn't a full
re-synchronisation.

## Enable it

```yaml
security:
  failed_auth_ban:            # (or apiban:) — the source of bans
    threshold: 10
    window_secs: 600
    ban_duration_secs: 3600

  firewall: {}                # that's it — every field below defaults
    # table:  "siphon"        # nf_tables table SIPhon owns (family inet)
    # chain:  "input"         # base chain SIPhon adds the drop rules to
    # set_v4: "banned4"       # IPv4 ban set
    # set_v6: "banned6"       # IPv6 ban set
    # manage_rule: true       # SIPhon owns the chain + drop rules too (see below)
    # gateway_set: true       # also maintain the gateway allow set (see below)
    # set_gateways_v4: "gateways4"   # IPv4 allow set (interval)
    # set_gateways_v6: "gateways6"   # IPv6 allow set (interval)
```

`firewall: {}` is enough. On startup SIPhon creates the `inet siphon` table, the
two timeout sets, a base chain, and the drop rules that reference them — all
idempotent and safe across restarts. Nothing else to configure.

## Grant `CAP_NET_ADMIN`

Programming nf_tables needs `CAP_NET_ADMIN` (the same capability the IMS P-CSCF
IPsec path uses). Without it SIPhon logs a warning and falls back to the userspace
ACL — the feature is never fatal, it just doesn't reach the kernel.

=== "systemd"

    ```ini
    [Service]
    AmbientCapabilities=CAP_NET_ADMIN
    ```

=== "Docker"

    ```bash
    docker run --cap-add=NET_ADMIN siphon-sip ...
    ```

=== "Kubernetes"

    ```yaml
    securityContext:
      capabilities:
        add: ["NET_ADMIN"]
    ```

## Zero-touch by default

With `manage_rule: true` (the default) SIPhon owns the whole ruleset — table,
sets, base chain, and the two drop rules — so enabling `firewall` is all you do.
On startup it installs, in the `inet siphon` table:

```nft
chain input {
    type filter hook input priority filter; policy accept;
    ip  saddr @banned4 drop
    ip6 saddr @banned6 drop
}
```

Banned sources are dropped in-kernel from the first ban; SIPhon keeps the set
contents current with per-element timeouts. The whole setup is **one atomic
nf_tables transaction**: every object is declared idempotently, and the chain's
rules are flushed and re-appended inside the same transaction — so a first run,
a clean restart, and a restart after a crash all converge to exactly this
ruleset, with no duplicated rules and no instant where the drop rule is absent.

### Bring your own rule (`manage_rule: false`)

If you already manage nftables and want to place the drop yourself, set
`manage_rule: false`. SIPhon then maintains only the **sets**, and you reference
them from your own ruleset:

```nft
table inet siphon {
    chain input {
        type filter hook input priority filter; policy accept;
        ip  saddr @banned4 drop
        ip6 saddr @banned6 drop
    }
}
```

```bash
nft -f /etc/siphon/firewall.nft
```

### Renaming or disabling: clean up the old objects yourself

SIPhon only ever **creates** its objects — it never deletes a table or chain it
finds, because it can't know the objects aren't yours. So if you rename `table`
/ `chain` in the config, flip `manage_rule` off, or remove `firewall:` entirely,
the previously created table (and its drop rules) stays in the kernel and keeps
dropping whatever is still in its sets until each element's timeout runs out —
and indefinitely for any element added with `ban_ttl_secs: 0`. Remove it
explicitly:

```bash
nft delete table inet siphon
```

## Gateway allow set

The ban sets say who to keep out. The allow set says who to let in, and it
exists because a carrier that authenticates by **source address** has no
registration and no outbound digest — the address list *is* the authentication,
and it is usually rendered into a ruleset at deploy time.

That breaks the moment the carrier list stops being static. A carrier added in
your controller and picked up by `gateway.backend`'s reconcile is one SIPhon
will dial and whose answers the kernel drops: the outbound half appears to work
while the inbound half is dead, which is the worst shape of failure to debug.

So whenever the firewall is enabled, SIPhon also declares two **interval** sets
and keeps them holding every source its gateways admit:

```nft
table inet siphon {
    set gateways4 { type ipv4_addr; flags interval; }
    set gateways6 { type ipv6_addr; flags interval; }
}
```

**SIPhon declares the sets and writes no rule for them, in either `manage_rule`
mode.** You reference them from your own ruleset:

```nft
ip  saddr @gateways4 udp dport 5060 accept
ip6 saddr @gateways6 udp dport 5060 accept
```

That is deliberate. An `accept` inside SIPhon's own chain would also make a
gateway immune to the ban drops above, and whether a known carrier can be
auto-banned is your policy call, not a side effect of SIPhon keeping a set
current. The sets are declared even before anything is published into them, so
an `nft -f` referencing them loads on a fresh node.

### What goes in

- Every address every gateway group resolves to — all of them, not just the one
  currently selected, so a carrier behind several A records works. This is the
  same view `request.from_gateway()` answers from, so the kernel and the script
  can never disagree about who is a gateway.
- Every `gateway.groups[].source_networks` entry, as written.
- Every `security.trusted_cidrs` entry, as written — it is already your "not an
  abuser" list: own trunks, monitoring, management.

Ranges are deduplicated and a range another already contains is dropped, so a
gateway inside a `trusted_cidrs` block goes in once.

### When it is republished

- Once during start-up, **before the listeners take traffic**, so a node never
  answers calls while the kernel is still dropping a carrier it will dial.
- On every `gateway.backend` reconcile and every `POST /admin/gateways/refresh`,
  so a carrier provisioned in your controller is admitted in the same tick it
  becomes dialable.
- On a 60-second floor tick, which also re-resolves groups with
  `probe.enabled: false` — nothing else ever revisits their DNS.

Each of these first checks that the sets are still the ones SIPhon declared
([below](#referencing-the-sets-from-your-own-table)).

A publish that changes nothing issues no netlink transaction at all. A publish
replaces the set contents wholesale rather than diffing, so a carrier removed
from your source stops being admitted.

### Referencing the sets from your own table

An nf_tables set is scoped to its table. A rule in your `table inet edge`
cannot name `@gateways4` in `table inet siphon`; `nft` refuses the load with
`No such file or directory`. So to reference the sets, point SIPhon at the
table your ruleset lives in:

```yaml
security:
  firewall:
    table: edge
    manage_rule: false      # usually: your ruleset already has its input chain
```

That table is yours, and you will reload it the way any ruleset is reloaded,
by deleting and redefining it so rules do not stack on every load:

```nft
table inet edge
delete table inet edge
table inet edge {
    set gateways4 { type ipv4_addr; flags interval; }
    set gateways6 { type ipv6_addr; flags interval; }
    chain input {
        type filter hook input priority 0; policy drop;
        ip  saddr @gateways4 udp dport 5060 accept
        ip6 saddr @gateways6 udp dport 5060 accept
    }
}
```

The file has to declare the sets itself, because after the `delete` there is
nothing for its rules to reference. The sets come back **empty**, and the
`delete` also took SIPhon's ban sets (and its chain, with `manage_rule: true`)
with it.

SIPhon notices the next time it republishes: at the latest on the floor tick,
sooner on a `gateway.backend` reconcile or an admin refresh. It keeps the kernel handle of every
object it declared, and a recreated table always gets a new one, so a set that
is back under the same name still reads as new. It then re-runs its start-up
declaration, which is idempotent and leaves your own objects and rules alone,
republishes the allow set whether or not the gateway view changed, and logs a
`warn` naming the table. `siphon_firewall_redeclared_total` counts each time.
A check that finds everything as it was reads a few handles and writes nothing.

What that leaves you to plan for:

- **A window after each reload**, in which the allow set is empty and your
  ruleset drops the carriers' answers. It lasts until the next republish: the
  floor tick (60 s) at the latest. With a `gateway.backend` source, close it at
  once by following the reload with
  `curl -X POST http://127.0.0.1:9091/admin/gateways/refresh`.
- **Bans placed before the reload are enforced in userspace only.** The ban
  sets come back empty, and SIPhon does not replay its active bans into them;
  bans placed after the recovery reach the kernel as usual.
- **A set flushed rather than deleted is not noticed.** `nft flush set` keeps
  the set and its handle, so nothing tells SIPhon; the next change to the
  gateway view refills it. Reload by redefining the table, not by flushing.

The same recovery covers `nft flush ruleset` underneath a running node, with
SIPhon's own `siphon` table.

### CIDRs go in as written

Expanding a `/24` into 256 bare addresses, or silently dropping its prefix and
admitting one host out of it, are each a half-fix that looks like it worked. So
a CIDR rides as a range: `nft_set_rbtree` — the backend an
`ipv4_addr`/`ipv6_addr` set with `flags interval` selects — takes a range as the
element that opens it plus an `NFT_SET_ELEM_INTERVAL_END` element keyed one
address past its last, which is exactly what `nft` itself sends. No kernel floor
beyond nf_tables: this is the original interval encoding, not the newer
`NFTA_SET_ELEM_KEY_END` attribute (which that backend rejects).

### Turning it off

```yaml
security:
  firewall:
    gateway_set: false
```

The sets are then neither declared nor published, and nothing else changes. Note
the [renaming caveat](#renaming-or-disabling-clean-up-the-old-objects-yourself)
applies here too: sets SIPhon already created stay in the kernel with their last
contents until you remove them.

## Containers: use nftables, not XDP

Most SIPhon binaries run in containers, and this is the right tool there. nftables
runs in the **pod's network namespace**; `CAP_NET_ADMIN` is grantable per-pod
without host privilege, and it works on any CNI, `veth`, or cloud vNIC.

XDP is *not* the tool here. From inside a pod you can't attach XDP to the host NIC
(that's the node/CNI's job), `veth` and cloud vNICs fall back to generic-mode XDP
(no faster than nftables), it needs `CAP_BPF`/bpffs, and it collides with CNIs that
already own XDP (Cilium). Line-rate volumetric scrubbing belongs at the **edge /
host / CNI**, not in the SIPhon container. (SIPhon's XDP story is on the *media*
plane, where packet rates justify it.)

One honest limit: from inside a container, neither nftables nor XDP drops at the
host NIC — the packet has already crossed host → CNI → `veth`. nftables still drops
it **before SIPhon's userspace**, which is the win here; true volumetric defense is
an edge/upstream concern.

## Verify & troubleshoot

Confirm the sets and their live contents:

```bash
nft list ruleset
# table inet siphon {
#   set banned4 { type ipv4_addr; flags timeout; elements = { 203.0.113.5 timeout 1h expires 59m } }
#   ...
# }
```

- **An element's `expires` went *up* between two listings?** That's the sliding
  ban expiry, not a bug. A further abuse signal from an already-banned source
  pushes its deadline out, and the kernel element is re-armed to match (the set
  element is re-added with the new timeout). `max_ban_duration_secs` bounds how
  far it can go; see
  [Hardening & security](cookbook/security.md#a-ban-that-slides).
- **Nothing in the sets?** Check that `failed_auth_ban` and/or `apiban` are
  configured — the firewall only mirrors bans those produce. Trigger a few failed
  auths and watch the set fill.
- **`kernel firewall (nf_tables) unavailable` in the logs?** SIPhon couldn't
  program the sets — almost always a missing `CAP_NET_ADMIN`. It's running on the
  userspace ACL until you grant it.
- **Bans not dropping?** Confirm the `chain input` + `@banned4/@banned6 drop` rules
  are present in `nft list ruleset`. With the default `manage_rule: true` SIPhon
  installs them; with `manage_rule: false` you add them yourself (see above).

Three counters on `/metrics` cover the runtime failure modes:

| Metric | Alert when | Meaning |
|---|---|---|
| `siphon_firewall_command_failures_total` | any sustained `rate() > 0` | Bans are **not** reaching the kernel (ruleset deleted out from under SIPhon, capability lost). Userspace ACL is the only enforcement left. |
| `siphon_firewall_commands_dropped_total` | sustained `rate() > 0` | A ban storm is outrunning the netlink actor's queue; kernel enforcement lags the ban rate (userspace ACL still enforces every ban). |
| `siphon_firewall_redeclared_total` | increases with no deploy behind it | SIPhon found its sets deleted or recreated (a [ruleset reload](#referencing-the-sets-from-your-own-table)) and re-declared them. Expected once per reload of the table that holds them. |

### Lifting a false-positive ban

If a legitimate source gets auto-banned, lift it through the [admin API](deployment.md)
rather than editing `nft` by hand — that keeps the userspace ban and the kernel
set in sync:

```bash
curl http://127.0.0.1:9091/admin/bans                        # list active bans
curl -X DELETE http://127.0.0.1:9091/admin/bans/203.0.113.5  # lift one
```

`DELETE /admin/bans/{ip}` clears the userspace ban and, when the kernel firewall
is enabled, removes the matching nf_tables element in the same step. (A ban left
alone expires on its own; both the userspace store and the kernel element use the
same TTL.)

## See also

- [How the scoring works](cookbook/security.md#how-the-scoring-works) — what earns
  a ban and how fast.
- [Monitoring](cookbook/monitoring.md) — the `siphon_banned_ips` gauge tracks the
  active ban count.
