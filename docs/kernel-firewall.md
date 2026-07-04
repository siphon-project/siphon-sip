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
  added permanently (the blocklist carries no per-IP lifetime).

`trusted_cidrs` are never banned, so they're never in the set.

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
contents current with per-element timeouts. On restart it leaves the existing
table in place (so the rules are never duplicated).

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

- **Nothing in the sets?** Check that `failed_auth_ban` and/or `apiban` are
  configured — the firewall only mirrors bans those produce. Trigger a few failed
  auths and watch the set fill.
- **`kernel firewall (nf_tables) unavailable` in the logs?** SIPhon couldn't
  program the sets — almost always a missing `CAP_NET_ADMIN`. It's running on the
  userspace ACL until you grant it.
- **Bans not dropping?** Confirm the `chain input` + `@banned4/@banned6 drop` rules
  are present in `nft list ruleset`. With the default `manage_rule: true` SIPhon
  installs them; with `manage_rule: false` you add them yourself (see above).

## See also

- [How the scoring works](cookbook/security.md#how-the-scoring-works) — what earns
  a ban and how fast.
- [Monitoring](cookbook/monitoring.md) — the `siphon_banned_ips` gauge tracks the
  active ban count.
