//! Direct nf_tables netlink backend.
//!
//! Programs a kernel nf_tables `inet` table + timeout sets of banned source
//! IPs, so abusive traffic is dropped in the kernel before it ever reaches
//! siphon's socket. Hand-rolled over `netlink-sys` (the same foundation the
//! IPsec XFRM backend uses in [`crate::ipsec::netlink`]) — no `nft` shell-out,
//! no libnftnl/libmnl C dependency, no external daemon.
//!
//! Wire format references:
//! - `linux/netfilter/nf_tables.h` (message types + attribute enums)
//! - `linux/netfilter/nfnetlink.h` (`NFNL_MSG_BATCH_*`, `NFNL_SUBSYS_NFTABLES`)
//! - <https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts>
//!
//! Every mutation is one atomic transaction: `NFNL_MSG_BATCH_BEGIN` … object
//! message(s) … `NFNL_MSG_BATCH_END`. Elements carry `NFTA_SET_ELEM_TIMEOUT`
//! (milliseconds; `0` = never), so the kernel auto-expires bans with no
//! userspace unban event — mirroring siphon's lazy in-memory ban expiry.
//!
//! **Endianness note:** unlike rtnetlink/XFRM (host-endian), nf_tables integer
//! attributes are **big-endian** (`nla_put_be32`/`be64`). The IP key data is
//! also network order (raw octets). Strings are NUL-terminated.

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use netlink_sys::{protocols::NETLINK_NETFILTER, Socket, SocketAddr};

use ipnet::IpNet;

/// Upper bound on waiting for a kernel ack (`SO_RCVTIMEO`). Netlink to the
/// local kernel is reliable, so this never fires in practice — it exists so a
/// lost ack can never park a `spawn_blocking` thread forever.
const ACK_RECV_TIMEOUT: Duration = Duration::from_secs(5);

// --- netlink framing (shared shape with src/ipsec/netlink.rs) --------------

const NLMSG_HDR_LEN: usize = 16;
const NLA_ALIGNTO: usize = 4;
const NLMSG_ALIGNTO: usize = 4;

const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_APPEND: u16 = 0x800;

const NLMSG_ERROR: u16 = 0x2;

/// Nested-attribute flag (`NLA_F_NESTED`); libnftnl sets it, so we match.
const NLA_F_NESTED: u16 = 0x8000;

// --- nfnetlink / nf_tables constants (from the kernel UAPI headers) --------

const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 16; // = NLMSG_MIN_TYPE
const NFNL_MSG_BATCH_END: u16 = 17;

// nf_tables message types (subsystem-relative). Wire type =
// `(NFNL_SUBSYS_NFTABLES << 8) | msg`.
const NFT_MSG_NEWTABLE: u16 = 0;
/// Look a table up by name. Like the other `GET` messages below it is sent
/// bare rather than inside a batch, and opens no transaction.
const NFT_MSG_GETTABLE: u16 = 1;
const NFT_MSG_NEWSET: u16 = 9;
const NFT_MSG_GETSET: u16 = 10;
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_DELSETELEM: u16 = 14;

// nftables address families.
const NFPROTO_UNSPEC: u8 = 0;
const NFPROTO_INET: u8 = 1;

// `enum nft_table_attributes`
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_HANDLE: u16 = 4;

// `enum nft_set_attributes`
const NFTA_SET_TABLE: u16 = 1;
const NFTA_SET_NAME: u16 = 2;
const NFTA_SET_FLAGS: u16 = 3;
const NFTA_SET_KEY_TYPE: u16 = 4;
const NFTA_SET_KEY_LEN: u16 = 5;
const NFTA_SET_ID: u16 = 10;
const NFTA_SET_HANDLE: u16 = 16;

// `enum nft_set_flags`
const NFT_SET_TIMEOUT: u32 = 0x10;
/// `NFT_SET_INTERVAL` — the set holds ranges, each element carrying a start
/// key and an inclusive end key. Needed because the gateway allow set takes
/// `security.trusted_cidrs` as written: expanding a `/24` into 256 bare
/// addresses, or dropping its prefix, would each be a silent half-fix.
const NFT_SET_INTERVAL: u32 = 0x4;

// nft datatypes for `NFTA_SET_KEY_TYPE` (informational, but the kernel wants
// it present): `ipv4_addr` = 7, `ipv6_addr` = 8.
const NFT_TYPE_IPADDR: u32 = 7;
const NFT_TYPE_IP6ADDR: u32 = 8;

// `enum nft_set_elem_list_attributes`
const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;

// `enum nft_set_elem_attributes`
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
/// `enum nft_set_elem_attributes`. An element carrying
/// [`NFT_SET_ELEM_INTERVAL_END`] closes the range the previous one opened.
const NFTA_SET_ELEM_FLAGS: u16 = 3;

/// `enum nft_set_elem_flags`. This element is the **exclusive** upper bound of
/// an interval: its key is the address one past the range's last.
///
/// Not `NFTA_SET_ELEM_KEY_END`, which reads like the obvious way to say the
/// same thing and is what the first cut of this used. `nft_set_rbtree` — the
/// backend an `ipv4_addr`/`ipv6_addr` set with `flags interval` selects —
/// rejects it with `EINVAL`, and `nft --debug=netlink` shows `nft` itself
/// emitting this two-element form instead. Matching what `nft` sends is the
/// only encoding worth trusting here.
const NFT_SET_ELEM_INTERVAL_END: u32 = 0x1;

// `enum nft_data_attributes`
const NFTA_DATA_VALUE: u16 = 1;

// Generic `enum nft_list_attributes` element wrapper.
const NFTA_LIST_ELEM: u16 = 1;

// --- self-contained chain + drop rule (manage_rule) ------------------------

const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_GETCHAIN: u16 = 4;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_DELRULE: u16 = 8;

const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;
const NF_INET_LOCAL_IN: u32 = 1;
const NF_DROP: u32 = 0;

// `enum nft_chain_attributes`
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_HANDLE: u16 = 2;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_TYPE: u16 = 7;
// `enum nft_hook_attributes`
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

// `enum nft_rule_attributes`
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
// `enum nft_expr_attributes`
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

// expression payloads
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;

const NFTA_LOOKUP_SET: u16 = 1;
const NFTA_LOOKUP_SREG: u16 = 2;

const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;

const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFT_META_NFPROTO: u32 = 15;

const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFT_CMP_EQ: u32 = 0;

// nf_tables registers: `NFT_REG_1` (first data register), `NFT_REG_VERDICT`.
const NFT_REG_1: u32 = 1;
const NFT_REG_VERDICT: u32 = 0;

/// Which IP family a set holds. An `inet` table holds both via two typed sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetFamily {
    V4,
    V6,
}

impl SetFamily {
    fn key_len(self) -> u32 {
        match self {
            SetFamily::V4 => 4,
            SetFamily::V6 => 16,
        }
    }

    fn key_type(self) -> u32 {
        match self {
            SetFamily::V4 => NFT_TYPE_IPADDR,
            SetFamily::V6 => NFT_TYPE_IP6ADDR,
        }
    }

    fn nfproto(self) -> u8 {
        match self {
            SetFamily::V4 => NFPROTO_IPV4,
            SetFamily::V6 => NFPROTO_IPV6,
        }
    }

    /// Offset of the source address within the L3 (network) header.
    fn saddr_offset(self) -> u32 {
        match self {
            SetFamily::V4 => 12,
            SetFamily::V6 => 8,
        }
    }

    fn of(address: &IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => SetFamily::V4,
            IpAddr::V6(_) => SetFamily::V6,
        }
    }
}

// --- byte helpers ----------------------------------------------------------

#[inline]
const fn align_to(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Push a 4-byte-aligned netlink attribute (`__u16 nla_len | __u16 nla_type |
/// payload`, padded to `NLA_ALIGNTO`).
fn push_nla(buffer: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let total_len = 4 + payload.len();
    buffer.extend_from_slice(&(total_len as u16).to_ne_bytes());
    buffer.extend_from_slice(&attr_type.to_ne_bytes());
    buffer.extend_from_slice(payload);
    for _ in 0..(align_to(total_len, NLA_ALIGNTO) - total_len) {
        buffer.push(0);
    }
}

/// A NUL-terminated string attribute (nftables names are null-terminated).
fn push_nla_str(buffer: &mut Vec<u8>, attr_type: u16, value: &str) {
    let mut payload = value.as_bytes().to_vec();
    payload.push(0);
    push_nla(buffer, attr_type, &payload);
}

/// nf_tables integer attributes are **big-endian** (`nla_put_be32`).
fn push_nla_be32(buffer: &mut Vec<u8>, attr_type: u16, value: u32) {
    push_nla(buffer, attr_type, &value.to_be_bytes());
}

fn push_nla_be64(buffer: &mut Vec<u8>, attr_type: u16, value: u64) {
    push_nla(buffer, attr_type, &value.to_be_bytes());
}

/// Push a nested attribute (its payload is itself a sequence of attributes).
fn push_nla_nested(buffer: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    push_nla(buffer, attr_type | NLA_F_NESTED, payload);
}

/// `struct nfgenmsg { __u8 nfgen_family; __u8 version; __be16 res_id; }`.
fn nfgenmsg(family: u8, res_id: u16) -> [u8; 4] {
    let res = res_id.to_be_bytes();
    [family, 0 /* NFNETLINK_V0 */, res[0], res[1]]
}

/// Wrap an object body (`nfgenmsg` + attributes) in a netlink message header.
fn nlmsg(msg_type: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let total_len = NLMSG_HDR_LEN + body.len();
    let aligned = align_to(total_len, NLMSG_ALIGNTO);
    let mut message = Vec::with_capacity(aligned);
    message.extend_from_slice(&(total_len as u32).to_ne_bytes()); // nlmsg_len
    message.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
    message.extend_from_slice(&flags.to_ne_bytes()); // nlmsg_flags
    message.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
    message.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (kernel fills)
    message.extend_from_slice(body);
    while message.len() < aligned {
        message.push(0);
    }
    message
}

#[inline]
fn nft_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

const OBJECT_FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

// --- object message builders (each returns one full nlmsg) -----------------

/// Create a timeout set (`flags timeout`) keyed by a bare IPv4/IPv6 address.
/// Idempotent (`NLM_F_CREATE`, no `NLM_F_EXCL`) so re-running siphon does not
/// error on an existing set.
fn build_new_set(table: &str, set: &str, set_id: u32, family: SetFamily, seq: u32) -> Vec<u8> {
    let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
    push_nla_str(&mut body, NFTA_SET_TABLE, table);
    push_nla_str(&mut body, NFTA_SET_NAME, set);
    push_nla_be32(&mut body, NFTA_SET_FLAGS, NFT_SET_TIMEOUT);
    push_nla_be32(&mut body, NFTA_SET_KEY_TYPE, family.key_type());
    push_nla_be32(&mut body, NFTA_SET_KEY_LEN, family.key_len());
    push_nla_be32(&mut body, NFTA_SET_ID, set_id);
    nlmsg(nft_type(NFT_MSG_NEWSET), OBJECT_FLAGS, seq, &body)
}

/// Create an interval set (`flags interval`) keyed by an IPv4/IPv6 range. Holds
/// the gateway allow set: the sources the operator's own ruleset accepts, as
/// CIDRs rather than expanded addresses. Idempotent, like [`build_new_set`].
///
/// No `NFT_SET_TIMEOUT`: an allow-set element is replaced wholesale by the next
/// publish, never expired by the kernel. A timeout here would drop a live
/// carrier out of the set between publishes.
fn build_new_interval_set(
    table: &str,
    set: &str,
    set_id: u32,
    family: SetFamily,
    seq: u32,
) -> Vec<u8> {
    let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
    push_nla_str(&mut body, NFTA_SET_TABLE, table);
    push_nla_str(&mut body, NFTA_SET_NAME, set);
    push_nla_be32(&mut body, NFTA_SET_FLAGS, NFT_SET_INTERVAL);
    push_nla_be32(&mut body, NFTA_SET_KEY_TYPE, family.key_type());
    push_nla_be32(&mut body, NFTA_SET_KEY_LEN, family.key_len());
    push_nla_be32(&mut body, NFTA_SET_ID, set_id);
    nlmsg(nft_type(NFT_MSG_NEWSET), OBJECT_FLAGS, seq, &body)
}

/// Encode one set element: nested `NFTA_LIST_ELEM { KEY { DATA_VALUE=ip }[,
/// TIMEOUT=ttl_ms] }`. `ttl_ms` is only meaningful on an add: `Some(0)` means
/// never expire; a delete passes `None` (it matches on the key alone, so the
/// attribute is omitted).
fn encode_element(address: &IpAddr, ttl_ms: Option<u64>) -> Vec<u8> {
    let key_value: Vec<u8> = match address {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let mut data = Vec::new();
    push_nla(&mut data, NFTA_DATA_VALUE, &key_value);

    let mut elem = Vec::new();
    push_nla_nested(&mut elem, NFTA_SET_ELEM_KEY, &data);
    if let Some(ttl_ms) = ttl_ms {
        push_nla_be64(&mut elem, NFTA_SET_ELEM_TIMEOUT, ttl_ms);
    }

    let mut list_elem = Vec::new();
    push_nla_nested(&mut list_elem, NFTA_LIST_ELEM, &elem);
    list_elem
}

/// Encode one set element: `NFTA_LIST_ELEM { KEY { DATA_VALUE=address }[,
/// FLAGS=INTERVAL_END ] }`.
fn encode_key_element(address: &[u8], interval_end: bool) -> Vec<u8> {
    let mut data = Vec::new();
    push_nla(&mut data, NFTA_DATA_VALUE, address);

    let mut elem = Vec::new();
    push_nla_nested(&mut elem, NFTA_SET_ELEM_KEY, &data);
    if interval_end {
        push_nla_be32(&mut elem, NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_INTERVAL_END);
    }

    let mut list_elem = Vec::new();
    push_nla_nested(&mut list_elem, NFTA_LIST_ELEM, &elem);
    list_elem
}

/// Encode one CIDR as the element **pair** `nft_set_rbtree` takes: the range's
/// first address, then an [`NFT_SET_ELEM_INTERVAL_END`] element keyed one past
/// its last.
///
/// A host prefix is a range of one, which is how a single resolved gateway
/// address goes in: `203.0.113.9/32` is `203.0.113.9` followed by the end
/// marker `203.0.113.10`. A range that runs to the top of the address space has
/// nothing after it to key an end marker on, so it gets none and stays open —
/// which is correct, since nothing follows it.
fn encode_interval_element(network: &IpNet) -> Vec<u8> {
    let mut elements = encode_key_element(&ip_octets(network.network()), false);
    if let Some(after_last) = address_after(network.broadcast()) {
        elements.extend_from_slice(&encode_key_element(&ip_octets(after_last), true));
    }
    elements
}

/// The address one past `address`, or `None` at the top of the address space.
fn address_after(address: IpAddr) -> Option<IpAddr> {
    match address {
        IpAddr::V4(v4) => u32::from(v4)
            .checked_add(1)
            .map(|next| IpAddr::V4(next.into())),
        IpAddr::V6(v6) => u128::from(v6)
            .checked_add(1)
            .map(|next| IpAddr::V6(next.into())),
    }
}

/// Network-order octets of an address, the form every nf_tables key data value
/// takes.
fn ip_octets(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn build_setelem(
    msg: u16,
    table: &str,
    set: &str,
    address: &IpAddr,
    ttl_ms: Option<u64>,
    seq: u32,
) -> Vec<u8> {
    let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
    push_nla_str(&mut body, NFTA_SET_ELEM_LIST_TABLE, table);
    push_nla_str(&mut body, NFTA_SET_ELEM_LIST_SET, set);
    let elements = encode_element(address, ttl_ms);
    push_nla_nested(&mut body, NFTA_SET_ELEM_LIST_ELEMENTS, &elements);
    nlmsg(nft_type(msg), OBJECT_FLAGS, seq, &body)
}

/// One `NFT_MSG_NEWSETELEM` carrying every range of an allow set, so a publish
/// is a single message rather than one per element.
fn build_interval_setelems(table: &str, set: &str, networks: &[IpNet], seq: u32) -> Vec<u8> {
    let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
    push_nla_str(&mut body, NFTA_SET_ELEM_LIST_TABLE, table);
    push_nla_str(&mut body, NFTA_SET_ELEM_LIST_SET, set);
    let mut elements = Vec::new();
    // Mark everything below the first range as outside the set. `nft` emits
    // this too: without a lower bound to close against, the rbtree has no way
    // to read the first range's start element as an opening one.
    if let Some(first) = networks.first() {
        let floor = match first {
            IpNet::V4(_) => vec![0u8; 4],
            IpNet::V6(_) => vec![0u8; 16],
        };
        elements.extend_from_slice(&encode_key_element(&floor, true));
    }
    for network in networks {
        elements.extend_from_slice(&encode_interval_element(network));
    }
    push_nla_nested(&mut body, NFTA_SET_ELEM_LIST_ELEMENTS, &elements);
    nlmsg(nft_type(NFT_MSG_NEWSETELEM), OBJECT_FLAGS, seq, &body)
}

/// Empty a set: `NFT_MSG_DELSETELEM` with no element list, which is what
/// `nft flush set` sends and what the kernel reads as "flush", not "delete
/// nothing".
fn build_flush_set(table: &str, set: &str, seq: u32) -> Vec<u8> {
    let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
    push_nla_str(&mut body, NFTA_SET_ELEM_LIST_TABLE, table);
    push_nla_str(&mut body, NFTA_SET_ELEM_LIST_SET, set);
    nlmsg(nft_type(NFT_MSG_DELSETELEM), OBJECT_FLAGS, seq, &body)
}

// --- self-contained chain + drop rule builders -----------------------------

/// Create the base chain that hosts the drop rules
/// (`type filter hook input priority 0; policy accept`). Idempotent.
fn build_new_chain(table: &str, chain: &str, seq: u32) -> Vec<u8> {
    let mut hook = Vec::new();
    push_nla_be32(&mut hook, NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_IN);
    push_nla_be32(&mut hook, NFTA_HOOK_PRIORITY, 0); // NF_IP_PRI_FILTER

    let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
    push_nla_str(&mut body, NFTA_CHAIN_TABLE, table);
    push_nla_str(&mut body, NFTA_CHAIN_NAME, chain);
    push_nla_nested(&mut body, NFTA_CHAIN_HOOK, &hook);
    push_nla_str(&mut body, NFTA_CHAIN_TYPE, "filter");
    nlmsg(nft_type(NFT_MSG_NEWCHAIN), OBJECT_FLAGS, seq, &body)
}

/// Declare siphon's `inet` table. Idempotent (`NLM_F_CREATE`, no `NLM_F_EXCL`),
/// so a restart re-declares the existing table as a no-op instead of erroring.
fn build_new_table(table: &str, seq: u32) -> Vec<u8> {
    let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
    push_nla_str(&mut body, NFTA_TABLE_NAME, table);
    nlmsg(nft_type(NFT_MSG_NEWTABLE), OBJECT_FLAGS, seq, &body)
}

/// Flush every rule in `chain` (`NFT_MSG_DELRULE` with only the table + chain
/// name and no rule handle deletes all of the chain's rules). Batched directly
/// before re-appending the drop rules so a restart converges to exactly the
/// current rule set instead of stacking a duplicate — and because the flush and
/// the re-append commit in the *same* atomic transaction, the drop rule is never
/// absent for even an instant.
fn build_flush_chain(table: &str, chain: &str, seq: u32) -> Vec<u8> {
    let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
    push_nla_str(&mut body, NFTA_RULE_TABLE, table);
    push_nla_str(&mut body, NFTA_RULE_CHAIN, chain);
    nlmsg(
        nft_type(NFT_MSG_DELRULE),
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        &body,
    )
}

// --- identity queries -------------------------------------------------------

/// Look up one table by name (`NFT_MSG_GETTABLE`, no dump). The kernel answers
/// with the table's description and an errno-0 ack when it exists, and a lone
/// `ENOENT` when it does not. The GET builders below answer the same way.
fn build_get_table(table: &str, seq: u32) -> Vec<u8> {
    let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
    push_nla_str(&mut body, NFTA_TABLE_NAME, table);
    nlmsg(
        nft_type(NFT_MSG_GETTABLE),
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        &body,
    )
}

/// Look up one set by table + name (`NFT_MSG_GETSET`, no dump).
fn build_get_set(table: &str, set: &str, seq: u32) -> Vec<u8> {
    let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
    push_nla_str(&mut body, NFTA_SET_TABLE, table);
    push_nla_str(&mut body, NFTA_SET_NAME, set);
    nlmsg(
        nft_type(NFT_MSG_GETSET),
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        &body,
    )
}

/// Look up one chain by table + name (`NFT_MSG_GETCHAIN`, no dump).
fn build_get_chain(table: &str, chain: &str, seq: u32) -> Vec<u8> {
    let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
    push_nla_str(&mut body, NFTA_CHAIN_TABLE, table);
    push_nla_str(&mut body, NFTA_CHAIN_NAME, chain);
    nlmsg(
        nft_type(NFT_MSG_GETCHAIN),
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        &body,
    )
}

/// Append one expression: `NFTA_LIST_ELEM { NFTA_EXPR_NAME, NFTA_EXPR_DATA }`.
fn push_expr(list: &mut Vec<u8>, name: &str, data: &[u8]) {
    let mut expr = Vec::new();
    push_nla_str(&mut expr, NFTA_EXPR_NAME, name);
    push_nla_nested(&mut expr, NFTA_EXPR_DATA, data);
    push_nla_nested(list, NFTA_LIST_ELEM, &expr);
}

/// Build a rule that drops packets whose source address is in `set`, scoped to
/// `family` via a leading `meta nfproto` guard (the chain is `inet`, so it sees
/// both families): `meta nfproto <fam>; <fam> saddr @<set>; drop`.
fn build_drop_rule(table: &str, chain: &str, set: &str, family: SetFamily, seq: u32) -> Vec<u8> {
    // meta nfproto -> reg1
    let mut meta = Vec::new();
    push_nla_be32(&mut meta, NFTA_META_KEY, NFT_META_NFPROTO);
    push_nla_be32(&mut meta, NFTA_META_DREG, NFT_REG_1);

    // cmp reg1 == nfproto (a single byte)
    let mut cmp_value = Vec::new();
    push_nla(&mut cmp_value, NFTA_DATA_VALUE, &[family.nfproto()]);
    let mut cmp = Vec::new();
    push_nla_be32(&mut cmp, NFTA_CMP_SREG, NFT_REG_1);
    push_nla_be32(&mut cmp, NFTA_CMP_OP, NFT_CMP_EQ);
    push_nla_nested(&mut cmp, NFTA_CMP_DATA, &cmp_value);

    // payload: load the network-header source address into reg1
    let mut payload = Vec::new();
    push_nla_be32(&mut payload, NFTA_PAYLOAD_DREG, NFT_REG_1);
    push_nla_be32(&mut payload, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    push_nla_be32(&mut payload, NFTA_PAYLOAD_OFFSET, family.saddr_offset());
    push_nla_be32(&mut payload, NFTA_PAYLOAD_LEN, family.key_len());

    // lookup reg1 in @set (by name — the set is already committed).
    let mut lookup = Vec::new();
    push_nla_be32(&mut lookup, NFTA_LOOKUP_SREG, NFT_REG_1);
    push_nla_str(&mut lookup, NFTA_LOOKUP_SET, set);

    // immediate verdict drop
    let mut verdict = Vec::new();
    push_nla_be32(&mut verdict, NFTA_VERDICT_CODE, NF_DROP);
    let mut immediate_data = Vec::new();
    push_nla_nested(&mut immediate_data, NFTA_DATA_VERDICT, &verdict);
    let mut immediate = Vec::new();
    push_nla_be32(&mut immediate, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
    push_nla_nested(&mut immediate, NFTA_IMMEDIATE_DATA, &immediate_data);

    let mut expressions = Vec::new();
    push_expr(&mut expressions, "meta", &meta);
    push_expr(&mut expressions, "cmp", &cmp);
    push_expr(&mut expressions, "payload", &payload);
    push_expr(&mut expressions, "lookup", &lookup);
    push_expr(&mut expressions, "immediate", &immediate);

    let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
    push_nla_str(&mut body, NFTA_RULE_TABLE, table);
    push_nla_str(&mut body, NFTA_RULE_CHAIN, chain);
    push_nla_nested(&mut body, NFTA_RULE_EXPRESSIONS, &expressions);
    nlmsg(
        nft_type(NFT_MSG_NEWRULE),
        OBJECT_FLAGS | NLM_F_APPEND,
        seq,
        &body,
    )
}

// --- batch framing + transport ---------------------------------------------

/// Wrap object messages in `BATCH_BEGIN`/`BATCH_END` so the kernel applies
/// them as one atomic transaction. The batch envelope's `nfgenmsg.res_id`
/// selects the nf_tables subsystem. Object seqs run 1..=N; BATCH_END is N+1.
fn wrap_batch(messages: &[Vec<u8>]) -> Vec<u8> {
    let begin = nlmsg(
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        0,
        &nfgenmsg(NFPROTO_UNSPEC, NFNL_SUBSYS_NFTABLES),
    );
    let end = nlmsg(
        NFNL_MSG_BATCH_END,
        NLM_F_REQUEST,
        (messages.len() + 1) as u32,
        &nfgenmsg(NFPROTO_UNSPEC, NFNL_SUBSYS_NFTABLES),
    );
    let mut buffer = begin;
    for message in messages {
        buffer.extend_from_slice(message);
    }
    buffer.extend_from_slice(&end);
    buffer
}

const EEXIST: i32 = 17;
const ENOENT: i32 = 2;

/// Bound the blocking `recv` with `SO_RCVTIMEO` so a lost ack surfaces as an
/// error instead of parking the thread forever. `netlink-sys` exposes no
/// timeout setter, so this goes through `libc::setsockopt` on the raw fd
/// (`libc` is already in the tree as a hard dependency of `netlink-sys`).
fn set_recv_timeout(socket: &Socket, timeout: Duration) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let timeval = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: libc::suseconds_t::from(timeout.subsec_micros()),
    };
    // SAFETY: plain setsockopt on a socket fd we own, passing a properly sized
    // and initialized `timeval` — no aliasing, no retained pointers.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeval).cast::<libc::c_void>(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Send a batch and read its `object_count` per-message acks. A successful
/// batch yields one errno-0 `NLMSG_ERROR` per acked object message; a failure
/// yields the offending message's errno and rolls the transaction back
/// atomically. Blocking I/O is offloaded to `spawn_blocking` (bans are rare, a
/// fresh socket per transaction is fine — matches the XFRM backend); the recv
/// is bounded by [`ACK_RECV_TIMEOUT`] so a missing ack cannot wedge the thread.
///
/// `benign_errno` is the ONE errno this operation may treat as idempotent
/// success (see [`count_acks`]). Because a kernel-side benign errno still
/// aborts the whole transaction, callers must never batch a benign-errno-able
/// message together with messages whose effects they rely on — element
/// add/remove are single-message batches for exactly this reason.
async fn send(buffer: Vec<u8>, object_count: usize, benign_errno: Option<i32>) -> io::Result<()> {
    let expected = buffer.len();
    tokio::task::spawn_blocking(move || -> io::Result<()> {
        let socket = Socket::new(NETLINK_NETFILTER)?;
        set_recv_timeout(&socket, ACK_RECV_TIMEOUT)?;
        socket.connect(&SocketAddr::new(0, 0))?;
        let sent = socket.send(&buffer, 0)?;
        if sent != expected {
            return Err(io::Error::other(format!("nftables: short send ({sent}/{expected})")));
        }
        let mut seen = 0usize;
        let mut response = vec![0u8; 8192];
        while seen < object_count {
            let received = socket.recv(&mut &mut response[..], 0).map_err(|error| {
                if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("nftables: timed out waiting for kernel ack ({seen}/{object_count} received)"),
                    )
                } else {
                    error
                }
            })?;
            seen += count_acks(&response[..received], benign_errno)?;
        }
        Ok(())
    })
    .await
    .map_err(|join| io::Error::other(format!("nftables netlink task panic: {join}")))?
}

/// Count the errno-0 acks in a reply, returning `Err` on a real kernel error.
///
/// `benign_errno` scopes idempotency to the operation at hand instead of
/// blanket-accepting: an add may treat `EEXIST` (element already present) as
/// success, a delete may treat `ENOENT` (element already expired) as success —
/// but an add must NOT swallow `ENOENT`, because there it means the set/table
/// is gone (e.g. an operator `nft flush ruleset`) and kernel enforcement has
/// silently stopped. That case must surface so the actor can log it.
fn count_acks(buffer: &[u8], benign_errno: Option<i32>) -> io::Result<usize> {
    let mut offset = 0;
    let mut ok = 0;
    while offset + NLMSG_HDR_LEN <= buffer.len() {
        let len = u32::from_ne_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]) as usize;
        let msg_type = u16::from_ne_bytes([buffer[offset + 4], buffer[offset + 5]]);
        if len < NLMSG_HDR_LEN || offset + len > buffer.len() {
            return Err(io::Error::other("nftables: malformed reply"));
        }
        if msg_type == NLMSG_ERROR {
            if len < NLMSG_HDR_LEN + 4 {
                return Err(io::Error::other("nftables: short NLMSG_ERROR"));
            }
            let errno = i32::from_ne_bytes([
                buffer[offset + NLMSG_HDR_LEN],
                buffer[offset + NLMSG_HDR_LEN + 1],
                buffer[offset + NLMSG_HDR_LEN + 2],
                buffer[offset + NLMSG_HDR_LEN + 3],
            ]);
            if errno == 0 || Some(-errno) == benign_errno {
                ok += 1;
            } else {
                return Err(io::Error::from_raw_os_error(-errno));
            }
        }
        offset += align_to(len, NLMSG_ALIGNTO);
    }
    Ok(ok)
}

/// Read one chunk of the answer to an identity query.
///
/// The kernel answers a found object with its description and then an errno-0
/// ack, possibly across two `recv`s. The description's `handle_attr` is stored
/// in `handle`; the ack finishes the query as `Some(true)`, and `ENOENT`
/// finishes it as `Some(false)`. `None` means the ack is still to come.
///
/// Any other errno is a real error. `EPERM` from a lost capability must not
/// read as "absent", which would re-declare into the same failure every tick,
/// nor as "present", which would hide it.
fn read_lookup(
    buffer: &[u8],
    handle_attr: u16,
    handle: &mut Option<u64>,
) -> io::Result<Option<bool>> {
    let mut offset = 0;
    while offset + NLMSG_HDR_LEN <= buffer.len() {
        let len = u32::from_ne_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]) as usize;
        let msg_type = u16::from_ne_bytes([buffer[offset + 4], buffer[offset + 5]]);
        if len < NLMSG_HDR_LEN || offset + len > buffer.len() {
            return Err(io::Error::other("nftables: malformed reply"));
        }
        if msg_type == NLMSG_ERROR {
            if len < NLMSG_HDR_LEN + 4 {
                return Err(io::Error::other("nftables: short NLMSG_ERROR"));
            }
            let errno = i32::from_ne_bytes([
                buffer[offset + NLMSG_HDR_LEN],
                buffer[offset + NLMSG_HDR_LEN + 1],
                buffer[offset + NLMSG_HDR_LEN + 2],
                buffer[offset + NLMSG_HDR_LEN + 3],
            ]);
            return match -errno {
                0 => Ok(Some(true)),
                ENOENT => Ok(Some(false)),
                other => Err(io::Error::from_raw_os_error(other)),
            };
        }
        // The object's description: nlmsghdr, nfgenmsg, then its attributes.
        let attributes_start = offset + NLMSG_HDR_LEN + 4;
        if attributes_start <= offset + len {
            if let Some(value) =
                find_be64_attr(&buffer[attributes_start..offset + len], handle_attr)
            {
                *handle = Some(value);
            }
        }
        offset += align_to(len, NLMSG_ALIGNTO);
    }
    Ok(None)
}

/// The value of the first top-level big-endian u64 attribute of `wanted` type.
fn find_be64_attr(attributes: &[u8], wanted: u16) -> Option<u64> {
    let mut offset = 0;
    while offset + 4 <= attributes.len() {
        let nla_len = u16::from_ne_bytes([attributes[offset], attributes[offset + 1]]) as usize;
        let nla_type =
            u16::from_ne_bytes([attributes[offset + 2], attributes[offset + 3]]) & !NLA_F_NESTED;
        if nla_len < 4 || offset + nla_len > attributes.len() {
            return None;
        }
        if nla_type == wanted && nla_len == 4 + 8 {
            let mut value = [0u8; 8];
            value.copy_from_slice(&attributes[offset + 4..offset + 12]);
            return Some(u64::from_be_bytes(value));
        }
        offset += align_to(nla_len, NLA_ALIGNTO);
    }
    None
}

/// Look each object up and collect its kernel handle, stopping at the first
/// that is missing (`Ok(None)`). One socket for all of them, each query
/// answered before the next is sent.
async fn lookup_handles(queries: Vec<(Vec<u8>, u16)>) -> io::Result<Option<Vec<u64>>> {
    tokio::task::spawn_blocking(move || -> io::Result<Option<Vec<u64>>> {
        let socket = Socket::new(NETLINK_NETFILTER)?;
        set_recv_timeout(&socket, ACK_RECV_TIMEOUT)?;
        socket.connect(&SocketAddr::new(0, 0))?;
        let mut response = vec![0u8; 8192];
        let mut handles = Vec::with_capacity(queries.len());
        for (query, handle_attr) in queries {
            let sent = socket.send(&query, 0)?;
            if sent != query.len() {
                return Err(io::Error::other(format!(
                    "nftables: short send ({sent}/{})",
                    query.len()
                )));
            }
            let mut handle = None;
            let found = loop {
                let received = socket.recv(&mut &mut response[..], 0).map_err(|error| {
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "nftables: timed out waiting for a lookup answer",
                        )
                    } else {
                        error
                    }
                })?;
                if let Some(found) = read_lookup(&response[..received], handle_attr, &mut handle)? {
                    break found;
                }
            };
            if !found {
                return Ok(None);
            }
            let handle = handle.ok_or_else(|| {
                io::Error::other("nftables: an object was found but its answer carried no handle")
            })?;
            handles.push(handle);
        }
        Ok(Some(handles))
    })
    .await
    .map_err(|join| io::Error::other(format!("nftables netlink task panic: {join}")))?
}

// --- public operations ------------------------------------------------------

/// Ensure the `inet` table + both timeout sets exist, and — when `manage_rule`
/// — the base chain + drop rules that reference them, all in ONE idempotent,
/// atomic netlink transaction.
///
/// Every object is declared with `NLM_F_CREATE` (a no-op when it already
/// exists), and the chain's rules are flushed and re-appended, so a first run,
/// a clean restart, and a restart after a crash that interrupted a previous
/// setup all converge to exactly the same ruleset — no half-configured state,
/// no stacked-duplicate rules. Because it is a single `BATCH_BEGIN … BATCH_END`
/// the kernel applies all of it or none of it, and the drop rule is never
/// missing for even an instant across the flush/re-append.
///
/// With `manage_rule` the operator needs no manual `nft` step at all; without it
/// siphon owns only the sets and the operator references them from their own
/// rule.
pub async fn ensure_firewall(
    table: &str,
    chain: &str,
    set_v4: &str,
    set_v6: &str,
    manage_rule: bool,
    gateway_sets: Option<(&str, &str)>,
) -> io::Result<()> {
    // Object seqs run 1..=N within the batch (BATCH_END is N+1, set by
    // `wrap_batch`). The kernel resolves the rules' set/chain references against
    // the objects staged earlier in the same transaction, so table → sets →
    // chain → rules in one batch is self-consistent.
    let mut messages = vec![
        build_new_table(table, 1),
        build_new_set(table, set_v4, 1, SetFamily::V4, 2),
        build_new_set(table, set_v6, 2, SetFamily::V6, 3),
    ];
    let mut seq = 4;
    // The allow sets are declared whenever the firewall is enabled, so an
    // operator's own `nft -f` referencing them loads on a fresh node — before
    // siphon has published anything into them. siphon writes no rule for them
    // in either `manage_rule` mode: an `accept` inside siphon's chain would
    // also make a gateway immune to the drop rules below, and that is the
    // operator's policy call, not a side effect of declaring a set.
    if let Some((gateways_v4, gateways_v6)) = gateway_sets {
        messages.push(build_new_interval_set(
            table,
            gateways_v4,
            3,
            SetFamily::V4,
            seq,
        ));
        seq += 1;
        messages.push(build_new_interval_set(
            table,
            gateways_v6,
            4,
            SetFamily::V6,
            seq,
        ));
        seq += 1;
    }
    if manage_rule {
        messages.push(build_new_chain(table, chain, seq));
        seq += 1;
        // Flush before re-appending so a restart never stacks a duplicate rule.
        messages.push(build_flush_chain(table, chain, seq));
        seq += 1;
        messages.push(build_drop_rule(table, chain, set_v4, SetFamily::V4, seq));
        seq += 1;
        messages.push(build_drop_rule(table, chain, set_v6, SetFamily::V6, seq));
    }
    let object_count = messages.len();
    // No benign errno: every object is declared with `NLM_F_CREATE` (existing
    // objects ack errno-0, never `EEXIST`), so ANY errno here is a real,
    // batch-aborting failure that must reach the caller.
    send(wrap_batch(&messages), object_count, None).await
}

/// The kernel identity of everything [`ensure_firewall`] declares with the same
/// arguments: one handle per object, or `None` when any of them is missing.
/// A read, not a transaction: a node whose ruleset nobody touched pays a
/// handful of lookups and changes nothing.
///
/// Presence alone is not enough, and handles are why. An operator's own
/// ruleset that references `@gateways4` only loads if it declares that set
/// itself — after `delete table` there is nothing to reference — so after a
/// reload the set is back, under the same name, and **empty**. The table's
/// handle is what tells the two apart: it comes from a per-namespace counter
/// that only goes up, so a recreated table never reuses one. The objects'
/// own handles restart inside a new table and can repeat, which is why the
/// table's handle is in the fingerprint and not only theirs; theirs catch a
/// single set deleted and recreated inside a table that survived.
///
/// Not seen here: a rule deleted from a chain that still exists, and a set
/// flushed rather than deleted. Neither changes a handle.
pub async fn firewall_fingerprint(
    table: &str,
    chain: &str,
    set_v4: &str,
    set_v6: &str,
    manage_rule: bool,
    gateway_sets: Option<(&str, &str)>,
) -> io::Result<Option<Vec<u64>>> {
    lookup_handles(identity_queries(
        table,
        chain,
        set_v4,
        set_v6,
        manage_rule,
        gateway_sets,
    ))
    .await
}

/// The lookups [`firewall_fingerprint`] sends, each with the attribute its
/// answer carries the handle in: the table, then one per object
/// [`ensure_firewall`] declares.
fn identity_queries(
    table: &str,
    chain: &str,
    set_v4: &str,
    set_v6: &str,
    manage_rule: bool,
    gateway_sets: Option<(&str, &str)>,
) -> Vec<(Vec<u8>, u16)> {
    let mut queries = vec![
        (build_get_table(table, 1), NFTA_TABLE_HANDLE),
        (build_get_set(table, set_v4, 2), NFTA_SET_HANDLE),
        (build_get_set(table, set_v6, 3), NFTA_SET_HANDLE),
    ];
    if let Some((gateways_v4, gateways_v6)) = gateway_sets {
        queries.push((build_get_set(table, gateways_v4, 4), NFTA_SET_HANDLE));
        queries.push((build_get_set(table, gateways_v6, 5), NFTA_SET_HANDLE));
    }
    if manage_rule {
        queries.push((build_get_chain(table, chain, 6), NFTA_CHAIN_HANDLE));
    }
    queries
}

/// Add a banned source to the appropriate set with a per-element timeout
/// (`ttl_ms == 0` = permanent, e.g. an apiban entry). `EEXIST` (element already
/// present, e.g. an apiban re-push after restart) is idempotent success;
/// `ENOENT` (set/table gone) is a real error and surfaces.
pub async fn add_banned(
    table: &str,
    set_v4: &str,
    set_v6: &str,
    address: IpAddr,
    ttl_ms: u64,
) -> io::Result<()> {
    let set = match SetFamily::of(&address) {
        SetFamily::V4 => set_v4,
        SetFamily::V6 => set_v6,
    };
    let message = build_setelem(NFT_MSG_NEWSETELEM, table, set, &address, Some(ttl_ms), 1);
    send(wrap_batch(&[message]), 1, Some(EEXIST)).await
}

/// Remove a banned source (optional — the kernel auto-expires timed elements).
/// `ENOENT` (the kernel already expired the element) is idempotent success.
pub async fn remove_banned(
    table: &str,
    set_v4: &str,
    set_v6: &str,
    address: IpAddr,
) -> io::Result<()> {
    let set = match SetFamily::of(&address) {
        SetFamily::V4 => set_v4,
        SetFamily::V6 => set_v6,
    };
    let message = build_setelem(NFT_MSG_DELSETELEM, table, set, &address, None, 1);
    send(wrap_batch(&[message]), 1, Some(ENOENT)).await
}

/// Replace both gateway allow sets' contents in one atomic transaction: flush
/// each, then add the ranges currently admitted.
///
/// A full replace, not an add/remove diff. A diff cannot converge after an
/// `nft flush ruleset` has wiped the sets under a running siphon, and these
/// sets hold tens of ranges rather than thousands, so re-sending all of them
/// costs nothing. The flush and the adds share one batch, so a packet is never
/// evaluated against a half-written set.
///
/// The ranges must not overlap: an interval set rejects an overlapping element
/// with `EEXIST`, and no errno is treated as benign here. [`super::gateways`]
/// merges before publishing.
pub async fn replace_gateways(
    table: &str,
    set_v4: &str,
    set_v6: &str,
    v4: &[IpNet],
    v6: &[IpNet],
) -> io::Result<()> {
    let mut messages = vec![
        build_flush_set(table, set_v4, 1),
        build_flush_set(table, set_v6, 2),
    ];
    let mut seq = 3;
    if !v4.is_empty() {
        messages.push(build_interval_setelems(table, set_v4, v4, seq));
        seq += 1;
    }
    if !v6.is_empty() {
        messages.push(build_interval_setelems(table, set_v6, v6, seq));
    }
    let object_count = messages.len();
    send(wrap_batch(&messages), object_count, None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn u16_at(buffer: &[u8], offset: usize) -> u16 {
        u16::from_ne_bytes([buffer[offset], buffer[offset + 1]])
    }
    fn u32_at(buffer: &[u8], offset: usize) -> u32 {
        u32::from_ne_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ])
    }
    fn be32(payload: &[u8]) -> u32 {
        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
    }

    /// Split a sequence of netlink attributes into `(type_without_nested_flag,
    /// payload)` pairs. `payload` is the value after the 4-byte attr header,
    /// length `nla_len - 4` (padding excluded). Works for both a top-level
    /// object body (pass `&message[NLMSG_HDR_LEN + 4..]`, i.e. past nlmsghdr +
    /// nfgenmsg) and a nested attribute's payload.
    fn walk_attrs(buffer: &[u8]) -> Vec<(u16, &[u8])> {
        let mut attrs = Vec::new();
        let mut offset = 0;
        while offset + 4 <= buffer.len() {
            let nla_len = u16_at(buffer, offset) as usize;
            let nla_type = u16_at(buffer, offset + 2) & !NLA_F_NESTED;
            if nla_len < 4 || offset + nla_len > buffer.len() {
                break;
            }
            attrs.push((nla_type, &buffer[offset + 4..offset + nla_len]));
            offset += align_to(nla_len, NLA_ALIGNTO);
        }
        attrs
    }

    /// The payload of the first attribute of `attr_type`, or panic. `expect_msg`
    /// names the attribute in the failure.
    fn attr<'a>(attrs: &[(u16, &'a [u8])], attr_type: u16, expect_msg: &str) -> &'a [u8] {
        attrs
            .iter()
            .find(|(ty, _)| *ty == attr_type)
            .map(|(_, payload)| *payload)
            .unwrap_or_else(|| panic!("missing attribute: {expect_msg}"))
    }

    /// The `NFTA_EXPR_DATA` payload of one expression `NFTA_LIST_ELEM`.
    fn expr_data(expr_elem: &[u8]) -> &[u8] {
        attr(&walk_attrs(expr_elem), NFTA_EXPR_DATA, "NFTA_EXPR_DATA")
    }

    #[test]
    fn align_is_4() {
        assert_eq!(align_to(1, 4), 4);
        assert_eq!(align_to(4, 4), 4);
        assert_eq!(align_to(5, 4), 8);
    }

    #[test]
    fn push_nla_pads_to_4() {
        let mut buffer = Vec::new();
        push_nla(&mut buffer, 7, &[0xaa, 0xbb, 0xcc]); // 4 hdr + 3 = 7 -> pad to 8
        assert_eq!(buffer.len(), 8);
        assert_eq!(u16_at(&buffer, 0), 7); // nla_len excludes padding
        assert_eq!(u16_at(&buffer, 2), 7); // nla_type
        assert_eq!(&buffer[4..7], &[0xaa, 0xbb, 0xcc]);
        assert_eq!(buffer[7], 0); // pad
    }

    #[test]
    fn str_attr_is_nul_terminated() {
        let mut buffer = Vec::new();
        push_nla_str(&mut buffer, NFTA_TABLE_NAME, "ab"); // 4 hdr + "ab\0" = 7 -> 8
        assert_eq!(buffer.len(), 8);
        assert_eq!(u16_at(&buffer, 0), 7);
        assert_eq!(&buffer[4..7], b"ab\0");
    }

    #[test]
    fn integer_attrs_are_big_endian() {
        // nf_tables uses network byte order for integer attributes.
        let mut buffer = Vec::new();
        push_nla_be32(&mut buffer, NFTA_SET_KEY_LEN, 4);
        assert_eq!(&buffer[4..8], &[0, 0, 0, 4]); // 4 as be32
    }

    #[test]
    fn nfgenmsg_layout() {
        assert_eq!(nfgenmsg(NFPROTO_INET, 0), [1, 0, 0, 0]);
        assert_eq!(
            nfgenmsg(NFPROTO_UNSPEC, NFNL_SUBSYS_NFTABLES),
            [0, 0, 0, 10]
        );
    }

    #[test]
    fn nlmsg_header_and_wire_type() {
        let message = nlmsg(
            nft_type(NFT_MSG_NEWSET),
            NLM_F_REQUEST | NLM_F_ACK,
            3,
            &[0xde, 0xad],
        );
        assert_eq!(u32_at(&message, 0), 18); // 16 hdr + 2 body
        assert_eq!(u16_at(&message, 4), (10 << 8) | 9); // (NFTABLES<<8)|NEWSET
        assert_eq!(u16_at(&message, 6), NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(u32_at(&message, 8), 3); // seq
        assert_eq!(message.len(), 20); // padded to 4
    }

    #[test]
    fn new_set_carries_timeout_flag_keytype_keylen_and_set_id() {
        let message = build_new_set("siphon", "banned4", 1, SetFamily::V4, 2);
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        assert_eq!(attr(&attrs, NFTA_SET_TABLE, "table"), b"siphon\0");
        assert_eq!(attr(&attrs, NFTA_SET_NAME, "name"), b"banned4\0");
        assert_eq!(be32(attr(&attrs, NFTA_SET_FLAGS, "flags")), NFT_SET_TIMEOUT);
        assert_eq!(
            be32(attr(&attrs, NFTA_SET_KEY_TYPE, "key type")),
            NFT_TYPE_IPADDR
        );
        assert_eq!(be32(attr(&attrs, NFTA_SET_KEY_LEN, "key len")), 4);
        // NFTA_SET_ID is REQUIRED by the kernel for NEWSET (nf_tables_newset
        // returns EINVAL without it) — it identifies the set within a batch.
        assert_eq!(be32(attr(&attrs, NFTA_SET_ID, "set id")), 1);
    }

    #[test]
    fn element_encodes_ipv4_key_and_be_timeout() {
        let element = encode_element(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), Some(3_600_000));
        assert_eq!(u16_at(&element, 2) & !NLA_F_NESTED, NFTA_LIST_ELEM);
        let elem = walk_attrs(attr(&walk_attrs(&element), NFTA_LIST_ELEM, "list elem"));
        let key = walk_attrs(attr(&elem, NFTA_SET_ELEM_KEY, "key"));
        assert_eq!(attr(&key, NFTA_DATA_VALUE, "key value"), &[203, 0, 113, 5]);
        assert_eq!(
            attr(&elem, NFTA_SET_ELEM_TIMEOUT, "timeout"),
            &3_600_000u64.to_be_bytes(),
            "timeout must be big-endian u64 milliseconds"
        );
    }

    #[test]
    fn ipv6_set_family() {
        assert_eq!(SetFamily::V6.key_len(), 16);
        assert_eq!(SetFamily::V6.key_type(), NFT_TYPE_IP6ADDR);
        assert_eq!(
            SetFamily::of(&IpAddr::V6(Ipv6Addr::LOCALHOST)),
            SetFamily::V6
        );
        let octets: [u8; 16] = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        let element = encode_element(&IpAddr::V6("2001:db8::1".parse().unwrap()), Some(0));
        assert!(element.windows(16).any(|w| w == octets));
    }

    #[test]
    fn setelem_add_carries_table_set_key_and_timeout() {
        let address: IpAddr = "203.0.113.5".parse().unwrap();
        let message = build_setelem(
            NFT_MSG_NEWSETELEM,
            "siphon",
            "banned4",
            &address,
            Some(60_000),
            1,
        );
        assert_eq!(u16_at(&message, 4), nft_type(NFT_MSG_NEWSETELEM));
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        assert_eq!(attr(&attrs, NFTA_SET_ELEM_LIST_TABLE, "table"), b"siphon\0");
        assert_eq!(attr(&attrs, NFTA_SET_ELEM_LIST_SET, "set"), b"banned4\0");
        let elements = walk_attrs(attr(&attrs, NFTA_SET_ELEM_LIST_ELEMENTS, "elements"));
        let elem = walk_attrs(attr(&elements, NFTA_LIST_ELEM, "list elem"));
        let key = walk_attrs(attr(&elem, NFTA_SET_ELEM_KEY, "key"));
        assert_eq!(attr(&key, NFTA_DATA_VALUE, "key value"), &[203, 0, 113, 5]);
        assert_eq!(
            attr(&elem, NFTA_SET_ELEM_TIMEOUT, "timeout"),
            &60_000u64.to_be_bytes()
        );
    }

    #[test]
    fn setelem_delete_matches_on_key_alone() {
        // A delete matches on the key; it must not carry a timeout attribute.
        let address: IpAddr = "203.0.113.5".parse().unwrap();
        let message = build_setelem(NFT_MSG_DELSETELEM, "siphon", "banned4", &address, None, 1);
        assert_eq!(u16_at(&message, 4), nft_type(NFT_MSG_DELSETELEM));
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        let elements = walk_attrs(attr(&attrs, NFTA_SET_ELEM_LIST_ELEMENTS, "elements"));
        let elem = walk_attrs(attr(&elements, NFTA_LIST_ELEM, "list elem"));
        let key = walk_attrs(attr(&elem, NFTA_SET_ELEM_KEY, "key"));
        assert_eq!(attr(&key, NFTA_DATA_VALUE, "key value"), &[203, 0, 113, 5]);
        assert!(
            !elem.iter().any(|(ty, _)| *ty == NFTA_SET_ELEM_TIMEOUT),
            "delete must not carry NFTA_SET_ELEM_TIMEOUT"
        );
    }

    #[test]
    fn interval_set_carries_the_interval_flag_and_no_timeout() {
        let message = build_new_interval_set("siphon", "gateways4", 3, SetFamily::V4, 4);
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        assert_eq!(attr(&attrs, NFTA_SET_NAME, "name"), b"gateways4\0");
        let flags = be32(attr(&attrs, NFTA_SET_FLAGS, "flags"));
        assert_eq!(flags & NFT_SET_INTERVAL, NFT_SET_INTERVAL);
        // An allow-set element is replaced by the next publish, never expired:
        // a timeout here would drop a live carrier out of the set.
        assert_eq!(flags & NFT_SET_TIMEOUT, 0);
        assert_eq!(be32(attr(&attrs, NFTA_SET_KEY_LEN, "key len")), 4);
        assert_eq!(be32(attr(&attrs, NFTA_SET_ID, "set id")), 3);
    }

    /// The start key of an encoded range, and the exclusive end key when the
    /// range has one. Asserts the shape `nft_set_rbtree` requires along the
    /// way: the first element carries no flags, the second is flagged as the
    /// interval's end.
    fn interval_bounds(network: &IpNet) -> (Vec<u8>, Option<Vec<u8>>) {
        let encoded = encode_interval_element(network);
        let elements: Vec<Vec<(u16, &[u8])>> = walk_attrs(&encoded)
            .into_iter()
            .filter(|(attr_type, _)| *attr_type == NFTA_LIST_ELEM)
            .map(|(_, payload)| walk_attrs(payload))
            .collect();

        let opener = &elements[0];
        assert!(
            !opener
                .iter()
                .any(|(attr_type, _)| *attr_type == NFTA_SET_ELEM_FLAGS),
            "the element that opens a range must not be flagged as its end"
        );
        let key = walk_attrs(attr(opener, NFTA_SET_ELEM_KEY, "key"));
        let start = attr(&key, NFTA_DATA_VALUE, "start").to_vec();

        let end = elements.get(1).map(|closer| {
            assert_eq!(
                be32(attr(closer, NFTA_SET_ELEM_FLAGS, "flags")),
                NFT_SET_ELEM_INTERVAL_END,
                "the second element must close the interval"
            );
            let key = walk_attrs(attr(closer, NFTA_SET_ELEM_KEY, "key"));
            attr(&key, NFTA_DATA_VALUE, "end").to_vec()
        });
        (start, end)
    }

    #[test]
    fn a_host_prefix_is_a_range_of_one() {
        let (start, end) = interval_bounds(&"203.0.113.5/32".parse().unwrap());
        assert_eq!(start, vec![203, 0, 113, 5]);
        // Exclusive: the end marker is the address *after* the range.
        assert_eq!(end, Some(vec![203, 0, 113, 6]));
    }

    #[test]
    fn a_v4_prefix_ends_one_past_its_last_address() {
        let (start, end) = interval_bounds(&"192.0.2.0/24".parse().unwrap());
        assert_eq!(start, vec![192, 0, 2, 0]);
        assert_eq!(end, Some(vec![192, 0, 3, 0]));
    }

    #[test]
    fn a_v4_prefix_shorter_than_a_byte_boundary() {
        let (start, end) = interval_bounds(&"198.51.100.64/28".parse().unwrap());
        assert_eq!(start, vec![198, 51, 100, 64]);
        assert_eq!(end, Some(vec![198, 51, 100, 80]));
    }

    #[test]
    fn a_v6_prefix_encodes_16_byte_bounds() {
        let (start, end) = interval_bounds(&"2001:db8::/32".parse().unwrap());
        assert_eq!(start, "2001:db8::".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(
            end,
            Some("2001:db9::".parse::<Ipv6Addr>().unwrap().octets().to_vec())
        );
    }

    #[test]
    fn a_range_running_to_the_top_of_the_space_stays_open() {
        // There is no address after the last one to key an end marker on, and
        // none is needed: nothing follows it.
        let (start, end) = interval_bounds(&"0.0.0.0/0".parse().unwrap());
        assert_eq!(start, vec![0, 0, 0, 0]);
        assert_eq!(end, None);
    }

    #[test]
    fn interval_setelems_carries_every_range_in_one_message() {
        let networks: Vec<IpNet> = vec![
            "192.0.2.0/24".parse().unwrap(),
            "203.0.113.5/32".parse().unwrap(),
        ];
        let message = build_interval_setelems("siphon", "gateways4", &networks, 3);
        assert_eq!(u16_at(&message, 4), nft_type(NFT_MSG_NEWSETELEM));
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        assert_eq!(attr(&attrs, NFTA_SET_ELEM_LIST_SET, "set"), b"gateways4\0");
        let elements = walk_attrs(attr(&attrs, NFTA_SET_ELEM_LIST_ELEMENTS, "elements"));
        let elements: Vec<Vec<(u16, &[u8])>> = elements
            .into_iter()
            .filter(|(attr_type, _)| *attr_type == NFTA_LIST_ELEM)
            .map(|(_, payload)| walk_attrs(payload))
            .collect();
        // The opening floor marker, then a start + end pair per range — all in
        // one message, not one message each.
        assert_eq!(elements.len(), 5);

        let floor = walk_attrs(attr(&elements[0], NFTA_SET_ELEM_KEY, "key"));
        assert_eq!(
            attr(&floor, NFTA_DATA_VALUE, "floor"),
            &[0, 0, 0, 0],
            "everything below the first range is marked as outside the set"
        );
        assert_eq!(
            be32(attr(&elements[0], NFTA_SET_ELEM_FLAGS, "flags")),
            NFT_SET_ELEM_INTERVAL_END
        );
    }

    #[test]
    fn flush_set_carries_no_elements() {
        // `nft flush set` is a DELSETELEM with no element list; with one, the
        // kernel would read it as "delete these" instead.
        let message = build_flush_set("siphon", "gateways4", 1);
        assert_eq!(u16_at(&message, 4), nft_type(NFT_MSG_DELSETELEM));
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        assert_eq!(attr(&attrs, NFTA_SET_ELEM_LIST_TABLE, "table"), b"siphon\0");
        assert_eq!(attr(&attrs, NFTA_SET_ELEM_LIST_SET, "set"), b"gateways4\0");
        assert!(
            !attrs
                .iter()
                .any(|(ty, _)| *ty == NFTA_SET_ELEM_LIST_ELEMENTS),
            "a flush must not carry an element list"
        );
    }

    #[test]
    fn new_chain_carries_hook_type_and_priority() {
        let message = build_new_chain("siphon", "input", 4);
        assert_eq!(u16_at(&message, 4), nft_type(NFT_MSG_NEWCHAIN));
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        assert_eq!(attr(&attrs, NFTA_CHAIN_TABLE, "table"), b"siphon\0");
        assert_eq!(attr(&attrs, NFTA_CHAIN_NAME, "name"), b"input\0");
        // A base chain: type "filter", hook = input, priority 0 (NF_IP_PRI_FILTER).
        assert_eq!(attr(&attrs, NFTA_CHAIN_TYPE, "type"), b"filter\0");
        let hook = walk_attrs(attr(&attrs, NFTA_CHAIN_HOOK, "hook"));
        assert_eq!(
            be32(attr(&hook, NFTA_HOOK_HOOKNUM, "hooknum")),
            NF_INET_LOCAL_IN
        );
        assert_eq!(be32(attr(&hook, NFTA_HOOK_PRIORITY, "priority")), 0);
    }

    #[test]
    fn drop_rule_expression_sequence_and_layout() {
        // The v4 rule: `meta nfproto ipv4; ipv4 saddr @banned4; drop`.
        let message = build_drop_rule("siphon", "input", "banned4", SetFamily::V4, 6);
        assert_eq!(u16_at(&message, 4), nft_type(NFT_MSG_NEWRULE));
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        assert_eq!(attr(&attrs, NFTA_RULE_TABLE, "table"), b"siphon\0");
        assert_eq!(attr(&attrs, NFTA_RULE_CHAIN, "chain"), b"input\0");

        // Expressions in order: meta, cmp, payload, lookup, immediate.
        let exprs = walk_attrs(attr(&attrs, NFTA_RULE_EXPRESSIONS, "expressions"));
        let names: Vec<&[u8]> = exprs
            .iter()
            .map(|(_, elem)| attr(&walk_attrs(elem), NFTA_EXPR_NAME, "expr name"))
            .collect();
        assert_eq!(
            names,
            vec![
                b"meta\0".as_ref(),
                b"cmp\0",
                b"payload\0",
                b"lookup\0",
                b"immediate\0"
            ]
        );

        // meta loads nfproto into reg1.
        let meta = walk_attrs(expr_data(exprs[0].1));
        assert_eq!(
            be32(attr(&meta, NFTA_META_KEY, "meta key")),
            NFT_META_NFPROTO
        );
        assert_eq!(be32(attr(&meta, NFTA_META_DREG, "meta dreg")), NFT_REG_1);

        // cmp reg1 == NFPROTO_IPV4 (a single byte) — the guard that keeps a v6
        // packet from matching the v4 saddr offset/length in the shared `inet`
        // chain.
        let cmp = walk_attrs(expr_data(exprs[1].1));
        assert_eq!(be32(attr(&cmp, NFTA_CMP_SREG, "cmp sreg")), NFT_REG_1);
        assert_eq!(be32(attr(&cmp, NFTA_CMP_OP, "cmp op")), NFT_CMP_EQ);
        let cmp_value = walk_attrs(attr(&cmp, NFTA_CMP_DATA, "cmp data"));
        assert_eq!(
            attr(&cmp_value, NFTA_DATA_VALUE, "cmp value"),
            &[NFPROTO_IPV4]
        );

        // payload loads the v4 source address: network base, offset 12, len 4.
        let payload = walk_attrs(expr_data(exprs[2].1));
        assert_eq!(be32(attr(&payload, NFTA_PAYLOAD_DREG, "dreg")), NFT_REG_1);
        assert_eq!(
            be32(attr(&payload, NFTA_PAYLOAD_BASE, "base")),
            NFT_PAYLOAD_NETWORK_HEADER
        );
        assert_eq!(be32(attr(&payload, NFTA_PAYLOAD_OFFSET, "offset")), 12);
        assert_eq!(be32(attr(&payload, NFTA_PAYLOAD_LEN, "len")), 4);

        // lookup references the set by name.
        let lookup = walk_attrs(expr_data(exprs[3].1));
        assert_eq!(
            be32(attr(&lookup, NFTA_LOOKUP_SREG, "lookup sreg")),
            NFT_REG_1
        );
        assert_eq!(attr(&lookup, NFTA_LOOKUP_SET, "lookup set"), b"banned4\0");

        // immediate verdict = drop, into the verdict register.
        let immediate = walk_attrs(expr_data(exprs[4].1));
        assert_eq!(
            be32(attr(&immediate, NFTA_IMMEDIATE_DREG, "imm dreg")),
            NFT_REG_VERDICT
        );
        let imm_data = walk_attrs(attr(&immediate, NFTA_IMMEDIATE_DATA, "imm data"));
        let verdict = walk_attrs(attr(&imm_data, NFTA_DATA_VERDICT, "verdict container"));
        assert_eq!(
            be32(attr(&verdict, NFTA_VERDICT_CODE, "verdict code")),
            NF_DROP
        );
    }

    #[test]
    fn drop_rule_v6_uses_ipv6_saddr_offset_and_len() {
        // The v6 rule must load 16 bytes at offset 8 and guard on NFPROTO_IPV6.
        let message = build_drop_rule("siphon", "input", "banned6", SetFamily::V6, 6);
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        let exprs = walk_attrs(attr(&attrs, NFTA_RULE_EXPRESSIONS, "expressions"));

        let cmp = walk_attrs(expr_data(exprs[1].1));
        let cmp_value = walk_attrs(attr(&cmp, NFTA_CMP_DATA, "cmp data"));
        assert_eq!(
            attr(&cmp_value, NFTA_DATA_VALUE, "cmp value"),
            &[NFPROTO_IPV6]
        );

        let payload = walk_attrs(expr_data(exprs[2].1));
        assert_eq!(be32(attr(&payload, NFTA_PAYLOAD_OFFSET, "offset")), 8);
        assert_eq!(be32(attr(&payload, NFTA_PAYLOAD_LEN, "len")), 16);

        let lookup = walk_attrs(expr_data(exprs[3].1));
        assert_eq!(attr(&lookup, NFTA_LOOKUP_SET, "lookup set"), b"banned6\0");
    }

    #[test]
    fn flush_chain_targets_table_and_chain_with_no_handle() {
        // A flush is DELRULE carrying only table + chain (no rule handle), so the
        // kernel drops every rule in the chain.
        const NFTA_RULE_HANDLE: u16 = 3; // absent = flush all rules in the chain
        let message = build_flush_chain("siphon", "input", 5);
        assert_eq!(u16_at(&message, 4), nft_type(NFT_MSG_DELRULE));
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        assert_eq!(attr(&attrs, NFTA_RULE_TABLE, "table"), b"siphon\0");
        assert_eq!(attr(&attrs, NFTA_RULE_CHAIN, "chain"), b"input\0");
        assert!(
            !attrs.iter().any(|(ty, _)| *ty == NFTA_RULE_HANDLE),
            "flush must carry no rule handle"
        );
    }

    #[test]
    fn get_table_is_a_bare_acked_lookup_by_name() {
        let message = build_get_table("edge", 1);
        assert_eq!(u16_at(&message, 4), (10 << 8) | NFT_MSG_GETTABLE);
        // No NLM_F_CREATE, no batch: a lookup must never be able to declare.
        assert_eq!(u16_at(&message, 6), NLM_F_REQUEST | NLM_F_ACK);
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        assert_eq!(attr(&attrs, NFTA_TABLE_NAME, "name"), b"edge\0");
        assert_eq!(attrs.len(), 1);
    }

    #[test]
    fn get_set_is_a_bare_acked_lookup_by_table_and_name() {
        let message = build_get_set("edge", "gateways4", 1);
        assert_eq!(u16_at(&message, 4), (10 << 8) | NFT_MSG_GETSET);
        assert_eq!(u16_at(&message, 6), NLM_F_REQUEST | NLM_F_ACK);
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        assert_eq!(attr(&attrs, NFTA_SET_TABLE, "table"), b"edge\0");
        assert_eq!(attr(&attrs, NFTA_SET_NAME, "name"), b"gateways4\0");
        assert_eq!(attrs.len(), 2);
    }

    #[test]
    fn get_chain_is_a_bare_acked_lookup_by_table_and_name() {
        let message = build_get_chain("edge", "input", 1);
        assert_eq!(u16_at(&message, 4), (10 << 8) | NFT_MSG_GETCHAIN);
        assert_eq!(u16_at(&message, 6), NLM_F_REQUEST | NLM_F_ACK);
        let attrs = walk_attrs(&message[NLMSG_HDR_LEN + 4..]);
        assert_eq!(attr(&attrs, NFTA_CHAIN_TABLE, "table"), b"edge\0");
        assert_eq!(attr(&attrs, NFTA_CHAIN_NAME, "name"), b"input\0");
    }

    /// `(message type, handle attribute)` of each identity query.
    fn query_shapes(queries: &[(Vec<u8>, u16)]) -> Vec<(u16, u16)> {
        queries
            .iter()
            .map(|(message, handle_attr)| (u16_at(message, 4) & 0xff, *handle_attr))
            .collect()
    }

    #[test]
    fn identity_queries_cover_the_table_and_every_declared_object() {
        let queries = identity_queries(
            "edge",
            "input",
            "banned4",
            "banned6",
            true,
            Some(("gateways4", "gateways6")),
        );
        assert_eq!(
            query_shapes(&queries),
            vec![
                (NFT_MSG_GETTABLE, NFTA_TABLE_HANDLE),
                (NFT_MSG_GETSET, NFTA_SET_HANDLE),
                (NFT_MSG_GETSET, NFTA_SET_HANDLE),
                (NFT_MSG_GETSET, NFTA_SET_HANDLE),
                (NFT_MSG_GETSET, NFTA_SET_HANDLE),
                (NFT_MSG_GETCHAIN, NFTA_CHAIN_HANDLE),
            ]
        );
        let set_names: Vec<&[u8]> = queries[1..5]
            .iter()
            .map(|(message, _)| {
                attr(
                    &walk_attrs(&message[NLMSG_HDR_LEN + 4..]),
                    NFTA_SET_NAME,
                    "set name",
                )
            })
            .collect();
        assert_eq!(
            set_names,
            vec![
                &b"banned4\0"[..],
                &b"banned6\0"[..],
                &b"gateways4\0"[..],
                &b"gateways6\0"[..],
            ]
        );
    }

    #[test]
    fn identity_queries_skip_what_was_not_declared() {
        // manage_rule off and no allow set: only the table and the ban sets
        // were declared, so a missing chain must not read as a reload.
        let queries = identity_queries("siphon", "input", "banned4", "banned6", false, None);
        assert_eq!(
            query_shapes(&queries),
            vec![
                (NFT_MSG_GETTABLE, NFTA_TABLE_HANDLE),
                (NFT_MSG_GETSET, NFTA_SET_HANDLE),
                (NFT_MSG_GETSET, NFTA_SET_HANDLE),
            ]
        );
    }

    /// An `NLMSG_ERROR` carrying `errno` (kernel sign convention: negative).
    fn nlmsg_error(errno: i32) -> Vec<u8> {
        let mut body = errno.to_ne_bytes().to_vec();
        body.extend_from_slice(&[0u8; NLMSG_HDR_LEN]); // the echoed request header
        nlmsg(NLMSG_ERROR, 0, 1, &body)
    }

    /// A found set's description, as the kernel sends it: nfgenmsg, the name,
    /// and the handle as a be64 attribute.
    fn set_description(handle: u64) -> Vec<u8> {
        let mut body = nfgenmsg(NFPROTO_INET, 0).to_vec();
        push_nla_str(&mut body, NFTA_SET_NAME, "gateways4");
        push_nla_be64(&mut body, NFTA_SET_HANDLE, handle);
        nlmsg(nft_type(NFT_MSG_NEWSET), 0, 1, &body)
    }

    #[test]
    fn a_found_object_yields_its_handle_on_the_ack() {
        let mut reply = set_description(7);
        reply.extend_from_slice(&nlmsg_error(0));
        let mut handle = None;
        assert_eq!(
            read_lookup(&reply, NFTA_SET_HANDLE, &mut handle).unwrap(),
            Some(true)
        );
        assert_eq!(handle, Some(7));
    }

    #[test]
    fn the_ack_may_arrive_in_a_later_recv() {
        let mut handle = None;
        assert_eq!(
            read_lookup(&set_description(9), NFTA_SET_HANDLE, &mut handle).unwrap(),
            None,
            "the description alone does not finish the query"
        );
        assert_eq!(handle, Some(9));
        assert_eq!(
            read_lookup(&nlmsg_error(0), NFTA_SET_HANDLE, &mut handle).unwrap(),
            Some(true)
        );
        assert_eq!(handle, Some(9), "the ack must not clear the handle");
    }

    #[test]
    fn enoent_reads_as_absent() {
        let mut handle = None;
        assert_eq!(
            read_lookup(&nlmsg_error(-ENOENT), NFTA_SET_HANDLE, &mut handle).unwrap(),
            Some(false)
        );
        assert_eq!(handle, None);
    }

    #[test]
    fn any_other_errno_surfaces() {
        // EPERM (a lost CAP_NET_ADMIN) is neither present nor absent.
        let mut handle = None;
        let error = read_lookup(&nlmsg_error(-1), NFTA_SET_HANDLE, &mut handle)
            .expect_err("EPERM must surface");
        assert_eq!(error.raw_os_error(), Some(1));
    }

    #[test]
    fn a_handle_under_another_attribute_is_not_taken() {
        // NFTA_TABLE_HANDLE (4) is NFTA_SET_KEY_TYPE on a set: reading the
        // wrong attribute would fingerprint the key type, which never changes.
        let mut handle = None;
        let mut reply = set_description(7);
        reply.extend_from_slice(&nlmsg_error(0));
        read_lookup(&reply, NFTA_CHAIN_HANDLE, &mut handle).unwrap();
        assert_eq!(handle, None);
    }

    #[test]
    fn batch_wraps_begin_and_end() {
        let inner = build_new_table("siphon", 1);
        let batch = wrap_batch(std::slice::from_ref(&inner));
        assert_eq!(u16_at(&batch, 4), NFNL_MSG_BATCH_BEGIN);
        let after_begin = 20; // BATCH_BEGIN = 16 hdr + 4 nfgenmsg
        assert_eq!(u16_at(&batch, after_begin + 4), nft_type(NFT_MSG_NEWTABLE));
        let end_offset = after_begin + inner.len();
        assert_eq!(u16_at(&batch, end_offset + 4), NFNL_MSG_BATCH_END);
    }

    #[test]
    fn count_acks_success_and_error() {
        let ok = nlmsg(NLMSG_ERROR, 0, 1, &0i32.to_ne_bytes());
        assert_eq!(count_acks(&ok, None).unwrap(), 1);
        let eperm = nlmsg(NLMSG_ERROR, 0, 1, &(-1i32).to_ne_bytes());
        assert!(count_acks(&eperm, None).is_err());
        // Two acks coalesced into one datagram both count.
        let mut two = nlmsg(NLMSG_ERROR, 0, 1, &0i32.to_ne_bytes());
        two.extend_from_slice(&nlmsg(NLMSG_ERROR, 0, 2, &0i32.to_ne_bytes()));
        assert_eq!(count_acks(&two, None).unwrap(), 2);
    }

    #[test]
    fn count_acks_benign_errno_is_operation_scoped() {
        let eexist = nlmsg(NLMSG_ERROR, 0, 1, &(-EEXIST).to_ne_bytes());
        let enoent = nlmsg(NLMSG_ERROR, 0, 1, &(-ENOENT).to_ne_bytes());
        // Add: re-adding an existing element is idempotent success...
        assert_eq!(count_acks(&eexist, Some(EEXIST)).unwrap(), 1);
        // ...but a missing set/table (operator flushed the ruleset) is a REAL
        // error — swallowing it would silently disable kernel enforcement.
        assert!(count_acks(&enoent, Some(EEXIST)).is_err());
        // Delete: removing an already-expired element is idempotent success.
        assert_eq!(count_acks(&enoent, Some(ENOENT)).unwrap(), 1);
        assert!(count_acks(&eexist, Some(ENOENT)).is_err());
        // Ensure: nothing is benign — every object uses NLM_F_CREATE, so any
        // errno means the atomic batch was rolled back.
        assert!(count_acks(&eexist, None).is_err());
        assert!(count_acks(&enoent, None).is_err());
    }

    /// End-to-end against the real kernel. Needs `CAP_NET_ADMIN`; run in a
    /// throwaway net namespace so it touches nothing real:
    ///   `unshare -rn cargo test -- --ignored live_kernel_roundtrip --nocapture`
    #[test]
    #[ignore = "requires CAP_NET_ADMIN (run under `unshare -rn`)"]
    fn live_kernel_roundtrip() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let gateway_sets = Some(("gateways4", "gateways6"));
            ensure_firewall("siphon", "input", "banned4", "banned6", true, gateway_sets)
                .await
                .expect("ensure_firewall");
            // Restart: must be idempotent AND not stack duplicate rules.
            ensure_firewall("siphon", "input", "banned4", "banned6", true, gateway_sets)
                .await
                .expect("ensure_firewall restart");
            add_banned(
                "siphon",
                "banned4",
                "banned6",
                "203.0.113.5".parse().unwrap(),
                3_600_000,
            )
            .await
            .expect("add v4");
            // Timed element that STAYS, so `nft list` shows its timeout below.
            add_banned(
                "siphon",
                "banned4",
                "banned6",
                "198.51.100.7".parse().unwrap(),
                3_600_000,
            )
            .await
            .expect("add v4 timed");
            add_banned(
                "siphon",
                "banned4",
                "banned6",
                "2001:db8::1".parse().unwrap(),
                0,
            )
            .await
            .expect("add v6 permanent");
            // Re-adding an existing element (apiban re-push after restart) is
            // idempotent success, not an error.
            add_banned(
                "siphon",
                "banned4",
                "banned6",
                "2001:db8::1".parse().unwrap(),
                0,
            )
            .await
            .expect("re-add v6 must be idempotent");
            remove_banned(
                "siphon",
                "banned4",
                "banned6",
                "203.0.113.5".parse().unwrap(),
            )
            .await
            .expect("remove v4");
            // Removing an element the kernel already expired/never had is
            // idempotent success.
            remove_banned(
                "siphon",
                "banned4",
                "banned6",
                "203.0.113.99".parse().unwrap(),
            )
            .await
            .expect("remove of a missing element must be idempotent");
            // But an add into a missing set is a REAL failure and must surface
            // (a swallowed ENOENT here would silently disable kernel
            // enforcement while siphon believes bans are being dropped).
            add_banned(
                "siphon",
                "no_such_set",
                "no_such_set6",
                "203.0.113.5".parse().unwrap(),
                0,
            )
            .await
            .expect_err("add into a missing set must error, not silently succeed");
            // manage_rule=false owns only table + sets — no chain, no rules.
            ensure_firewall("siphon_sets", "input", "banned4", "banned6", false, None)
                .await
                .expect("ensure_firewall sets-only");

            // Gateway allow set: publish a mixed address/CIDR set, then replace
            // it with a smaller one. The replace is what proves a carrier
            // removed from the source stops being admitted, which an
            // add-only publisher would never do.
            replace_gateways(
                "siphon",
                "gateways4",
                "gateways6",
                &["198.51.100.128/25".parse().unwrap()],
                &[],
            )
            .await
            .expect("publish gateway allow set");
            // Replace, not merge: the first publish must be gone afterwards.
            replace_gateways(
                "siphon",
                "gateways4",
                "gateways6",
                &[
                    "192.0.2.0/24".parse().unwrap(),
                    "203.0.113.9/32".parse().unwrap(),
                ],
                &["2001:db8:1::/48".parse().unwrap()],
            )
            .await
            .expect("republish gateway allow set");
        });

        let output = std::process::Command::new("nft")
            .args(["list", "ruleset"])
            .output()
            .expect("run nft");
        let text = String::from_utf8_lossy(&output.stdout);
        // Sets + elements.
        assert!(
            text.contains("banned4") && text.contains("banned6"),
            "sets missing:\n{text}"
        );
        assert!(
            text.contains("2001:db8::1"),
            "v6 permanent element missing:\n{text}"
        );
        assert!(
            text.contains("flags timeout"),
            "timeout flag missing:\n{text}"
        );
        assert!(
            !text.contains("203.0.113.5"),
            "removed v4 element still present:\n{text}"
        );
        // The timed element must carry a kernel-side expiry.
        assert!(
            text.contains("198.51.100.7"),
            "timed v4 element missing:\n{text}"
        );
        assert!(
            text.contains("expires"),
            "per-element timeout not armed:\n{text}"
        );
        // Self-contained chain + drop rules.
        assert!(text.contains("chain input"), "base chain missing:\n{text}");
        assert!(
            text.contains("@banned4") && text.contains("@banned6"),
            "drop rules missing:\n{text}"
        );
        assert!(text.contains("drop"), "drop verdict missing:\n{text}");
        // The double ensure_firewall must NOT have duplicated the rules.
        assert_eq!(
            text.matches("@banned4 drop").count(),
            1,
            "duplicate v4 drop rule:\n{text}"
        );
        assert_eq!(
            text.matches("@banned6 drop").count(),
            1,
            "duplicate v6 drop rule:\n{text}"
        );

        // The sets-only table: sets exist, but no chain and no rules.
        let output = std::process::Command::new("nft")
            .args(["list", "table", "inet", "siphon_sets"])
            .output()
            .expect("run nft");
        let sets_only = String::from_utf8_lossy(&output.stdout);
        assert!(
            sets_only.contains("banned4"),
            "sets-only table missing sets:\n{sets_only}"
        );
        assert!(
            !sets_only.contains("chain"),
            "manage_rule=false must not create a chain:\n{sets_only}"
        );
        assert!(
            !sets_only.contains("gateways4"),
            "gateway_set=None must not declare an allow set:\n{sets_only}"
        );

        // The gateway allow set: declared as an interval set, holding what the
        // second publish left, and nothing the first one held on its own.
        assert!(
            text.contains("gateways4") && text.contains("gateways6"),
            "gateway allow sets missing:\n{text}"
        );
        assert!(
            text.contains("flags interval"),
            "allow set is not an interval set:\n{text}"
        );
        assert!(
            text.contains("192.0.2.0/24"),
            "published v4 range missing:\n{text}"
        );
        assert!(
            text.contains("203.0.113.9"),
            "published v4 host missing:\n{text}"
        );
        assert!(
            text.contains("2001:db8:1::/48"),
            "published v6 range missing:\n{text}"
        );
        assert!(
            !text.contains("198.51.100.128/25"),
            "a replaced range must be gone, not merged with the new one:\n{text}"
        );
    }
}
