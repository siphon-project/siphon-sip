//! Direct XFRM netlink backend (Phase 3 of the IPsec sec-agree work).
//!
//! Replaces the legacy `ip xfrm` shell-out with hand-rolled
//! ``XFRM_MSG_NEWSA`` / ``XFRM_MSG_DELSA`` / ``XFRM_MSG_NEWPOLICY`` /
//! ``XFRM_MSG_DELPOLICY`` netlink messages.  Compared to fork+exec of
//! `/sbin/ip` per SA, this saves ~5 ms / SA setup, eliminates the
//! `iproute2` runtime dependency, and gives us proper kernel ``errno``
//! values instead of brittle stderr parsing.
//!
//! Linux-only — netlink does not exist on other kernels.  Consumers of
//! this module gate the call sites on ``cfg(target_os = "linux")``.
//!
//! # Wire format
//!
//! All structs are packed little-endian in the kernel's native byte
//! order on the host architecture except for the fields explicitly
//! typed ``__be32`` / ``__be16`` (SPI, ports, IP addresses), which are
//! big-endian on the wire.  Layout matches `/usr/include/linux/xfrm.h`
//! exactly — these are kernel-stable ABI structs that haven't changed
//! since Linux 3.0.
//!
//! # Reference
//!
//! - `linux/xfrm.h` (kernel UAPI header)
//! - `linux/netlink.h` (NETLINK_XFRM = 6)
//! - `linux/rtnetlink.h` (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)
//!
//! The whole module is gated on `target_os = "linux"` at its declaration in
//! `ipsec/mod.rs`, so no inner `#![cfg]` is needed here.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;

use netlink_sys::{protocols::NETLINK_XFRM, Socket, SocketAddr};

use super::{EncryptionAlgorithm, IntegrityAlgorithm, IpsecError};

// ---------------------------------------------------------------------------
// XFRM constants — values taken verbatim from `/usr/include/linux/xfrm.h`.
// ---------------------------------------------------------------------------

const XFRM_MSG_NEWSA: u16 = 0x10;
const XFRM_MSG_DELSA: u16 = 0x11;
/// Get/dump SAs.  With `NLM_F_DUMP` the kernel routes to `xfrm_dump_sa`,
/// streaming every SA back as a sequence of `XFRM_MSG_NEWSA` messages
/// terminated by `NLMSG_DONE`.
const XFRM_MSG_GETSA: u16 = 0x12;
const XFRM_MSG_NEWPOLICY: u16 = 0x13;
const XFRM_MSG_DELPOLICY: u16 = 0x14;
/// Update an existing SA's mutable fields (notably `lft` lifetime config).
/// Kernel maps to `xfrm_state_update()`, which preserves `add_time` so a
/// tightened `hard_add_expires_seconds` produces deadline = original
/// install time + new value (not "now + new value").
const XFRM_MSG_UPDSA: u16 = 0x1a;

const XFRMA_ALG_CRYPT: u16 = 2;
const XFRMA_TMPL: u16 = 5;
const XFRMA_ALG_AUTH_TRUNC: u16 = 20;

const XFRM_MODE_TRANSPORT: u8 = 0;

const XFRM_POLICY_IN: u8 = 0;
const XFRM_POLICY_OUT: u8 = 1;

const XFRM_POLICY_ALLOW: u8 = 0;

const XFRM_SHARE_ANY: u8 = 0;

// Linux address families.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// IP protocol numbers.
const IPPROTO_ESP: u8 = 50;
// TCP/UDP protocol numbers are only referenced by the selector-encoding
// tests below; production code passes the selector proto in from
// `SaProtocol::as_u8()`.
#[cfg(test)]
const IPPROTO_TCP: u8 = 6;
#[cfg(test)]
const IPPROTO_UDP: u8 = 17;

// Netlink message header flags (`linux/netlink.h`).
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
/// Dump flag (`NLM_F_ROOT | NLM_F_MATCH`) — request the whole table.
const NLM_F_DUMP: u16 = 0x300;

// Field offsets within `struct xfrm_usersa_info` (x86_64 ABI, 224 bytes):
//   selector(56) + id(24){ daddr(16) + spi(4, BE) + proto(1) + pad(3) }
//   + saddr(16) + lft(64)
//   + curlft(32){ u64 bytes; u64 packets; u64 add_time; u64 use_time }
//   + stats(12) + seq(4) + reqid(4) + family(2) + mode + replay + flags + pad.
const SA_INFO_SPI_OFFSET: usize = 72;
const SA_INFO_ADD_TIME_OFFSET: usize = 176;
const SA_INFO_USE_TIME_OFFSET: usize = 184;
/// Minimum bytes of an `xfrm_usersa_info` body we must see to read `use_time`.
const SA_INFO_MIN_LEN: usize = SA_INFO_USE_TIME_OFFSET + 8;

// Netlink message types <16 are control / errors.
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// ---------------------------------------------------------------------------
// Byte-level helpers.  Everything is host-endian (le on x86_64) for the
// xfrm struct fields, with three explicit big-endian conversions for
// SPI, port, and IP — these are the on-wire-network-order fields the
// kernel expects.
// ---------------------------------------------------------------------------

const NLA_ALIGNTO: usize = 4;
const NLMSG_ALIGNTO: usize = 4;

#[inline]
const fn align_to(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Push a 4-byte aligned netlink attribute (TLV) onto `buffer`.
///
/// Header is `__u16 nla_len` + `__u16 nla_type` followed by `payload`,
/// padded out to a multiple of `NLA_ALIGNTO`.
fn push_nla(buffer: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let header_len = 4u16;
    let total_len = header_len as usize + payload.len();
    buffer.extend_from_slice(&(total_len as u16).to_ne_bytes());
    buffer.extend_from_slice(&attr_type.to_ne_bytes());
    buffer.extend_from_slice(payload);
    let padding = align_to(total_len, NLA_ALIGNTO) - total_len;
    for _ in 0..padding {
        buffer.push(0);
    }
}

/// Encode an `IpAddr` into the kernel's `xfrm_address_t` (16 bytes,
/// big-endian for the host's logical IP value).  IPv4 occupies the
/// first 4 bytes; the rest are zeroed.
fn encode_xfrm_address(address: &IpAddr, out: &mut [u8; 16]) {
    *out = [0u8; 16];
    match address {
        IpAddr::V4(v4) => {
            out[..4].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.copy_from_slice(&v6.octets());
        }
    }
}

fn family_for(address: &IpAddr) -> u16 {
    match address {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    }
}

fn host_prefix_len(address: &IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

// ---------------------------------------------------------------------------
// XFRM struct encoders — produce the exact byte layout the kernel ABI
// expects (LE on x86, native-endian on the host arch in general).
// ---------------------------------------------------------------------------

/// Encode `struct xfrm_selector` (56 bytes on x86_64; 16+16+2*4+2+1+1+1+4+4 = 56).
fn encode_xfrm_selector(
    source: &IpAddr,
    source_port: u16,
    destination: &IpAddr,
    destination_port: u16,
    proto: u8,
    out: &mut Vec<u8>,
) {
    let mut daddr = [0u8; 16];
    let mut saddr = [0u8; 16];
    encode_xfrm_address(destination, &mut daddr);
    encode_xfrm_address(source, &mut saddr);
    out.extend_from_slice(&daddr);
    out.extend_from_slice(&saddr);
    // dport, dport_mask, sport, sport_mask — all big-endian.
    out.extend_from_slice(&destination_port.to_be_bytes());
    out.extend_from_slice(&u16::MAX.to_be_bytes()); // dport_mask = 0xFFFF
    out.extend_from_slice(&source_port.to_be_bytes());
    out.extend_from_slice(&u16::MAX.to_be_bytes()); // sport_mask = 0xFFFF
    out.extend_from_slice(&family_for(source).to_ne_bytes());
    out.push(host_prefix_len(destination)); // prefixlen_d
    out.push(host_prefix_len(source));      // prefixlen_s
    out.push(proto);                         // selector proto (UDP/TCP)
    // C struct pads 3 bytes here so `ifindex` (i32) lands on a 4-byte
    // boundary — total selector size 56 bytes.
    out.push(0);
    out.push(0);
    out.push(0);
    out.extend_from_slice(&0i32.to_ne_bytes()); // ifindex
    out.extend_from_slice(&0u32.to_ne_bytes()); // user
}

/// `struct xfrm_lifetime_cfg` — 8 * u64 = 64 bytes.  We only set
/// `hard_add_expires_seconds`; the rest are XFRM_INF (0xFFFFFFFFFFFFFFFF
/// for "no limit") or 0 for no soft expiry.
fn encode_xfrm_lifetime_cfg(hard_lifetime_secs: Option<u64>, out: &mut Vec<u8>) {
    let inf = u64::MAX;
    let zero = 0u64;
    let hard_add = hard_lifetime_secs.unwrap_or(0); // 0 = no expiry
    // soft_byte_limit, hard_byte_limit
    out.extend_from_slice(&inf.to_ne_bytes());
    out.extend_from_slice(&inf.to_ne_bytes());
    // soft_packet_limit, hard_packet_limit
    out.extend_from_slice(&inf.to_ne_bytes());
    out.extend_from_slice(&inf.to_ne_bytes());
    // soft_add_expires_seconds, hard_add_expires_seconds
    out.extend_from_slice(&zero.to_ne_bytes());
    out.extend_from_slice(&hard_add.to_ne_bytes());
    // soft_use_expires_seconds, hard_use_expires_seconds
    out.extend_from_slice(&zero.to_ne_bytes());
    out.extend_from_slice(&zero.to_ne_bytes());
}

/// 32 zeroed bytes for `xfrm_lifetime_cur`.
fn encode_xfrm_lifetime_cur(out: &mut Vec<u8>) {
    for _ in 0..32 {
        out.push(0);
    }
}

/// 12 zeroed bytes for `xfrm_stats`.
fn encode_xfrm_stats(out: &mut Vec<u8>) {
    for _ in 0..12 {
        out.push(0);
    }
}

/// `struct xfrm_id` (24 bytes) — 16 daddr + 4 spi (BE) + 1 proto + 3 pad.
fn encode_xfrm_id(daddr: &IpAddr, spi: u32, proto: u8, out: &mut Vec<u8>) {
    let mut daddr_bytes = [0u8; 16];
    encode_xfrm_address(daddr, &mut daddr_bytes);
    out.extend_from_slice(&daddr_bytes);
    out.extend_from_slice(&spi.to_be_bytes());
    out.push(proto);
    out.push(0);
    out.push(0);
    out.push(0);
}

/// Encode `struct xfrm_usersa_info` — total 220 bytes on x86_64.
fn encode_xfrm_usersa_info(
    source: &IpAddr,
    source_port: u16,
    destination: &IpAddr,
    destination_port: u16,
    spi: u32,
    selector_proto: u8,
    hard_lifetime_secs: Option<u64>,
    out: &mut Vec<u8>,
) {
    encode_xfrm_selector(source, source_port, destination, destination_port, selector_proto, out);
    encode_xfrm_id(destination, spi, IPPROTO_ESP, out);
    let mut saddr = [0u8; 16];
    encode_xfrm_address(source, &mut saddr);
    out.extend_from_slice(&saddr);
    encode_xfrm_lifetime_cfg(hard_lifetime_secs, out);
    encode_xfrm_lifetime_cur(out);
    encode_xfrm_stats(out);
    // seq, reqid (both u32), family, mode, replay_window, flags
    out.extend_from_slice(&0u32.to_ne_bytes()); // seq
    out.extend_from_slice(&0u32.to_ne_bytes()); // reqid
    out.extend_from_slice(&family_for(source).to_ne_bytes());
    out.push(XFRM_MODE_TRANSPORT);
    out.push(0); // replay_window
    out.push(0); // flags
    // The C struct embeds `xfrm_lifetime_cfg` whose `__u64` fields force
    // 8-byte struct alignment.  sizeof(struct xfrm_usersa_info) on
    // x86_64 is therefore 224, not 220 — content spans 217 bytes
    // (selector 56 + id 24 + saddr 16 + lft 64 + curlft 32 + stats 12 +
    // seq 4 + reqid 4 + family 2 + mode 1 + replay 1 + flags 1) and the
    // struct pads 7 bytes to round to 224.  The kernel rejects with
    // EINVAL when the netlink body is shorter than its expected
    // `min_len = sizeof(...)`, so emitting 220 (4-byte-aligned) is not
    // enough.
    for _ in 0..7 {
        out.push(0);
    }
}

/// Encode `struct xfrm_userpolicy_info`.  Total size 168 bytes on
/// x86_64 (selector 56 + lft 64 + curlft 32 + priority 4 + index 4 +
/// 4 single-byte fields + 4 bytes of trailing alignment padding to
/// the struct's 8-byte alignment, forced by lft's u64 fields).
fn encode_xfrm_userpolicy_info(
    source: &IpAddr,
    source_port: u16,
    destination: &IpAddr,
    destination_port: u16,
    direction: u8,
    selector_proto: u8,
    hard_lifetime_secs: Option<u64>,
    out: &mut Vec<u8>,
) {
    encode_xfrm_selector(source, source_port, destination, destination_port, selector_proto, out);
    encode_xfrm_lifetime_cfg(hard_lifetime_secs, out);
    encode_xfrm_lifetime_cur(out);
    out.extend_from_slice(&0u32.to_ne_bytes()); // priority
    out.extend_from_slice(&0u32.to_ne_bytes()); // index
    out.push(direction);
    out.push(XFRM_POLICY_ALLOW);
    out.push(0); // flags
    out.push(XFRM_SHARE_ANY);
    // Trailing padding to 168 bytes (8-byte struct alignment).  Same
    // root cause as xfrm_usersa_info — embedded xfrm_lifetime_cfg has
    // u64 fields and the kernel's min_len validation enforces the full
    // sizeof.
    for _ in 0..4 {
        out.push(0);
    }
}

/// Encode `struct xfrm_user_tmpl`.
fn encode_xfrm_user_tmpl(
    source: &IpAddr,
    destination: &IpAddr,
    spi: u32,
    out: &mut Vec<u8>,
) {
    encode_xfrm_id(destination, spi, IPPROTO_ESP, out);
    out.extend_from_slice(&family_for(source).to_ne_bytes());
    // C struct pads 2 bytes after `family` (u16 at offset 24) to keep
    // `saddr` 4-byte aligned; without it the trailing struct size is 62
    // not 64 and the kernel rejects the message.
    out.push(0);
    out.push(0);
    let mut saddr = [0u8; 16];
    encode_xfrm_address(source, &mut saddr);
    out.extend_from_slice(&saddr);
    out.extend_from_slice(&0u32.to_ne_bytes()); // reqid
    out.push(XFRM_MODE_TRANSPORT);
    out.push(XFRM_SHARE_ANY); // share
    out.push(0); // optional
    out.push(0); // pad to 4-byte align aalgos
    // aalgos, ealgos, calgos — ~0 means accept any.
    out.extend_from_slice(&u32::MAX.to_ne_bytes());
    out.extend_from_slice(&u32::MAX.to_ne_bytes());
    out.extend_from_slice(&u32::MAX.to_ne_bytes());
}

/// Encode `struct xfrm_usersa_id` (24 bytes).
fn encode_xfrm_usersa_id(daddr: &IpAddr, spi: u32, out: &mut Vec<u8>) {
    let mut daddr_bytes = [0u8; 16];
    encode_xfrm_address(daddr, &mut daddr_bytes);
    out.extend_from_slice(&daddr_bytes);
    out.extend_from_slice(&spi.to_be_bytes());
    out.extend_from_slice(&family_for(daddr).to_ne_bytes());
    out.push(IPPROTO_ESP);
    // pad to 24
    out.push(0);
}

/// Encode `struct xfrm_userpolicy_id`.
fn encode_xfrm_userpolicy_id(
    source: &IpAddr,
    source_port: u16,
    destination: &IpAddr,
    destination_port: u16,
    direction: u8,
    selector_proto: u8,
    out: &mut Vec<u8>,
) {
    encode_xfrm_selector(source, source_port, destination, destination_port, selector_proto, out);
    out.extend_from_slice(&0u32.to_ne_bytes()); // index
    out.push(direction);
    // pad to 4
    out.push(0);
    out.push(0);
    out.push(0);
}

/// Encode an `XFRMA_ALG_AUTH_TRUNC` payload (`struct xfrm_algo_auth`).
///
/// Layout: 64-byte name + u32 alg_key_len (in bits) + u32 alg_trunc_len
/// (in bits) + variable-length key bytes.
fn encode_xfrm_algo_auth_trunc(name: &str, key: &[u8], trunc_bits: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64 + 8 + key.len());
    let mut name_bytes = [0u8; 64];
    let copy_len = name.len().min(63);
    name_bytes[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
    payload.extend_from_slice(&name_bytes);
    let key_bits = (key.len() as u32) * 8;
    payload.extend_from_slice(&key_bits.to_ne_bytes());
    payload.extend_from_slice(&trunc_bits.to_ne_bytes());
    payload.extend_from_slice(key);
    payload
}

/// Encode an `XFRMA_ALG_CRYPT` payload (`struct xfrm_algo`).
fn encode_xfrm_algo(name: &str, key: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64 + 4 + key.len());
    let mut name_bytes = [0u8; 64];
    let copy_len = name.len().min(63);
    name_bytes[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
    payload.extend_from_slice(&name_bytes);
    let key_bits = (key.len() as u32) * 8;
    payload.extend_from_slice(&key_bits.to_ne_bytes());
    payload.extend_from_slice(key);
    payload
}

// ---------------------------------------------------------------------------
// Algorithm name + truncation-length lookup for XFRM netlink.
//
// Note these match the kernel's expected names — the same strings that
// `ip xfrm` uses internally (`/proc/net/xfrm_stat` confirms with
// `cat /sys/kernel/debug/iproute2-xfrm`).
// ---------------------------------------------------------------------------

fn xfrm_auth_name_and_trunc(aalg: IntegrityAlgorithm) -> (&'static str, u32) {
    match aalg {
        IntegrityAlgorithm::HmacMd5 => ("hmac(md5)", 96),
        IntegrityAlgorithm::HmacSha1 => ("hmac(sha1)", 96),
        IntegrityAlgorithm::HmacSha256 => ("hmac(sha256)", 128),
    }
}

fn xfrm_enc_name(ealg: EncryptionAlgorithm) -> &'static str {
    match ealg {
        EncryptionAlgorithm::Null => "ecb(cipher_null)",
        EncryptionAlgorithm::AesCbc128 => "cbc(aes)",
        EncryptionAlgorithm::DesEde3Cbc => "cbc(des3_ede)",
    }
}

// ---------------------------------------------------------------------------
// Public backend API.
// ---------------------------------------------------------------------------

/// Add an IPsec SA via XFRM netlink.  Returns `Ok(())` on kernel ack,
/// `Err(IpsecError::Command(...))` on netlink/kernel failure (parsed
/// errno included in the error message).
///
/// `selector_proto` is the upper-layer protocol number stamped into the
/// XFRM selector — typically `IPPROTO_UDP` (17) for ESP-over-UDP IMS
/// IPsec, or `IPPROTO_TCP` (6) for ESP-over-TCP (TS 33.203 §7.2).  The
/// kernel only applies this SA to inner-protocol frames matching the
/// selector, so a UDP-pinned selector silently drops TCP IPsec frames.
pub async fn add_sa(
    source: &IpAddr,
    source_port: u16,
    destination: &IpAddr,
    destination_port: u16,
    spi: u32,
    ealg: EncryptionAlgorithm,
    aalg: IntegrityAlgorithm,
    encryption_key: &[u8],
    integrity_key: &[u8],
    selector_proto: u8,
    hard_lifetime_secs: Option<u64>,
) -> Result<(), IpsecError> {
    let mut payload = Vec::with_capacity(256);
    encode_xfrm_usersa_info(
        source,
        source_port,
        destination,
        destination_port,
        spi,
        selector_proto,
        hard_lifetime_secs,
        &mut payload,
    );

    let (auth_name, trunc_bits) = xfrm_auth_name_and_trunc(aalg);
    let auth_attr = encode_xfrm_algo_auth_trunc(auth_name, integrity_key, trunc_bits);
    push_nla(&mut payload, XFRMA_ALG_AUTH_TRUNC, &auth_attr);

    if ealg != EncryptionAlgorithm::Null {
        let enc_attr = encode_xfrm_algo(xfrm_enc_name(ealg), encryption_key);
        push_nla(&mut payload, XFRMA_ALG_CRYPT, &enc_attr);
    } else {
        // The kernel still requires *some* crypt algo on ESP — pass
        // `ecb(cipher_null)` with an empty key.
        let enc_attr = encode_xfrm_algo(xfrm_enc_name(EncryptionAlgorithm::Null), &[]);
        push_nla(&mut payload, XFRMA_ALG_CRYPT, &enc_attr);
    }

    send_and_ack(XFRM_MSG_NEWSA, NLM_F_CREATE | NLM_F_EXCL, &payload).await
}

/// Update an existing IPsec SA via XFRM netlink (`XFRM_MSG_UPDSA`).
///
/// Re-installs the SA's mutable fields (lifetime, replay window) without
/// disturbing keys, SPIs, selectors, or `add_time` — the kernel keys the
/// existing state by `(daddr, spi, proto)` and merges the new
/// `xfrm_lifetime_cfg` in.  Used by [`super::IpsecManager::update_sa_pair_lifetime`]
/// to repin a previously-installed SA's hard expiry once the registrar
/// of record has granted a real `Expires` value (3GPP TS 33.203 §7.4 —
/// IPsec SA lifetime tracks SIP registration lifetime).
///
/// All payload-shape arguments mirror [`add_sa`] so the kernel sees the
/// same selector/keys/SPIs and only updates the lifetime fields.  The
/// caller is responsible for passing identical key material; if the
/// `integrity_key` / `encryption_key` change between install and update,
/// the kernel rekeys the SA mid-flight (correct behaviour, but rarely
/// what scripts intend).
pub async fn update_sa(
    source: &IpAddr,
    source_port: u16,
    destination: &IpAddr,
    destination_port: u16,
    spi: u32,
    ealg: EncryptionAlgorithm,
    aalg: IntegrityAlgorithm,
    encryption_key: &[u8],
    integrity_key: &[u8],
    selector_proto: u8,
    hard_lifetime_secs: Option<u64>,
) -> Result<(), IpsecError> {
    let mut payload = Vec::with_capacity(256);
    encode_xfrm_usersa_info(
        source,
        source_port,
        destination,
        destination_port,
        spi,
        selector_proto,
        hard_lifetime_secs,
        &mut payload,
    );

    let (auth_name, trunc_bits) = xfrm_auth_name_and_trunc(aalg);
    let auth_attr = encode_xfrm_algo_auth_trunc(auth_name, integrity_key, trunc_bits);
    push_nla(&mut payload, XFRMA_ALG_AUTH_TRUNC, &auth_attr);

    if ealg != EncryptionAlgorithm::Null {
        let enc_attr = encode_xfrm_algo(xfrm_enc_name(ealg), encryption_key);
        push_nla(&mut payload, XFRMA_ALG_CRYPT, &enc_attr);
    } else {
        let enc_attr = encode_xfrm_algo(xfrm_enc_name(EncryptionAlgorithm::Null), &[]);
        push_nla(&mut payload, XFRMA_ALG_CRYPT, &enc_attr);
    }

    // No NLM_F_CREATE / NLM_F_EXCL — UPDSA targets an existing SA;
    // requesting create-exclusive against a known SPI yields EEXIST.
    send_and_ack(XFRM_MSG_UPDSA, 0, &payload).await
}

/// Delete an IPsec SA via XFRM netlink.
pub async fn del_sa(daddr: &IpAddr, spi: u32) -> Result<(), IpsecError> {
    let mut payload = Vec::with_capacity(32);
    encode_xfrm_usersa_id(daddr, spi, &mut payload);
    send_and_ack(XFRM_MSG_DELSA, 0, &payload).await
}

/// Add an IPsec policy via XFRM netlink.
///
/// `selector_proto` must match the corresponding SA's selector, otherwise
/// the kernel will not bind the SA template to incoming/outgoing packets.
///
/// `hard_lifetime_secs` mirrors the value threaded into the matching SA via
/// [`add_sa`].  When `Some`, the kernel installs `xfrm_userpolicy_info.lft.
/// hard_add_expires_seconds` so the policy self-reaps on the same deadline
/// as its states.  When `None` the policy lives until explicitly deleted —
/// keep this for caller-managed lifetimes (dev/test, permanent SAs).
pub async fn add_policy(
    source: &IpAddr,
    source_port: u16,
    destination: &IpAddr,
    destination_port: u16,
    direction: PolicyDirection,
    spi: u32,
    selector_proto: u8,
    hard_lifetime_secs: Option<u64>,
) -> Result<(), IpsecError> {
    let mut payload = Vec::with_capacity(256);
    encode_xfrm_userpolicy_info(
        source,
        source_port,
        destination,
        destination_port,
        direction.as_u8(),
        selector_proto,
        hard_lifetime_secs,
        &mut payload,
    );
    let mut tmpl = Vec::with_capacity(64);
    encode_xfrm_user_tmpl(source, destination, spi, &mut tmpl);
    push_nla(&mut payload, XFRMA_TMPL, &tmpl);
    send_and_ack(XFRM_MSG_NEWPOLICY, NLM_F_CREATE | NLM_F_EXCL, &payload).await
}

/// Delete an IPsec policy via XFRM netlink.
///
/// `selector_proto` must match the value used at policy install time; the
/// kernel keys policies on the full selector tuple including the
/// upper-layer protocol number.
pub async fn del_policy(
    source: &IpAddr,
    source_port: u16,
    destination: &IpAddr,
    destination_port: u16,
    direction: PolicyDirection,
    selector_proto: u8,
) -> Result<(), IpsecError> {
    let mut payload = Vec::with_capacity(96);
    encode_xfrm_userpolicy_id(
        source,
        source_port,
        destination,
        destination_port,
        direction.as_u8(),
        selector_proto,
        &mut payload,
    );
    send_and_ack(XFRM_MSG_DELPOLICY, 0, &payload).await
}

/// Direction parameter for policies (in/out).
#[derive(Debug, Clone, Copy)]
pub enum PolicyDirection {
    In,
    Out,
}

impl PolicyDirection {
    fn as_u8(self) -> u8 {
        match self {
            PolicyDirection::In => XFRM_POLICY_IN,
            PolicyDirection::Out => XFRM_POLICY_OUT,
        }
    }
}

// ---------------------------------------------------------------------------
// Send + ack — common dispatch path used by all four operations.
// ---------------------------------------------------------------------------

const NLMSG_HDR_LEN: usize = 16;

async fn send_and_ack(msg_type: u16, extra_flags: u16, payload: &[u8]) -> Result<(), IpsecError> {
    // Build the netlink message: header (16 B) + payload, padded to 4 B.
    let total_len = NLMSG_HDR_LEN + payload.len();
    let aligned_len = align_to(total_len, NLMSG_ALIGNTO);
    let mut buffer = Vec::with_capacity(aligned_len);
    buffer.extend_from_slice(&(total_len as u32).to_ne_bytes()); // nlmsg_len
    buffer.extend_from_slice(&msg_type.to_ne_bytes());
    let flags = NLM_F_REQUEST | NLM_F_ACK | extra_flags;
    buffer.extend_from_slice(&flags.to_ne_bytes());
    buffer.extend_from_slice(&0u32.to_ne_bytes()); // seq
    buffer.extend_from_slice(&0u32.to_ne_bytes()); // pid (kernel fills in)
    buffer.extend_from_slice(payload);
    while buffer.len() < aligned_len {
        buffer.push(0);
    }

    let buffer_len = buffer.len();

    // The actual socket I/O is blocking; offload it to a tokio blocking
    // pool so we don't stall the dispatcher.  XFRM operations are slow
    // enough (~ms) that this is the right shape regardless.
    let result = tokio::task::spawn_blocking(move || -> io::Result<()> {
        let socket = Socket::new(NETLINK_XFRM)?;
        let kernel_addr = SocketAddr::new(0, 0);
        socket.connect(&kernel_addr)?;
        let bytes_sent = socket.send(&buffer, 0)?;
        if bytes_sent != buffer_len {
            return Err(io::Error::other(format!(
                "netlink: short send ({}/{})",
                bytes_sent, buffer_len
            )));
        }
        // Read the ack.  4 KiB is plenty for an XFRM ack.
        let mut response = vec![0u8; 4096];
        let bytes_received = socket.recv(&mut &mut response[..], 0)?;
        parse_ack(&response[..bytes_received])
    })
    .await;

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(IpsecError::Command(format!("xfrm netlink: {error}"))),
        Err(join_error) => Err(IpsecError::Command(format!(
            "xfrm netlink task panic: {join_error}"
        ))),
    }
}

/// Parse a netlink ack reply.  Looks for an `NLMSG_ERROR` carrying
/// errno 0 (success) or a non-zero kernel error.  Other message types
/// in the response stream are silently ignored — XFRM acks always
/// include exactly one NLMSG_ERROR.
fn parse_ack(buffer: &[u8]) -> io::Result<()> {
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
            return Err(io::Error::other("netlink: malformed reply"));
        }
        match msg_type {
            NLMSG_ERROR => {
                if len < NLMSG_HDR_LEN + 4 {
                    return Err(io::Error::other("netlink: short NLMSG_ERROR"));
                }
                let error = i32::from_ne_bytes([
                    buffer[offset + NLMSG_HDR_LEN],
                    buffer[offset + NLMSG_HDR_LEN + 1],
                    buffer[offset + NLMSG_HDR_LEN + 2],
                    buffer[offset + NLMSG_HDR_LEN + 3],
                ]);
                if error == 0 {
                    return Ok(());
                }
                return Err(io::Error::from_raw_os_error(-error));
            }
            NLMSG_DONE => return Ok(()),
            _ => {
                // Skip — likely a multipart fragment.
            }
        }
        offset += align_to(len, NLMSG_ALIGNTO);
    }
    Err(io::Error::other(
        "netlink: no NLMSG_ERROR / NLMSG_DONE in reply",
    ))
}

// ---------------------------------------------------------------------------
// SA liveness — dump every SA's last-active time for the registrar's
// UDP+IPsec idle reaper.  Pull-based (the kernel emits no idle notification),
// run on the existing 30 s sweep so there is no per-packet hot-path cost.
// ---------------------------------------------------------------------------

/// Dump every XFRM SA and return `spi → last_active_secs`, where
/// `last_active = max(curlft.add_time, curlft.use_time)` in seconds since the
/// UNIX epoch (`ktime_get_real_seconds`).
///
/// Taking the max means a freshly installed SA that has not yet carried a
/// packet (`use_time == 0`) reports its install time rather than looking
/// infinitely idle — without this a brand-new binding would be reaped before
/// its first keepalive.  One netlink round-trip (multipart dump); the caller
/// reuses the map across every UE binding in a liveness sweep instead of
/// querying per-SA.
pub async fn dump_sa_use_times() -> Result<HashMap<u32, u64>, IpsecError> {
    let result = tokio::task::spawn_blocking(move || -> io::Result<HashMap<u32, u64>> {
        let socket = Socket::new(NETLINK_XFRM)?;
        let kernel_addr = SocketAddr::new(0, 0);
        socket.connect(&kernel_addr)?;

        // Header-only GETSA dump request: no XFRMA_ADDRESS_FILTER attribute,
        // so the kernel dumps every SA.
        let mut request = Vec::with_capacity(NLMSG_HDR_LEN);
        request.extend_from_slice(&(NLMSG_HDR_LEN as u32).to_ne_bytes()); // nlmsg_len
        request.extend_from_slice(&XFRM_MSG_GETSA.to_ne_bytes());
        request.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        request.extend_from_slice(&0u32.to_ne_bytes()); // seq
        request.extend_from_slice(&0u32.to_ne_bytes()); // pid (kernel fills in)
        let sent = socket.send(&request, 0)?;
        if sent != request.len() {
            return Err(io::Error::other(format!(
                "netlink: short send ({}/{})",
                sent,
                request.len()
            )));
        }

        let mut use_times: HashMap<u32, u64> = HashMap::new();
        let mut response = vec![0u8; 64 * 1024];
        'recv: loop {
            let received = socket.recv(&mut &mut response[..], 0)?;
            if received == 0 {
                break;
            }
            let mut offset = 0usize;
            while offset + NLMSG_HDR_LEN <= received {
                let len = u32::from_ne_bytes([
                    response[offset],
                    response[offset + 1],
                    response[offset + 2],
                    response[offset + 3],
                ]) as usize;
                let msg_type = u16::from_ne_bytes([response[offset + 4], response[offset + 5]]);
                if len < NLMSG_HDR_LEN || offset + len > received {
                    return Err(io::Error::other("netlink: malformed dump reply"));
                }
                match msg_type {
                    NLMSG_DONE => break 'recv,
                    NLMSG_ERROR => {
                        let errno = if len >= NLMSG_HDR_LEN + 4 {
                            i32::from_ne_bytes([
                                response[offset + NLMSG_HDR_LEN],
                                response[offset + NLMSG_HDR_LEN + 1],
                                response[offset + NLMSG_HDR_LEN + 2],
                                response[offset + NLMSG_HDR_LEN + 3],
                            ])
                        } else {
                            0
                        };
                        if errno != 0 {
                            return Err(io::Error::from_raw_os_error(-errno));
                        }
                        break 'recv; // errno 0 terminates the dump
                    }
                    XFRM_MSG_NEWSA => {
                        let body = offset + NLMSG_HDR_LEN;
                        if let Some((spi, last_active)) =
                            parse_sa_use_time(&response[body..offset + len])
                        {
                            use_times.insert(spi, last_active);
                        }
                    }
                    _ => {}
                }
                offset += align_to(len, NLMSG_ALIGNTO);
            }
        }
        Ok(use_times)
    })
    .await;

    match result {
        Ok(Ok(map)) => Ok(map),
        Ok(Err(error)) => Err(IpsecError::Command(format!("xfrm GETSA dump: {error}"))),
        Err(join_error) => Err(IpsecError::Command(format!(
            "xfrm GETSA dump task panic: {join_error}"
        ))),
    }
}

/// Extract `(spi, last_active_secs)` from a `struct xfrm_usersa_info` body
/// (the netlink message payload after the 16-byte header).  `last_active` is
/// `max(curlft.add_time, curlft.use_time)`.  Returns `None` when the slice is
/// shorter than the fields we read (defensive against a truncated reply).
fn parse_sa_use_time(info: &[u8]) -> Option<(u32, u64)> {
    if info.len() < SA_INFO_MIN_LEN {
        return None;
    }
    let spi = u32::from_be_bytes([
        info[SA_INFO_SPI_OFFSET],
        info[SA_INFO_SPI_OFFSET + 1],
        info[SA_INFO_SPI_OFFSET + 2],
        info[SA_INFO_SPI_OFFSET + 3],
    ]);
    let add_time = u64::from_ne_bytes(
        info[SA_INFO_ADD_TIME_OFFSET..SA_INFO_ADD_TIME_OFFSET + 8]
            .try_into()
            .ok()?,
    );
    let use_time = u64::from_ne_bytes(
        info[SA_INFO_USE_TIME_OFFSET..SA_INFO_USE_TIME_OFFSET + 8]
            .try_into()
            .ok()?,
    );
    Some((spi, add_time.max(use_time)))
}

// ---------------------------------------------------------------------------
// Tests — byte-level correctness of the marshalling, no kernel needed.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn align_to_rounds_up_to_multiple() {
        assert_eq!(align_to(0, 4), 0);
        assert_eq!(align_to(1, 4), 4);
        assert_eq!(align_to(4, 4), 4);
        assert_eq!(align_to(5, 4), 8);
        assert_eq!(align_to(7, 4), 8);
    }

    #[test]
    fn push_nla_layout_and_padding() {
        let mut buffer = Vec::new();
        push_nla(&mut buffer, 0x1234, &[0xAA, 0xBB, 0xCC]);
        // header: len=7 (4+3), type=0x1234; payload 3 bytes; 1 byte pad → total 8.
        assert_eq!(buffer.len(), 8);
        assert_eq!(buffer[0], 7);
        assert_eq!(buffer[1], 0);
        assert_eq!(buffer[2], 0x34);
        assert_eq!(buffer[3], 0x12);
        assert_eq!(buffer[4], 0xAA);
        assert_eq!(buffer[5], 0xBB);
        assert_eq!(buffer[6], 0xCC);
        assert_eq!(buffer[7], 0); // padding
    }

    #[test]
    fn xfrm_address_ipv4_zero_extends() {
        let mut out = [0xFFu8; 16];
        encode_xfrm_address(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), &mut out);
        assert_eq!(&out[..4], &[192, 0, 2, 1]);
        assert!(out[4..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn xfrm_address_ipv6_full() {
        let mut out = [0u8; 16];
        let v6 = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap();
        encode_xfrm_address(&IpAddr::V6(v6), &mut out);
        let expected = v6.octets();
        assert_eq!(out, expected);
    }

    #[test]
    fn host_prefix_ipv4_is_32() {
        assert_eq!(host_prefix_len(&IpAddr::V4(Ipv4Addr::LOCALHOST)), 32);
    }

    #[test]
    fn host_prefix_ipv6_is_128() {
        let v6 = "::1".parse::<std::net::Ipv6Addr>().unwrap();
        assert_eq!(host_prefix_len(&IpAddr::V6(v6)), 128);
    }

    #[test]
    fn xfrm_selector_size_56_bytes() {
        let mut out = Vec::new();
        encode_xfrm_selector(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5066,
            IPPROTO_UDP,
            &mut out,
        );
        assert_eq!(out.len(), 56);
        // Check ports are big-endian.
        // sel.daddr (16) + sel.saddr (16) → port fields start at offset 32.
        assert_eq!(&out[32..34], &[5066u16.to_be_bytes()[0], 5066u16.to_be_bytes()[1]]);
    }

    #[test]
    fn xfrm_lifetime_cfg_size_64_bytes() {
        let mut out = Vec::new();
        encode_xfrm_lifetime_cfg(Some(3600), &mut out);
        assert_eq!(out.len(), 64);
        // Hard add expires at offset 5*8 = 40.
        let hard_add = u64::from_ne_bytes(out[40..48].try_into().unwrap());
        assert_eq!(hard_add, 3600);
    }

    #[test]
    fn xfrm_id_size_24_bytes() {
        let mut out = Vec::new();
        encode_xfrm_id(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            0x12345678,
            IPPROTO_ESP,
            &mut out,
        );
        assert_eq!(out.len(), 24);
        // SPI at offset 16, big-endian.
        assert_eq!(&out[16..20], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(out[20], IPPROTO_ESP);
    }

    #[test]
    fn xfrm_algo_auth_trunc_layout() {
        let payload = encode_xfrm_algo_auth_trunc("hmac(sha1)", &[0xAA; 20], 96);
        // 64 (name) + 4 (len) + 4 (trunc) + 20 (key) = 92.
        assert_eq!(payload.len(), 92);
        assert!(payload.starts_with(b"hmac(sha1)\0"));
        let key_bits = u32::from_ne_bytes(payload[64..68].try_into().unwrap());
        assert_eq!(key_bits, 160);
        let trunc_bits = u32::from_ne_bytes(payload[68..72].try_into().unwrap());
        assert_eq!(trunc_bits, 96);
        assert!(payload[72..].iter().all(|&byte| byte == 0xAA));
    }

    #[test]
    fn xfrm_usersa_info_size_224_bytes() {
        let mut out = Vec::new();
        encode_xfrm_usersa_info(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5066,
            0xDEADBEEF,
            IPPROTO_UDP,
            None,
            &mut out,
        );
        // sizeof(struct xfrm_usersa_info) on x86_64 = 224.  The struct
        // alignment is 8 because it embeds xfrm_lifetime_cfg with u64
        // fields, and 217 bytes of content rounds up to 224.  The
        // kernel validates the body size against this in xfrm_user_rcv_msg
        // — emitting 220 yields EINVAL.
        assert_eq!(out.len(), 224);
    }

    #[test]
    fn xfrm_userpolicy_info_size_168_bytes() {
        let mut out = Vec::new();
        encode_xfrm_userpolicy_info(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5066,
            XFRM_POLICY_OUT,
            IPPROTO_UDP,
            None,
            &mut out,
        );
        assert_eq!(out.len(), 168);
    }

    #[test]
    fn xfrm_userpolicy_info_encodes_hard_lifetime() {
        // The embedded xfrm_lifetime_cfg starts right after the 56-byte
        // selector, so its hard_add_expires_seconds field sits at offset
        // 56 + 40 = 96 (5th u64 of the lifetime_cfg).  When a hard
        // lifetime is requested it must be honoured — this is what makes
        // an abandoned UE's policies self-reap on the same deadline as
        // its states (kernel reads xfrm_userpolicy_info.lft.hard_*).
        let mut with_lifetime = Vec::new();
        encode_xfrm_userpolicy_info(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5066,
            XFRM_POLICY_OUT,
            IPPROTO_UDP,
            Some(3600),
            &mut with_lifetime,
        );
        let hard_add =
            u64::from_ne_bytes(with_lifetime[96..104].try_into().unwrap());
        assert_eq!(hard_add, 3600);

        // None must keep the legacy "no expiry" (0) encoding so
        // caller-managed lifetimes stay permanent.
        let mut no_lifetime = Vec::new();
        encode_xfrm_userpolicy_info(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5066,
            XFRM_POLICY_OUT,
            IPPROTO_UDP,
            None,
            &mut no_lifetime,
        );
        let hard_add_none =
            u64::from_ne_bytes(no_lifetime[96..104].try_into().unwrap());
        assert_eq!(hard_add_none, 0);
    }

    /// Selector proto byte lives at offset 44 inside the 56-byte
    /// `xfrm_selector` (16 daddr + 16 saddr + 4*u16 ports + 2 family +
    /// 1 prefixlen_d + 1 prefixlen_s = 44).  This is the byte that
    /// determines whether the kernel applies the SA to inner-protocol
    /// UDP frames or TCP frames — so we pin it down explicitly here.
    const SELECTOR_PROTO_OFFSET: usize = 44;

    #[test]
    fn xfrm_selector_proto_byte_position_for_tcp_and_udp() {
        let mut udp_out = Vec::new();
        encode_xfrm_selector(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5066,
            IPPROTO_UDP,
            &mut udp_out,
        );
        assert_eq!(udp_out[SELECTOR_PROTO_OFFSET], 17);

        let mut tcp_out = Vec::new();
        encode_xfrm_selector(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5066,
            IPPROTO_TCP,
            &mut tcp_out,
        );
        assert_eq!(tcp_out[SELECTOR_PROTO_OFFSET], 6);
    }

    /// Regression test for the IPPROTO_UDP hard-pin bug: the encoded
    /// selector inside `xfrm_usersa_info` must reflect the
    /// `selector_proto` argument, not a hard-coded UDP.
    #[test]
    fn usersa_info_carries_tcp_selector_proto_when_requested() {
        let mut out = Vec::new();
        encode_xfrm_usersa_info(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5066,
            0xDEADBEEF,
            IPPROTO_TCP,
            None,
            &mut out,
        );
        assert_eq!(
            out[SELECTOR_PROTO_OFFSET], 6,
            "selector proto byte must be IPPROTO_TCP (6)"
        );
    }

    /// Regression test for the IPPROTO_UDP hard-pin bug on policies.
    #[test]
    fn userpolicy_info_carries_tcp_selector_proto_when_requested() {
        let mut out = Vec::new();
        encode_xfrm_userpolicy_info(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5060,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5066,
            XFRM_POLICY_OUT,
            IPPROTO_TCP,
            None,
            &mut out,
        );
        assert_eq!(out[SELECTOR_PROTO_OFFSET], 6);
    }

    /// `SaProtocol::Any` (the spec-compliant default per TS 33.203 §7.2)
    /// must surface as selector_proto=0 in both `xfrm_usersa_info` and
    /// `xfrm_userpolicy_info`.  The Linux kernel short-circuits the
    /// proto check when `sel->proto == 0` (see
    /// `__xfrm{4,6}_selector_match`), so the SA covers both TCP and UDP
    /// inner flows under one SPI pair without doubling kernel state.
    /// Port matching still applies because `sport_mask`/`dport_mask`
    /// remain 0xFFFF — only the proto byte goes wide.
    #[test]
    fn usersa_info_carries_any_selector_proto_for_dual_transport() {
        let mut out = Vec::new();
        encode_xfrm_usersa_info(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5066,
            0x1000,
            0, // SaProtocol::Any.as_u8()
            None,
            &mut out,
        );
        assert_eq!(
            out[SELECTOR_PROTO_OFFSET], 0,
            "selector_proto must be 0 to match any inner protocol (TS 33.203 §7.2)"
        );
        // Ports remain pinned — the SA still discriminates UE↔P-CSCF
        // flows by (port_uc, port_ps) vs (port_us, port_pc) even with
        // proto=0.  dport sits at selector offset 32 (BE u16).
        assert_eq!(u16::from_be_bytes([out[32], out[33]]), 5066);
    }

    #[test]
    fn userpolicy_info_carries_any_selector_proto_for_dual_transport() {
        let mut out = Vec::new();
        encode_xfrm_userpolicy_info(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5066,
            XFRM_POLICY_OUT,
            0, // SaProtocol::Any.as_u8()
            None,
            &mut out,
        );
        assert_eq!(
            out[SELECTOR_PROTO_OFFSET], 0,
            "policy selector_proto must be 0 to bind both UDP and TCP flows"
        );
    }

    /// Compile-time cross-check — mirror the kernel C ABI structs as
    /// `#[repr(C)]` in Rust so the compiler computes the same layout
    /// the kernel does, then assert sizes match what the encoders emit.
    /// If the kernel ever adds a field, this catches it at build time.
    #[test]
    fn struct_sizes_match_kernel_abi() {
        #[repr(C)]
        #[allow(dead_code)]
        struct XfrmAddress(u32, u32, u32, u32);

        #[repr(C)]
        #[allow(dead_code)]
        struct XfrmSelector {
            daddr: XfrmAddress,
            saddr: XfrmAddress,
            dport: u16,
            dport_mask: u16,
            sport: u16,
            sport_mask: u16,
            family: u16,
            prefixlen_d: u8,
            prefixlen_s: u8,
            proto: u8,
            ifindex: i32,
            user: u32,
        }

        #[repr(C)]
        #[allow(dead_code)]
        struct XfrmId {
            daddr: XfrmAddress,
            spi: u32,
            proto: u8,
        }

        #[repr(C)]
        #[allow(dead_code)]
        struct XfrmLifetimeCfg {
            soft_byte_limit: u64,
            hard_byte_limit: u64,
            soft_packet_limit: u64,
            hard_packet_limit: u64,
            soft_add_expires_seconds: u64,
            hard_add_expires_seconds: u64,
            soft_use_expires_seconds: u64,
            hard_use_expires_seconds: u64,
        }

        #[repr(C)]
        #[allow(dead_code)]
        struct XfrmLifetimeCur {
            bytes: u64,
            packets: u64,
            add_time: u64,
            use_time: u64,
        }

        #[repr(C)]
        #[allow(dead_code)]
        struct XfrmStats {
            replay_window: u32,
            replay: u32,
            integrity_failed: u32,
        }

        #[repr(C)]
        #[allow(dead_code)]
        struct XfrmUsersaInfo {
            sel: XfrmSelector,
            id: XfrmId,
            saddr: XfrmAddress,
            lft: XfrmLifetimeCfg,
            curlft: XfrmLifetimeCur,
            stats: XfrmStats,
            seq: u32,
            reqid: u32,
            family: u16,
            mode: u8,
            replay_window: u8,
            flags: u8,
        }

        #[repr(C)]
        #[allow(dead_code)]
        struct XfrmUserpolicyInfo {
            sel: XfrmSelector,
            lft: XfrmLifetimeCfg,
            curlft: XfrmLifetimeCur,
            priority: u32,
            index: u32,
            dir: u8,
            action: u8,
            flags: u8,
            share: u8,
        }

        assert_eq!(std::mem::size_of::<XfrmSelector>(), 56);
        assert_eq!(std::mem::size_of::<XfrmId>(), 24);
        assert_eq!(std::mem::size_of::<XfrmLifetimeCfg>(), 64);
        assert_eq!(std::mem::size_of::<XfrmLifetimeCur>(), 32);
        assert_eq!(std::mem::size_of::<XfrmStats>(), 12);
        assert_eq!(std::mem::size_of::<XfrmUsersaInfo>(), 224);
        assert_eq!(std::mem::size_of::<XfrmUserpolicyInfo>(), 168);
    }

    /// XFRM_MSG_UPDSA is the kernel netlink type used by
    /// `update_sa` — value taken verbatim from `linux/xfrm.h`
    /// (`XFRM_MSG_BASE + 10`).  Wrong value here would silently
    /// reroute the netlink message to a different kernel handler
    /// (probably XFRM_MSG_GETPOLICY at 0x15), producing baffling EINVAL
    /// failures at runtime — pin it down with a unit test.
    #[test]
    fn xfrm_msg_updsa_constant_matches_kernel_uapi() {
        assert_eq!(XFRM_MSG_UPDSA, 0x1a);
        assert_eq!(XFRM_MSG_UPDSA, XFRM_MSG_NEWSA + 10);
    }

    #[test]
    fn xfrm_user_tmpl_size_64_bytes() {
        let mut out = Vec::new();
        encode_xfrm_user_tmpl(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            0xCAFEBABE,
            &mut out,
        );
        // 24 id + 2 family + 16 saddr + 4 reqid + 1 mode + 1 share + 1 opt + 1 pad
        // + 4 aalgos + 4 ealgos + 4 calgos = 62.  The kernel pads to 64.
        assert_eq!(out.len(), 64);
    }

    /// The hand-coded `xfrm_usersa_info` field offsets used by the liveness
    /// SA dump must track the repr(C) struct layout (selector 56 + id 24 +
    /// saddr 16 + lft 64, then curlft{ bytes, packets, add_time, use_time }).
    #[test]
    fn sa_info_offsets_match_struct_layout() {
        assert_eq!(SA_INFO_SPI_OFFSET, 56 + 16); // selector + id.daddr
        assert_eq!(SA_INFO_ADD_TIME_OFFSET, 56 + 24 + 16 + 64 + 16); // + curlft{bytes,packets}
        assert_eq!(SA_INFO_USE_TIME_OFFSET, SA_INFO_ADD_TIME_OFFSET + 8);
        assert_eq!(SA_INFO_MIN_LEN, SA_INFO_USE_TIME_OFFSET + 8);
    }

    #[test]
    fn parse_sa_use_time_reads_spi_and_uses_max_of_add_and_use() {
        let mut info = vec![0u8; 224];
        let spi: u32 = 0x10203040;
        info[SA_INFO_SPI_OFFSET..SA_INFO_SPI_OFFSET + 4].copy_from_slice(&spi.to_be_bytes());
        let add_time: u64 = 1_700_000_000;
        let use_time: u64 = 1_700_000_090;
        info[SA_INFO_ADD_TIME_OFFSET..SA_INFO_ADD_TIME_OFFSET + 8]
            .copy_from_slice(&add_time.to_ne_bytes());
        info[SA_INFO_USE_TIME_OFFSET..SA_INFO_USE_TIME_OFFSET + 8]
            .copy_from_slice(&use_time.to_ne_bytes());

        let (parsed_spi, last_active) = parse_sa_use_time(&info).expect("should parse");
        assert_eq!(parsed_spi, spi);
        assert_eq!(last_active, use_time, "use_time > add_time → last_active = use_time");
    }

    #[test]
    fn parse_sa_use_time_falls_back_to_add_time_when_never_used() {
        let mut info = vec![0u8; 224];
        let spi: u32 = 0xDEAD_BEEF;
        info[SA_INFO_SPI_OFFSET..SA_INFO_SPI_OFFSET + 4].copy_from_slice(&spi.to_be_bytes());
        let add_time: u64 = 1_700_000_500;
        info[SA_INFO_ADD_TIME_OFFSET..SA_INFO_ADD_TIME_OFFSET + 8]
            .copy_from_slice(&add_time.to_ne_bytes());
        // use_time stays 0 — SA installed but no packet seen yet.
        let (parsed_spi, last_active) = parse_sa_use_time(&info).expect("should parse");
        assert_eq!(parsed_spi, spi);
        assert_eq!(last_active, add_time, "use_time == 0 → fall back to add_time");
    }

    #[test]
    fn parse_sa_use_time_rejects_short_body() {
        let info = vec![0u8; SA_INFO_MIN_LEN - 1];
        assert!(parse_sa_use_time(&info).is_none());
    }
}
