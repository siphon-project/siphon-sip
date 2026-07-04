//! Kernel firewall integration — drop banned source IPs in the kernel.
//!
//! Siphon already decides *who* to ban (the confidence-weighted
//! [`crate::security::AutoBanStore`] + the [`crate::apiban`] blocklist) but only
//! enforces it in userspace via the transport ACL, so every abusive packet
//! still travels NIC → kernel → siphon before being dropped. This module
//! mirrors those bans into a kernel nf_tables set with per-element timeouts, so
//! the kernel drops the traffic before it reaches siphon's socket — real
//! defense against volume, self-contained (no `nft` shell-out, no daemon), and
//! the kernel auto-expires bans so there is no unban bookkeeping.
//!
//! Linux-only (nf_tables + netlink). The whole feature is opt-in via
//! `security.firewall` and requires `CAP_NET_ADMIN`; when unavailable siphon
//! logs a warning and the userspace ACL keeps working.
//!
//! A single actor task owns the netlink work; the [`KernelFirewall`] handle
//! feeds it bans with a non-blocking `try_send`, so the ban / auth hot paths
//! never block on a syscall.

use std::net::IpAddr;
use std::time::Duration;

use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
pub mod nftables;

/// A command for the firewall actor.
#[derive(Debug)]
enum Command {
    /// Add `ip` to the kernel ban set. `ttl_ms == 0` means permanent.
    Ban { ip: IpAddr, ttl_ms: u64 },
    /// Remove `ip` (optional — timed elements self-expire in the kernel).
    Unban { ip: IpAddr },
}

/// Handle to the kernel-firewall actor. Cheap to clone; feeding a ban is a
/// non-blocking `try_send` that drops silently if the actor's queue is full
/// (the userspace ACL still enforces the ban, so a dropped kernel update only
/// costs a little extra CPU until the next ban lands).
#[derive(Clone)]
pub struct KernelFirewall {
    sender: mpsc::Sender<Command>,
}

impl KernelFirewall {
    /// Drop `ip` in the kernel for `ttl` (mirrors an auto-ban's TTL so the
    /// kernel expires it in lockstep with the userspace store).
    pub fn ban(&self, ip: IpAddr, ttl: Duration) {
        let ttl_ms = ttl.as_millis().min(u64::MAX as u128) as u64;
        let _ = self.sender.try_send(Command::Ban { ip, ttl_ms });
    }

    /// Drop `ip` permanently — for an apiban blocklist entry, which carries no
    /// per-IP lifetime.
    pub fn ban_permanent(&self, ip: IpAddr) {
        let _ = self.sender.try_send(Command::Ban { ip, ttl_ms: 0 });
    }

    /// Lift a ban early (optional; timed elements self-expire).
    pub fn unban(&self, ip: IpAddr) {
        let _ = self.sender.try_send(Command::Unban { ip });
    }
}

/// Build the kernel firewall: ensure the nf_tables sets exist, then spawn the
/// actor that applies bans over netlink. Returns an error (so the caller can
/// warn + fall back to the userspace ACL) when the sets can't be programmed —
/// typically a missing `CAP_NET_ADMIN`.
#[cfg(target_os = "linux")]
pub async fn start(config: &crate::config::FirewallConfig) -> std::io::Result<KernelFirewall> {
    nftables::ensure_firewall(
        &config.table,
        &config.chain,
        &config.set_v4,
        &config.set_v6,
        config.manage_rule,
    )
    .await?;

    let (sender, mut receiver) = mpsc::channel::<Command>(1024);
    let table = config.table.clone();
    let set_v4 = config.set_v4.clone();
    let set_v6 = config.set_v6.clone();

    tokio::spawn(async move {
        while let Some(command) = receiver.recv().await {
            let result = match command {
                Command::Ban { ip, ttl_ms } => {
                    nftables::add_banned(&table, &set_v4, &set_v6, ip, ttl_ms).await
                }
                Command::Unban { ip } => {
                    nftables::remove_banned(&table, &set_v4, &set_v6, ip).await
                }
            };
            if let Err(error) = result {
                tracing::warn!(%error, "nftables: failed to apply firewall command");
            }
        }
    });

    tracing::info!(
        table = %config.table,
        "kernel firewall active (nf_tables) — banned sources dropped in-kernel"
    );
    Ok(KernelFirewall { sender })
}

#[cfg(not(target_os = "linux"))]
pub async fn start(_config: &crate::config::FirewallConfig) -> std::io::Result<KernelFirewall> {
    Err(std::io::Error::other(
        "firewall: the nf_tables backend is Linux-only",
    ))
}
