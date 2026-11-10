//! DNS membership and name expansion for equivalent Diameter instances.
use super::DiameterManager;
use std::sync::atomic::AtomicUsize;

pub(super) struct Group {
    pub members: Vec<String>,
    pub cursor: AtomicUsize,
}

impl DiameterManager {
    /// Replace a group's membership, retaining its independent selection cursor.
    pub fn set_group(&self, tenant: Option<&str>, name: &str, members: Vec<String>) {
        let key = (tenant.map(str::to_owned), name.to_owned());
        self.groups
            .entry(key)
            .and_modify(|group| group.members.clone_from(&members))
            .or_insert(Group {
                members,
                cursor: AtomicUsize::new(0),
            });
    }
}

pub(crate) fn spawn_client(
    entry: &crate::config::DiameterPeerEntry,
    config: super::peer::PeerConfig,
    interval: u64,
    manager: Arc<DiameterManager>,
    tx: super::client_connection::Incoming,
) {
    if !entry.all_addresses {
        super::client_connection::spawn(entry.name.clone(), config, manager, tx);
        return;
    }
    spawn_group(
        manager.clone(),
        None,
        entry.name.clone(),
        entry.host.clone(),
        entry.port,
        interval,
        move |name, address| {
            let mut member = config.clone();
            member.host = connection_host(address);
            member.port = address.port();
            super::client_connection::spawn(name, member, manager.clone(), tx.clone())
        },
    );
}

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

pub type Resolution<'a> =
    Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>>;

/// Resolution is injectable so membership changes can be tested without DNS.
pub trait Resolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> Resolution<'a>;
}

pub struct SystemResolver;
impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> Resolution<'a> {
        Box::pin(async move {
            tokio::net::lookup_host((host, port))
                .await
                .map(Iterator::collect)
        })
    }
}

/// Owns member tasks. Cancellation aborts loops and closes registered connections.
pub struct Supervisor {
    manager: Arc<DiameterManager>,
    tenant: Option<String>,
    name: String,
    members: HashMap<SocketAddr, (String, JoinHandle<()>)>,
}

impl Supervisor {
    pub fn new(manager: Arc<DiameterManager>, tenant: Option<String>, name: String) -> Self {
        manager.set_group(tenant.as_deref(), &name, vec![]);
        Self {
            manager,
            tenant,
            name,
            members: HashMap::new(),
        }
    }

    pub async fn refresh<R, F>(&mut self, resolver: &R, host: &str, port: u16, spawn: &F)
    where
        R: Resolver + ?Sized,
        F: Fn(String, SocketAddr) -> JoinHandle<()>,
    {
        let addresses: BTreeSet<_> = match resolver.resolve(host, port).await {
            Ok(addresses) => addresses.into_iter().collect(),
            Err(error) => {
                tracing::warn!(peer = %self.name, %error, "Diameter group resolution failed; keeping members");
                return;
            }
        };
        let removed: Vec<_> = self
            .members
            .keys()
            .filter(|addr| !addresses.contains(addr))
            .copied()
            .collect();
        for address in removed {
            if let Some((name, task)) = self.members.remove(&address) {
                task.abort();
                // Wait until the loop cannot register another connection.
                let _ = task.await;
                // The member left the group: say so (RFC 6733 section 5.4)
                // before the connection closes, so the far end does not take
                // it for a failure.
                if let Some(client) = self.remove(&name) {
                    let wait = client.peer().config().lifecycle.disconnect_timeout();
                    client
                        .peer()
                        .disconnect(
                            super::lifecycle::DisconnectCause::DoNotWantToTalkToYou,
                            wait,
                        )
                        .await;
                }
            }
        }
        for address in &addresses {
            if let std::collections::hash_map::Entry::Vacant(entry) = self.members.entry(*address) {
                // The configured port is implicit; injected alternative ports remain distinct.
                let suffix = if address.port() == port {
                    address.ip().to_string()
                } else {
                    address.to_string()
                };
                let name = format!("{}@{suffix}", self.name);
                let task = spawn(name.clone(), *address);
                entry.insert((name, task));
            }
        }
        let members = addresses
            .iter()
            .filter_map(|addr| self.members.get(addr).map(|(name, _)| name.clone()))
            .collect();
        self.manager
            .set_group(self.tenant.as_deref(), &self.name, members);
    }

    fn remove(&self, name: &str) -> Option<Arc<super::DiameterClient>> {
        let client = match &self.tenant {
            Some(tenant) => self
                .manager
                .backends
                .remove(&(tenant.clone(), name.to_owned()))
                .map(|(_, client)| client),
            None => self.manager.deregister(name),
        };
        // Only group members are removed here; a static peer is never
        // deregistered, so it keeps reading 0 rather than losing its series.
        crate::metrics::remove_diameter_peer_up(name);
        client
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        for (name, task) in self.members.values() {
            task.abort();
            let Some(client) = self.remove(name) else {
                continue;
            };
            // Drop cannot wait: tell the peer from a task when there is a
            // runtime to run it on, else just close.
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => {
                    runtime.spawn(async move {
                        let wait = client.peer().config().lifecycle.disconnect_timeout();
                        client
                            .peer()
                            .disconnect(super::lifecycle::DisconnectCause::Rebooting, wait)
                            .await;
                    });
                }
                Err(_) => client.shutdown(),
            }
        }
        self.manager
            .set_group(self.tenant.as_deref(), &self.name, vec![]);
    }
}

pub fn spawn_group<F>(
    manager: Arc<DiameterManager>,
    tenant: Option<String>,
    name: String,
    host: String,
    port: u16,
    interval: u64,
    spawn: F,
) -> JoinHandle<()>
where
    F: Fn(String, SocketAddr) -> JoinHandle<()> + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut supervisor = Supervisor::new(manager, tenant, name);
        loop {
            supervisor
                .refresh(&SystemResolver, &host, port, &spawn)
                .await;
            tokio::time::sleep(Duration::from_secs(interval.max(1))).await;
        }
    })
}

impl DiameterManager {
    /// All open members, or the single fixed peer. Does not advance a cursor.
    pub fn open_members(
        &self,
        tenant: Option<&str>,
        name: &str,
    ) -> Vec<(String, Arc<super::DiameterClient>)> {
        let names = self
            .groups
            .get(&(tenant.map(str::to_owned), name.to_owned()))
            .map(|group| group.members.clone())
            .unwrap_or_else(|| vec![name.to_owned()]);
        names
            .into_iter()
            .filter_map(|name| {
                let client = match tenant {
                    Some(tenant) => self
                        .backends
                        .get(&(tenant.to_owned(), name.clone()))
                        .map(|entry| entry.value().clone()),
                    None => self.clients.get(&name).map(|entry| entry.value().clone()),
                }?;
                client.peer().is_open().then_some((name, client))
            })
            .collect()
    }

    pub fn live_named(
        &self,
        tenant: Option<&str>,
        name: &str,
    ) -> Option<(String, Arc<super::DiameterClient>)> {
        let members = self.open_members(tenant, name);
        if members.is_empty() {
            return None;
        }
        let cursor = self
            .groups
            .get(&(tenant.map(str::to_owned), name.to_owned()))
            .map(|group| {
                group
                    .cursor
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            })
            .unwrap_or(0);
        let index = cursor % members.len();
        members.into_iter().nth(index)
    }
}

/// Peer connections append a port to the host, so IPv6 literals need brackets.
pub(crate) fn connection_host(address: SocketAddr) -> String {
    match address.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    }
}
