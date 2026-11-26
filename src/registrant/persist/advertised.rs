//! The advertised addresses each node publishes beside its bindings.
//!
//! A Contact on an advertised IP is this node's only when no other node
//! advertises the same IP (see `startup::contact_is_held_here`). Records alone
//! cannot say so: a node's record is written after its REGISTER is answered,
//! and a node that registered a moment ago may have none yet. Each node
//! therefore publishes the IP literals it advertises, once, before it sends any
//! REGISTER, and keeps the entry alive with a TTL; the clean-up reads them all.

// Without Redis (and outside tests) no store can be written or read: nothing here runs.
#![cfg_attr(not(any(feature = "redis-backend", test)), allow(unused))]

use std::collections::HashSet;

use super::{Backend, BindingStore};

/// How long a published entry lives without being refreshed.
pub(in crate::registrant) const ADVERTISED_TTL_SECS: u64 = 300;

/// What the store holds of the nodes' advertised addresses.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AdvertisedView {
    /// What this node published; `None` when its entry is missing or expired.
    pub own: Option<HashSet<String>>,
    /// Everything every other node publishes.
    pub others: HashSet<String>,
}

fn encode(literals: &[String]) -> String {
    literals.join(",")
}

fn decode(value: &str) -> HashSet<String> {
    value
        .split(',')
        .filter(|literal| !literal.is_empty())
        .map(str::to_string)
        .collect()
}

impl BindingStore {
    fn advertised_key(&self, instance: &str) -> String {
        format!("{}~advertised~{instance}", self.shared.key_prefix)
    }

    /// Publish the IP literals this node advertises, for
    /// [`ADVERTISED_TTL_SECS`]. Called before the first REGISTER and again
    /// before the entry would expire.
    pub async fn publish_advertised(&self, literals: &[String]) -> Result<(), String> {
        let key = self.advertised_key(&self.shared.instance_id);
        match &self.shared.backend {
            #[cfg(feature = "redis-backend")]
            Backend::Redis(connection) => redis::cmd("SET")
                .arg(&key)
                .arg(encode(literals))
                .arg("EX")
                .arg(ADVERTISED_TTL_SECS)
                .query_async::<()>(&mut connection.clone())
                .await
                .map_err(|error| format!("SET failed: {error}")),
            #[cfg(test)]
            Backend::Memory(_) => {
                if let Ok(mut adverts) = self.shared.adverts.lock() {
                    adverts.insert(key, encode(literals));
                }
                Ok(())
            }
            Backend::Inert => Err("the store cannot be written".to_string()),
        }
    }

    /// Every node's published addresses. An unreadable store is an error: it
    /// never reads as "nobody else advertises this".
    pub async fn advertised_view(&self) -> Result<AdvertisedView, String> {
        let own_key = self.advertised_key(&self.shared.instance_id);
        let mut view = AdvertisedView::default();
        let entries: Vec<(String, String)> = match &self.shared.backend {
            #[cfg(feature = "redis-backend")]
            Backend::Redis(connection) => {
                let mut connection = connection.clone();
                let pattern = format!(
                    "{}~advertised~*",
                    super::glob_escape(&self.shared.key_prefix)
                );
                let mut keys = std::collections::BTreeSet::new();
                let mut cursor: u64 = 0;
                loop {
                    let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH")
                        .arg(&pattern)
                        .arg("COUNT")
                        .arg(1000)
                        .query_async(&mut connection)
                        .await
                        .map_err(|error| format!("SCAN failed: {error}"))?;
                    keys.extend(batch);
                    cursor = next;
                    if cursor == 0 {
                        break;
                    }
                }
                let mut found = Vec::new();
                for key in keys {
                    let value: Option<String> = redis::cmd("GET")
                        .arg(&key)
                        .query_async(&mut connection)
                        .await
                        .map_err(|error| format!("GET failed: {error}"))?;
                    // Gone between the SCAN and now: its TTL ran out.
                    if let Some(value) = value {
                        found.push((key, value));
                    }
                }
                found
            }
            #[cfg(test)]
            Backend::Memory(_) => match self.shared.adverts.lock() {
                Ok(adverts) => adverts
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
                Err(poisoned) => poisoned
                    .into_inner()
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            },
            Backend::Inert => return Err("the store cannot be read".to_string()),
        };
        for (key, value) in entries {
            if key == own_key {
                view.own = Some(decode(&value));
            } else {
                view.others.extend(decode(&value));
            }
        }
        Ok(view)
    }

    /// Hold the addresses another instance published.
    #[cfg(test)]
    pub(crate) fn save_advertised_as_instance(&self, instance: &str, literals: &[&str]) {
        let literals: Vec<String> = literals
            .iter()
            .map(|literal| (*literal).to_string())
            .collect();
        if let Ok(mut adverts) = self.shared.adverts.lock() {
            adverts.insert(self.advertised_key(instance), encode(&literals));
        }
    }
}
