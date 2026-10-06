//! Per-group inbound call limits (`gateway.groups[].inbound_limit`).
//!
//! A group's limit is a ceiling on the calls arriving *from* the sources the
//! group admits: its destinations' resolved addresses and its
//! `source_networks`, the same membership `call.from_gateway()` answers from.
//!
//! Two things here exist because of how groups live:
//!
//! - **The counters outlive the group object.** Every refresh of a group builds
//!   a new `DispatcherGroup`, so a count kept on the group would restart at
//!   zero with calls still up. The counters are kept here by group name and
//!   handed to each incarnation, with a changed limit applied in place.
//! - **The admission check reads a snapshot.** It runs for every inbound
//!   INVITE, so it loads a prebuilt list of only the groups that have a limit,
//!   rebuilt when a group is added or removed. With no limited group the check
//!   is one atomic load.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use dashmap::DashMap;

use super::DispatcherGroup;
use crate::admission::{GroupLimit, InboundLimits, LimitState};

impl DispatcherGroup {
    /// The group's inbound limit and the calls up against it, as
    /// `GET /admin/gateways` reports them. `null` for a group with no limit,
    /// so "not limited" and "limited, nothing up" read differently.
    pub fn inbound_limit_json(&self) -> serde_json::Value {
        match self.inbound_limits {
            None => serde_json::Value::Null,
            Some(limits) => serde_json::json!({
                "max_concurrent_calls": limits.max_concurrent_calls,
                "max_calls_per_second": limits.max_calls_per_second,
                "reject_code": limits.reject_code,
                "retry_after_secs": limits.retry_after_secs,
                "calls_active": self.inbound_calls_active().unwrap_or(0),
            }),
        }
    }
}

/// One limited group in the snapshot the admission check reads.
struct Limited {
    group: Arc<DispatcherGroup>,
    limit: GroupLimit,
}

/// A limited group's limits and the calls it has up, for the metrics and the
/// admin API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundUsage {
    pub group: Arc<str>,
    pub active: u32,
    pub limits: InboundLimits,
}

pub(super) struct InboundLimitRegistry {
    /// Counters by group name, for as long as a group of that name has a limit.
    states: DashMap<String, Arc<LimitState>>,
    limited: ArcSwap<Vec<Limited>>,
    /// Serialises rebuilds, so two groups added at once cannot leave the
    /// snapshot of the one that read the group map first.
    rebuild: Mutex<()>,
}

impl InboundLimitRegistry {
    pub(super) fn new() -> Self {
        Self {
            states: DashMap::new(),
            limited: ArcSwap::from_pointee(Vec::new()),
            rebuild: Mutex::new(()),
        }
    }

    /// The counters a group named `name` with `limits` is to use: the ones
    /// already held under that name, with the limits updated, or new ones.
    /// `None`, and nothing held, for a group with no limit.
    pub(super) fn bind(
        &self,
        name: &str,
        limits: Option<InboundLimits>,
    ) -> Option<Arc<LimitState>> {
        let Some(limits) = limits.filter(InboundLimits::is_limited) else {
            self.states.remove(name);
            return None;
        };
        let state = Arc::clone(
            self.states
                .entry(name.to_string())
                .or_insert_with(|| Arc::new(LimitState::new(limits)))
                .value(),
        );
        state.set_limits(limits);
        Some(state)
    }

    /// Stop holding counters for `name`. Calls still up keep their own handle
    /// on them and release into it harmlessly.
    pub(super) fn forget(&self, name: &str) {
        self.states.remove(name);
    }

    /// Rebuild the snapshot from the live groups.
    pub(super) fn rebuild(&self, groups: &DashMap<String, Arc<DispatcherGroup>>) {
        let _serialised = self
            .rebuild
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut limited: Vec<Limited> = groups
            .iter()
            .filter_map(|entry| {
                let group = entry.value();
                let state = group.inbound_state.as_ref()?;
                Some(Limited {
                    group: Arc::clone(group),
                    limit: GroupLimit {
                        name: Arc::from(group.name.as_str()),
                        state: Arc::clone(state),
                    },
                })
            })
            .collect();
        // A stable order, so a source in two groups is always refused in the
        // name of the same one.
        limited.sort_by(|left, right| left.limit.name.cmp(&right.limit.name));
        self.limited.store(Arc::new(limited));
    }

    /// The limits of every limited group that admits `source`.
    pub(super) fn admitting(&self, source: IpAddr) -> Vec<GroupLimit> {
        let limited = self.limited.load();
        if limited.is_empty() {
            return Vec::new();
        }
        limited
            .iter()
            .filter(|entry| entry.group.contains_source(source))
            .map(|entry| entry.limit.clone())
            .collect()
    }

    pub(super) fn usage(&self) -> Vec<InboundUsage> {
        self.limited
            .load()
            .iter()
            .map(|entry| InboundUsage {
                group: Arc::clone(&entry.limit.name),
                active: entry.limit.state.active(),
                limits: entry.limit.state.limits(),
            })
            .collect()
    }

    #[cfg(test)]
    pub(super) fn held_states(&self) -> usize {
        self.states.len()
    }
}
