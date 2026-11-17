//! `siphon_mtu_tcp_upgrade_total`: requests moved from UDP to TCP because of
//! their size (RFC 3261 §18.1.1, `listen.mtu`), by the path that sent them.

use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts, Registry};

use crate::sip::message::{Method, SipMessage};

static UPGRADES: OnceLock<IntCounterVec> = OnceLock::new();

/// Which sender moved a request to TCP: the `path` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverMtuPath {
    /// A request the proxy relays or forks.
    Relay,
    /// A B2BUA B-leg INVITE.
    BLeg,
    /// A request a script originates (`proxy.send_request`), other than the
    /// two below.
    Script,
    /// A NOTIFY siphon originates (`SubscribeHandle.notify()`, the NOTIFY that
    /// ends an expired subscription, `presence.notify()`).
    Notify,
    /// A SUBSCRIBE siphon originates (`proxy.subscribe_state.send()`, its
    /// refresh and its unsubscribe).
    Subscribe,
}

impl OverMtuPath {
    const ALL: [Self; 5] = [
        Self::Relay,
        Self::BLeg,
        Self::Script,
        Self::Notify,
        Self::Subscribe,
    ];

    /// The label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::BLeg => "b_leg",
            Self::Script => "script",
            Self::Notify => "notify",
            Self::Subscribe => "subscribe",
        }
    }

    /// The path of a request siphon originates as a UAC, by its method.
    pub fn of_originated(message: &SipMessage) -> Self {
        match message.method() {
            Some(Method::Notify) => Self::Notify,
            Some(Method::Subscribe) => Self::Subscribe,
            _ => Self::Script,
        }
    }
}

/// Create and register the counter. Called once, when the process-wide
/// metrics are built.
pub(crate) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    let upgrades = IntCounterVec::new(
        Opts::new(
            "siphon_mtu_tcp_upgrade_total",
            "UDP requests over the listen.mtu threshold sent over TCP instead (RFC 3261 18.1.1), by the path that sent them",
        ),
        &["path"],
    )?;
    registry.register(Box::new(upgrades.clone()))?;
    // A labelled counter exports no series until a label value is first used;
    // create every path's series at zero so `rate()` has a baseline.
    for path in OverMtuPath::ALL {
        upgrades.with_label_values(&[path.as_str()]);
    }
    let _ = UPGRADES.set(upgrades);
    Ok(())
}

/// Count one request moved to TCP by `path`.
pub fn record(path: OverMtuPath) {
    if let Some(upgrades) = UPGRADES.get() {
        upgrades.with_label_values(&[path.as_str()]).inc();
    }
}

/// The count for `path` so far, for tests; 0 before [`init`].
#[cfg(test)]
pub(crate) fn count(path: OverMtuPath) -> u64 {
    UPGRADES
        .get()
        .map(|upgrades| upgrades.with_label_values(&[path.as_str()]).get())
        .unwrap_or(0)
}

/// Register the counter on a registry of the test's own, once per process,
/// so [`count`] reads what [`record`] wrote.
#[cfg(test)]
pub(crate) fn init_for_tests() {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(Registry::new);
    if UPGRADES.get().is_none() {
        // Lost a race with another test: the counter is there either way.
        let _ = init(registry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_path_exports_its_series_at_zero() {
        let registry = Registry::new();
        // The process-wide counter may already be set by another test; the
        // series are created on this registry's own collector regardless.
        init(&registry).expect("registers");
        let families = registry.gather();
        let family = families
            .iter()
            .find(|family| family.name() == "siphon_mtu_tcp_upgrade_total")
            .expect("exported before any upgrade");
        let mut paths: Vec<String> = family
            .get_metric()
            .iter()
            .map(|metric| metric.get_label()[0].value().to_string())
            .collect();
        paths.sort();
        assert_eq!(paths, ["b_leg", "notify", "relay", "script", "subscribe"]);
    }

    #[test]
    fn record_counts_under_the_paths_label() {
        init_for_tests();
        let before = count(OverMtuPath::Subscribe);
        record(OverMtuPath::Subscribe);
        assert_eq!(count(OverMtuPath::Subscribe), before + 1);
    }

    #[test]
    fn an_originated_request_is_labelled_by_its_method() {
        let request = |method: &str| {
            let raw = format!(
                concat!(
                    "{method} sip:watcher@example.com SIP/2.0\r\n",
                    "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-uac-1\r\n",
                    "From: <sip:a@example.com>;tag=1\r\n",
                    "To: <sip:b@example.com>\r\n",
                    "Call-ID: path-label\r\n",
                    "CSeq: 1 {method}\r\n",
                    "Content-Length: 0\r\n",
                    "\r\n",
                ),
                method = method
            );
            crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).expect("a request")
        };
        assert_eq!(
            OverMtuPath::of_originated(&request("NOTIFY")),
            OverMtuPath::Notify
        );
        assert_eq!(
            OverMtuPath::of_originated(&request("SUBSCRIBE")),
            OverMtuPath::Subscribe
        );
        assert_eq!(
            OverMtuPath::of_originated(&request("MESSAGE")),
            OverMtuPath::Script
        );
    }
}
