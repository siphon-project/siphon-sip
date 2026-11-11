//! Sending a request to another peer of its route when the first one could
//! not serve it, once.
//!
//! A request that failed with DIAMETER_TOO_BUSY (3004) or
//! DIAMETER_UNABLE_TO_DELIVER (3002), that was not answered in time, that was
//! lost with its connection (a peer gone SUSPECT, RFC 3539), or that this node
//! abated on an overload report (RFC 7683) goes to the next open peer, and no
//! further: one retry, never a loop.
//!
//! Retrying is safe only for a request whose repetition does no harm. A
//! request that was abated never left this node, so it is diverted whatever it
//! is (when `diameter.overload.reacting.action` is `divert`). Everything else
//! is retried only where `diameter.retry` says so for the application and the
//! command, and a command that changes state at the peer (accounting and
//! credit control records, re-auth, abort and termination) is left out of an
//! entry that lists no commands, and sent again only when an entry names it.

use super::codec::DiameterMessage;
use super::dictionary;
use super::overload::{self, Origin};
use super::DiameterClient;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;

/// Why a request is sent to another peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The peer answered DIAMETER_TOO_BUSY (3004).
    TooBusy,
    /// The peer answered DIAMETER_UNABLE_TO_DELIVER (3002), or the request
    /// was lost with its connection.
    UnableToDeliver,
    /// No answer in time.
    Timeout,
    /// This node abated it on an overload report; it was not sent.
    Abated,
}

impl Failure {
    /// The label of `siphon_diameter_retries_total`.
    pub fn label(self) -> &'static str {
        match self {
            Self::TooBusy => "too_busy",
            Self::UnableToDeliver => "unable_to_deliver",
            Self::Timeout => "timeout",
            Self::Abated => "abated",
        }
    }
}

/// Commands that change state at the peer: ACR, CCR, RAR, ASR and STR. An
/// entry of `diameter.retry` that lists no commands does not retry them.
const NON_IDEMPOTENT: [u32; 5] = [271, 272, 258, 274, 275];

/// One `diameter.retry` entry.
#[derive(Debug, Clone)]
pub struct RetryRule {
    pub application_id: u32,
    /// The commands retried; empty is every command that is safe to repeat.
    pub commands: Vec<u32>,
    pub too_busy: bool,
    pub unable_to_deliver: bool,
    pub timeout: bool,
}

/// What may be retried, and what is diverted.
#[derive(Debug, Clone, Default)]
pub struct RetryPolicy {
    pub rules: Vec<RetryRule>,
    /// Send an abated request to another peer instead of failing it.
    pub divert_abated: bool,
}

impl RetryPolicy {
    /// From `diameter.retry` and `diameter.overload.reacting.action`.
    pub fn from_config(config: &crate::config::DiameterConfig) -> Self {
        let rules = config
            .retry
            .iter()
            .map(|entry| RetryRule {
                application_id: entry.application.to_app_id().1,
                commands: entry
                    .commands
                    .iter()
                    .filter_map(|name| dictionary::command_code_by_name(name))
                    .collect(),
                too_busy: entry.on.is_empty() || entry.on.iter().any(|on| on == "too_busy"),
                unable_to_deliver: entry.on.is_empty()
                    || entry.on.iter().any(|on| on == "unable_to_deliver"),
                timeout: entry.on.is_empty() || entry.on.iter().any(|on| on == "timeout"),
            })
            .collect();
        let divert_abated = config
            .overload
            .as_ref()
            .and_then(|overload| overload.reacting.as_ref())
            .is_some_and(|reacting| {
                reacting.action == crate::config::DiameterAbatementAction::Divert
            })
            // An agent has nowhere else to put what it abates.
            || config.overload.as_ref().is_some_and(|overload| overload.agent);
        Self {
            rules,
            divert_abated,
        }
    }

    /// Whether a request of `command_code` in `application_id` that failed
    /// for `failure` is sent to another peer.
    pub fn allows(&self, application_id: u32, command_code: u32, failure: Failure) -> bool {
        if failure == Failure::Abated {
            return self.divert_abated;
        }
        self.rules.iter().any(|rule| {
            rule.application_id == application_id
                && match failure {
                    Failure::TooBusy => rule.too_busy,
                    Failure::UnableToDeliver => rule.unable_to_deliver,
                    Failure::Timeout => rule.timeout,
                    Failure::Abated => false,
                }
                && if rule.commands.is_empty() {
                    !NON_IDEMPOTENT.contains(&command_code)
                } else {
                    rule.commands.contains(&command_code)
                }
        })
    }
}

static CURRENT: LazyLock<RwLock<Arc<RetryPolicy>>> =
    LazyLock::new(|| RwLock::new(Arc::new(RetryPolicy::default())));

/// The policy in force: nothing retried until [`install`] is called.
pub fn current() -> Arc<RetryPolicy> {
    CURRENT
        .read()
        .map(|current| Arc::clone(&current))
        .unwrap_or_else(|poisoned| Arc::clone(&poisoned.into_inner()))
}

/// Put `policy` in force.
pub fn install(policy: RetryPolicy) {
    let mut current = CURRENT
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *current = Arc::new(policy);
}

/// How a send ended, as far as retrying goes.
fn failure_of(result: &Result<DiameterMessage, String>) -> Option<Failure> {
    match result {
        Ok(answer) => {
            let code = answer
                .avps
                .get("Result-Code")
                .and_then(serde_json::Value::as_u64)?;
            match code as u32 {
                dictionary::DIAMETER_TOO_BUSY => Some(Failure::TooBusy),
                dictionary::DIAMETER_UNABLE_TO_DELIVER => Some(Failure::UnableToDeliver),
                _ => None,
            }
        }
        Err(error) if overload::is_abated(error) => Some(Failure::Abated),
        Err(error) if error.contains("timed out") => Some(Failure::Timeout),
        // A connection lost under the request, a queue that did not drain,
        // a peer that went SUSPECT: the request did not get through.
        Err(_) => Some(Failure::UnableToDeliver),
    }
}

/// `wire` with the Hop-by-Hop Identifier `peer` hands out next.
fn with_hop_by_hop(wire: &[u8], peer: &super::peer::DiameterPeer) -> Vec<u8> {
    let mut wire = wire.to_vec();
    if wire.len() >= 20 {
        wire[12..16].copy_from_slice(&peer.next_hbh().to_be_bytes());
    }
    wire
}

/// `wire` with the T (potentially retransmitted) flag set, as RFC 6733
/// sections 5.5.4 and 6.1.8 require of a request sent again after a failover.
fn with_retransmitted_flag(mut wire: Vec<u8>) -> Vec<u8> {
    if wire.len() >= 20 {
        wire[4] |= super::codec::FLAG_RETRANSMITTED;
    }
    wire
}

/// Send `wire` to `first` and wait up to `timeout`. When that fails in a way
/// `policy` allows for this request, send it once to the first open peer of
/// `alternates` and return that outcome. `wire` carries the Hop-by-Hop
/// Identifier of `first`; each attempt gets its own peer's. The attempt at an
/// alternate peer carries the T flag.
pub async fn send_routed(
    policy: &RetryPolicy,
    first: &DiameterClient,
    alternates: &[Arc<DiameterClient>],
    wire: Vec<u8>,
    timeout: Duration,
    origin: Origin,
) -> Result<DiameterMessage, String> {
    let (application_id, command_code) = if wire.len() >= 20 {
        (
            u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
            u32::from_be_bytes([0, wire[5], wire[6], wire[7]]),
        )
    } else {
        (0, 0)
    };
    let result = first
        .peer()
        .send_request_as(wire.clone(), timeout, origin)
        .await;
    let Some(failure) = failure_of(&result) else {
        return result;
    };
    if !policy.allows(application_id, command_code, failure) {
        return result;
    }
    let Some(next) = overload::least_reduced(
        alternates
            .iter()
            .filter(|client| client.peer().is_open() && !Arc::ptr_eq(client.peer(), first.peer())),
        application_id,
        origin,
    ) else {
        return result;
    };
    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics
            .diameter_retries_total
            .with_label_values(&[failure.label()])
            .inc();
    }
    tracing::info!(
        reason = failure.label(),
        "Diameter: request sent to another peer of its route"
    );
    let again = with_retransmitted_flag(with_hop_by_hop(&wire, next.peer()));
    next.peer().send_request_as(again, timeout, origin).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(application_id: u32, commands: &[u32]) -> RetryRule {
        RetryRule {
            application_id,
            commands: commands.to_vec(),
            too_busy: true,
            unable_to_deliver: true,
            timeout: true,
        }
    }

    fn policy(rules: Vec<RetryRule>) -> RetryPolicy {
        RetryPolicy {
            rules,
            divert_abated: false,
        }
    }

    const S6A: u32 = dictionary::S6A_APP_ID;
    const AIR: u32 = 318;
    const CCR: u32 = 272;

    fn silent_peer(
        origin_host: &str,
    ) -> (Arc<DiameterClient>, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let (write_tx, write_rx) = tokio::sync::mpsc::channel(8);
        let config = super::super::peer::PeerConfig {
            host: "192.0.2.10".to_string(),
            port: 3868,
            origin_host: origin_host.to_string(),
            origin_realm: "epc.example.net".to_string(),
            destination_host: None,
            destination_realm: "epc.example.net".to_string(),
            local_ip: "192.0.2.11".parse().unwrap(),
            application_ids: Vec::new(),
            watchdog_interval: 30,
            reconnect_delay: 5,
            source_address: None,
            lifecycle: Default::default(),
            product_name: "test".to_string(),
            firmware_revision: 1,
        };
        let peer = Arc::new(super::super::peer::DiameterPeer::new_for_test(
            config, write_tx,
        ));
        (Arc::new(DiameterClient::new(peer)), write_rx)
    }

    /// RFC 6733 sections 5.5.4 and 6.1.8: a request sent again to another
    /// peer carries the T flag; the first send does not. End-to-End
    /// Identifier unchanged, Hop-by-Hop fresh.
    #[tokio::test]
    async fn a_request_sent_to_an_alternate_peer_carries_the_t_flag() {
        let (first, mut first_wire) = silent_peer("hss-1.epc.example.net");
        let (alternate, mut alternate_wire) = silent_peer("hss-2.epc.example.net");
        let request = super::super::codec::DiameterMsg {
            flags: super::super::codec::FLAG_REQUEST | super::super::codec::FLAG_PROXIABLE,
            command_code: AIR,
            application_id: S6A,
            hop_by_hop: first.peer().next_hbh(),
            end_to_end: 0x5151,
            avps: Vec::new(),
        };
        let policy = policy(vec![rule(S6A, &[])]);
        let result = send_routed(
            &policy,
            &first,
            &[Arc::clone(&alternate)],
            request.to_wire(),
            Duration::from_millis(100),
            Origin::Local,
        )
        .await;
        assert!(result.is_err(), "neither peer answers");

        let sent_first = super::super::codec::DiameterMsg::from_wire(
            &first_wire.try_recv().expect("the first peer got it"),
        )
        .unwrap();
        let sent_again = super::super::codec::DiameterMsg::from_wire(
            &alternate_wire.try_recv().expect("the alternate got it"),
        )
        .unwrap();
        assert_eq!(
            sent_first.flags & super::super::codec::FLAG_RETRANSMITTED,
            0
        );
        assert_ne!(
            sent_again.flags & super::super::codec::FLAG_RETRANSMITTED,
            0,
            "T flag on the request sent again"
        );
        assert_eq!(sent_first.end_to_end, sent_again.end_to_end);
        assert_eq!(sent_first.command_code, sent_again.command_code);
    }

    #[test]
    fn nothing_is_retried_by_default() {
        let nothing = RetryPolicy::default();
        for failure in [Failure::TooBusy, Failure::UnableToDeliver, Failure::Timeout] {
            assert!(!nothing.allows(S6A, AIR, failure));
        }
        assert!(!nothing.allows(S6A, AIR, Failure::Abated));
    }

    #[test]
    fn an_application_is_retried_for_the_failures_its_entry_names() {
        let mut entry = rule(S6A, &[]);
        entry.timeout = false;
        let policy = policy(vec![entry]);
        assert!(policy.allows(S6A, AIR, Failure::TooBusy));
        assert!(policy.allows(S6A, AIR, Failure::UnableToDeliver));
        assert!(!policy.allows(S6A, AIR, Failure::Timeout));
        assert!(!policy.allows(dictionary::CX_APP_ID, AIR, Failure::TooBusy));
    }

    #[test]
    fn a_command_that_changes_state_is_not_retried_unless_the_entry_names_it() {
        let open = policy(vec![rule(4, &[])]);
        for command in NON_IDEMPOTENT {
            assert!(
                !open.allows(4, command, Failure::TooBusy),
                "command {command}"
            );
        }
        assert!(open.allows(4, 300, Failure::TooBusy));
        let named = policy(vec![rule(4, &[CCR])]);
        assert!(named.allows(4, CCR, Failure::TooBusy));
        assert!(
            !named.allows(4, 300, Failure::TooBusy),
            "only the named command"
        );
    }

    #[test]
    fn an_abated_request_is_diverted_only_when_configured() {
        let mut policy = policy(vec![]);
        assert!(!policy.allows(S6A, CCR, Failure::Abated));
        policy.divert_abated = true;
        // It never left this node, so even a state-changing command is safe.
        assert!(policy.allows(S6A, CCR, Failure::Abated));
    }

    #[test]
    fn the_configuration_builds_the_policy() {
        let config: crate::config::DiameterConfig = serde_saphyr::from_str(
            "retry:\n  - {application: cx, commands: [UAR, LIR], on: [too_busy, timeout]}\n  - {application: ro}\noverload:\n  reacting: {action: divert}\n",
        )
        .unwrap();
        let policy = RetryPolicy::from_config(&config);
        assert!(policy.divert_abated);
        assert!(policy.allows(
            dictionary::CX_APP_ID,
            dictionary::CMD_USER_AUTHORIZATION,
            Failure::TooBusy
        ));
        assert!(!policy.allows(
            dictionary::CX_APP_ID,
            dictionary::CMD_USER_AUTHORIZATION,
            Failure::UnableToDeliver
        ));
        assert!(!policy.allows(
            dictionary::CX_APP_ID,
            dictionary::CMD_SERVER_ASSIGNMENT,
            Failure::TooBusy
        ));
        assert!(
            !policy.allows(4, CCR, Failure::TooBusy),
            "ro without commands skips credit control"
        );
        assert!(policy.allows(4, 300, Failure::TooBusy));
    }
}
