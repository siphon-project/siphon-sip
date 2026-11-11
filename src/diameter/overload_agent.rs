//! A DOIC agent (RFC 7683 section 5.3) for the requests a node relays with
//! `forward_to`, switched on by `diameter.overload.agent`.
//!
//! A plain relay leaves the OC-* AVPs alone. An agent sits between clients and
//! the backends of one realm and speaks for that realm:
//!
//! * a request towards a backend whose host report is in force is abated, and
//!   diverted to another backend of the pool ([`Failure::Abated`]); when every
//!   backend abates it the client gets 3004;
//! * the host reports of the backends stop at the agent. The answer carries the
//!   agent's own REALM report (section 7.6): the Origin-Realm of the answer,
//!   with the reduction the realm as a whole needs, which is how a client that
//!   keys its reports by Destination-Realm hears it;
//! * the agent advertises OC-Supported-Features to the backends for a client
//!   that did not, acts on what they report, and tells that client nothing
//!   (section 5.3: no OC-* towards a node that did not advertise support).
//!
//! The reduction of the realm is what is left of its capacity: every backend
//! counts as much as the others, a backend that reports `r` percent offers
//! `100 - r` of one, one that is down or not in the pool's open members offers
//! nothing, and the reduction is `100` minus the mean offer. Three backends,
//! one of them down, give 33 percent.

use super::codec::DiameterMsg;
use super::dictionary::{self, avp};
use super::forward;
use super::overload::{
    olr_avp, supported_features_avp, supports_loss, ReactingTable, ReportKey, ReportType,
    ReportingState, FEATURE_LOSS,
};
use super::retry::{self, RetryPolicy};
use super::DiameterClient;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What the agent knows of a backend it can send to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Backend {
    /// Origin-Host the backend gave in the capabilities exchange.
    pub host: Option<String>,
    /// Its Origin-Realm.
    pub realm: Option<String>,
}

impl Backend {
    fn of(client: &DiameterClient) -> Self {
        Self {
            host: client.peer().remote_origin_host().map(str::to_owned),
            realm: client.peer().remote_origin_realm().map(str::to_owned),
        }
    }
}

/// The realm reports an agent has made, one sequence per realm and
/// application.
#[derive(Debug)]
pub struct Agent {
    validity_secs: u32,
    reports: Mutex<HashMap<(String, u32), Arc<ReportingState>>>,
}

impl Agent {
    pub fn new(validity_secs: u32) -> Self {
        Self {
            validity_secs,
            reports: Mutex::new(HashMap::new()),
        }
    }

    fn state(&self, realm: &str, application: u32) -> Option<Arc<ReportingState>> {
        let mut reports = self.reports.lock().ok()?;
        Some(Arc::clone(
            reports
                .entry((realm.to_ascii_lowercase(), application))
                .or_insert_with(|| {
                    Arc::new(ReportingState::of_type(
                        ReportType::Realm,
                        self.validity_secs,
                        None,
                    ))
                }),
        ))
    }

    /// The reduction the realm needs, in percent: see the module comment.
    /// `up` are the backends that are open, `configured` how many the pool
    /// has in all (the ones missing from `up` are down).
    pub fn reduction(
        table: &ReactingTable,
        application: u32,
        up: &[Backend],
        configured: usize,
        now: Instant,
    ) -> u32 {
        let total = configured.max(up.len());
        if total == 0 {
            return 0;
        }
        let offered: u32 = up
            .iter()
            .map(|backend| {
                let mut keys = Vec::with_capacity(2);
                if let Some(host) = &backend.host {
                    keys.push(ReportKey::new(ReportType::Host, host, application));
                }
                if let Some(realm) = &backend.realm {
                    keys.push(ReportKey::new(ReportType::Realm, realm, application));
                }
                100 - table.reduction_for(&keys, now).map_or(0, |found| found.0)
            })
            .sum();
        (100.0 - f64::from(offered) / total as f64)
            .round()
            .clamp(0.0, 100.0) as u32
    }

    /// Make `answer`, relayed from a backend, what the agent says to its
    /// client: the backend's OC-Supported-Features and OC-OLR out, and, for a
    /// client that advertised the loss algorithm, the agent's own
    /// OC-Supported-Features and, while there is overload in the realm, its
    /// realm report. `realm` is the realm the report is about. Returns
    /// whether an OC-OLR was added.
    pub fn rewrite_answer(
        &self,
        table: &ReactingTable,
        answer: &mut DiameterMsg,
        realm: &str,
        client_supports_loss: bool,
        up: &[Backend],
        configured: usize,
        now: Instant,
    ) -> bool {
        answer.avps.retain(|avp| {
            !(avp.vendor == 0
                && (avp.code == avp::OC_OLR || avp.code == avp::OC_SUPPORTED_FEATURES))
        });
        if !client_supports_loss {
            return false;
        }
        answer.avps.push(supported_features_avp(FEATURE_LOSS));
        let Some(state) = self.state(realm, answer.application_id) else {
            return false;
        };
        let reduction = Self::reduction(table, answer.application_id, up, configured, now);
        state.set(reduction, None, now);
        let Some(olr) = state.olr(0, now) else {
            return false;
        };
        answer.avps.push(olr_avp(&olr));
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics
                .diameter_overload_olr_total
                .with_label_values(&["sent"])
                .inc();
            metrics
                .diameter_overload_reduction_percent
                .with_label_values(&["agent", &realm.to_ascii_lowercase()])
                .set(i64::from(reduction));
        }
        true
    }
}

/// Make `request`, about to go to a backend, advertise the loss algorithm.
/// Returns whether its sender did, which decides what the client is told of
/// the answer.
pub fn prepare_request(request: &mut DiameterMsg) -> bool {
    let supported = supports_loss(request);
    if !supported {
        request
            .avps
            .retain(|avp| !(avp.vendor == 0 && avp.code == avp::OC_SUPPORTED_FEATURES));
        request.avps.push(supported_features_avp(FEATURE_LOSS));
    }
    supported
}

/// Where a relayed request may go, for [`relay`].
pub struct Target<'a> {
    pub first: &'a Arc<DiameterClient>,
    /// The other open members of the pool `first` came from.
    pub alternates: &'a [Arc<DiameterClient>],
    /// How many members the pool has, open or not.
    pub configured: usize,
}

/// Send `request` (already prepared for forwarding, carrying the inbound
/// Hop-by-Hop Identifier) to `target` and return the answer for the client,
/// with the inbound identifiers restored. A failure is answered here:
/// DIAMETER_TOO_BUSY when it timed out or every backend abated it,
/// DIAMETER_UNABLE_TO_DELIVER otherwise. As an agent the request is made to
/// advertise DOIC and the answer carries the realm's report, see the module
/// comment.
pub async fn relay(
    policy: &RetryPolicy,
    request: &mut DiameterMsg,
    target: Target<'_>,
    timeout: Duration,
    local_origin: (&str, &str),
) -> DiameterMsg {
    let overload = super::overload::current();
    let agent = overload.agent.as_ref();
    let client_supports = agent.map(|_| prepare_request(request));

    let inbound_hbh = request.hop_by_hop;
    request.hop_by_hop = target.first.peer().next_hbh();
    let wire = request.to_wire();
    request.hop_by_hop = inbound_hbh;

    let sent = retry::send_routed(
        policy,
        target.first,
        target.alternates,
        wire,
        timeout,
        super::overload::Origin::Relayed,
    )
    .await;

    let mut from_backend = false;
    let mut answer = match sent {
        Ok(message) => match DiameterMsg::from_wire(&message.raw) {
            Ok(mut answer) => {
                from_backend = true;
                answer.hop_by_hop = inbound_hbh;
                answer.end_to_end = request.end_to_end;
                answer
            }
            Err(_) => forward::build_error_answer(
                request,
                local_origin.0,
                local_origin.1,
                dictionary::DIAMETER_UNABLE_TO_DELIVER,
                "malformed answer from backend",
            ),
        },
        Err(reason) => {
            let result_code = if reason.contains("timed out") || super::overload::is_abated(&reason)
            {
                dictionary::DIAMETER_TOO_BUSY
            } else {
                dictionary::DIAMETER_UNABLE_TO_DELIVER
            };
            forward::build_error_answer(
                request,
                local_origin.0,
                local_origin.1,
                result_code,
                &reason,
            )
        }
    };

    if let (Some(agent), Some(client_supports)) = (agent, client_supports) {
        // The realm that answered; an answer the agent made itself speaks
        // for the realm the client addressed.
        let realm = if from_backend {
            answer.get_str(avp::ORIGIN_REALM)
        } else {
            request.get_str(avp::DESTINATION_REALM)
        }
        .unwrap_or_else(|| local_origin.1.to_string());
        let mut up = vec![Backend::of(target.first)];
        up.extend(
            target
                .alternates
                .iter()
                .filter(|client| client.peer().is_open())
                .map(|client| Backend::of(client)),
        );
        if !target.first.peer().is_open() {
            up.remove(0);
        }
        agent.rewrite_answer(
            &overload.table,
            &mut answer,
            &realm,
            client_supports,
            &up,
            target.configured,
            Instant::now(),
        );
    }
    answer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::codec::Avp;
    use crate::diameter::overload::{parse_olr, Olr};

    const S6A: u32 = dictionary::S6A_APP_ID;

    fn host(name: &str) -> Backend {
        Backend {
            host: Some(name.to_string()),
            realm: Some("example.net".to_string()),
        }
    }

    fn report(table: &ReactingTable, name: &str, reduction: u32, now: Instant) {
        table.update(
            ReportKey::new(ReportType::Host, name, S6A),
            &Olr {
                sequence: 1,
                report_type: ReportType::Host,
                validity_secs: 30,
                reduction_percentage: reduction,
            },
            now,
        );
    }

    fn answer() -> DiameterMsg {
        DiameterMsg {
            flags: 0,
            command_code: 318,
            application_id: S6A,
            hop_by_hop: 1,
            end_to_end: 2,
            avps: vec![Avp::utf8(avp::ORIGIN_REALM, 0, "example.net")],
        }
    }

    #[test]
    fn the_realm_reduction_is_what_is_left_of_the_capacity() {
        let table = ReactingTable::default();
        let now = Instant::now();
        let up = [host("a"), host("b"), host("c")];
        assert_eq!(Agent::reduction(&table, S6A, &up, 3, now), 0);
        report(&table, "a", 60, now);
        // offers 40 + 100 + 100 of 300
        assert_eq!(Agent::reduction(&table, S6A, &up, 3, now), 20);
        report(&table, "b", 100, now);
        assert_eq!(Agent::reduction(&table, S6A, &up, 3, now), 53);
        // One down offers nothing: 40 + 0 of 300.
        assert_eq!(Agent::reduction(&table, S6A, &up[..2], 3, now), 87);
        assert_eq!(Agent::reduction(&table, S6A, &[], 3, now), 100);
        assert_eq!(Agent::reduction(&table, S6A, &[], 0, now), 0);
        // A report of another application is not this one's.
        assert_eq!(Agent::reduction(&table, 4, &up, 3, now), 0);
    }

    #[test]
    fn the_answer_to_a_client_that_supports_doic_carries_the_realm_report_only() {
        let table = ReactingTable::default();
        let agent = Agent::new(30);
        let now = Instant::now();
        let up = [host("a"), host("b")];
        report(&table, "a", 100, now);
        let mut relayed = answer();
        // What backend a said: its own host report.
        relayed.avps.push(supported_features_avp(FEATURE_LOSS));
        relayed.avps.push(olr_avp(&Olr {
            sequence: 9,
            report_type: ReportType::Host,
            validity_secs: 30,
            reduction_percentage: 100,
        }));
        assert!(agent.rewrite_answer(&table, &mut relayed, "example.net", true, &up, 2, now));
        let seen = parse_olr(&relayed).expect("a report");
        assert_eq!(seen.report_type, ReportType::Realm);
        assert_eq!(seen.reduction_percentage, 50);
        assert_eq!(seen.validity_secs, 30);
        assert_eq!(
            relayed.find_all(avp::OC_OLR, 0).count(),
            1,
            "the backend's report is gone"
        );
        assert_eq!(
            relayed.find_all(avp::OC_SUPPORTED_FEATURES, 0).count(),
            1,
            "one OC-Supported-Features, the agent's"
        );
    }

    #[test]
    fn the_sequence_holds_while_the_report_holds_and_rises_when_it_changes() {
        let table = ReactingTable::default();
        let agent = Agent::new(30);
        let now = Instant::now();
        let up = [host("a"), host("b")];
        report(&table, "a", 100, now);
        let mut first = answer();
        agent.rewrite_answer(&table, &mut first, "example.net", true, &up, 2, now);
        let mut again = answer();
        agent.rewrite_answer(&table, &mut again, "example.net", true, &up, 2, now);
        assert_eq!(
            parse_olr(&first).map(|olr| olr.sequence),
            parse_olr(&again).map(|olr| olr.sequence)
        );
        report(&table, "b", 100, now);
        // The table ignores a report that does not carry a newer sequence.
        table.update(
            ReportKey::new(ReportType::Host, "b", S6A),
            &Olr {
                sequence: 2,
                report_type: ReportType::Host,
                validity_secs: 30,
                reduction_percentage: 100,
            },
            now,
        );
        let mut changed = answer();
        agent.rewrite_answer(&table, &mut changed, "example.net", true, &up, 2, now);
        let changed = parse_olr(&changed).expect("a report");
        assert_eq!(changed.reduction_percentage, 100);
        assert!(changed.sequence > parse_olr(&first).expect("a report").sequence);
        // The backends recover: one report with no reduction, then nothing.
        table.update(
            ReportKey::new(ReportType::Host, "a", S6A),
            &Olr {
                sequence: 2,
                report_type: ReportType::Host,
                validity_secs: 30,
                reduction_percentage: 0,
            },
            now,
        );
        table.update(
            ReportKey::new(ReportType::Host, "b", S6A),
            &Olr {
                sequence: 3,
                report_type: ReportType::Host,
                validity_secs: 30,
                reduction_percentage: 0,
            },
            now,
        );
        let mut ended = answer();
        agent.rewrite_answer(&table, &mut ended, "example.net", true, &up, 2, now);
        let ended = parse_olr(&ended).expect("the end is reported");
        assert_eq!(ended.reduction_percentage, 0);
        assert!(ended.sequence > changed.sequence);
        let mut quiet = answer();
        assert!(!agent.rewrite_answer(&table, &mut quiet, "example.net", true, &up, 2, now));
        assert!(parse_olr(&quiet).is_none());
    }

    #[test]
    fn a_client_without_doic_hears_nothing_of_the_backends_reports() {
        let table = ReactingTable::default();
        let agent = Agent::new(30);
        let now = Instant::now();
        report(&table, "a", 100, now);
        let mut relayed = answer();
        relayed.avps.push(supported_features_avp(FEATURE_LOSS));
        relayed.avps.push(olr_avp(&Olr {
            sequence: 9,
            report_type: ReportType::Host,
            validity_secs: 30,
            reduction_percentage: 100,
        }));
        assert!(!agent.rewrite_answer(
            &table,
            &mut relayed,
            "example.net",
            false,
            &[host("a")],
            1,
            now
        ));
        assert_eq!(relayed, answer());
    }

    // Hand-assembled from RFC 7683 section 7: the OC-OLR of a realm report,
    // sequence 1, 50 percent, 30 s. It differs from a host report in the
    // OC-Report-Type only.
    const REALM_OLR_50_PERCENT: [u8; 60] = [
        0x00, 0x00, 0x02, 0x6f, 0x00, 0x00, 0x00, 0x3c, // OC-OLR, 60
        0x00, 0x00, 0x02, 0x70, 0x00, 0x00, 0x00, 0x10, // OC-Sequence-Number
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 1
        0x00, 0x00, 0x02, 0x72, 0x00, 0x00, 0x00, 0x0c, // OC-Report-Type
        0x00, 0x00, 0x00, 0x01, // REALM_REPORT
        0x00, 0x00, 0x02, 0x73, 0x00, 0x00, 0x00, 0x0c, // OC-Reduction-Percentage
        0x00, 0x00, 0x00, 0x32, // 50
        0x00, 0x00, 0x02, 0x71, 0x00, 0x00, 0x00, 0x0c, // OC-Validity-Duration
        0x00, 0x00, 0x00, 0x1e, // 30 s
    ];

    #[test]
    fn the_realm_report_on_the_wire_is_the_rfc_7683_encoding() {
        let table = ReactingTable::default();
        let agent = Agent::new(30);
        let now = Instant::now();
        report(&table, "a", 100, now);
        let mut relayed = answer();
        agent.rewrite_answer(
            &table,
            &mut relayed,
            "example.net",
            true,
            &[host("a"), host("b")],
            2,
            now,
        );
        let wire = relayed.to_wire();
        let start = wire
            .windows(4)
            .position(|window| window == [0x00, 0x00, 0x02, 0x6f])
            .expect("an OC-OLR on the wire");
        let mut emitted = wire[start..start + 60].to_vec();
        // The sequence number is seeded from the clock: compare the rest.
        emitted[16..24].copy_from_slice(&1u64.to_be_bytes());
        assert_eq!(emitted, REALM_OLR_50_PERCENT);
        // And the hand-assembled bytes read back as a realm report.
        let mut message = answer().to_wire();
        let length = (message.len() + 60) as u32;
        message.extend_from_slice(&REALM_OLR_50_PERCENT);
        message[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
        let parsed = parse_olr(&DiameterMsg::from_wire(&message).unwrap()).unwrap();
        assert_eq!(parsed.report_type, ReportType::Realm);
        assert_eq!(parsed.reduction_percentage, 50);
    }

    #[test]
    fn a_request_is_made_to_advertise_the_loss_algorithm() {
        let mut plain = answer();
        assert!(!prepare_request(&mut plain));
        assert!(supports_loss(&plain));
        let mut capable = answer();
        capable.avps.push(supported_features_avp(FEATURE_LOSS));
        let before = capable.clone();
        assert!(prepare_request(&mut capable));
        assert_eq!(capable, before, "left as the client made it");
        let mut other = answer();
        other.avps.push(supported_features_avp(0x8));
        assert!(!prepare_request(&mut other));
        assert!(supports_loss(&other));
        assert_eq!(other.find_all(avp::OC_SUPPORTED_FEATURES, 0).count(), 1);
    }
}
