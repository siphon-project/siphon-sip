//! Every charging record, and every CDR, names the carrier the call was on.
//!
//! `Outgoing-Trunk-Group-Id` (TS 32.299 §7.2.71) used to be stamped on the Ro
//! session at the 2xx alone, so an OCS was told a call was placed, told what it
//! consumed, and never told where it went unless somebody answered. The largest
//! class of unanswered call — a caller hanging up during ringing — could not be
//! attributed to a carrier at all, which makes a per-carrier answer-seizure
//! ratio computed from the charging feed 100 % for every carrier. The CDR feed
//! had the same hole on the same calls, so there was nothing to reconcile
//! against either.
//!
//! Driven through the real dispatcher with the LCR harness of
//! [`super::lcr_ring_timeout_tests`], against the loopback mock OCS of
//! [`crate::diameter::ro_test_support`]: every assertion below reads a **CCR the
//! OCS actually received**, decoded on its side of the socket, not a value on
//! siphon's.

use super::lcr_ring_timeout_tests::{carrier, invite_to, Sequence, FIRST_CARRIER, SECOND_CARRIER};
use super::lcr_route_bookkeeping_tests::caller_cancels;
use super::*;
use crate::diameter::ro::{ImsChargingData, SubscriberId};
use crate::diameter::ro_service::{ChargeDecision, RoChargingService};
use crate::diameter::ro_test_support::{
    ccr_of_type, enabled_config, mock_ocs_manager, outgoing_trunk_group,
};
use std::time::Duration;

/// CC-Request-Type values (RFC 8506 §8.3).
const CCR_INITIAL: u64 = 1;
const CCR_UPDATE: u64 = 2;
const CCR_TERMINATION: u64 = 3;

/// A caller's LCR call with a live Ro reservation against a mock OCS, wired the
/// way a real one is: the reservation is taken **before** any B-leg INVITE
/// leaves, which is what `call.ro_authorize()` does from `@b2bua.on_invite`.
struct Charged {
    sequence: Sequence,
    /// Every CCR the OCS received, decoded.
    captured: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    /// The mock peer's inbound-request channel. Held only so the connection
    /// tasks keep a live receiver for the call's lifetime.
    _incoming: tokio::sync::mpsc::Receiver<crate::diameter::peer::IncomingRequest>,
}

impl Charged {
    /// Reserve credit, then start `routes` with a 5 s sequence ring bound.
    async fn start(routes: Vec<crate::lcr::Route>) -> Charged {
        Charged::start_on_grant(routes, 30).await
    }

    /// [`Charged::start`] with the OCS granting `grant_secs`, which is what
    /// drives the re-authorization cadence.
    async fn start_on_grant(routes: Vec<crate::lcr::Route>, grant_secs: u32) -> Charged {
        let (manager, incoming, captured) =
            mock_ocs_manager(2001, Some(grant_secs), 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let mut sequence = Sequence::new_call("");
        sequence.dispatcher.state.ro_charger = Some(Arc::clone(&service));

        let session = match service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                ImsChargingData {
                    calling_party: vec!["sip:+10000000001@ims.example.com".into()],
                    called_party: Some("sip:+10000000002@ims.example.com".into()),
                    sip_method: Some("INVITE".into()),
                    ims_charging_identifier: Some("icid-value-1".into()),
                    ..Default::default()
                },
                "lcr-policy@192.0.2.10".to_string(),
            )
            .await
        {
            ChargeDecision::Granted(Some(session)) => session,
            _ => panic!("the mock OCS granted no session"),
        };
        sequence
            .dispatcher
            .state
            .ro_sessions
            .insert(ro_b2bua_key(&sequence.call_id), session);

        sequence.start_routes(routes, 5);
        Charged {
            sequence,
            captured,
            _incoming: incoming,
        }
    }

    /// The first CCR of `request_type` the OCS received, waiting for it to land.
    ///
    /// The charging sends are `tokio::spawn`ed off the SIP path on purpose (the
    /// caller's 487 must never wait on an OCS), so the record arrives after the
    /// call that triggered it has already been torn down. The budget is generous
    /// because a re-authorization is driven by the OCS grant, not by the call.
    async fn ccr(&self, request_type: u64) -> serde_json::Value {
        for _ in 0..1000 {
            let ccrs = self.captured.lock().expect("the capture lock").clone();
            if ccrs.iter().any(|ccr| {
                ccr.get("CC-Request-Type").and_then(|v| v.as_u64()) == Some(request_type)
            }) {
                return ccr_of_type(&ccrs, request_type);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no CCR of type {request_type} reached the OCS");
    }
}

/// The failure this exists for, read off the OCS side: a call routed to one
/// carrier and abandoned by the caller while it rang produced a
/// CCR-TERMINATION naming nobody, so the seizure could not be attributed and
/// the carrier's ASR from the charging feed read 100 %.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_the_caller_hung_up_on_reaches_the_final_record() {
    let charged = Charged::start(vec![carrier("carrier-a", FIRST_CARRIER, 2)]).await;

    // The reservation is taken before any carrier is chosen, so the INITIAL
    // still names nobody — that part was never the bug.
    let initial = charged.ccr(CCR_INITIAL).await;
    assert_eq!(
        outgoing_trunk_group(&initial),
        None,
        "no carrier is known yet when credit is reserved",
    );

    caller_cancels(&charged.sequence);

    let terminate = charged.ccr(CCR_TERMINATION).await;
    assert_eq!(
        outgoing_trunk_group(&terminate).as_deref(),
        Some("carrier-a"),
        "the call was on carrier-a when the caller gave up, and the record must say so",
    );
}

/// A re-authorization that fires while a carrier is still ringing carries that
/// carrier — the mid-call records used to be as anonymous as the final one,
/// because nothing had been stamped yet.
///
/// Slow by construction: the re-auth cadence comes from the OCS grant, floored
/// at `MIN_REAUTH_SECS` (5 s), so the loop cannot be asked to fire sooner.
#[tokio::test(flavor = "multi_thread")]
async fn a_reauthorization_while_a_carrier_rings_carries_that_carrier() {
    let charged = Charged::start_on_grant(vec![carrier("carrier-a", FIRST_CARRIER, 30)], 1).await;

    // Nobody answers. The next record in the session is the re-authorization.
    let update = charged.ccr(CCR_UPDATE).await;
    assert_eq!(
        outgoing_trunk_group(&update).as_deref(),
        Some("carrier-a"),
        "a call still ringing is on a carrier, and its mid-call records must say which",
    );
}

/// The carrier a failover moved off is not the one the call was on. After A's
/// 503 the call rings on B, so an abandoned call names B.
#[tokio::test(flavor = "multi_thread")]
async fn a_failover_names_the_carrier_that_was_ringing_not_the_one_that_failed() {
    let mut charged = Charged::start(vec![
        carrier("carrier-a", FIRST_CARRIER, 2),
        carrier("carrier-b", SECOND_CARRIER, 2),
    ])
    .await;

    let first = invite_to(charged.sequence.wire(), FIRST_CARRIER);
    charged
        .sequence
        .carrier_answers(FIRST_CARRIER, &first, 503, "Service Unavailable");
    let _ = invite_to(charged.sequence.wire(), SECOND_CARRIER);
    charged.sequence.redialled();

    caller_cancels(&charged.sequence);

    let terminate = charged.ccr(CCR_TERMINATION).await;
    assert_eq!(
        outgoing_trunk_group(&terminate).as_deref(),
        Some("carrier-b"),
        "the last carrier dialled is the one the call was on, not the one it failed over from",
    );
}

/// The answered path is unchanged: a call that fails over from A and is
/// answered by B still names B, and names it on the answer-time CCR-UPDATE —
/// which is also what a re-authorization firing later in the call carries,
/// since both clone the same stored `ImsChargingData`.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_answered_after_a_failover_still_names_the_carrier_that_answered() {
    let mut charged = Charged::start(vec![
        carrier("carrier-a", FIRST_CARRIER, 2),
        carrier("carrier-b", SECOND_CARRIER, 2),
    ])
    .await;

    let first = invite_to(charged.sequence.wire(), FIRST_CARRIER);
    charged
        .sequence
        .carrier_answers(FIRST_CARRIER, &first, 503, "Service Unavailable");
    let second = invite_to(charged.sequence.wire(), SECOND_CARRIER);
    charged.sequence.redialled();

    charged
        .sequence
        .carrier_answers(SECOND_CARRIER, &second, 200, "OK");

    let update = charged.ccr(CCR_UPDATE).await;
    assert_eq!(
        outgoing_trunk_group(&update).as_deref(),
        Some("carrier-b"),
        "the carrier that answered must be on every record from the answer on",
    );
}

/// The CDR has the same hole on the same calls, and it is the feed a charging
/// record is reconciled against: the answer path and the exhausted-sequence path
/// both stamp the carrier and the attempt list, the caller-cancel path did not.
/// So a call abandoned during ringing wrote a 487 record naming no carrier,
/// while the engine log for it named the carrier it was dialled to.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_call_writes_a_record_naming_the_carrier_it_was_ringing_on() {
    let records = crate::cdr::capture_auto_emitted_cdrs();
    let mut sequence = Sequence::new_call("");

    // What the INVITE path does when it creates the call actor.
    {
        let guard = sequence.invite.lock().expect("the A-leg INVITE lock");
        cdr_track_b2bua_start(
            &sequence.dispatcher.state,
            &sequence.call_id,
            &guard,
            "192.0.2.10",
            "udp",
        );
    }

    let billed = |carrier_id: &str, address: &str| crate::lcr::Route {
        cdr_fields: std::collections::HashMap::from([(
            "carrier_id".to_string(),
            carrier_id.to_string(),
        )]),
        ..carrier(carrier_id, address, 2)
    };
    sequence.start_routes(
        vec![
            billed("carrier-a", FIRST_CARRIER),
            billed("carrier-b", SECOND_CARRIER),
        ],
        5,
    );

    // carrier-a fails, carrier-b is dialled, and the caller gives up on it.
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 503, "Service Unavailable");
    let _ = invite_to(sequence.wire(), SECOND_CARRIER);
    sequence.redialled();
    caller_cancels(&sequence);

    let written = records.lock().expect("the capture lock").clone();
    let record = written
        .iter()
        .find(|cdr| cdr.call_id == "lcr-policy@192.0.2.10" && cdr.response_code == 487)
        .unwrap_or_else(|| panic!("no 487 record was written, got {written:?}"));

    assert_eq!(
        record.extra.get("carrier_id").map(String::as_str),
        Some("carrier-b"),
        "the record must name the carrier the call was ringing on when it was abandoned",
    );
    // `elapsed_ms` is wall-clock, so the attempt list is matched on its
    // identifying fields rather than byte-for-byte.
    let attempts = record
        .extra
        .get("lcr_attempts")
        .map(String::as_str)
        .unwrap_or_default();
    assert!(
        attempts.contains(r#""carrier_id":"carrier-a""#)
            && attempts.contains(r#""status":503"#)
            && attempts.contains(r#""dialed":true"#),
        "and the carrier it burned on the way there, got {attempts:?}",
    );
}

/// The honest null, unchanged: a sequence whose every carrier is unroutable put
/// no INVITE on the wire, so the call was on no carrier and the record names
/// none. A stamp placed before the "did it send" check would have invented one.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_that_never_reached_a_carrier_names_none() {
    let unroutable = |carrier_id: &str| crate::lcr::Route {
        carrier_id: carrier_id.to_string(),
        gateway_group: Some("a-group-siphon-does-not-know".to_string()),
        ..Default::default()
    };
    let charged = Charged::start(vec![unroutable("carrier-a"), unroutable("carrier-b")]).await;
    assert!(
        charged.sequence.wire().is_empty(),
        "an unroutable sequence sends no INVITE",
    );

    caller_cancels(&charged.sequence);

    let terminate = charged.ccr(CCR_TERMINATION).await;
    assert_eq!(
        outgoing_trunk_group(&terminate),
        None,
        "no carrier ever saw this call, so the record must name none",
    );
}
