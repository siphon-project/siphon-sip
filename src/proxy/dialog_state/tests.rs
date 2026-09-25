use super::*;
use crate::b2bua::actor::DialogDirection;

const CALL_ID: &str = "proxied@192.0.2.21";

fn hop(address: &str) -> Hop {
    Hop {
        destination: address.parse().expect("a literal address"),
        transport: Transport::Udp,
        connection_id: ConnectionId::default(),
        local_addr: None,
    }
}

fn key() -> DialogKey {
    (CALL_ID.to_string(), "caller-tag".to_string())
}

fn watch(aor: &str, direction: DialogDirection, leg: &str) -> DialogWatch {
    DialogWatch {
        leg_id: leg.to_string(),
        aor: aor.to_string(),
        direction,
        call_id: CALL_ID.to_string(),
        local_tag: (direction == DialogDirection::Initiator).then(|| "caller-tag".to_string()),
        remote_tag: (direction == DialogDirection::Recipient).then(|| "caller-tag".to_string()),
        remote_uri: "sip:peer@example.com".to_string(),
        remote_display_name: None,
        state: if direction == DialogDirection::Initiator {
            DialogState::Proceeding
        } else {
            DialogState::Trying
        },
        contact: Some(format!("{aor}-contact")),
    }
}

fn config() -> DialogStateConfig {
    DialogStateConfig {
        probe_interval_secs: 60,
        probe_timeout_secs: 1,
        probe_failures: 2,
        max_early_secs: 300,
        max_lifetime_secs: 3600,
        session_timer_grace_secs: 32,
    }
}

/// A caller watched as `sip:201`, forked to `sip:202` (watched) and an
/// unregistered branch.
fn forked(store: &ProxyDialogStore, now: Instant) -> Vec<DialogWatch> {
    let mut reports = store.begin(
        NewDialog {
            call_id: CALL_ID.to_string(),
            caller_tag: "caller-tag".to_string(),
            caller: Some(watch("sip:201", DialogDirection::Initiator, "leg-caller")),
            caller_hop: hop("192.0.2.21:5060"),
            caller_contact: Some("sip:201@192.0.2.21:5060".to_string()),
            from: "<sip:201@example.com>;tag=caller-tag".to_string(),
            to: "<sip:202@example.com>".to_string(),
            invite_cseq: 7,
            route_to_caller: vec!["<sip:upstream.example.com;lr>".to_string()],
        },
        now,
    );
    reports.extend(store.add_branch(
        &key(),
        NewBranch {
            via_branch: "z9hG4bK-b1".to_string(),
            watch: Some(watch("sip:202", DialogDirection::Recipient, "leg-202")),
            hop: hop("198.51.100.22:5060"),
            own_record_routes: 1,
        },
    ));
    reports.extend(store.add_branch(
        &key(),
        NewBranch {
            via_branch: "z9hG4bK-b2".to_string(),
            watch: None,
            hop: hop("198.51.100.7:5060"),
            own_record_routes: 1,
        },
    ));
    reports
}

fn summary(reports: &[DialogWatch]) -> Vec<String> {
    reports
        .iter()
        .map(|report| format!("{} {}", report.aor, report.state.as_str()))
        .collect()
}

fn answer(
    store: &ProxyDialogStore,
    now: Instant,
    session_expires: Option<u64>,
) -> Vec<DialogWatch> {
    let mut reports = store.branch_response(
        "z9hG4bK-b1",
        200,
        Some("callee-tag"),
        Some(Answer {
            contact: Some("sip:202@198.51.100.22:5060".to_string()),
            record_routes: vec![
                "<sip:downstream.example.com;lr>".to_string(),
                "<sip:192.0.2.1;lr>".to_string(),
                "<sip:upstream.example.com;lr>".to_string(),
            ],
            session_expires,
        }),
        now,
        &config(),
    );
    reports.extend(store.upstream_response(&key(), 200, Some("callee-tag")));
    reports.extend(store.branches_cancelled(&key(), Some("z9hG4bK-b1")));
    reports.extend(store.settle(&key()));
    reports
}

#[test]
fn a_fork_reports_each_watched_party_and_a_bye_ends_both() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    assert_eq!(
        summary(&forked(&store, now)),
        ["sip:201 proceeding", "sip:202 trying"]
    );
    let mut reports =
        store.branch_response("z9hG4bK-b1", 180, Some("callee-tag"), None, now, &config());
    reports.extend(store.upstream_response(&key(), 180, Some("callee-tag")));
    assert_eq!(summary(&reports), ["sip:202 early", "sip:201 early"]);
    assert_eq!(reports[0].local_tag.as_deref(), Some("callee-tag"));
    assert_eq!(reports[1].remote_tag.as_deref(), Some("callee-tag"));

    assert_eq!(
        summary(&answer(&store, now, None)),
        ["sip:202 confirmed", "sip:201 confirmed"]
    );

    // A BYE from the callee: its From-tag is the callee's.
    let reports =
        store.in_dialog_request(CALL_ID, "callee-tag", "caller-tag", "BYE", Some(1), None);
    assert_eq!(
        summary(&reports),
        ["sip:201 terminated", "sip:202 terminated"]
    );
    assert!(store.is_empty(), "nothing watched is left");
    assert_eq!(store.branch_index_len(), 0);
}

#[test]
fn a_bye_from_the_caller_ends_the_dialog_too() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    forked(&store, now);
    answer(&store, now, None);
    let reports =
        store.in_dialog_request(CALL_ID, "caller-tag", "callee-tag", "BYE", Some(8), None);
    assert_eq!(
        summary(&reports),
        ["sip:201 terminated", "sip:202 terminated"]
    );
    // A BYE naming another to-tag belongs to no dialog siphon reported.
    assert!(store.is_empty());
}

#[test]
fn a_failed_branch_ends_alone_and_the_caller_ends_with_the_last_branch() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    forked(&store, now);
    let reports =
        store.branch_response("z9hG4bK-b1", 486, Some("callee-tag"), None, now, &config());
    assert_eq!(summary(&reports), ["sip:202 terminated"]);
    assert!(
        store.settle(&key()).is_empty(),
        "the other branch still rings"
    );
    store.branch_response("z9hG4bK-b2", 404, Some("other"), None, now, &config());
    assert_eq!(summary(&store.settle(&key())), ["sip:201 terminated"]);
    assert!(store.is_empty());
}

#[test]
fn a_cancel_ends_every_watch() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    forked(&store, now);
    assert_eq!(
        summary(&store.end_invite(&key())),
        ["sip:201 terminated", "sip:202 terminated"]
    );
    assert!(store.is_empty());
}

#[test]
fn the_losers_of_a_fork_end_when_one_answers() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    forked(&store, now);
    // The unregistered branch answers; the registered one was CANCELled.
    let mut reports = store.branch_response(
        "z9hG4bK-b2",
        200,
        Some("trunk-tag"),
        Some(Answer::default()),
        now,
        &config(),
    );
    reports.extend(store.upstream_response(&key(), 200, Some("trunk-tag")));
    reports.extend(store.branches_cancelled(&key(), Some("z9hG4bK-b2")));
    assert_eq!(
        summary(&reports),
        ["sip:201 confirmed", "sip:202 terminated"]
    );
}

#[test]
fn the_route_to_each_end_comes_from_the_record_route_sets() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    forked(&store, now);
    answer(&store, now, None);
    let (_, probes) = store.sweep(now + Duration::from_secs(61), &config(), &|_, _| true);
    assert_eq!(probes.len(), 2);
    let to_caller = probes
        .iter()
        .find(|probe| probe.end == End::Caller)
        .expect("caller probe");
    assert_eq!(to_caller.request_uri, "sip:201@192.0.2.21:5060");
    assert_eq!(to_caller.route, ["<sip:upstream.example.com;lr>"]);
    assert_eq!(to_caller.from, "<sip:202@example.com>;tag=callee-tag");
    assert_eq!(to_caller.to, "<sip:201@example.com>;tag=caller-tag");
    assert_eq!(to_caller.cseq, 0, "the callee has sent nothing yet");
    assert_eq!(to_caller.hop, hop("192.0.2.21:5060"));
    let to_callee = probes
        .iter()
        .find(|probe| probe.end == End::Callee)
        .expect("callee probe");
    assert_eq!(to_callee.request_uri, "sip:202@198.51.100.22:5060");
    assert_eq!(to_callee.route, ["<sip:downstream.example.com;lr>"]);
    assert_eq!(to_callee.cseq, 7, "the INVITE's CSeq, not one past it");
    assert_eq!(to_callee.hop, hop("198.51.100.22:5060"));

    // No second probe while one is out.
    let (_, probes) = store.sweep(now + Duration::from_secs(200), &config(), &|_, _| true);
    assert!(probes.is_empty());
}

#[test]
fn a_probe_reuses_the_last_cseq_each_side_sent() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    forked(&store, now);
    answer(&store, now, None);
    store.in_dialog_request(CALL_ID, "caller-tag", "callee-tag", "INFO", Some(9), None);
    store.in_dialog_request(
        CALL_ID,
        "callee-tag",
        "caller-tag",
        "INVITE",
        Some(3),
        Some("sip:202@198.51.100.99:5070".to_string()),
    );
    let (_, probes) = store.sweep(now + Duration::from_secs(61), &config(), &|_, _| true);
    let cseq_of = |end: End| {
        probes
            .iter()
            .find(|probe| probe.end == end)
            .map(|probe| probe.cseq)
    };
    assert_eq!(cseq_of(End::Callee), Some(9));
    assert_eq!(cseq_of(End::Caller), Some(3));
    let refreshed = probes
        .iter()
        .find(|probe| probe.end == End::Callee)
        .expect("probe");
    assert_eq!(refreshed.request_uri, "sip:202@198.51.100.99:5070");
}

#[test]
fn a_481_ends_that_end_only_and_unanswered_probes_end_it_after_the_limit() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    forked(&store, now);
    answer(&store, now, None);
    store.sweep(now + Duration::from_secs(61), &config(), &|_, _| true);
    assert_eq!(
        summary(&store.probe_result(&key(), End::Callee, ProbeOutcome::Gone, &config())),
        ["sip:202 terminated"]
    );
    assert!(store
        .probe_result(&key(), End::Caller, ProbeOutcome::Unanswered, &config())
        .is_empty());
    store.sweep(now + Duration::from_secs(122), &config(), &|_, _| true);
    assert_eq!(
        summary(&store.probe_result(&key(), End::Caller, ProbeOutcome::Unanswered, &config())),
        ["sip:201 terminated"]
    );
    assert!(store.is_empty());
}

#[test]
fn an_answered_probe_resets_the_count() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    forked(&store, now);
    answer(&store, now, None);
    for round in 1..=4u64 {
        store.sweep(now + Duration::from_secs(61 * round), &config(), &|_, _| {
            true
        });
        let outcome = if round % 2 == 1 {
            ProbeOutcome::Unanswered
        } else {
            ProbeOutcome::Alive
        };
        assert!(store
            .probe_result(&key(), End::Caller, outcome, &config())
            .is_empty());
    }
    assert!(!store.is_empty());
}

#[test]
fn an_expired_session_interval_ends_the_dialog_and_a_refresh_extends_it() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    forked(&store, now);
    answer(&store, now, Some(90));
    let (reports, _) = store.sweep(now + Duration::from_secs(100), &config(), &|_, _| true);
    assert!(reports.is_empty(), "inside the grace");
    store.in_dialog_refreshed(
        CALL_ID,
        "caller-tag",
        "callee-tag",
        Some(120),
        now + Duration::from_secs(100),
    );
    let (reports, _) = store.sweep(now + Duration::from_secs(240), &config(), &|_, _| true);
    assert!(
        reports.is_empty(),
        "refreshed at 100 s for 120 s + 32 s grace"
    );
    let (reports, _) = store.sweep(now + Duration::from_secs(253), &config(), &|_, _| true);
    assert_eq!(
        summary(&reports),
        ["sip:201 terminated", "sip:202 terminated"]
    );
    assert!(store.is_empty());
}

#[test]
fn a_binding_that_is_gone_ends_that_phones_dialog() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    forked(&store, now);
    answer(&store, now, None);
    let (reports, _) = store.sweep(now, &config(), &|aor, _| aor != "sip:202");
    assert_eq!(summary(&reports), ["sip:202 terminated"]);
    let (reports, _) = store.sweep(now, &config(), &|_, _| false);
    assert_eq!(summary(&reports), ["sip:201 terminated"]);
    assert!(store.is_empty());
}

#[test]
fn ringing_past_the_bound_and_the_hard_lifetime_end_everything() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    forked(&store, now);
    let (reports, _) = store.sweep(now + Duration::from_secs(299), &config(), &|_, _| true);
    assert!(reports.is_empty());
    let (reports, _) = store.sweep(now + Duration::from_secs(300), &config(), &|_, _| true);
    assert_eq!(
        summary(&reports),
        ["sip:201 terminated", "sip:202 terminated"]
    );

    let store = ProxyDialogStore::new();
    forked(&store, now);
    answer(&store, now, None);
    let mut quiet = config();
    quiet.probe_interval_secs = 0;
    let (reports, probes) = store.sweep(now + Duration::from_secs(3599), &quiet, &|_, _| true);
    assert!(reports.is_empty() && probes.is_empty());
    let (reports, _) = store.sweep(now + Duration::from_secs(3600), &quiet, &|_, _| true);
    assert_eq!(
        summary(&reports),
        ["sip:201 terminated", "sip:202 terminated"]
    );
    assert!(store.is_empty());
}

/// Steady state: complete dialogs, however they end, leave nothing behind.
#[test]
fn the_store_drains_to_baseline() {
    let store = ProxyDialogStore::new();
    let now = Instant::now();
    for round in 0..200u64 {
        forked(&store, now);
        answer(&store, now, Some(90));
        match round % 4 {
            0 => {
                store.in_dialog_request(CALL_ID, "caller-tag", "callee-tag", "BYE", Some(8), None);
            }
            1 => {
                store.sweep(now + Duration::from_secs(61), &config(), &|_, _| true);
                store.probe_result(&key(), End::Caller, ProbeOutcome::Gone, &config());
                store.probe_result(&key(), End::Callee, ProbeOutcome::Gone, &config());
            }
            2 => {
                store.sweep(now, &config(), &|_, _| false);
            }
            _ => {
                store.sweep(now + Duration::from_secs(200), &config(), &|_, _| true);
            }
        }
        assert_eq!(store.len(), 0, "round {round}");
        assert_eq!(store.branch_index_len(), 0, "round {round}");
    }
}

#[test]
fn session_expires_values_parse() {
    assert_eq!(session_expires_secs("1800;refresher=uac"), Some(1800));
    assert_eq!(session_expires_secs(" 90 "), Some(90));
    assert_eq!(session_expires_secs("soon"), None);
}
