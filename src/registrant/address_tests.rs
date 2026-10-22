use super::*;
use crate::registrant::test_support::{self, impu, trunk, ue};
use crate::registrant::EgressDefaults;
use std::collections::HashMap;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an IP literal")
}

fn listeners() -> HashMap<Transport, SocketAddr> {
    HashMap::from([(Transport::Udp, "203.0.113.5:5070".parse().expect("addr"))])
}

/// Branch, Call-ID and tags are random per message; everything else is pinned.
fn normalised(manager: &RegistrantManager, aor: &str, raw: &str) -> String {
    let call_id = manager
        .entries
        .get(aor)
        .map(|entry| entry.call_id.clone())
        .expect("entry");
    let mut out = raw.replace(&call_id, "CALL-ID");
    if let Some(start) = out.find("branch=z9hG4bK-reg-") {
        let end = out[start..]
            .find(';')
            .map_or(out.len(), |offset| start + offset);
        out.replace_range(start..end, "branch=BRANCH");
    }
    out
}

/// Golden: an entry without a `local_addr` builds byte for byte what it did
/// before per-entry addresses, and is pinned to the same UDP source.
#[test]
fn an_entry_without_an_address_registers_exactly_as_before() {
    let manager = test_support::manager();
    manager.add(trunk("sip:trunk@carrier.example"));
    let listen = listeners();
    let built = manager
        .build_register(
            "sip:trunk@carrier.example",
            EgressDefaults::new("203.0.113.5:5060".parse().expect("addr"), &listen),
            3600,
        )
        .expect("built");
    let raw = String::from_utf8_lossy(&built.message.to_bytes()).into_owned();
    assert_eq!(
        normalised(&manager, "sip:trunk@carrier.example", &raw),
        concat!(
            "REGISTER sip:198.51.100.10:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 203.0.113.5:5070;branch=BRANCH;rport\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:trunk@carrier.example>;tag=reg-1\r\n",
            "To: <sip:trunk@carrier.example>\r\n",
            "Call-ID: CALL-ID\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Contact: <sip:trunk@203.0.113.5:5070>\r\n",
            "Expires: 3600\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
    );
    assert_eq!(
        built.source_local_addr,
        Some("203.0.113.5:5070".parse().expect("addr"))
    );
    assert_eq!(built.sent_by, "203.0.113.5:5070".parse().expect("addr"));
    assert!(!built.own_address);
}

#[test]
fn an_entry_with_an_address_names_and_leaves_from_it() {
    let manager = test_support::manager();
    manager.add(trunk("sip:trunk@carrier.example").with_local_addr(ip("192.0.2.77")));
    let listen = listeners();
    let built = manager
        .build_register(
            "sip:trunk@carrier.example",
            EgressDefaults::new("203.0.113.5:5060".parse().expect("addr"), &listen),
            3600,
        )
        .expect("built");
    let raw = String::from_utf8_lossy(&built.message.to_bytes()).into_owned();
    assert!(raw.contains("Via: SIP/2.0/UDP 192.0.2.77:5070;"), "{raw}");
    assert!(
        raw.contains("Contact: <sip:trunk@192.0.2.77:5070>"),
        "{raw}"
    );
    assert!(
        !raw.contains("203.0.113.5"),
        "the process address leaked: {raw}"
    );
    let own: SocketAddr = "192.0.2.77:5070".parse().expect("addr");
    assert_eq!(built.source_local_addr, Some(own));
    assert_eq!(built.sent_by, own);
    assert!(built.own_address);
}

#[test]
fn the_plain_port_defaults_to_5060_without_a_udp_listener() {
    let manager = test_support::manager();
    manager.add(trunk("sip:trunk@carrier.example").with_local_addr(ip("192.0.2.77")));
    let built = manager
        .build_register(
            "sip:trunk@carrier.example",
            EgressDefaults::new("203.0.113.5:5080".parse().expect("addr"), &HashMap::new()),
            3600,
        )
        .expect("built");
    assert_eq!(
        built.source_local_addr,
        Some("192.0.2.77:5060".parse().expect("addr"))
    );
}

#[test]
fn every_ue_registers_from_its_own_address_with_repeated_protected_ports() {
    let manager = test_support::manager();
    let listen = listeners();
    let defaults = EgressDefaults::new("203.0.113.5:5060".parse().expect("addr"), &listen);
    for index in 1..=3 {
        manager
            .try_add(ue(index, Some(ip(&format!("192.0.2.{}", 10 + index)))))
            .expect("distinct addresses, same ports");
    }
    for index in 1..=3 {
        let built = manager
            .build_register(&impu(index), defaults, 600000)
            .expect("built");
        let raw = String::from_utf8_lossy(&built.message.to_bytes()).into_owned();
        let own = format!("192.0.2.{}", 10 + index);
        assert!(
            raw.contains(&format!("Via: SIP/2.0/UDP {own}:5070;")),
            "{raw}"
        );
        assert!(
            raw.contains("port-c=6100") && raw.contains("port-s=6101"),
            "{raw}"
        );
        assert_eq!(
            built.source_local_addr,
            Some(SocketAddr::new(ip(&own), 5070))
        );
    }
    let plan = manager.ue_socket_plan(5070);
    assert_eq!(plan.len(), 3);
    for (_, addrs) in plan {
        let ports: Vec<u16> = addrs.iter().map(|addr| addr.port()).collect();
        assert_eq!(ports, [5070, 6100, 6101]);
    }
}

#[test]
fn the_de_register_of_each_entry_leaves_from_its_own_address() {
    let manager = test_support::manager();
    manager.add(trunk("sip:a@carrier.example").with_local_addr(ip("192.0.2.21")));
    manager.add(trunk("sip:b@carrier.example"));
    manager.handle_success("sip:a@carrier.example", 3600);
    manager.handle_success("sip:b@carrier.example", 3600);
    let listen = listeners();
    let deregistrations = manager.build_deregistrations(EgressDefaults::new(
        "203.0.113.5:5060".parse().expect("addr"),
        &listen,
    ));
    let mut sources: Vec<Option<SocketAddr>> = deregistrations
        .iter()
        .map(|built| built.source_local_addr)
        .collect();
    sources.sort();
    assert_eq!(
        sources,
        [
            Some("192.0.2.21:5070".parse().expect("addr")),
            Some("203.0.113.5:5070".parse().expect("addr")),
        ]
    );
    assert!(deregistrations
        .iter()
        .all(|built| String::from_utf8_lossy(&built.message.to_bytes()).contains("Expires: 0")));
}

#[test]
fn two_entries_may_not_share_an_address_and_protected_port() {
    let manager = test_support::manager();
    manager
        .try_add(ue(1, Some(ip("192.0.2.11"))))
        .expect("first");
    let refused = manager
        .try_add(ue(2, Some(ip("192.0.2.11"))))
        .expect_err("same address and ue_port_c");
    assert!(refused.contains(&impu(1)), "{refused}");
    assert_eq!(manager.len(), 1);
    // Re-adding the same AoR replaces it.
    manager
        .try_add(ue(1, Some(ip("192.0.2.11"))))
        .expect("replace");
    // add() refuses the same way, logging instead of returning.
    manager.add(ue(3, Some(ip("192.0.2.11"))));
    assert_eq!(manager.len(), 1);
    // Two plain entries on one address collide too.
    manager
        .try_add(trunk("sip:a@carrier.example").with_local_addr(ip("192.0.2.30")))
        .expect("first plain");
    assert!(manager
        .try_add(trunk("sip:b@carrier.example").with_local_addr(ip("192.0.2.30")))
        .is_err());
}

#[test]
fn an_address_needs_udp() {
    let manager = test_support::manager();
    let mut entry = trunk("sip:trunk@carrier.example").with_local_addr(ip("192.0.2.77"));
    entry.transport = Transport::Tls;
    assert!(manager.try_add(entry).expect_err("refused").contains("udp"));

    let mut stream = trunk("sip:stream@carrier.example");
    stream.transport = Transport::Tcp;
    manager.add(stream);
    assert!(manager
        .set_local_addr("sip:stream@carrier.example", Some(ip("192.0.2.78")))
        .is_err());
}

#[test]
fn an_entry_requiring_an_address_waits_without_one() {
    let manager = test_support::manager();
    let mut events = manager.subscribe_events();
    manager
        .try_add(ue(1, None).requiring_local_addr())
        .expect("added");
    assert_eq!(
        manager.state(&impu(1)),
        Some(RegistrantState::AwaitingAddress)
    );
    assert!(manager
        .entries_due_at(Instant::now() + std::time::Duration::from_secs(3600))
        .is_empty());
    assert!(matches!(
        events.try_recv(),
        Ok(RegistrantEvent::AwaitingAddress { aor }) if aor == impu(1)
    ));
    assert_eq!(manager.counts()["awaiting_address"], 1);
}

#[test]
fn moving_an_entry_queues_its_old_sas_and_starts_over() {
    let manager = test_support::manager();
    manager
        .try_add(ue(1, Some(ip("192.0.2.11"))))
        .expect("added");
    // A handshake in progress and a grant.
    let listen = listeners();
    let defaults = EgressDefaults::new("203.0.113.5:5060".parse().expect("addr"), &listen);
    manager
        .build_register(&impu(1), defaults, 600000)
        .expect("built");
    let server = crate::ipsec::parse_security_client(test_support::SECURITY_SERVER).expect("parse");
    manager.store_security_server(&impu(1), &server, test_support::SECURITY_SERVER);
    manager.store_registration_routes(
        &impu(1),
        vec!["<sip:scscf>".to_string()],
        Vec::new(),
        Vec::new(),
    );
    manager.handle_success(&impu(1), 600000);

    // Restating the address is a no-op.
    assert_eq!(
        manager.set_local_addr(&impu(1), Some(ip("192.0.2.11"))),
        Ok(true)
    );
    assert_eq!(manager.state(&impu(1)), Some(RegistrantState::Registered));
    assert!(manager.take_pending_sa_deletions().is_empty());

    assert_eq!(
        manager.set_local_addr(&impu(1), Some(ip("192.0.2.12"))),
        Ok(true)
    );
    assert_eq!(
        manager.take_pending_sa_deletions(),
        [(Some(ip("192.0.2.11")), 6100)]
    );
    assert_eq!(manager.state(&impu(1)), Some(RegistrantState::Unregistered));
    assert_eq!(manager.ue_addr(&impu(1)), Some(ip("192.0.2.12")));
    assert!(manager.service_route(&impu(1)).is_empty());
    assert!(manager.security_server_value(&impu(1)).is_none());
    assert!(manager.ue_flow_components(&impu(1)).is_none());
    assert_eq!(manager.entries_due(), [impu(1)]);

    // Taken away: it had an address, so it waits rather than falling back.
    let mut events = manager.subscribe_events();
    assert_eq!(manager.set_local_addr(&impu(1), None), Ok(true));
    assert_eq!(
        manager.state(&impu(1)),
        Some(RegistrantState::AwaitingAddress)
    );
    assert_eq!(
        manager.take_pending_sa_deletions(),
        [(Some(ip("192.0.2.12")), 6100)]
    );
    assert!(matches!(
        events.try_recv(),
        Ok(RegistrantEvent::AwaitingAddress { .. })
    ));

    assert_eq!(
        manager.set_local_addr("sip:nobody@example.invalid", None),
        Ok(false)
    );
}

#[test]
fn a_process_address_entry_set_to_none_stays_on_the_process_address() {
    let manager = test_support::manager();
    manager.add(trunk("sip:trunk@carrier.example"));
    assert_eq!(
        manager.set_local_addr("sip:trunk@carrier.example", None),
        Ok(true)
    );
    assert_eq!(
        manager.state("sip:trunk@carrier.example"),
        Some(RegistrantState::Unregistered)
    );
}

#[test]
fn moving_onto_a_held_address_is_refused() {
    let manager = test_support::manager();
    manager
        .try_add(ue(1, Some(ip("192.0.2.11"))))
        .expect("first");
    manager
        .try_add(ue(2, Some(ip("192.0.2.12"))))
        .expect("second");
    assert!(manager
        .set_local_addr(&impu(2), Some(ip("192.0.2.11")))
        .is_err());
    assert_eq!(manager.ue_addr(&impu(2)), Some(ip("192.0.2.12")));
}

#[test]
fn find_by_local_matches_the_address_and_its_ports() {
    let manager = test_support::manager();
    manager
        .try_add(ue(1, Some(ip("192.0.2.11"))))
        .expect("added");
    manager
        .try_add(ue(2, Some(ip("192.0.2.12"))))
        .expect("added");
    manager.add(trunk("sip:trunk@carrier.example"));
    let find = |text: &str| manager.find_by_local(LocalAddrQuery::parse(text).expect("parses"));
    assert_eq!(find("192.0.2.12"), Some(impu(2)));
    assert_eq!(find("192.0.2.12:6101"), Some(impu(2)));
    assert_eq!(find("192.0.2.12:6100"), Some(impu(2)));
    assert_eq!(find("192.0.2.11:5060"), Some(impu(1)));
    assert_eq!(find("192.0.2.11:7000"), None);
    assert_eq!(find("192.0.2.99"), None);
    assert!(LocalAddrQuery::parse("not-an-address").is_err());
    assert_eq!(
        LocalAddrQuery::parse("[2001:db8::1]:6101"),
        Ok(LocalAddrQuery::Socket(
            "[2001:db8::1]:6101".parse().expect("addr")
        ))
    );
    assert_eq!(
        LocalAddrQuery::parse("2001:db8::1"),
        Ok(LocalAddrQuery::Ip(ip("2001:db8::1")))
    );
}

#[test]
fn counts_name_every_state() {
    let manager = test_support::manager();
    manager.add(trunk("sip:a@carrier.example"));
    manager.add(trunk("sip:b@carrier.example"));
    manager.handle_success("sip:a@carrier.example", 3600);
    let counts = manager.counts();
    assert_eq!(counts.len(), 6);
    assert_eq!(counts["registered"], 1);
    assert_eq!(counts["unregistered"], 1);
    assert_eq!(counts["awaiting_address"], 0);
    assert_eq!(
        RegistrantState::AwaitingAddress.to_string(),
        "awaiting_address"
    );
}

#[test]
fn the_refresh_lands_where_the_window_draw_says() {
    let manager = test_support::manager()
        .with_refresh_window(crate::registrant::RefreshWindow::new(0.2, 0.6).expect("window"));
    manager.add(trunk("sip:a@carrier.example"));
    manager.add(
        trunk("sip:b@carrier.example")
            .with_refresh_window(crate::registrant::RefreshWindow::new(0.9, 0.9).expect("window")),
    );
    let before = Instant::now();
    manager.handle_success_with_draw("sip:a@carrier.example", 1000, 0.5);
    manager.handle_success_with_draw("sip:b@carrier.example", 1000, 0.5);
    let next = |aor: &str| {
        manager
            .entries
            .get(aor)
            .map(|entry| entry.next_attempt.duration_since(before).as_secs())
            .expect("entry")
    };
    assert!((400..=401).contains(&next("sip:a@carrier.example")));
    assert!(
        (900..=901).contains(&next("sip:b@carrier.example")),
        "the entry window wins"
    );
}

#[test]
fn due_entries_come_longest_overdue_first() {
    let manager = test_support::manager();
    let now = Instant::now();
    for (index, age) in [(1u32, 5u64), (2, 50), (3, 20)] {
        let mut entry = trunk(&format!("sip:t{index}@carrier.example"));
        entry.next_attempt = now - std::time::Duration::from_secs(age);
        manager.add(entry);
    }
    assert_eq!(
        manager.entries_due_at(now),
        [
            "sip:t2@carrier.example",
            "sip:t3@carrier.example",
            "sip:t1@carrier.example"
        ]
    );
}

#[test]
fn spi_allocation_never_wraps_into_the_reserved_range() {
    let manager = test_support::manager();
    for start in [u32::MAX - 5, u32::MAX - 2, u32::MAX - 1, u32::MAX, 0, 7] {
        manager
            .ue_spi_counter
            .store(start, std::sync::atomic::Ordering::Relaxed);
        for _ in 0..6 {
            let (client, server) = manager.allocate_ue_spi_pair();
            assert!(
                client >= RegistrantManager::UE_SPI_BASE,
                "{client} from {start}"
            );
            assert_eq!(server, client + 1, "from {start}");
        }
    }
    manager
        .ue_spi_counter
        .store(u32::MAX - 1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(manager.allocate_ue_spi_pair(), (u32::MAX - 1, u32::MAX));
    assert_eq!(
        manager.allocate_ue_spi_pair(),
        (
            RegistrantManager::UE_SPI_BASE,
            RegistrantManager::UE_SPI_BASE + 1
        )
    );
}

#[test]
fn the_event_capacity_is_raised_but_never_lowered() {
    let manager = test_support::manager().with_event_capacity(4);
    let mut receiver = manager.subscribe_events();
    for index in 0..RegistrantManager::MIN_EVENT_CAPACITY {
        manager.emit_event(RegistrantEvent::Deregistered {
            aor: format!("sip:{index}@example.invalid"),
        });
    }
    assert!(receiver.try_recv().is_ok(), "64 held without lag");

    let manager = test_support::manager().with_event_capacity(500);
    let mut receiver = manager.subscribe_events();
    for index in 0..500 {
        manager.emit_event(RegistrantEvent::Deregistered {
            aor: format!("sip:{index}@example.invalid"),
        });
    }
    assert!(receiver.try_recv().is_ok(), "500 held without lag");
}

/// Store gate: entries added and moved and removed over and over leave no
/// queued SA deletion or de-registration behind once drained.
#[test]
fn adding_moving_and_removing_entries_returns_the_queues_to_baseline() {
    let manager = test_support::manager();
    for round in 0..200u32 {
        manager
            .try_add(ue(1, Some(ip("192.0.2.11"))))
            .expect("added");
        manager
            .set_local_addr(&impu(1), Some(ip(&format!("192.0.2.{}", 12 + round % 50))))
            .expect("moved");
        manager.remove(&impu(1));
        manager.take_pending_sa_deletions();
        manager.take_pending_deregistrations();
    }
    assert!(manager.is_empty());
    assert!(manager.take_pending_sa_deletions().is_empty());
    assert!(manager.ue_socket_plan(5060).is_empty());
}
