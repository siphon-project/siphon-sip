//! The protected-port rotation, the SA-set bookkeeping on its own, and the
//! protected REGISTER read the way siphon's own P-CSCF and S-CSCF read it.

use super::*;
use crate::registrant::test_support::{self, impu, ue};

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an IP literal")
}

#[test]
fn the_client_ports_rotate_above_the_configured_pair() {
    assert_eq!(protected_client_ports(6100, 6101), [6100, 6102, 6103]);
    assert_eq!(protected_client_ports(6101, 6100), [6101, 6102, 6103]);
    assert_eq!(protected_client_ports(5064, 5066), [5064, 5067, 5068]);
    // No room above: below the lower one instead.
    assert_eq!(protected_client_ports(65534, 65535), [65534, 65533, 65532]);
}

#[test]
fn protected_ports_must_avoid_the_sip_ports_and_each_other() {
    assert_eq!(protected_ports_problem(6100, 6101), None);
    assert!(protected_ports_problem(5058, 5059).is_some_and(|problem| problem.contains("5060")));
    assert!(protected_ports_problem(6100, 6100).is_some_and(|problem| problem.contains("repeat")));
    assert!(protected_ports_problem(0, 6101).is_some());
}

#[test]
fn an_entry_whose_ports_reach_the_sip_ports_is_refused() {
    let manager = test_support::manager();
    let mut entry = ue(1, Some(ip("192.0.2.77")));
    entry.ue_ipsec = Some(UeIpsec::new(
        5058,
        5059,
        IntegrityAlgorithm::HmacSha1,
        EncryptionAlgorithm::Null,
    ));
    let refused = manager.try_add(entry).expect_err("refused");
    assert!(refused.contains("5060"), "{refused}");
    assert!(manager.is_empty());
}

#[test]
fn two_ues_on_one_address_may_not_share_a_rotated_port() {
    let manager = test_support::manager();
    manager
        .try_add(ue(1, Some(ip("192.0.2.77"))))
        .expect("added");
    // 6102/6103 are the first UE's rotation ports.
    let mut second = ue(2, Some(ip("192.0.2.77")));
    second.ue_ipsec = Some(UeIpsec::new(
        6103,
        6104,
        IntegrityAlgorithm::HmacSha1,
        EncryptionAlgorithm::Null,
    ));
    let refused = manager.try_add(second).expect_err("refused");
    assert!(refused.contains("overlaps"), "{refused}");
    // Disjoint ports on the same address are another UE.
    let mut third = ue(3, Some(ip("192.0.2.77")));
    third.ue_ipsec = Some(UeIpsec::new(
        6200,
        6201,
        IntegrityAlgorithm::HmacSha1,
        EncryptionAlgorithm::Null,
    ));
    manager.try_add(third).expect("added");
}

#[test]
fn the_socket_plan_opens_every_rotated_port_and_the_process_entries_too() {
    let manager = test_support::manager();
    manager
        .try_add(ue(1, Some(ip("192.0.2.77"))))
        .expect("added");
    manager.try_add(ue(2, None)).expect("added");
    let plan: HashMap<String, Vec<SocketAddr>> = manager
        .ue_socket_plan(5060, ip("192.0.2.1"))
        .into_iter()
        .collect();
    let own: Vec<SocketAddr> = [5060, 6100, 6102, 6103, 6101]
        .into_iter()
        .map(|port| SocketAddr::new(ip("192.0.2.77"), port))
        .collect();
    assert_eq!(plan.get(&impu(1)), Some(&own));
    let process: Vec<SocketAddr> = [6100, 6102, 6103, 6101]
        .into_iter()
        .map(|port| SocketAddr::new(ip("192.0.2.1"), port))
        .collect();
    assert_eq!(
        plan.get(&impu(2)),
        Some(&process),
        "the plain port is the configured listener's"
    );
    // Nothing for a process entry when the process address is a wildcard.
    assert!(manager
        .ue_socket_plan(5060, ip("0.0.0.0"))
        .iter()
        .all(|(aor, _)| *aor != impu(2)));
}

#[test]
fn the_sets_are_listed_oldest_first() {
    let key = |port: u16| UeSaKey {
        ue_port_c: port,
        spi_uc: u32::from(port),
        spi_us: u32::from(port) + 1,
    };
    let sets = UeSaSets {
        established: Some(EstablishedSaSet {
            key: key(6102),
            pcscf_port_s: 5066,
            security_server: String::new(),
            authorization: String::new(),
            usable: true,
        }),
        retiring: Some(key(6100)),
        temporary: Some(key(6103)),
        exchange: UeExchange::Idle,
        pending_authorization: None,
    };
    assert_eq!(sets.keys(), vec![key(6100), key(6102), key(6103)]);
    assert!(sets.usable().is_some());
    assert!(UeSaSets::default().keys().is_empty());
}

#[test]
fn a_digest_trunk_register_is_untouched() {
    let manager = test_support::manager();
    manager.add(test_support::trunk("sip:trunk@carrier.example"));
    let listen = HashMap::from([(Transport::Udp, "192.0.2.1:5060".parse().expect("addr"))]);
    let built = manager
        .build_register(
            "sip:trunk@carrier.example",
            EgressDefaults::new("192.0.2.1:5060".parse().expect("addr"), &listen),
            3600,
        )
        .expect("built");
    assert!(!built.protected);
    let headers = &built.message.headers;
    assert!(headers.get("Security-Client").is_none());
    assert!(headers.get("Security-Verify").is_none());
    assert!(headers.get("Authorization").is_none());
    assert_eq!(manager.ipsec_exchange("sip:trunk@carrier.example"), None);
    assert_eq!(manager.tracked_sa_sets(), 0);
}

/// What siphon's P-CSCF and S-CSCF make of a protected refresh: the P-CSCF
/// finds the SA set it set up for the UE by the REGISTER's source and stamps
/// `integrity-protected="yes"` because the Authorization username is the IMPI
/// that set was negotiated for, so the S-CSCF accepts it without a challenge.
#[test]
fn siphons_p_cscf_stamps_a_protected_refresh_integrity_protected() {
    let manager = test_support::manager();
    manager
        .try_add(ue(1, Some(ip("192.0.2.77"))))
        .expect("added");
    let listen = HashMap::from([(Transport::Udp, "192.0.2.1:5060".parse().expect("addr"))]);
    let defaults = EgressDefaults::new("192.0.2.1:5060".parse().expect("addr"), &listen);
    let aor = impu(1);

    // The initial registration, as the dispatcher runs it.
    manager
        .build_register(&aor, defaults, 600000)
        .expect("built");
    let challenge =
        crate::auth::parse_challenge(&test_support::aka_challenge_value("ff9bb4d0b607"))
            .expect("a challenge");
    let server = crate::ipsec::parse_security_client(test_support::SECURITY_SERVER)
        .expect("a Security-Server");
    manager.store_security_server(&aor, &server, test_support::SECURITY_SERVER);
    let verify = manager.security_server_value(&aor);
    let authenticated = manager
        .build_register_aka(&aor, defaults, &challenge, 600000, verify.as_deref())
        .expect("the authenticated REGISTER");
    let authorization = authenticated
        .message
        .headers
        .get("Authorization")
        .cloned()
        .expect("an Authorization");
    manager.begin_authentication(&aor, &authorization);
    let concluded = manager.conclude_ipsec_exchange(&aor).expect("concluded");
    manager.handle_success(&aor, 600);

    let refresh = manager
        .build_register(&aor, defaults, 600000)
        .expect("built");
    assert!(refresh.protected);
    let source = refresh.source_local_addr.expect("a source");
    assert_eq!(source.port(), concluded.established.ue_port_c);

    // The P-CSCF side of that set, keyed as its SA table keys it.
    let impi = format!("00101{:010}@{}", 1, test_support::REALM);
    let pcscf_sa = SecurityAssociationPair {
        ue_addr: source.ip(),
        pcscf_addr: ip("198.51.100.10"),
        ue_port_c: source.port(),
        ue_port_s: 6101,
        pcscf_port_c: 5064,
        pcscf_port_s: 5066,
        spi_uc: concluded.established.spi_uc,
        spi_us: concluded.established.spi_us,
        spi_pc: 55555,
        spi_ps: 66666,
        ealg: EncryptionAlgorithm::Null,
        aalg: IntegrityAlgorithm::HmacSha1,
        encryption_key: String::new(),
        integrity_key: String::new(),
        hard_lifetime_secs: None,
        protocol: SaProtocol::Any,
        expires_at: Instant::now(),
        created_at: Instant::now(),
        role: SaRole::PCscf,
        impi: Some(impi.clone()),
        security_server: Some(test_support::SECURITY_SERVER.to_string()),
    };
    let header = refresh
        .message
        .headers
        .get("Authorization")
        .cloned()
        .expect("an Authorization");
    let username = crate::script::api::ipsec::auth_header_param(&header, "username");
    assert_eq!(username.as_deref(), Some(impi.as_str()));
    assert_eq!(
        crate::script::api::ipsec::integrity_protected_for(Some(&pcscf_sa), username.as_deref()),
        "yes"
    );
    // And the Security-Verify is the Security-Server that P-CSCF sent.
    assert_eq!(
        refresh
            .message
            .headers
            .get("Security-Verify")
            .map(String::as_str),
        Some(test_support::SECURITY_SERVER)
    );
}

fn established_on(manager: &RegistrantManager, aor: &str, port: u16) {
    let mut entry = manager.entries.get_mut(aor).expect("an entry");
    let ipsec = entry.ue_ipsec.as_mut().expect("IPsec");
    ipsec.sa_sets.established = Some(EstablishedSaSet {
        key: UeSaKey {
            ue_port_c: port,
            spi_uc: 50_000,
            spi_us: 50_001,
        },
        pcscf_port_s: 5066,
        security_server: test_support::SECURITY_SERVER.to_string(),
        authorization: "Digest username=\"u\"".to_string(),
        usable: true,
    });
}

fn client_ports(manager: &RegistrantManager, aor: &str) -> [u16; 3] {
    manager
        .entries
        .get(aor)
        .and_then(|entry| entry.ue_ipsec.as_ref().map(|ipsec| ipsec.client_ports))
        .expect("IPsec")
}

/// A rotation port another socket holds no longer stalls the entry: it moves
/// to the next free port, past the other UE's on the address, and is counted.
#[test]
fn an_unbindable_rotation_port_moves_to_a_free_one() {
    let manager = test_support::manager();
    manager
        .try_add(ue(1, Some(ip("192.0.2.77"))))
        .expect("added");
    let mut second = ue(2, Some(ip("192.0.2.77")));
    second.ue_ipsec = Some(UeIpsec::new(
        6104,
        6105,
        IntegrityAlgorithm::HmacSha1,
        EncryptionAlgorithm::Null,
    ));
    manager.try_add(second).expect("added");
    crate::metrics::init().expect("metrics");
    let before = crate::metrics::ipsec::ue_port_bind_failures().expect("initialised");

    let outcome = manager.degrade_unbindable_ports(&impu(1), &[6102], 5060);

    assert_eq!(
        outcome,
        PortDegradation {
            moved: true,
            blocked: false
        }
    );
    assert_eq!(
        client_ports(&manager, &impu(1)),
        [6100, 6108, 6103],
        "past its own ports and every port of UE 2 (6104 to 6107)"
    );
    assert!(crate::metrics::ipsec::ue_port_bind_failures().expect("initialised") > before);
    // The moved port is what the socket plan asks for next.
    let plan: HashMap<String, Vec<SocketAddr>> = manager
        .ue_socket_plan(5060, ip("192.0.2.1"))
        .into_iter()
        .collect();
    assert!(plan[&impu(1)].contains(&SocketAddr::new(ip("192.0.2.77"), 6108)));
}

/// The established set's own client port will not bind: that set is taken out
/// of use, so the next REGISTER goes unprotected (TS 33.203 7.4.0) from a port
/// that binds, rather than the entry stalling.
#[test]
fn an_unbindable_established_port_falls_back_to_an_unprotected_register() {
    let manager = test_support::manager();
    manager.try_add(ue(1, None)).expect("added");
    established_on(&manager, &impu(1), 6100);

    let outcome = manager.degrade_unbindable_ports(&impu(1), &[6100], 5060);

    assert_eq!(
        outcome,
        PortDegradation {
            moved: false,
            blocked: false
        }
    );
    let sets = test_support::sa_sets(&manager, &impu(1));
    assert!(sets.established.is_some_and(|set| !set.usable));
    let listen = HashMap::from([(Transport::Udp, "192.0.2.1:5060".parse().expect("addr"))]);
    let built = manager
        .build_register(
            &impu(1),
            EgressDefaults::new("192.0.2.1:5060".parse().expect("addr"), &listen),
            600000,
        )
        .expect("built");
    assert!(!built.protected);
    assert!(built
        .message
        .headers
        .get("Security-Client")
        .is_some_and(|client| client.contains("port-c=6102")));
}

/// Nothing replaces the plain or protected server port: the entry sits the
/// tick out. Nor a client port once its moves are spent.
#[test]
fn an_unbindable_server_port_or_spent_moves_block_the_entry() {
    let manager = test_support::manager();
    manager
        .try_add(ue(1, Some(ip("192.0.2.77"))))
        .expect("added");
    assert!(
        manager
            .degrade_unbindable_ports(&impu(1), &[6101], 5060)
            .blocked
    );
    assert!(
        manager
            .degrade_unbindable_ports(&impu(1), &[5060], 5060)
            .blocked
    );

    let mut rounds = 0;
    loop {
        let ports = client_ports(&manager, &impu(1));
        let outcome = manager.degrade_unbindable_ports(&impu(1), &ports, 5060);
        if !outcome.moved {
            assert!(outcome.blocked, "out of moves, nothing left to offer");
            break;
        }
        rounds += 1;
        assert!(rounds <= MAX_PORT_REPLACEMENTS, "the moves are bounded");
    }
    // A trunk without IPsec: any failure is its plain port.
    manager
        .try_add(test_support::trunk("sip:t@carrier.example").with_local_addr(ip("192.0.2.90")))
        .expect("added");
    assert!(
        manager
            .degrade_unbindable_ports("sip:t@carrier.example", &[5060], 5060)
            .blocked
    );
}

/// TS 33.203 7.1: "The UE shall select the SPIs uniquely, and different from
/// any SPIs that might be used in any existing SAs". The counter restarts at
/// its base every boot, so the kernel's states at start, a previous process's
/// among them, are skipped, as are the SPIs of the sets the UE holds.
#[test]
fn an_offer_never_reuses_an_spi_an_existing_sa_uses() {
    let manager = test_support::manager();
    manager.note_kernel_spis(50_000..50_010);
    let (spi_uc, spi_us) = manager.allocate_unique_ue_spi_pair(&HashSet::new());
    assert!(spi_uc >= 50_010, "{spi_uc}");
    assert_eq!(spi_us, spi_uc + 1);
    let avoid: HashSet<u32> = [spi_uc + 2, spi_uc + 5].into_iter().collect();
    let (next_uc, next_us) = manager.allocate_unique_ue_spi_pair(&avoid);
    assert!(!avoid.contains(&next_uc) && !avoid.contains(&next_us));

    let manager = test_support::manager();
    manager.note_kernel_spis([50_000, 50_001]);
    manager
        .try_add(ue(1, Some(ip("192.0.2.77"))))
        .expect("added");
    let listen = HashMap::from([(Transport::Udp, "192.0.2.1:5060".parse().expect("addr"))]);
    let built = manager
        .build_register(
            &impu(1),
            EgressDefaults::new("192.0.2.1:5060".parse().expect("addr"), &listen),
            600000,
        )
        .expect("built");
    let client = built
        .message
        .headers
        .get("Security-Client")
        .cloned()
        .expect("a Security-Client");
    assert!(
        !client.contains("spi-c=50000;") && !client.contains("spi-s=50001;"),
        "{client}"
    );
}
