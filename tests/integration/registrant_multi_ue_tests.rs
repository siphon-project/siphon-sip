//! Many IMS UEs in one registrant, each from an address of its own, driven
//! from `siphon.yaml` through the manager to the REGISTERs handed to the
//! transport (a channel, no sockets).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use siphon::config::Config;
use siphon::registrant::address::LocalAddrQuery;
use siphon::registrant::entry_config::entry_from_config;
use siphon::registrant::{EgressDefaults, RegistrantManager, RegistrantState};
use siphon::transport::{ConnectionId, OutboundMessage, OutboundRouter, Transport};

const HOME: &str = "ims.mnc01.mcc001.3gppnetwork.org";

fn ue_yaml(count: u32) -> String {
    let mut yaml = String::from(concat!(
        "listen:\n",
        "  udp: [\"203.0.113.5:5060\"]\n",
        "domain:\n",
        "  local: [\"203.0.113.5\"]\n",
        "registrant:\n",
        "  refresh_window: [0.4, 0.6]\n",
        "  max_registers_per_sec: 20\n",
        "  entries:\n",
    ));
    for index in 1..=count {
        yaml.push_str(&format!(
            concat!(
                "    - aor: \"sip:00101{index:010}@{home}\"\n",
                "      registrar: \"sip:198.51.100.10:5060\"\n",
                "      user: \"00101{index:010}@{home}\"\n",
                "      auth: aka\n",
                "      aka:\n",
                "        k: \"465b5ce8b199b49faa5f0a2ee238a6bc\"\n",
                "        opc: \"cd63cb71954a9f4e48a5994e37a02baf\"\n",
                "      ipsec:\n",
                "        ue_port_c: 6100\n",
                "        ue_port_s: 6101\n",
                "      ims:\n",
                "        imei: \"01234567-{index:06}-0\"\n",
                "        features: [mmtel, smsip]\n",
                "      local_addr: \"192.0.2.{last}\"\n",
            ),
            index = index,
            home = HOME,
            last = 10 + index,
        ));
    }
    yaml
}

fn impu(index: u32) -> String {
    format!("sip:00101{index:010}@{HOME}")
}

fn manager_from(config: &Config) -> RegistrantManager {
    let registrant = config.registrant.as_ref().expect("a registrant block");
    let manager = RegistrantManager::new(
        registrant.default_interval,
        Duration::from_secs(registrant.retry_interval),
        Duration::from_secs(registrant.max_retry_interval),
        siphon::config::IdentityHeaders::default().shared(),
    )
    .with_max_registers_per_sec(registrant.max_registers_per_sec);
    for entry in &registrant.entries {
        manager
            .try_add(entry_from_config(entry, registrant).expect("a valid entry"))
            .expect("added");
    }
    manager
}

fn router() -> (OutboundRouter, flume::Receiver<OutboundMessage>) {
    let (udp_tx, udp_rx) = flume::unbounded();
    let (tcp, _) = flume::unbounded();
    let (tls, _) = flume::unbounded();
    let (ws, _) = flume::unbounded();
    let (wss, _) = flume::unbounded();
    (
        OutboundRouter {
            udp: udp_tx.into(),
            udp_by_local: HashMap::new(),
            udp_dynamic: None,
            tcp,
            tls,
            ws,
            wss,
            sctp: None,
        },
        udp_rx,
    )
}

#[test]
fn every_ue_from_yaml_registers_from_its_own_address() {
    let config = Config::from_str(&ue_yaml(8)).expect("the config loads");
    let manager = manager_from(&config);
    assert_eq!(manager.len(), 8);
    assert_eq!(manager.max_registers_per_sec(), Some(20));

    let listen = HashMap::from([(Transport::Udp, "203.0.113.5:5060".parse().expect("addr"))]);
    let defaults = EgressDefaults::new("203.0.113.5:5060".parse().expect("addr"), &listen);
    let (router, sent) = router();
    for aor in manager.entries_due() {
        let built = manager
            .build_register(&aor, defaults, 600000)
            .expect("built");
        router
            .send(OutboundMessage {
                connection_id: ConnectionId::default(),
                transport: built.transport,
                destination: built.destination,
                data: bytes::Bytes::from(built.message.to_bytes()),
                source_local_addr: built.source_local_addr,
                server_name: None,
                verify_server: None,
                followups: None,
            })
            .expect("handed to the transport");
    }

    let mut sources = Vec::new();
    for message in sent.try_iter() {
        let raw = String::from_utf8_lossy(&message.data).into_owned();
        let source = message.source_local_addr.expect("pinned");
        assert!(
            raw.contains(&format!("Via: SIP/2.0/UDP {source};")),
            "{raw}"
        );
        assert!(
            raw.contains(&format!("@{source}>")),
            "Contact names the UE: {raw}"
        );
        assert!(
            raw.contains("port-c=6100") && raw.contains("port-s=6101"),
            "{raw}"
        );
        assert!(
            !raw.contains("203.0.113.5"),
            "the process address leaked: {raw}"
        );
        sources.push(source);
    }
    sources.sort();
    let expected: Vec<SocketAddr> = (1..=8)
        .map(|index| SocketAddr::from(([192, 0, 2, 10 + index as u8], 5060)))
        .collect();
    assert_eq!(
        sources, expected,
        "one REGISTER per UE, each from its own address"
    );
}

#[test]
fn a_ue_moves_waits_and_comes_back_without_a_restart() {
    let config = Config::from_str(&ue_yaml(3)).expect("the config loads");
    let manager = manager_from(&config);
    for index in 1..=3 {
        manager.handle_success(&impu(index), 600000);
    }
    let ip = |text: &str| -> IpAddr { text.parse().expect("ip") };

    // The address pool shifted: UE 2 now holds .30.
    manager
        .set_local_addr(&impu(2), Some(ip("192.0.2.30")))
        .expect("moved");
    assert_eq!(manager.state(&impu(2)), Some(RegistrantState::Unregistered));
    assert_eq!(manager.entries_due(), [impu(2)]);
    assert_eq!(
        manager.find_by_local(LocalAddrQuery::parse("192.0.2.30:6101").expect("parse")),
        Some(impu(2))
    );
    assert_eq!(
        manager.find_by_local(LocalAddrQuery::parse("192.0.2.12").expect("parse")),
        None,
        "the old address belongs to nobody"
    );

    // Its address went away entirely.
    manager.set_local_addr(&impu(2), None).expect("taken away");
    assert_eq!(
        manager.state(&impu(2)),
        Some(RegistrantState::AwaitingAddress)
    );
    assert!(manager.entries_due().is_empty());
    assert_eq!(manager.counts()["registered"], 2);
    assert_eq!(manager.counts()["awaiting_address"], 1);

    // And came back.
    manager
        .set_local_addr(&impu(2), Some(ip("192.0.2.31")))
        .expect("back");
    assert_eq!(manager.entries_due(), [impu(2)]);
}

#[test]
fn yaml_refuses_two_ues_on_one_address_and_port() {
    let yaml = ue_yaml(2).replace("192.0.2.12", "192.0.2.11");
    let error = Config::from_str(&yaml).expect_err("refused at load");
    assert!(error.to_string().contains("already used"), "{error}");
}

#[test]
fn yaml_refuses_a_local_addr_on_tls_and_takes_one_on_tcp() {
    let on = |transport: &str| {
        Config::from_str(&ue_yaml(1).replace(
            "      local_addr:",
            &format!("      transport: {transport}\n      local_addr:"),
        ))
    };
    let error = on("tls").expect_err("refused at load");
    assert!(error.to_string().contains("udp or tcp"), "{error}");
    on("tcp").expect("a TCP UE on its own address loads");
}

#[test]
fn yaml_refuses_a_window_that_would_lapse() {
    let yaml = ue_yaml(1).replace("[0.4, 0.6]", "[0.4, 1.2]");
    assert!(Config::from_str(&yaml).is_err());
}

#[test]
fn a_config_without_the_new_keys_keeps_the_old_defaults() {
    let config = Config::from_str(concat!(
        "listen:\n",
        "  udp: [\"203.0.113.5:5060\"]\n",
        "domain:\n",
        "  local: [\"203.0.113.5\"]\n",
        "registrant:\n",
        "  entries:\n",
        "    - aor: \"sip:trunk@carrier.example\"\n",
        "      registrar: \"sip:198.51.100.20:5060\"\n",
        "      user: \"trunk\"\n",
        "      password: \"secret\"\n",
    ))
    .expect("loads");
    let registrant = config.registrant.as_ref().expect("block");
    assert_eq!(registrant.refresh_window, None);
    assert_eq!(registrant.max_registers_per_sec, None);
    assert_eq!(registrant.effective_event_capacity(), 1024);
    let entry = entry_from_config(&registrant.entries[0], registrant).expect("entry");
    assert_eq!(entry.local_addr, None);
    let _ = Arc::new(entry);
}
