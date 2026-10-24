//! Building a [`RegistrantEntry`] from a `registrant.entries[]` item of
//! `siphon.yaml`.
//!
//! Lives beside the entry rather than in the server bootstrap so the rules for
//! what a YAML entry may say (transport, AKA, IPsec, IMS tags, its own
//! address, refresh window) sit next to the type they build, and are unit
//! testable without starting a server.

use crate::config::{RegistrantEntryConfig, RegistrantYamlConfig};
use crate::ipsec::{EncryptionAlgorithm, IntegrityAlgorithm};
use crate::transport::Transport;

use super::{
    aka, AuthMode, ImsContactParams, RefreshWindow, RegistrantCredentials, RegistrantEntry, UeIpsec,
};

/// Build the entry `entry_config` describes, or the reason it cannot be.
///
/// Resolves the registrar (DNS for a hostname, kept for re-resolution on
/// failure). The reason is phrased for a log line naming the AoR.
pub fn entry_from_config(
    entry_config: &RegistrantEntryConfig,
    registrant_config: &RegistrantYamlConfig,
) -> Result<RegistrantEntry, String> {
    let registrar_host = entry_config
        .registrar
        .strip_prefix("sip:")
        .or_else(|| entry_config.registrar.strip_prefix("sips:"))
        .unwrap_or(&entry_config.registrar);

    // Refused at load by `Config::validate_registrant_transports`; refused here
    // too rather than defaulting to UDP, which is how an `sctp` or mis-cased
    // trunk registered on a transport nobody named.
    let transport_type = entry_config.outbound_transport("registrant transport")?;

    let default_port: u16 = if transport_type == Transport::Tls {
        5061
    } else {
        5060
    };
    let address_str = if registrar_host.contains(':') {
        registrar_host.to_string()
    } else {
        format!("{registrar_host}:{default_port}")
    };
    let destination = crate::gateway::resolve_address(&address_str)
        .map_err(|error| format!("cannot resolve registrant host {registrar_host}: {error}"))?;

    let is_hostname = address_str.parse::<std::net::SocketAddr>().is_err();
    let mut entry = RegistrantEntry::new(
        entry_config.aor.clone(),
        entry_config.registrar.clone(),
        destination,
        transport_type,
        RegistrantCredentials::password(
            entry_config.user.clone(),
            entry_config.password.clone(),
            entry_config.realm.clone(),
        ),
        entry_config
            .interval
            .unwrap_or(registrant_config.default_interval),
        entry_config.contact.clone(),
    );
    if is_hostname {
        entry.address_str = Some(address_str);
    }

    // IMS AKAv1-MD5 (3GPP TS 33.203): attach the USIM secrets so the 401 runs
    // through Milenage instead of password digest.
    if entry_config
        .auth
        .as_deref()
        .is_some_and(|mode| mode.eq_ignore_ascii_case("aka"))
    {
        let aka_config = entry_config
            .aka
            .as_ref()
            .ok_or_else(|| "auth: aka requires an `aka:` block".to_string())?;
        let credentials = aka::AkaCredentials::from_hex(
            &aka_config.k,
            aka_config.op.as_deref(),
            aka_config.opc.as_deref(),
            &aka_config.amf,
        )
        .map_err(|error| format!("invalid AKA credentials: {error}"))?;
        let initial_sqn = match crate::ipsec::milenage::hex_to_bytes(&aka_config.sqn) {
            Some(bytes) if bytes.len() == 6 => {
                let mut sqn = [0u8; 6];
                sqn.copy_from_slice(&bytes);
                sqn
            }
            _ => return Err("sqn must be 12 hex chars".to_string()),
        };
        entry = entry.with_aka(credentials, initial_sqn);
    }

    // IPsec sec-agree (UE side) — only meaningful alongside auth: aka.
    if let Some(ipsec_config) = &entry_config.ipsec {
        if entry.auth_mode != AuthMode::Aka {
            return Err("registrant ipsec requires auth: aka".to_string());
        }
        let aalg = IntegrityAlgorithm::from_sec_agree_name(&ipsec_config.alg)
            .ok_or_else(|| format!("unknown ipsec alg {}", ipsec_config.alg))?;
        let ealg = EncryptionAlgorithm::from_sec_agree_name(&ipsec_config.ealg)
            .ok_or_else(|| format!("unknown ipsec ealg {}", ipsec_config.ealg))?;
        entry = entry.with_ipsec(UeIpsec::new(
            ipsec_config.ue_port_c,
            ipsec_config.ue_port_s,
            aalg,
            ealg,
        ));
    }

    // IMS Contact feature tags (instance ID + MMTel/video/SMS).
    if let Some(ims_config) = &entry_config.ims {
        let has = |tag: &str| {
            ims_config
                .features
                .iter()
                .any(|feature| feature.eq_ignore_ascii_case(tag))
        };
        entry = entry.with_ims_contact(ImsContactParams {
            instance_id: ims_config.imei.clone(),
            mmtel: has("mmtel"),
            video: has("video"),
            smsip: has("smsip"),
        });
    }

    // Its own address, or a promise of one (see `registrant::address`).
    if let Some(local_addr) = entry_config.local_addr {
        if !matches!(transport_type, Transport::Udp | Transport::Tcp) {
            return Err(format!(
                "local_addr needs transport udp or tcp, not {transport_type}"
            ));
        }
        entry = entry.with_local_addr(local_addr);
    } else if entry_config.require_local_addr {
        entry = entry.requiring_local_addr();
    }
    if let Some(pair) = entry_config.refresh_window {
        entry = entry.with_refresh_window(RefreshWindow::from_pair(pair)?);
    }

    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registrant_config(yaml: &str) -> RegistrantYamlConfig {
        serde_saphyr::from_str(yaml).expect("a registrant block")
    }

    const UE_YAML: &str = concat!(
        "entries:\n",
        "  - aor: \"sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org\"\n",
        "    registrar: \"sip:198.51.100.10:5060\"\n",
        "    user: \"001010000000001@ims.mnc01.mcc001.3gppnetwork.org\"\n",
        "    auth: aka\n",
        "    aka:\n",
        "      k: \"465b5ce8b199b49faa5f0a2ee238a6bc\"\n",
        "      opc: \"cd63cb71954a9f4e48a5994e37a02baf\"\n",
        "    ipsec:\n",
        "      ue_port_c: 6100\n",
        "      ue_port_s: 6101\n",
        "    ims:\n",
        "      imei: \"01234567-000001-0\"\n",
        "      features: [mmtel, smsip]\n",
        "    local_addr: \"192.0.2.77\"\n",
        "    refresh_window: [0.4, 0.6]\n",
    );

    #[test]
    fn a_ue_entry_carries_its_address_window_and_ipsec() {
        let config = registrant_config(UE_YAML);
        let entry = entry_from_config(&config.entries[0], &config).expect("a valid entry");
        assert_eq!(entry.local_addr, Some("192.0.2.77".parse().expect("ip")));
        assert!(entry.require_local_addr);
        assert_eq!(
            entry.refresh_window,
            Some(RefreshWindow::new(0.4, 0.6).expect("window"))
        );
        assert_eq!(entry.auth_mode, AuthMode::Aka);
        assert_eq!(
            entry.ue_ipsec.as_ref().map(|ipsec| ipsec.ue_port_c),
            Some(6100)
        );
        assert!(entry
            .ims_contact
            .as_ref()
            .is_some_and(|ims| ims.mmtel && ims.smsip));
    }

    #[test]
    fn an_entry_without_an_address_keeps_the_process_address() {
        let config = registrant_config(concat!(
            "entries:\n",
            "  - aor: \"sip:trunk@carrier.example\"\n",
            "    registrar: \"sip:198.51.100.20:5060\"\n",
            "    user: \"trunk\"\n",
            "    password: \"secret\"\n",
        ));
        let entry = entry_from_config(&config.entries[0], &config).expect("a valid entry");
        assert_eq!(entry.local_addr, None);
        assert!(!entry.require_local_addr);
        assert_eq!(entry.refresh_window, None);
        assert_eq!(entry.auth_mode, AuthMode::Digest);
    }

    #[test]
    fn require_local_addr_without_one_is_a_promise() {
        let config = registrant_config(concat!(
            "entries:\n",
            "  - aor: \"sip:ue@ims.mnc01.mcc001.3gppnetwork.org\"\n",
            "    registrar: \"sip:198.51.100.10:5060\"\n",
            "    user: \"ue\"\n",
            "    require_local_addr: true\n",
        ));
        let entry = entry_from_config(&config.entries[0], &config).expect("a valid entry");
        assert_eq!(entry.local_addr, None);
        assert!(entry.require_local_addr);
    }

    #[test]
    fn a_local_addr_on_tls_is_refused_and_on_tcp_accepted() {
        let entry_on = |transport: &str| {
            let config = registrant_config(&format!(
                concat!(
                    "entries:\n",
                    "  - aor: \"sip:trunk@carrier.example\"\n",
                    "    registrar: \"sip:198.51.100.20:5060\"\n",
                    "    user: \"trunk\"\n",
                    "    transport: {}\n",
                    "    local_addr: \"192.0.2.77\"\n",
                ),
                transport
            ));
            entry_from_config(&config.entries[0], &config)
        };
        let error = entry_on("tls").expect_err("refused");
        assert!(error.contains("udp or tcp"), "{error}");
        let entry = entry_on("tcp").expect("a TCP entry on its own address");
        assert_eq!(entry.transport, Transport::Tcp);
        assert_eq!(entry.local_addr, Some("192.0.2.77".parse().unwrap()));
    }

    #[test]
    fn a_bad_refresh_window_is_refused() {
        let config = registrant_config(concat!(
            "entries:\n",
            "  - aor: \"sip:trunk@carrier.example\"\n",
            "    registrar: \"sip:198.51.100.20:5060\"\n",
            "    user: \"trunk\"\n",
            "    refresh_window: [0.9, 0.2]\n",
        ));
        assert!(entry_from_config(&config.entries[0], &config).is_err());
    }

    #[test]
    fn ipsec_without_aka_is_refused() {
        let config = registrant_config(concat!(
            "entries:\n",
            "  - aor: \"sip:trunk@carrier.example\"\n",
            "    registrar: \"sip:198.51.100.20:5060\"\n",
            "    user: \"trunk\"\n",
            "    ipsec:\n",
            "      ue_port_c: 6100\n",
            "      ue_port_s: 6101\n",
        ));
        let error = entry_from_config(&config.entries[0], &config).expect_err("refused");
        assert!(error.contains("aka"), "{error}");
    }
}
