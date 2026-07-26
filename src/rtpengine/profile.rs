//! RTP media profiles and their translation to RTPEngine NG protocol flags.
//!
//! Each profile describes a media transcoding/relay scenario (e.g. SRTP on the
//! UE side, plain RTP on the core side).  The profile determines which NG flags
//! are sent in `offer` and `answer` commands.
//!
//! Four built-in profiles are always available:
//!   srtp_to_rtp, ws_to_rtp, wss_to_rtp, rtp_passthrough
//!
//! Operators can define additional profiles (or override built-ins) in the YAML
//! config under `media.profiles`.

use std::collections::HashMap;

use crate::config::{MediaProfileConfig, NgFlagsConfig};

/// A single media profile: offer flags + answer flags.
#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub offer: NgFlags,
    pub answer: NgFlags,
}

/// Registry of named media profiles.
///
/// Populated at startup from built-in defaults + YAML config.  Shared via
/// `Arc<ProfileRegistry>` so that the Python API and dispatcher can look up
/// profiles by name.
#[derive(Debug, Clone)]
pub struct ProfileRegistry {
    profiles: HashMap<String, ProfileEntry>,
}

impl ProfileRegistry {
    /// Create a registry containing only the built-in profiles.
    pub fn new() -> Self {
        let mut profiles = HashMap::new();
        profiles.insert("srtp_to_rtp".into(), Self::builtin_srtp_to_rtp());
        profiles.insert("rtp_to_srtp".into(), Self::builtin_rtp_to_srtp());
        profiles.insert("ws_to_rtp".into(), Self::builtin_ws_to_rtp());
        profiles.insert("wss_to_rtp".into(), Self::builtin_wss_to_rtp());
        profiles.insert("rtp_passthrough".into(), Self::builtin_rtp_passthrough());
        profiles.insert("srs_recording".into(), Self::builtin_srs_recording());
        profiles.insert("siprec_src".into(), Self::builtin_siprec_src());
        Self { profiles }
    }

    /// Create a registry from built-in defaults + custom YAML profiles.
    /// Custom profiles override built-ins with the same name.
    pub fn from_config(custom: &HashMap<String, MediaProfileConfig>) -> Self {
        let mut registry = Self::new();
        for (name, config) in custom {
            registry.profiles.insert(
                name.clone(),
                ProfileEntry {
                    offer: NgFlags::from_config(&config.offer),
                    answer: NgFlags::from_config(&config.answer),
                },
            );
        }
        registry
    }

    /// Look up a profile by name.
    pub fn get(&self, name: &str) -> Option<&ProfileEntry> {
        self.profiles.get(name)
    }

    /// List all available profile names (sorted for deterministic error messages).
    pub fn profile_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.profiles.keys().map(|s| s.as_str()).collect();
        names.sort_unstable();
        names
    }

    // --- Built-in profiles ---

    fn builtin_srtp_to_rtp() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/SAVP".into()),
                ice: Some("remove".into()),
                dtls: None,
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec![],
                direction: vec!["external".into(), "internal".into()],
                record_call: false,
                record_path: None,
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: None,
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec![],
                direction: vec!["internal".into(), "external".into()],
                record_call: false,
                record_path: None,
            },
        }
    }

    fn builtin_rtp_to_srtp() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/SAVP".into()),
                ice: Some("remove".into()),
                dtls: None,
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec![],
                direction: vec!["internal".into(), "external".into()],
                record_call: false,
                record_path: None,
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: None,
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec![],
                direction: vec!["external".into(), "internal".into()],
                record_call: false,
                record_path: None,
            },
        }
    }

    fn builtin_ws_to_rtp() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/AVPF".into()),
                ice: Some("force".into()),
                dtls: None,
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec![],
                direction: vec!["external".into(), "internal".into()],
                record_call: false,
                record_path: None,
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: None,
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec![],
                direction: vec!["internal".into(), "external".into()],
                record_call: false,
                record_path: None,
            },
        }
    }

    fn builtin_wss_to_rtp() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/SAVPF".into()),
                ice: Some("force".into()),
                dtls: Some("passive".into()),
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec![],
                direction: vec!["external".into(), "internal".into()],
                record_call: false,
                record_path: None,
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec![],
                direction: vec!["internal".into(), "external".into()],
                record_call: false,
                record_path: None,
            },
        }
    }

    fn builtin_srs_recording() -> ProfileEntry {
        // SIPREC SRS recording profile:
        // - replace origin so RTPEngine rewrites o= line
        // - media handover + port latching for NAT/SIPREC source port flexibility
        // - ICE remove, DTLS off (recording sink, no peer security needed)
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec![
                    "media handover".into(),
                    "port latching".into(),
                ],
                direction: vec![],
                record_call: true,
                record_path: None,
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec![
                    "media handover".into(),
                    "port latching".into(),
                ],
                direction: vec![],
                record_call: true,
                record_path: None,
            },
        }
    }

    fn builtin_siprec_src() -> ProfileEntry {
        // SIPREC SRC subscribe profile:
        // - ICE remove, DTLS off (recording leg, no peer security)
        // - replace origin so RTPEngine rewrites o= line
        // - plain RTP to SRS
        // These flags are merged into the subscribe request alongside the
        // mandatory ["all", "siprec"] flags.
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec![],
                direction: vec![],
                record_call: false,
                record_path: None,
            },
            answer: NgFlags::default(),
        }
    }

    fn builtin_rtp_passthrough() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: None,
                ice: None,
                dtls: None,
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec!["trust-address".into()],
                direction: vec![],
                record_call: false,
                record_path: None,
            },
            answer: NgFlags {
                transport_protocol: None,
                ice: None,
                dtls: None,
                replace: vec!["origin".into()],
                address_family: None,
                flags: vec!["trust-address".into()],
                direction: vec![],
                record_call: false,
                record_path: None,
            },
        }
    }
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// NG protocol flags sent with offer/answer commands.
#[derive(Debug, Clone, Default)]
pub struct NgFlags {
    /// Transport protocol override (e.g. "RTP/AVP", "RTP/SAVPF").
    pub transport_protocol: Option<String>,
    /// ICE handling: "remove", "force", or "force-relay".
    pub ice: Option<String>,
    /// DTLS mode: "passive", "active", or "off".
    pub dtls: Option<String>,
    /// SDP fields to replace: "origin".
    pub replace: Vec<String>,
    /// Address family for the engine's relay endpoints on this side of the call:
    /// `"IP4"` or `"IP6"` (the SDP `addrtype` spelling).  `None` leaves the
    /// engine following the offered SDP's own family — a single-family relay.
    ///
    /// Carried on the wire as rtpengine's dedicated `"address family"` NG dict
    /// key (**not** a `flags` token — rtpengine would ignore it there) and as
    /// siphon-rtp's `address_family` JSON field.  The classic `rtpproxy` backend
    /// has no equivalent and cannot honour it.
    pub address_family: Option<String>,
    /// Additional flags: "trust-address", "symmetric", "asymmetric".
    pub flags: Vec<String>,
    /// Direction pair for NAT traversal: ["external", "internal"].
    pub direction: Vec<String>,
    /// Enable call recording in RTPEngine.
    pub record_call: bool,
    /// Directory path for RTPEngine to write recording files.
    pub record_path: Option<String>,
}

impl NgFlags {
    /// Build from the YAML config representation.
    pub fn from_config(config: &NgFlagsConfig) -> Self {
        Self {
            transport_protocol: config.transport_protocol.clone(),
            ice: config.ice.clone(),
            dtls: config.dtls.clone(),
            replace: config.replace.clone(),
            address_family: config.address_family.clone(),
            flags: config.flags.clone(),
            direction: config.direction.clone(),
            record_call: config.record_call,
            record_path: config.record_path.clone(),
        }
    }

    /// Convert these flags to bencode dict entries to merge into the command dict.
    pub fn to_bencode_pairs(&self) -> Vec<(&str, super::bencode::BencodeValue)> {
        use super::bencode::BencodeValue;

        let mut pairs = Vec::new();

        if let Some(transport_protocol) = &self.transport_protocol {
            pairs.push((
                "transport-protocol",
                BencodeValue::string(transport_protocol),
            ));
        }
        if let Some(ice) = &self.ice {
            pairs.push(("ICE", BencodeValue::string(ice)));
        }
        if let Some(dtls) = &self.dtls {
            pairs.push(("DTLS", BencodeValue::string(dtls)));
        }
        if !self.replace.is_empty() {
            let items: Vec<&str> = self.replace.iter().map(|s| s.as_str()).collect();
            pairs.push(("replace", BencodeValue::string_list(&items)));
        }
        // rtpengine reads the address family from a dedicated dict key
        // (`"address family": "IP4"`), NOT as a token in the `flags` list — a
        // family smuggled into `flags` is silently dropped by the engine.
        if let Some(address_family) = &self.address_family {
            pairs.push(("address family", BencodeValue::string(address_family)));
        }
        if !self.flags.is_empty() {
            let items: Vec<&str> = self.flags.iter().map(|s| s.as_str()).collect();
            pairs.push(("flags", BencodeValue::string_list(&items)));
        }
        if !self.direction.is_empty() {
            let items: Vec<&str> = self.direction.iter().map(|s| s.as_str()).collect();
            pairs.push(("direction", BencodeValue::string_list(&items)));
        }
        if self.record_call {
            pairs.push(("record call", BencodeValue::string("yes")));
        }
        if let Some(record_path) = &self.record_path {
            pairs.push(("recording-dir", BencodeValue::string(record_path)));
        }

        pairs
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_builtins() {
        let registry = ProfileRegistry::new();
        assert!(registry.get("srtp_to_rtp").is_some());
        assert!(registry.get("rtp_to_srtp").is_some());
        assert!(registry.get("ws_to_rtp").is_some());
        assert!(registry.get("wss_to_rtp").is_some());
        assert!(registry.get("rtp_passthrough").is_some());
        assert!(registry.get("srs_recording").is_some());
        assert!(registry.get("siprec_src").is_some());
    }

    #[test]
    fn unknown_profile_returns_none() {
        let registry = ProfileRegistry::new();
        assert!(registry.get("invalid").is_none());
        assert!(registry.get("").is_none());
    }

    #[test]
    fn profile_names_sorted() {
        let registry = ProfileRegistry::new();
        let names = registry.profile_names();
        assert_eq!(names.len(), 7);
        // Sorted alphabetically
        assert_eq!(names[0], "rtp_passthrough");
        assert_eq!(names[1], "rtp_to_srtp");
        assert_eq!(names[2], "siprec_src");
        assert_eq!(names[3], "srs_recording");
        assert_eq!(names[6], "wss_to_rtp");
    }

    #[test]
    fn custom_profile_from_config() {
        let mut custom = HashMap::new();
        custom.insert(
            "my_profile".to_string(),
            MediaProfileConfig {
                offer: NgFlagsConfig {
                    transport_protocol: Some("RTP/SAVPF".into()),
                    ice: Some("force".into()),
                    dtls: Some("passive".into()),
                    replace: vec!["origin".into()],
                    address_family: None,
                    flags: vec![],
                    direction: vec!["external".into(), "internal".into()],
                    record_call: false,
                    record_path: None,
                },
                answer: NgFlagsConfig {
                    transport_protocol: Some("RTP/AVP".into()),
                    ice: Some("remove".into()),
                    dtls: Some("off".into()),
                    replace: vec!["origin".into()],
                    address_family: None,
                    flags: vec![],
                    direction: vec!["internal".into(), "external".into()],
                    record_call: false,
                    record_path: None,
                },
            },
        );
        let registry = ProfileRegistry::from_config(&custom);
        // Custom profile exists
        let entry = registry.get("my_profile").unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/SAVPF"));
        assert_eq!(entry.answer.dtls.as_deref(), Some("off"));
        // Built-ins still exist
        assert!(registry.get("srtp_to_rtp").is_some());
        assert_eq!(registry.profile_names().len(), 8);
    }

    #[test]
    fn custom_profile_overrides_builtin() {
        let mut custom = HashMap::new();
        custom.insert(
            "srtp_to_rtp".to_string(),
            MediaProfileConfig {
                offer: NgFlagsConfig {
                    transport_protocol: Some("CUSTOM/OFFER".into()),
                    ice: None,
                    dtls: None,
                    replace: vec![],
                    address_family: None,
                    flags: vec![],
                    direction: vec![],
                    record_call: false,
                    record_path: None,
                },
                answer: NgFlagsConfig {
                    transport_protocol: Some("CUSTOM/ANSWER".into()),
                    ice: None,
                    dtls: None,
                    replace: vec![],
                    address_family: None,
                    flags: vec![],
                    direction: vec![],
                    record_call: false,
                    record_path: None,
                },
            },
        );
        let registry = ProfileRegistry::from_config(&custom);
        let entry = registry.get("srtp_to_rtp").unwrap();
        assert_eq!(
            entry.offer.transport_protocol.as_deref(),
            Some("CUSTOM/OFFER")
        );
    }

    #[test]
    fn srtp_to_rtp_offer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("srtp_to_rtp").unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/SAVP"));
        assert_eq!(entry.offer.ice.as_deref(), Some("remove"));
        assert!(entry.offer.dtls.is_none());
        assert_eq!(entry.offer.replace, vec!["origin"]);
        assert!(entry.offer.flags.is_empty());
        assert_eq!(entry.offer.direction, vec!["external", "internal"]);
    }

    #[test]
    fn srtp_to_rtp_answer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("srtp_to_rtp").unwrap();
        assert_eq!(entry.answer.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(entry.answer.ice.as_deref(), Some("remove"));
        assert_eq!(entry.answer.direction, vec!["internal", "external"]);
    }

    #[test]
    fn ws_to_rtp_offer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("ws_to_rtp").unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/AVPF"));
        assert_eq!(entry.offer.ice.as_deref(), Some("force"));
    }

    #[test]
    fn wss_to_rtp_offer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("wss_to_rtp").unwrap();
        assert_eq!(
            entry.offer.transport_protocol.as_deref(),
            Some("RTP/SAVPF")
        );
        assert_eq!(entry.offer.ice.as_deref(), Some("force"));
        assert_eq!(entry.offer.dtls.as_deref(), Some("passive"));
    }

    #[test]
    fn wss_to_rtp_answer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("wss_to_rtp").unwrap();
        assert_eq!(entry.answer.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(entry.answer.ice.as_deref(), Some("remove"));
        assert_eq!(entry.answer.dtls.as_deref(), Some("off"));
    }

    #[test]
    fn rtp_passthrough_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("rtp_passthrough").unwrap();
        assert!(entry.offer.transport_protocol.is_none());
        assert!(entry.offer.ice.is_none());
        assert_eq!(entry.offer.flags, vec!["trust-address"]);
        assert!(entry.offer.direction.is_empty());
        // Passthrough: offer and answer flags are symmetric.
        assert_eq!(entry.offer.flags, entry.answer.flags);
    }

    #[test]
    fn siprec_src_offer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("siprec_src").unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(entry.offer.ice.as_deref(), Some("remove"));
        assert_eq!(entry.offer.dtls.as_deref(), Some("off"));
        assert_eq!(entry.offer.replace, vec!["origin"]);
        assert!(!entry.offer.record_call);
    }

    #[test]
    fn ng_flags_to_bencode_pairs_full() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("wss_to_rtp").unwrap();
        let pairs = entry.offer.to_bencode_pairs();
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"transport-protocol"));
        assert!(keys.contains(&"ICE"));
        assert!(keys.contains(&"DTLS"));
        assert!(keys.contains(&"replace"));
        assert!(keys.contains(&"direction"));
        // No flags for WSS offer.
        assert!(!keys.contains(&"flags"));
    }

    #[test]
    fn ng_flags_to_bencode_pairs_minimal() {
        let flags = NgFlags::default();
        let pairs = flags.to_bencode_pairs();
        assert!(pairs.is_empty());
    }

    /// Regression check: `record_call` and `record_path` (set in user YAML
    /// or in the built-in `srs_recording` profile) MUST appear in the bencode
    /// emission as the keys RTPEngine actually understands. An audit once
    /// claimed these were dead config; if anyone inadvertently drops the
    /// emission again this test catches it.
    #[test]
    fn ng_flags_emits_record_call_and_recording_dir() {
        let flags = NgFlags {
            record_call: true,
            record_path: Some("/var/spool/rtpengine".into()),
            ..NgFlags::default()
        };
        let pairs = flags.to_bencode_pairs();
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"record call"), "missing 'record call' key");
        assert!(keys.contains(&"recording-dir"), "missing 'recording-dir' key");
    }

    /// `address family` must ride its own NG dict key with the SDP `addrtype`
    /// spelling.  rtpengine reads the family from that key only — a family put in
    /// the free-form `flags` list is silently ignored by the engine, which is the
    /// exact bug this key exists to avoid.
    #[test]
    fn ng_flags_emits_address_family_as_its_own_key() {
        let flags = NgFlags {
            address_family: Some("IP4".into()),
            ..NgFlags::default()
        };
        let pairs = flags.to_bencode_pairs();
        let (key, value) = pairs
            .iter()
            .find(|(key, _)| *key == "address family")
            .expect("missing 'address family' key");
        assert_eq!(*key, "address family");
        assert_eq!(*value, super::super::bencode::BencodeValue::string("IP4"));
        // Never smuggled into the flags list.
        assert!(!pairs.iter().any(|(key, _)| *key == "flags"));
    }

    #[test]
    fn ng_flags_omits_address_family_when_unset() {
        let flags = NgFlags::default();
        assert!(!flags
            .to_bencode_pairs()
            .iter()
            .any(|(key, _)| *key == "address family"));
    }

    /// A profile's `address_family` must survive the YAML → `NgFlags` hop; it
    /// previously had no `NgFlagsConfig` source at all.
    #[test]
    fn address_family_flows_from_config_to_flags() {
        let mut custom = HashMap::new();
        custom.insert(
            "v6_access_to_v4_core".to_string(),
            MediaProfileConfig {
                offer: NgFlagsConfig {
                    transport_protocol: None,
                    ice: None,
                    dtls: None,
                    replace: vec!["origin".into()],
                    address_family: Some("IP4".into()),
                    flags: vec![],
                    direction: vec![],
                    record_call: false,
                    record_path: None,
                },
                answer: NgFlagsConfig {
                    transport_protocol: None,
                    ice: None,
                    dtls: None,
                    replace: vec!["origin".into()],
                    address_family: Some("IP6".into()),
                    flags: vec![],
                    direction: vec![],
                    record_call: false,
                    record_path: None,
                },
            },
        );
        let registry = ProfileRegistry::from_config(&custom);
        let entry = registry.get("v6_access_to_v4_core").unwrap();
        assert_eq!(entry.offer.address_family.as_deref(), Some("IP4"));
        assert_eq!(entry.answer.address_family.as_deref(), Some("IP6"));
        let keys: Vec<&str> = entry
            .offer
            .to_bencode_pairs()
            .iter()
            .map(|(key, _)| *key)
            .collect();
        assert!(keys.contains(&"address family"));
    }

    /// Built-ins must stay family-agnostic — anchoring a plain call must not
    /// suddenly pin a relay family (that would be a silent wire change).
    #[test]
    fn builtin_profiles_leave_address_family_unset() {
        let registry = ProfileRegistry::new();
        for name in registry.profile_names() {
            let entry = registry.get(name).unwrap();
            assert!(
                entry.offer.address_family.is_none(),
                "{name} offer pins an address family"
            );
            assert!(
                entry.answer.address_family.is_none(),
                "{name} answer pins an address family"
            );
        }
    }

    #[test]
    fn srs_recording_builtin_emits_record_call() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("srs_recording").expect("srs_recording profile");
        assert!(entry.offer.record_call, "srs_recording offer must record_call");
        let pairs = entry.offer.to_bencode_pairs();
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"record call"));
    }
}
