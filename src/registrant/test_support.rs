//! Fixtures shared by the registrant tests and the dispatcher's tests of the
//! registrant's answers: a manager, IMS UE entries, and an AKA challenge that
//! Milenage verifies (TS 35.208 Test Set 1).

use std::net::IpAddr;
use std::time::Duration;

use super::{aka, RegistrantCredentials, RegistrantEntry, RegistrantManager, UeIpsec};
use crate::ipsec::{EncryptionAlgorithm, IntegrityAlgorithm};
use crate::transport::Transport;

/// The IMS home domain the fixtures register into.
pub(crate) const REALM: &str = "ims.mnc01.mcc001.3gppnetwork.org";

/// The P-CSCF's Security-Server answer on the 401.
pub(crate) const SECURITY_SERVER: &str =
    "ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=55555; spi-s=66666; port-c=5064; port-s=5066";

/// The P-CSCF the fixtures register through.
pub(crate) const PCSCF: &str = "198.51.100.10:5060";

/// A manager with the defaults the registrant tests use.
pub(crate) fn manager() -> RegistrantManager {
    RegistrantManager::new(
        3600,
        Duration::from_secs(60),
        Duration::from_secs(300),
        crate::config::IdentityHeaders::default().shared(),
    )
}

/// The IMPU of test UE `index` (MCC 001 / MNC 01).
pub(crate) fn impu(index: u32) -> String {
    format!("sip:00101{index:010}@{REALM}")
}

/// A digest trunk entry registering through `PCSCF` over UDP.
pub(crate) fn trunk(aor: &str) -> RegistrantEntry {
    RegistrantEntry::new(
        aor.to_string(),
        format!("sip:{PCSCF}"),
        PCSCF.parse().expect("an address"),
        Transport::Udp,
        RegistrantCredentials::password("trunk".to_string(), "secret".to_string(), None),
        3600,
        None,
    )
}

/// An IMS UE entry: AKA (Test Set 1) + IPsec on protected ports 6100/6101,
/// from `local_addr` when given.
pub(crate) fn ue(index: u32, local_addr: Option<IpAddr>) -> RegistrantEntry {
    let credentials = aka::AkaCredentials::from_hex(
        "465b5ce8b199b49faa5f0a2ee238a6bc",
        None,
        Some("cd63cb71954a9f4e48a5994e37a02baf"),
        "b9b9",
    )
    .expect("Test Set 1 credentials");
    let entry = RegistrantEntry::new(
        impu(index),
        format!("sip:{PCSCF}"),
        PCSCF.parse().expect("an address"),
        Transport::Udp,
        RegistrantCredentials::password(
            format!("00101{index:010}@{REALM}"),
            String::new(),
            Some(REALM.to_string()),
        ),
        600000,
        None,
    )
    .with_aka(credentials, [0u8; 6])
    .with_ipsec(UeIpsec::new(
        6100,
        6101,
        IntegrityAlgorithm::HmacSha1,
        EncryptionAlgorithm::Null,
    ));
    match local_addr {
        Some(ip) => entry.with_local_addr(ip),
        None => entry,
    }
}

/// A `WWW-Authenticate` value carrying an AKAv1-MD5 challenge for network SQN
/// `sqn_hex`, which the [`ue`] fixture's USIM accepts.
pub(crate) fn aka_challenge_value(sqn_hex: &str) -> String {
    use crate::ipsec::milenage::{generate_vector_with_rand, hex_to_bytes};
    use base64::Engine as _;

    let bytes = |hex: &str| hex_to_bytes(hex).expect("hex");
    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes("465b5ce8b199b49faa5f0a2ee238a6bc"));
    let mut op = [0u8; 16];
    op.copy_from_slice(&bytes("cdc202d5123e20f62b6d676ac72cb318"));
    let mut sqn = [0u8; 6];
    sqn.copy_from_slice(&bytes(sqn_hex));
    let mut rand = [0u8; 16];
    rand.copy_from_slice(&bytes("23553cbe9637a89d218ae64dae47bf35"));
    let vector = generate_vector_with_rand(&key, &op, &sqn, &[0xb9, 0xb9], &rand);
    let mut joined = Vec::new();
    joined.extend_from_slice(&vector.rand);
    joined.extend_from_slice(&vector.autn);
    let nonce = base64::engine::general_purpose::STANDARD.encode(&joined);
    format!("Digest realm=\"{REALM}\", nonce=\"{nonce}\", qop=\"auth\", algorithm=AKAv1-MD5")
}
