//! UE-side IPsec sec-agree helpers (3GPP TS 33.203 / RFC 3329).
//!
//! The P-CSCF side of sec-agree lives in the parent module; this is the
//! mirror a soft-UE needs when registering *into* an IMS core:
//!
//! - [`UeSecurityOffer`] + [`build_security_client`]: the UE picks its own
//!   protected ports + SPIs and offers a transform on the initial REGISTER.
//! - [`parse_security_server`]: read back the P-CSCF's chosen ports/SPIs.
//!   The Security-Server header shares the Security-Client grammar, so this
//!   reuses [`crate::ipsec::parse_security_client`].
//! - [`build_security_verify`]: echo the Security-Server value byte-for-byte
//!   on the protected REGISTER (RFC 3329 §2.4 — any normalisation breaks the
//!   P-CSCF's integrity check).
//!
//! Installing the kernel SAs from a negotiated offer/answer is
//! [`crate::ipsec::IpsecManager::create_ue_sa_pair`].

use crate::ipsec::{EncryptionAlgorithm, IntegrityAlgorithm, SecurityClient};

/// The transform + endpoints a UE offers in its Security-Client header.
///
/// `spi_c`/`spi_s` are the UE's own SPIs (it allocates them) and
/// `port_c`/`port_s` are the UE's protected client/server ports. The P-CSCF
/// answers with its own SPIs/ports in the Security-Server header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeSecurityOffer {
    /// Security mechanism — always `"ipsec-3gpp"` for IMS.
    pub mechanism: String,
    /// Offered integrity algorithm.
    pub aalg: IntegrityAlgorithm,
    /// Offered encryption algorithm (`Null` for integrity-only).
    pub ealg: EncryptionAlgorithm,
    /// UE client SPI (becomes `spi_uc` in the SA pair).
    pub spi_c: u32,
    /// UE server SPI (becomes `spi_us` in the SA pair).
    pub spi_s: u32,
    /// UE protected client port.
    pub port_c: u16,
    /// UE protected server port.
    pub port_s: u16,
}

impl UeSecurityOffer {
    /// Build an `ipsec-3gpp` offer for the given transform + endpoints.
    pub fn new(
        aalg: IntegrityAlgorithm,
        ealg: EncryptionAlgorithm,
        spi_c: u32,
        spi_s: u32,
        port_c: u16,
        port_s: u16,
    ) -> Self {
        Self {
            mechanism: "ipsec-3gpp".to_string(),
            aalg,
            ealg,
            spi_c,
            spi_s,
            port_c,
            port_s,
        }
    }
}

/// Build the `Security-Client` header value the UE puts on its REGISTER
/// (3GPP TS 33.203 §7.2 / RFC 3329).
///
/// `ealg` is always emitted (including `ealg=null`) — IMS P-CSCFs key the
/// answer on the offered algorithm pair, and an absent `ealg` is ambiguous.
pub fn build_security_client(offer: &UeSecurityOffer) -> String {
    format!(
        "{}; alg={}; ealg={}; spi-c={}; spi-s={}; port-c={}; port-s={}",
        offer.mechanism,
        offer.aalg.sec_agree_name(),
        offer.ealg.sec_agree_name(),
        offer.spi_c,
        offer.spi_s,
        offer.port_c,
        offer.port_s,
    )
}

/// Parse a `Security-Server` header value sent by the P-CSCF.
///
/// The Security-Server grammar is identical to Security-Client (mechanism +
/// `alg`/`ealg`/`spi-c`/`spi-s`/`port-c`/`port-s`, plus ignorable `q=` /
/// `protocol=`), so this reuses [`crate::ipsec::parse_security_client`]. The
/// returned `spi_c`/`spi_s` and `port_c`/`port_s` are the **P-CSCF's**.
pub fn parse_security_server(header: &str) -> Option<SecurityClient> {
    crate::ipsec::parse_security_client(header)
}

/// Build the `Security-Verify` header value for the protected REGISTER.
///
/// RFC 3329 §2.4: the client echoes the server's Security-Server value
/// **verbatim** so the P-CSCF can verify the negotiation wasn't tampered
/// with mid-flight. This trims only surrounding whitespace — the parameter
/// text and ordering are preserved exactly as received.
pub fn build_security_verify(security_server_value: &str) -> String {
    security_server_value.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_security_client_emits_all_params() {
        let offer = UeSecurityOffer::new(
            IntegrityAlgorithm::HmacSha1,
            EncryptionAlgorithm::Null,
            0x1111,
            0x2222,
            6100,
            6101,
        );
        let header = build_security_client(&offer);
        assert_eq!(
            header,
            "ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=4369; spi-s=8738; port-c=6100; port-s=6101"
        );
    }

    #[test]
    fn build_security_client_emits_aes_cbc() {
        let offer = UeSecurityOffer::new(
            IntegrityAlgorithm::HmacMd5,
            EncryptionAlgorithm::AesCbc128,
            11111,
            22222,
            5060,
            5062,
        );
        let header = build_security_client(&offer);
        assert!(header.contains("alg=hmac-md5-96"));
        assert!(header.contains("ealg=aes-cbc"));
        assert!(header.contains("spi-c=11111"));
        assert!(header.contains("port-s=5062"));
    }

    /// The Security-Client we build must round-trip through the shared parser
    /// (the P-CSCF reads it with exactly that code).
    #[test]
    fn build_security_client_round_trips_through_parser() {
        let offer = UeSecurityOffer::new(
            IntegrityAlgorithm::HmacSha1,
            EncryptionAlgorithm::Null,
            33333,
            44444,
            6200,
            6201,
        );
        let header = build_security_client(&offer);
        let parsed = crate::ipsec::parse_security_client(&header).unwrap();
        assert_eq!(parsed.mechanism, "ipsec-3gpp");
        assert_eq!(parsed.algorithm, "hmac-sha-1-96");
        assert_eq!(parsed.spi_c, 33333);
        assert_eq!(parsed.spi_s, 44444);
        assert_eq!(parsed.port_c, 6200);
        assert_eq!(parsed.port_s, 6201);
        assert_eq!(parsed.ealg.as_deref(), Some("null"));
    }

    #[test]
    fn parse_security_server_reads_pcscf_params() {
        // What a P-CSCF answers with — its own SPIs/ports, plus a protocol= it
        // is allowed to add (TS 33.203). The shared parser ignores protocol=.
        let header =
            "ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=55555; spi-s=66666; port-c=5064; port-s=5066; protocol=udp";
        let server = parse_security_server(header).unwrap();
        assert_eq!(server.spi_c, 55555);
        assert_eq!(server.spi_s, 66666);
        assert_eq!(server.port_c, 5064);
        assert_eq!(server.port_s, 5066);
        assert_eq!(
            IntegrityAlgorithm::from_sec_agree_name(&server.algorithm),
            Some(IntegrityAlgorithm::HmacSha1)
        );
    }

    #[test]
    fn build_security_verify_echoes_verbatim() {
        let server_value =
            "ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=55555; spi-s=66666; port-c=5064; port-s=5066";
        // Surrounding whitespace stripped, inner text preserved exactly.
        assert_eq!(
            build_security_verify(&format!("  {server_value}  ")),
            server_value
        );
    }

    #[test]
    fn algorithm_names_round_trip() {
        for alg in [
            IntegrityAlgorithm::HmacMd5,
            IntegrityAlgorithm::HmacSha1,
            IntegrityAlgorithm::HmacSha256,
        ] {
            assert_eq!(
                IntegrityAlgorithm::from_sec_agree_name(alg.sec_agree_name()),
                Some(alg)
            );
        }
        for ealg in [
            EncryptionAlgorithm::Null,
            EncryptionAlgorithm::AesCbc128,
            EncryptionAlgorithm::DesEde3Cbc,
        ] {
            assert_eq!(
                EncryptionAlgorithm::from_sec_agree_name(ealg.sec_agree_name()),
                Some(ealg)
            );
        }
        assert!(IntegrityAlgorithm::from_sec_agree_name("bogus").is_none());
    }
}
