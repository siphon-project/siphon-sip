//! The Security-Client offer of an IMS UE entry, named explicitly.
//!
//! By default the UE offers the preferred `(alg, ealg)` pair, then HMAC-SHA-1-96
//! and HMAC-MD5-96 with the same ealg (see [`super::UeIpsec::new`]): two
//! `ipsec-3gpp` mechanisms for the defaults. `ipsec_offer=` in
//! `registration.add()` and `offer:` in a YAML `registrant` entry replace that
//! with a list of `(alg, ealg)` pairs, each its own mechanism in Security-Client
//! (RFC 3329 clause 2.2, 3GPP TS 33.203 clause 6.1 and Annex H), in the order
//! given: a UE that offers only `hmac-sha-1-96` with `aes-cbc`, say, or three
//! pairs. The tokens are the ones `src/ipsec` implements.

use crate::ipsec::ue::UeTransform;
use crate::ipsec::{EncryptionAlgorithm, IntegrityAlgorithm};

use super::UeIpsec;

/// Parse `(alg, ealg)` token pairs into an offer.
///
/// Refused: an empty list, an `alg` or `ealg` this build does not implement
/// (the message names the valid tokens), and the same pair twice (it would
/// send one mechanism twice).
pub fn parse_ipsec_offer<A, E>(pairs: &[(A, E)]) -> Result<Vec<UeTransform>, String>
where
    A: AsRef<str>,
    E: AsRef<str>,
{
    if pairs.is_empty() {
        return Err("the ipsec offer needs at least one (alg, ealg) pair".to_string());
    }
    let mut offer: Vec<UeTransform> = Vec::with_capacity(pairs.len());
    for (alg_token, ealg_token) in pairs {
        let (alg_token, ealg_token) = (alg_token.as_ref(), ealg_token.as_ref());
        let alg = IntegrityAlgorithm::from_sec_agree_name(alg_token).ok_or_else(|| {
            format!(
                "unknown ipsec alg '{alg_token}' (one of {})",
                INTEGRITY_TOKENS.join(", ")
            )
        })?;
        let ealg = EncryptionAlgorithm::from_sec_agree_name(ealg_token).ok_or_else(|| {
            format!(
                "unknown ipsec ealg '{ealg_token}' (one of {})",
                ENCRYPTION_TOKENS.join(", ")
            )
        })?;
        if offer.contains(&(alg, ealg)) {
            return Err(format!(
                "the ipsec offer names ({alg_token}, {ealg_token}) twice"
            ));
        }
        offer.push((alg, ealg));
    }
    Ok(offer)
}

const INTEGRITY_TOKENS: [&str; 3] = ["hmac-sha-1-96", "hmac-md5-96", "hmac-sha-256-128"];
const ENCRYPTION_TOKENS: [&str; 3] = ["null", "aes-cbc", "des-ede3-cbc"];

impl UeIpsec {
    /// Offer exactly `offer` in Security-Client, in order, instead of the
    /// default set; the first pair is the one a fresh handshake starts from.
    /// An empty `offer` leaves the default in place.
    pub fn with_offer(mut self, offer: Vec<UeTransform>) -> Self {
        if let Some((aalg, ealg)) = offer.first().copied() {
            self.aalg = aalg;
            self.ealg = ealg;
            self.offered = offer;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(offer: &UeIpsec) -> String {
        crate::ipsec::ue::build_security_client(&offer.offer())
    }

    fn ue(offer: Option<Vec<UeTransform>>) -> UeIpsec {
        let ipsec = UeIpsec::new(
            6100,
            6101,
            IntegrityAlgorithm::HmacSha1,
            EncryptionAlgorithm::Null,
        );
        match offer {
            Some(offer) => ipsec.with_offer(offer),
            None => ipsec,
        }
    }

    #[test]
    fn the_default_offer_is_the_two_mechanisms_it_always_was() {
        let header = header(&ue(None));
        let mechanisms: Vec<&str> = header.split(", ").collect();
        assert_eq!(mechanisms.len(), 2);
        assert!(mechanisms[0].ends_with("alg=hmac-sha-1-96;ealg=null"));
        assert!(mechanisms[1].ends_with("alg=hmac-md5-96;ealg=null"));
    }

    #[test]
    fn a_single_pair_is_a_single_mechanism() {
        let offer = parse_ipsec_offer(&[("hmac-sha-1-96", "aes-cbc")]).expect("a valid pair");
        let header = header(&ue(Some(offer)));
        assert_eq!(
            header,
            "ipsec-3gpp;prot=esp;mod=trans;spi-c=0;spi-s=0;port-c=6100;port-s=6101;alg=hmac-sha-1-96;ealg=aes-cbc"
        );
    }

    #[test]
    fn two_pairs_are_two_mechanisms_in_the_order_given() {
        let offer = parse_ipsec_offer(&[("hmac-md5-96", "null"), ("hmac-sha-1-96", "aes-cbc")])
            .expect("valid pairs");
        let header = header(&ue(Some(offer)));
        let mechanisms: Vec<&str> = header.split(", ").collect();
        assert_eq!(mechanisms.len(), 2);
        assert!(mechanisms[0].ends_with("alg=hmac-md5-96;ealg=null"));
        assert!(mechanisms[1].ends_with("alg=hmac-sha-1-96;ealg=aes-cbc"));
    }

    #[test]
    fn the_first_pair_is_the_one_a_fresh_handshake_starts_from() {
        let offer = parse_ipsec_offer(&[("hmac-md5-96", "aes-cbc"), ("hmac-sha-1-96", "null")])
            .expect("valid pairs");
        let mut ipsec = ue(Some(offer));
        assert_eq!(ipsec.aalg, IntegrityAlgorithm::HmacMd5);
        assert_eq!(ipsec.ealg, EncryptionAlgorithm::AesCbc128);
        // The P-CSCF picks the second; a later handshake reset starts over and
        // the offer itself never changes.
        ipsec.aalg = IntegrityAlgorithm::HmacSha1;
        ipsec.ealg = EncryptionAlgorithm::Null;
        let before = header(&ipsec);
        ipsec.reset_handshake();
        assert_eq!(ipsec.aalg, IntegrityAlgorithm::HmacMd5);
        assert_eq!(ipsec.ealg, EncryptionAlgorithm::AesCbc128);
        assert_eq!(header(&ipsec), before);
    }

    #[test]
    fn an_unknown_alg_or_ealg_is_refused_naming_the_valid_ones() {
        let error = parse_ipsec_offer(&[("hmac-sha-9-9", "null")]).expect_err("unknown alg");
        assert!(error.contains("hmac-sha-9-9"), "{error}");
        assert!(error.contains("hmac-md5-96"), "{error}");
        let error = parse_ipsec_offer(&[("hmac-sha-1-96", "rot13")]).expect_err("unknown ealg");
        assert!(error.contains("rot13"), "{error}");
        assert!(error.contains("aes-cbc"), "{error}");
        // One bad pair refuses the whole offer.
        assert!(parse_ipsec_offer(&[("hmac-sha-1-96", "null"), ("nope", "null")]).is_err());
    }

    #[test]
    fn an_empty_offer_and_a_repeated_pair_are_refused() {
        let none: [(&str, &str); 0] = [];
        assert!(parse_ipsec_offer(&none).is_err());
        let error = parse_ipsec_offer(&[("hmac-sha-1-96", "null"), ("HMAC-SHA-1-96", "null")])
            .expect_err("the same pair twice");
        assert!(error.contains("twice"), "{error}");
        // The same alg with another ealg is a different mechanism.
        assert!(
            parse_ipsec_offer(&[("hmac-sha-1-96", "null"), ("hmac-sha-1-96", "aes-cbc")]).is_ok()
        );
    }

    #[test]
    fn every_token_the_message_lists_parses() {
        for alg in INTEGRITY_TOKENS {
            assert!(
                IntegrityAlgorithm::from_sec_agree_name(alg).is_some(),
                "{alg}"
            );
        }
        for ealg in ENCRYPTION_TOKENS {
            assert!(
                EncryptionAlgorithm::from_sec_agree_name(ealg).is_some(),
                "{ealg}"
            );
        }
    }
}
