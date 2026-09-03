//! Schema validation of X1 messages against the published ETSI XSDs.
//!
//! Every inbound request and every outbound response is validated against the
//! schemas in `schemas/etsi/`, in both directions. Validating only on the way
//! in would let a malformed response of ours reach the ADMF and fail there
//! instead of here.
//!
//! The schemas are the ETSI originals, byte-for-byte:
//!
//! * `TS_103_221_01.xsd` — TS 103 221-1 v1.23.1
//! * `TS_103_221_01_HashedID.xsd` — v1.10.1
//! * `TS_103_221_01_DestinationSet.xsd` — v1.11.1
//! * `TS_103_280_v021701.xsd` — the TS 103 280 v2.19.1 package's dictionary
//!   (which declares `version="2.17.1"`; the schema did not change across
//!   those releases, so that is expected rather than a mismatch)
//!
//! `X1All.xsd` is ours: the published modules declare `<xs:import>` with no
//! `schemaLocation`, so a validator cannot find them on its own, and the
//! wrapper supplies the locations. It deliberately omits `TrafficPolicy` and
//! `Configuration`, which pull in TS 103 120 and TS 104 000 — neither is part
//! of this profile and including them would fail to compile.
//!
//! # Why a validator *and* typed values
//!
//! `uppsala` does not inherit pattern facets through an empty
//! `<xs:restriction base="…"/>`, which is precisely how TS 103 221-1 derives
//! `XId`, `DId` and `X1TransactionId` from the dictionary's `UUID` type — so
//! it accepts `<x1TransactionId>not-a-uuid</x1TransactionId>` where `xmllint`
//! rejects it. Those identifiers are therefore parsed into real `Uuid` values
//! by [`super::types`], and the test suite validates the same documents with
//! `xmllint` as an independent decoder. Three layers, each covering what the
//! others miss.

use std::io::Write;
use std::path::Path;

use tracing::debug;
use uppsala::xsd::XsdValidator;

use super::error::X1Error;

/// The wrapper that gives the published modules resolvable import locations.
const X1_ALL_XSD: &str = include_str!("../../../schemas/etsi/X1All.xsd");
/// TS 103 221-1 v1.23.1, verbatim from ETSI.
const X1_XSD: &str = include_str!("../../../schemas/etsi/TS_103_221_01.xsd");
/// TS 103 221-1 HashedID module, verbatim from ETSI.
const X1_HASHED_ID_XSD: &str = include_str!("../../../schemas/etsi/TS_103_221_01_HashedID.xsd");
/// TS 103 221-1 DestinationSet module, verbatim from ETSI.
const X1_DESTINATION_SET_XSD: &str =
    include_str!("../../../schemas/etsi/TS_103_221_01_DestinationSet.xsd");
/// TS 103 280 dictionary, verbatim from ETSI.
const COMMON_XSD: &str = include_str!("../../../schemas/etsi/TS_103_280_v021701.xsd");

/// The schema files, as `(filename, contents)`.
///
/// The filenames must match the `schemaLocation` values in `X1All.xsd`.
const SCHEMA_FILES: &[(&str, &str)] = &[
    ("X1All.xsd", X1_ALL_XSD),
    ("TS_103_221_01.xsd", X1_XSD),
    ("TS_103_221_01_HashedID.xsd", X1_HASHED_ID_XSD),
    ("TS_103_221_01_DestinationSet.xsd", X1_DESTINATION_SET_XSD),
    ("TS_103_280_v021701.xsd", COMMON_XSD),
];

/// A compiled X1 schema validator.
///
/// Compilation costs about a millisecond and happens once, when the LI
/// subsystem starts. Validating one message costs tens of microseconds, which
/// is immaterial on a provisioning interface.
pub struct X1Schema {
    validator: XsdValidator,
}

impl std::fmt::Debug for X1Schema {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // XsdValidator is not Debug; the compiled schema has no useful state
        // to print anyway.
        formatter.debug_struct("X1Schema").finish_non_exhaustive()
    }
}

impl X1Schema {
    /// Compile the embedded schemas.
    ///
    /// The XSDs are baked into the binary with `include_str!`, so there is no
    /// deployment-time file dependency. They are written to a scratch
    /// directory only because the validator resolves `schemaLocation` through
    /// the filesystem; the compiled validator outlives the directory, which is
    /// removed before this function returns.
    pub fn compile() -> Result<Self, X1Error> {
        let scratch = tempfile::Builder::new()
            .prefix("siphon-x1-schema-")
            .tempdir()
            .map_err(|error| {
                X1Error::syntax(format!(
                    "could not create a scratch directory for the X1 schemas: {error}"
                ))
            })?;

        for (name, contents) in SCHEMA_FILES {
            let path = scratch.path().join(name);
            let mut file = std::fs::File::create(&path).map_err(|error| {
                X1Error::syntax(format!("could not write schema {name}: {error}"))
            })?;
            file.write_all(contents.as_bytes()).map_err(|error| {
                X1Error::syntax(format!("could not write schema {name}: {error}"))
            })?;
        }

        let entry = scratch.path().join("X1All.xsd");
        let validator = Self::compile_from(&entry)?;

        // `scratch` drops here, removing the directory. The compiled
        // validator holds no path references.
        drop(scratch);

        debug!("X1 schema set compiled");
        Ok(Self { validator })
    }

    /// Compile from an on-disk entry point. Split out so tests can compile the
    /// repository's own `schemas/etsi/` copies directly.
    fn compile_from(entry: &Path) -> Result<XsdValidator, X1Error> {
        let source = std::fs::read_to_string(entry).map_err(|error| {
            X1Error::syntax(format!(
                "could not read the X1 schema entry point {}: {error}",
                entry.display()
            ))
        })?;
        let document = uppsala::parse(&source).map_err(|error| {
            X1Error::syntax(format!(
                "the X1 schema entry point does not parse: {error:?}"
            ))
        })?;
        XsdValidator::from_schema_with_base_path(&document, entry.parent()).map_err(|error| {
            X1Error::syntax(format!("the X1 schema set does not compile: {error:?}"))
        })
    }

    /// Validate an X1 document.
    ///
    /// Returns the first few validation errors joined into one description —
    /// a schema failure usually cascades, and the first error is the one that
    /// tells the operator what to fix.
    pub fn validate(&self, xml: &str) -> Result<(), X1Error> {
        let document = uppsala::parse(xml)
            .map_err(|error| X1Error::syntax(format!("XML does not parse: {error:?}")))?;

        let errors = self.validator.validate(&document);
        if errors.is_empty() {
            return Ok(());
        }

        let detail = errors
            .iter()
            .take(3)
            .map(|error| error.message.clone())
            .collect::<Vec<_>>()
            .join("; ");
        let more = errors.len().saturating_sub(3);
        let suffix = if more > 0 {
            format!(" (and {more} more)")
        } else {
            String::new()
        };
        Err(X1Error::syntax(format!(
            "schema validation failed: {detail}{suffix}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared compiled schema — compiling per test would dominate the run.
    fn schema() -> &'static X1Schema {
        use std::sync::OnceLock;
        static SCHEMA: OnceLock<X1Schema> = OnceLock::new();
        SCHEMA.get_or_init(|| X1Schema::compile().expect("embedded X1 schemas must compile"))
    }

    fn activate_task(target_element: &str, target_value: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<X1Request xmlns="http://uri.etsi.org/03221/X1/2017/10"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <x1RequestMessage xsi:type="ActivateTaskRequest">
    <admfIdentifier>admf-id</admfIdentifier>
    <neIdentifier>siphon-ne</neIdentifier>
    <messageTimestamp>2026-08-31T09:00:00.000000Z</messageTimestamp>
    <version>v1.23.1</version>
    <x1TransactionId>0f3b7a1c-2d4e-4f60-8a91-1b2c3d4e5f60</x1TransactionId>
    <taskDetails>
      <xId>11111111-2222-3333-4444-555555555555</xId>
      <targetIdentifiers>
        <targetIdentifier><{target_element}>{target_value}</{target_element}></targetIdentifier>
      </targetIdentifiers>
      <deliveryType>X2andX3</deliveryType>
      <listOfDIDs><dId>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</dId></listOfDIDs>
    </taskDetails>
  </x1RequestMessage>
</X1Request>"#
        )
    }

    fn create_destination(ipv6: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<X1Request xmlns="http://uri.etsi.org/03221/X1/2017/10"
           xmlns:c="http://uri.etsi.org/03280/common/2017/07"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <x1RequestMessage xsi:type="CreateDestinationRequest">
    <admfIdentifier>admf-id</admfIdentifier>
    <neIdentifier>siphon-ne</neIdentifier>
    <messageTimestamp>2026-08-31T09:00:00.000000Z</messageTimestamp>
    <version>v1.23.1</version>
    <x1TransactionId>0f3b7a1c-2d4e-4f60-8a91-1b2c3d4e5f61</x1TransactionId>
    <destinationDetails>
      <dId>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</dId>
      <deliveryType>X2andX3</deliveryType>
      <deliveryAddress>
        <ipAddressAndPort>
          <c:address><c:IPv6Address>{ipv6}</c:IPv6Address></c:address>
          <c:port><c:TCPPort>42069</c:TCPPort></c:port>
        </ipAddressAndPort>
      </deliveryAddress>
    </destinationDetails>
  </x1RequestMessage>
</X1Request>"#
        )
    }

    #[test]
    fn embedded_schemas_compile() {
        // If this fails, everything else in the module is moot.
        let _ = schema();
    }

    #[test]
    fn a_well_formed_activate_task_validates() {
        schema()
            .validate(&activate_task("sipUri", "sip:alice@example.com"))
            .expect("a conformant ActivateTask must validate");
    }

    #[test]
    fn an_unknown_xsi_type_is_rejected() {
        let xml = activate_task("sipUri", "sip:a@b.com").replace("ActivateTaskRequest", "Nonsense");
        assert!(schema().validate(&xml).is_err());
    }

    #[test]
    fn the_out_of_profile_generic_object_types_are_still_schema_valid() {
        // They are in the schema, so they must pass validation and be refused
        // at dispatch with UnsupportedRequest — not fail the container here.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<X1Request xmlns="http://uri.etsi.org/03221/X1/2017/10"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <x1RequestMessage xsi:type="DeleteAllObjectsRequest">
    <admfIdentifier>admf-id</admfIdentifier>
    <neIdentifier>siphon-ne</neIdentifier>
    <messageTimestamp>2026-08-31T09:00:00.000000Z</messageTimestamp>
    <version>v1.23.1</version>
    <x1TransactionId>0f3b7a1c-2d4e-4f60-8a91-1b2c3d4e5f62</x1TransactionId>
  </x1RequestMessage>
</X1Request>"#;
        schema()
            .validate(xml)
            .expect("an out-of-profile message must still be schema-valid");
    }

    #[test]
    fn a_missing_mandatory_element_is_rejected() {
        let xml = activate_task("sipUri", "sip:a@b.com")
            .replace("<deliveryType>X2andX3</deliveryType>", "");
        assert!(schema().validate(&xml).is_err());
    }

    #[test]
    fn an_out_of_enumeration_delivery_type_is_rejected() {
        // Catches the natural-looking but wrong "X2AndX3" casing.
        let xml = activate_task("sipUri", "sip:a@b.com").replace("X2andX3", "X2AndX3");
        assert!(schema().validate(&xml).is_err());
    }

    #[test]
    fn a_malformed_sip_uri_is_rejected() {
        assert!(schema()
            .validate(&activate_task("sipUri", "alice@example.com"))
            .is_err());
    }

    #[test]
    fn a_timestamp_without_microseconds_is_rejected() {
        let xml = activate_task("sipUri", "sip:a@b.com")
            .replace("2026-08-31T09:00:00.000000Z", "2026-08-31T09:00:00Z");
        assert!(schema().validate(&xml).is_err());
    }

    #[test]
    fn a_version_outside_the_pattern_is_rejected() {
        let xml = activate_task("sipUri", "sip:a@b.com").replace("v1.23.1", "1.23.1");
        assert!(schema().validate(&xml).is_err());
    }

    // -- the IPv6 rule --------------------------------------------------

    #[test]
    fn an_expanded_ipv6_destination_validates() {
        schema()
            .validate(&create_destination(
                "2001:0db8:0000:0000:0000:0000:0000:0001",
            ))
            .expect("an expanded IPv6 destination must validate");
    }

    #[test]
    fn a_compressed_ipv6_destination_is_rejected() {
        // The compressed form is what every convenient IPv6 formatter emits,
        // so this is the likeliest first-interop failure and the one worth a
        // test of its own.
        let error = schema()
            .validate(&create_destination("2001:db8::1"))
            .expect_err("a compressed IPv6 address must fail the schema");
        assert!(
            error.description.contains("2001:db8::1"),
            "the error should name the offending value, got: {}",
            error.description
        );
    }

    #[test]
    fn an_uppercase_ipv6_destination_is_rejected() {
        assert!(schema()
            .validate(&create_destination(
                "2001:0DB8:0000:0000:0000:0000:0000:0001"
            ))
            .is_err());
    }

    #[test]
    fn malformed_xml_is_reported_as_a_syntax_error() {
        let error = schema()
            .validate("<X1Request><unclosed>")
            .expect_err("malformed XML must be rejected");
        assert_eq!(
            error.code,
            super::super::error::ErrorCode::SyntaxSchemaError
        );
    }

    #[test]
    fn an_empty_container_is_rejected() {
        // The schema requires at least one x1RequestMessage.
        let xml = r#"<?xml version="1.0"?>
<X1Request xmlns="http://uri.etsi.org/03221/X1/2017/10"/>"#;
        assert!(schema().validate(xml).is_err());
    }

    #[test]
    fn the_repository_copies_match_what_is_embedded() {
        // Guards against someone updating schemas/etsi/ without rebuilding,
        // or editing the embedded copy out of step with the shipped files.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/etsi");
        for (name, embedded) in SCHEMA_FILES {
            let on_disk = std::fs::read_to_string(root.join(name))
                .unwrap_or_else(|error| panic!("schemas/etsi/{name} is missing: {error}"));
            assert_eq!(
                on_disk, *embedded,
                "schemas/etsi/{name} differs from the embedded copy"
            );
        }
    }

    #[test]
    fn the_shipped_schemas_declare_the_expected_versions() {
        // The schema-selection decision is v1.23.1 + the TS 103 280 v2.19.1
        // package. If someone swaps a file, this says so.
        assert!(
            X1_XSD.contains(r#"version="1.23.1""#),
            "TS_103_221_01.xsd is not v1.23.1"
        );
        assert!(
            COMMON_XSD.contains(r#"version="2.17.1""#),
            "the dictionary is not the 2.19.1 package's 2.17.1-declared XSD"
        );
        // The namespaces are what everything else keys on.
        assert!(X1_XSD.contains(super::super::types::NS_X1));
        assert!(COMMON_XSD.contains(super::super::types::NS_COMMON));
    }
}
