//! RFC 4475 SIP torture-test corpus, driven from byte-exact fixtures.
//!
//! The fixtures under `corpus/` are the message files from RFC 4475, imported
//! verbatim (see `corpus/ATTRIBUTION.md` for provenance and licence). They are
//! deliberately adversarial about whitespace, header folding, escaping and
//! binary bodies, so they are stored as bytes and fed through
//! [`parse_sip_message_bytes`] rather than transcribed into Rust string
//! literals — hand-transcription destroys exactly the properties under test.
//!
//! # Classification
//!
//! Each fixture is classified by the RFC 4475 section it comes from, not by
//! any filename convention:
//!
//! * **§3.1.1 Valid Messages** — `Expect::Parse`. RFC 4475 §3.1 is titled
//!   "Parser Tests (syntax)"; these are syntactically well-formed and the
//!   parser must accept them. They must additionally reach a serialisation
//!   fixed point.
//! * **§3.1.2 Invalid Messages** — `Expect::Reject`. Syntactically invalid;
//!   the parser must reject them with a defined error rather than accept or
//!   panic.
//! * **§3.2 / §3.3 / §3.4** — `Expect::Parse`. §3.3 is explicitly
//!   "Application-Layer Semantics": these messages parse, and the torture is
//!   above the parser (missing required header fields, unknown schemes,
//!   multiple Content-Length, RFC 2543 syntax, ...). Rejecting them in the
//!   parser would be wrong — the application layer decides the response.
//!
//! Note that this classification is *not* the same as the `_V` / `_I` suffix
//! carried by the upstream filenames. That suffix records whether the source
//! project's own codec decodes the message, which diverges from the RFC's
//! verdict on 13 of the 50 files (nine `_V` files are RFC §3.1.2 invalid, and
//! four `_I` files are §3.3/§3.4 messages that parse). The RFC is the
//! authority here; the filenames are preserved only so fixtures can be traced
//! back to their source.

// The byte-level entry point, which is what the transport ingress path in
// `dispatcher` uses for received datagrams. It is not re-exported at
// `siphon::sip`, so reach it through the public `parser` module.
use siphon::sip::parser::parse_sip_message_bytes;

/// What the parser is required to do with a fixture.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Expect {
    /// Syntactically well-formed: the parser must accept it.
    Parse,
    /// Syntactically invalid: the parser must reject it with an error.
    Reject,
}

/// One corpus fixture and its RFC-derived contract.
struct Case {
    /// Fixture filename, preserved from the source project.
    file: &'static str,
    /// RFC 4475 section, or `"-"` for fixtures that are not RFC 4475 messages.
    section: &'static str,
    /// Section title, for failure output.
    title: &'static str,
    /// Required parser behaviour.
    expect: Expect,
    /// Byte-exact message.
    bytes: &'static [u8],
}

/// Outcome of running the parser over one fixture.
enum Outcome {
    Parsed,
    /// Rejected, carrying the parser's error so a fixture that was expected to
    /// parse reports *why* it did not.
    Rejected(String),
    Panicked,
}

/// Run the parser over `bytes`, converting a panic into an [`Outcome`] rather
/// than unwinding — one panicking fixture must not mask the other 49.
fn probe(bytes: &'static [u8]) -> Outcome {
    match std::panic::catch_unwind(|| parse_sip_message_bytes(bytes)) {
        Ok(Ok(_)) => Outcome::Parsed,
        Ok(Err(error)) => Outcome::Rejected(error),
        Err(_) => Outcome::Panicked,
    }
}

const CORPUS: &[Case] = &[
    // --- RFC 4475 §3.1.1 Valid Messages (syntax) -------------------------
    Case {
        file: "TC_WSINV.dat",
        section: "3.1.1.1",
        title: "A Short Tortuous INVITE",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_WSINV.dat"),
    },
    Case {
        file: "TC_INTMETH.dat",
        section: "3.1.1.2",
        title: "Wide Range of Valid Characters",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_INTMETH.dat"),
    },
    Case {
        file: "TC_ESC01_V.dat",
        section: "3.1.1.3",
        title: "Valid Use of the % Escaping Mechanism",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_ESC01_V.dat"),
    },
    Case {
        file: "TC_ESCNULL_V.dat",
        section: "3.1.1.4",
        title: "Escaped Nulls in URIs",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_ESCNULL_V.dat"),
    },
    Case {
        file: "TC_ESC02_V.dat",
        section: "3.1.1.5",
        title: "Use of % When It Is Not an Escape",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_ESC02_V.dat"),
    },
    Case {
        file: "TC_LWSDISP_V.dat",
        section: "3.1.1.6",
        title: "Message with No LWS between Display Name and <",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_LWSDISP_V.dat"),
    },
    Case {
        file: "TC_LONGREQ_V.dat",
        section: "3.1.1.7",
        title: "Long Values in Header Fields",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_LONGREQ_V.dat"),
    },
    Case {
        file: "TC_DBLREQ.dat",
        section: "3.1.1.8",
        title: "Extra Trailing Octets in a UDP Datagram",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_DBLREQ.dat"),
    },
    Case {
        file: "TC_SEMIURI_V.dat",
        section: "3.1.1.9",
        title: "Semicolon-Separated Parameters in URI User Part",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_SEMIURI_V.dat"),
    },
    Case {
        file: "TC_TRANSPORTS_V.dat",
        section: "3.1.1.10",
        title: "Varied and Unknown Transport Types",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_TRANSPORTS_V.dat"),
    },
    Case {
        file: "TC_MPART01.dat",
        section: "3.1.1.11",
        title: "Multipart MIME Message",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_MPART01.dat"),
    },
    Case {
        file: "TC_UNREASON_V.dat",
        section: "3.1.1.12",
        title: "Unusual Reason Phrase",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_UNREASON_V.dat"),
    },
    Case {
        file: "TC_NOREASON_V.dat",
        section: "3.1.1.13",
        title: "Empty Reason Phrase",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_NOREASON_V.dat"),
    },
    // --- RFC 4475 §3.1.2 Invalid Messages (syntax) -----------------------
    Case {
        file: "TC_BADINV01_I.dat",
        section: "3.1.2.1",
        title: "Extraneous Header Field Separators",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_BADINV01_I.dat"),
    },
    Case {
        file: "TC_CLERR_I.dat",
        section: "3.1.2.2",
        title: "Content Length Larger Than Message",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_CLERR_I.dat"),
    },
    Case {
        file: "TC_NCL_I.dat",
        section: "3.1.2.3",
        title: "Negative Content-Length",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_NCL_I.dat"),
    },
    Case {
        file: "TC_SCALAR02_V.dat",
        section: "3.1.2.4",
        title: "Request Scalar Fields with Overlarge Values",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_SCALAR02_V.dat"),
    },
    Case {
        file: "TC_SCALARLG_V.dat",
        section: "3.1.2.5",
        title: "Response Scalar Fields with Overlarge Values",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_SCALARLG_V.dat"),
    },
    Case {
        file: "TC_QUOTBAL_I.dat",
        section: "3.1.2.6",
        title: "Unterminated Quoted String in Display Name",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_QUOTBAL_I.dat"),
    },
    Case {
        file: "TC_LTGTRURI_I.dat",
        section: "3.1.2.7",
        title: "<> Enclosing Request-URI",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_LTGTRURI_I.dat"),
    },
    Case {
        file: "TC_LWSRURI_I.dat",
        section: "3.1.2.8",
        title: "Malformed SIP Request-URI (embedded LWS)",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_LWSRURI_I.dat"),
    },
    Case {
        file: "TC_LWSSTART_V.dat",
        section: "3.1.2.9",
        title: "Multiple SP Separating Request-Line Elements",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_LWSSTART_V.dat"),
    },
    Case {
        file: "TC_TRWS_I.dat",
        section: "3.1.2.10",
        title: "SP Characters at End of Request-Line",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_TRWS_I.dat"),
    },
    Case {
        file: "TC_ESCRURI_V.dat",
        section: "3.1.2.11",
        title: "Escaped Headers in SIP Request-URI",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_ESCRURI_V.dat"),
    },
    Case {
        file: "TC_BADDATE_V.dat",
        section: "3.1.2.12",
        title: "Invalid Time Zone in Date Header Field",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_BADDATE_V.dat"),
    },
    Case {
        file: "TC_REGBADCT_I.dat",
        section: "3.1.2.13",
        title: "Failure to Enclose name-addr URI in <>",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_REGBADCT_I.dat"),
    },
    Case {
        file: "TC_BADASPEC_I.dat",
        section: "3.1.2.14",
        title: "Spaces within addr-spec",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_BADASPEC_I.dat"),
    },
    Case {
        file: "TC_BADDN_I.dat",
        section: "3.1.2.15",
        title: "Non-token Characters in Display Name",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_BADDN_I.dat"),
    },
    Case {
        file: "TC_BADVERS_V.dat",
        section: "3.1.2.16",
        title: "Unknown Protocol Version",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_BADVERS_V.dat"),
    },
    Case {
        file: "TC_MISMATCH01_V.dat",
        section: "3.1.2.17",
        title: "Start Line and CSeq Method Mismatch",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_MISMATCH01_V.dat"),
    },
    Case {
        file: "TC_MISMATCH02_V.dat",
        section: "3.1.2.18",
        title: "Unknown Method with CSeq Method Mismatch",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_MISMATCH02_V.dat"),
    },
    Case {
        file: "TC_BIGCODE_V.dat",
        section: "3.1.2.19",
        title: "Overlarge Response Code",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_BIGCODE_V.dat"),
    },
    // --- RFC 4475 §3.2 / §3.3 / §3.4: parses, torture is above the parser -
    Case {
        file: "TC_BADBRANCH_V.dat",
        section: "3.2.1",
        title: "Missing Transaction Identifier",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_BADBRANCH_V.dat"),
    },
    Case {
        file: "TC_INSUF_I.dat",
        section: "3.3.1",
        title: "Missing Required Header Fields",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_INSUF_I.dat"),
    },
    Case {
        file: "TC_UNKSCM_V.dat",
        section: "3.3.2",
        title: "Request-URI with Unknown Scheme",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_UNKSCM_V.dat"),
    },
    Case {
        file: "TC_NOVELSC_V.dat",
        section: "3.3.3",
        title: "Request-URI with Known but Atypical Scheme",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_NOVELSC_V.dat"),
    },
    Case {
        file: "TC_UNKSM2_V.dat",
        section: "3.3.4",
        title: "Unknown URI Schemes in Header Fields",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_UNKSM2_V.dat"),
    },
    Case {
        file: "TC_BEXT01_V.dat",
        section: "3.3.5",
        title: "Proxy-Require and Require",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_BEXT01_V.dat"),
    },
    Case {
        file: "TC_INVUT_V.dat",
        section: "3.3.6",
        title: "Unknown Content-Type",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_INVUT_V.dat"),
    },
    Case {
        file: "TC_REGAUT01_V.dat",
        section: "3.3.7",
        title: "Unknown Authorization Scheme",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_REGAUT01_V.dat"),
    },
    Case {
        file: "TC_MULTI01_I.dat",
        section: "3.3.8",
        title: "Multiple Values in Single Value Required Fields",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_MULTI01_I.dat"),
    },
    Case {
        file: "TC_MCL01_I.dat",
        section: "3.3.9",
        title: "Multiple Content-Length Values",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_MCL01_I.dat"),
    },
    Case {
        file: "TC_BCAST_V.dat",
        section: "3.3.10",
        title: "200 OK Response with Broadcast Via Header Field Value",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_BCAST_V.dat"),
    },
    Case {
        file: "TC_ZEROMF_V.dat",
        section: "3.3.11",
        title: "Max-Forwards of Zero",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_ZEROMF_V.dat"),
    },
    Case {
        file: "TC_CPARAM01_V.dat",
        section: "3.3.12",
        title: "REGISTER with a Contact Header Parameter",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_CPARAM01_V.dat"),
    },
    Case {
        file: "TC_CPARAM02_V.dat",
        section: "3.3.13",
        title: "REGISTER with a url-parameter",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_CPARAM02_V.dat"),
    },
    Case {
        file: "TC_REGESCRT_V.dat",
        section: "3.3.14",
        title: "REGISTER with a URL Escaped Header",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_REGESCRT_V.dat"),
    },
    Case {
        file: "TC_SDP01_V.dat",
        section: "3.3.15",
        title: "Unacceptable Accept Offering",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_SDP01_V.dat"),
    },
    Case {
        file: "TC_INV2543_I.dat",
        section: "3.4.1",
        title: "INVITE with RFC 2543 Syntax",
        expect: Expect::Parse,
        bytes: include_bytes!("corpus/TC_INV2543_I.dat"),
    },
    // --- Not an RFC 4475 message ----------------------------------------
    // Carried by the upstream corpus but absent from RFC 4475. The request
    // line has no SIP-Version and the header block contains a line with no
    // colon ("Foobar roobar"), so it is malformed on its own terms.
    Case {
        file: "TC_TEST_I.dat",
        section: "-",
        title: "Non-RFC fixture: no SIP-Version in request line",
        expect: Expect::Reject,
        bytes: include_bytes!("corpus/TC_TEST_I.dat"),
    },
];

/// A fixture whose current behaviour deviates from the RFC-derived contract.
struct Deviation {
    /// Fixture filename.
    file: &'static str,
    /// Short identifier for the underlying defect. Fixtures sharing an id share
    /// a root cause and are fixed by the same change.
    defect: &'static str,
    /// What the parser does today, and what the RFC requires instead.
    note: &'static str,
}

/// The parser's current deviations from RFC 4475, enumerated.
///
/// This list is not a way to excuse the failures — it is how they are kept
/// visible and machine-checked. [`messages_parse_or_are_rejected_per_rfc4475`]
/// fails if a fixture deviates *without* an entry here (a regression), and
/// equally fails if an entry here no longer deviates (a fix landed and the list
/// is now stale). So the gap can only shrink deliberately, and it can never
/// rot silently.
///
/// Six fixtures fail to parse, from three distinct grammar defects:
///
/// * `HCOLON-WS` — RFC 3261 §25.1 defines
///   `HCOLON = *( SP / HTAB ) ":" SWS`, so whitespace between a header name
///   and its colon is legal. The header parser rejects it.
/// * `METHOD-TOKEN` — `Method = INVITEm / ... / extension-method`, and
///   `extension-method = token`, where `token` admits
///   `alphanum / "-" / "." / "!" / "%" / "*" / "_" / "+" / "`" / "'" / "~"`.
///   The start-line parser does not accept the full set.
/// * `RURI-ABSOLUTEURI` — `Request-URI = SIP-URI / SIPS-URI / absoluteURI`.
///   A Request-URI in an unknown or atypical scheme is syntactically valid;
///   RFC 3261 §8.2.2 makes it a 416 Unsupported URI Scheme at the application
///   layer, not a parse failure.
///
/// The remaining fourteen parse when RFC 4475 §3.1.2 classifies them invalid.
/// Some of those are defensible in a permissive parser that leaves the 400 to
/// the application layer; the scalar and framing ones (`CL-FRAMING`,
/// `SCALAR-RANGE`) are not, because nothing above the parser can recover a
/// length or a scalar that was already accepted out of range.
const KNOWN_DEVIATIONS: &[Deviation] = &[
    // --- parse but RFC 4475 §3.1.2 classifies invalid --------------------
    Deviation {
        file: "TC_CLERR_I.dat",
        defect: "CL-FRAMING",
        note: "accepts Content-Length larger than the message body",
    },
    Deviation {
        file: "TC_NCL_I.dat",
        defect: "CL-FRAMING",
        note: "accepts a negative Content-Length",
    },
    Deviation {
        file: "TC_SCALAR02_V.dat",
        defect: "SCALAR-RANGE",
        note: "accepts overlarge request scalars (Max-Forwards, CSeq, Expires)",
    },
    Deviation {
        file: "TC_SCALARLG_V.dat",
        defect: "SCALAR-RANGE",
        note: "accepts overlarge response scalars",
    },
    Deviation {
        file: "TC_QUOTBAL_I.dat",
        defect: "PERMISSIVE-SYNTAX",
        note: "accepts an unterminated quoted string in a display name",
    },
    Deviation {
        file: "TC_BADINV01_I.dat",
        defect: "PERMISSIVE-SYNTAX",
        note: "accepts extraneous header field separators",
    },
    Deviation {
        file: "TC_LWSSTART_V.dat",
        defect: "PERMISSIVE-SYNTAX",
        note: "accepts multiple SP separating request-line elements",
    },
    Deviation {
        file: "TC_ESCRURI_V.dat",
        defect: "PERMISSIVE-SYNTAX",
        note: "accepts escaped headers in the Request-URI",
    },
    Deviation {
        file: "TC_BADDATE_V.dat",
        defect: "PERMISSIVE-SYNTAX",
        note: "accepts an invalid time zone in Date",
    },
    Deviation {
        file: "TC_REGBADCT_I.dat",
        defect: "PERMISSIVE-SYNTAX",
        note: "accepts a name-addr URI not enclosed in <>",
    },
    Deviation {
        file: "TC_BADASPEC_I.dat",
        defect: "PERMISSIVE-SYNTAX",
        note: "accepts spaces within addr-spec",
    },
    Deviation {
        file: "TC_BADVERS_V.dat",
        defect: "PERMISSIVE-SEMANTIC",
        note: "accepts SIP/7.0; RFC 4475 expects 505 from the element",
    },
    Deviation {
        file: "TC_MISMATCH01_V.dat",
        defect: "PERMISSIVE-SEMANTIC",
        note: "accepts start-line/CSeq method mismatch (cross-field check)",
    },
    Deviation {
        file: "TC_MISMATCH02_V.dat",
        defect: "PERMISSIVE-SEMANTIC",
        note: "accepts unknown method with CSeq method mismatch",
    },
];

/// Guards against a fixture being added to `corpus/` without a matching
/// classification, or a `CORPUS` entry losing its file.
#[test]
fn corpus_is_completely_classified() {
    assert_eq!(CORPUS.len(), 50, "corpus should hold all 50 fixtures");

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/rfc4475/corpus");
    let on_disk: Vec<String> = std::fs::read_dir(dir)
        .expect("corpus directory should exist")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".dat"))
        .collect();

    assert_eq!(
        on_disk.len(),
        CORPUS.len(),
        "every .dat fixture on disk must be classified in CORPUS"
    );

    for case in CORPUS {
        assert!(
            on_disk.iter().any(|name| name == case.file),
            "{} is classified but missing from corpus/",
            case.file
        );
        assert!(
            !case.bytes.is_empty(),
            "{} should not be empty — check the import",
            case.file
        );
    }
}

/// The corpus contract: RFC §3.1.1, §3.2, §3.3 and §3.4 messages parse;
/// RFC §3.1.2 messages are rejected. Every fixture is run, and all deviations
/// are reported together so one run yields the complete picture.
#[test]
fn messages_parse_or_are_rejected_per_rfc4475() {
    let mut regressions = Vec::new();
    let mut deviating = Vec::new();

    for case in CORPUS {
        let outcome = probe(case.bytes);
        let deviation = match (case.expect, &outcome) {
            (Expect::Parse, Outcome::Parsed) | (Expect::Reject, Outcome::Rejected(_)) => None,
            (Expect::Parse, Outcome::Rejected(error)) => {
                Some(format!("expected parse, was rejected: {error}"))
            }
            (Expect::Reject, Outcome::Parsed) => Some("expected rejection, parsed".to_string()),
            // A panic is never tolerated, whatever KNOWN_DEVIATIONS says.
            (_, Outcome::Panicked) => {
                regressions.push(format!(
                    "  {:<22} §{:<9} {:<46} parser PANICKED",
                    case.file, case.section, case.title
                ));
                continue;
            }
        };

        let Some(reason) = deviation else { continue };
        deviating.push(case.file);

        if !KNOWN_DEVIATIONS
            .iter()
            .any(|known| known.file == case.file)
        {
            regressions.push(format!(
                "  {:<22} §{:<9} {:<46} {}",
                case.file, case.section, case.title, reason
            ));
        }
    }

    // A listed deviation that no longer reproduces means the defect was fixed.
    // Fail so the list is pruned in the same change, rather than drifting into
    // a record of problems that no longer exist.
    let stale: Vec<String> = KNOWN_DEVIATIONS
        .iter()
        .filter(|known| !deviating.contains(&known.file))
        .map(|known| format!("  {:<22} [{}] {}", known.file, known.defect, known.note))
        .collect();

    assert!(
        regressions.is_empty(),
        "{} fixture(s) deviate from RFC 4475 without a KNOWN_DEVIATIONS entry \
         — this is a regression, fix the parser rather than extending the list:\n{}",
        regressions.len(),
        regressions.join("\n")
    );

    assert!(
        stale.is_empty(),
        "{} KNOWN_DEVIATIONS entr(y/ies) no longer reproduce. The defect appears \
         fixed — remove the entry so the list stays accurate:\n{}",
        stale.len(),
        stale.join("\n")
    );
}

/// `KNOWN_DEVIATIONS` must only ever name fixtures that exist, so a renamed or
/// removed fixture cannot leave a dangling entry behind.
#[test]
fn known_deviations_reference_real_fixtures() {
    for known in KNOWN_DEVIATIONS {
        assert!(
            CORPUS.iter().any(|case| case.file == known.file),
            "KNOWN_DEVIATIONS names {}, which is not in CORPUS",
            known.file
        );
    }
}

/// A message the parser accepts must survive re-serialisation: parsing its own
/// output must produce the same wire form again.
///
/// The comparison is between round one and round two, not against the original
/// bytes — these messages carry deliberately abnormal whitespace, header
/// folding and case, all of which a parser is entitled to canonicalise on the
/// way out. What is not acceptable is for the form to keep drifting, which
/// would mean the parser and serialiser disagree.
#[test]
fn valid_messages_reach_a_serialisation_fixed_point() {
    let mut failures = Vec::new();

    for case in CORPUS.iter().filter(|case| case.expect == Expect::Parse) {
        let Ok(first) = parse_sip_message_bytes(case.bytes) else {
            // Covered by messages_parse_or_are_rejected_per_rfc4475; skip here
            // so a parse regression reports once, against the contract test.
            continue;
        };

        let wire_one = first.to_bytes();
        match parse_sip_message_bytes(&wire_one) {
            Ok(second) => {
                let wire_two = second.to_bytes();
                if wire_one != wire_two {
                    failures.push(format!(
                        "  {:<22} RFC 4475 §{:<9} serialisation not stable across re-parse",
                        case.file, case.section
                    ));
                }
            }
            Err(error) => failures.push(format!(
                "  {:<22} RFC 4475 §{:<9} own output failed to re-parse: {error}",
                case.file, case.section
            )),
        }
    }

    assert!(
        failures.is_empty(),
        "{} fixture(s) failed the serialisation fixed-point check:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// No fixture, valid or invalid, may panic the parser. This is the one
/// invariant that holds regardless of how the parse/reject contract is
/// resolved for any individual message.
#[test]
fn no_fixture_panics_the_parser() {
    let panicked: Vec<&str> = CORPUS
        .iter()
        .filter(|case| matches!(probe(case.bytes), Outcome::Panicked))
        .map(|case| case.file)
        .collect();

    assert!(
        panicked.is_empty(),
        "parser panicked on {} fixture(s): {}",
        panicked.len(),
        panicked.join(", ")
    );
}
