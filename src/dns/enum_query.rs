//! ENUM queries that say what happened (RFC 6116 section 5.2), follow
//! non-terminal NAPTR records (RFC 6116 section 5.2.1, RFC 3402 section 3.3)
//! and hand back every usable URI in ORDER / PREFERENCE sequence.
//!
//! [`enum_query`] walks the DDDS loop over an abstract [`NaptrSource`], so the
//! walk is tested against a table of answers and the network sits behind the
//! two sources a node has: its own resolver, or a list of ENUM servers with
//! failover ([`super::enum_servers::EnumServers`]).

use std::future::Future;
use std::net::SocketAddr;

use super::enum_naptr::{
    application_unique_string, evaluate_rule, query_name, requested_enumservices, NaptrRule,
};

/// The most non-terminal records one query follows. RFC 6116 section 5.2.1:
/// a client "MAY consider a chain of more than 5 'non-terminal' NAPTRs
/// traversed in a single ENUM query as an indication that a referential loop
/// has been entered".
pub const MAX_NON_TERMINAL_CHAIN: usize = 5;

/// What an ENUM query came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumOutcome {
    /// At least one usable URI.
    Ok,
    /// The query name does not exist (NXDOMAIN): the number has no ENUM entry.
    NoSuchName,
    /// The name exists but holds no NAPTR record (NODATA).
    NoRecords,
    /// NAPTR records came back, and none of them, nor any record a
    /// non-terminal one led to, yields a URI for the requested service.
    NoUsableRecord,
    /// SERVFAIL, REFUSED or another error response, or no server reachable.
    ServerFailure,
    /// No answer within the time allowed, on every server tried.
    Timeout,
}

impl EnumOutcome {
    /// The name a script sees.
    pub fn as_str(self) -> &'static str {
        match self {
            EnumOutcome::Ok => "ok",
            EnumOutcome::NoSuchName => "no_such_name",
            EnumOutcome::NoRecords => "no_records",
            EnumOutcome::NoUsableRecord => "no_usable_record",
            EnumOutcome::ServerFailure => "server_failure",
            EnumOutcome::Timeout => "timeout",
        }
    }

    /// Every outcome, for metrics that pre-register their labels.
    pub const ALL: [EnumOutcome; 6] = [
        EnumOutcome::Ok,
        EnumOutcome::NoSuchName,
        EnumOutcome::NoRecords,
        EnumOutcome::NoUsableRecord,
        EnumOutcome::ServerFailure,
        EnumOutcome::Timeout,
    ];
}

/// What one NAPTR query at one name returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NaptrLookup {
    /// An answer with records, in answer order.
    Records(Vec<NaptrRule>),
    /// NXDOMAIN.
    NoSuchName,
    /// NODATA: no error, no NAPTR record.
    NoRecords,
    /// An error response, or a failure that is not a timeout.
    ServerFailure,
    /// No answer in time.
    Timeout,
}

impl NaptrLookup {
    /// The outcome of a query that stopped at this lookup.
    fn outcome(&self) -> EnumOutcome {
        match self {
            NaptrLookup::Records(rules) if rules.is_empty() => EnumOutcome::NoRecords,
            NaptrLookup::Records(_) => EnumOutcome::NoUsableRecord,
            NaptrLookup::NoSuchName => EnumOutcome::NoSuchName,
            NaptrLookup::NoRecords => EnumOutcome::NoRecords,
            NaptrLookup::ServerFailure => EnumOutcome::ServerFailure,
            NaptrLookup::Timeout => EnumOutcome::Timeout,
        }
    }
}

/// A lookup and the server that answered it, when a server list is in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaptrAnswer {
    pub lookup: NaptrLookup,
    pub server: Option<SocketAddr>,
}

/// Where the NAPTR records of a name come from.
pub trait NaptrSource {
    fn naptr(&self, name: &str) -> impl Future<Output = NaptrAnswer> + Send;
}

/// One record an ENUM query considered, with why it gave no URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumRecord {
    /// The name whose NAPTR set held it.
    pub domain: String,
    pub rule: NaptrRule,
    /// `None` for a record that gave a URI, or a non-terminal one that was
    /// followed; otherwise why it was passed over.
    pub rejected: Option<String>,
}

/// The whole result of an ENUM query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumAnswer {
    pub outcome: EnumOutcome,
    /// Every usable URI, in evaluation sequence: ORDER then PREFERENCE within
    /// each NAPTR set, the URIs a non-terminal record leads to in its place.
    pub uris: Vec<String>,
    /// Every record considered, in the same sequence.
    pub records: Vec<EnumRecord>,
    /// The server that answered the first query, when a server list is used.
    pub server: Option<SocketAddr>,
}

/// Why [`enum_query`] could not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnumQueryError {
    #[error("number {0:?} holds no digit")]
    NoDigits(String),
    #[error("service {0:?} is not an E2U service field")]
    NotEnumService(String),
}

/// A name as compared for loops: lower case, no trailing dot.
fn normalised(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn sorted(mut rules: Vec<NaptrRule>) -> Vec<NaptrRule> {
    // RFC 6116 section 5.2: ORDER major, PREFERENCE minor, ties kept in answer
    // order (a stable sort).
    rules.sort_by_key(|rule| (rule.order, rule.preference));
    rules
}

/// One NAPTR set being walked.
struct Frame {
    domain: String,
    rules: std::vec::IntoIter<NaptrRule>,
    depth: usize,
}

/// Run an ENUM query for `number` under `suffix`, wanting the Enumservices of
/// `service`, over `source`.
///
/// The records of each NAPTR set are taken in ORDER then PREFERENCE sequence
/// (RFC 6116 section 5.2); a discarded record does not end the query. A
/// terminal `u` record that offers a requested Enumservice and whose
/// expression matches gives a URI, and the walk goes on, so `uris` holds every
/// candidate in sequence rather than only the first (section 3.5 leaves
/// presenting several to the application). A non-terminal record (empty
/// Flags) names the next domain in its Replacement (section 3.4.2, RFC 3402
/// section 3.3); with `follow_non_terminal` that domain's set is walked in the
/// record's place, and ORDER is not compared across sets (section 5.2). A
/// failed lookup there, a loop back to a name already visited, or a chain
/// past [`MAX_NON_TERMINAL_CHAIN`] discards that record and the walk continues
/// with the next one (section 5.2.1).
pub async fn enum_query<S: NaptrSource>(
    source: &S,
    number: &str,
    suffix: &str,
    service: &str,
    follow_non_terminal: bool,
) -> Result<EnumAnswer, EnumQueryError> {
    let application_unique_string = application_unique_string(number)
        .ok_or_else(|| EnumQueryError::NoDigits(number.to_string()))?;
    let requested = requested_enumservices(service)
        .ok_or_else(|| EnumQueryError::NotEnumService(service.to_string()))?;
    let top = query_name(&application_unique_string, suffix);

    let first = source.naptr(&top).await;
    let server = first.server;
    let rules = match first.lookup {
        NaptrLookup::Records(rules) if !rules.is_empty() => rules,
        other => {
            return Ok(EnumAnswer {
                outcome: other.outcome(),
                uris: Vec::new(),
                records: Vec::new(),
                server,
            })
        }
    };

    let mut uris = Vec::new();
    let mut records = Vec::new();
    let mut visited = vec![normalised(&top)];
    let mut stack = vec![Frame {
        domain: top,
        rules: sorted(rules).into_iter(),
        depth: 0,
    }];
    while let Some(frame) = stack.last_mut() {
        let Some(rule) = frame.rules.next() else {
            stack.pop();
            continue;
        };
        let domain = frame.domain.clone();
        let depth = frame.depth;
        if !rule.flags.is_empty() {
            let rejected = match evaluate_rule(&rule, &application_unique_string, &requested) {
                Ok(uri) => {
                    uris.push(uri);
                    None
                }
                Err(rejection) => Some(rejection.to_string()),
            };
            records.push(EnumRecord {
                domain,
                rule,
                rejected,
            });
            continue;
        }

        // Non-terminal: the Replacement is the next key (RFC 6116 section
        // 5.2.1); Services and Regexp are ignored.
        let next = rule.replacement.trim().to_string();
        let rejected = if !follow_non_terminal {
            Some("non-terminal rule, not followed".to_string())
        } else if next.is_empty() || next == "." {
            Some("non-terminal rule with no replacement".to_string())
        } else if depth + 1 > MAX_NON_TERMINAL_CHAIN {
            Some(format!(
                "more than {MAX_NON_TERMINAL_CHAIN} non-terminal rules in a row, taken for a loop"
            ))
        } else if visited.contains(&normalised(&next)) {
            Some(format!("referential loop back to {next}"))
        } else {
            None
        };
        let index = records.len();
        records.push(EnumRecord {
            domain,
            rule,
            rejected: rejected.clone(),
        });
        if rejected.is_some() {
            continue;
        }
        visited.push(normalised(&next));
        match source.naptr(&next).await.lookup {
            NaptrLookup::Records(rules) if !rules.is_empty() => stack.push(Frame {
                domain: next,
                rules: sorted(rules).into_iter(),
                depth: depth + 1,
            }),
            other => {
                records[index].rejected = Some(format!(
                    "the domain it names gave {}",
                    other.outcome().as_str()
                ));
            }
        }
    }

    Ok(EnumAnswer {
        outcome: if uris.is_empty() {
            EnumOutcome::NoUsableRecord
        } else {
            EnumOutcome::Ok
        },
        uris,
        records,
        server,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// The RFC 6116 section 4 number; its query name under e164.arpa.
    const NUMBER: &str = "+441632960083";
    const TOP: &str = "3.8.0.0.6.9.2.3.6.1.4.4.e164.arpa.";

    /// Answers from a table, recording every name asked.
    #[derive(Default)]
    struct Table {
        answers: HashMap<String, NaptrLookup>,
        asked: Mutex<Vec<String>>,
    }

    impl Table {
        fn with(mut self, name: &str, lookup: NaptrLookup) -> Self {
            self.answers.insert(name.to_string(), lookup);
            self
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().expect("the log").clone()
        }
    }

    impl NaptrSource for Table {
        fn naptr(&self, name: &str) -> impl Future<Output = NaptrAnswer> + Send {
            self.asked.lock().expect("the log").push(name.to_string());
            let lookup = self
                .answers
                .get(name)
                .cloned()
                .unwrap_or(NaptrLookup::NoSuchName);
            async move {
                NaptrAnswer {
                    lookup,
                    server: None,
                }
            }
        }
    }

    fn terminal(order: u16, preference: u16, services: &str, regexp: &str) -> NaptrRule {
        NaptrRule {
            order,
            preference,
            flags: "u".to_string(),
            services: services.to_string(),
            regexp: regexp.to_string(),
            replacement: ".".to_string(),
        }
    }

    fn non_terminal(order: u16, preference: u16, replacement: &str) -> NaptrRule {
        NaptrRule {
            order,
            preference,
            flags: String::new(),
            services: "E2U+sip".to_string(),
            regexp: String::new(),
            replacement: replacement.to_string(),
        }
    }

    async fn query(table: &Table, service: &str) -> EnumAnswer {
        enum_query(table, NUMBER, "e164.arpa.", service, true)
            .await
            .expect("the query starts")
    }

    #[tokio::test]
    async fn each_failure_of_the_query_has_its_own_outcome() {
        for (lookup, outcome) in [
            (NaptrLookup::NoSuchName, EnumOutcome::NoSuchName),
            (NaptrLookup::NoRecords, EnumOutcome::NoRecords),
            (NaptrLookup::Records(Vec::new()), EnumOutcome::NoRecords),
            (NaptrLookup::ServerFailure, EnumOutcome::ServerFailure),
            (NaptrLookup::Timeout, EnumOutcome::Timeout),
        ] {
            let table = Table::default().with(TOP, lookup);
            let answer = query(&table, "E2U+sip").await;
            assert_eq!(answer.outcome, outcome);
            assert!(answer.uris.is_empty());
            assert_eq!(table.asked(), [TOP]);
        }
    }

    /// Three records, the first unusable for the caller: the other two come
    /// back in ORDER / PREFERENCE sequence, and the first says why it did not.
    #[tokio::test]
    async fn every_usable_uri_comes_back_in_sequence() {
        let table = Table::default().with(
            TOP,
            NaptrLookup::Records(vec![
                terminal(100, 20, "E2U+pstn:tel", "!^.*$!tel:+441632960083;npdi!"),
                terminal(100, 10, "E2U+h323", "!^.*$!h323:operator@example.com!"),
                terminal(100, 15, "E2U+sip", r"!^\+(.*)$!sip:\1@example.com!"),
            ]),
        );
        let answer = query(&table, "E2U+sip+pstn:tel").await;
        assert_eq!(answer.outcome, EnumOutcome::Ok);
        assert_eq!(
            answer.uris,
            ["sip:441632960083@example.com", "tel:+441632960083;npdi"]
        );
        assert_eq!(answer.records.len(), 3);
        assert_eq!(answer.records[0].rule.preference, 10);
        assert!(answer.records[0]
            .rejected
            .as_deref()
            .is_some_and(|why| why.contains("none of the requested")));
        assert_eq!(answer.records[1].rejected, None);
        assert_eq!(answer.records[2].rejected, None);
    }

    #[tokio::test]
    async fn records_that_all_fail_are_no_usable_record() {
        let table = Table::default().with(
            TOP,
            NaptrLookup::Records(vec![terminal(
                10,
                10,
                "E2U+h323",
                "!^.*$!h323:a@example.com!",
            )]),
        );
        let answer = query(&table, "E2U+sip").await;
        assert_eq!(answer.outcome, EnumOutcome::NoUsableRecord);
        assert_eq!(answer.records.len(), 1);
    }

    /// A non-terminal record delegates the number to another domain, whose
    /// terminal record gives the URI (RFC 6116 section 5.2.1). The URIs it
    /// leads to take its place in the sequence.
    #[tokio::test]
    async fn a_non_terminal_record_is_followed_to_the_next_domain() {
        let table = Table::default()
            .with(
                TOP,
                NaptrLookup::Records(vec![
                    non_terminal(10, 10, "nonterminal.enum.example.net."),
                    terminal(20, 10, "E2U+sip", "!^.*$!sip:fallback@example.com!"),
                ]),
            )
            .with(
                "nonterminal.enum.example.net.",
                NaptrLookup::Records(vec![terminal(
                    // ORDER is not compared across sets (section 5.2).
                    90,
                    10,
                    "E2U+sip",
                    r"!^\+(.*)$!sip:\1@delegated.example.net!",
                )]),
            );
        let answer = query(&table, "E2U+sip").await;
        assert_eq!(answer.outcome, EnumOutcome::Ok);
        assert_eq!(
            answer.uris,
            [
                "sip:441632960083@delegated.example.net",
                "sip:fallback@example.com"
            ]
        );
        assert_eq!(table.asked(), [TOP, "nonterminal.enum.example.net."]);
        assert_eq!(answer.records[1].domain, "nonterminal.enum.example.net.");
    }

    /// Without following, the record says so and nothing more is asked.
    #[tokio::test]
    async fn not_following_leaves_the_non_terminal_record_aside() {
        let table = Table::default().with(
            TOP,
            NaptrLookup::Records(vec![non_terminal(10, 10, "next.example.net.")]),
        );
        let answer = enum_query(&table, NUMBER, "e164.arpa.", "E2U+sip", false)
            .await
            .expect("the query starts");
        assert_eq!(answer.outcome, EnumOutcome::NoUsableRecord);
        assert_eq!(table.asked(), [TOP]);
        assert!(answer.records[0].rejected.is_some());
    }

    /// A loop of non-terminal records ends with an outcome, each name asked
    /// once (section 5.2.1: detect the loop and do not make the query).
    #[tokio::test]
    async fn a_loop_of_non_terminal_records_ends() {
        let table = Table::default()
            .with(
                TOP,
                NaptrLookup::Records(vec![non_terminal(10, 10, "a.example.net.")]),
            )
            .with(
                "a.example.net.",
                NaptrLookup::Records(vec![non_terminal(10, 10, "b.example.net.")]),
            )
            .with(
                "b.example.net.",
                NaptrLookup::Records(vec![non_terminal(10, 10, "A.example.net")]),
            );
        let answer = query(&table, "E2U+sip").await;
        assert_eq!(answer.outcome, EnumOutcome::NoUsableRecord);
        assert_eq!(table.asked(), [TOP, "a.example.net.", "b.example.net."]);
        assert!(answer.records[2]
            .rejected
            .as_deref()
            .is_some_and(|why| why.contains("loop")));
    }

    /// A chain longer than five is taken for a loop: the sixth domain is not
    /// asked.
    #[tokio::test]
    async fn a_chain_past_five_non_terminal_records_is_cut() {
        let mut table = Table::default().with(
            TOP,
            NaptrLookup::Records(vec![non_terminal(10, 10, "n1.example.net.")]),
        );
        for hop in 1..=6 {
            table = table.with(
                &format!("n{hop}.example.net."),
                NaptrLookup::Records(vec![non_terminal(
                    10,
                    10,
                    &format!("n{}.example.net.", hop + 1),
                )]),
            );
        }
        let answer = query(&table, "E2U+sip").await;
        assert_eq!(answer.outcome, EnumOutcome::NoUsableRecord);
        assert_eq!(table.asked().len(), 1 + MAX_NON_TERMINAL_CHAIN);
        assert!(answer
            .records
            .last()
            .and_then(|record| record.rejected.as_deref())
            .is_some_and(|why| why.contains("more than 5")));
    }

    /// A domain a non-terminal record names that does not answer discards
    /// that record only; the walk goes on with the next one.
    #[tokio::test]
    async fn a_failed_delegation_moves_on_to_the_next_record() {
        let table = Table::default()
            .with(
                TOP,
                NaptrLookup::Records(vec![
                    non_terminal(10, 10, "broken.example.net."),
                    terminal(20, 10, "E2U+sip", "!^.*$!sip:next@example.com!"),
                ]),
            )
            .with("broken.example.net.", NaptrLookup::ServerFailure);
        let answer = query(&table, "E2U+sip").await;
        assert_eq!(answer.uris, ["sip:next@example.com"]);
        assert_eq!(
            answer.records[0].rejected.as_deref(),
            Some("the domain it names gave server_failure")
        );
    }

    #[tokio::test]
    async fn a_number_without_digits_or_a_service_that_is_not_enum_is_refused() {
        let table = Table::default();
        assert_eq!(
            enum_query(&table, "+", "e164.arpa.", "E2U+sip", true).await,
            Err(EnumQueryError::NoDigits("+".to_string()))
        );
        assert_eq!(
            enum_query(&table, NUMBER, "e164.arpa.", "SIP+D2U", true).await,
            Err(EnumQueryError::NotEnumService("SIP+D2U".to_string()))
        );
        assert!(table.asked().is_empty());
    }

    #[test]
    fn outcomes_have_the_names_scripts_see() {
        let names: Vec<&str> = EnumOutcome::ALL
            .iter()
            .map(|outcome| outcome.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "ok",
                "no_such_name",
                "no_records",
                "no_usable_record",
                "server_failure",
                "timeout"
            ]
        );
    }
}
