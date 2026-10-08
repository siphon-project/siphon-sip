//! ENUM rule selection (RFC 6116) over NAPTR records (RFC 3403), with the
//! DDDS substitution expression of RFC 3402 section 3.2.
//!
//! Everything here is a pure function of the records a query returned, so it
//! is tested without a resolver.

/// One NAPTR resource record (RFC 3403 section 4.1), as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaptrRule {
    /// Major sort term, lowest first.
    pub order: u16,
    /// Minor sort term among records of equal order, lowest first.
    pub preference: u16,
    /// Flags field. `u` marks a terminal rule whose output is a URI.
    pub flags: String,
    /// Services field, `E2U+enumservice[+enumservice...]` for ENUM.
    pub services: String,
    /// Substitution expression, `delimiter ere delimiter repl delimiter flags`.
    pub regexp: String,
    /// Replacement domain name; empty or `.` when the record carries none.
    pub replacement: String,
}

/// Build the Application Unique String for a number (RFC 6116 section 3.1):
/// a leading `+` and the digits, with every other character removed.
///
/// Returns `None` when the number holds no digit.
pub fn application_unique_string(number: &str) -> Option<String> {
    let digits: String = number
        .chars()
        .filter(|character| character.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    Some(format!("+{digits}"))
}

/// Apply the First Well Known Rule (RFC 6116 section 3.2): the digits of the
/// Application Unique String reversed, dot-separated, under `suffix`.
pub fn query_name(application_unique_string: &str, suffix: &str) -> String {
    let reversed: Vec<String> = application_unique_string
        .chars()
        .filter(|character| character.is_ascii_digit())
        .rev()
        .map(|digit| digit.to_string())
        .collect();
    format!("{}.{suffix}", reversed.join("."))
}

/// Why a NAPTR record did not yield the URI of an ENUM query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleRejection {
    /// The Flags field is empty: a non-terminal rule, which is not followed.
    #[error("non-terminal rule (empty flags)")]
    NonTerminal,
    /// The Flags field holds something other than `u` (RFC 6116 section 3.4.2).
    #[error("unknown flags {0:?}")]
    UnknownFlags(String),
    /// The Services field is not an ENUM (`E2U`) service field.
    #[error("services field {0:?} is not an E2U service field")]
    NotEnum(String),
    /// None of the requested Enumservices is offered.
    #[error("services field {0:?} offers none of the requested enumservices")]
    ServiceNotOffered(String),
    /// Both Regexp and Replacement are set (RFC 3403 section 4.1).
    #[error("both regexp and replacement are set")]
    RegexpAndReplacement,
    /// The Regexp field is not a usable substitution expression.
    #[error("malformed substitution expression: {0}")]
    MalformedExpression(#[from] ExpressionError),
    /// The expression does not match the Application Unique String, or
    /// produces an empty string.
    #[error("substitution expression does not match")]
    NoMatch,
    /// The output is not an absolute URI (RFC 6116 section 3.3).
    #[error("output {0:?} is not an absolute URI")]
    NotAbsoluteUri(String),
}

/// Why a Regexp field is not a usable substitution expression.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExpressionError {
    /// The field is empty.
    #[error("empty")]
    Empty,
    /// The delimiter is a digit or the flag character `i`.
    #[error("delimiter {0:?} is a digit or a flag character")]
    InvalidDelimiter(char),
    /// There are not exactly three unescaped delimiters.
    #[error("expected exactly three unescaped delimiters")]
    DelimiterCount,
    /// A backslash in the replacement that starts neither an escaped
    /// delimiter nor a back-reference. The RFC 3402 grammar reads it as a
    /// literal backslash, which no URI can hold, so the rule is refused here
    /// rather than at the URI check.
    #[error("undefined escape in the replacement")]
    UndefinedEscape,
    /// A flag other than `i` follows the last delimiter.
    #[error("unknown flag {0:?}")]
    UnknownFlag(char),
    /// The regular expression does not compile.
    #[error("regular expression does not compile: {0}")]
    InvalidExpression(String),
    /// A back-reference names a group the expression does not have.
    #[error("back-reference \\{0} has no matching subexpression")]
    BackReferenceOutOfRange(usize),
}

/// One piece of the `repl` part of a substitution expression.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReplacementPart {
    Literal(String),
    BackReference(usize),
}

/// A parsed substitution expression (RFC 3402 section 3.2):
/// `delim-char ere delim-char repl delim-char *flags`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SubstitutionExpression {
    /// The `ere` part, with escaped delimiters turned into literals.
    pattern: String,
    replacement: Vec<ReplacementPart>,
    /// The `i` flag.
    case_insensitive: bool,
}

/// Upper bound on a compiled expression. The Regexp field is at most 255
/// octets, but nested counted repetitions can still ask for a very large
/// program; such a record is rejected instead of compiled.
const COMPILED_EXPRESSION_SIZE_LIMIT: usize = 1 << 20;

impl SubstitutionExpression {
    fn parse(field: &str) -> Result<Self, ExpressionError> {
        let mut characters = field.chars();
        let delimiter = characters.next().ok_or(ExpressionError::Empty)?;
        if delimiter.is_ascii_digit() || delimiter.eq_ignore_ascii_case(&'i') {
            return Err(ExpressionError::InvalidDelimiter(delimiter));
        }

        let mut pattern = String::new();
        let mut pattern_closed = false;
        while let Some(character) = characters.next() {
            if character == delimiter {
                pattern_closed = true;
                break;
            }
            if character != '\\' {
                pattern.push(character);
                continue;
            }
            // A backslash pair belongs to the expression, except for an
            // escaped delimiter, which stands for that character itself.
            let escaped = characters.next().ok_or(ExpressionError::DelimiterCount)?;
            if escaped == delimiter {
                pattern.push_str(&regex::escape(escaped.encode_utf8(&mut [0; 4])));
            } else {
                pattern.push('\\');
                pattern.push(escaped);
            }
        }
        if !pattern_closed {
            return Err(ExpressionError::DelimiterCount);
        }

        let mut replacement = Vec::new();
        let mut literal = String::new();
        let mut replacement_closed = false;
        while let Some(character) = characters.next() {
            if character == delimiter {
                replacement_closed = true;
                break;
            }
            if character != '\\' {
                literal.push(character);
                continue;
            }
            let escaped = characters.next().ok_or(ExpressionError::DelimiterCount)?;
            if escaped == delimiter {
                literal.push(escaped);
            } else if let Some(group) = escaped.to_digit(10).filter(|digit| *digit != 0) {
                if !literal.is_empty() {
                    replacement.push(ReplacementPart::Literal(std::mem::take(&mut literal)));
                }
                replacement.push(ReplacementPart::BackReference(group as usize));
            } else {
                return Err(ExpressionError::UndefinedEscape);
            }
        }
        if !replacement_closed {
            return Err(ExpressionError::DelimiterCount);
        }
        if !literal.is_empty() {
            replacement.push(ReplacementPart::Literal(literal));
        }

        let mut case_insensitive = false;
        for flag in characters {
            if flag == delimiter {
                return Err(ExpressionError::DelimiterCount);
            }
            if !flag.eq_ignore_ascii_case(&'i') {
                return Err(ExpressionError::UnknownFlag(flag));
            }
            case_insensitive = true;
        }

        Ok(Self {
            pattern,
            replacement,
            case_insensitive,
        })
    }

    /// Apply the expression to `input`, sed-style: the first match is
    /// replaced and whatever surrounds it is kept.
    ///
    /// `Ok(None)` when the expression does not match or the result is empty
    /// (RFC 3402 section 3.3 step 3 moves on to the next rule in both cases).
    ///
    /// The `ere` is run by the `regex` crate, whose syntax covers POSIX
    /// extended regular expressions as ENUM zones use them. Two differences
    /// remain: an alternation takes the first alternative that matches
    /// rather than the longest, and a backslash inside a bracket expression
    /// escapes the next character rather than standing for itself.
    fn apply(&self, input: &str) -> Result<Option<String>, ExpressionError> {
        let expression = regex::RegexBuilder::new(&self.pattern)
            .case_insensitive(self.case_insensitive)
            .size_limit(COMPILED_EXPRESSION_SIZE_LIMIT)
            .build()
            .map_err(|error| ExpressionError::InvalidExpression(error.to_string()))?;

        // Checked before matching, so a rule is rejected the same way for
        // every input.
        for part in &self.replacement {
            if let ReplacementPart::BackReference(group) = part {
                if *group >= expression.captures_len() {
                    return Err(ExpressionError::BackReferenceOutOfRange(*group));
                }
            }
        }

        let Some(captures) = expression.captures(input) else {
            return Ok(None);
        };
        let Some(matched) = captures.get(0) else {
            return Ok(None);
        };

        let mut output = String::from(&input[..matched.start()]);
        for part in &self.replacement {
            match part {
                ReplacementPart::Literal(text) => output.push_str(text),
                ReplacementPart::BackReference(group) => {
                    // A group that took no part in the match is empty.
                    if let Some(captured) = captures.get(*group) {
                        output.push_str(captured.as_str());
                    }
                }
            }
        }
        output.push_str(&input[matched.end()..]);

        if output.is_empty() {
            return Ok(None);
        }
        Ok(Some(output))
    }
}

/// The Enumservices of a Services field, lower-cased, in field order.
///
/// Accepts `E2U+enumservice[+enumservice...]` (RFC 6116 section 3.4.3) and
/// the obsolete `enumservice[+enumservice...]+E2U` of RFC 2916, which
/// RFC 6116 section 5.2 asks clients to keep supporting. `None` when the
/// field is neither, or names no Enumservice.
fn enumservices(services: &str) -> Option<Vec<String>> {
    let tokens: Vec<&str> = services.split('+').collect();
    let (first, last) = (tokens.first()?, tokens.last()?);
    let names = if first.eq_ignore_ascii_case("E2U") {
        &tokens[1..]
    } else if last.eq_ignore_ascii_case("E2U") {
        &tokens[..tokens.len() - 1]
    } else {
        return None;
    };
    if names.is_empty() || names.iter().any(|name| name.is_empty()) {
        return None;
    }
    Some(names.iter().map(|name| name.to_ascii_lowercase()).collect())
}

/// Whether `candidate` has the shape of an absolute URI (RFC 3986): a scheme,
/// a colon and something after it, in visible US-ASCII only. Rejecting
/// everything else keeps whitespace and line breaks from a DNS answer out of
/// whatever the URI is used for next.
fn is_absolute_uri(candidate: &str) -> bool {
    let Some((scheme, rest)) = candidate.split_once(':') else {
        return false;
    };
    let mut scheme_characters = scheme.chars();
    let scheme_is_valid = scheme_characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && scheme_characters
            .all(|character| character.is_ascii_alphanumeric() || "+-.".contains(character));
    scheme_is_valid
        && !rest.is_empty()
        && rest.chars().all(|character| character.is_ascii_graphic())
}

/// Evaluate one record: the URI it yields for the Application Unique String,
/// or why it yields none.
fn evaluate_rule(
    rule: &NaptrRule,
    application_unique_string: &str,
    requested: &[String],
) -> Result<String, RuleRejection> {
    // RFC 6116 section 3.4.2: the flag test comes before everything else,
    // since a flag can change how the other fields are read.
    if rule.flags.is_empty() {
        return Err(RuleRejection::NonTerminal);
    }
    if !rule.flags.eq_ignore_ascii_case("u") {
        return Err(RuleRejection::UnknownFlags(rule.flags.clone()));
    }

    let offered = enumservices(&rule.services)
        .ok_or_else(|| RuleRejection::NotEnum(rule.services.clone()))?;
    if !offered.iter().any(|name| requested.contains(name)) {
        return Err(RuleRejection::ServiceNotOffered(rule.services.clone()));
    }

    let has_replacement = !rule.replacement.is_empty() && rule.replacement != ".";
    if has_replacement && !rule.regexp.is_empty() {
        return Err(RuleRejection::RegexpAndReplacement);
    }

    let uri = SubstitutionExpression::parse(&rule.regexp)?
        .apply(application_unique_string)?
        .ok_or(RuleRejection::NoMatch)?;
    if !is_absolute_uri(&uri) {
        return Err(RuleRejection::NotAbsoluteUri(uri));
    }
    Ok(uri)
}

/// Select the URI an ENUM query yields from the NAPTR records it returned.
///
/// The records are taken in ORDER, then PREFERENCE sequence, records equal in
/// both staying in answer order (RFC 6116 section 5.2). The first one that is
/// a terminal `u` rule, offers one of the Enumservices named in `service`
/// (an `E2U+enumservice[+enumservice...]` field, compared without case) and
/// whose substitution expression matches `application_unique_string` gives
/// the result. A record that is rejected does not end the query: the next
/// one is considered, whatever its ORDER.
///
/// Non-terminal rules (empty Flags) are skipped, not followed, which
/// RFC 6116 section 5.2.1 allows.
pub fn select_enum_uri(
    rules: &[NaptrRule],
    application_unique_string: &str,
    service: &str,
) -> Option<String> {
    let Some(requested) = enumservices(service) else {
        tracing::warn!(
            service,
            "ENUM service is not an E2U service field, nothing can be selected"
        );
        return None;
    };

    let mut ordered: Vec<&NaptrRule> = rules.iter().collect();
    ordered.sort_by_key(|rule| (rule.order, rule.preference));

    for rule in ordered {
        match evaluate_rule(rule, application_unique_string, &requested) {
            Ok(uri) => return Some(uri),
            Err(rejection) => {
                tracing::debug!(
                    order = rule.order,
                    preference = rule.preference,
                    services = %rule.services,
                    %rejection,
                    "ENUM NAPTR record skipped"
                );
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The number of the RFC 6116 section 4 example.
    const NUMBER: &str = "+441632960083";

    fn rule(order: u16, preference: u16, flags: &str, services: &str, regexp: &str) -> NaptrRule {
        NaptrRule {
            order,
            preference,
            flags: flags.to_string(),
            services: services.to_string(),
            regexp: regexp.to_string(),
            replacement: ".".to_string(),
        }
    }

    /// RFC 6116 section 4, with the master-file backslash doubling undone
    /// (the wire form carries a single backslash).
    fn rfc6116_section_4_records() -> Vec<NaptrRule> {
        vec![
            rule(
                100,
                50,
                "u",
                "E2U+sip",
                r"!^(\+441632960083)$!sip:\1@example.com!",
            ),
            rule(
                100,
                51,
                "u",
                "E2U+h323",
                r"!^\+441632960083$!h323:operator@example.com!",
            ),
            rule(
                100,
                52,
                "u",
                "E2U+email:mailto",
                "!^.*$!mailto:info@example.com!",
            ),
        ]
    }

    #[test]
    fn application_unique_string_keeps_the_plus_and_the_digits() {
        // RFC 6116 section 3.1.
        assert_eq!(
            application_unique_string("+44-116-496-0348").as_deref(),
            Some("+441164960348")
        );
        assert_eq!(
            application_unique_string("441164960348").as_deref(),
            Some("+441164960348")
        );
        assert_eq!(application_unique_string("+"), None);
        assert_eq!(application_unique_string(""), None);
    }

    #[test]
    fn query_name_is_the_first_well_known_rule() {
        // RFC 6116 section 3.2.
        assert_eq!(
            query_name("+442079460148", "e164.arpa."),
            "8.4.1.0.6.4.9.7.0.2.4.4.e164.arpa."
        );
    }

    #[test]
    fn rfc6116_example_sip_applies_the_back_reference() {
        assert_eq!(
            select_enum_uri(&rfc6116_section_4_records(), NUMBER, "E2U+sip").as_deref(),
            Some("sip:+441632960083@example.com")
        );
    }

    #[test]
    fn rfc6116_example_honours_the_requested_service() {
        let records = rfc6116_section_4_records();
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+h323").as_deref(),
            Some("h323:operator@example.com")
        );
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+email:mailto").as_deref(),
            Some("mailto:info@example.com")
        );
        assert_eq!(select_enum_uri(&records, NUMBER, "E2U+pres"), None);
    }

    #[test]
    fn rfc6116_example_skips_a_rule_whose_expression_does_not_match() {
        // The first two records match one number only; the third matches any.
        let records = rfc6116_section_4_records();
        let other = "+441632960084";
        assert_eq!(select_enum_uri(&records, other, "E2U+sip"), None);
        assert_eq!(select_enum_uri(&records, other, "E2U+h323"), None);
        assert_eq!(
            select_enum_uri(&records, other, "E2U+email:mailto").as_deref(),
            Some("mailto:info@example.com")
        );
    }

    #[test]
    fn records_are_taken_by_order_then_preference_not_answer_order() {
        let records = vec![
            rule(200, 1, "u", "E2U+sip", "!^.*$!sip:order-200@example.com!"),
            rule(
                100,
                20,
                "u",
                "E2U+sip",
                "!^.*$!sip:order-100-preference-20@example.com!",
            ),
            rule(
                100,
                10,
                "u",
                "E2U+sip",
                "!^.*$!sip:order-100-preference-10@example.com!",
            ),
        ];
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+sip").as_deref(),
            Some("sip:order-100-preference-10@example.com")
        );
    }

    #[test]
    fn order_outranks_preference() {
        let records = vec![
            rule(101, 1, "u", "E2U+sip", "!^.*$!sip:second@example.com!"),
            rule(100, 65535, "u", "E2U+sip", "!^.*$!sip:first@example.com!"),
        ];
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+sip").as_deref(),
            Some("sip:first@example.com")
        );
    }

    #[test]
    fn equal_order_and_preference_keep_answer_order() {
        // RFC 6116 section 5.2.
        let records = vec![
            rule(100, 10, "u", "E2U+sip", "!^.*$!sip:first@example.com!"),
            rule(100, 10, "u", "E2U+sip", "!^.*$!sip:second@example.com!"),
        ];
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+sip").as_deref(),
            Some("sip:first@example.com")
        );
    }

    #[test]
    fn a_worse_order_is_still_considered_when_nothing_better_is_accepted() {
        // RFC 6116 section 5.2: a record is not discarded for its ORDER
        // unless an earlier record has been accepted.
        let records = vec![
            rule(100, 10, "u", "E2U+h323", "!^.*$!h323:operator@example.com!"),
            rule(200, 10, "u", "E2U+sip", "!^.*$!sip:fallback@example.com!"),
        ];
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+sip").as_deref(),
            Some("sip:fallback@example.com")
        );
    }

    #[test]
    fn several_back_references_and_a_prefix_rewrite() {
        let records = vec![rule(
            100,
            10,
            "u",
            "E2U+sip",
            r"!^\+44(1632)(.*)$!sip:\2-\1-\2@example.com!",
        )];
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+sip").as_deref(),
            Some("sip:960083-1632-960083@example.com")
        );
    }

    #[test]
    fn the_delimiter_need_not_be_an_exclamation_mark() {
        // RFC 6116 section 5.2.
        let records = vec![rule(
            100,
            10,
            "u",
            "E2U+sip",
            r"/^\+(.*)$/sip:\1@example.com/",
        )];
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+sip").as_deref(),
            Some("sip:441632960083@example.com")
        );
    }

    #[test]
    fn an_escaped_delimiter_is_a_literal_character() {
        let records = vec![rule(
            100,
            10,
            "u",
            "E2U+sip",
            r"/^.*$/sip:operator@example.com;path=\/a\/b/",
        )];
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+sip").as_deref(),
            Some("sip:operator@example.com;path=/a/b")
        );
    }

    #[test]
    fn obsolete_service_syntax_with_a_trailing_flag_is_accepted() {
        // The shape of the RFC 3403 section 6.2 records: the RFC 2916
        // `sip+E2U` services form and an `i` flag after the last delimiter.
        let records = vec![
            rule(
                100,
                10,
                "u",
                "sip+E2U",
                "!^.*$!sip:information@example.com!i",
            ),
            rule(
                102,
                10,
                "u",
                "smtp+E2U",
                "!^.*$!mailto:information@example.com!i",
            ),
        ];
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+sip").as_deref(),
            Some("sip:information@example.com")
        );
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+smtp").as_deref(),
            Some("mailto:information@example.com")
        );
    }

    #[test]
    fn services_are_compared_without_case_and_as_whole_enumservices() {
        let records = vec![
            rule(100, 10, "u", "e2u+SIPS", "!^.*$!sips:wrong@example.com!"),
            rule(100, 20, "u", "e2u+SIP", "!^.*$!sip:right@example.com!"),
        ];
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+sip").as_deref(),
            Some("sip:right@example.com")
        );
    }

    #[test]
    fn a_compound_record_offers_each_of_its_enumservices() {
        // RFC 6116 section 3.4.3.2.
        let records = vec![rule(
            100,
            10,
            "u",
            "E2U+voice:tel+sms:tel",
            "!^.*$!tel:+441632960083!",
        )];
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+sms:tel").as_deref(),
            Some("tel:+441632960083")
        );
        assert_eq!(select_enum_uri(&records, NUMBER, "E2U+sms"), None);
    }

    #[test]
    fn a_record_for_another_application_is_skipped() {
        let records = vec![
            rule(100, 10, "u", "http+N2L", "!^.*$!http://example.com/!"),
            rule(100, 20, "u", "E2U+sip", "!^.*$!sip:operator@example.com!"),
        ];
        assert_eq!(
            select_enum_uri(&records, NUMBER, "E2U+sip").as_deref(),
            Some("sip:operator@example.com")
        );
    }

    #[test]
    fn only_a_terminal_u_rule_yields_a_uri() {
        let mut non_terminal = rule(100, 10, "", "", "");
        non_terminal.replacement = "enum.example.com.".to_string();
        let unknown_flag = rule(100, 20, "s", "E2U+sip", "!^.*$!sip:wrong@example.com!");
        let terminal = rule(100, 30, "U", "E2U+sip", "!^.*$!sip:right@example.com!");
        assert_eq!(
            select_enum_uri(
                &[non_terminal.clone(), unknown_flag.clone(), terminal],
                NUMBER,
                "E2U+sip"
            )
            .as_deref(),
            Some("sip:right@example.com")
        );
        assert_eq!(
            select_enum_uri(&[non_terminal, unknown_flag], NUMBER, "E2U+sip"),
            None
        );
    }

    #[test]
    fn a_malformed_record_is_skipped_and_the_next_one_used() {
        let fallback = rule(100, 90, "u", "E2U+sip", "!^.*$!sip:fallback@example.com!");
        for malformed in [
            // Two delimiters only.
            "!^.*$!sip:broken@example.com",
            // Four unescaped delimiters.
            "!^.*$!sip:broken@example.com!!",
            // A flag other than `i`.
            "!^.*$!sip:broken@example.com!g",
            // A digit as the delimiter.
            "1^.*$1sip:broken@example.com1",
            // A back-reference to a group the expression does not have.
            r"!^(.*)$!sip:\2@example.com!",
            // An expression that does not compile.
            "!^(.*$!sip:broken@example.com!",
            // A backslash that is neither an escaped delimiter nor a
            // back-reference.
            r"!^.*$!sip:bro\ken@example.com!",
            // No expression at all.
            "",
        ] {
            let records = vec![rule(100, 10, "u", "E2U+sip", malformed), fallback.clone()];
            assert_eq!(
                select_enum_uri(&records, NUMBER, "E2U+sip").as_deref(),
                Some("sip:fallback@example.com"),
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn a_record_with_both_an_expression_and_a_replacement_is_skipped() {
        // RFC 3403 section 4.1: the two fields are mutually exclusive.
        let mut both = rule(100, 10, "u", "E2U+sip", "!^.*$!sip:wrong@example.com!");
        both.replacement = "example.com.".to_string();
        assert_eq!(select_enum_uri(&[both], NUMBER, "E2U+sip"), None);
    }

    #[test]
    fn output_that_is_not_an_absolute_uri_is_rejected() {
        for expression in [
            "!^.*$!no-scheme!",
            "!^.*$!sip:operator@example.com\r\nRoute: <sip:192.0.2.1>!",
            "!^.*$!sip:operator @example.com!",
            "!^.*$!:missing-scheme!",
            "!^.*$!sip:!",
        ] {
            let records = vec![rule(100, 10, "u", "E2U+sip", expression)];
            assert_eq!(
                select_enum_uri(&records, NUMBER, "E2U+sip"),
                None,
                "{expression:?}"
            );
        }
    }

    #[test]
    fn an_unusable_service_argument_selects_nothing() {
        let records = rfc6116_section_4_records();
        assert_eq!(select_enum_uri(&records, NUMBER, ""), None);
        assert_eq!(select_enum_uri(&records, NUMBER, "E2U"), None);
        assert_eq!(select_enum_uri(&records, NUMBER, "sip"), None);
    }

    fn substitute(field: &str, input: &str) -> Result<Option<String>, ExpressionError> {
        SubstitutionExpression::parse(field)?.apply(input)
    }

    #[test]
    fn rfc3403_section_6_1_substitution() {
        // A non-ENUM DDDS rule: case-insensitive match, second back-reference.
        assert_eq!(
            substitute(
                r"!^urn:cid:.+@([^\.]+\.)(.*)$!\2!i",
                "urn:cid:199606121851.1@bar.example.com"
            ),
            Ok(Some("example.com".to_string()))
        );
        assert_eq!(
            substitute(
                r"!^urn:cid:.+@([^\.]+\.)(.*)$!\2!i",
                "URN:CID:199606121851.1@bar.example.com"
            ),
            Ok(Some("example.com".to_string()))
        );
    }

    #[test]
    fn rfc3402_section_3_2_back_reference_numbering() {
        let input = "ABCDEFG";
        for (back_reference, expected) in [(1, "ABCDEFG"), (2, "BCDE"), (3, "C"), (4, "F")] {
            assert_eq!(
                substitute(&format!(r"!(A(B(C)DE)(F)G)!\{back_reference}!"), input),
                Ok(Some(expected.to_string())),
                "\\{back_reference}"
            );
        }
        for back_reference in 5..=9 {
            assert_eq!(
                substitute(&format!(r"!(A(B(C)DE)(F)G)!\{back_reference}!"), input),
                Err(ExpressionError::BackReferenceOutOfRange(back_reference))
            );
        }
    }

    #[test]
    fn matching_is_case_sensitive_without_the_i_flag() {
        assert_eq!(substitute("!^abc$!x:y!", "ABC"), Ok(None));
        assert_eq!(
            substitute("!^abc$!x:y!i", "ABC"),
            Ok(Some("x:y".to_string()))
        );
        assert_eq!(
            substitute("!^abc$!x:y!I", "ABC"),
            Ok(Some("x:y".to_string()))
        );
    }

    #[test]
    fn the_replacement_keeps_its_case() {
        // RFC 6116 section 3.6.
        assert_eq!(
            substitute("!^.*$!SIP:Operator@Example.COM!i", NUMBER),
            Ok(Some("SIP:Operator@Example.COM".to_string()))
        );
    }

    #[test]
    fn text_around_the_match_is_kept() {
        assert_eq!(
            substitute("!1632!-!", NUMBER),
            Ok(Some("+44-960083".to_string()))
        );
    }

    #[test]
    fn an_empty_result_is_no_match() {
        assert_eq!(substitute("!^.*$!!", NUMBER), Ok(None));
    }

    #[test]
    fn a_group_that_took_no_part_in_the_match_is_empty() {
        assert_eq!(
            substitute(r"!^\+44(9)?(.*)$!tel:\1\2!", NUMBER),
            Ok(Some("tel:1632960083".to_string()))
        );
    }

    #[test]
    fn an_escaped_delimiter_in_the_expression_is_matched_literally() {
        assert_eq!(
            substitute(r"/^a\/b$/x:y/", "a/b"),
            Ok(Some("x:y".to_string()))
        );
        // A delimiter that would be a regular-expression operator unescaped.
        assert_eq!(
            substitute(r"|^a\|b$|x:y|", "a|b"),
            Ok(Some("x:y".to_string()))
        );
        assert_eq!(substitute(r"|^a\|b$|x:y|", "a"), Ok(None));
        // An escaped backslash does not escape the delimiter that follows it.
        assert_eq!(
            substitute(r"!^a\\!x:y!", r"a\"),
            Ok(Some("x:y".to_string()))
        );
    }

    #[test]
    fn expression_errors_name_the_defect() {
        assert_eq!(substitute("", NUMBER), Err(ExpressionError::Empty));
        assert_eq!(
            substitute("1a1b1", NUMBER),
            Err(ExpressionError::InvalidDelimiter('1'))
        );
        assert_eq!(
            substitute("iaibi", NUMBER),
            Err(ExpressionError::InvalidDelimiter('i'))
        );
        assert_eq!(
            substitute("!a", NUMBER),
            Err(ExpressionError::DelimiterCount)
        );
        assert_eq!(
            substitute("!a!b", NUMBER),
            Err(ExpressionError::DelimiterCount)
        );
        assert_eq!(
            substitute("!a!b!!", NUMBER),
            Err(ExpressionError::DelimiterCount)
        );
        assert_eq!(
            substitute(r"!a!b\", NUMBER),
            Err(ExpressionError::DelimiterCount)
        );
        assert_eq!(
            substitute("!a!b!x", NUMBER),
            Err(ExpressionError::UnknownFlag('x'))
        );
        assert_eq!(
            substitute(r"!a!\0!", NUMBER),
            Err(ExpressionError::UndefinedEscape)
        );
        assert!(matches!(
            substitute("!(!b!", NUMBER),
            Err(ExpressionError::InvalidExpression(_))
        ));
    }

    #[test]
    fn an_expression_too_large_to_compile_is_rejected() {
        assert!(matches!(
            substitute("!((a{255}){255}){255}!x:y!", NUMBER),
            Err(ExpressionError::InvalidExpression(_))
        ));
    }

    #[test]
    fn enumservices_of_a_services_field() {
        assert_eq!(enumservices("E2U+sip"), Some(vec!["sip".to_string()]));
        assert_eq!(
            enumservices("e2u+Voice:Tel+SMS:tel"),
            Some(vec!["voice:tel".to_string(), "sms:tel".to_string()])
        );
        assert_eq!(enumservices("sip+E2U"), Some(vec!["sip".to_string()]));
        assert_eq!(enumservices("E2U"), None);
        assert_eq!(enumservices("E2U+"), None);
        assert_eq!(enumservices("E2U++sip"), None);
        assert_eq!(enumservices("http+N2L"), None);
        assert_eq!(enumservices(""), None);
    }

    #[test]
    fn rejections_name_the_reason() {
        let requested = vec!["sip".to_string()];
        let evaluate = |candidate: &NaptrRule| evaluate_rule(candidate, NUMBER, &requested);

        assert_eq!(
            evaluate(&rule(100, 10, "", "", "")),
            Err(RuleRejection::NonTerminal)
        );
        assert_eq!(
            evaluate(&rule(100, 10, "a", "E2U+sip", "!^.*$!sip:a@example.com!")),
            Err(RuleRejection::UnknownFlags("a".to_string()))
        );
        assert_eq!(
            evaluate(&rule(100, 10, "u", "http+N2L", "!^.*$!sip:a@example.com!")),
            Err(RuleRejection::NotEnum("http+N2L".to_string()))
        );
        assert_eq!(
            evaluate(&rule(100, 10, "u", "E2U+h323", "!^.*$!sip:a@example.com!")),
            Err(RuleRejection::ServiceNotOffered("E2U+h323".to_string()))
        );
        assert_eq!(
            evaluate(&rule(100, 10, "u", "E2U+sip", "!^x$!sip:a@example.com!")),
            Err(RuleRejection::NoMatch)
        );
        assert_eq!(
            evaluate(&rule(100, 10, "u", "E2U+sip", "!^.*$!a!")),
            Err(RuleRejection::NotAbsoluteUri("a".to_string()))
        );
        assert_eq!(
            evaluate(&rule(100, 10, "u", "E2U+sip", "")),
            Err(RuleRejection::MalformedExpression(ExpressionError::Empty))
        );
    }

    #[test]
    fn rejection_display() {
        assert_eq!(
            RuleRejection::NonTerminal.to_string(),
            "non-terminal rule (empty flags)"
        );
        assert_eq!(
            RuleRejection::MalformedExpression(ExpressionError::BackReferenceOutOfRange(5))
                .to_string(),
            "malformed substitution expression: back-reference \\5 has no matching subexpression"
        );
    }

    #[test]
    fn absolute_uri_shape() {
        assert!(is_absolute_uri("sip:operator@example.com"));
        assert!(is_absolute_uri("tel:+441632960083"));
        assert!(is_absolute_uri("x-a.b+c:d"));
        assert!(!is_absolute_uri("operator@example.com"));
        assert!(!is_absolute_uri("1sip:operator@example.com"));
        assert!(!is_absolute_uri("sip:"));
        assert!(!is_absolute_uri(":operator"));
        assert!(!is_absolute_uri("sip:operator@example.com\r\n"));
    }

    #[test]
    fn no_records_select_nothing() {
        assert_eq!(select_enum_uri(&[], NUMBER, "E2U+sip"), None);
    }
}
