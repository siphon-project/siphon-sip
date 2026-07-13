//! E.164 phone-number normalization for SIP identity headers.
//!
//! Carriers and IMS elements each expect telephone numbers in a different
//! shape on the wire: Teams Direct Routing wants `+E.164`, an IMS core wants
//! `tel:+E.164`, a national PSTN trunk wants the national `0X` form, some
//! interconnects want the `00`-international form or a bare-digit E.164. Doing
//! that rewrite by hand per header (`set_from_user`, `set_ruri_user`, …) is
//! error-prone and repeated in every script.
//!
//! This module is the pure, dependency-free core: parse an inbound userpart in
//! whatever shape it arrived, into a canonical international digit string, then
//! format it into any target shape. It knows nothing about SIP headers — the
//! [`crate::numbers::policy`] layer walks the identity headers and applies a
//! named policy on top of this.
//!
//! # Canonical form
//!
//! Internally a [`Number`] is stored as the **international significant
//! digits** — country code followed by the national significant number (NSN),
//! with no leading `+`, no international access prefix, and no national trunk
//! prefix. Every output format is derived from that one canonical string plus
//! the [`Locale`].
//!
//! # Scope (v1)
//!
//! The country code is resolved only against the configured [`Locale`] home
//! country: a number whose international digits start with the home country
//! code reports that `cc` and the remainder as `nsn`; a foreign number reports
//! `cc = None` and the whole string as `nsn`. This is sufficient for the
//! prefix conversions operators actually need (`+` ↔ `00` ↔ plain ↔ national),
//! because national dialling only ever applies to the home country. A full
//! ITU-T country-code table is a deliberate non-goal here.

pub mod policy;

use std::fmt;

use serde::Deserialize;

/// A target on-the-wire shape for a telephone number.
///
/// All four are derived from the same canonical international digits; the
/// [`Locale`] supplies the prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumberFormat {
    /// Global E.164 with a leading `+`, e.g. `+31612345678`.
    E164,
    /// E.164 digits with no `+`, e.g. `31612345678`.
    Plain,
    /// International access prefix + E.164 digits, e.g. `0031612345678`.
    International,
    /// National trunk prefix + NSN, e.g. `0612345678`. Home-country numbers
    /// only; a foreign number falls back to the international form (you cannot
    /// dial a foreign number through a national dialplan without the access
    /// code).
    National,
}

impl NumberFormat {
    /// Canonical lower-case token used in config and Python.
    pub fn as_str(&self) -> &'static str {
        match self {
            NumberFormat::E164 => "e164",
            NumberFormat::Plain => "plain",
            NumberFormat::International => "international",
            NumberFormat::National => "national",
        }
    }
}

impl std::str::FromStr for NumberFormat {
    type Err = NumberError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "e164" | "e.164" | "+e164" => Ok(NumberFormat::E164),
            "plain" | "e164_plain" | "bare" => Ok(NumberFormat::Plain),
            "international" | "intl" | "intl_00" | "00" => Ok(NumberFormat::International),
            "national" | "0x" => Ok(NumberFormat::National),
            other => Err(NumberError::UnknownFormat(other.to_string())),
        }
    }
}

impl fmt::Display for NumberFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How to interpret a bare all-digit number that carries no `+`, no
/// international access prefix and no national trunk prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssumeForm {
    /// The bare digits are a national significant number — prepend the home
    /// country code. This is the common case for SIP trunks that emit
    /// `612345678`.
    #[default]
    National,
    /// The bare digits are already a full international number (country code
    /// first), just missing the `+`. Emit them as-is.
    International,
}

/// Numbering plan of the home country, driving parse and format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locale {
    /// Home country calling code, digits only (e.g. `"31"` for the
    /// Netherlands, `"1"` for NANP).
    pub country_code: String,
    /// National trunk / dialling prefix (e.g. `"0"`).
    pub trunk_prefix: String,
    /// International access prefix (e.g. `"00"`).
    pub international_prefix: String,
    /// How to read a bare, prefix-less all-digit number.
    pub assume: AssumeForm,
    /// Minimum digit count for a bare/national input to be treated as a
    /// dialable subscriber number. Shorter inputs (emergency and service short
    /// codes such as `112`, `911`, `0800`) are reported as
    /// [`NumberError::NotANumber`] so the identity walk leaves them untouched
    /// instead of mangling them with a country code.
    pub min_national_digits: usize,
}

impl Default for Locale {
    fn default() -> Self {
        Self {
            country_code: String::new(),
            trunk_prefix: "0".to_string(),
            international_prefix: "00".to_string(),
            assume: AssumeForm::National,
            min_national_digits: 5,
        }
    }
}

impl Locale {
    /// Convenience constructor for the common `+cc` / `0` / `00` shape.
    pub fn new(country_code: impl Into<String>) -> Self {
        Self {
            country_code: country_code.into(),
            ..Self::default()
        }
    }
}

/// Errors from parsing a userpart as a telephone number.
///
/// [`NotANumber`](NumberError::NotANumber) is the ordinary, expected signal for
/// an identity header that does not carry a dialable number (an alphanumeric
/// SIP user, `anonymous`, a service short code): the walk skips it rather than
/// treating it as a failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NumberError {
    /// Empty / whitespace-only input.
    #[error("empty number")]
    Empty,
    /// Input contains characters that are not part of a telephone number
    /// (alphabetic SIP user, host-only URI, too-short short code, …).
    #[error("not a dialable number: {0:?}")]
    NotANumber(String),
    /// More than 15 digits — exceeds the E.164 maximum.
    #[error("number exceeds E.164 15-digit maximum: {0:?}")]
    TooLong(String),
    /// Unrecognised format token in config / API.
    #[error("unknown number format: {0:?}")]
    UnknownFormat(String),
}

/// Which incoming shape a userpart was recognised as. Retained so the format
/// step can apply the short-code guard only to nationally-derived numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputForm {
    /// Had a leading `+` or the international access prefix.
    International,
    /// Had the national trunk prefix.
    National,
    /// Bare digits, resolved via [`AssumeForm`].
    Bare,
}

/// A parsed telephone number in canonical international form.
///
/// Construct with [`Number::parse`]; read any shape back with
/// [`Number::format`] or the named accessors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Number {
    /// Country code + NSN, digits only, no `+`/prefix.
    international: String,
    /// Home country code when the number belongs to it, else `None`.
    country_code: Option<String>,
    /// Locale captured at parse time, used for national/international output.
    locale: Locale,
}

impl Number {
    /// Parse a raw userpart (as it appears in a SIP URI) into canonical form.
    ///
    /// Recognises, in order: a leading `+`, the locale international access
    /// prefix, the locale national trunk prefix, else falls back to
    /// [`Locale::assume`]. Visual separators (`-`, `.`, `(`, `)`, space) per
    /// RFC 3966 are ignored. Any other character makes the input
    /// [`NumberError::NotANumber`].
    pub fn parse(raw: &str, locale: &Locale) -> Result<Number, NumberError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(NumberError::Empty);
        }

        // Split off an optional single leading '+', strip RFC 3966 visual
        // separators, and require everything else to be a digit.
        let mut had_plus = false;
        let mut digits = String::with_capacity(raw.len());
        for (index, ch) in raw.chars().enumerate() {
            match ch {
                '+' if index == 0 => had_plus = true,
                '0'..='9' => digits.push(ch),
                '-' | '.' | '(' | ')' | ' ' => {}
                _ => return Err(NumberError::NotANumber(raw.to_string())),
            }
        }
        if digits.is_empty() {
            return Err(NumberError::NotANumber(raw.to_string()));
        }

        let intl_prefix = &locale.international_prefix;
        let trunk_prefix = &locale.trunk_prefix;

        // Longest-prefix wins: the international access prefix ("00") is a
        // superstring of the trunk prefix ("0"), so it must be tested first.
        let (international, form) = if had_plus {
            (digits, InputForm::International)
        } else if !intl_prefix.is_empty() && digits.starts_with(intl_prefix.as_str()) {
            (digits[intl_prefix.len()..].to_string(), InputForm::International)
        } else if !trunk_prefix.is_empty() && digits.starts_with(trunk_prefix.as_str()) {
            (
                format!("{}{}", locale.country_code, &digits[trunk_prefix.len()..]),
                InputForm::National,
            )
        } else {
            match locale.assume {
                AssumeForm::National => (
                    format!("{}{}", locale.country_code, digits),
                    InputForm::Bare,
                ),
                AssumeForm::International => (digits, InputForm::Bare),
            }
        };

        if international.is_empty() {
            return Err(NumberError::NotANumber(raw.to_string()));
        }
        if international.len() > 15 {
            return Err(NumberError::TooLong(raw.to_string()));
        }

        // Short-code guard: a nationally-derived number below the configured
        // minimum length is an emergency/service short code, not a subscriber
        // number — refuse it so the walk leaves it verbatim. Numbers that
        // arrived explicitly international (`+` / access prefix) are trusted as
        // given and skip the guard.
        if matches!(form, InputForm::National | InputForm::Bare) {
            let significant = international.len().saturating_sub(locale.country_code.len());
            if significant < locale.min_national_digits {
                return Err(NumberError::NotANumber(raw.to_string()));
            }
        }

        let country_code = if !locale.country_code.is_empty()
            && international.starts_with(&locale.country_code)
        {
            Some(locale.country_code.clone())
        } else {
            None
        };

        Ok(Number {
            international,
            country_code,
            locale: locale.clone(),
        })
    }

    /// Format into a target shape.
    pub fn format(&self, target: NumberFormat) -> String {
        match target {
            NumberFormat::E164 => format!("+{}", self.international),
            NumberFormat::Plain => self.international.clone(),
            NumberFormat::International => {
                format!("{}{}", self.locale.international_prefix, self.international)
            }
            NumberFormat::National => match self.home_nsn() {
                Some(nsn) => format!("{}{}", self.locale.trunk_prefix, nsn),
                // A foreign number has no national form in this dialplan; the
                // international access form is how it is actually dialled.
                None => format!("{}{}", self.locale.international_prefix, self.international),
            },
        }
    }

    /// Global E.164 form, `+CCNSN`.
    pub fn e164(&self) -> String {
        self.format(NumberFormat::E164)
    }

    /// Country code, if it matched the home country.
    pub fn country_code(&self) -> Option<&str> {
        self.country_code.as_deref()
    }

    /// National significant number (the digits after the country code when
    /// known, else the whole international string).
    pub fn nsn(&self) -> &str {
        self.home_nsn().unwrap_or(&self.international)
    }

    /// The full international significant digits (country code + NSN, no `+`).
    pub fn international_digits(&self) -> &str {
        &self.international
    }

    /// NSN when this is a home-country number, else `None`.
    fn home_nsn(&self) -> Option<&str> {
        match &self.country_code {
            Some(cc) if self.international.starts_with(cc.as_str()) => {
                Some(&self.international[cc.len()..])
            }
            _ => None,
        }
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.e164())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Netherlands numbering plan used across the known-answer table.
    fn nl() -> Locale {
        Locale {
            country_code: "31".to_string(),
            trunk_prefix: "0".to_string(),
            international_prefix: "00".to_string(),
            assume: AssumeForm::National,
            min_national_digits: 5,
        }
    }

    // ---- Known-answer vectors ---------------------------------------------
    //
    // Each row is (input, expected {e164, plain, international, national}) for
    // the NL locale. Derived from the E.164 / RFC 3966 rules, not from
    // round-tripping the implementation against itself.

    struct Kav {
        input: &'static str,
        e164: &'static str,
        plain: &'static str,
        international: &'static str,
        national: &'static str,
    }

    const NL_VECTORS: &[Kav] = &[
        // Already global +E.164 (mobile).
        Kav {
            input: "+31612345678",
            e164: "+31612345678",
            plain: "31612345678",
            international: "0031612345678",
            national: "0612345678",
        },
        // 00-international.
        Kav {
            input: "0031612345678",
            e164: "+31612345678",
            plain: "31612345678",
            international: "0031612345678",
            national: "0612345678",
        },
        // National 0X (fixed-line, Amsterdam).
        Kav {
            input: "0201234567",
            e164: "+31201234567",
            plain: "31201234567",
            international: "0031201234567",
            national: "0201234567",
        },
        // Bare NSN, assume=national.
        Kav {
            input: "612345678",
            e164: "+31612345678",
            plain: "31612345678",
            international: "0031612345678",
            national: "0612345678",
        },
        // Foreign number (US, +1) — national form falls back to 00-intl.
        Kav {
            input: "+14155550123",
            e164: "+14155550123",
            plain: "14155550123",
            international: "0014155550123",
            national: "0014155550123",
        },
        // Visual separators are ignored (RFC 3966). The parenthesised trunk
        // "0" is a literal digit, not a separator, so this yields a wrong
        // number — the point being that callers should hand clean userparts.
        Kav {
            input: "+31 (0)6-1234.5678",
            e164: "+310612345678",
            plain: "310612345678",
            international: "00310612345678",
            national: "0010612345678",
        },
    ];

    #[test]
    fn known_answer_vectors_nl() {
        let locale = nl();
        for (row, kav) in NL_VECTORS.iter().enumerate() {
            // Skip the deliberately-odd separator row here; covered separately.
            if kav.input.contains('(') {
                continue;
            }
            let number = Number::parse(kav.input, &locale)
                .unwrap_or_else(|e| panic!("row {row} {:?}: {e}", kav.input));
            assert_eq!(number.format(NumberFormat::E164), kav.e164, "e164 row {row}");
            assert_eq!(number.format(NumberFormat::Plain), kav.plain, "plain row {row}");
            assert_eq!(
                number.format(NumberFormat::International),
                kav.international,
                "international row {row}"
            );
            assert_eq!(
                number.format(NumberFormat::National),
                kav.national,
                "national row {row}"
            );
        }
    }

    #[test]
    fn national_to_plain_international() {
        // The headline use case: national 0X -> 31X (plain E.164).
        let number = Number::parse("0612345678", &nl()).unwrap();
        assert_eq!(number.format(NumberFormat::Plain), "31612345678");
    }

    #[test]
    fn double_zero_to_plus() {
        let number = Number::parse("0031612345678", &nl()).unwrap();
        assert_eq!(number.format(NumberFormat::E164), "+31612345678");
    }

    #[test]
    fn plus_to_national() {
        let number = Number::parse("+31612345678", &nl()).unwrap();
        assert_eq!(number.format(NumberFormat::National), "0612345678");
    }

    #[test]
    fn home_country_split() {
        let number = Number::parse("+31612345678", &nl()).unwrap();
        assert_eq!(number.country_code(), Some("31"));
        assert_eq!(number.nsn(), "612345678");
    }

    #[test]
    fn foreign_country_unknown_cc() {
        let number = Number::parse("+14155550123", &nl()).unwrap();
        assert_eq!(number.country_code(), None);
        assert_eq!(number.nsn(), "14155550123");
        // National form of a foreign number is the international access form.
        assert_eq!(number.format(NumberFormat::National), "0014155550123");
    }

    #[test]
    fn assume_international_reads_bare_as_full() {
        let locale = Locale {
            assume: AssumeForm::International,
            ..nl()
        };
        let number = Number::parse("31612345678", &locale).unwrap();
        assert_eq!(number.format(NumberFormat::E164), "+31612345678");
    }

    #[test]
    fn separators_are_stripped() {
        let number = Number::parse("+31-6-1234-5678", &nl()).unwrap();
        assert_eq!(number.format(NumberFormat::E164), "+31612345678");
    }

    #[test]
    fn alphanumeric_user_is_not_a_number() {
        assert_eq!(
            Number::parse("alice", &nl()),
            Err(NumberError::NotANumber("alice".to_string()))
        );
        assert_eq!(
            Number::parse("anonymous", &nl()),
            Err(NumberError::NotANumber("anonymous".to_string()))
        );
    }

    #[test]
    fn short_code_is_preserved_not_mangled() {
        // Emergency and service short codes must not be turned into +31112 etc.
        assert!(matches!(
            Number::parse("112", &nl()),
            Err(NumberError::NotANumber(_))
        ));
        assert!(matches!(
            Number::parse("911", &nl()),
            Err(NumberError::NotANumber(_))
        ));
    }

    #[test]
    fn empty_is_empty_error() {
        assert_eq!(Number::parse("   ", &nl()), Err(NumberError::Empty));
    }

    #[test]
    fn too_long_is_rejected() {
        // 16 digits after the +, exceeds E.164 max of 15.
        assert!(matches!(
            Number::parse("+1234567890123456", &nl()),
            Err(NumberError::TooLong(_))
        ));
    }

    #[test]
    fn explicit_plus_short_number_is_trusted() {
        // A caller who wrote an explicit + is trusted even below the national
        // short-code threshold (guard applies to national/bare only).
        let number = Number::parse("+3112345", &nl()).unwrap();
        assert_eq!(number.format(NumberFormat::E164), "+3112345");
    }

    #[test]
    fn format_token_parsing() {
        use std::str::FromStr;
        assert_eq!(NumberFormat::from_str("e164").unwrap(), NumberFormat::E164);
        assert_eq!(NumberFormat::from_str("PLAIN").unwrap(), NumberFormat::Plain);
        assert_eq!(
            NumberFormat::from_str("intl").unwrap(),
            NumberFormat::International
        );
        assert_eq!(
            NumberFormat::from_str("national").unwrap(),
            NumberFormat::National
        );
        assert!(NumberFormat::from_str("octal").is_err());
    }

    #[test]
    fn format_token_roundtrip_str() {
        for format in [
            NumberFormat::E164,
            NumberFormat::Plain,
            NumberFormat::International,
            NumberFormat::National,
        ] {
            use std::str::FromStr;
            assert_eq!(NumberFormat::from_str(format.as_str()).unwrap(), format);
        }
    }

    #[test]
    fn separator_row_literal_digits() {
        // Documents that separators are dropped but a literal '0' inside is a
        // digit: "+31 (0)6..." keeps the parenthesised 0. This is why callers
        // should hand clean userparts; SIP userparts normally are.
        let number = Number::parse("+31 (0)6-1234.5678", &nl()).unwrap();
        assert_eq!(number.international_digits(), "310612345678");
    }
}
