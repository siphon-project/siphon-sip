//! The YAML reader behind `siphon.yaml`, `script_config` and extension entries.
//!
//! Two entry points, one dialect:
//!
//! - [`from_str`] reads a document into a typed configuration struct. The
//!   struct is the schema: a `bool` field takes `true` / `false` and nothing
//!   else, so `yes`, `on` and friends are refused rather than guessed at.
//! - [`parse_value`] reads a document into an untyped [`Value`] tree, for the
//!   parts of the configuration siphon hands on without interpreting:
//!   `script_config` (which a script sees as Python data) and `extensions`.
//!
//! An untyped plain scalar is resolved by the YAML 1.2 core schema, exactly
//! as siphon has always resolved it, because a script compares what it gets:
//!
//! - `~`, `null`, `Null`, `NULL` and an empty value are null.
//! - `true`, `True`, `TRUE`, `false`, `False`, `FALSE` are booleans. `yes`,
//!   `no`, `on`, `off`, `y` and `n` are strings.
//! - Decimal integers, and `0x` / `0o` / `0b` integers, are integers. Digits
//!   with a leading zero (`0101234567`, `007`) are strings, never numbers, so
//!   a dialled number keeps its zeros. `+15551234567` is the integer
//!   15551234567; quote it to keep the `+`.
//! - Floats are the usual decimal and exponent forms plus `.inf` / `.nan`.
//!   A literal too large for a float (`1e400`) stays a string.
//! - Everything else is a string. Quoted and block scalars are always strings.
//!
//! In both readers a mapping that repeats a key is refused, `<<` is an
//! ordinary key (not a merge), and only one document is allowed.

use std::fmt;
use std::hash::{Hash, Hasher};

use indexmap::map::Entry;
use indexmap::{Equivalent, IndexMap};
use serde::de::DeserializeOwned;
use serde_saphyr::granit_parser::{Event, Parser, ScalarStyle, ScanError, Span, Tag};

/// Why a YAML document did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
}

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn at(message: impl fmt::Display, span: &Span) -> Self {
        Self::new(format!(
            "{message} at line {}, column {}",
            span.start.line(),
            span.start.col() + 1
        ))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<serde_saphyr::Error> for Error {
    fn from(error: serde_saphyr::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<ScanError> for Error {
    fn from(error: ScanError) -> Self {
        Self::new(format!(
            "{} at line {}, column {}",
            error.info(),
            error.marker().line(),
            error.marker().col() + 1
        ))
    }
}

/// Deepest nesting a document may have. Deeper than any real configuration,
/// shallow enough that a hostile file cannot exhaust the stack.
const MAX_DEPTH: usize = 128;

/// Most nodes alias expansion may produce in one [`parse_value`] document.
/// A routing table that reuses an anchored block a few thousand times is
/// nowhere near it; a billion-laughs file is refused.
const MAX_ALIAS_NODES: usize = 1_000_000;

/// The reader options every typed siphon YAML document is parsed with.
fn options() -> serde_saphyr::Options {
    let mut budget = serde_saphyr::Budget::default();
    budget.max_depth = MAX_DEPTH;
    // Configuration is operator input, and a routing table can legitimately
    // run to millions of nodes. Size stays unbounded, as it always was; the
    // alias limits stay, so a billion-laughs file is still refused.
    budget.max_events = usize::MAX;
    budget.max_nodes = usize::MAX;
    budget.max_total_scalar_bytes = usize::MAX;
    serde_saphyr::options! {
        budget: Some(budget),
        // `yes` / `on` into a `bool` field is an error, not `true`.
        strict_booleans: true,
        legacy_octal_numbers: false,
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
        ignore_binary_tag_for_string: true,
        // Errors name the line and column but do not quote the file: a
        // `siphon.yaml` holds secrets, and its errors end up in logs.
        with_snippet: false,
    }
}

/// Parse `text` as one YAML document into `T`.
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    serde_saphyr::from_str_with_options(text, options()).map_err(Error::from)
}

/// Parse `text` as one YAML document into an untyped [`Value`] tree.
///
/// An empty document is [`Value::Null`].
pub fn parse_value(text: &str) -> Result<Value, Error> {
    TreeBuilder::new(text).document()
}

/// A YAML number: an integer that fits `u64` or `i64`, or a float.
#[derive(Clone, Copy)]
pub struct Number(N);

#[derive(Clone, Copy)]
enum N {
    PositiveInteger(u64),
    /// Always below zero.
    NegativeInteger(i64),
    Float(f64),
}

impl Number {
    /// The value as an `i64`, when it is an integer that fits.
    pub fn as_i64(&self) -> Option<i64> {
        match self.0 {
            N::PositiveInteger(value) => i64::try_from(value).ok(),
            N::NegativeInteger(value) => Some(value),
            N::Float(_) => None,
        }
    }

    /// The value as a `u64`, when it is a non-negative integer.
    pub fn as_u64(&self) -> Option<u64> {
        match self.0 {
            N::PositiveInteger(value) => Some(value),
            N::NegativeInteger(_) | N::Float(_) => None,
        }
    }

    /// The value as an `f64`. Always `Some`; integers are converted.
    pub fn as_f64(&self) -> Option<f64> {
        Some(match self.0 {
            N::PositiveInteger(value) => value as f64,
            N::NegativeInteger(value) => value as f64,
            N::Float(value) => value,
        })
    }

    /// Whether the number was written as a float.
    pub fn is_f64(&self) -> bool {
        matches!(self.0, N::Float(_))
    }
}

impl From<u64> for Number {
    fn from(value: u64) -> Self {
        Self(N::PositiveInteger(value))
    }
}

impl From<i64> for Number {
    fn from(value: i64) -> Self {
        match u64::try_from(value) {
            Ok(positive) => Self(N::PositiveInteger(positive)),
            Err(_) => Self(N::NegativeInteger(value)),
        }
    }
}

impl From<f64> for Number {
    fn from(value: f64) -> Self {
        Self(N::Float(value))
    }
}

impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        match (self.0, other.0) {
            (N::PositiveInteger(left), N::PositiveInteger(right)) => left == right,
            (N::NegativeInteger(left), N::NegativeInteger(right)) => left == right,
            // NaN equals NaN here so a float can be a mapping key.
            (N::Float(left), N::Float(right)) => left == right || (left.is_nan() && right.is_nan()),
            _ => false,
        }
    }
}

impl Eq for Number {}

impl Hash for Number {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self.0 {
            N::PositiveInteger(value) => {
                state.write_u8(0);
                value.hash(state);
            }
            N::NegativeInteger(value) => {
                state.write_u8(1);
                value.hash(state);
            }
            N::Float(value) => {
                state.write_u8(2);
                // 0.0 and -0.0 are equal, so they must hash alike; every NaN
                // is equal to every other, likewise.
                let canonical = if value == 0.0 {
                    0.0f64
                } else if value.is_nan() {
                    f64::NAN
                } else {
                    value
                };
                canonical.to_bits().hash(state);
            }
        }
    }
}

impl fmt::Display for Number {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            N::PositiveInteger(value) => write!(formatter, "{value}"),
            N::NegativeInteger(value) => write!(formatter, "{value}"),
            N::Float(value) if value.is_nan() => formatter.write_str(".nan"),
            N::Float(value) if value.is_infinite() => {
                formatter.write_str(if value > 0.0 { ".inf" } else { "-.inf" })
            }
            N::Float(value) => write!(formatter, "{value:?}"),
        }
    }
}

impl fmt::Debug for Number {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Number({self})")
    }
}

/// A node carrying an application tag (`!widget value`). A YAML tag (`!!str`,
/// `!!binary`, ...) is never kept: it only steers how the node is read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TaggedValue {
    pub tag: String,
    pub value: Value,
}

/// An untyped YAML node.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Sequence(Vec<Value>),
    Mapping(Mapping),
    Tagged(Box<TaggedValue>),
}

impl Value {
    /// Whether this is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// The flag, when this is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(flag) => Some(*flag),
            _ => None,
        }
    }

    /// The number as an `i64`, when this is an integer that fits.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(number) => number.as_i64(),
            _ => None,
        }
    }

    /// The number as a `u64`, when this is a non-negative integer.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(number) => number.as_u64(),
            _ => None,
        }
    }

    /// The number as an `f64`, when this is a number.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(number) => number.as_f64(),
            _ => None,
        }
    }

    /// The text, when this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    /// The items, when this is a sequence.
    pub fn as_sequence(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Sequence(items) => Some(items),
            _ => None,
        }
    }

    /// The mapping, when this is one.
    pub fn as_mapping(&self) -> Option<&Mapping> {
        match self {
            Value::Mapping(mapping) => Some(mapping),
            _ => None,
        }
    }

    /// Whether this is a mapping.
    pub fn is_mapping(&self) -> bool {
        matches!(self, Value::Mapping(_))
    }

    /// The child at `index`: a mapping entry by key (`"name"`, or a
    /// [`Value`]) or a sequence item by position (`0`). `None` when there is
    /// no such child.
    pub fn get<I: Index>(&self, index: I) -> Option<&Value> {
        index.index_into(self)
    }
}

/// Something a [`Value`] or [`Mapping`] can be indexed by: `str`, `String`,
/// a [`Value`] key, or a `usize` sequence position.
pub trait Index {
    #[doc(hidden)]
    fn index_into<'value>(&self, value: &'value Value) -> Option<&'value Value>;

    #[doc(hidden)]
    fn index_into_mapping<'value>(&self, mapping: &'value Mapping) -> Option<&'value Value>;
}

impl Index for usize {
    fn index_into<'value>(&self, value: &'value Value) -> Option<&'value Value> {
        match value {
            Value::Sequence(items) => items.get(*self),
            Value::Mapping(mapping) => self.index_into_mapping(mapping),
            _ => None,
        }
    }

    fn index_into_mapping<'value>(&self, mapping: &'value Mapping) -> Option<&'value Value> {
        mapping.0.get(&Value::Number(Number::from(*self as u64)))
    }
}

impl Index for str {
    fn index_into<'value>(&self, value: &'value Value) -> Option<&'value Value> {
        self.index_into_mapping(value.as_mapping()?)
    }

    fn index_into_mapping<'value>(&self, mapping: &'value Mapping) -> Option<&'value Value> {
        mapping.0.get(self)
    }
}

impl Index for String {
    fn index_into<'value>(&self, value: &'value Value) -> Option<&'value Value> {
        self.as_str().index_into(value)
    }

    fn index_into_mapping<'value>(&self, mapping: &'value Mapping) -> Option<&'value Value> {
        self.as_str().index_into_mapping(mapping)
    }
}

impl Index for Value {
    fn index_into<'value>(&self, value: &'value Value) -> Option<&'value Value> {
        self.index_into_mapping(value.as_mapping()?)
    }

    fn index_into_mapping<'value>(&self, mapping: &'value Mapping) -> Option<&'value Value> {
        mapping.0.get(self)
    }
}

impl<T: Index + ?Sized> Index for &T {
    fn index_into<'value>(&self, value: &'value Value) -> Option<&'value Value> {
        (**self).index_into(value)
    }

    fn index_into_mapping<'value>(&self, mapping: &'value Mapping) -> Option<&'value Value> {
        (**self).index_into_mapping(mapping)
    }
}

static NULL: Value = Value::Null;

/// `value["key"]` / `value[0]`: the child, or `null` when there is none, so a
/// chain of lookups never panics.
impl<I: Index> std::ops::Index<I> for Value {
    type Output = Value;

    fn index(&self, index: I) -> &Value {
        index.index_into(self).unwrap_or(&NULL)
    }
}

/// A YAML mapping, in document order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mapping(IndexMap<Value, Value>);

impl Mapping {
    pub fn new() -> Self {
        Self::default()
    }

    /// The value at `index` (`"name"`, a [`Value`] key, or an integer key).
    pub fn get<I: Index>(&self, index: I) -> Option<&Value> {
        index.index_into_mapping(self)
    }

    /// Set `key` to `value`, returning the value it replaced.
    pub fn insert(&mut self, key: Value, value: Value) -> Option<Value> {
        self.0.insert(key, value)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> indexmap::map::Iter<'_, Value, Value> {
        self.0.iter()
    }
}

impl Hash for Mapping {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Mapping equality ignores order, so the hash must too: the length
        // alone is consistent with it, and a mapping used as a key is rare.
        self.0.len().hash(state);
    }
}

impl<'a> IntoIterator for &'a Mapping {
    type Item = (&'a Value, &'a Value);
    type IntoIter = indexmap::map::Iter<'a, Value, Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for Mapping {
    type Item = (Value, Value);
    type IntoIter = indexmap::map::IntoIter<Value, Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<(Value, Value)> for Mapping {
    fn from_iter<I: IntoIterator<Item = (Value, Value)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// Look a string key up without building a [`Value::String`] for it.
impl Equivalent<Value> for str {
    fn equivalent(&self, key: &Value) -> bool {
        matches!(key, Value::String(text) if text == self)
    }
}

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            // Exactly as a `str` hashes, so `Mapping::get("key")` finds it.
            Value::String(text) => text.as_str().hash(state),
            Value::Null => state.write_u8(0),
            Value::Bool(flag) => {
                state.write_u8(1);
                flag.hash(state);
            }
            Value::Number(number) => {
                state.write_u8(2);
                number.hash(state);
            }
            Value::Sequence(items) => {
                state.write_u8(3);
                items.hash(state);
            }
            Value::Mapping(mapping) => {
                state.write_u8(4);
                mapping.hash(state);
            }
            Value::Tagged(tagged) => {
                state.write_u8(5);
                tagged.hash(state);
            }
        }
    }
}

/// Builds a [`Value`] from parser events, resolving each plain scalar with
/// [`resolve_plain`].
struct TreeBuilder<'input> {
    parser: Parser<'input, serde_saphyr::granit_parser::StrInput<'input>>,
    /// Anchored nodes, by the parser's anchor id.
    anchors: std::collections::HashMap<usize, Value>,
    /// Nodes produced by alias expansion so far.
    alias_nodes: usize,
}

impl<'input> TreeBuilder<'input> {
    fn new(text: &'input str) -> Self {
        Self {
            parser: Parser::new_from_str(text),
            anchors: std::collections::HashMap::new(),
            alias_nodes: 0,
        }
    }

    fn next(&mut self) -> Result<(Event<'input>, Span), Error> {
        match self.parser.next_event() {
            Some(result) => Ok(result?),
            None => Err(Error::new("unexpected end of the YAML stream")),
        }
    }

    fn document(mut self) -> Result<Value, Error> {
        let mut root = Value::Null;
        let mut documents = 0usize;
        loop {
            let (event, span) = self.next()?;
            match event {
                Event::StreamStart | Event::DocumentEnd => {}
                Event::StreamEnd => return Ok(root),
                Event::DocumentStart(..) => {
                    documents += 1;
                    if documents > 1 {
                        return Err(Error::at(
                            "only one YAML document is allowed, found a second",
                            &span,
                        ));
                    }
                    let (event, span) = self.next()?;
                    root = self.node(event, span, 0)?;
                }
                other => return Err(Error::at(format!("unexpected YAML event {other:?}"), &span)),
            }
        }
    }

    fn node(&mut self, event: Event<'input>, span: Span, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::at(
                format!("nesting deeper than {MAX_DEPTH} levels"),
                &span,
            ));
        }
        let (value, anchor) = match event {
            Event::Alias(id) => {
                let value = self
                    .anchors
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| Error::at("alias to an unknown anchor", &span))?;
                self.alias_nodes = self.alias_nodes.saturating_add(value.node_count());
                if self.alias_nodes > MAX_ALIAS_NODES {
                    return Err(Error::at(
                        format!("aliases expand to more than {MAX_ALIAS_NODES} nodes"),
                        &span,
                    ));
                }
                return Ok(value);
            }
            Event::Scalar(text, style, anchor, tag) => {
                (scalar(&text, style, tag.as_deref(), &span)?, anchor)
            }
            Event::SequenceStart(_, anchor, tag) => {
                let mut items = Vec::new();
                loop {
                    let (event, span) = self.next()?;
                    if matches!(event, Event::SequenceEnd) {
                        break;
                    }
                    items.push(self.node(event, span, depth + 1)?);
                }
                (local_tagged(Value::Sequence(items), tag.as_deref()), anchor)
            }
            Event::MappingStart(_, anchor, tag) => {
                let mut mapping = IndexMap::new();
                loop {
                    let (event, key_span) = self.next()?;
                    if matches!(event, Event::MappingEnd) {
                        break;
                    }
                    let key = self.node(event, key_span, depth + 1)?;
                    let (event, span) = self.next()?;
                    let value = self.node(event, span, depth + 1)?;
                    match mapping.entry(key) {
                        Entry::Vacant(slot) => {
                            slot.insert(value);
                        }
                        Entry::Occupied(slot) => {
                            return Err(Error::at(
                                format!("duplicate mapping key {}", slot.key().describe_key()),
                                &key_span,
                            ));
                        }
                    }
                }
                (
                    local_tagged(Value::Mapping(Mapping(mapping)), tag.as_deref()),
                    anchor,
                )
            }
            other => return Err(Error::at(format!("unexpected YAML event {other:?}"), &span)),
        };
        if anchor != 0 {
            self.anchors.insert(anchor, value.clone());
        }
        Ok(value)
    }
}

/// The value of one scalar node.
fn scalar(text: &str, style: ScalarStyle, tag: Option<&Tag>, span: &Span) -> Result<Value, Error> {
    let Some(tag) = tag else {
        return Ok(if style == ScalarStyle::Plain {
            resolve_plain(text).map_err(|message| Error::at(message, span))?
        } else {
            Value::String(text.to_owned())
        });
    };
    let Some(name) = yaml_tag_name(tag) else {
        // An application tag (`!foo`): kept, for the consumer to accept or
        // refuse. Its content reads as if untagged.
        let value = scalar(text, style, None, span)?;
        return Ok(Value::Tagged(Box::new(TaggedValue {
            tag: tag_name(tag),
            value,
        })));
    };
    // A YAML tag decides the type whatever the quoting.
    let wrong = |expected: &str| Error::at(format!("{text:?} is not {expected}"), span);
    Ok(match name.as_ref() {
        "null" => match text {
            "~" | "null" | "Null" | "NULL" => Value::Null,
            _ => return Err(wrong("null")),
        },
        "bool" => Value::Bool(parse_bool(text).ok_or_else(|| wrong("a boolean"))?),
        "int" => match parse_integer(text) {
            Some(Ok(number)) => Value::Number(number),
            Some(Err(message)) => return Err(Error::at(message, span)),
            None => return Err(wrong("an integer")),
        },
        "float" => Value::Number(
            parse_integer(text)
                .and_then(Result::ok)
                .and_then(|number| number.as_f64())
                .or_else(|| parse_float(text))
                .ok_or_else(|| wrong("a float"))?
                .into(),
        ),
        // `!!str`, and the YAML tags that only describe text (`!!binary`,
        // `!!timestamp`, ...): the text as written.
        _ => Value::String(text.to_owned()),
    })
}

/// Wrap a collection that carries an application tag; a YAML tag (`!!set`,
/// `!!omap`, ...) on a collection changes nothing.
fn local_tagged(value: Value, tag: Option<&Tag>) -> Value {
    match tag {
        Some(tag) if yaml_tag_name(tag).is_none() => Value::Tagged(Box::new(TaggedValue {
            tag: tag_name(tag),
            value,
        })),
        _ => value,
    }
}

/// The type name of a tag in the YAML namespace (`!!str` is `str`), or
/// `None` for an application tag.
fn yaml_tag_name(tag: &Tag) -> Option<std::borrow::Cow<'_, str>> {
    tag.suffix_in_namespace("tag:yaml.org,2002:")
}

fn tag_name(tag: &Tag) -> String {
    format!("{}{}", tag.handle(), tag.suffix())
}

/// Resolve an untagged plain scalar: null, boolean, integer, float or string.
fn resolve_plain(text: &str) -> Result<Value, String> {
    if matches!(text, "" | "~" | "null" | "Null" | "NULL") {
        return Ok(Value::Null);
    }
    if let Some(flag) = parse_bool(text) {
        return Ok(Value::Bool(flag));
    }
    if let Some(number) = parse_integer(text) {
        return number.map(Value::Number);
    }
    if !digits_with_leading_zero(text) {
        if let Some(float) = parse_float(text) {
            return Ok(Value::Number(float.into()));
        }
    }
    Ok(Value::String(text.to_owned()))
}

fn parse_bool(text: &str) -> Option<bool> {
    match text {
        "true" | "True" | "TRUE" => Some(true),
        "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

/// `Some(Ok)` for an integer that fits `u64` / `i64`, `Some(Err)` for one
/// that does not, `None` for text that is not an integer.
fn parse_integer(text: &str) -> Option<Result<Number, String>> {
    let (negative, unsigned) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let (radix, digits) = if let Some(rest) = unsigned.strip_prefix("0x") {
        (16, rest)
    } else if let Some(rest) = unsigned.strip_prefix("0o") {
        (8, rest)
    } else if let Some(rest) = unsigned.strip_prefix("0b") {
        (2, rest)
    } else {
        if digits_with_leading_zero(text) {
            return None;
        }
        (10, unsigned)
    };
    if digits.is_empty() || !digits.chars().all(|digit| digit.is_digit(radix)) {
        return None;
    }
    let out_of_range = || Err(format!("integer {text} is out of range"));
    let Ok(magnitude) = u128::from_str_radix(digits, radix) else {
        return Some(out_of_range());
    };
    Some(if negative {
        match i64::try_from(magnitude).map(|value| -value) {
            Ok(value) => Ok(Number::from(value)),
            Err(_) if magnitude == 1u128 << 63 => Ok(Number::from(i64::MIN)),
            Err(_) => out_of_range(),
        }
    } else {
        u64::try_from(magnitude)
            .map(Number::from)
            .or_else(|_| out_of_range())
    })
}

/// Digits with a leading zero, optionally signed (`007`, `-0612`): a string
/// in YAML 1.2, not a number.
fn digits_with_leading_zero(text: &str) -> bool {
    let digits = text.strip_prefix(['-', '+']).unwrap_or(text);
    digits.len() > 1
        && digits.starts_with('0')
        && digits[1..].bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_float(text: &str) -> Option<f64> {
    let unsigned = match text.strip_prefix('+') {
        Some(rest) if rest.starts_with(['+', '-']) => return None,
        Some(rest) => rest,
        None => text,
    };
    match unsigned {
        ".inf" | ".Inf" | ".INF" => return Some(f64::INFINITY),
        "-.inf" | "-.Inf" | "-.INF" => return Some(f64::NEG_INFINITY),
        ".nan" | ".NaN" | ".NAN" => return Some(f64::NAN),
        _ => {}
    }
    // Rust's float syntax is a superset of YAML's for the forms that reach
    // here, apart from its own `inf` / `nan` words, which come back
    // non-finite and are refused, as is a literal too large for an `f64`.
    unsigned
        .parse::<f64>()
        .ok()
        .filter(|float| float.is_finite())
}

impl Value {
    /// Nodes in this subtree, itself included.
    fn node_count(&self) -> usize {
        match self {
            Value::Sequence(items) => 1 + items.iter().map(Value::node_count).sum::<usize>(),
            Value::Mapping(mapping) => {
                1 + mapping
                    .iter()
                    .map(|(key, value)| key.node_count() + value.node_count())
                    .sum::<usize>()
            }
            Value::Tagged(tagged) => 1 + tagged.value.node_count(),
            _ => 1,
        }
    }

    /// A mapping key as an error message names it.
    fn describe_key(&self) -> String {
        match self {
            Value::Null => "null".to_owned(),
            Value::Bool(flag) => flag.to_string(),
            Value::Number(number) => number.to_string(),
            Value::String(text) => format!("{text:?}"),
            _ => "(a collection)".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(text: &str) -> Value {
        parse_value(&format!("value: {text}\n"))
            .unwrap_or_else(|error| panic!("{text:?}: {error}"))
            .get("value")
            .cloned()
            .expect("the value key")
    }

    fn string(text: &str) -> Value {
        Value::String(text.to_owned())
    }

    fn integer(value: i64) -> Value {
        Value::Number(value.into())
    }

    fn float(value: f64) -> Value {
        Value::Number(value.into())
    }

    #[test]
    fn only_the_core_schema_spellings_are_booleans() {
        for text in ["true", "True", "TRUE"] {
            assert_eq!(plain(text), Value::Bool(true), "{text}");
        }
        for text in ["false", "False", "FALSE"] {
            assert_eq!(plain(text), Value::Bool(false), "{text}");
        }
        // YAML 1.1 words a script may compare against as text.
        for text in [
            "yes", "no", "on", "off", "y", "n", "Yes", "ON", "Off", "tRuE",
        ] {
            assert_eq!(plain(text), string(text), "{text}");
        }
    }

    #[test]
    fn only_the_core_schema_spellings_are_null() {
        for text in ["~", "null", "Null", "NULL", ""] {
            assert_eq!(plain(text), Value::Null, "{text:?}");
        }
        assert_eq!(plain("nUlL"), string("nUlL"));
        assert_eq!(plain("\"\""), string(""));
        assert_eq!(plain("'~'"), string("~"));
    }

    #[test]
    fn digits_with_a_leading_zero_stay_text() {
        // A dialled number keeps its zeros: never an int, never a float.
        for text in ["0101234567", "00101012345678", "007", "00", "-007", "+0101"] {
            assert_eq!(plain(text), string(text), "{text}");
        }
    }

    #[test]
    fn integers_resolve_in_every_core_schema_form() {
        assert_eq!(plain("0"), integer(0));
        assert_eq!(plain("-0"), integer(0));
        assert_eq!(plain("+0"), integer(0));
        assert_eq!(plain("1233"), integer(1233));
        assert_eq!(plain("-12"), integer(-12));
        // A leading `+` is a sign; quote the value to keep it.
        assert_eq!(plain("+15551234567"), integer(15_551_234_567));
        assert_eq!(plain("\"+15551234567\""), string("+15551234567"));
        assert_eq!(plain("0x1F"), integer(31));
        assert_eq!(plain("0o17"), integer(15));
        assert_eq!(plain("0b101"), integer(5));
        assert_eq!(plain("+0x10"), integer(16));
        assert_eq!(plain("-0x10"), integer(-16));
        assert_eq!(
            plain("18446744073709551615"),
            Value::Number(u64::MAX.into())
        );
        assert_eq!(plain("-9223372036854775808"), integer(i64::MIN));
    }

    #[test]
    fn number_like_text_outside_the_core_schema_stays_text() {
        for text in [
            "1_000",
            "0X1F",
            "0O17",
            "0xFF_FF",
            "0x",
            "0o",
            "1:30",
            "190:20:30",
            "1_0.5",
        ] {
            assert_eq!(plain(text), string(text), "{text}");
        }
        assert_eq!(plain("2001-12-14"), string("2001-12-14"));
        assert_eq!(plain("192.0.2.1:5060"), string("192.0.2.1:5060"));
        assert_eq!(plain("inf"), string("inf"));
        assert_eq!(plain("nan"), string("nan"));
    }

    #[test]
    fn an_integer_out_of_range_is_refused() {
        let error = parse_value("value: 18446744073709551616\n").expect_err("out of range");
        assert!(error.to_string().contains("out of range"), "{error}");
        let error = parse_value("value: -9223372036854775809\n").expect_err("out of range");
        assert!(error.to_string().contains("out of range"), "{error}");
    }

    #[test]
    fn floats_resolve_in_the_core_schema_forms() {
        assert_eq!(plain("0.5"), float(0.5));
        assert_eq!(plain(".5"), float(0.5));
        assert_eq!(plain("1."), float(1.0));
        assert_eq!(plain("+1.5"), float(1.5));
        assert_eq!(plain("1e3"), float(1000.0));
        assert_eq!(plain("1.5E-3"), float(0.0015));
        assert_eq!(plain("0009.5"), float(9.5));
        assert_eq!(plain(".inf"), float(f64::INFINITY));
        assert_eq!(plain("-.Inf"), float(f64::NEG_INFINITY));
        assert_eq!(plain(".NaN"), float(f64::NAN));
        // Too large for an f64: kept as written rather than turned into inf.
        assert_eq!(plain("1e400"), string("1e400"));
    }

    #[test]
    fn quoted_and_block_scalars_are_always_text() {
        assert_eq!(plain("\"true\""), string("true"));
        assert_eq!(plain("'10'"), string("10"));
        let document = parse_value("value: |\n  10\n").expect("parses");
        assert_eq!(document["value"], string("10\n"));
    }

    #[test]
    fn mapping_keys_resolve_like_values() {
        let document = parse_value(concat!(
            "1233: integer\n",
            "\"1234\": text\n",
            "+1: signed\n",
            "\"+32\": quoted\n",
            "001: zeros\n",
            "true: flag\n",
            "on: word\n",
        ))
        .expect("parses");
        let mapping = document.as_mapping().expect("a mapping");
        let keys: Vec<&Value> = mapping.iter().map(|(key, _)| key).collect();
        assert_eq!(
            keys,
            [
                &integer(1233),
                &string("1234"),
                &integer(1),
                &string("+32"),
                &string("001"),
                &Value::Bool(true),
                &string("on"),
            ]
        );
    }

    #[test]
    fn a_repeated_key_is_refused() {
        let error = parse_value("a: 1\na: 2\n").expect_err("duplicate");
        assert!(error.to_string().contains("duplicate"), "{error}");
        // Two spellings of one integer are the same key.
        let error = parse_value("0x10: a\n16: b\n").expect_err("duplicate");
        assert!(error.to_string().contains("duplicate"), "{error}");
        // A string and an integer are not.
        parse_value("1: a\n\"1\": b\n").expect("distinct keys");
    }

    #[test]
    fn a_merge_key_is_an_ordinary_key() {
        let document =
            parse_value("base: &base {x: 1}\nderived:\n  <<: *base\n  y: 2\n").expect("parses");
        let derived = document.get("derived").expect("derived");
        assert_eq!(
            derived.get("<<").and_then(|base| base.get("x")),
            Some(&integer(1))
        );
        assert_eq!(derived.get("x"), None);
    }

    #[test]
    fn aliases_repeat_their_anchor() {
        let document = parse_value("a: &list [1, 2]\nb: *list\n").expect("parses");
        assert_eq!(document["a"], document["b"]);
    }

    #[test]
    fn an_alias_bomb_is_refused() {
        let mut text = String::from("l0: &l0 [x, x, x, x, x, x, x, x, x, x]\n");
        for level in 1..8 {
            let previous = level - 1;
            text.push_str(&format!(
                "l{level}: &l{level} [*l{previous}, *l{previous}, *l{previous}, *l{previous}, \
                 *l{previous}, *l{previous}, *l{previous}, *l{previous}, *l{previous}, \
                 *l{previous}]\n"
            ));
        }
        let error = parse_value(&text).expect_err("ten to the eighth nodes");
        assert!(error.to_string().contains("aliases expand"), "{error}");
    }

    #[test]
    fn nesting_beyond_the_limit_is_refused() {
        let text = format!(
            "{}1{}",
            "[".repeat(MAX_DEPTH + 2),
            "]".repeat(MAX_DEPTH + 2)
        );
        parse_value(&text).expect_err("too deep");
        let text = format!("{}1{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        parse_value(&text).expect("deep but within the limit");
    }

    #[test]
    fn only_one_document_is_allowed() {
        parse_value("a: 1\n---\nb: 2\n").expect_err("two documents");
        assert_eq!(
            parse_value("---\na: 1\n...\n").expect("one").get("a"),
            Some(&integer(1))
        );
        assert_eq!(parse_value("").expect("empty"), Value::Null);
        assert_eq!(
            parse_value("# only a comment\n").expect("empty"),
            Value::Null
        );
    }

    #[test]
    fn yaml_tags_steer_the_type_and_application_tags_are_kept() {
        let document = parse_value(concat!(
            "text: !!str 123\n",
            "number: !!int \"7\"\n",
            "real: !!float 1\n",
            "flag: !!bool \"true\"\n",
            "blob: !!binary aGVsbG8=\n",
            "set: !!set {x, y}\n",
            "custom: !widget bar\n",
        ))
        .expect("parses");
        assert_eq!(document["text"], string("123"));
        assert_eq!(document["number"], integer(7));
        assert_eq!(document["real"], float(1.0));
        assert_eq!(document["flag"], Value::Bool(true));
        assert_eq!(document["blob"], string("aGVsbG8="));
        assert!(document["set"].is_mapping());
        assert_eq!(
            document["custom"],
            Value::Tagged(Box::new(TaggedValue {
                tag: "!widget".to_owned(),
                value: string("bar"),
            }))
        );
        parse_value("value: !!int seven\n").expect_err("not an integer");
    }

    #[test]
    fn errors_name_the_line_without_quoting_the_file() {
        let error = parse_value("a: 1\nb: [\n").expect_err("unterminated");
        assert!(error.to_string().contains("line"), "{error}");
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct Typed {
            password: String,
            port: u16,
        }
        let error = from_str::<Typed>("password: hunter2\nport: many\n").expect_err("not a port");
        let message = error.to_string();
        assert!(message.contains("line 2"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
    }

    #[test]
    fn a_typed_bool_takes_only_true_or_false() {
        #[derive(serde::Deserialize, Debug)]
        struct Typed {
            flag: bool,
        }
        assert!(from_str::<Typed>("flag: true\n").expect("parses").flag);
        assert!(!from_str::<Typed>("flag: False\n").expect("parses").flag);
        for word in ["yes", "on", "y", "no", "off"] {
            from_str::<Typed>(&format!("flag: {word}\n")).expect_err(word);
        }
    }

    #[test]
    fn a_typed_document_refuses_a_repeated_key() {
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct Typed {
            port: u16,
        }
        from_str::<Typed>("port: 1\nport: 2\n").expect_err("duplicate");
    }

    #[test]
    fn a_string_key_is_found_without_building_a_value() {
        // `Hash` for a string `Value` must agree with `Hash` for `str`, or
        // this lookup misses on a populated map.
        let document = parse_value(concat!(
            "alpha: 1\nbeta: 2\ngamma: 3\ndelta: 4\nepsilon: 5\n",
            "zeta: 6\neta: 7\ntheta: 8\niota: 9\nkappa: 10\n",
        ))
        .expect("parses");
        let mapping = document.as_mapping().expect("a mapping");
        for (index, name) in [
            "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
        ]
        .iter()
        .enumerate()
        {
            let expected = integer(index as i64 + 1);
            assert_eq!(mapping.get(*name), Some(&expected), "{name}");
            assert_eq!(mapping.get(name.to_string()), Some(&expected), "{name}");
            assert_eq!(mapping.get(string(name)), Some(&expected), "{name}");
        }
        assert_eq!(mapping.get("missing"), None);
    }

    #[test]
    fn indexing_never_panics() {
        let document = parse_value("routes:\n  - gateway: a\n").expect("parses");
        assert_eq!(document["routes"][0]["gateway"], string("a"));
        assert_eq!(document["routes"][5]["gateway"], Value::Null);
        assert_eq!(document["missing"]["deeper"], Value::Null);
        assert!(document
            .get("routes")
            .and_then(|routes| routes.get(0))
            .is_some());
    }

    #[test]
    fn number_accessors_and_display() {
        assert_eq!(plain("7").as_u64(), Some(7));
        assert_eq!(plain("7").as_i64(), Some(7));
        assert_eq!(plain("-7").as_u64(), None);
        assert_eq!(plain("-7").as_i64(), Some(-7));
        assert_eq!(plain("18446744073709551615").as_i64(), None);
        assert_eq!(plain("1.5").as_f64(), Some(1.5));
        assert_eq!(plain("1.5").as_i64(), None);
        let Value::Number(number) = plain("1.0") else {
            panic!("a number")
        };
        assert!(number.is_f64());
        assert_eq!(number.to_string(), "1.0");
        let Value::Number(number) = plain("-.inf") else {
            panic!("a number")
        };
        assert_eq!(number.to_string(), "-.inf");
    }
}
