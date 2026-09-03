//! Bencode encoder/decoder for the RTPEngine NG protocol.
//!
//! Bencode has four types:
//! - Byte strings: `<length>:<data>` (e.g. `5:hello`)
//! - Integers: `i<number>e` (e.g. `i42e`)
//! - Lists: `l<items>e` (e.g. `l5:helloi42ee`)
//! - Dictionaries: `d<key><value>...e` (keys are byte strings, sorted)

use super::error::RtpEngineError;

/// A bencode value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BencodeValue {
    /// Byte string (SDP bodies can contain arbitrary bytes).
    String(Vec<u8>),
    /// Signed integer.
    Integer(i64),
    /// Ordered list of values.
    List(Vec<BencodeValue>),
    /// Dictionary — ordered key-value pairs (keys are byte strings).
    Dict(Vec<(Vec<u8>, BencodeValue)>),
}

impl BencodeValue {
    /// Get as a UTF-8 string, if this is a String variant.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            BencodeValue::String(bytes) => std::str::from_utf8(bytes).ok(),
            _ => None,
        }
    }

    /// Get as raw bytes, if this is a String variant.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            BencodeValue::String(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// Get as an integer, if this is an Integer variant.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            BencodeValue::Integer(number) => Some(*number),
            _ => None,
        }
    }

    /// Get as a dict slice, if this is a Dict variant.
    pub fn as_dict(&self) -> Option<&[(Vec<u8>, BencodeValue)]> {
        match self {
            BencodeValue::Dict(pairs) => Some(pairs),
            _ => None,
        }
    }

    /// Look up a key in a Dict and return its string value.
    pub fn dict_get_str(&self, key: &str) -> Option<&str> {
        self.as_dict().and_then(|pairs| {
            pairs
                .iter()
                .find(|(k, _)| k == key.as_bytes())
                .and_then(|(_, value)| value.as_str())
        })
    }

    /// Look up a key in a Dict and return its bytes value.
    pub fn dict_get_bytes(&self, key: &str) -> Option<&[u8]> {
        self.as_dict().and_then(|pairs| {
            pairs
                .iter()
                .find(|(k, _)| k == key.as_bytes())
                .and_then(|(_, value)| value.as_bytes())
        })
    }

    /// Look up a key in a Dict and return the value.
    pub fn dict_get(&self, key: &str) -> Option<&BencodeValue> {
        self.as_dict().and_then(|pairs| {
            pairs
                .iter()
                .find(|(k, _)| k == key.as_bytes())
                .map(|(_, value)| value)
        })
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encode a bencode value to bytes.
pub fn encode(value: &BencodeValue) -> Vec<u8> {
    let mut output = Vec::new();
    encode_into(value, &mut output);
    output
}

fn encode_into(value: &BencodeValue, output: &mut Vec<u8>) {
    match value {
        BencodeValue::String(bytes) => {
            output.extend_from_slice(bytes.len().to_string().as_bytes());
            output.push(b':');
            output.extend_from_slice(bytes);
        }
        BencodeValue::Integer(number) => {
            output.push(b'i');
            output.extend_from_slice(number.to_string().as_bytes());
            output.push(b'e');
        }
        BencodeValue::List(items) => {
            output.push(b'l');
            for item in items {
                encode_into(item, output);
            }
            output.push(b'e');
        }
        BencodeValue::Dict(pairs) => {
            output.push(b'd');
            for (key, value) in pairs {
                // Keys are always byte strings.
                output.extend_from_slice(key.len().to_string().as_bytes());
                output.push(b':');
                output.extend_from_slice(key);
                encode_into(value, output);
            }
            output.push(b'e');
        }
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decode a bencode value from the beginning of the input.
/// Returns the decoded value and the remaining unconsumed bytes.
pub fn decode(input: &[u8]) -> Result<(BencodeValue, &[u8]), RtpEngineError> {
    if input.is_empty() {
        return Err(RtpEngineError::Decode("empty input".to_string()));
    }

    match input[0] {
        b'i' => decode_integer(input),
        b'l' => decode_list(input),
        b'd' => decode_dict(input),
        b'0'..=b'9' => decode_string(input),
        byte => Err(RtpEngineError::Decode(format!(
            "unexpected byte 0x{byte:02x} at start of value"
        ))),
    }
}

/// Decode a complete bencode dictionary from the entire input.
pub fn decode_full_dict(input: &[u8]) -> Result<BencodeValue, RtpEngineError> {
    let (value, remaining) = decode(input)?;
    if !remaining.is_empty() {
        return Err(RtpEngineError::Decode(format!(
            "{} trailing bytes after value",
            remaining.len()
        )));
    }
    if !matches!(value, BencodeValue::Dict(_)) {
        return Err(RtpEngineError::Decode(
            "expected dictionary at top level".to_string(),
        ));
    }
    Ok(value)
}

fn decode_string(input: &[u8]) -> Result<(BencodeValue, &[u8]), RtpEngineError> {
    // Find the colon separator.
    let colon_position = input
        .iter()
        .position(|&byte| byte == b':')
        .ok_or_else(|| RtpEngineError::Decode("string missing ':' separator".to_string()))?;

    let length_str = std::str::from_utf8(&input[..colon_position])
        .map_err(|_| RtpEngineError::Decode("invalid UTF-8 in string length".to_string()))?;

    let length: usize = length_str
        .parse()
        .map_err(|_| RtpEngineError::Decode(format!("invalid string length: {length_str}")))?;

    let data_start = colon_position + 1;
    let data_end = data_start + length;

    if data_end > input.len() {
        return Err(RtpEngineError::Decode(format!(
            "string length {length} exceeds available data ({})",
            input.len() - data_start
        )));
    }

    let bytes = input[data_start..data_end].to_vec();
    Ok((BencodeValue::String(bytes), &input[data_end..]))
}

fn decode_integer(input: &[u8]) -> Result<(BencodeValue, &[u8]), RtpEngineError> {
    debug_assert_eq!(input[0], b'i');

    let end_position = input
        .iter()
        .position(|&byte| byte == b'e')
        .ok_or_else(|| RtpEngineError::Decode("integer missing 'e' terminator".to_string()))?;

    let number_str = std::str::from_utf8(&input[1..end_position])
        .map_err(|_| RtpEngineError::Decode("invalid UTF-8 in integer".to_string()))?;

    let number: i64 = number_str
        .parse()
        .map_err(|_| RtpEngineError::Decode(format!("invalid integer: {number_str}")))?;

    Ok((BencodeValue::Integer(number), &input[end_position + 1..]))
}

fn decode_list(input: &[u8]) -> Result<(BencodeValue, &[u8]), RtpEngineError> {
    debug_assert_eq!(input[0], b'l');

    let mut remaining = &input[1..];
    let mut items = Vec::new();

    loop {
        if remaining.is_empty() {
            return Err(RtpEngineError::Decode(
                "list missing 'e' terminator".to_string(),
            ));
        }
        if remaining[0] == b'e' {
            return Ok((BencodeValue::List(items), &remaining[1..]));
        }
        let (value, rest) = decode(remaining)?;
        items.push(value);
        remaining = rest;
    }
}

fn decode_dict(input: &[u8]) -> Result<(BencodeValue, &[u8]), RtpEngineError> {
    debug_assert_eq!(input[0], b'd');

    let mut remaining = &input[1..];
    let mut pairs = Vec::new();

    loop {
        if remaining.is_empty() {
            return Err(RtpEngineError::Decode(
                "dict missing 'e' terminator".to_string(),
            ));
        }
        if remaining[0] == b'e' {
            return Ok((BencodeValue::Dict(pairs), &remaining[1..]));
        }
        // Keys must be byte strings.
        let (key_value, rest) = decode_string(remaining)?;
        let key = match key_value {
            BencodeValue::String(bytes) => bytes,
            _ => unreachable!("decode_string always returns String"),
        };
        let (value, rest) = decode(rest)?;
        pairs.push((key, value));
        remaining = rest;
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors
// ---------------------------------------------------------------------------

impl BencodeValue {
    /// Create a string value from a `&str`.
    pub fn string(s: &str) -> Self {
        BencodeValue::String(s.as_bytes().to_vec())
    }

    /// Create an integer value.
    pub fn from_integer(number: i64) -> Self {
        BencodeValue::Integer(number)
    }

    /// Build a dictionary from key-value pairs.
    pub fn dict(pairs: Vec<(&str, BencodeValue)>) -> Self {
        BencodeValue::Dict(
            pairs
                .into_iter()
                .map(|(key, value)| (key.as_bytes().to_vec(), value))
                .collect(),
        )
    }

    /// Build a list of string values.
    pub fn string_list(items: &[&str]) -> Self {
        BencodeValue::List(items.iter().map(|s| BencodeValue::string(s)).collect())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Encoding --

    #[test]
    fn encode_empty_string() {
        let value = BencodeValue::String(vec![]);
        assert_eq!(encode(&value), b"0:");
    }

    #[test]
    fn encode_short_string() {
        let value = BencodeValue::string("hello");
        assert_eq!(encode(&value), b"5:hello");
    }

    #[test]
    fn encode_binary_string() {
        let value = BencodeValue::String(vec![0x00, 0xff, 0x42]);
        assert_eq!(encode(&value), b"3:\x00\xff\x42");
    }

    #[test]
    fn encode_integer_zero() {
        let value = BencodeValue::Integer(0);
        assert_eq!(encode(&value), b"i0e");
    }

    #[test]
    fn encode_positive_integer() {
        let value = BencodeValue::Integer(42);
        assert_eq!(encode(&value), b"i42e");
    }

    #[test]
    fn encode_negative_integer() {
        let value = BencodeValue::Integer(-7);
        assert_eq!(encode(&value), b"i-7e");
    }

    #[test]
    fn encode_empty_list() {
        let value = BencodeValue::List(vec![]);
        assert_eq!(encode(&value), b"le");
    }

    #[test]
    fn encode_list_with_items() {
        let value = BencodeValue::List(vec![
            BencodeValue::string("hello"),
            BencodeValue::Integer(42),
        ]);
        assert_eq!(encode(&value), b"l5:helloi42ee");
    }

    #[test]
    fn encode_empty_dict() {
        let value = BencodeValue::Dict(vec![]);
        assert_eq!(encode(&value), b"de");
    }

    #[test]
    fn encode_dict_with_entries() {
        let value = BencodeValue::dict(vec![
            ("command", BencodeValue::string("offer")),
            ("call-id", BencodeValue::string("abc-1234")),
        ]);
        assert_eq!(encode(&value), b"d7:command5:offer7:call-id8:abc-1234e");
    }

    #[test]
    fn encode_nested_dict_with_list() {
        let value = BencodeValue::dict(vec![(
            "flags",
            BencodeValue::string_list(&["trust-address", "symmetric"]),
        )]);
        assert_eq!(encode(&value), b"d5:flagsl13:trust-address9:symmetricee");
    }

    // -- Decoding --

    #[test]
    fn decode_empty_string() {
        let (value, remaining) = decode(b"0:").unwrap();
        assert_eq!(value, BencodeValue::String(vec![]));
        assert!(remaining.is_empty());
    }

    #[test]
    fn decode_short_string() {
        let (value, remaining) = decode(b"5:hello").unwrap();
        assert_eq!(value, BencodeValue::string("hello"));
        assert!(remaining.is_empty());
    }

    #[test]
    fn decode_string_with_remaining() {
        let (value, remaining) = decode(b"5:helloextra").unwrap();
        assert_eq!(value, BencodeValue::string("hello"));
        assert_eq!(remaining, b"extra");
    }

    #[test]
    fn decode_integer_zero() {
        let (value, remaining) = decode(b"i0e").unwrap();
        assert_eq!(value, BencodeValue::Integer(0));
        assert!(remaining.is_empty());
    }

    #[test]
    fn decode_positive_integer() {
        let (value, remaining) = decode(b"i42e").unwrap();
        assert_eq!(value, BencodeValue::Integer(42));
        assert!(remaining.is_empty());
    }

    #[test]
    fn decode_negative_integer() {
        let (value, remaining) = decode(b"i-7e").unwrap();
        assert_eq!(value, BencodeValue::Integer(-7));
        assert!(remaining.is_empty());
    }

    #[test]
    fn decode_empty_list() {
        let (value, remaining) = decode(b"le").unwrap();
        assert_eq!(value, BencodeValue::List(vec![]));
        assert!(remaining.is_empty());
    }

    #[test]
    fn decode_list_with_items() {
        let (value, remaining) = decode(b"l5:helloi42ee").unwrap();
        assert_eq!(
            value,
            BencodeValue::List(vec![
                BencodeValue::string("hello"),
                BencodeValue::Integer(42),
            ])
        );
        assert!(remaining.is_empty());
    }

    #[test]
    fn decode_empty_dict() {
        let (value, remaining) = decode(b"de").unwrap();
        assert_eq!(value, BencodeValue::Dict(vec![]));
        assert!(remaining.is_empty());
    }

    #[test]
    fn decode_dict_with_entries() {
        let (value, remaining) = decode(b"d7:command5:offer7:call-id8:abc-1234e").unwrap();
        assert_eq!(value.dict_get_str("command"), Some("offer"));
        assert_eq!(value.dict_get_str("call-id"), Some("abc-1234"));
        assert!(remaining.is_empty());
    }

    #[test]
    fn decode_nested_dict_with_list() {
        let input = b"d5:flagsl13:trust-address9:symmetricee";
        let (value, remaining) = decode(input).unwrap();
        let flags = value.dict_get("flags").unwrap();
        assert!(matches!(flags, BencodeValue::List(_)));
        assert!(remaining.is_empty());
    }

    // -- Roundtrips --

    #[test]
    fn roundtrip_string() {
        let original = BencodeValue::string("hello world");
        let encoded = encode(&original);
        let (decoded, _) = decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_integer() {
        let original = BencodeValue::Integer(-999);
        let encoded = encode(&original);
        let (decoded, _) = decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_complex_dict() {
        let original = BencodeValue::dict(vec![
            ("command", BencodeValue::string("offer")),
            ("call-id", BencodeValue::string("test-call-123")),
            ("from-tag", BencodeValue::string("tag-abc")),
            (
                "sdp",
                BencodeValue::string(concat!(
                    "v=0\r\n",
                    "o=- 0 0 IN IP4 10.0.0.1\r\n",
                    "s=-\r\n",
                    "c=IN IP4 10.0.0.1\r\n",
                    "t=0 0\r\n",
                    "m=audio 8000 RTP/AVP 0\r\n",
                )),
            ),
            ("replace", BencodeValue::string_list(&["origin"])),
            ("flags", BencodeValue::string_list(&["trust-address"])),
        ]);
        let encoded = encode(&original);
        let (decoded, remaining) = decode(&encoded).unwrap();
        assert_eq!(original, decoded);
        assert!(remaining.is_empty());
    }

    #[test]
    fn roundtrip_binary_sdp() {
        let sdp_bytes = vec![0x76, 0x3d, 0x30, 0x0d, 0x0a, 0x00, 0xff];
        let original = BencodeValue::dict(vec![("sdp", BencodeValue::String(sdp_bytes))]);
        let encoded = encode(&original);
        let (decoded, _) = decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    // -- decode_full_dict --

    #[test]
    fn decode_full_dict_success() {
        let input = b"d6:result2:oke";
        let value = decode_full_dict(input).unwrap();
        assert_eq!(value.dict_get_str("result"), Some("ok"));
    }

    #[test]
    fn decode_full_dict_trailing_bytes() {
        let input = b"d6:result2:okegarbage";
        let result = decode_full_dict(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("trailing bytes"));
    }

    #[test]
    fn decode_full_dict_not_a_dict() {
        let input = b"5:hello";
        let result = decode_full_dict(input);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expected dictionary"));
    }

    // -- Error cases --

    #[test]
    fn decode_empty_input() {
        let result = decode(b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty input"));
    }

    #[test]
    fn decode_invalid_start_byte() {
        let result = decode(b"x");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unexpected byte"));
    }

    #[test]
    fn decode_string_missing_colon() {
        let result = decode(b"5hello");
        assert!(result.is_err());
    }

    #[test]
    fn decode_string_truncated() {
        let result = decode(b"10:hi");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds"));
    }

    #[test]
    fn decode_integer_missing_terminator() {
        let result = decode(b"i42");
        assert!(result.is_err());
    }

    #[test]
    fn decode_list_missing_terminator() {
        let result = decode(b"l5:hello");
        assert!(result.is_err());
    }

    #[test]
    fn decode_dict_missing_terminator() {
        let result = decode(b"d3:key5:value");
        assert!(result.is_err());
    }

    // -- Real NG protocol message --

    #[test]
    fn encode_ng_offer_request() {
        let request = BencodeValue::dict(vec![
            ("command", BencodeValue::string("offer")),
            ("call-id", BencodeValue::string("abc-1234")),
            ("from-tag", BencodeValue::string("foo")),
            (
                "sdp",
                BencodeValue::string("v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\n"),
            ),
            ("ICE", BencodeValue::string("remove")),
            ("replace", BencodeValue::string_list(&["origin"])),
        ]);
        let encoded = encode(&request);
        // Verify it starts with 'd' and ends with 'e'.
        assert_eq!(encoded[0], b'd');
        assert_eq!(encoded[encoded.len() - 1], b'e');
        // Roundtrip to verify integrity.
        let (decoded, _) = decode(&encoded).unwrap();
        assert_eq!(decoded.dict_get_str("command"), Some("offer"));
        assert_eq!(decoded.dict_get_str("call-id"), Some("abc-1234"));
        assert_eq!(decoded.dict_get_str("from-tag"), Some("foo"));
        assert_eq!(decoded.dict_get_str("ICE"), Some("remove"));
    }

    #[test]
    fn decode_ng_offer_response() {
        // Simulate a typical RTPEngine response.
        let response = BencodeValue::dict(vec![
            ("result", BencodeValue::string("ok")),
            (
                "sdp",
                BencodeValue::string(concat!(
                    "v=0\r\n",
                    "o=- 0 0 IN IP4 203.0.113.1\r\n",
                    "s=-\r\n",
                    "c=IN IP4 203.0.113.1\r\n",
                    "t=0 0\r\n",
                    "m=audio 30000 RTP/AVP 0\r\n",
                )),
            ),
        ]);
        let encoded = encode(&response);
        let decoded = decode_full_dict(&encoded).unwrap();
        assert_eq!(decoded.dict_get_str("result"), Some("ok"));
        let sdp = decoded.dict_get_str("sdp").unwrap();
        assert!(sdp.contains("203.0.113.1"));
        assert!(sdp.contains("30000"));
    }

    // -- Accessor helpers --

    #[test]
    fn as_str_on_string() {
        let value = BencodeValue::string("hello");
        assert_eq!(value.as_str(), Some("hello"));
    }

    #[test]
    fn as_str_on_non_string() {
        let value = BencodeValue::Integer(42);
        assert_eq!(value.as_str(), None);
    }

    #[test]
    fn as_integer_on_integer() {
        let value = BencodeValue::Integer(42);
        assert_eq!(value.as_integer(), Some(42));
    }

    #[test]
    fn as_integer_on_non_integer() {
        let value = BencodeValue::string("not a number");
        assert_eq!(value.as_integer(), None);
    }

    #[test]
    fn dict_get_missing_key() {
        let value = BencodeValue::dict(vec![("a", BencodeValue::string("b"))]);
        assert_eq!(value.dict_get_str("missing"), None);
    }

    #[test]
    fn dict_get_bytes_on_binary() {
        let value = BencodeValue::dict(vec![("data", BencodeValue::String(vec![0x00, 0xff]))]);
        assert_eq!(value.dict_get_bytes("data"), Some(&[0x00, 0xff][..]));
    }
}
