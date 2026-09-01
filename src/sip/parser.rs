//! RFC 3261 SIP message parser built with nom.

use nom::{
    IResult, Parser,
    bytes::complete::{tag, take_until, take_while, take_while1},
    character::complete::{char, space1, digit1},
    sequence::{preceded, delimited},
    multi::many0,
    combinator::{opt, map_res},
    branch::alt,
};
use crate::sip::message::*;
use crate::sip::uri::SipUri;
use crate::sip::headers::SipHeaders;

/// Parse a SIP message (request or response)
///
/// Leading CRLFs are stripped per RFC 3261 §7.5:
/// "Implementations processing SIP messages over stream-oriented
/// transports MUST ignore any CRLF appearing before the start-line."
pub fn parse_sip_message(input: &str) -> IResult<&str, SipMessage> {
    let input = input.trim_start_matches("\r\n");
    let (input, start_line) = parse_start_line(input)?;
    let (input, headers) = parse_headers(input)?;
    let (input, body) = parse_body(input, &headers)?;

    Ok((input, SipMessage {
        start_line,
        headers,
        body: body.as_bytes().to_vec(),
    }))
}

/// Reject a header block whose lines are not all CRLF-terminated.
///
/// RFC 3261 §7.5 and the §25.1 grammar make CRLF the only line terminator in a
/// SIP message: "The start-line, each message-header line, and the empty line
/// MUST be terminated by a carriage-return line-feed sequence (CRLF)."
///
/// Enforcing that is a framing-consistency requirement, not pedantry. siphon's
/// header-value scan continues to the next CRLF, so a line ended with a bare LF
/// is absorbed into the *previous* header's value — while the stream framer's
/// `Content-Length` scan splits on LF and reads that same line as a header of
/// its own. Given
///
/// ```text
/// X-Pad: a\nContent-Length: 4\r\nContent-Length: 0\r\n\r\nAAAA
/// ```
///
/// the parser sees `Content-Length: 0` and a header `X-Pad` whose value happens
/// to contain a newline, and the framer sees `Content-Length: 4`. Any upstream
/// element that treats a bare LF as a terminator (proxies and load balancers
/// commonly do) sees a different message again, which is the shape request
/// smuggling is built out of. A bare CR is rejected on the same grounds.
///
/// Bodies are untouched — they are opaque octets, and RFC 4475's multipart case
/// carries bare CR and LF inside one legitimately.
fn validate_header_line_endings(header_bytes: &[u8]) -> Result<(), String> {
    for (index, byte) in header_bytes.iter().enumerate() {
        match byte {
            b'\n' if index == 0 || header_bytes[index - 1] != b'\r' => {
                return Err(format!(
                    "bare LF at offset {index} in the header block; RFC 3261 §7.5 requires CRLF"
                ));
            }
            b'\r' if header_bytes.get(index + 1) != Some(&b'\n') => {
                return Err(format!(
                    "bare CR at offset {index} in the header block; RFC 3261 §7.5 requires CRLF"
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Count the leading CRLF pairs a peer may send before the start-line
/// (RFC 3261 §7.5). Only whole pairs count — a lone CR or LF at the front is
/// not a keepalive and is left for [`validate_header_line_endings`] to refuse.
pub(crate) fn leading_crlf_len(input: &[u8]) -> usize {
    let mut offset = 0;
    while input[offset..].starts_with(b"\r\n") {
        offset += 2;
    }
    offset
}

/// Parse the start line and header block out of raw message bytes.
///
/// Returns the parsed start line, the headers, and the index of the `\r\n\r\n`
/// boundary. Shared by [`parse_sip_message_bytes`] and
/// [`parse_sip_headers_only`], which differ only in how they treat the body.
fn parse_header_block(input: &[u8]) -> Result<(StartLine, SipHeaders, usize), String> {
    // RFC 3261 §7.5: "Implementations processing SIP messages over
    // stream-oriented transports MUST ignore any CRLF appearing before the
    // start-line." Skip them *before* looking for the header/body boundary —
    // searching first would find the leading CRLF pair itself and leave an
    // empty start line. (The `trim_start_matches` further down was meant to
    // cover this but can never fire, for exactly that reason.) The stream
    // transports drain keepalives in their own read tasks, so in practice this
    // is the UDP path, where a datagram prefixed with a stray CRLF used to be
    // dropped as a parse error.
    let prefix = leading_crlf_len(input);
    let body = &input[prefix..];
    let boundary = prefix
        + find_header_boundary(body)
            .ok_or_else(|| "no header/body boundary (\\r\\n\\r\\n) found".to_string())?;

    // Headers portion including the terminating \r\n\r\n must be valid UTF-8
    let header_end = boundary + 4; // include \r\n\r\n
    let header_bytes = &input[prefix..header_end.min(input.len())];
    validate_header_line_endings(header_bytes)?;
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|error| format!("non-UTF8 in SIP headers: {error}"))?;

    // Parse start line + headers using the existing text-based parser.
    // The text parser handles start line → headers → body in one pass.
    // We feed it the header portion only; it will see no body (Content-Length
    // references bytes beyond what we pass, so parse_body returns "").
    let trimmed = header_str;
    let (_, start_line) = parse_start_line(trimmed)
        .map_err(|error| format!("start line parse error: {error}"))?;
    // Skip past start line to parse headers
    let after_start_line = trimmed.find("\r\n")
        .map(|pos| &trimmed[pos + 2..])
        .unwrap_or("");
    let (_, headers) = parse_headers(after_start_line)
        .map_err(|error| format!("header parse error: {error}"))?;

    Ok((start_line, headers, boundary))
}

/// Parse only the header block, ignoring `Content-Length` entirely. The
/// returned message always has an empty body.
///
/// [`parse_sip_message_bytes`] rejects a `Content-Length` larger than the body
/// actually received (RFC 4475 §3.1.2.2), which is right for a message on its
/// way upstream but wrong for the one caller that has deliberately refused to
/// read the body: the stream framer rejecting an over-sized declaration still
/// needs the Via / From / To / Call-ID / CSeq set to address its 513 response
/// back at the sender.
pub fn parse_sip_headers_only(input: &[u8]) -> Result<SipMessage, String> {
    let (start_line, headers, _) = parse_header_block(input)?;
    Ok(SipMessage { start_line, headers, body: Vec::new() })
}

/// Parse a SIP message from raw bytes, supporting binary bodies.
///
/// Headers are ASCII/UTF-8 per RFC 3261. The body after the blank line
/// (`\r\n\r\n`) is treated as opaque bytes — not validated as UTF-8.
/// This supports binary content types like `application/vnd.3gpp.sms`.
pub fn parse_sip_message_bytes(input: &[u8]) -> Result<SipMessage, String> {
    let (start_line, headers, boundary) = parse_header_block(input)?;

    // Body is raw bytes after the \r\n\r\n boundary
    let body_start = boundary + 4;

    // RFC 3261 §20.14: `Content-Length = 1*DIGIT`, counting body octets. A value
    // that is not a non-negative integer, or that claims more octets than were
    // actually received, leaves the message unframeable — there is no body to
    // hand upstream and no way to tell where the next message starts. Both are
    // rejected here rather than papered over with a short read (RFC 4475
    // §3.1.2.2 "Content Length Larger Than Message" and §3.1.2.3 "Negative
    // Content-Length"). Stream transports never trip the overrun check: the TCP
    // framer already waits for `headers + Content-Length` octets before handing
    // a message over, so a short buffer never reaches the parser.
    if let Some(declared) = headers.get("Content-Length") {
        let declared = declared.trim();
        let declared: usize = declared
            .parse()
            .map_err(|_| format!("invalid Content-Length {declared:?} (RFC 3261 §20.14)"))?;
        let available = input.len().saturating_sub(body_start);
        if declared > available {
            return Err(format!(
                "Content-Length {declared} exceeds the {available} body octet(s) received"
            ));
        }
    }

    let content_length = headers.content_length().unwrap_or(0);
    let body = if content_length > 0 && input.len() >= body_start + content_length {
        input[body_start..body_start + content_length].to_vec()
    } else if content_length == 0 {
        Vec::new()
    } else {
        input[body_start..].to_vec()
    };

    Ok(SipMessage {
        start_line,
        headers,
        body,
    })
}

/// Find the position of the first `\r\n\r\n` in raw bytes (header/body boundary).
/// Returns the index of the first `\r` in the `\r\n\r\n` sequence.
fn find_header_boundary(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse start line (request or response)
fn parse_start_line(input: &str) -> IResult<&str, StartLine> {
    alt((
        parse_request_line.map(StartLine::Request),
        parse_status_line.map(StartLine::Response),
    )).parse(input)
}

/// Parse request line: METHOD SP Request-URI SP SIP-Version CRLF
fn parse_request_line(input: &str) -> IResult<&str, RequestLine> {
    // RFC 3261 §25.1: Method = INVITEm / ACKm / ... / extension-method, where
    // extension-method = token, and
    //   token = 1*( alphanum / "-" / "." / "!" / "%" / "*" / "_" / "+" / "`"
    //               / "'" / "~" )
    // An unknown method is not a parse error — it is a 501 from the element,
    // which cannot be sent if the message never parses. Note that "%" in a
    // method name is a literal token character, not an escape (RFC 4475
    // §3.1.1.5: "RE%47IST%45R" is an unknown method, NOT a REGISTER).
    let (input, method_str) = take_while1(|c: char| {
        c.is_alphanumeric() || matches!(c, '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~')
    })(input)?;
    let method = Method::from_str(method_str);

    // RFC 3261 §25.1: `Request-Line = Method SP Request-URI SP SIP-Version CRLF`
    // — exactly one SP between elements, no LWS. Accepting a run of spaces makes
    // the Request-URI ambiguous (RFC 4475 §3.1.2.9 "Multiple SP Separating
    // Request-Line Elements", and §3.1.2.10 for trailing SP).
    let (input, _) = char(' ')(input)?;
    let (input, uri) = parse_uri(input)?;
    let (input, _) = char(' ')(input)?;
    let (input, version) = parse_version(input)?;
    let (input, _) = parse_crlf(input)?;

    Ok((input, RequestLine {
        method,
        request_uri: uri,
        version,
    }))
}

/// Parse status line: SIP-Version SP Status-Code SP Reason-Phrase CRLF
fn parse_status_line(input: &str) -> IResult<&str, StatusLine> {
    let (input, version) = parse_version(input)?;
    let (input, _) = space1(input)?;
    let (input, status_code) = map_res(digit1, |s: &str| s.parse::<u16>()).parse(input)?;
    let (input, _) = space1(input)?;
    let (input, reason_phrase) = take_until("\r\n")(input)?;
    let (input, _) = parse_crlf(input)?;

    Ok((input, StatusLine {
        version,
        status_code,
        reason_phrase: reason_phrase.to_string(),
    }))
}

/// Parse SIP version: SIP/2.0
fn parse_version(input: &str) -> IResult<&str, Version> {
    let (input, _) = tag("SIP/")(input)?;
    let (input, major) = map_res(digit1, |s: &str| s.parse::<u8>()).parse(input)?;
    let (input, _) = char('.')(input)?;
    let (input, minor) = map_res(digit1, |s: &str| s.parse::<u8>()).parse(input)?;

    Ok((input, Version { major, minor }))
}

/// Parse a SIP URI from a standalone string (not embedded in a nom pipeline).
///
/// Returns the parsed `SipUri` or an error message.
pub fn parse_uri_standalone(input: &str) -> Result<SipUri, String> {
    let input = input.trim();
    match parse_uri(input) {
        Ok((_rest, uri)) => Ok(uri),
        Err(error) => Err(format!("failed to parse SIP URI '{input}': {error}")),
    }
}

/// Parse SIP URI: sip:user@host:port;params?headers
fn parse_uri(input: &str) -> IResult<&str, SipUri> {
    // tel: URIs (RFC 3966) — common in IMS
    if let Some(rest) = input.strip_prefix("tel:") {
        return parse_tel_uri(rest);
    }

    // RFC 3261 §25.1: Request-URI = SIP-URI / SIPS-URI / absoluteURI. A URI in
    // some other scheme is syntactically well-formed, and §8.2.2 requires the
    // element to answer 416 Unsupported URI Scheme — a response it cannot send
    // if the message as a whole fails to parse. RFC 4475 §3.3.2
    // ("nobodyKnowsThisScheme:...") and §3.3.3 ("soap.beep://...") cover both
    // the opaque and the hierarchical shape.
    if !input.starts_with("sip:") && !input.starts_with("sips:") {
        return parse_absolute_uri(input);
    }

    let (input, scheme) = alt((tag("sip:"), tag("sips:"))).parse(input)?;
    let scheme = scheme.trim_end_matches(':').to_string();

    // Parse user part (optional).
    // Per RFC 3261 §19.1.1, userinfo includes user-params (e.g. ;phone-context=)
    // before the @ delimiter. We must find @ first to correctly split user from host,
    // because ; within user-params (RFC 3966 phone-context) is NOT a URI param separator.
    // Only scan up to the first whitespace/> to avoid matching @ in a different context.
    let uri_end = input.find([' ', '\r', '\n', '>']).unwrap_or(input.len());
    let uri_portion = &input[..uri_end];
    let (input, user, user_params) = if let Some(at_pos) = uri_portion.rfind('@') {
        let user_part = &input[..at_pos];
        let rest = &input[at_pos + 1..]; // skip @
        // Split user from user-params at first ';' (RFC 3966 phone-context etc.)
        if let Some(semi_pos) = user_part.find(';') {
            let bare_user = &user_part[..semi_pos];
            let params_str = &user_part[semi_pos..]; // ";phone-context=..."
            let mut user_params = Vec::new();
            for param in params_str.split(';').filter(|s| !s.is_empty()) {
                let (name, value) = match param.split_once('=') {
                    Some((n, v)) => (n.to_string(), Some(v.to_string())),
                    None => (param.to_string(), None),
                };
                user_params.push((name, value));
            }
            (rest, Some(bare_user), user_params)
        } else {
            (rest, Some(user_part), Vec::new())
        }
    } else {
        (input, None, Vec::new())
    };

    // Parse host (stop before port separator or URI parameters)
    // Host can be domain name, IPv4, or IPv6 in brackets
    let (input, host_str) = if input.starts_with('[') {
        // IPv6 address in brackets
        let (input, ipv6) = delimited(
            char('['),
            take_while1(|c: char| c != ']'),
            char(']')
        ).parse(input)?;
        (input, format!("[{}]", ipv6))
    } else {
        // Domain name or IPv4 - take until : or ; or ? or space
        let (input, host) = take_while1(|c: char| {
            c.is_alphanumeric() || matches!(c, '.' | '-')
        })(input)?;
        (input, host.to_string())
    };

    // Parse port (optional)
    let (input, port) = opt(preceded(
        char(':'),
        map_res(take_while1(|c: char| c.is_ascii_digit()), |s: &str| s.parse::<u16>())
    )).parse(input)?;

    // Parse URI parameters (optional)
    let (input, params) = opt(parse_uri_params).parse(input)?;
    let params = params.unwrap_or_default();

    // Parse URI headers (optional, after ?)
    let (input, headers) = opt(preceded(
        char('?'),
        parse_uri_headers
    )).parse(input)?;
    let headers = headers.unwrap_or_default();

    Ok((input, SipUri {
        scheme,
        user: user.map(|s| s.to_string()),
        host: host_str.to_string(),
        port,
        params,
        headers,
        user_params,
    }))
}

/// Parse tel: URI (RFC 3966): tel:+1234567890;phone-context=example.com
///
/// Maps to SipUri with scheme="tel", user=subscriber, host=phone-context
/// domain (or empty if global number), no port.
fn parse_tel_uri(input: &str) -> IResult<&str, SipUri> {
    // Subscriber number: digits, +, -, . (visual separators)
    let (input, subscriber) = take_while1(|c: char| {
        c.is_ascii_digit() || matches!(c, '+' | '-' | '.' | '(' | ')')
    })(input)?;

    // Parse parameters (;phone-context=..., ;isub=..., etc.)
    let (input, params) = opt(parse_uri_params).parse(input)?;
    let params = params.unwrap_or_default();

    // Extract phone-context as the host equivalent
    let host = params
        .iter()
        .find(|(name, _)| name == "phone-context")
        .and_then(|(_, value)| value.clone())
        .unwrap_or_default();

    Ok((input, SipUri {
        scheme: "tel".to_string(),
        user: Some(subscriber.to_string()),
        host,
        port: None,
        params,
        headers: Vec::new(),
        user_params: Vec::new(),
    }))
}

/// Parse a non-SIP `absoluteURI` — a scheme and an opaque remainder.
///
/// `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` (RFC 3986 §3.1). The
/// remainder is kept verbatim in [`SipUri::host`] so the URI re-serialises
/// byte-for-byte. A trailing `:port` is split out because the URI formatter
/// reads a colon in the host as an IPv6 literal and would bracket it.
///
/// This is deliberately shallow: siphon does not route on a scheme it does not
/// implement, and all the caller needs is a parse good enough to build the 416.
fn parse_absolute_uri(input: &str) -> IResult<&str, SipUri> {
    let error = |kind| nom::Err::Error(nom::error::Error::new(input, kind));

    let scheme_len = input
        .find(':')
        .filter(|&pos| pos > 0)
        .ok_or_else(|| error(nom::error::ErrorKind::Char))?;
    let scheme = &input[..scheme_len];

    let mut scheme_chars = scheme.chars();
    let scheme_is_valid = scheme_chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !scheme_is_valid {
        return Err(error(nom::error::ErrorKind::Tag));
    }

    // The opaque part runs to whatever ends a URI in context: the SP before
    // SIP-Version, CRLF, or the '>' closing a name-addr.
    let rest = &input[scheme_len + 1..];
    let end = rest
        .find([' ', '\t', '\r', '\n', '>', ','])
        .unwrap_or(rest.len());
    if end == 0 {
        return Err(error(nom::error::ErrorKind::TakeWhile1));
    }
    let opaque = &rest[..end];

    let (host, port) = match opaque.rsplit_once(':') {
        Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => {
            match tail.parse::<u16>() {
                Ok(port) => (head, Some(port)),
                Err(_) => (opaque, None),
            }
        }
        _ => (opaque, None),
    };

    Ok((
        &rest[end..],
        SipUri {
            scheme: scheme.to_string(),
            user: None,
            host: host.to_string(),
            port,
            params: Vec::new(),
            headers: Vec::new(),
            user_params: Vec::new(),
        },
    ))
}

/// Parse URI parameters: ;param=value;param2
fn parse_uri_params(input: &str) -> IResult<&str, Vec<(String, Option<String>)>> {
    many0(preceded(
        char(';'),
        (
            take_while1(|c: char| !matches!(c, '=' | ';' | '?' | ' ' | '\r' | '\n')),
            opt(preceded(
                char('='),
                take_while(|c: char| !matches!(c, ';' | '?' | ' ' | '\r' | '\n'))
            )),
        )
    )).parse(input)
    .map(|(input, params)| {
        let params: Vec<(String, Option<String>)> = params
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.map(|s| s.to_string())))
            .collect();
        (input, params)
    })
}

/// Parse URI headers: header=value&header2=value2
fn parse_uri_headers(input: &str) -> IResult<&str, Vec<(String, Option<String>)>> {
    many0(preceded(
        opt(char('&')),
        (
            take_while1(|c: char| !matches!(c, '=' | '&' | ' ' | '\r' | '\n')),
            opt(preceded(
                char('='),
                take_while(|c: char| !matches!(c, '&' | ' ' | '\r' | '\n'))
            )),
        )
    )).parse(input)
    .map(|(input, headers)| {
        let headers: Vec<(String, Option<String>)> = headers
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.map(|s| s.to_string())))
            .collect();
        (input, headers)
    })
}

/// Parse headers section until empty line
fn parse_headers(input: &str) -> IResult<&str, SipHeaders> {
    let mut headers = SipHeaders::new();
    let mut remaining = input;

    loop {
        if remaining.is_empty() {
            return Ok((remaining, headers));
        }
        if let Some(after) = remaining.strip_prefix("\r\n") {
            return Ok((after, headers));
        }
        if let Some(after) = remaining.strip_prefix('\n') {
            return Ok((after, headers));
        }

        // A line starting with SP or HTAB is a folded continuation (RFC 3261
        // §7.3.1). `parse_header_line` consumes the continuations belonging to
        // the header it just read, so reaching the top of this loop on one
        // means it continues nothing — the header section opened with a fold.
        // Trimming the whitespace away, as this used to, promoted that line to
        // a header of its own, which the stream framer skips as a fold: the
        // two then disagree about whether a `Content-Length` on it counts.
        // There is no antecedent to fold into, so it is malformed either way.
        if remaining.starts_with([' ', '\t']) {
            return Err(nom::Err::Error(nom::error::Error::new(
                remaining,
                nom::error::ErrorKind::Space,
            )));
        }

        match parse_header_line(remaining) {
            Ok((input, (name, value))) => {
                headers.add(&name, value);
                remaining = input;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

/// Parse a single header line (handles folding)
fn parse_header_line(input: &str) -> IResult<&str, (String, String)> {
    let input = input.trim_start_matches([' ', '\t']);

    // Parse header name
    let (input, name) = take_while1(|c: char| !matches!(c, ':' | '\r' | '\n' | ' ' | '\t'))(input)?;
    // RFC 3261 §25.1: HCOLON = *( SP / HTAB ) ":" SWS. Whitespace between the
    // header name and its colon is legal and appears in the wild — RFC 4475
    // §3.1.1.1 ("TO :") and §3.1.1.7 ("v :", "Via  :") both exercise it.
    let (input, _) = take_while(|c: char| matches!(c, ' ' | '\t'))(input)?;
    let (input, _) = char(':')(input)?;
    // SWS, not "any whitespace". RFC 3261 §25.1 has `SWS = [LWS]` and
    // `LWS = [*WSP CRLF] 1*WSP` — a CRLF may only appear inside linear
    // whitespace when at least one space or tab follows it, which is exactly
    // the folding rule the value loop below implements. `multispace0` accepted
    // a bare CRLF here, so a header with an empty value swallowed the whole of
    // the next line as its own value:
    //
    //     X:\r\nContent-Length: 5\r\n\r\n
    //
    // parsed as one header `X` with the value `Content-Length: 5` and no
    // Content-Length at all, while the stream framer read the 5. Consume only
    // spaces and tabs and let the fold loop decide about continuation lines.
    let (input, _) = take_while(|c: char| matches!(c, ' ' | '\t'))(input)?;

    // Parse header value (may be folded with SP/TAB on next line)
    let mut value = String::new();
    let mut remaining = input;

    loop {
        let (input, line_value) = take_until("\r\n")(remaining)?;
        value.push_str(line_value);

        let (input, _) = parse_crlf(input)?;

        if input.is_empty() {
            return Ok((input, (name.trim_ascii().to_string(), value.trim().to_string())));
        }

        let trimmed = input.trim_start_matches([' ', '\t']);
        if trimmed.is_empty() {
            return Ok((input, (name.trim_ascii().to_string(), value.trim().to_string())));
        }

        if input.starts_with([' ', '\t']) {
            let (input, _) = take_while1(|c: char| matches!(c, ' ' | '\t'))(input)?;
            value.push(' ');
            remaining = input;
        } else {
            return Ok((input, (name.trim_ascii().to_string(), value.trim().to_string())));
        }
    }
}

/// Parse body based on Content-Length header
fn parse_body<'a>(input: &'a str, headers: &SipHeaders) -> IResult<&'a str, &'a str> {
    if let Some(content_length) = headers.content_length() {
        if content_length == 0 {
            Ok((input, ""))
        } else if input.len() >= content_length {
            // Content-Length is an octet count (RFC 3261 §20.14). Slice by byte
            // index, but never split a UTF-8 character: `input.get(..n)` returns
            // None when `n` is not a char boundary, so a Content-Length that
            // points into the middle of a multi-byte body character degrades to
            // "take the whole remaining input as the body" instead of panicking.
            // (Truly binary bodies should use `parse_sip_message_bytes`, which
            // slices `&[u8]`.)
            match (input.get(..content_length), input.get(content_length..)) {
                (Some(body), Some(rest)) => Ok((rest, body)),
                _ => Ok(("", input)),
            }
        } else {
            Ok((input, ""))
        }
    } else {
        Ok((input, ""))
    }
}

/// Parse CRLF
fn parse_crlf(input: &str) -> IResult<&str, &str> {
    alt((
        tag("\r\n"),
        tag("\n"),
    )).parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- line-ending strictness in the header block (RFC 3261 §7.5) --------

    /// The differential this rejection closes, stated as the two disagreeing
    /// readings of one byte string.
    ///
    /// `parse_header_line` scans a value up to the next CRLF, so a bare LF is
    /// absorbed into the preceding header's value — siphon used to read the
    /// message below as `Content-Length: 0` with an `X-Pad` whose value
    /// contained a newline. The stream framer's `Content-Length` scan splits on
    /// LF, so it read `Content-Length: 4` off the same bytes. Two components of
    /// the same proxy disagreed about where the message ended, and any upstream
    /// element that treats a bare LF as a terminator made a third reading.
    #[test]
    fn bare_lf_smuggling_shape_is_refused() {
        let smuggled = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TCP host;branch=z9hG4bK1\r\n",
            "X-Pad: a\nContent-Length: 4\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
        .as_bytes();

        let error = parse_sip_message_bytes(smuggled)
            .expect_err("a header block with a bare LF must not parse");
        assert!(error.contains("bare LF"), "unexpected error: {error}");

        // And the framer really did read it the other way, which is why this
        // has to be refused rather than reconciled.
        assert_eq!(
            crate::transport::tcp::extract_sip_message_length(smuggled),
            Some(smuggled.len() + 4),
            "precondition: the framer counts the smuggled Content-Length"
        );
    }

    /// A bare CR is refused on the same grounds — it is the other half of a
    /// terminator, and implementations differ on whether it ends a line.
    #[test]
    fn bare_cr_in_the_header_block_is_refused() {
        let message = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TCP host;branch=z9hG4bK1\rX-Pad: a\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
        .as_bytes();
        let error = parse_sip_message_bytes(message)
            .expect_err("a header block with a bare CR must not parse");
        assert!(error.contains("bare CR"), "unexpected error: {error}");
    }

    /// Bodies are opaque octets and are not held to CRLF framing. RFC 4475's
    /// multipart case (`TC_MPART01`) carries bare CR and LF inside its body
    /// legitimately, so the check must stop at the header/body boundary.
    #[test]
    fn bare_line_endings_are_allowed_in_the_body() {
        let mut message = concat!(
            "MESSAGE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TCP host;branch=z9hG4bK1\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Length: 9\r\n",
            "\r\n",
        )
        .as_bytes()
        .to_vec();
        message.extend_from_slice(b"a\nb\rc\r\nd\n");
        let parsed = parse_sip_message_bytes(&message).expect("body octets are opaque");
        assert_eq!(parsed.body, b"a\nb\rc\r\nd\n");
    }

    /// Ordinary CRLF messages, folded headers and the leading-CRLF keepalive
    /// prefix (RFC 3261 §7.5) all still parse.
    #[test]
    fn well_formed_messages_still_parse() {
        let folded = concat!(
            "\r\n\r\n",
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TCP host;branch=z9hG4bK1\r\n",
            "Subject: I know you are there,\r\n",
            " \tpick up the phone\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
        .as_bytes();
        let parsed = parse_sip_message_bytes(folded).expect("folded headers are legal");
        assert_eq!(
            parsed.headers.get("Subject").map(String::as_str),
            Some("I know you are there, pick up the phone")
        );
    }

    /// `parse_sip_headers_only` shares the same check — the reject path must
    /// not become a way to parse a message the main path refuses.
    #[test]
    fn headers_only_parse_applies_the_same_check() {
        let smuggled = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "X-Pad: a\nContent-Length: 4\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
        .as_bytes();
        assert!(parse_sip_headers_only(smuggled).is_err());
    }

    // --- framer/parser agreement, each shape found by the fuzz target -------
    //
    // The invariant: for any bytes the parser accepts, the framer must compute
    // the same total length. Where they differ, the bytes in between belong to
    // this message for one of them and to the next message for the other.

    /// Assert both sides read the same message length out of `raw`.
    fn framer_and_parser_agree(raw: &[u8]) {
        let parsed = parse_sip_message_bytes(raw).expect("fixture must parse");
        let boundary = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(
            crate::transport::tcp::extract_sip_message_length(raw),
            Some(boundary + parsed.body.len()),
            "framer and parser disagree on message length"
        );
    }

    /// A continuation line carrying a `Content-Length`. The parser folds it
    /// into `Subject`; a naive line scan read it as a header of its own.
    #[test]
    fn folded_line_carrying_content_length_agrees() {
        framer_and_parser_agree(
            concat!(
                "INVITE sip:bob@example.com SIP/2.0\r\n",
                "Subject: hello\r\n",
                " Content-Length: 99\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            )
            .as_bytes(),
        );
    }

    /// The reverse: a `Content-Length` whose value is folded onto the next
    /// line. The parser reads it; a naive line scan saw an empty value.
    #[test]
    fn folded_content_length_value_agrees() {
        framer_and_parser_agree(
            concat!(
                "INVITE sip:bob@example.com SIP/2.0\r\n",
                "Content-Length:\r\n",
                "\t1\r\n",
                "\r\n",
                "A",
            )
            .as_bytes(),
        );
    }

    /// RFC 3261 §25.1 `SWS = [LWS]`, `LWS = [*WSP CRLF] 1*WSP` — a CRLF after
    /// the colon is only whitespace when a space or tab follows it. Accepting a
    /// bare one made a header with an empty value swallow the whole next line,
    /// so the message below parsed as a single header `X` with the value
    /// `Content-Length: 5` and no Content-Length at all, while the framer read
    /// the 5.
    #[test]
    fn empty_header_value_does_not_swallow_the_next_line() {
        let raw = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "X:\r\n",
            "Content-Length: 5\r\n",
            "\r\n",
            "AAAAA",
        )
        .as_bytes();
        let parsed = parse_sip_message_bytes(raw).expect("fixture must parse");
        assert_eq!(parsed.headers.get("X").map(String::as_str), Some(""));
        assert_eq!(parsed.headers.content_length(), Some(5));
        framer_and_parser_agree(raw);
    }

    /// A continuation line with nothing to continue — the header section opens
    /// with a fold. The parser used to trim the leading whitespace and promote
    /// it to a header (here a compact `l:`, i.e. Content-Length); the framer
    /// skipped it as a fold.
    #[test]
    fn header_section_opening_with_a_fold_is_refused() {
        let raw = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "\tl: 1\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
        .as_bytes();
        assert!(
            parse_sip_message_bytes(raw).is_err(),
            "a fold with no antecedent is malformed"
        );
    }

    /// A vertical tab in a header name. `str::trim` is Unicode-aware and
    /// stripped it, turning `content-length\\x0b` into `Content-Length`;
    /// `[u8]::trim_ascii` in the framer does not treat VT as whitespace and
    /// left the name alone. Header names are ASCII tokens (§25.1), so the
    /// parser trims ASCII too and neither side calls this Content-Length.
    #[test]
    fn vertical_tab_in_a_header_name_is_not_content_length() {
        let raw = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "content-length\u{0b} : 5\r\n",
            "\r\n",
        )
        .as_bytes();
        let parsed = parse_sip_message_bytes(raw).expect("fixture must parse");
        assert_eq!(parsed.headers.content_length(), None);
        framer_and_parser_agree(raw);
    }

    #[test]
    fn tel_uri_global_number() {
        let uri = parse_uri_standalone("tel:+15551234567").unwrap();
        assert_eq!(uri.scheme, "tel");
        assert_eq!(uri.user.as_deref(), Some("+15551234567"));
        assert!(uri.host.is_empty());
    }

    #[test]
    fn tel_uri_with_phone_context() {
        let uri = parse_uri_standalone(
            "tel:8367;phone-context=ims.mnc001.mcc001.3gppnetwork.org"
        ).unwrap();
        assert_eq!(uri.scheme, "tel");
        assert_eq!(uri.user.as_deref(), Some("8367"));
        assert_eq!(uri.host, "ims.mnc001.mcc001.3gppnetwork.org");
        assert!(uri.params.iter().any(|(n, _)| n == "phone-context"));
    }

    #[test]
    fn tel_uri_roundtrip() {
        let input = "tel:8367;phone-context=ims.example.com";
        let uri = parse_uri_standalone(input).unwrap();
        assert_eq!(uri.to_string(), input);
    }

    #[test]
    fn sip_uri_still_works() {
        let uri = parse_uri_standalone("sip:alice@atlanta.com:5060;transport=tcp").unwrap();
        assert_eq!(uri.scheme, "sip");
        assert_eq!(uri.user.as_deref(), Some("alice"));
        assert_eq!(uri.host, "atlanta.com");
        assert_eq!(uri.port, Some(5060));
    }

    /// RFC 3261 §7.5: leading CRLFs before start-line must be ignored
    #[test]
    fn leading_crlf_stripped() {
        let raw = concat!(
            "\r\n",
            "\r\n",
            "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776\r\n",
            "From: <sip:alice@atlanta.com>;tag=1234\r\n",
            "To: <sip:bob@biloxi.com>\r\n",
            "Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n",
            "CSeq: 314159 INVITE\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let (_, message) = parse_sip_message(raw).unwrap();
        match &message.start_line {
            StartLine::Request(rl) => {
                assert_eq!(rl.method, Method::Invite);
                assert_eq!(rl.request_uri.user.as_deref(), Some("bob"));
            }
            _ => panic!("expected request"),
        }
    }

    /// Single leading CRLF should also work
    #[test]
    fn single_leading_crlf_stripped() {
        let raw = concat!(
            "\r\n",
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776\r\n",
            "From: <sip:alice@atlanta.com>;tag=1234\r\n",
            "To: <sip:bob@biloxi.com>;tag=5678\r\n",
            "Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n",
            "CSeq: 314159 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let (_, message) = parse_sip_message(raw).unwrap();
        match &message.start_line {
            StartLine::Response(sl) => {
                assert_eq!(sl.status_code, 200);
                assert_eq!(sl.reason_phrase, "OK");
            }
            _ => panic!("expected response"),
        }
    }

    #[test]
    fn parse_bytes_with_binary_body() {
        // Simulate a SIP MESSAGE with binary SMS TPDU body
        let headers = concat!(
            "MESSAGE sip:+31612345678@ims.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-sms-1\r\n",
            "From: <sip:+31687654321@ims.example.com>;tag=abc\r\n",
            "To: <sip:+31612345678@ims.example.com>\r\n",
            "Call-ID: sms-001@ims.example.com\r\n",
            "CSeq: 1 MESSAGE\r\n",
            "Content-Type: application/vnd.3gpp.sms\r\n",
            "Content-Length: 8\r\n",
            "\r\n",
        );
        // Binary body: 8 bytes including non-UTF8
        let body_bytes: [u8; 8] = [0x00, 0x01, 0xFF, 0xFE, 0x80, 0x90, 0xA0, 0xB0];
        let mut raw = Vec::from(headers.as_bytes());
        raw.extend_from_slice(&body_bytes);

        let message = parse_sip_message_bytes(&raw).expect("should parse binary body");
        assert!(matches!(message.start_line, StartLine::Request(_)));
        assert_eq!(message.body.len(), 8);
        assert_eq!(message.body, body_bytes);
        assert_eq!(
            message.headers.get("Content-Type").unwrap(),
            "application/vnd.3gpp.sms"
        );
    }

    #[test]
    fn parse_bytes_empty_body() {
        let raw = concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-1\r\n",
            "From: <sip:alice@example.com>;tag=a\r\n",
            "To: <sip:bob@example.com>;tag=b\r\n",
            "Call-ID: test@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let message = parse_sip_message_bytes(raw.as_bytes()).expect("should parse");
        assert!(message.body.is_empty());
    }

    #[test]
    fn parse_uri_with_phone_context_user_param() {
        // RFC 3966 phone-context in SIP URI: ;phone-context= is a user param, not a URI param.
        // The @ delimiter comes after user params.
        let input = "sip:0017;phone-context=ims.mnc001.mcc206.3gppnetwork.org@ims.mnc090.mcc208.3gppnetwork.org;user=phone";
        let uri = parse_uri_standalone(input).expect("should parse phone-context URI");
        assert_eq!(uri.user.as_deref(), Some("0017"));
        assert_eq!(uri.host, "ims.mnc090.mcc208.3gppnetwork.org");
        assert_eq!(
            uri.user_params,
            vec![("phone-context".to_string(), Some("ims.mnc001.mcc206.3gppnetwork.org".to_string()))],
        );
        assert!(uri.params.iter().any(|(n, _)| n == "user"), "URI params should contain user=phone");
    }

    #[test]
    fn parse_uri_phone_context_roundtrip() {
        let input = "sip:0017;phone-context=ims.mnc001.mcc206.3gppnetwork.org@ims.mnc090.mcc208.3gppnetwork.org;user=phone";
        let uri = parse_uri_standalone(input).expect("should parse");
        assert_eq!(uri.to_string(), input);
    }

    /// Regression (fuzz): a Content-Length that points into the middle of a
    /// multi-byte UTF-8 body character must not panic the parser. `parse_body`
    /// slices the `&str` body by byte index; before the `.get()` guard,
    /// `&input[..n]` panicked with "byte index is not a char boundary".
    /// Reachable via any Content-Length form — surfaced through the compact
    /// `l:` once compact forms started being honored.
    #[test]
    fn content_length_mid_utf8_char_does_not_panic() {
        // Body "€" is 3 bytes (0xE2 0x82 0xAC); char boundaries at 0 and 3 only.
        // Content-Length: 2 lands mid-character.
        let raw = "SIP/2.0 200 OK\r\n\
                    Via: SIP/2.0/UDP h:5060;branch=z9hG4bK1\r\n\
                    l:2\r\n\
                    \r\n€";
        let (_, message) = parse_sip_message(raw).expect("must parse without panicking");
        assert!(matches!(message.start_line, StartLine::Response(_)));
        // Degrades to taking the whole remaining input as the body.
        assert_eq!(message.body, "€".as_bytes());
    }

    /// The exact libFuzzer-minimized crash input for the above panic, replayed
    /// through the same entry point the fuzz target uses (`parse_sip_message`
    /// over the UTF-8 view of the bytes). Must not panic.
    #[test]
    fn fuzz_crash_content_length_mid_char() {
        let data: &[u8] = &[
            83, 73, 80, 47, 48, 46, 48, 32, 48, 32, 18, 0, 9, 9, 9, 13, 10, 108, 58, 55, 32, 13,
            10, 10, 108, 58, 0, 0, 10, 9, 231, 185, 187, 231, 185, 187, 65, 67, 75, 67, 67, 231,
            185, 187, 231, 185, 187, 65, 17, 0, 118, 78,
        ];
        let input = std::str::from_utf8(data).expect("crash input is valid UTF-8");
        let _ = parse_sip_message(input); // just must not panic
    }

    /// A char-boundary-aligned Content-Length still splits exactly as before
    /// (no behavior change for the common ASCII / aligned case).
    #[test]
    fn content_length_aligned_still_splits() {
        let raw = "SIP/2.0 200 OK\r\n\
                    Via: SIP/2.0/UDP h:5060;branch=z9hG4bK1\r\n\
                    Content-Length: 3\r\n\
                    \r\n€tail";
        let (_, message) = parse_sip_message(raw).expect("must parse");
        assert_eq!(message.body, "€".as_bytes());
    }

    #[test]
    fn parse_uri_no_user_params_unchanged() {
        // Normal URI without user params should parse identically to before.
        let input = "sip:alice@example.com;transport=tcp";
        let uri = parse_uri_standalone(input).expect("should parse");
        assert_eq!(uri.user.as_deref(), Some("alice"));
        assert_eq!(uri.host, "example.com");
        assert!(uri.user_params.is_empty());
        assert!(uri.params.iter().any(|(n, _)| n == "transport"));
    }

    /// RFC 3261 §25.1: `HCOLON = *( SP / HTAB ) ":" SWS`.
    #[test]
    fn header_name_may_be_separated_from_its_colon_by_whitespace() {
        let raw = concat!(
            "OPTIONS sip:user@example.com SIP/2.0\r\n",
            "To : <sip:user@example.com>\r\n",
            "From\t: <sip:caller@example.net>;tag=1\r\n",
            "Via  : SIP/2.0/UDP host.example.com;branch=z9hG4bK1\r\n",
            "Call-ID: hcolon.ws@example.com\r\n",
            "CSeq: 1 OPTIONS\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let (_, message) = parse_sip_message(raw).expect("whitespace before HCOLON is legal");
        assert_eq!(
            message.headers.get("Call-ID"),
            Some("hcolon.ws@example.com".to_string()).as_ref()
        );
        assert!(message.headers.get("To").is_some(), "`To :` should parse");
        assert!(message.headers.get("From").is_some(), "`From\\t:` should parse");
        assert!(message.headers.get("Via").is_some(), "`Via  :` should parse");
    }

    /// RFC 3261 §25.1: `extension-method = token`, and `token` admits
    /// `alphanum / "-" / "." / "!" / "%" / "*" / "_" / "+" / "`" / "'" / "~"`.
    #[test]
    fn extension_method_accepts_the_full_token_charset() {
        for method in [
            "!interesting-Method0123456789_*+`.%indeed'~",
            "RE%47IST%45R",
            "PROCEED~ing",
        ] {
            let raw = format!(
                "{method} sip:user@example.com SIP/2.0\r\n\
                 Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK1\r\n\
                 Call-ID: token.method@example.com\r\n\
                 CSeq: 1 {method}\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            );
            let (_, message) =
                parse_sip_message(&raw).unwrap_or_else(|_| panic!("`{method}` is a valid token"));
            let StartLine::Request(request) = &message.start_line else {
                panic!("`{method}` should parse as a request");
            };
            assert_eq!(request.method.as_str(), method);
        }
    }

    /// RFC 3261 §25.1: `Request-URI = SIP-URI / SIPS-URI / absoluteURI`. An
    /// unsupported scheme is a 416 from the element (§8.2.2), which cannot be
    /// sent at all if the message fails to parse.
    #[test]
    fn request_uri_accepts_a_non_sip_absolute_uri() {
        for (raw_uri, scheme, host, port) in [
            (
                "nobodyKnowsThisScheme:totallyopaquecontent",
                "nobodyKnowsThisScheme",
                "totallyopaquecontent",
                None,
            ),
            (
                "soap.beep://192.0.2.103:3002",
                "soap.beep",
                "//192.0.2.103",
                Some(3002),
            ),
        ] {
            let raw = format!(
                "OPTIONS {raw_uri} SIP/2.0\r\n\
                 Via: SIP/2.0/TCP host9.example.com;branch=z9hG4bK1\r\n\
                 Call-ID: absoluteuri@example.com\r\n\
                 CSeq: 1 OPTIONS\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            );
            let (_, message) =
                parse_sip_message(&raw).unwrap_or_else(|_| panic!("`{raw_uri}` should parse"));
            let StartLine::Request(request) = &message.start_line else {
                panic!("`{raw_uri}` should parse as a request");
            };
            assert_eq!(request.request_uri.scheme, scheme);
            assert_eq!(request.request_uri.host, host);
            assert_eq!(request.request_uri.port, port);
            // Must survive re-serialisation unchanged, or a proxy would corrupt
            // the Request-URI while forwarding the 416.
            assert_eq!(request.request_uri.to_string(), raw_uri);
        }
    }

    /// The absoluteURI fallback must not swallow genuine rubbish — a scheme has
    /// to look like one (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`).
    #[test]
    fn absolute_uri_fallback_rejects_a_malformed_scheme() {
        for bad in ["1nvalid:content", ":noscheme", "has space:content", "nocolon"] {
            assert!(
                parse_uri_standalone(bad).is_err(),
                "`{bad}` is not a valid absoluteURI and must not parse"
            );
        }
    }
}
