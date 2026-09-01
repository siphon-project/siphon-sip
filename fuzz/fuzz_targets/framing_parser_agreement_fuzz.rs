#![no_main]

use libfuzzer_sys::fuzz_target;
use siphon::sip::parser::parse_sip_message_bytes;
use siphon::transport::tcp::extract_sip_message_length;

// Two components decide independently how long a message is: the stream framer
// (which splits the accumulator and so decides where the *next* message starts)
// and the parser (which decides what this message contains). If they ever
// disagree, bytes one of them considers part of this message are, to the other,
// the start of a new one — which is the shape request smuggling is built out
// of, and how a bare LF used to hide a second Content-Length from the parser
// while the framer counted it.
//
// So: for every input the parser accepts, the framer must agree on the total.
fuzz_target!(|data: &[u8]| {
    let Ok(parsed) = parse_sip_message_bytes(data) else {
        // Refused inputs are fine — a message siphon will not parse is never
        // dispatched, so there is no reading of it to disagree with.
        return;
    };

    let framed = extract_sip_message_length(data)
        .expect("the parser accepted these bytes, so an end-of-headers marker is present");

    // Recompute the header block the same way both sides do: past any leading
    // CRLF keepalives, up to and including the first end-of-headers marker.
    let mut prefix = 0;
    while data[prefix..].starts_with(b"\r\n") {
        prefix += 2;
    }
    let header_len = prefix
        + data[prefix..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("parser accepted, so the marker is there")
        + 4;

    assert_eq!(
        framed,
        header_len + parsed.body.len(),
        "framer and parser disagree on message length: framer {framed}, \
         parser {header_len} header + {} body",
        parsed.body.len(),
    );
});
