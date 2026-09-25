//! `@proxy.on_reply` takes the same optional method filter as
//! `@proxy.on_request`, matched against the method of the request the response
//! answers, and `@proxy.on_register_reply` is shorthand for
//! `@proxy.on_reply("REGISTER")`.
//!
//! Driven through [`run_reply_handlers`], the function the proxy response path
//! calls for every relayed response, so a filter that parsed but never reached
//! dispatch would fail here.

use super::response::run_reply_handlers;
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;
use crate::sip::parser::parse_sip_message_bytes;

const UAC: &str = "192.0.2.10:5060";
const UAS: &str = "198.51.100.20:5060";

/// A script whose reply handlers each stamp their name on the response.
const SCRIPT: &str = r#"
from siphon import proxy

@proxy.on_reply
def every_reply(request, reply):
    reply.set_header("X-Every", "yes")
    reply.relay()

@proxy.on_reply("REGISTER")
def register_reply(request, reply):
    reply.set_header("X-Register", "yes")
    reply.relay()

@proxy.on_reply("INVITE|UPDATE")
def invite_or_update_reply(request, reply):
    reply.set_header("X-Invite-Or-Update", "yes")
    reply.relay()

@proxy.on_register_reply
def register_shorthand(request, reply):
    reply.set_header("X-Register-Shorthand", "yes")
    reply.relay()
"#;

fn request(method: &str) -> SipMessage {
    let raw = format!(
        concat!(
            "{method} sip:alice@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-{method}\r\n",
            "From: <sip:alice@siphon.example.com>;tag=from-1\r\n",
            "To: <sip:alice@siphon.example.com>\r\n",
            "Call-ID: reply-filter-{method}\r\n",
            "CSeq: 1 {method}\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the request parses")
}

fn response(method: &str) -> SipMessage {
    let raw = format!(
        concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-{method}\r\n",
            "From: <sip:alice@siphon.example.com>;tag=from-1\r\n",
            "To: <sip:alice@siphon.example.com>;tag=to-1\r\n",
            "Call-ID: reply-filter-{method}\r\n",
            "CSeq: 1 {method}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the response parses")
}

/// The headers of the form `X-…` the reply handlers left on a 200 to `method`.
fn stamped(script: &str, method: &str) -> (Vec<String>, bool) {
    let dispatcher = test_dispatcher_with_script(script);
    let (message, forwarded, _) = run_reply_handlers(
        response(method),
        200,
        "z9hG4bK-branch",
        &dispatcher.state,
        request(method),
        UAC.parse().expect("a literal address"),
        Transport::Udp,
        UAS.parse().expect("a literal address"),
        dispatcher.state.local_addr,
        ConnectionId(0),
    );
    let mut names: Vec<String> = [
        "X-Every",
        "X-Register",
        "X-Invite-Or-Update",
        "X-Register-Shorthand",
    ]
    .iter()
    .filter(|name| message.headers.get(name).is_some())
    .map(|name| name.to_string())
    .collect();
    names.sort();
    (names, forwarded)
}

#[test]
fn filtered_reply_handler_runs_only_for_its_method() {
    let (names, forwarded) = stamped(SCRIPT, "REGISTER");
    assert_eq!(names, ["X-Every", "X-Register", "X-Register-Shorthand"]);
    assert!(forwarded);
}

#[test]
fn pipe_separated_reply_filter_matches_each_method() {
    for method in ["INVITE", "UPDATE"] {
        let (names, forwarded) = stamped(SCRIPT, method);
        assert_eq!(names, ["X-Every", "X-Invite-Or-Update"], "{method}");
        assert!(forwarded, "{method}");
    }
}

#[test]
fn unmatched_method_reaches_only_the_unfiltered_handler() {
    let (names, forwarded) = stamped(SCRIPT, "OPTIONS");
    assert_eq!(names, ["X-Every"]);
    assert!(forwarded);
}

#[test]
fn response_no_filter_matches_is_forwarded_unchanged() {
    // With only a REGISTER handler, a response to anything else takes the
    // no-handler path: forwarded as-is, not dropped for want of a relay().
    let script = r#"
from siphon import proxy

@proxy.on_reply("REGISTER")
def register_reply(request, reply):
    reply.set_header("X-Register", "yes")
"#;
    let (names, forwarded) = stamped(script, "INVITE");
    assert!(names.is_empty());
    assert!(forwarded);

    // The REGISTER handler does run for REGISTER, and not relaying drops it.
    let (names, forwarded) = stamped(script, "REGISTER");
    assert_eq!(names, ["X-Register"]);
    assert!(!forwarded);
}
