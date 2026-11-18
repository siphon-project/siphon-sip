//! The SRS handshake (RFC 7866) through the dispatcher's own request path,
//! against a siphon-rtp engine in the test process.
//!
//! Each test sends what an SRC sends, reads back what went on the wire, and
//! checks what the engine was asked to do: one single-leg call per offered
//! stream, one recording on each, and every call ended with the session.

use std::time::Duration;

use super::test_dispatcher::test_dispatcher;
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

const SRC: &str = "198.51.100.20:5060";

/// A dispatcher with the SRS on, its media on `engine`.
fn srs_state(
    engine: &NativeTestEngine,
    recording_dir: &std::path::Path,
) -> (Arc<DispatcherState>, flume::Receiver<OutboundMessage>) {
    let mut dispatcher = test_dispatcher();
    dispatcher.state.rtpengine_set = Some(engine.backend());
    dispatcher.state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    dispatcher.state.srs_manager = Some(Arc::new(crate::srs::SrsManager::new(
        crate::config::SrsConfig {
            enabled: true,
            recording_dir: recording_dir.display().to_string(),
            max_sessions: 10,
            backend: "file".to_string(),
            file: None,
            http: None,
            rtpengine_profile: "srs_recording".to_string(),
        },
    )));
    (Arc::new(dispatcher.state), dispatcher.udp)
}

fn srs(state: &DispatcherState) -> &crate::srs::SrsManager {
    state.srs_manager.as_deref().expect("the SRS is on")
}

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "siphon-srs-handshake-{name}-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&directory).expect("a scratch directory");
    directory
}

/// An SDP offer of `streams` sendonly audio m-lines, labelled 1, 2, ...
fn offer(streams: usize) -> String {
    let mut sdp = String::from(concat!(
        "v=0\r\n",
        "o=src 1 1 IN IP4 198.51.100.20\r\n",
        "s=-\r\n",
        "c=IN IP4 198.51.100.20\r\n",
        "t=0 0\r\n",
    ));
    for index in 0..streams {
        sdp.push_str(&format!(
            "m=audio {} RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=label:{}\r\na=sendonly\r\n",
            40000 + 2 * index,
            index + 1
        ));
    }
    sdp
}

/// Complete metadata for a two-party call recorded on `streams` streams.
fn metadata(streams: usize) -> String {
    let mut xml = String::from(concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n",
        "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\r\n",
        "<datamode>complete</datamode>\r\n",
        "<session session_id=\"rs-shared\"><sipSessionID>orig@example.com</sipSessionID></session>\r\n",
        "<participant participant_id=\"p-a\"><nameID aor=\"sip:alice@example.com\"/></participant>\r\n",
        "<participant participant_id=\"p-b\"><nameID aor=\"sip:bob@example.com\"/></participant>\r\n",
    ));
    for index in 0..streams {
        xml.push_str(&format!(
            "<stream stream_id=\"s-{index}\" session_id=\"rs-shared\"><label>{}</label></stream>\r\n",
            index + 1
        ));
    }
    xml.push_str(concat!(
        "<participantstreamassoc participant_id=\"p-a\"><send>s-0</send><recv>s-1</recv></participantstreamassoc>\r\n",
        "<participantstreamassoc participant_id=\"p-b\"><send>s-1</send><recv>s-0</recv></participantstreamassoc>\r\n",
        "</recording>\r\n",
    ));
    xml
}

/// A multipart SIPREC body with `sdp` and `xml`.
fn multipart(sdp: &str, xml: &str) -> String {
    format!(
        concat!(
            "--srs-boundary\r\n",
            "Content-Type: application/sdp\r\n",
            "\r\n",
            "{sdp}",
            "--srs-boundary\r\n",
            "Content-Type: application/rs-metadata+xml\r\n",
            "Content-Disposition: recording-session\r\n",
            "\r\n",
            "{xml}",
            "--srs-boundary--\r\n",
        ),
        sdp = sdp,
        xml = xml
    )
}

/// The SRC's request: `markers` false leaves out both RFC 7866 markers.
#[allow(clippy::too_many_arguments)]
fn request(
    method: &str,
    call_id: &str,
    branch: &str,
    cseq: u32,
    to_tag: Option<&str>,
    content_type: Option<&str>,
    body: &str,
    markers: bool,
) -> String {
    let to = match to_tag {
        Some(tag) => format!("<sip:srs@example.com>;tag={tag}"),
        None => "<sip:srs@example.com>".to_string(),
    };
    let mut raw = format!(
        concat!(
            "{method} sip:srs@192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {src};branch={branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:src@example.com>;tag=src-tag\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} {method}\r\n",
        ),
        method = method,
        src = SRC,
        branch = branch,
        to = to,
        call_id = call_id,
        cseq = cseq,
    );
    if markers {
        raw.push_str(&format!(
            "Require: siprec\r\nContact: <sip:src@{SRC}>;+sip.src\r\n"
        ));
    } else {
        raw.push_str(&format!("Contact: <sip:src@{SRC}>\r\n"));
    }
    if let Some(content_type) = content_type {
        raw.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    raw.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    raw
}

fn siprec_invite(call_id: &str, streams: usize, markers: bool) -> String {
    request(
        "INVITE",
        call_id,
        &format!("z9hG4bK-{call_id}"),
        1,
        None,
        Some("multipart/mixed;boundary=srs-boundary"),
        &multipart(&offer(streams), &metadata(streams)),
        markers,
    )
}

fn send(state: &Arc<DispatcherState>, raw: &str) {
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    let method = message
        .method()
        .map(|method| method.as_str().to_string())
        .expect("a request");
    let inbound = super::dialog_state_events_tests::inbound(SRC, raw);
    handle_request(inbound, message, method, state);
}

/// Everything sent so far, parsed.
fn drain(udp: &flume::Receiver<OutboundMessage>) -> Vec<SipMessage> {
    let mut sent = Vec::new();
    while let Ok(outbound) = udp.try_recv() {
        if let Ok(message) = parse_sip_message_bytes(&outbound.data) {
            sent.push(message);
        }
    }
    sent
}

/// Wait up to two seconds for a response `code` to `method`, collecting
/// everything sent meanwhile.
async fn await_response(
    udp: &flume::Receiver<OutboundMessage>,
    seen: &mut Vec<SipMessage>,
    code: u16,
    method: &str,
) -> SipMessage {
    for _ in 0..200 {
        seen.extend(drain(udp));
        if let Some(found) = seen.iter().find(|message| {
            message.status_code() == Some(code)
                && message
                    .headers
                    .cseq()
                    .is_some_and(|cseq| cseq.ends_with(method))
        }) {
            return found.clone();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "no {code} to {method}; sent: {:?}",
        seen.iter()
            .map(|message| message.status_code())
            .collect::<Vec<_>>()
    );
}

fn count(seen: &[SipMessage], code: u16, method: &str) -> usize {
    seen.iter()
        .filter(|message| {
            message.status_code() == Some(code)
                && message
                    .headers
                    .cseq()
                    .is_some_and(|cseq| cseq.ends_with(method))
        })
        .count()
}

fn body(message: &SipMessage) -> String {
    String::from_utf8_lossy(&message.body).into_owned()
}

fn to_tag(response: &SipMessage) -> String {
    let to = response.headers.to().expect("a To");
    to.split("tag=").nth(1).expect("a To-tag").to_string()
}

fn m_lines(sdp: &str) -> Vec<&str> {
    sdp.lines().filter(|line| line.starts_with("m=")).collect()
}

async fn eventually(check: impl Fn() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// The whole handshake: 100 at once, then a 200 answering both streams
/// recvonly, in order, labels kept, from the engine; a Contact marked
/// `+sip.srs`; one engine call and one recording per stream. The ACK stops the
/// 2xx retransmission, and the BYE ends every engine call and the session.
#[tokio::test(flavor = "multi_thread")]
async fn a_two_stream_recording_is_answered_per_stream_and_ended_by_bye() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("two");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "two-streams@198.51.100.20";

    send(&state, &siprec_invite(call_id, 2, true));
    let mut seen = Vec::new();
    await_response(&udp, &mut seen, 100, "INVITE").await;
    let ok = await_response(&udp, &mut seen, 200, "INVITE").await;

    let answer = body(&ok);
    assert_eq!(m_lines(&answer).len(), 2, "{answer}");
    assert_eq!(answer.matches("a=recvonly").count(), 2, "{answer}");
    assert!(!answer.contains("sendonly") && !answer.contains("sendrecv"));
    let first = answer.find("a=label:1").expect("label 1 kept");
    let second = answer.find("a=label:2").expect("label 2 kept");
    assert!(first < second, "offer order kept: {answer}");
    assert!(
        answer.contains("203.0.113.60"),
        "the engine's address: {answer}"
    );
    assert!(
        !answer.contains("198.51.100.20"),
        "never the SRC's own SDP: {answer}"
    );
    let contact = ok.headers.get("Contact").expect("a Contact");
    assert!(contact.ends_with(";+sip.srs"), "{contact}");

    let answered: Vec<String> = engine
        .commands("answer_local")
        .into_iter()
        .map(|command| command.call_id)
        .collect();
    assert_eq!(answered, [format!("{call_id}~0"), format!("{call_id}~1")]);
    assert!(
        engine.commands("offer").is_empty(),
        "never a two-party relay"
    );
    assert!(
        engine.commands("answer").is_empty(),
        "never a two-party relay"
    );
    let recordings = engine.commands("start_recording");
    assert_eq!(recordings.len(), 2);
    for recording in &recordings {
        let path = recording.detail.as_deref().expect("a file");
        assert!(path.starts_with(&directory.display().to_string()), "{path}");
        assert!(path.ends_with(".wav"), "{path}");
    }
    assert!(engine
        .commands("answer_local")
        .iter()
        .all(|command| command.sip_call_id.as_deref() == Some(call_id)));

    // The 2xx is retransmitted until its ACK.
    assert!(state.uas_2xx_retransmits.contains_key(call_id));
    let tag = to_tag(&ok);
    send(
        &state,
        &request("ACK", call_id, "z9hG4bK-ack", 1, Some(&tag), None, "", true),
    );
    assert!(
        !state.uas_2xx_retransmits.contains_key(call_id),
        "the ACK stopped it"
    );

    send(
        &state,
        &request("BYE", call_id, "z9hG4bK-bye", 2, Some(&tag), None, "", true),
    );
    await_response(&udp, &mut seen, 200, "BYE").await;
    assert!(
        eventually(|| engine.commands("delete").len() == 2).await,
        "both engine calls end: {:?}",
        engine.commands("delete")
    );
    assert_eq!(engine.held_count(), 0);
    assert_eq!(srs(&state).session_count(), 0, "the store drains");
    let _ = std::fs::remove_dir_all(directory);
}

/// One stream offered is one answered; three are three (RFC 3264 §6).
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_has_as_many_m_lines_as_the_offer() {
    for streams in [1, 3] {
        let engine = NativeTestEngine::start().await;
        let directory = scratch_dir("count");
        let (state, udp) = srs_state(&engine, &directory);
        let call_id = format!("count-{streams}@198.51.100.20");
        send(&state, &siprec_invite(&call_id, streams, true));
        let mut seen = Vec::new();
        let ok = await_response(&udp, &mut seen, 200, "INVITE").await;
        assert_eq!(m_lines(&body(&ok)).len(), streams, "{}", body(&ok));
        assert_eq!(engine.commands("answer_local").len(), streams);
        let _ = std::fs::remove_dir_all(directory);
    }
}

/// RFC 7866 §6.2: a SIPREC body without `Require: siprec` and `+sip.src` is
/// not a recording session. Refused, never recorded.
#[tokio::test(flavor = "multi_thread")]
async fn a_siprec_body_without_the_markers_is_refused() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("markers");
    let (state, udp) = srs_state(&engine, &directory);
    send(&state, &siprec_invite("markers@198.51.100.20", 2, false));
    let mut seen = Vec::new();
    let refused = await_response(&udp, &mut seen, 400, "INVITE").await;
    let crate::sip::message::StartLine::Response(status) = &refused.start_line else {
        panic!("a response");
    };
    assert_eq!(status.reason_phrase, "Not A Recording Session");
    assert_eq!(
        count(&seen, 100, "INVITE"),
        0,
        "refused before anything else"
    );
    assert_eq!(count(&seen, 200, "INVITE"), 0);
    assert!(engine.commands("answer_local").is_empty());
    assert_eq!(srs(&state).session_count(), 0);
    let _ = std::fs::remove_dir_all(directory);
}

/// A profile the deployment does not have is a non-2xx, never a 200 echoing
/// the SRC's own SDP.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_profile_refuses_the_recording() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("profile");
    let mut dispatcher = test_dispatcher();
    dispatcher.state.rtpengine_set = Some(engine.backend());
    dispatcher.state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    dispatcher.state.srs_manager = Some(Arc::new(crate::srs::SrsManager::new(
        crate::config::SrsConfig {
            enabled: true,
            recording_dir: directory.display().to_string(),
            max_sessions: 10,
            backend: "file".to_string(),
            file: None,
            http: None,
            rtpengine_profile: "no_such_profile".to_string(),
        },
    )));
    let (state, udp) = (Arc::new(dispatcher.state), dispatcher.udp);
    send(&state, &siprec_invite("profile@198.51.100.20", 2, true));
    let mut seen = Vec::new();
    let refused = await_response(&udp, &mut seen, 500, "INVITE").await;
    assert!(refused.body.is_empty());
    assert_eq!(count(&seen, 200, "INVITE"), 0);
    assert!(engine.commands("answer_local").is_empty());
    assert_eq!(srs(&state).session_count(), 0);
    let _ = std::fs::remove_dir_all(directory);
}

/// A retransmitted INVITE is the same session, answered again; the engine is
/// asked nothing more.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_invite_is_answered_again_not_recorded_twice() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("retransmit");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "retransmit@198.51.100.20";
    let invite = siprec_invite(call_id, 2, true);
    send(&state, &invite);
    let mut seen = Vec::new();
    await_response(&udp, &mut seen, 200, "INVITE").await;

    send(&state, &invite);
    for _ in 0..20 {
        seen.extend(drain(&udp));
        if count(&seen, 200, "INVITE") >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(count(&seen, 200, "INVITE"), 2, "the 200 again");
    assert_eq!(
        engine.commands("answer_local").len(),
        2,
        "one call per stream, once"
    );
    assert_eq!(srs(&state).session_count(), 1);
    let _ = std::fs::remove_dir_all(directory);
}

/// A CANCEL before the final response: 200 to the CANCEL, 487 to the INVITE,
/// no 200, and whatever the engine started is ended (RFC 3261 §9.2).
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_invite_gets_487_and_leaves_nothing_behind() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("cancel");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "cancel@198.51.100.20";
    // The engine holds its answers, so the INVITE's media set-up is provably
    // still pending when the CANCEL arrives.
    engine.hold_answers();
    send(&state, &siprec_invite(call_id, 2, true));
    let mut seen = Vec::new();
    await_response(&udp, &mut seen, 100, "INVITE").await;
    send(
        &state,
        &request(
            "CANCEL",
            call_id,
            &format!("z9hG4bK-{call_id}"),
            1,
            None,
            None,
            "",
            true,
        ),
    );
    await_response(&udp, &mut seen, 200, "CANCEL").await;
    let terminated = await_response(&udp, &mut seen, 487, "INVITE").await;
    assert!(
        terminated
            .headers
            .to()
            .is_some_and(|to| to.contains("tag=")),
        "a final response carries siphon's To-tag"
    );
    // The set-up the CANCEL overtook finishes, and is undone.
    engine.release_answers();
    assert!(
        eventually(|| srs(&state).session_count() == 0).await,
        "the session ends"
    );
    assert!(
        eventually(|| engine.held_count() == 0).await,
        "no engine call is left"
    );
    seen.extend(drain(&udp));
    assert_eq!(count(&seen, 200, "INVITE"), 0, "no 200 after the 487");

    // The INVITE again gets the 487 again.
    send(&state, &siprec_invite(call_id, 2, true));
    seen.clear();
    await_response(&udp, &mut seen, 487, "INVITE").await;
    assert_eq!(srs(&state).session_count(), 0);
    let _ = std::fs::remove_dir_all(directory);
}

/// A CANCEL for a Call-ID the SRS holds but on another branch matches nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_after_the_200_changes_nothing() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("late-cancel");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "late-cancel@198.51.100.20";
    send(&state, &siprec_invite(call_id, 2, true));
    let mut seen = Vec::new();
    await_response(&udp, &mut seen, 200, "INVITE").await;
    send(
        &state,
        &request(
            "CANCEL",
            call_id,
            &format!("z9hG4bK-{call_id}"),
            1,
            None,
            None,
            "",
            true,
        ),
    );
    await_response(&udp, &mut seen, 200, "CANCEL").await;
    assert_eq!(count(&seen, 487, "INVITE"), 0);
    assert_eq!(srs(&state).session_count(), 1, "the recording goes on");
    let _ = std::fs::remove_dir_all(directory);
}

/// A stream added by re-INVITE is answered and recorded on a call of its own;
/// the streams already there keep their calls (RFC 3264 §8).
#[tokio::test(flavor = "multi_thread")]
async fn a_reinvite_adding_a_stream_answers_and_records_only_that_one() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("reinvite");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "reinvite@198.51.100.20";
    send(&state, &siprec_invite(call_id, 2, true));
    let mut seen = Vec::new();
    let ok = await_response(&udp, &mut seen, 200, "INVITE").await;
    let tag = to_tag(&ok);
    send(
        &state,
        &request("ACK", call_id, "z9hG4bK-a1", 1, Some(&tag), None, "", true),
    );
    seen.clear();

    send(
        &state,
        &request(
            "INVITE",
            call_id,
            "z9hG4bK-re",
            2,
            Some(&tag),
            Some("multipart/mixed;boundary=srs-boundary"),
            &multipart(&offer(3), &metadata(3)),
            true,
        ),
    );
    let reanswered = await_response(&udp, &mut seen, 200, "INVITE").await;
    assert_eq!(
        m_lines(&body(&reanswered)).len(),
        3,
        "{}",
        body(&reanswered)
    );
    let answered: Vec<String> = engine
        .commands("answer_local")
        .into_iter()
        .map(|command| command.call_id)
        .collect();
    assert_eq!(
        answered,
        [
            format!("{call_id}~0"),
            format!("{call_id}~1"),
            format!("{call_id}~2")
        ],
        "only the new stream is answered again"
    );
    assert_eq!(engine.commands("start_recording").len(), 3);
    assert_eq!(
        srs(&state)
            .get_session(call_id)
            .map(|session| session.metadata.streams.len()),
        Some(3)
    );
    let _ = std::fs::remove_dir_all(directory);
}

/// A re-INVITE that only pauses a stream (`inactive`) keeps its engine call and
/// recording, and is answered `inactive`.
#[tokio::test(flavor = "multi_thread")]
async fn pausing_a_stream_keeps_its_recording() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("pause");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "pause@198.51.100.20";
    send(&state, &siprec_invite(call_id, 2, true));
    let mut seen = Vec::new();
    let ok = await_response(&udp, &mut seen, 200, "INVITE").await;
    let tag = to_tag(&ok);
    send(
        &state,
        &request("ACK", call_id, "z9hG4bK-a1", 1, Some(&tag), None, "", true),
    );
    seen.clear();

    let paused = offer(2).replace("a=sendonly", "a=inactive");
    send(
        &state,
        &request(
            "INVITE",
            call_id,
            "z9hG4bK-pause",
            2,
            Some(&tag),
            Some("application/sdp"),
            &paused,
            true,
        ),
    );
    let reanswered = await_response(&udp, &mut seen, 200, "INVITE").await;
    assert_eq!(body(&reanswered).matches("a=inactive").count(), 2);
    assert_eq!(
        engine.commands("answer_local").len(),
        2,
        "no call answered again"
    );
    assert_eq!(
        engine.commands("start_recording").len(),
        2,
        "no recording restarted"
    );
    assert!(engine.commands("delete").is_empty());
    let _ = std::fs::remove_dir_all(directory);
}

/// RFC 7866 §5.2: metadata alone in an UPDATE, folded into the snapshot.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_with_partial_metadata_merges_it() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("update");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "update@198.51.100.20";
    send(&state, &siprec_invite(call_id, 2, true));
    let mut seen = Vec::new();
    let ok = await_response(&udp, &mut seen, 200, "INVITE").await;
    let tag = to_tag(&ok);
    send(
        &state,
        &request("ACK", call_id, "z9hG4bK-a1", 1, Some(&tag), None, "", true),
    );

    let partial = concat!(
        "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">",
        "<datamode>partial</datamode>",
        "<participant participant_id=\"p-c\"><nameID aor=\"sip:carol@example.com\"/></participant>",
        "<participantstreamassoc participant_id=\"p-c\"><send>s-1</send><recv>s-0</recv></participantstreamassoc>",
        "</recording>",
    );
    send(
        &state,
        &request(
            "UPDATE",
            call_id,
            "z9hG4bK-up",
            2,
            Some(&tag),
            Some("application/rs-metadata+xml"),
            partial,
            true,
        ),
    );
    await_response(&udp, &mut seen, 200, "UPDATE").await;
    let session = srs(&state).get_session(call_id).expect("the session");
    assert_eq!(session.metadata.participants.len(), 3);
    assert_eq!(session.metadata.participant_streams.len(), 3);
    assert_eq!(
        session.metadata.session_id, "rs-shared",
        "the snapshot kept its session"
    );
    drop(session);
    assert_eq!(engine.commands("answer_local").len(), 2, "no media change");
    let _ = std::fs::remove_dir_all(directory);
}

/// A request in a recording dialog with a To-tag that is not siphon's is no
/// dialog of the SRS (RFC 3261 §12.2.2).
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_with_the_wrong_to_tag_is_481_and_ends_nothing() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("wrong-tag");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "wrong-tag@198.51.100.20";
    send(&state, &siprec_invite(call_id, 2, true));
    let mut seen = Vec::new();
    await_response(&udp, &mut seen, 200, "INVITE").await;
    send(
        &state,
        &request(
            "BYE",
            call_id,
            "z9hG4bK-b",
            2,
            Some("srs-forged"),
            None,
            "",
            true,
        ),
    );
    await_response(&udp, &mut seen, 481, "BYE").await;
    assert_eq!(srs(&state).session_count(), 1);
    assert!(engine.commands("delete").is_empty());
    let _ = std::fs::remove_dir_all(directory);
}

/// Two SRCs that pick the same metadata `session_id` record two sessions; one
/// BYE ends only its own (the session_id is data, never a key).
#[tokio::test(flavor = "multi_thread")]
async fn two_srcs_with_one_session_id_are_two_recordings() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("shared-id");
    let (state, udp) = srs_state(&engine, &directory);
    let mut seen = Vec::new();
    send(&state, &siprec_invite("first@198.51.100.20", 2, true));
    let first = await_response(&udp, &mut seen, 200, "INVITE").await;
    seen.clear();
    send(&state, &siprec_invite("second@198.51.100.20", 2, true));
    await_response(&udp, &mut seen, 200, "INVITE").await;
    assert_eq!(srs(&state).session_count(), 2);

    send(
        &state,
        &request(
            "BYE",
            "first@198.51.100.20",
            "z9hG4bK-b1",
            2,
            Some(&to_tag(&first)),
            None,
            "",
            true,
        ),
    );
    await_response(&udp, &mut seen, 200, "BYE").await;
    assert!(eventually(|| srs(&state).session_count() == 1).await);
    assert!(srs(&state).is_srs_session("second@198.51.100.20"));
    assert!(
        eventually(|| engine.held_count() == 2).await,
        "the second keeps its calls"
    );
    let _ = std::fs::remove_dir_all(directory);
}

/// RFC 3261 §13.3.1.4: a 2xx the SRC never ACKs within 64×T1 ends the session
/// with a BYE to the SRC, and the engine calls go with it.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_never_acked_ends_the_recording_with_a_bye() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("no-ack");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "no-ack@198.51.100.20";
    send(&state, &siprec_invite(call_id, 2, true));
    let mut seen = Vec::new();
    let ok = await_response(&udp, &mut seen, 200, "INVITE").await;

    // Its 64×T1 run out.
    let armed = state
        .uas_2xx_retransmits
        .get(call_id)
        .map(|entry| Arc::clone(entry.value()))
        .expect("the 2xx waits for its ACK");
    state.uas_2xx_retransmits.insert(
        call_id.to_string(),
        Arc::new(UnackedAnswer {
            cancel: tokio::sync::Notify::new(),
            deadline: tokio::time::Instant::now() - Duration::from_millis(1),
            internal_call_id: armed.internal_call_id.clone(),
        }),
    );
    armed.cancel.notify_one();
    // Before its deadline the sweep leaves an SRS 2xx alone, as a call's.
    tokio::task::block_in_place(|| sweep_unacked_uas_2xx(&state));

    seen.extend(drain(&udp));
    let bye = seen
        .iter()
        .find(|message| message.method() == Some(&crate::sip::message::Method::Bye))
        .expect("a BYE to the SRC");
    assert_eq!(bye.headers.call_id().map(String::as_str), Some(call_id));
    assert!(
        bye.headers
            .from()
            .is_some_and(|from| from.contains(&to_tag(&ok))),
        "from siphon's side of the dialog"
    );
    assert!(bye
        .headers
        .to()
        .is_some_and(|to| to.contains("tag=src-tag")));
    assert!(bye
        .request_uri()
        .is_some_and(|uri| uri.to_string().contains("198.51.100.20")));
    assert_eq!(srs(&state).session_count(), 0);
    assert!(eventually(|| engine.held_count() == 0).await);
    let _ = std::fs::remove_dir_all(directory);
}

/// Before its 64×T1 the sweep keeps retransmitting an SRS 2xx: an SRS dialog
/// has no call actor, and is not taken for one that ended.
#[tokio::test(flavor = "multi_thread")]
async fn the_sweep_leaves_a_live_srs_2xx_retransmitting() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("sweep");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "sweep@198.51.100.20";
    send(&state, &siprec_invite(call_id, 2, true));
    let mut seen = Vec::new();
    await_response(&udp, &mut seen, 200, "INVITE").await;
    tokio::task::block_in_place(|| sweep_unacked_uas_2xx(&state));
    assert!(state.uas_2xx_retransmits.contains_key(call_id));
    tokio::time::sleep(Duration::from_millis(700)).await;
    seen.extend(drain(&udp));
    assert!(count(&seen, 200, "INVITE") >= 2, "retransmitted at T1");
    assert_eq!(srs(&state).session_count(), 1);
    let _ = std::fs::remove_dir_all(directory);
}

/// The leak check: sessions, engine calls and 2xx entries all drain to zero.
#[tokio::test(flavor = "multi_thread")]
async fn many_sessions_drain_back_to_baseline() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("drain");
    let (state, udp) = srs_state(&engine, &directory);
    let mut seen = Vec::new();
    for index in 0..8 {
        let call_id = format!("drain-{index}@198.51.100.20");
        send(&state, &siprec_invite(&call_id, 2, true));
        seen.clear();
        let ok = await_response(&udp, &mut seen, 200, "INVITE").await;
        let tag = to_tag(&ok);
        if index % 2 == 0 {
            send(
                &state,
                &request("ACK", &call_id, "z9hG4bK-a", 1, Some(&tag), None, "", true),
            );
        }
        send(
            &state,
            &request("BYE", &call_id, "z9hG4bK-b", 2, Some(&tag), None, "", true),
        );
        await_response(&udp, &mut seen, 200, "BYE").await;
    }
    assert!(eventually(|| srs(&state).session_count() == 0).await);
    assert!(eventually(|| engine.held_count() == 0).await);
    assert!(
        state.uas_2xx_retransmits.is_empty(),
        "a BYE before the ACK stops the 2xx too"
    );
    let _ = std::fs::remove_dir_all(directory);
}
