//! The SRS side of a SIPREC offer/answer (RFC 7866 §8.1, RFC 3264).
//!
//! An SRC offers one m-line per recorded stream, each normally `sendonly`, and
//! the SRS answers every one of them, in the offer's order and count (RFC 3264
//! §6), receive-only. siphon terminates each stream on its own single-leg media
//! engine call, so the offer is split into one SDP per m-line, and the answer
//! is put back together from the engine's per-stream answers.

use std::fmt::Write as _;

/// One m-line of a SIPREC offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedStream {
    /// Position of the m-line in the offer, from 0.
    pub index: usize,
    /// The m-line's `a=label` (RFC 4574), which the metadata's `<stream>`
    /// elements refer to.
    pub label: Option<String>,
    /// The media type: `audio`, `video`, ...
    pub media: String,
    /// The m-line as offered.
    pub m_line: String,
    /// The offer narrowed to this stream: the session-level lines and this
    /// m-section alone, for the engine to answer.
    pub sdp: String,
    /// What the stream's answer direction must be.
    pub answer_direction: AnswerDirection,
    /// Offered with port 0: the SRC is not using this stream, and its answer is
    /// port 0 too (RFC 3264 §6).
    pub disabled: bool,
}

/// The direction an SRS answers a stream with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerDirection {
    /// The SRC sends on it (`sendonly`, or `sendrecv` from an SRC that does not
    /// mark it): the SRS receives.
    RecvOnly,
    /// The SRC paused it (`inactive`) or would only receive on it
    /// (`recvonly`): an SRS has nothing to send (RFC 7866 §8.1.8), so neither
    /// side sends.
    Inactive,
}

impl AnswerDirection {
    fn attribute(self) -> &'static str {
        match self {
            Self::RecvOnly => "a=recvonly",
            Self::Inactive => "a=inactive",
        }
    }
}

/// Why a SIPREC offer could not be split.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SrsSdpError {
    /// No m-line at all: there is nothing to record.
    #[error("the offer has no media stream")]
    NoMedia,
    /// An m-line without port, protocol and format.
    #[error("malformed m-line: {0}")]
    MalformedMediaLine(String),
}

/// Split a SIPREC offer into its streams.
pub fn split_offer(sdp: &[u8]) -> Result<Vec<OfferedStream>, SrsSdpError> {
    let text = String::from_utf8_lossy(sdp);
    let mut session = String::new();
    let mut sections: Vec<Vec<&str>> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if line.starts_with("m=") {
            sections.push(vec![line]);
        } else if let Some(section) = sections.last_mut() {
            section.push(line);
        } else {
            session.push_str(line);
            session.push_str("\r\n");
        }
    }
    if sections.is_empty() {
        return Err(SrsSdpError::NoMedia);
    }
    let session_direction = direction_of(session.lines());

    sections
        .into_iter()
        .enumerate()
        .map(|(index, section)| {
            let m_line = section[0].to_string();
            let fields: Vec<&str> = m_line["m=".len()..].split_whitespace().collect();
            if fields.len() < 4 {
                return Err(SrsSdpError::MalformedMediaLine(m_line));
            }
            let disabled = fields[1].split('/').next() == Some("0");
            let label = section
                .iter()
                .find_map(|line| line.strip_prefix("a=label:"))
                .map(|label| label.trim().to_string());
            let direction = direction_of(section.iter().copied())
                .or(session_direction)
                .unwrap_or("sendrecv");
            let answer_direction = match direction {
                "sendonly" | "sendrecv" => AnswerDirection::RecvOnly,
                _ => AnswerDirection::Inactive,
            };
            let mut sdp = session.clone();
            for line in &section {
                sdp.push_str(line);
                sdp.push_str("\r\n");
            }
            Ok(OfferedStream {
                index,
                label,
                media: fields[0].to_string(),
                m_line,
                sdp,
                answer_direction,
                disabled,
            })
        })
        .collect()
}

/// The direction attribute among `lines`, without its `a=`.
fn direction_of<'a>(lines: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    lines
        .filter_map(|line| line.strip_prefix("a="))
        .find(|attribute| {
            matches!(
                *attribute,
                "sendonly" | "recvonly" | "sendrecv" | "inactive"
            )
        })
}

/// How one offered stream was answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamAnswer {
    /// The media engine answered it with this SDP (one m-line).
    Engine(String),
    /// Not taken: answered with port 0 (RFC 3264 §6).
    Rejected,
}

/// Put the SRS answer together: one m-line per offered stream, in the offer's
/// order, each from the engine's answer for it with the direction set to the
/// stream's [`AnswerDirection`] and the offer's label kept; a rejected stream is
/// its offered m-line with port 0. The session-level lines come from the first
/// engine answer, and a connection address an engine answer gave at session
/// level moves into its own m-section, since each stream is on a call of its
/// own. `None` when no stream was answered by the engine at all.
pub fn build_answer(streams: &[(OfferedStream, StreamAnswer)]) -> Option<Vec<u8>> {
    let first_engine = streams.iter().find_map(|(_, answer)| match answer {
        StreamAnswer::Engine(sdp) => Some(sdp.as_str()),
        StreamAnswer::Rejected => None,
    })?;

    let mut out = String::new();
    let mut has_timing = false;
    for line in first_engine.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("m=") {
            break;
        }
        // The connection address and a direction are per stream here.
        if line.starts_with("c=")
            || direction_of(std::iter::once(line)).is_some()
            || line.is_empty()
        {
            continue;
        }
        has_timing |= line.starts_with("t=");
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !has_timing {
        out.push_str("t=0 0\r\n");
    }

    for (offered, answer) in streams {
        match answer {
            StreamAnswer::Engine(sdp) => append_engine_stream(&mut out, offered, sdp),
            StreamAnswer::Rejected => append_rejected_stream(&mut out, offered),
        }
    }
    Some(out.into_bytes())
}

fn append_engine_stream(out: &mut String, offered: &OfferedStream, sdp: &str) {
    let mut session_connection = None;
    let mut in_media = false;
    let mut media_connection = false;
    let mut section = String::new();
    for line in sdp.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("m=") {
            if in_media {
                break;
            }
            in_media = true;
            section.push_str(line);
            section.push_str("\r\n");
            continue;
        }
        if !in_media {
            if line.starts_with("c=") {
                session_connection = Some(line.to_string());
            }
            continue;
        }
        if direction_of(std::iter::once(line)).is_some() || line.starts_with("a=label:") {
            continue;
        }
        media_connection |= line.starts_with("c=");
        section.push_str(line);
        section.push_str("\r\n");
    }
    if !in_media {
        append_rejected_stream(out, offered);
        return;
    }
    // The connection line goes right after the m-line (RFC 4566 §5 order).
    let mut lines = section.splitn(2, "\r\n");
    let m_line = lines.next().unwrap_or_default();
    let rest = lines.next().unwrap_or_default();
    out.push_str(m_line);
    out.push_str("\r\n");
    if !media_connection {
        if let Some(connection) = &session_connection {
            out.push_str(connection);
            out.push_str("\r\n");
        }
    }
    out.push_str(rest);
    out.push_str(offered.answer_direction.attribute());
    out.push_str("\r\n");
    if let Some(label) = &offered.label {
        let _ = write!(out, "a=label:{label}\r\n");
    }
}

fn append_rejected_stream(out: &mut String, offered: &OfferedStream) {
    let mut fields = offered.m_line["m=".len()..].split_whitespace();
    let media = fields.next().unwrap_or("audio");
    let _port = fields.next();
    let rest: Vec<&str> = fields.collect();
    let _ = write!(out, "m={media} 0 {}\r\n", rest.join(" "));
    if let Some(label) = &offered.label {
        let _ = write!(out, "a=label:{label}\r\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A two-stream offer as an SRC sends it: session-level connection, both
    /// streams sendonly and labelled.
    const TWO_STREAMS: &str = concat!(
        "v=0\r\n",
        "o=src 1 1 IN IP4 198.51.100.20\r\n",
        "s=-\r\n",
        "c=IN IP4 198.51.100.20\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 0 101\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=label:1\r\n",
        "a=sendonly\r\n",
        "m=audio 40002 RTP/AVP 0 101\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=label:2\r\n",
        "a=sendonly\r\n",
    );

    /// What the engine answers a single-stream offer with.
    fn engine_answer(port: u16) -> String {
        format!(
            concat!(
                "v=0\r\n",
                "o=- 7 7 IN IP4 203.0.113.60\r\n",
                "s=-\r\n",
                "c=IN IP4 203.0.113.60\r\n",
                "t=0 0\r\n",
                "m=audio {port} RTP/AVP 0\r\n",
                "a=rtpmap:0 PCMU/8000\r\n",
                "a=recvonly\r\n",
            ),
            port = port
        )
    }

    fn m_lines(sdp: &str) -> Vec<&str> {
        sdp.lines().filter(|line| line.starts_with("m=")).collect()
    }

    #[test]
    fn splits_each_m_line_with_the_session_lines() {
        let streams = split_offer(TWO_STREAMS.as_bytes()).unwrap();
        assert_eq!(streams.len(), 2);
        for (index, stream) in streams.iter().enumerate() {
            assert_eq!(stream.index, index);
            assert_eq!(stream.media, "audio");
            assert_eq!(m_lines(&stream.sdp).len(), 1, "{}", stream.sdp);
            assert!(stream.sdp.contains("c=IN IP4 198.51.100.20\r\n"));
            assert_eq!(stream.answer_direction, AnswerDirection::RecvOnly);
            assert!(!stream.disabled);
        }
        assert_eq!(streams[0].label.as_deref(), Some("1"));
        assert_eq!(streams[1].label.as_deref(), Some("2"));
        assert!(streams[1].sdp.contains("m=audio 40002 "));
    }

    #[test]
    fn a_single_stream_offer_is_one_stream() {
        let one = TWO_STREAMS.split("m=audio 40002").next().unwrap();
        assert_eq!(split_offer(one.as_bytes()).unwrap().len(), 1);
    }

    #[test]
    fn three_streams_are_three() {
        let three = format!(
            "{TWO_STREAMS}m=video 40004 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=label:3\r\na=sendonly\r\n"
        );
        let streams = split_offer(three.as_bytes()).unwrap();
        assert_eq!(streams.len(), 3);
        assert_eq!(streams[2].media, "video");
        assert_eq!(streams[2].label.as_deref(), Some("3"));
    }

    #[test]
    fn a_paused_or_receive_only_stream_is_answered_inactive() {
        let paused = TWO_STREAMS.replacen("a=sendonly", "a=inactive", 1);
        let streams = split_offer(paused.as_bytes()).unwrap();
        assert_eq!(streams[0].answer_direction, AnswerDirection::Inactive);
        assert_eq!(streams[1].answer_direction, AnswerDirection::RecvOnly);
        let receive_only = TWO_STREAMS.replacen("a=sendonly", "a=recvonly", 1);
        let streams = split_offer(receive_only.as_bytes()).unwrap();
        assert_eq!(streams[0].answer_direction, AnswerDirection::Inactive);
    }

    #[test]
    fn a_session_level_direction_applies_to_unmarked_streams() {
        let offer = TWO_STREAMS
            .replace("a=sendonly\r\n", "")
            .replace("t=0 0\r\n", "t=0 0\r\na=inactive\r\n");
        let streams = split_offer(offer.as_bytes()).unwrap();
        assert!(streams
            .iter()
            .all(|stream| stream.answer_direction == AnswerDirection::Inactive));
    }

    #[test]
    fn a_port_zero_stream_is_disabled() {
        let offer = TWO_STREAMS.replace("m=audio 40002", "m=audio 0");
        let streams = split_offer(offer.as_bytes()).unwrap();
        assert!(!streams[0].disabled);
        assert!(streams[1].disabled);
    }

    #[test]
    fn an_offer_without_media_is_refused() {
        assert_eq!(
            split_offer(b"v=0\r\ns=-\r\nt=0 0\r\n"),
            Err(SrsSdpError::NoMedia)
        );
    }

    #[test]
    fn a_malformed_m_line_is_refused() {
        assert!(matches!(
            split_offer(b"v=0\r\nm=audio 4000\r\n"),
            Err(SrsSdpError::MalformedMediaLine(_))
        ));
    }

    #[test]
    fn the_answer_has_one_recvonly_labelled_m_line_per_stream_in_order() {
        let streams = split_offer(TWO_STREAMS.as_bytes()).unwrap();
        let answered: Vec<_> = streams
            .into_iter()
            .zip([51000, 51002])
            .map(|(stream, port)| (stream, StreamAnswer::Engine(engine_answer(port))))
            .collect();
        let answer = String::from_utf8(build_answer(&answered).unwrap()).unwrap();

        assert_eq!(
            m_lines(&answer),
            ["m=audio 51000 RTP/AVP 0", "m=audio 51002 RTP/AVP 0"]
        );
        assert_eq!(answer.matches("a=recvonly").count(), 2, "{answer}");
        assert!(!answer.contains("sendonly") && !answer.contains("sendrecv"));
        let first = answer.find("m=audio 51000").unwrap();
        let second = answer.find("m=audio 51002").unwrap();
        assert!(answer[first..second].contains("a=label:1"), "{answer}");
        assert!(answer[second..].contains("a=label:2"), "{answer}");
        // Each stream carries its own connection address, right after its m-line.
        assert!(answer[first..].starts_with("m=audio 51000 RTP/AVP 0\r\nc=IN IP4 203.0.113.60\r\n"));
        assert!(
            answer[second..].starts_with("m=audio 51002 RTP/AVP 0\r\nc=IN IP4 203.0.113.60\r\n")
        );
        // One session section, from the engine.
        assert_eq!(answer.matches("v=0").count(), 1);
        assert!(answer.starts_with("v=0\r\no=- 7 7 IN IP4 203.0.113.60\r\ns=-\r\nt=0 0\r\n"));
        assert!(!answer.contains("198.51.100.20"), "never the SRC's address");
    }

    #[test]
    fn a_rejected_stream_keeps_its_place_with_port_zero() {
        let streams = split_offer(TWO_STREAMS.as_bytes()).unwrap();
        let answered = vec![
            (streams[0].clone(), StreamAnswer::Rejected),
            (
                streams[1].clone(),
                StreamAnswer::Engine(engine_answer(51002)),
            ),
        ];
        let answer = String::from_utf8(build_answer(&answered).unwrap()).unwrap();
        assert_eq!(
            m_lines(&answer),
            ["m=audio 0 RTP/AVP 0 101", "m=audio 51002 RTP/AVP 0"]
        );
        assert!(answer.contains("m=audio 0 RTP/AVP 0 101\r\na=label:1\r\n"));
    }

    #[test]
    fn an_inactive_stream_is_answered_inactive() {
        let paused = TWO_STREAMS.replacen("a=sendonly", "a=inactive", 1);
        let streams = split_offer(paused.as_bytes()).unwrap();
        let answered: Vec<_> = streams
            .into_iter()
            .map(|stream| (stream, StreamAnswer::Engine(engine_answer(51000))))
            .collect();
        let answer = String::from_utf8(build_answer(&answered).unwrap()).unwrap();
        assert_eq!(answer.matches("a=inactive").count(), 1, "{answer}");
        assert_eq!(answer.matches("a=recvonly").count(), 1, "{answer}");
    }

    #[test]
    fn no_engine_answer_builds_nothing() {
        let streams = split_offer(TWO_STREAMS.as_bytes()).unwrap();
        let answered: Vec<_> = streams
            .into_iter()
            .map(|stream| (stream, StreamAnswer::Rejected))
            .collect();
        assert_eq!(build_answer(&answered), None);
    }
}
