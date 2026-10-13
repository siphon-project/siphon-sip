//! The precondition status an answerer with nothing to reserve gives back
//! (RFC 3312 §5.2).
//!
//! A session description that uses preconditions says, for each stream and
//! status type, what is reserved (`a=curr:`) and what has to be before the
//! callee is alerted (`a=des:`). The status type is `e2e`, or `local` and
//! `remote` for the two access networks, and every tag is the point of view of
//! whoever wrote the description: in an answer "`send`, `recv`, `local` and
//! `remote` tags have to be inverted" (§5.2, table 4).
//!
//! A B2BUA that answers an offer itself reserves nothing: its side of each
//! status is met from the start. So its answer says, per stream:
//!
//! * segmented: `curr:qos local sendrecv` for its own access network, and for
//!   the offerer's (`remote` here) what the offerer reported as its `local`,
//!   turned round. §5.2 has the answerer take a "yes" of the offer's over (table
//!   3, third row), and a B2BUA has no information of its own about that
//!   network to add to it;
//! * end to end: what the offerer reported, turned round, plus `send`. Each
//!   party reports the direction it sends in (§13.1), and nothing has to be
//!   reserved for the B2BUA's;
//! * every `des` line of the offer with its strength as offered, neither
//!   upgraded nor downgraded (§5.2), and its status type and direction turned
//!   round.
//!
//! It asks for no confirmation (`a=conf:`, §7): there is nothing it waits for.
//! Only the `qos` precondition type is answered. RFC 3312 defines no other, and
//! a type defined since means something siphon cannot vouch for.

use super::sdp::MediaLine;

/// The attributes that carry preconditions (RFC 3312 §4).
pub const ATTRIBUTE_NAMES: [&str; 3] = ["curr", "des", "conf"];

/// Whether `section` carries a precondition attribute.
pub fn uses_preconditions(section: &MediaLine) -> bool {
    ATTRIBUTE_NAMES.iter().any(|name| section.has_attr(name))
}

/// Take every precondition attribute off `section`.
pub fn remove_preconditions(section: &mut MediaLine) {
    for name in ATTRIBUTE_NAMES {
        section.remove_attr(name);
    }
}

/// A `direction-tag`: the directions a status covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Direction {
    send: bool,
    recv: bool,
}

impl Direction {
    const NONE: Direction = Direction {
        send: false,
        recv: false,
    };
    const SEND: Direction = Direction {
        send: true,
        recv: false,
    };
    const BOTH: Direction = Direction {
        send: true,
        recv: true,
    };

    fn parse(tag: &str) -> Option<Direction> {
        match tag {
            "none" => Some(Direction::NONE),
            "send" => Some(Direction::SEND),
            "recv" => Some(Direction {
                send: false,
                recv: true,
            }),
            "sendrecv" => Some(Direction::BOTH),
            _ => None,
        }
    }

    /// The same directions seen from the other party (table 4).
    fn turned(self) -> Direction {
        Direction {
            send: self.recv,
            recv: self.send,
        }
    }

    fn with(self, other: Direction) -> Direction {
        Direction {
            send: self.send || other.send,
            recv: self.recv || other.recv,
        }
    }

    fn tag(self) -> &'static str {
        match (self.send, self.recv) {
            (false, false) => "none",
            (true, false) => "send",
            (false, true) => "recv",
            (true, true) => "sendrecv",
        }
    }
}

/// A `status-type`, in the order an answer lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StatusType {
    EndToEnd,
    Local,
    Remote,
}

impl StatusType {
    fn parse(tag: &str) -> Option<StatusType> {
        match tag {
            "e2e" => Some(StatusType::EndToEnd),
            "local" => Some(StatusType::Local),
            "remote" => Some(StatusType::Remote),
            _ => None,
        }
    }

    /// The same segment named by the other party (table 4).
    fn turned(self) -> StatusType {
        match self {
            StatusType::EndToEnd => StatusType::EndToEnd,
            StatusType::Local => StatusType::Remote,
            StatusType::Remote => StatusType::Local,
        }
    }

    fn tag(self) -> &'static str {
        match self {
            StatusType::EndToEnd => "e2e",
            StatusType::Local => "local",
            StatusType::Remote => "remote",
        }
    }
}

/// The values of the `a=curr:` and `a=des:` attributes that answer the
/// preconditions `offered` carries, from an answerer with nothing to reserve,
/// each as `curr:…` or `des:…` without the `a=`. Empty when `offered` carries
/// none. `Err` says why the preconditions cannot be answered.
pub fn answered_by_a_party_with_nothing_to_reserve(
    offered: &MediaLine,
) -> Result<Vec<String>, &'static str> {
    const UNREADABLE: &str = "a precondition attribute of the offer does not read";
    const NOT_QOS: &str = "the offer carries a precondition type other than qos";

    let mut end_to_end: Option<Direction> = None;
    let mut offerer_access: Option<Direction> = None;
    let mut segmented = false;
    for value in offered.get_attrs_by_name("curr") {
        let fields: Vec<&str> = value.split_whitespace().collect();
        let [precondition_type, status_type, direction] = fields[..] else {
            return Err(UNREADABLE);
        };
        if precondition_type != "qos" {
            return Err(NOT_QOS);
        }
        let direction = Direction::parse(direction).ok_or(UNREADABLE)?;
        match StatusType::parse(status_type).ok_or(UNREADABLE)? {
            StatusType::EndToEnd => end_to_end = Some(direction),
            StatusType::Local => {
                segmented = true;
                offerer_access = Some(direction);
            }
            // What the offerer believes of this side's access network, which
            // this side knows for itself.
            StatusType::Remote => segmented = true,
        }
    }

    let mut desired: Vec<(StatusType, String)> = Vec::new();
    for value in offered.get_attrs_by_name("des") {
        let fields: Vec<&str> = value.split_whitespace().collect();
        let [precondition_type, strength, status_type, direction] = fields[..] else {
            return Err(UNREADABLE);
        };
        if precondition_type != "qos" {
            return Err(NOT_QOS);
        }
        if !matches!(strength, "mandatory" | "optional" | "none") {
            return Err(UNREADABLE);
        }
        let direction = Direction::parse(direction).ok_or(UNREADABLE)?;
        let status_type = StatusType::parse(status_type).ok_or(UNREADABLE)?;
        match status_type {
            StatusType::EndToEnd => {
                end_to_end.get_or_insert(Direction::NONE);
            }
            StatusType::Local | StatusType::Remote => segmented = true,
        }
        let answered = status_type.turned();
        desired.push((
            answered,
            format!(
                "des:qos {strength} {} {}",
                answered.tag(),
                direction.turned().tag()
            ),
        ));
    }
    for value in offered.get_attrs_by_name("conf") {
        if value.split_whitespace().next() != Some("qos") {
            return Err(NOT_QOS);
        }
    }

    let mut answered = Vec::new();
    if let Some(reported) = end_to_end {
        answered.push(format!(
            "curr:qos e2e {}",
            reported.turned().with(Direction::SEND).tag()
        ));
    }
    if segmented {
        answered.push(format!("curr:qos local {}", Direction::BOTH.tag()));
        answered.push(format!(
            "curr:qos remote {}",
            offerer_access.unwrap_or(Direction::NONE).turned().tag()
        ));
    }
    desired.sort_by_key(|(status_type, _)| *status_type);
    answered.extend(desired.into_iter().map(|(_, line)| line));
    Ok(answered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::sdp::SdpBody;

    fn section(attributes: &[&str]) -> MediaLine {
        let mut sdp = String::from("v=0\r\nm=audio 20000 RTP/AVP 0\r\n");
        for attribute in attributes {
            sdp.push_str(&format!("a={attribute}\r\n"));
        }
        SdpBody::parse(&sdp).media_sections.remove(0)
    }

    fn answered(attributes: &[&str]) -> Vec<String> {
        answered_by_a_party_with_nothing_to_reserve(&section(attributes))
            .expect("the preconditions are answered")
    }

    /// RFC 3312 §13.2: the offerer's UPDATE once its access network is
    /// reserved (SDP3) and the answer that confirms both (SDP4).
    #[test]
    fn a_segmented_offer_is_answered_with_both_access_networks_ready() {
        assert_eq!(
            answered(&[
                "curr:qos local sendrecv",
                "curr:qos remote none",
                "des:qos mandatory local sendrecv",
                "des:qos mandatory remote sendrecv",
            ]),
            [
                "curr:qos local sendrecv",
                "curr:qos remote sendrecv",
                "des:qos mandatory local sendrecv",
                "des:qos mandatory remote sendrecv",
            ]
        );
    }

    /// What the offerer has not reserved is not claimed for it: only this
    /// side's own access network is ready.
    #[test]
    fn the_offerers_access_network_is_reported_as_the_offerer_reported_it() {
        assert_eq!(
            answered(&[
                "curr:qos local none",
                "curr:qos remote none",
                "des:qos mandatory local sendrecv",
                "des:qos optional remote sendrecv",
            ]),
            [
                "curr:qos local sendrecv",
                "curr:qos remote none",
                "des:qos optional local sendrecv",
                "des:qos mandatory remote sendrecv",
            ]
        );
        assert_eq!(
            answered(&["curr:qos local send", "curr:qos remote none"]),
            ["curr:qos local sendrecv", "curr:qos remote recv"]
        );
    }

    /// Table 4: `send` and `recv`, `local` and `remote` are inverted in the
    /// answer, and a strength is neither upgraded nor downgraded. The example
    /// of §5.1.1, second stream.
    #[test]
    fn every_tag_of_a_desired_status_is_turned_round_at_its_own_strength() {
        assert_eq!(
            answered(&[
                "curr:qos local none",
                "curr:qos remote none",
                "des:qos optional remote send",
                "des:qos none remote recv",
                "des:qos none local sendrecv",
            ]),
            [
                "curr:qos local sendrecv",
                "curr:qos remote none",
                "des:qos optional local recv",
                "des:qos none local send",
                "des:qos none remote sendrecv",
            ]
        );
    }

    /// RFC 3312 §13.1: each party reports the direction it sends in. The
    /// offerer's `send` is this side's `recv`, and this side's own `send`
    /// needs no reservation.
    #[test]
    fn an_end_to_end_offer_is_answered_with_this_sides_direction_added() {
        assert_eq!(
            answered(&["curr:qos e2e send", "des:qos mandatory e2e sendrecv"]),
            ["curr:qos e2e sendrecv", "des:qos mandatory e2e sendrecv"]
        );
        assert_eq!(
            answered(&["curr:qos e2e none", "des:qos mandatory e2e sendrecv"]),
            ["curr:qos e2e send", "des:qos mandatory e2e sendrecv"]
        );
        assert_eq!(
            answered(&["curr:qos e2e recv", "des:qos optional e2e send"]),
            ["curr:qos e2e send", "des:qos optional e2e recv"]
        );
    }

    #[test]
    fn a_confirmation_the_offerer_asks_for_is_not_echoed_and_none_is_asked() {
        let lines = answered(&[
            "curr:qos local none",
            "curr:qos remote none",
            "des:qos mandatory local sendrecv",
            "conf:qos remote sendrecv",
        ]);
        assert!(lines.iter().all(|line| !line.starts_with("conf")));
    }

    #[test]
    fn a_stream_without_preconditions_is_answered_without_any() {
        assert_eq!(answered(&["rtpmap:0 PCMU/8000"]), Vec::<String>::new());
        assert!(!uses_preconditions(&section(&["sendrecv"])));
    }

    #[test]
    fn a_precondition_that_is_not_qos_or_does_not_read_is_not_answered() {
        for attributes in [
            &["curr:sec e2e none"][..],
            &["des:sec mandatory e2e sendrecv"][..],
            &["conf:sec e2e sendrecv"][..],
            &["curr:qos e2e"][..],
            &["curr:qos e2e both"][..],
            &["curr:qos nearby none"][..],
            &["des:qos mandatory e2e"][..],
            &["des:qos failure e2e sendrecv"][..],
        ] {
            assert!(
                answered_by_a_party_with_nothing_to_reserve(&section(attributes)).is_err(),
                "{attributes:?}"
            );
        }
    }

    #[test]
    fn the_precondition_attributes_are_found_and_removed() {
        let mut stream = section(&[
            "curr:qos e2e none",
            "des:qos mandatory e2e sendrecv",
            "conf:qos e2e recv",
            "ptime:20",
        ]);
        assert!(uses_preconditions(&stream));
        remove_preconditions(&mut stream);
        assert!(!uses_preconditions(&stream));
        assert_eq!(stream.attrs(), ["ptime:20"]);
    }
}
