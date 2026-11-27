//! A siphon-rtp media engine speaking the native protocol inside the test
//! process.
//!
//! [`super::test_engine::TestEngine`] speaks the rtpengine NG protocol, which
//! has no `answer_local`: an offerless originate is only served by the native
//! backend, so a test that drives one end to end points a [`MediaBackend`] at
//! this engine. It answers `answer_local` with [`NATIVE_ENGINE_ANSWER`], pings
//! with a pong and everything else with a bare `ok`, and records the call-id and
//! tag of every media command it is sent.
//!
//! It keeps the calls it holds the way the real engine does: `answer_local` and
//! `offer` create one, `delete` ends it, and an `answer`, `reoffer`,
//! `play_media`, `stop_media` or `delete` on a call it does not hold is refused
//! with the engine's own `unknown call: <call-id>`. A test that deletes a
//! session too early therefore sees the refusal a deployment would.
//!
//! It models what siphon-rtp 0.25.2 does with a lawful interception, as far
//! as the commands go ([`X3Model`]): a seat that joined a room is attached by
//! naming the room and the seat's tag, on an engine that lists
//! `x3_conference_seat`; a call it answered itself is attached on one that
//! lists `x3_single_leg` and refused on any other; `conference_seat` is taken
//! on an intercepted call; an `echo` on an intercepted call, and an attach on
//! an echoing one, are refused.
//!
//! And what 0.26.0 does, on an engine that lists `x3_multi_delivery`: a call
//! or a seat carries one delivery per warrant, delivery address and
//! Correlation ID, an attach of the same three replaces only itself and ends
//! the one it replaces with `detached`, a `detach_x3` ends what its selectors
//! name, and every end names its delivery. An engine that does not list it
//! holds one delivery per call: any further attach replaces it, a detach
//! ends it whatever it names, and an end names nothing. On one that lists
//! `x3_ws_takeover` a call whose audio goes to a `ws_uri` server is attached;
//! on any other it is refused.
//!
//! It sends no events. It keeps the `x3_ended` the real engine would have
//! sent for what it was asked ([`NativeTestEngine::take_x3_ends`]), and a
//! test passes them on, or sends one of its own.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use siphon_rtp_proto::{frame, CmdResult, Command, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::MediaBackend;

mod offer_local;
mod split;
use offer_local::OfferLocalModel;
pub(crate) use offer_local::{
    NATIVE_ENGINE_ANSWER_REFUSALS, NATIVE_ENGINE_LOCAL_OFFER, NATIVE_ENGINE_OFFER_LOCAL,
};
use split::SplitModel;
pub(crate) use split::NATIVE_ENGINE_WS_SPLIT;

/// The SDP answer the engine returns for every `answer_local`: its own address,
/// so a test can tell the engine's answer from any SDP a peer sent.
pub(crate) const NATIVE_ENGINE_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=- 7 7 IN IP4 203.0.113.60\r\n",
    "s=-\r\n",
    "c=IN IP4 203.0.113.60\r\n",
    "t=0 0\r\n",
    "m=audio 51000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=sendrecv\r\n",
);

/// The SDP the engine returns for every `offer` and `reoffer`: the relay side
/// it presents to the leg the offer is for, on an address of its own.
pub(crate) const NATIVE_ENGINE_OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 9 9 IN IP4 203.0.113.61\r\n",
    "s=-\r\n",
    "c=IN IP4 203.0.113.61\r\n",
    "t=0 0\r\n",
    "m=audio 52000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=sendrecv\r\n",
);

/// `base` as the engine shapes it for a command: on the profile's `transport`
/// (with an RFC 4568 SDES key when it is a secure one), and carrying the
/// direction the SDP it was given (`input`) states, the way an engine relays a
/// party's `sendonly` hold to the other party and the other's `recvonly` back.
fn native_engine_sdp(base: &str, port: &str, transport: Option<&str>, input: &str) -> String {
    let mut sdp = base.to_string();
    if let Some(transport) = transport {
        sdp = sdp.replace(
            &format!("m=audio {port} RTP/AVP 0 101"),
            &format!("m=audio {port} {transport} 0 101"),
        );
    }
    if let Some(direction) = ["sendonly", "recvonly", "inactive"]
        .into_iter()
        .find(|direction| input.contains(&format!("a={direction}")))
    {
        sdp = sdp.replace("a=sendrecv", &format!("a={direction}"));
    }
    if transport.is_some_and(|transport| transport.contains("SAVP")) {
        sdp.push_str(
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz\r\n",
        );
    }
    sdp
}

/// The SDP the engine returns for every `offer_far`: the offer for the far
/// leg it binds behind a call it answered itself, on a port of its own, so a
/// test can tell it from the caller's answer and from any SDP a peer sent.
pub(crate) const NATIVE_ENGINE_FAR_OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 11 11 IN IP4 203.0.113.62\r\n",
    "s=-\r\n",
    "c=IN IP4 203.0.113.62\r\n",
    "t=0 0\r\n",
    "m=audio 53000 RTP/AVP 0 8 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:8 PCMA/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=sendrecv\r\n",
);

/// An answer the engine refuses on a grown call, as the real one refuses a
/// far party that picks a codec its offer did not list.
pub(crate) const NATIVE_ENGINE_UNOFFERED_CODEC: &str = "G729/8000";

/// An attribute that makes the engine refuse the `answer_local` whose SDP
/// carries it, as the real one refuses an offer it has no stream for.
pub(crate) const NATIVE_ENGINE_REFUSED_OFFER: &str = "a=x-test-refused";

/// One media command the engine was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeCommand {
    /// `answer_local`, `answer`, `delete`, `offer`, `reoffer`, `play_media`,
    /// `stop_media`, `offer_far`, or `delete_far_leg` (a `delete` with a
    /// `to_tag` on a call `offer_far` grew).
    pub(crate) name: &'static str,
    pub(crate) call_id: String,
    pub(crate) from_tag: String,
    /// What the command carried that a test asserts on: the tone a
    /// `play_media` plays (`None` for any other source), the `play_id` a
    /// `stop_media` targets (`None` for a stop of everything), the SDP an
    /// `answer_local` is asked to answer.
    pub(crate) detail: Option<String>,
    /// The `repeat_times` a `play_media` carried, as it is on the wire: a
    /// count, or `inf`. `None` when the command named none.
    pub(crate) repeat: Option<String>,
    /// The profile's `transport_protocol` on an `answer_local`, `offer`,
    /// `answer` or `reoffer`.
    pub(crate) transport_protocol: Option<String>,
    /// The profile's per-call `received_from` on the same four.
    pub(crate) received_from: Option<IpAddr>,
    /// The profile's per-call `sip_call_id` on the same four: the Call-ID of
    /// the dialog whose SDP the command carried.
    pub(crate) sip_call_id: Option<String>,
    /// The profile's `ws_uri` and `ws_tee` on the same four.
    pub(crate) ws_uri: Option<String>,
    pub(crate) ws_tee: Option<String>,
    /// Whether the engine refused the command because it holds no such call.
    pub(crate) refused: bool,
    /// The `dtmf` a `conference_seat` carried (`events` or `forward`).
    pub(crate) dtmf: Option<String>,
    /// The further calls a `start_recording` or `attach_ws_tee` takes audio
    /// from (`additional_sources`), and its `channels`.
    pub(crate) sources: Vec<String>,
    pub(crate) channels: Option<String>,
    /// The frame's `scope`: the node's or a per-call one. The engine keys a
    /// call by `(scope, call_id)`.
    pub(crate) scope: Option<String>,
    /// The profile's `address_family` on an `answer_local`, `offer`, `answer`
    /// or `reoffer`.
    pub(crate) address_family: Option<String>,
    /// The whole profile a command carried, for a test asserting on a
    /// processing setting (`echo_cancellation`, the VAD knobs).
    pub(crate) profile: Option<siphon_rtp_proto::ProfileFlags>,
    /// The delivery an `attach_x3` asked for, or the one a `detach_x3` named
    /// with all three selectors. `None` on a detach of the whole call.
    pub(crate) x3_delivery: Option<crate::rtpengine::events::X3Delivery>,
    /// The `sample_rate` an `attach_ws_split` asked for; `None` when it named
    /// none or the command is another.
    pub(crate) sample_rate: Option<u32>,
}

/// What a recorded command carried, before the engine decides on it.
struct Recorded {
    name: &'static str,
    call_id: String,
    from_tag: String,
    detail: Option<String>,
    repeat: Option<String>,
    profile: Option<siphon_rtp_proto::ProfileFlags>,
    dtmf: Option<String>,
    sources: Vec<String>,
    channels: Option<String>,
    x3_delivery: Option<crate::rtpengine::events::X3Delivery>,
    sample_rate: Option<u32>,
}

/// What the engine makes of a command on a call `offer_far` grew (or the
/// `offer_far` that grows it): the record, the SDP it answers with, and a
/// refusal.
struct GrownCall {
    record: Recorded,
    sdp: Option<String>,
    refusal: Option<String>,
}

/// `command` as the engine handles it on a grown call, or `None` for any
/// other command, which the ordinary arms handle.
fn grown_call_command(command: &Command, grown: &Mutex<HashSet<String>>) -> Option<GrownCall> {
    let Ok(mut set) = grown.lock() else {
        return None;
    };
    match command {
        Command::OfferFar {
            call_id,
            from_tag,
            profile,
        } => {
            set.insert(call_id.clone());
            Some(GrownCall {
                record: Recorded {
                    profile: Some(profile.clone()),
                    ..Recorded::new("offer_far", call_id, from_tag)
                },
                sdp: Some(NATIVE_ENGINE_FAR_OFFER.to_string()),
                refusal: None,
            })
        }
        Command::Delete {
            call_id,
            from_tag,
            to_tag: Some(to_tag),
        } if set.contains(call_id) => {
            set.remove(call_id);
            Some(GrownCall {
                record: Recorded {
                    detail: Some(to_tag.clone()),
                    ..Recorded::new("delete_far_leg", call_id, from_tag)
                },
                sdp: None,
                refusal: None,
            })
        }
        Command::Delete { call_id, .. } => {
            // A whole-call delete forgets the far leg; the ordinary arm records it.
            set.remove(call_id);
            None
        }
        Command::Answer {
            call_id,
            from_tag,
            to_tag,
            profile,
            sdp,
        } if set.contains(call_id) => Some(GrownCall {
            record: Recorded {
                detail: Some(to_tag.clone()),
                profile: Some(profile.clone()),
                ..Recorded::new("answer", call_id, from_tag)
            },
            // The caller's own answer, unchanged.
            sdp: Some(NATIVE_ENGINE_ANSWER.to_string()),
            refusal: sdp.contains(NATIVE_ENGINE_UNOFFERED_CODEC).then(|| {
                "answer: codec-not-offered: the far party answered a codec the far offer did not list"
                    .to_string()
            }),
        }),
        _ => None,
    }
}

impl Recorded {
    /// What the engine keeps of the command, once it has decided on it.
    fn logged(self, refused: bool, scope: Option<String>) -> NativeCommand {
        let profile = self.profile.as_ref();
        NativeCommand {
            transport_protocol: profile.and_then(|profile| profile.transport_protocol.clone()),
            received_from: profile.and_then(|profile| profile.received_from),
            sip_call_id: profile.and_then(|profile| profile.sip_call_id.clone()),
            ws_uri: profile.and_then(|profile| profile.ws_uri.clone()),
            ws_tee: profile.and_then(|profile| profile.ws_tee.clone()),
            address_family: profile.and_then(|profile| profile.address_family.clone()),
            name: self.name,
            call_id: self.call_id,
            from_tag: self.from_tag,
            detail: self.detail,
            repeat: self.repeat,
            refused,
            dtmf: self.dtmf,
            sources: self.sources,
            channels: self.channels,
            scope,
            profile: self.profile,
            x3_delivery: self.x3_delivery,
            sample_rate: self.sample_rate,
        }
    }

    fn new(name: &'static str, call_id: &str, from_tag: &str) -> Self {
        Recorded {
            name,
            call_id: call_id.to_string(),
            from_tag: from_tag.to_string(),
            detail: None,
            repeat: None,
            profile: None,
            dtmf: None,
            sources: Vec::new(),
            channels: None,
            x3_delivery: None,
            sample_rate: None,
        }
    }
}

/// The delivery an X3 command names with a warrant, an address and a
/// Correlation ID; none when it leaves any of them out.
fn named_delivery(
    xid: Option<siphon_rtp_proto::Xid>,
    delivery: Option<&String>,
    correlation_id: Option<u64>,
) -> Option<crate::rtpengine::events::X3Delivery> {
    Some(crate::rtpengine::events::X3Delivery {
        xid: *xid?.as_bytes(),
        address: delivery?.clone(),
        correlation_id: correlation_id?,
    })
}

/// What the engine records of an X3 attach or detach, and whether it needs the
/// call: an interception taps a call the engine holds, or (`on_seat`) a seat
/// that joined a room, which has no call. `detail` is an attach's
/// `target_leg`.
fn x3_command(command: &Command, on_seat: bool) -> (Option<Recorded>, Option<String>, bool, bool) {
    match command {
        Command::AttachX3 {
            call_id,
            from_tag,
            target_leg,
            xid,
            delivery,
            correlation_id,
        } => (
            Some(Recorded {
                detail: serde_json::to_value(target_leg)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_string)),
                x3_delivery: named_delivery(Some(*xid), Some(delivery), Some(*correlation_id)),
                ..Recorded::new("attach_x3", call_id, from_tag)
            }),
            None,
            false,
            !on_seat,
        ),
        Command::DetachX3 {
            call_id,
            from_tag,
            xid,
            delivery,
            correlation_id,
        } => (
            Some(Recorded {
                x3_delivery: named_delivery(*xid, delivery.as_ref(), *correlation_id),
                ..Recorded::new("detach_x3", call_id, from_tag)
            }),
            None,
            false,
            false,
        ),
        Command::Echo {
            call_id,
            from_tag,
            enabled,
            ..
        } => (
            Some(Recorded {
                detail: Some(enabled.to_string()),
                ..Recorded::new("echo", call_id, from_tag)
            }),
            None,
            false,
            true,
        ),
        _ => (None, None, false, false),
    }
}

/// What [`NativeTestEngine::start`] lists in `node_info.features`.
const NATIVE_ENGINE_FEATURES: [&str; 3] = ["relay", "scope", "conference_seat"];

/// What an engine provisioned for X3 that takes `attach_x3` on an offered,
/// unanswered call lists on top of that.
pub(crate) const NATIVE_ENGINE_X3_AT_OFFER: &str = "x3_attach_at_offer";

/// What a siphon-rtp 0.25.2 provisioned for X3 lists beside it: an
/// interception on a seat that joined a room, and on a call it answered
/// itself.
pub(crate) const NATIVE_ENGINE_X3_CONFERENCE_SEAT: &str = "x3_conference_seat";
pub(crate) const NATIVE_ENGINE_X3_SINGLE_LEG: &str = "x3_single_leg";

/// A room whose id starts with this closes while a call's leg is being moved
/// into it: the engine refuses the `conference_seat` with the call's media
/// path already stopped, and ends the call's interception.
pub(crate) const NATIVE_ENGINE_CLOSING_ROOM: &str = "closing-";

/// The engine's refusal of an `echo` on an intercepted call.
pub(crate) const NATIVE_ENGINE_ECHO_REFUSED: &str = "echo: a lawful-interception delivery is \
    attached to this call and echo bypasses its tap; detach_x3 first";

/// The engine's refusal of an `attach_x3` on a call that is being re-answered.
pub(crate) const NATIVE_ENGINE_ATTACH_RETRY: &str =
    "attach_x3: the call is being re-answered; retry the attach once it is";

/// What a siphon-rtp 0.26.0 provisioned for X3 lists on top: several
/// deliveries on one call, and an interception on a WebSocket-takeover call.
pub(crate) const NATIVE_ENGINE_X3_MULTI_DELIVERY: &str = "x3_multi_delivery";
pub(crate) const NATIVE_ENGINE_X3_WS_TAKEOVER: &str = "x3_ws_takeover";

/// The engine's refusal of an `attach_x3` on a WebSocket-takeover call,
/// before 0.26.0.
pub(crate) const NATIVE_ENGINE_WS_TAKEOVER_REFUSED: &str =
    "attach_x3: a WebSocket-takeover call (ws_uri) has no relayed second party to intercept";

/// One content delivery the engine holds: the call or the seat it is on, and
/// the three values its attach named.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HeldDelivery {
    scope: Option<String>,
    call_id: String,
    from_tag: String,
    xid: siphon_rtp_proto::Xid,
    delivery: String,
    correlation_id: u64,
}

/// What the engine keeps of its interceptions, to answer as siphon-rtp does:
/// the seats that joined a room, the deliveries it holds, the calls in echo
/// mode and the calls whose audio goes to a WebSocket server.
#[derive(Default)]
struct X3Model {
    /// Whether `node_info` lists `x3_conference_seat` and `x3_single_leg`.
    conference_seat: bool,
    single_leg: bool,
    /// Whether it lists `x3_multi_delivery` and `x3_ws_takeover`.
    multi_delivery: bool,
    ws_takeover: bool,
    deliveries: Mutex<Vec<HeldDelivery>>,
    /// The `x3_ended` the engine would have sent, oldest first.
    ends: Mutex<Vec<crate::rtpengine::events::X3EndedEvent>>,
    ws_calls: Mutex<HashSet<(Option<String>, String)>>,
    /// The verbs whose next command is refused, once each.
    refuse_next: Mutex<Vec<&'static str>>,
    /// How many more `attach_x3` to refuse with a reason that says to retry.
    retry_refusals: Mutex<u32>,
    seats: Mutex<HashSet<(String, String)>>,
    echoing: Mutex<HashSet<(Option<String>, String)>>,
}

impl X3Model {
    fn listing(features: &[String]) -> Self {
        let lists = |name: &str| features.iter().any(|feature| feature == name);
        X3Model {
            conference_seat: lists(NATIVE_ENGINE_X3_CONFERENCE_SEAT),
            single_leg: lists(NATIVE_ENGINE_X3_SINGLE_LEG),
            multi_delivery: lists(NATIVE_ENGINE_X3_MULTI_DELIVERY),
            ws_takeover: lists(NATIVE_ENGINE_X3_WS_TAKEOVER),
            ..X3Model::default()
        }
    }

    /// End the deliveries `ends` picks, each with `reason`, and keep the
    /// `x3_ended` of each. An engine that carries several deliveries names
    /// the one that ended; one that holds a single delivery names none.
    fn end_where(
        &self,
        deliveries: &mut Vec<HeldDelivery>,
        reason: &str,
        ends: impl Fn(&HeldDelivery) -> bool,
    ) {
        let (ended, kept): (Vec<_>, Vec<_>) = std::mem::take(deliveries)
            .into_iter()
            .partition(|held| ends(held));
        *deliveries = kept;
        let Ok(mut reported) = self.ends.lock() else {
            return;
        };
        for held in ended {
            reported.push(crate::rtpengine::events::X3EndedEvent {
                call_id: held.call_id,
                from_tag: held.from_tag,
                delivery: self
                    .multi_delivery
                    .then(|| crate::rtpengine::events::X3Delivery {
                        xid: *held.xid.as_bytes(),
                        address: held.delivery,
                        correlation_id: held.correlation_id,
                    }),
                reason: reason.to_string(),
                orderly: reason == "Detached",
                delivered: 10,
                dropped: 0,
            });
        }
    }

    /// Whether the engine holds a delivery on the call `call_id` in `scope`.
    fn intercepts(&self, scope: &Option<String>, call_id: &str) -> bool {
        self.deliveries.lock().is_ok_and(|deliveries| {
            deliveries
                .iter()
                .any(|held| &held.scope == scope && held.call_id == call_id)
        })
    }

    /// Whether an X3 command names a seat that joined a room, on an engine
    /// that intercepts one. Any other engine looks for a call and finds none.
    fn names_seat(&self, command: &Command) -> bool {
        let (Command::AttachX3 {
            call_id, from_tag, ..
        }
        | Command::DetachX3 {
            call_id, from_tag, ..
        }) = command
        else {
            return false;
        };
        self.conference_seat
            && self
                .seats
                .lock()
                .is_ok_and(|seats| seats.contains(&(call_id.clone(), from_tag.clone())))
    }

    /// The engine's refusal of a command an interception rules out.
    fn refusal(
        &self,
        command: &Command,
        scope: &Option<String>,
        local: &Mutex<HashSet<(Option<String>, String)>>,
        grown: &Mutex<HashSet<String>>,
    ) -> Option<String> {
        let holds = |set: &Mutex<HashSet<(Option<String>, String)>>, call_id: &String| {
            set.lock()
                .is_ok_and(|set| set.contains(&(scope.clone(), call_id.clone())))
        };
        let refused_for_now = || {
            self.retry_refusals.lock().is_ok_and(|mut left| {
                let refuse = *left > 0;
                *left = left.saturating_sub(1);
                refuse
            })
        };
        let refuse_next = |verb: &'static str| {
            self.refuse_next.lock().is_ok_and(|mut verbs| {
                let position = verbs.iter().position(|held| *held == verb);
                position.map(|index| verbs.remove(index)).is_some()
            })
        };
        match command {
            Command::Delete { .. } if refuse_next("delete") => {
                Some("delete: refused for the test".to_string())
            }
            // The call is not there to detach from, as after siphon's `delete`.
            Command::DetachX3 { call_id, .. } if refuse_next("detach_x3") => {
                Some(format!("unknown call: {call_id}"))
            }
            Command::ConferenceLeave { .. } if refuse_next("conference_leave") => {
                Some("conference_leave: refused for the test".to_string())
            }
            Command::AttachX3 { .. } if refused_for_now() => {
                Some(NATIVE_ENGINE_ATTACH_RETRY.to_string())
            }
            Command::AttachX3 { call_id, .. } if holds(&self.echoing, call_id) => {
                Some("attach_x3: the call is in echo mode, which bypasses the tap".to_string())
            }
            // Before 0.26.0 a call whose audio goes to a WebSocket server had
            // no second party to intercept.
            Command::AttachX3 { call_id, .. }
                if !self.ws_takeover && holds(&self.ws_calls, call_id) =>
            {
                Some(NATIVE_ENGINE_WS_TAKEOVER_REFUSED.to_string())
            }
            // Either can be shared by two warrants, so neither names a
            // delivery without the warrant.
            Command::DetachX3 {
                xid: None,
                delivery,
                correlation_id,
                ..
            } if self.multi_delivery && (delivery.is_some() || correlation_id.is_some()) => Some(
                "detach_x3: delivery and correlation_id select within xid; name the xid"
                    .to_string(),
            ),
            // Before 0.25.2 a call the engine answered itself, and that no
            // `offer_far` grew a far leg on, had no second party to intercept.
            Command::AttachX3 { call_id, .. } if !self.single_leg => {
                let has_far_leg = grown.lock().is_ok_and(|grown| grown.contains(call_id));
                (holds(local, call_id) && !has_far_leg && !holds(&self.ws_calls, call_id))
                    .then(|| "attach_x3: the call has no second leg to intercept".to_string())
            }
            Command::Echo {
                call_id,
                enabled: true,
                ..
            } if self.intercepts(scope, call_id) => Some(NATIVE_ENGINE_ECHO_REFUSED.to_string()),
            Command::ConferenceSeat { conference_id, .. }
                if conference_id.starts_with(NATIVE_ENGINE_CLOSING_ROOM) =>
            {
                Some(
                    "conference_seat: the room closed before the seat opened; the call's \
                     media path is stopped, delete the call"
                        .to_string(),
                )
            }
            _ => None,
        }
    }

    /// Keep what an accepted command changed.
    fn accepted(&self, command: &Command, scope: &Option<String>) {
        let key = |call_id: &String| (scope.clone(), call_id.clone());
        let (Ok(mut seats), Ok(mut deliveries), Ok(mut echoing), Ok(mut ws_calls)) = (
            self.seats.lock(),
            self.deliveries.lock(),
            self.echoing.lock(),
            self.ws_calls.lock(),
        ) else {
            return;
        };
        let on_call = |held: &HeldDelivery, call_id: &String| {
            &held.scope == scope && &held.call_id == call_id
        };
        match command {
            Command::ConferenceJoin {
                conference_id,
                from_tag,
                ..
            } => {
                seats.insert((conference_id.clone(), from_tag.clone()));
            }
            Command::ConferenceLeave {
                conference_id,
                from_tag,
            } => {
                seats.remove(&(conference_id.clone(), from_tag.clone()));
                // A seat's deliveries end with the seat.
                self.end_where(&mut deliveries, "CallEnded", |held| {
                    on_call(held, conference_id) && &held.from_tag == from_tag
                });
            }
            Command::AttachX3 {
                call_id,
                from_tag,
                delivery,
                xid,
                correlation_id,
                ..
            } => {
                let asked = HeldDelivery {
                    scope: scope.clone(),
                    call_id: call_id.clone(),
                    from_tag: from_tag.clone(),
                    xid: *xid,
                    delivery: delivery.clone(),
                    correlation_id: *correlation_id,
                };
                // The same three values replace only that delivery. An
                // engine that holds one delivery per call replaces whatever
                // the call holds.
                let several = self.multi_delivery;
                self.end_where(&mut deliveries, "Detached", |held| match several {
                    true => held == &asked,
                    false => on_call(held, call_id) && &held.from_tag == from_tag,
                });
                deliveries.push(asked);
            }
            Command::DetachX3 {
                call_id,
                from_tag,
                xid,
                delivery,
                correlation_id,
            } => {
                // An engine from before the selectors reads none of them.
                let several = self.multi_delivery;
                self.end_where(&mut deliveries, "Detached", |held| {
                    on_call(held, call_id)
                        && &held.from_tag == from_tag
                        && (!several
                            || (xid.is_none_or(|xid| xid == held.xid)
                                && delivery
                                    .as_ref()
                                    .is_none_or(|named| named == &held.delivery)
                                && correlation_id.is_none_or(|named| named == held.correlation_id)))
                });
            }
            Command::Delete { call_id, .. } => {
                self.end_where(&mut deliveries, "CallEnded", |held| on_call(held, call_id));
                echoing.remove(&key(call_id));
                ws_calls.remove(&key(call_id));
            }
            // An `offer` on a call the engine holds replaces it, and ends
            // what was attached to it.
            Command::Offer { call_id, .. } => {
                self.end_where(&mut deliveries, "CallEnded", |held| on_call(held, call_id));
                ws_calls.remove(&key(call_id));
            }
            // A call whose audio goes to a WebSocket server, from here on.
            Command::AnswerLocal {
                call_id, profile, ..
            }
            | Command::Answer {
                call_id, profile, ..
            } => {
                if profile.ws_uri.is_some() {
                    ws_calls.insert(key(call_id));
                }
            }
            Command::Echo {
                call_id, enabled, ..
            } => {
                match enabled {
                    true => echoing.insert(key(call_id)),
                    false => echoing.remove(&key(call_id)),
                };
            }
            _ => {}
        }
    }
}

/// The engine's `node_info` answer to request `id`, listing `features`.
fn node_info_answer(id: u64, features: &[String]) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "result": "node_info",
        "node": {
            "node_id": "engine-1",
            "version": "0.14.0",
            "media_addresses": ["192.0.2.10"],
            "codecs": ["PCMU"],
            "features": features,
            "max_sessions": 0,
            "draining": false,
        },
    })
}

/// What the engine records of a `conference_seat`: a leg of a live call
/// moved into a room, which needs the call held.
fn seat_command(command: &Command) -> (Option<Recorded>, Option<String>, bool, bool) {
    match command {
        Command::ConferenceSeat {
            call_id,
            from_tag,
            conference_id,
            dtmf,
            ..
        } => (
            Some(Recorded {
                dtmf: serde_json::to_value(dtmf)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_string)),
                detail: Some(conference_id.clone()),
                ..Recorded::new("conference_seat", call_id, from_tag)
            }),
            None,
            false,
            true,
        ),
        // A seat a participant dialled in for: the room is the engine's, no
        // call is.
        Command::ConferenceJoin {
            conference_id,
            from_tag,
            ..
        } => (
            Some(Recorded::new("conference_join", conference_id, from_tag)),
            Some(NATIVE_ENGINE_ANSWER.to_string()),
            false,
            false,
        ),
        Command::ConferenceLeave {
            conference_id,
            from_tag,
        } => (
            Some(Recorded::new("conference_leave", conference_id, from_tag)),
            None,
            false,
            false,
        ),
        _ => (None, None, false, false),
    }
}

/// The id an accepted `start_recording` is answered with: `rec-<n>`, from the
/// counter the play ids come from.
fn recording_id_for(
    command: &Command,
    refused: bool,
    counter: &std::sync::atomic::AtomicU64,
) -> Option<String> {
    (!refused && matches!(command, Command::StartRecording { .. })).then(|| {
        format!(
            "rec-{}",
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        )
    })
}

/// A recording on a call the engine holds: `detail` is the file it writes.
fn recording_command(command: &Command) -> (Option<Recorded>, Option<String>, bool, bool) {
    match command {
        Command::StartRecording {
            call_id,
            from_tag,
            path,
            channels,
            additional_sources,
            ..
        } => (
            Some(Recorded {
                detail: path.clone(),
                sources: additional_sources
                    .iter()
                    .map(|source| source.call_id.clone())
                    .collect(),
                channels: channels.map(|channels| format!("{channels:?}").to_lowercase()),
                ..Recorded::new("start_recording", call_id, from_tag)
            }),
            None,
            false,
            true,
        ),
        // A tee on a call the engine holds; `detail` is where it streams.
        Command::AttachWsTee {
            call_id,
            from_tag,
            ws_uri,
            channels,
            additional_sources,
            ..
        } => (
            Some(Recorded {
                detail: Some(ws_uri.clone()),
                sources: additional_sources
                    .iter()
                    .map(|source| source.call_id.clone())
                    .collect(),
                channels: channels.map(|channels| channels.to_string()),
                ..Recorded::new("attach_ws_tee", call_id, from_tag)
            }),
            None,
            false,
            true,
        ),
        Command::DetachWsTee { call_id, from_tag } => (
            Some(Recorded::new("detach_ws_tee", call_id, from_tag)),
            None,
            false,
            true,
        ),
        // The engine's own offer for a call whose INVITE carried no SDP.
        Command::OfferLocal { .. } => (
            OfferLocalModel::record(command),
            Some(NATIVE_ENGINE_LOCAL_OFFER.to_string()),
            true,
            false,
        ),
        _ => (None, None, false, false),
    }
}

/// The engine's refusal of a `conference_seat` into a full room: one whose id
/// starts `full-`.
fn seat_refusal(command: &Command) -> Option<String> {
    match command {
        Command::AnswerLocal { sdp, .. } if sdp.contains(NATIVE_ENGINE_REFUSED_OFFER) => {
            Some("answer_local: no stream of the offer can be answered".to_string())
        }
        Command::ConferenceSeat { conference_id, .. } if conference_id.starts_with("full-") => {
            Some(format!(
                "conference_seat: conference {conference_id} is full"
            ))
        }
        _ => None,
    }
}

/// Wait while a test holds the answers of the command's kind: an
/// `answer_local`'s (or `offer_local`'s, or `offer`'s), a `delete`'s, or an
/// `attach_x3`'s.
async fn held_answer(command: &Command, gates: &mut [tokio::sync::watch::Receiver<bool>; 3]) {
    let [answers_open, deletes_open, attaches_open] = gates;
    let gate = match command {
        Command::AnswerLocal { .. } | Command::OfferLocal { .. } | Command::Offer { .. } => {
            answers_open
        }
        Command::Delete { .. } => deletes_open,
        Command::AttachX3 { .. } => attaches_open,
        _ => return,
    };
    let _ = gate.wait_for(|open| *open).await;
}

/// The next request on `stream` and the `scope` its frame carries, or `None`
/// once the client has gone or sent what is not a request.
async fn next_request(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut Vec<u8>,
) -> Option<(Request, Option<String>)> {
    let mut chunk = [0u8; 4096];
    loop {
        match frame::decode::<serde_json::Value>(buffer) {
            Ok(Some((value, consumed))) => {
                buffer.drain(..consumed);
                let scope = value
                    .get("scope")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string);
                return serde_json::from_value::<Request>(value)
                    .ok()
                    .map(|request| (request, scope));
            }
            Ok(None) => {}
            Err(_) => return None,
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
}

/// The `play_id` the engine hands the first playback it accepts; each later one
/// gets the next.
pub(crate) const NATIVE_ENGINE_FIRST_PLAY_ID: u64 = 7001;

/// The engine: its address, and the media commands it has been sent.
pub(crate) struct NativeTestEngine {
    address: SocketAddr,
    commands: Arc<Mutex<Vec<NativeCommand>>>,
    live: LiveCalls,
    x3: Arc<X3Model>,
    split: Arc<SplitModel>,
    offer_local: Arc<OfferLocalModel>,
    /// Gates on the answers of `answer_local`, `delete` and `attach_x3`, in
    /// that order. Open (the default) answers; closed holds every answer until
    /// it opens, so a test can act while a command is provably out: report an
    /// end (a delete is acted on and its answer held), or withdraw a warrant
    /// (the engine holds the delivery of an attach whose answer is held).
    gates: [tokio::sync::watch::Sender<bool>; 3],
}

/// The calls the engine holds, keyed the way the engine keys a call:
/// `(scope, call_id)`.
type LiveCalls = Arc<Mutex<HashSet<(Option<String>, String)>>>;

impl NativeTestEngine {
    /// Start the engine on a loopback port. Serves every connection the client
    /// opens until the test's runtime ends.
    pub(crate) async fn start() -> NativeTestEngine {
        NativeTestEngine::start_with_features(&NATIVE_ENGINE_FEATURES).await
    }

    /// [`NativeTestEngine::start`] for an engine that also lists
    /// `x3_attach_at_offer`: one provisioned for X3 that takes an
    /// interception on a call before its callee answers.
    pub(crate) async fn start_with_x3_at_offer() -> NativeTestEngine {
        let mut features = NATIVE_ENGINE_FEATURES.to_vec();
        features.push(NATIVE_ENGINE_X3_AT_OFFER);
        NativeTestEngine::start_with_features(&features).await
    }

    /// [`NativeTestEngine::start`] for a siphon-rtp 0.25.2 provisioned for
    /// X3: it lists `x3_attach_at_offer`, `x3_conference_seat` and
    /// `x3_single_leg`.
    pub(crate) async fn start_with_x3() -> NativeTestEngine {
        let mut features = NATIVE_ENGINE_FEATURES.to_vec();
        features.extend([
            NATIVE_ENGINE_X3_AT_OFFER,
            NATIVE_ENGINE_X3_CONFERENCE_SEAT,
            NATIVE_ENGINE_X3_SINGLE_LEG,
        ]);
        NativeTestEngine::start_with_features(&features).await
    }

    /// [`NativeTestEngine::start`] for a siphon-rtp 0.26.0 provisioned for
    /// X3: what 0.25.2 lists, and `x3_multi_delivery` and `x3_ws_takeover`.
    pub(crate) async fn start_with_x3_026() -> NativeTestEngine {
        let mut features = NATIVE_ENGINE_FEATURES.to_vec();
        features.extend([
            NATIVE_ENGINE_X3_AT_OFFER,
            NATIVE_ENGINE_X3_CONFERENCE_SEAT,
            NATIVE_ENGINE_X3_SINGLE_LEG,
            NATIVE_ENGINE_X3_MULTI_DELIVERY,
            NATIVE_ENGINE_X3_WS_TAKEOVER,
        ]);
        NativeTestEngine::start_with_features(&features).await
    }

    /// [`NativeTestEngine::start`] for a siphon-rtp 0.29.0, which lists
    /// `ws_split`: it takes `attach_ws_split` / `detach_ws_split` on a call it
    /// holds and keeps the events it would have sent
    /// ([`NativeTestEngine::take_split_events`]).
    pub(crate) async fn start_with_ws_split() -> NativeTestEngine {
        let mut features = NATIVE_ENGINE_FEATURES.to_vec();
        features.push(NATIVE_ENGINE_WS_SPLIT);
        NativeTestEngine::start_with_features(&features).await
    }

    /// [`NativeTestEngine::start`] for a siphon-rtp 0.30.0, which lists
    /// `offer_local`: it makes its own offer for a call whose INVITE carried
    /// no SDP and waits for the caller's answer.
    pub(crate) async fn start_with_offer_local() -> NativeTestEngine {
        let mut features = NATIVE_ENGINE_FEATURES.to_vec();
        features.push(NATIVE_ENGINE_OFFER_LOCAL);
        NativeTestEngine::start_with_features(&features).await
    }

    /// [`NativeTestEngine::start`] for an engine whose `node_info` lists
    /// `features`: one from before a verb leaves the verb's feature out.
    pub(crate) async fn start_with_features(features: &[&str]) -> NativeTestEngine {
        let features: Vec<String> = features.iter().map(|feature| feature.to_string()).collect();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let address = listener.local_addr().expect("the listener's address");
        let commands = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&commands);
        let live: LiveCalls = Arc::new(Mutex::new(HashSet::new()));
        let held = Arc::clone(&live);
        // The calls `offer_far` grew a far leg on, which `answer` completes
        // with the caller's own answer and a `delete` with a `to_tag` drops.
        let grown: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        // The calls `answer_local` created: the engine is their far side.
        let local: LiveCalls = Arc::new(Mutex::new(HashSet::new()));
        let x3 = Arc::new(X3Model::listing(&features));
        let x3_model = Arc::clone(&x3);
        let split = Arc::new(SplitModel::default());
        let split_model = Arc::clone(&split);
        let offer_local = Arc::new(OfferLocalModel::default());
        let offer_local_model = Arc::clone(&offer_local);
        let (answers, answers_open) = tokio::sync::watch::channel(true);
        let (deletes, deletes_open) = tokio::sync::watch::channel(true);
        let (attaches, attaches_open) = tokio::sync::watch::channel(true);
        let next_play_id = Arc::new(std::sync::atomic::AtomicU64::new(
            NATIVE_ENGINE_FIRST_PLAY_ID,
        ));
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let features = features.clone();
                let recorded = Arc::clone(&recorded);
                let held = Arc::clone(&held);
                let grown = Arc::clone(&grown);
                let local = Arc::clone(&local);
                let x3 = Arc::clone(&x3_model);
                let split = Arc::clone(&split_model);
                let offer_local = Arc::clone(&offer_local_model);
                let next_play_id = Arc::clone(&next_play_id);
                let mut gates = [
                    answers_open.clone(),
                    deletes_open.clone(),
                    attaches_open.clone(),
                ];
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    loop {
                        let request = next_request(&mut stream, &mut buffer).await;
                        let Some((request, scope)) = request else {
                            return;
                        };
                        // An engine that keys calls by scope says so.
                        if matches!(request.command, Command::NodeInfo) {
                            let node_info = node_info_answer(request.id, &features);
                            let Ok(bytes) = frame::encode(&node_info) else {
                                return;
                            };
                            if stream.write_all(&bytes).await.is_err() {
                                return;
                            }
                            continue;
                        }
                        let mut play_id = None;
                        // What the command is, what SDP an accepted one answers
                        // with, and what it does to the calls the engine holds.
                        let grown_call = grown_call_command(&request.command, &grown);
                        let refusal = grown_call
                            .as_ref()
                            .and_then(|grown| grown.refusal.clone())
                            .or_else(|| seat_refusal(&request.command))
                            .or_else(|| x3.refusal(&request.command, &scope, &local, &grown))
                            .or_else(|| split.refusal(&request.command, &scope))
                            .or_else(|| offer_local.refusal(&request.command, &scope));
                        let on_seat = x3.names_seat(&request.command);
                        if let Ok(mut local) = local.lock() {
                            match &request.command {
                                Command::AnswerLocal { call_id, .. }
                                | Command::OfferLocal { call_id, .. } => {
                                    local.insert((scope.clone(), call_id.clone()));
                                }
                                Command::Offer { call_id, .. }
                                | Command::Delete { call_id, .. } => {
                                    local.remove(&(scope.clone(), call_id.clone()));
                                }
                                _ => {}
                            }
                        }
                        let (record, sdp, creates, needs_call) = match &request.command {
                            _ if grown_call.is_some() => grown_call
                                .map(|grown| (Some(grown.record), grown.sdp, false, true))
                                .unwrap_or((None, None, false, false)),
                            Command::AnswerLocal {
                                call_id,
                                from_tag,
                                profile,
                                sdp,
                            } => (
                                Some(Recorded {
                                    profile: Some(profile.clone()),
                                    detail: Some(sdp.clone()),
                                    ..Recorded::new("answer_local", call_id, from_tag)
                                }),
                                Some(NATIVE_ENGINE_ANSWER.to_string()),
                                true,
                                false,
                            ),
                            Command::Delete {
                                call_id, from_tag, ..
                            } => (
                                Some(Recorded::new("delete", call_id, from_tag)),
                                None,
                                false,
                                true,
                            ),
                            Command::Offer {
                                call_id,
                                from_tag,
                                profile,
                                sdp,
                            } => (
                                Some(Recorded {
                                    profile: Some(profile.clone()),
                                    ..Recorded::new("offer", call_id, from_tag)
                                }),
                                Some(native_engine_sdp(
                                    NATIVE_ENGINE_OFFER,
                                    "52000",
                                    profile.transport_protocol.as_deref(),
                                    sdp,
                                )),
                                true,
                                false,
                            ),
                            Command::Answer {
                                call_id,
                                from_tag,
                                to_tag,
                                profile,
                                sdp,
                            } => (
                                Some(Recorded {
                                    profile: Some(profile.clone()),
                                    detail: Some(to_tag.clone()),
                                    ..Recorded::new("answer", call_id, from_tag)
                                }),
                                Some(native_engine_sdp(
                                    NATIVE_ENGINE_ANSWER,
                                    "51000",
                                    profile.transport_protocol.as_deref(),
                                    sdp,
                                )),
                                false,
                                true,
                            ),
                            Command::Reoffer {
                                call_id,
                                from_tag,
                                profile,
                                sdp,
                            } => (
                                Some(Recorded {
                                    profile: Some(profile.clone()),
                                    ..Recorded::new("reoffer", call_id, from_tag)
                                }),
                                Some(native_engine_sdp(
                                    NATIVE_ENGINE_OFFER,
                                    "52000",
                                    profile.transport_protocol.as_deref(),
                                    sdp,
                                )),
                                false,
                                true,
                            ),
                            Command::PlayMedia {
                                call_id,
                                from_tag,
                                source,
                                repeat_times,
                                ..
                            } => {
                                // As serialised, which is what the engine reads.
                                let repeat = repeat_times.and_then(|repeat| {
                                    serde_json::to_value(repeat).ok().map(|value| {
                                        value
                                            .as_str()
                                            .map(str::to_string)
                                            .unwrap_or_else(|| value.to_string())
                                    })
                                });
                                let tone = match source {
                                    siphon_rtp_proto::PlayMediaSource::Tone { tone } => {
                                        Some(tone.clone())
                                    }
                                    _ => None,
                                };
                                (
                                    Some(Recorded {
                                        detail: tone,
                                        repeat,
                                        ..Recorded::new("play_media", call_id, from_tag)
                                    }),
                                    None,
                                    false,
                                    true,
                                )
                            }
                            Command::StopMedia {
                                call_id,
                                from_tag,
                                play_id,
                            } => (
                                Some(Recorded {
                                    detail: play_id.map(|play_id| play_id.to_string()),
                                    ..Recorded::new("stop_media", call_id, from_tag)
                                }),
                                None,
                                false,
                                true,
                            ),
                            Command::AttachX3 { .. }
                            | Command::DetachX3 { .. }
                            | Command::Echo { .. } => x3_command(&request.command, on_seat),
                            Command::ConferenceSeat { .. }
                            | Command::ConferenceJoin { .. }
                            | Command::ConferenceLeave { .. } => seat_command(&request.command),
                            // A split on a call the engine holds.
                            Command::AttachWsSplit(_) | Command::DetachWsSplit(_) => {
                                (SplitModel::record(&request.command), None, false, true)
                            }
                            // A recording or a tee, or nothing the engine records.
                            _ => recording_command(&request.command),
                        };
                        let mut refused = false;
                        if let (Some(record), Ok(mut live)) = (record.as_ref(), held.lock()) {
                            let key = (scope.clone(), record.call_id.clone());
                            if needs_call && !live.contains(&key) {
                                refused = true;
                            } else if creates {
                                live.insert(key);
                            } else if record.name == "delete" && refusal.is_none() {
                                live.remove(&key);
                            }
                        }
                        if !refused && matches!(request.command, Command::PlayMedia { .. }) {
                            play_id = Some(
                                next_play_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                            );
                        }
                        let recording_id =
                            recording_id_for(&request.command, refused, &next_play_id);
                        if !refused && refusal.is_none() {
                            x3.accepted(&request.command, &scope);
                            split.accepted(&request.command, &scope);
                            offer_local.accepted(&request.command, &scope);
                        }
                        let unknown_call = record
                            .as_ref()
                            .map(|record| format!("unknown call: {}", record.call_id));
                        if let Some(record) = record {
                            if let Ok(mut log) = recorded.lock() {
                                log.push(record.logged(refused, scope.clone()));
                            }
                        }
                        let result = match request.command {
                            Command::Ping => CmdResult::Pong,
                            _ if refused => CmdResult::Error {
                                reason: unknown_call.unwrap_or_default(),
                            },
                            _ if refusal.is_some() => CmdResult::Error {
                                reason: refusal.clone().unwrap_or_default(),
                            },
                            _ => CmdResult::Ok {
                                sdp,
                                duration_ms: None,
                                play_id,
                                recording_id,
                                to_tag: None,
                                stats: None,
                                streams: Vec::new(),
                                video_declined: None,
                            },
                        };
                        held_answer(&request.command, &mut gates).await;
                        let Ok(bytes) = frame::encode(&Response {
                            id: request.id,
                            result,
                        }) else {
                            return;
                        };
                        if stream.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        NativeTestEngine {
            address,
            commands,
            live,
            x3,
            split,
            offer_local,
            gates: [answers, deletes, attaches],
        }
    }

    /// The `x3_ended` the engine would have sent since this was last asked,
    /// oldest first: one for each delivery a detach, a replacing attach, a
    /// `delete`, a replacing `offer` or a seat leaving ended.
    pub(crate) fn take_x3_ends(&self) -> Vec<crate::rtpengine::events::RtpEngineEvent> {
        self.x3
            .ends
            .lock()
            .map(|mut ends| std::mem::take(&mut *ends))
            .unwrap_or_default()
            .into_iter()
            .map(crate::rtpengine::events::RtpEngineEvent::X3Ended)
            .collect()
    }

    /// The `ws_split_started` and `ws_split_ended` the engine would have sent
    /// since this was last asked, oldest first.
    pub(crate) fn take_split_events(&self) -> Vec<crate::rtpengine::events::RtpEngineEvent> {
        self.split.take_events()
    }

    /// End the split on the unscoped `call_id` as the engine would on its own
    /// (`reason`: the bot closed the socket, a failure): reported once, and the
    /// call stays isolated until a detach.
    pub(crate) fn end_split(&self, call_id: &str, reason: siphon_rtp_proto::WsSplitEndReason) {
        self.split.end(&None, call_id, reason);
    }

    /// Refuse the next `attach_ws_split` with `token`
    /// (`ws-split-renegotiation`, ...).
    pub(crate) fn refuse_next_split(&self, token: &str) {
        self.split.refuse_next(token);
    }

    /// How many calls made by `offer_local` still wait for their answer.
    pub(crate) fn offer_local_pending_count(&self) -> usize {
        self.offer_local.pending_calls()
    }

    /// How many calls the engine holds isolated by a split.
    pub(crate) fn split_count(&self) -> usize {
        self.split.count()
    }

    /// How many content deliveries the engine holds.
    pub(crate) fn x3_delivery_count(&self) -> usize {
        self.x3
            .deliveries
            .lock()
            .map(|deliveries| deliveries.len())
            .unwrap_or(0)
    }

    /// Hold every `delete` answer until [`release_deletes`](Self::release_deletes).
    pub(crate) fn hold_deletes(&self) {
        self.gates[1].send_replace(false);
    }

    /// Answer the held `delete`s, and every one after.
    pub(crate) fn release_deletes(&self) {
        self.gates[1].send_replace(true);
    }

    /// Hold every `attach_x3` answer until [`release_attaches`](Self::release_attaches).
    pub(crate) fn hold_attaches(&self) {
        self.gates[2].send_replace(false);
    }

    /// Answer the held `attach_x3`s, and every one after.
    pub(crate) fn release_attaches(&self) {
        self.gates[2].send_replace(true);
    }

    /// Refuse the next `delete`, `conference_leave` or `detach_x3` (`verb`), leaving the
    /// call or the seat as it is.
    pub(crate) fn refuse_next(&self, verb: &'static str) {
        if let Ok(mut verbs) = self.x3.refuse_next.lock() {
            verbs.push(verb);
        }
    }

    /// Refuse the next `count` `attach_x3` as a call being re-answered is:
    /// with a reason that says to ask again.
    pub(crate) fn refuse_attaches_for_now(&self, count: u32) {
        if let Ok(mut left) = self.x3.retry_refusals.lock() {
            *left = count;
        }
    }

    /// Hold every `answer_local` answer until [`release_answers`](Self::release_answers).
    pub(crate) fn hold_answers(&self) {
        self.gates[0].send_replace(false);
    }

    /// Answer the held `answer_local`s, and every one after.
    pub(crate) fn release_answers(&self) {
        self.gates[0].send_replace(true);
    }

    /// Whether the engine holds the unscoped `call_id`: created and not
    /// deleted.
    pub(crate) fn holds(&self, call_id: &str) -> bool {
        self.holds_in(None, call_id)
    }

    /// Whether the engine holds `call_id` under `scope`.
    pub(crate) fn holds_in(&self, scope: Option<&str>, call_id: &str) -> bool {
        self.live
            .lock()
            .map(|live| live.contains(&(scope.map(str::to_string), call_id.to_string())))
            .unwrap_or(false)
    }

    /// The engine's control address.
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// Hold the unscoped `call_id` as if an `offer` had created it: a call a
    /// test builds without dialling it.
    pub(crate) fn admit(&self, call_id: &str) {
        if let Ok(mut live) = self.live.lock() {
            live.insert((None, call_id.to_string()));
        }
    }

    /// How many calls the engine holds.
    pub(crate) fn held_count(&self) -> usize {
        self.live.lock().map(|live| live.len()).unwrap_or(0)
    }

    /// A media backend that sends its commands to this engine.
    pub(crate) fn backend(&self) -> Arc<MediaBackend> {
        let (event_tx, _event_rx) = tokio::sync::mpsc::channel(16);
        let set =
            super::SiphonRtpClientSet::new(vec![(self.address, 2000, 1)], None, 5_000, event_tx)
                .expect("a native engine set");
        Arc::new(MediaBackend::SiphonRtp(set))
    }

    /// Every command the engine has been sent so far, in order.
    pub(crate) fn all_commands(&self) -> Vec<NativeCommand> {
        self.commands
            .lock()
            .map(|log| log.clone())
            .unwrap_or_default()
    }

    /// Every command of kind `name` the engine has been sent so far, in order.
    pub(crate) fn commands(&self, name: &str) -> Vec<NativeCommand> {
        self.commands
            .lock()
            .map(|log| {
                log.iter()
                    .filter(|command| command.name == name)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}
