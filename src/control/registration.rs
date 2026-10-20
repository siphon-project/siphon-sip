//! Registration state on the control plane.
//!
//! Two application-level event classes carry it: `registration`
//! (`RegistrationChanged`, the bindings siphon's registrar holds) and
//! `outbound_registration` (`RegistrantChanged`, the REGISTERs siphon sends to
//! upstream registrars). Each event is numbered by a per-process, per-class
//! `seq` that rises by one per event published, and two substrate verbs,
//! `registrations` and `outbound_registrations`, answer with everything held
//! now and the `seq` it is current to.
//!
//! That pair is how a controller stays whole. Events can be lost: a
//! connection's queue drops its oldest event when it overflows, siphon's own
//! registration task can fall behind the registrar (the `seq` jumps by the
//! number of events it lost), and a controller that restarts misses whatever
//! happened while it was away. Every loss shows as a gap in `seq`; on a gap,
//! or on connecting, the controller asks for the state, replaces its copy with
//! the reply (which also drops the AoRs that went away), and applies only the
//! events numbered above the reply's `seq`.
//!
//! The replies are paged in AoR order (`after`, `limit`, `next`), since one
//! frame past the client's frame limit would close the connection; a
//! controller keeps the first page's `seq`.
//!
//! Why a verb and not a burst of snapshot events on connect: a reply is one
//! frame that is never dropped, where a registrar's worth of events would land
//! on a bounded queue that drops the oldest — the snapshot would lose itself on
//! exactly the deployments big enough to need it. And a complete set tells the
//! controller which AoRs are gone, which per-AoR events cannot.
//!
//! The ordering that makes "apply what is above the reply's `seq`" correct:
//! an event takes its number before it reads the state it reports, and the
//! verb reads the number before it reads the state. So a change the reply does
//! not show was reported by an event numbered above the reply's `seq`.

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

use crate::registrant::RegistrantManager;
use crate::registrar::{Contact, Registrar};

use super::{ControlBus, ControlErrorCode, ControlResult};

/// The event class of the bindings siphon's registrar holds.
pub const REGISTRATION_CLASS: &str = "registration";
/// The event class of the registrations siphon itself sends upstream.
pub const OUTBOUND_REGISTRATION_CLASS: &str = "outbound_registration";

/// The AoRs one reply page carries when the app names no `limit`.
pub const DEFAULT_PAGE_LIMIT: usize = 500;
/// The most AoRs one reply page carries. A page is one WebSocket frame, and a
/// frame past the client's limit (16 MiB in the Rust SDK) kills the
/// connection: 1000 AoRs of ten bindings each stay well inside it.
pub const MAX_PAGE_LIMIT: usize = 1000;

/// The last `seq` a `RegistrationChanged` was published with.
static REGISTRATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);
/// The last `seq` a `RegistrantChanged` was published with.
static REGISTRANT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// One binding as the control plane reports it.
///
/// `received` is the script's `Contact.received`, byte for byte: where the
/// REGISTER came from, which is what an INVITE from the same phone is matched
/// against (the Contact may name a private address behind NAT). `transport` is
/// the transport it arrived on, `client_transport` the one the client used to
/// reach a front that declared a different one (PROXY protocol), absent
/// otherwise. `call_id` and `cseq` are those of the REGISTER that last wrote
/// the binding.
pub fn contact_payload(contact: &Contact) -> Value {
    let mut payload = json!({
        "uri": contact.uri.to_string(),
        "expires": contact.remaining_seconds(),
        "q": contact.q,
        "received": contact.received_uri(),
        "transport": contact.source_transport.map(|transport| transport.as_scheme()),
        "instance": contact.sip_instance.as_deref(),
        "reg_id": contact.reg_id,
        "path": contact.path.iter().map(|hop| hop.as_ref()).collect::<Vec<&str>>(),
        "call_id": contact.call_id.as_ref(),
        "cseq": contact.cseq,
    });
    if let Some(client_transport) = contact
        .client_transport
        .filter(|client| Some(*client) != contact.source_transport)
    {
        payload["client_transport"] = json!(client_transport.as_scheme());
    }
    payload
}

/// The bindings `aor` holds now, as [`contact_payload`]s.
fn contacts_of(registrar: &Registrar, aor: &str) -> Vec<Value> {
    registrar.lookup(aor).iter().map(contact_payload).collect()
}

/// Publish a `RegistrationChanged` for `aor` to every app subscribed to
/// [`REGISTRATION_CLASS`]: `event` is what happened (`snapshot` for a re-report
/// after siphon's event task fell behind), and the contacts are read now.
///
/// `seq` is the change's number from [`next_registration_sequence`], taken
/// before the contacts are read (see the module notes) and handed to the
/// script's `@registrar.on_change` too, so the rail and the script agree.
pub fn publish_registration_change(registrar: &Registrar, aor: &str, event: &str, seq: u64) {
    if !super::app_event_wanted(REGISTRATION_CLASS) {
        return;
    }
    super::notify_app_event(
        REGISTRATION_CLASS,
        "RegistrationChanged",
        json!({
            "seq": seq,
            "instance_epoch": instance_epoch(),
            "aor": aor,
            "event": event,
            "contacts": contacts_of(registrar, aor),
        }),
    );
}

/// Number the next registration change (a `RegistrationChanged` and the
/// matching `@registrar.on_change` call): one higher than the last.
pub fn next_registration_sequence() -> u64 {
    REGISTRATION_SEQUENCE.fetch_add(1, Ordering::SeqCst) + 1
}

/// Number the next outbound-registration change (a `RegistrantChanged` and
/// the matching `@registration.on_change` call).
pub fn next_registrant_sequence() -> u64 {
    REGISTRANT_SEQUENCE.fetch_add(1, Ordering::SeqCst) + 1
}

/// This process's boot epoch: the `instance_epoch` stamped on the bindings it
/// accepts, fresh at every start. `seq` restarts with the process, so a
/// controller that sees the epoch change knows the numbers began again and
/// resyncs. An identifier, not an order: it says the process restarted, not
/// which of two epochs is newer. `None` when no registrar identity is set.
pub fn instance_epoch() -> Option<String> {
    crate::script::api::registrar_arc().and_then(|registrar| registrar.instance_epoch())
}

/// Account for `skipped` registration events siphon's own event task lost: the
/// next `RegistrationChanged` is numbered past them, so a controller sees the
/// gap.
pub fn skip_registration_events(skipped: u64) {
    REGISTRATION_SEQUENCE.fetch_add(skipped, Ordering::SeqCst);
}

/// Collects one page: the first `limit` keys past `after` in order, and the
/// key that asks for the next page.
///
/// Paged in key order rather than by offset, so an AoR that registers or goes
/// between two pages moves no other AoR from one page to the next. Each page
/// walks the whole key set, so it keeps only the `limit + 1` smallest it has
/// seen in a heap rather than copying and sorting every key: a registrar of a
/// million AoRs is read a page at a time without a million-string copy each.
struct PageCollector<'a> {
    after: Option<&'a str>,
    limit: usize,
    smallest: std::collections::BinaryHeap<String>,
}

impl<'a> PageCollector<'a> {
    fn new(after: Option<&'a str>, limit: usize) -> Self {
        Self {
            after,
            limit,
            smallest: std::collections::BinaryHeap::with_capacity(limit + 1),
        }
    }

    fn offer(&mut self, key: &str) {
        if self.after.is_some_and(|after| key <= after) {
            return;
        }
        // One past the limit is kept, which is how the page knows more follow.
        if self.smallest.len() <= self.limit {
            self.smallest.push(key.to_string());
        } else if self
            .smallest
            .peek()
            .is_some_and(|largest| key < largest.as_str())
        {
            self.smallest.pop();
            self.smallest.push(key.to_string());
        }
    }

    /// The page's keys in order, and the `next` that asks for the one after
    /// (`None` when this is the last).
    fn finish(self) -> (Vec<String>, Option<String>) {
        let more = self.smallest.len() > self.limit;
        let mut keys = self.smallest.into_sorted_vec();
        keys.truncate(self.limit);
        let next = if more { keys.last().cloned() } else { None };
        (keys, next)
    }
}

/// One page of `keys`, for a key set already in hand.
fn page(keys: Vec<String>, after: Option<&str>, limit: usize) -> (Vec<String>, Option<String>) {
    let mut collector = PageCollector::new(after, limit);
    for key in &keys {
        collector.offer(key);
    }
    collector.finish()
}

/// A page of registered AoRs with their contacts, and the `seq` the set is
/// current to (the `registrations` reply). Across pages a controller keeps the
/// first page's `seq`: every change after it is in an event numbered above it.
pub fn registrations_reply(registrar: &Registrar, after: Option<&str>, limit: usize) -> Value {
    // Read before the state: see the module notes.
    let seq = REGISTRATION_SEQUENCE.load(Ordering::SeqCst);
    let mut collector = PageCollector::new(after, limit);
    registrar.visit_registered_aors(|aor| collector.offer(aor));
    let (aors, next) = collector.finish();
    let registrations: Vec<Value> = aors
        .into_iter()
        .filter_map(|aor| {
            let contacts = contacts_of(registrar, &aor);
            // Expired between the two reads: not registered any more.
            (!contacts.is_empty()).then(|| json!({ "aor": aor, "contacts": contacts }))
        })
        .collect();
    json!({
        "seq": seq,
        "instance_epoch": instance_epoch(),
        "registrations": registrations,
        "next": next,
    })
}

/// One outbound registration's current state. `status_code` is the status of
/// the last failed attempt (the one that failed it, on a `failed` event),
/// `null` once an attempt succeeded; everything is `null` or `0` for a
/// registration that has been removed.
fn registrant_state(registrant: &RegistrantManager, aor: &str, status_code: Option<u16>) -> Value {
    let status = registrant.status(aor);
    json!({
        "aor": aor,
        "registrar": status.as_ref().map(|status| status.registrar_uri.clone()),
        "state": status.as_ref().map(|status| status.state.to_string()),
        "expires_in": status.as_ref().map_or(0, |status| status.expires_in),
        "failure_count": status.as_ref().map_or(0, |status| status.failure_count),
        "status_code": status_code
            .or_else(|| status.as_ref().and_then(|status| status.last_failure_status)),
    })
}

/// Publish a `RegistrantChanged` for `aor` to every app subscribed to
/// [`OUTBOUND_REGISTRATION_CLASS`]. `status_code` is the status a `failed`
/// event carries; `seq` comes from [`next_registrant_sequence`].
pub fn publish_registrant_change(
    registrant: &RegistrantManager,
    aor: &str,
    event: &str,
    status_code: Option<u16>,
    seq: u64,
) {
    if !super::app_event_wanted(OUTBOUND_REGISTRATION_CLASS) {
        return;
    }
    let mut payload = registrant_state(registrant, aor, status_code);
    payload["seq"] = json!(seq);
    payload["instance_epoch"] = json!(instance_epoch());
    payload["event"] = json!(event);
    super::notify_app_event(OUTBOUND_REGISTRATION_CLASS, "RegistrantChanged", payload);
}

/// Account for `skipped` registrant events siphon's own event task lost.
pub fn skip_registrant_events(skipped: u64) {
    REGISTRANT_SEQUENCE.fetch_add(skipped, Ordering::SeqCst);
}

/// A page of outbound registrations, and the `seq` it is current to (the
/// `outbound_registrations` reply), paged like [`registrations_reply`].
pub fn outbound_registrations_reply(
    registrant: &RegistrantManager,
    after: Option<&str>,
    limit: usize,
) -> Value {
    let seq = REGISTRANT_SEQUENCE.load(Ordering::SeqCst);
    let aors: Vec<String> = registrant
        .list()
        .into_iter()
        .map(|(aor, _, _)| aor)
        .collect();
    let (aors, next) = page(aors, after, limit);
    let registrations: Vec<Value> = aors
        .iter()
        .filter(|aor| registrant.status(aor).is_some())
        .map(|aor| registrant_state(registrant, aor, None))
        .collect();
    json!({
        "seq": seq,
        "instance_epoch": instance_epoch(),
        "registrations": registrations,
        "next": next,
    })
}

/// The `after` and `limit` a state verb was given.
fn page_args(verb: &str, args: &Value) -> Result<(Option<String>, usize), ControlResult> {
    let after = match args.get("after") {
        None | Some(Value::Null) => None,
        Some(Value::String(after)) => Some(after.clone()),
        Some(_) => {
            return Err(ControlResult::error(
                ControlErrorCode::BadRequest,
                format!("{verb}: after must be the next of the previous page, a string"),
            ));
        }
    };
    let limit = match args.get("limit") {
        None | Some(Value::Null) => DEFAULT_PAGE_LIMIT,
        Some(limit) => match limit.as_u64() {
            Some(limit) if (1..=MAX_PAGE_LIMIT as u64).contains(&limit) => limit as usize,
            _ => {
                return Err(ControlResult::error(
                    ControlErrorCode::BadRequest,
                    format!("{verb}: limit must be a whole number from 1 to {MAX_PAGE_LIMIT}"),
                ));
            }
        },
    };
    Ok((after, limit))
}

/// Answer `registrations` / `outbound_registrations` for `app`.
///
/// Only an app subscribed to the class may read it (`forbidden` otherwise): the
/// state names every phone's source address, and the subscription is the
/// operator's say-so that this app is to see it.
pub(super) fn state_verb(bus: &ControlBus, app: &str, verb: &str, args: &Value) -> ControlResult {
    let class = match verb {
        "registrations" => REGISTRATION_CLASS,
        _ => OUTBOUND_REGISTRATION_CLASS,
    };
    let subscribed = bus
        .app_config(app)
        .is_some_and(|config| config.events.iter().any(|wanted| wanted == class));
    if !subscribed {
        return ControlResult::error(
            ControlErrorCode::Forbidden,
            format!(
                "{verb} needs the app to subscribe to the {class:?} event class \
                 (control.apps[].events)"
            ),
        );
    }
    let (after, limit) = match page_args(verb, args) {
        Ok(page) => page,
        Err(refusal) => return refusal,
    };
    if class == REGISTRATION_CLASS {
        match crate::script::api::registrar_arc() {
            Some(registrar) => {
                ControlResult::Ok(registrations_reply(registrar, after.as_deref(), limit))
            }
            None => ControlResult::error(ControlErrorCode::Unavailable, "no registrar is running"),
        }
    } else {
        match crate::registrant::manager() {
            Some(registrant) => ControlResult::Ok(outbound_registrations_reply(
                registrant,
                after.as_deref(),
                limit,
            )),
            None => ControlResult::error(
                ControlErrorCode::Unavailable,
                "outbound registration is not configured (registrant:)",
            ),
        }
    }
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod tests;
