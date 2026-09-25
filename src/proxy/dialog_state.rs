//! RFC 4235 dialog state of registered AoRs for INVITEs the proxy relays.
//!
//! A B2BUA is a party to its dialogs and ends them itself; a proxy is not, so
//! this store follows each proxied dialog from what passes through siphon:
//!
//! - the INVITE and each branch it is relayed on, per branch, so a fork shows
//!   every callee ringing;
//! - the responses on each branch (`early` per tagged provisional,
//!   `confirmed` on a 2xx, `terminated` on a final failure), and what goes back
//!   to the caller;
//! - the losing branches siphon CANCELs when one answers, and the caller's
//!   own CANCEL;
//! - a BYE in either direction, which reaches siphon because siphon
//!   Record-Routes every INVITE it tracks (RFC 3261 §16.6 step 4, and §12.2
//!   obliges the UAs to honour the route set).
//!
//! Keyed by the dialog (Call-ID and the caller's tag, then the callee's tag
//! once answered), not by transaction entries, which retire on Timer I.
//!
//! What a BYE cannot be relied on for, the liveness checks in [`ProxyDialogStore::sweep`]
//! cover: a vouching binding that is gone, an RFC 4028 session interval that
//! ran out, an in-dialog OPTIONS probe that finds the dialog gone at an end,
//! the Timer C bound on ringing, and a hard lifetime. None of them tears the
//! call down; only the reported state ends.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::b2bua::actor::{DialogState, DialogWatch};
use crate::config::DialogStateConfig;
use crate::transport::{ConnectionId, Transport};

/// Where siphon reaches one end of a proxied dialog: the next hop toward it,
/// which is where the INVITE came from (the caller's side) or went to (the
/// callee's side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hop {
    pub destination: SocketAddr,
    pub transport: Transport,
    /// A captured connection to write on, or the default for "by address".
    pub connection_id: ConnectionId,
    /// The listener to send from, when the hop is pinned to one.
    pub local_addr: Option<SocketAddr>,
}

/// One end of a proxied dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    Caller,
    Callee,
}

impl End {
    fn index(self) -> usize {
        match self {
            End::Caller => 0,
            End::Callee => 1,
        }
    }
}

/// `(Call-ID, the caller's From-tag)`: an INVITE's dialog before any callee
/// has tagged it.
pub type DialogKey = (String, String);

/// Everything the INVITE says about the caller's side.
#[derive(Debug, Clone)]
pub struct NewDialog {
    pub call_id: String,
    pub caller_tag: String,
    /// The caller's watch, when the caller is a registered phone.
    pub caller: Option<DialogWatch>,
    pub caller_hop: Hop,
    /// The caller's remote target (its Contact).
    pub caller_contact: Option<String>,
    /// The INVITE's From, with the caller's tag.
    pub from: String,
    /// The INVITE's To, untagged.
    pub to: String,
    /// The INVITE's CSeq number.
    pub invite_cseq: u32,
    /// The Record-Route entries the INVITE arrived with, in order: the proxies
    /// between the caller and siphon, nearest siphon first — the route from
    /// siphon back to the caller.
    pub route_to_caller: Vec<String>,
}

/// A branch the INVITE is relayed on.
#[derive(Debug, Clone)]
pub struct NewBranch {
    /// The Via branch siphon stamped on it.
    pub via_branch: String,
    /// The callee's watch, when the branch rings a registered phone.
    pub watch: Option<DialogWatch>,
    pub hop: Hop,
    /// How many Record-Route entries siphon added to it (one per socket).
    pub own_record_routes: usize,
}

/// What a 2xx establishing the dialog carries.
#[derive(Debug, Clone, Default)]
pub struct Answer {
    /// The callee's remote target (the 2xx Contact).
    pub contact: Option<String>,
    /// The 2xx Record-Route entries, flattened, in order.
    pub record_routes: Vec<String>,
    /// The negotiated session interval (RFC 4028 `Session-Expires`).
    pub session_expires: Option<u64>,
}

/// An in-dialog OPTIONS siphon owes one end of a dialog (RFC 3261 §11): the
/// request-line and headers of a request from the *other* end, so the end
/// probed matches it to its dialog and answers `481` if it has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub key: DialogKey,
    pub end: End,
    pub request_uri: String,
    pub route: Vec<String>,
    pub from: String,
    pub to: String,
    pub call_id: String,
    /// The last CSeq the probed end received from the other end in this
    /// dialog, or `0` when it received none. Reusing it, rather than going one
    /// higher, keeps the probe from advancing the probed end's view of the
    /// other end's CSeq space, which the other end's next real request would
    /// then fall below (RFC 3261 §12.2.2 answers that with `500`).
    pub cseq: u32,
    pub hop: Hop,
}

/// What a probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The end answered with anything but `481` / `408`: its dialog exists.
    Alive,
    /// `481`: the end has no such dialog.
    Gone,
    /// `408` or no answer at all.
    Unanswered,
}

#[derive(Debug, Clone)]
struct Branch {
    via_branch: String,
    watch: Option<DialogWatch>,
    ended: bool,
    hop: Hop,
    own_record_routes: usize,
}

#[derive(Debug, Clone)]
struct Confirmed {
    callee_tag: String,
    branch: usize,
    callee_contact: Option<String>,
    route_to_callee: Vec<String>,
    session_expires: Option<Duration>,
    refreshed_at: Instant,
    /// The last CSeq the callee received from the caller.
    last_cseq_from_caller: u32,
    /// The last CSeq the caller received from the callee.
    last_cseq_from_callee: Option<u32>,
    next_probe_at: Instant,
    failures: [u32; 2],
    in_flight: [bool; 2],
}

#[derive(Debug, Clone)]
struct Dialog {
    created_at: Instant,
    caller: Option<DialogWatch>,
    caller_hop: Hop,
    caller_contact: Option<String>,
    from: String,
    to: String,
    invite_cseq: u32,
    route_to_caller: Vec<String>,
    branches: Vec<Branch>,
    confirmed: Option<Confirmed>,
}

impl Dialog {
    fn callee_watch_mut(&mut self) -> Option<&mut DialogWatch> {
        let index = self.confirmed.as_ref()?.branch;
        self.branches.get_mut(index)?.watch.as_mut()
    }

    fn watch_mut(&mut self, end: End) -> Option<&mut DialogWatch> {
        match end {
            End::Caller => self.caller.as_mut(),
            End::Callee => self.callee_watch_mut(),
        }
    }

    /// Whether any watch on this dialog can still change.
    fn has_live_watch(&self) -> bool {
        let live = |watch: &Option<DialogWatch>| {
            watch
                .as_ref()
                .is_some_and(|watch| watch.state != DialogState::Terminated)
        };
        live(&self.caller) || self.branches.iter().any(|branch| live(&branch.watch))
    }

    /// End every watch on this dialog.
    fn end_all(&mut self) -> Vec<DialogWatch> {
        let mut reports = Vec::new();
        reports.extend(end(&mut self.caller));
        for branch in &mut self.branches {
            branch.ended = true;
            reports.extend(end(&mut branch.watch));
        }
        reports
    }
}

/// Move `watch` to `state`, returning the report when it moved.
fn advance(
    watch: &mut Option<DialogWatch>,
    state: DialogState,
    tag: Option<&str>,
) -> Option<DialogWatch> {
    let watch = watch.as_mut()?;
    watch.advance(state, tag).then(|| watch.clone())
}

fn end(watch: &mut Option<DialogWatch>) -> Option<DialogWatch> {
    advance(watch, DialogState::Terminated, None)
}

/// The proxied dialogs of registered AoRs, keyed by dialog.
#[derive(Debug, Default)]
pub struct ProxyDialogStore {
    dialogs: DashMap<DialogKey, Dialog>,
    /// Via branch of each tracked branch → its dialog.
    by_branch: DashMap<String, DialogKey>,
    /// `dialogs.len()`, kept alongside so the check every proxied message makes
    /// is one atomic load: `DashMap::len` takes a read lock on every shard.
    tracked: AtomicUsize,
}

impl ProxyDialogStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Nothing tracked: the check every hook on the proxy path makes first.
    pub fn is_empty(&self) -> bool {
        self.tracked.load(Ordering::Acquire) == 0
    }

    /// Dialogs tracked, for the leak test.
    pub fn len(&self) -> usize {
        self.dialogs.len()
    }

    /// Branch index entries, for the leak test.
    pub fn branch_index_len(&self) -> usize {
        self.by_branch.len()
    }

    pub fn contains(&self, key: &DialogKey) -> bool {
        self.dialogs.contains_key(key)
    }

    /// Start tracking an INVITE's dialog, reporting the caller's first state.
    /// Nothing happens when it is already tracked.
    pub fn begin(&self, dialog: NewDialog, now: Instant) -> Vec<DialogWatch> {
        let key = (dialog.call_id.clone(), dialog.caller_tag.clone());
        let dashmap::mapref::entry::Entry::Vacant(vacant) = self.dialogs.entry(key) else {
            return Vec::new();
        };
        let reports: Vec<DialogWatch> = dialog.caller.iter().cloned().collect();
        self.tracked.fetch_add(1, Ordering::AcqRel);
        vacant.insert(Dialog {
            created_at: now,
            caller: dialog.caller,
            caller_hop: dialog.caller_hop,
            caller_contact: dialog.caller_contact,
            from: dialog.from,
            to: dialog.to,
            invite_cseq: dialog.invite_cseq,
            route_to_caller: dialog.route_to_caller,
            branches: Vec::new(),
            confirmed: None,
        });
        reports
    }

    /// Record a branch the INVITE was relayed on, reporting the callee's first
    /// state when it rings a registered phone.
    pub fn add_branch(&self, key: &DialogKey, branch: NewBranch) -> Vec<DialogWatch> {
        let Some(mut dialog) = self.dialogs.get_mut(key) else {
            return Vec::new();
        };
        let reports: Vec<DialogWatch> = branch.watch.iter().cloned().collect();
        self.by_branch
            .insert(branch.via_branch.clone(), key.clone());
        dialog.branches.push(Branch {
            via_branch: branch.via_branch,
            watch: branch.watch,
            ended: false,
            hop: branch.hop,
            own_record_routes: branch.own_record_routes,
        });
        reports
    }

    /// Whether the INVITE's dialog was relayed on no branch at all.
    pub fn has_no_branch(&self, key: &DialogKey) -> bool {
        self.dialogs
            .get(key)
            .is_some_and(|dialog| dialog.branches.is_empty())
    }

    /// The dialog a tracked branch belongs to.
    pub fn key_of_branch(&self, via_branch: &str) -> Option<DialogKey> {
        self.by_branch.get(via_branch).map(|entry| entry.clone())
    }

    /// A response to the INVITE arrived on a tracked branch.
    pub fn branch_response(
        &self,
        via_branch: &str,
        status_code: u16,
        to_tag: Option<&str>,
        answer: Option<Answer>,
        now: Instant,
        config: &DialogStateConfig,
    ) -> Vec<DialogWatch> {
        let Some(key) = self.key_of_branch(via_branch) else {
            return Vec::new();
        };
        let Some(mut dialog) = self.dialogs.get_mut(&key) else {
            return Vec::new();
        };
        let Some(index) = dialog
            .branches
            .iter()
            .position(|branch| branch.via_branch == via_branch)
        else {
            return Vec::new();
        };
        let mut reports = Vec::new();
        match status_code {
            100..=199 => {
                let state = DialogState::of_provisional(to_tag.is_some());
                reports.extend(advance(&mut dialog.branches[index].watch, state, to_tag));
            }
            200..=299 => {
                reports.extend(advance(
                    &mut dialog.branches[index].watch,
                    DialogState::Confirmed,
                    to_tag,
                ));
                if let (None, Some(to_tag)) = (&dialog.confirmed, to_tag) {
                    let answer = answer.unwrap_or_default();
                    let own = dialog.branches[index].own_record_routes;
                    let upstream = dialog.route_to_caller.len();
                    let downstream = answer.record_routes.len().saturating_sub(own + upstream);
                    let route_to_callee: Vec<String> = answer.record_routes[..downstream]
                        .iter()
                        .rev()
                        .cloned()
                        .collect();
                    let invite_cseq = dialog.invite_cseq;
                    dialog.confirmed = Some(Confirmed {
                        callee_tag: to_tag.to_string(),
                        branch: index,
                        callee_contact: answer.contact,
                        route_to_callee,
                        session_expires: answer.session_expires.map(Duration::from_secs),
                        refreshed_at: now,
                        last_cseq_from_caller: invite_cseq,
                        last_cseq_from_callee: None,
                        next_probe_at: now + Duration::from_secs(config.probe_interval_secs),
                        failures: [0; 2],
                        in_flight: [false; 2],
                    });
                }
            }
            _ => {
                dialog.branches[index].ended = true;
                reports.extend(end(&mut dialog.branches[index].watch));
            }
        }
        reports
    }

    /// siphon sent the caller a response to the INVITE.
    pub fn upstream_response(
        &self,
        key: &DialogKey,
        status_code: u16,
        to_tag: Option<&str>,
    ) -> Vec<DialogWatch> {
        let Some(mut dialog) = self.dialogs.get_mut(key) else {
            return Vec::new();
        };
        let state = match status_code {
            101..=199 if to_tag.is_some() => DialogState::Early,
            200..=299 => DialogState::Confirmed,
            300.. => DialogState::Terminated,
            _ => return Vec::new(),
        };
        if state == DialogState::Confirmed {
            // The dialog the caller is in is the answering branch's, whatever
            // early dialog it saw first.
            if let (Some(watch), Some(tag)) = (dialog.caller.as_mut(), to_tag) {
                if watch.state < DialogState::Confirmed {
                    watch.remote_tag = Some(tag.to_string());
                }
            }
        }
        advance(&mut dialog.caller, state, to_tag)
            .into_iter()
            .collect()
    }

    /// Once the INVITE's response handling is over: an unanswered dialog every
    /// branch of which ended is over for the caller too, whether or not a final
    /// response reached it (a script may suppress it). A dialog nobody is
    /// watching any more is forgotten.
    pub fn settle(&self, key: &DialogKey) -> Vec<DialogWatch> {
        let mut reports = Vec::new();
        if let Some(mut dialog) = self.dialogs.get_mut(key) {
            if dialog.confirmed.is_none() && dialog.branches.iter().all(|branch| branch.ended) {
                reports.extend(end(&mut dialog.caller));
            }
        }
        self.forget_if_done(key);
        reports
    }

    /// The INVITE was abandoned before an answer: the caller CANCELled it, or a
    /// reply-time reject failed it. Every watch ends.
    pub fn end_invite(&self, key: &DialogKey) -> Vec<DialogWatch> {
        let reports = match self.dialogs.get_mut(key) {
            Some(mut dialog) if dialog.confirmed.is_none() => dialog.end_all(),
            _ => Vec::new(),
        };
        self.forget_if_done(key);
        reports
    }

    /// siphon CANCELled the branches of `key` other than `keep` (one answered,
    /// or a 6xx ended the fork), or all of them.
    pub fn branches_cancelled(&self, key: &DialogKey, keep: Option<&str>) -> Vec<DialogWatch> {
        let Some(mut dialog) = self.dialogs.get_mut(key) else {
            return Vec::new();
        };
        let answered = dialog.confirmed.as_ref().map(|confirmed| confirmed.branch);
        let mut reports = Vec::new();
        for (index, branch) in dialog.branches.iter_mut().enumerate() {
            if Some(branch.via_branch.as_str()) == keep || Some(index) == answered {
                continue;
            }
            branch.ended = true;
            reports.extend(end(&mut branch.watch));
        }
        reports
    }

    /// Find the confirmed dialog an in-dialog message belongs to, and which end
    /// sent it (the end whose tag is its From-tag).
    fn confirmed_key(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Option<(DialogKey, End)> {
        let as_caller = (call_id.to_string(), from_tag.to_string());
        if let Some(dialog) = self.dialogs.get(&as_caller) {
            if dialog
                .confirmed
                .as_ref()
                .is_some_and(|confirmed| confirmed.callee_tag == to_tag)
            {
                return Some((as_caller, End::Caller));
            }
        }
        let as_callee = (call_id.to_string(), to_tag.to_string());
        let dialog = self.dialogs.get(&as_callee)?;
        dialog
            .confirmed
            .as_ref()
            .is_some_and(|confirmed| confirmed.callee_tag == from_tag)
            .then_some((as_callee, End::Callee))
    }

    /// An in-dialog request passed through siphon. A BYE ends the dialog for
    /// both ends; anything else records its CSeq (what a later probe from the
    /// same side reuses) and, for a target refresh, its Contact.
    pub fn in_dialog_request(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        method: &str,
        cseq: Option<u32>,
        contact: Option<String>,
    ) -> Vec<DialogWatch> {
        let Some((key, sender)) = self.confirmed_key(call_id, from_tag, to_tag) else {
            return Vec::new();
        };
        let mut reports = Vec::new();
        if let Some(mut dialog) = self.dialogs.get_mut(&key) {
            if method.eq_ignore_ascii_case("BYE") {
                reports.extend(end(&mut dialog.caller));
                if let Some(watch) = dialog.callee_watch_mut() {
                    reports.extend(
                        watch
                            .advance(DialogState::Terminated, None)
                            .then(|| watch.clone()),
                    );
                }
            } else {
                let is_refresh =
                    method.eq_ignore_ascii_case("INVITE") || method.eq_ignore_ascii_case("UPDATE");
                if sender == End::Caller && is_refresh {
                    if let Some(contact) = contact.clone() {
                        dialog.caller_contact = Some(contact);
                    }
                }
                if let Some(confirmed) = dialog.confirmed.as_mut() {
                    match (sender, cseq) {
                        (End::Caller, Some(cseq)) => {
                            confirmed.last_cseq_from_caller =
                                confirmed.last_cseq_from_caller.max(cseq)
                        }
                        (End::Callee, Some(cseq)) => {
                            confirmed.last_cseq_from_callee =
                                Some(confirmed.last_cseq_from_callee.unwrap_or(0).max(cseq))
                        }
                        _ => {}
                    }
                    if sender == End::Callee && is_refresh {
                        if let Some(contact) = contact {
                            confirmed.callee_contact = Some(contact);
                        }
                    }
                }
            }
        }
        self.forget_if_done(&key);
        reports
    }

    /// A 2xx to an in-dialog re-INVITE or UPDATE passed through siphon: the
    /// session is refreshed (RFC 4028 §7.4 / §9), at the interval it carries.
    pub fn in_dialog_refreshed(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        session_expires: Option<u64>,
        now: Instant,
    ) {
        let Some((key, _)) = self.confirmed_key(call_id, from_tag, to_tag) else {
            return;
        };
        if let Some(mut dialog) = self.dialogs.get_mut(&key) {
            if let Some(confirmed) = dialog.confirmed.as_mut() {
                confirmed.refreshed_at = now;
                if let Some(interval) = session_expires {
                    confirmed.session_expires = Some(Duration::from_secs(interval));
                }
            }
        }
    }

    /// The liveness pass, at `now`. Ends every watch whose dialog cannot be
    /// taken as still there — a vouching binding `binding_live` no longer
    /// knows, a session interval run out, a dialog past `max_early_secs`
    /// unanswered or past `max_lifetime_secs` at all — and hands back the
    /// probes now due.
    pub fn sweep(
        &self,
        now: Instant,
        config: &DialogStateConfig,
        binding_live: &dyn Fn(&str, &str) -> bool,
    ) -> (Vec<DialogWatch>, Vec<Probe>) {
        let mut reports = Vec::new();
        let mut probes = Vec::new();
        let keys: Vec<DialogKey> = self
            .dialogs
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys {
            let Some(mut dialog) = self.dialogs.get_mut(&key) else {
                continue;
            };
            let age = now.saturating_duration_since(dialog.created_at);
            let lifetime_over = age >= Duration::from_secs(config.max_lifetime_secs);
            let ringing_too_long =
                dialog.confirmed.is_none() && age >= Duration::from_secs(config.max_early_secs);
            let session_over = dialog.confirmed.as_ref().is_some_and(|confirmed| {
                confirmed.session_expires.is_some_and(|interval| {
                    now.saturating_duration_since(confirmed.refreshed_at)
                        >= interval + Duration::from_secs(config.session_timer_grace_secs)
                })
            });
            if lifetime_over || ringing_too_long || session_over {
                reports.extend(dialog.end_all());
                drop(dialog);
                self.forget_if_done(&key);
                continue;
            }

            // A phone whose vouching binding is gone — de-registered, expired,
            // or reaped by registrar liveness — is no longer reachable through
            // siphon, and its dialogs end with it.
            let gone = |watch: &DialogWatch| {
                watch.state != DialogState::Terminated
                    && watch
                        .contact
                        .as_deref()
                        .is_some_and(|contact| !binding_live(&watch.aor, contact))
            };
            if dialog.caller.as_ref().is_some_and(gone) {
                reports.extend(end(&mut dialog.caller));
            }
            for branch in &mut dialog.branches {
                if branch.watch.as_ref().is_some_and(gone) {
                    branch.ended = true;
                    reports.extend(end(&mut branch.watch));
                }
            }

            if config.probe_interval_secs > 0 {
                probes.extend(Self::due_probes(&key, &mut dialog, now, config));
            }
            drop(dialog);
            self.forget_if_done(&key);
        }
        (reports, probes)
    }

    /// The probes `dialog` owes at `now`: one to each end still watched, when
    /// the interval is up and none is already out.
    fn due_probes(
        key: &DialogKey,
        dialog: &mut Dialog,
        now: Instant,
        config: &DialogStateConfig,
    ) -> Vec<Probe> {
        let caller_live = dialog
            .caller
            .as_ref()
            .is_some_and(|watch| watch.state != DialogState::Terminated);
        let callee_live = dialog
            .callee_watch_mut()
            .is_some_and(|watch| watch.state != DialogState::Terminated);
        let from = dialog.from.clone();
        let to = dialog.to.clone();
        let caller_contact = dialog.caller_contact.clone();
        let caller_hop = dialog.caller_hop;
        let route_to_caller = dialog.route_to_caller.clone();
        let callee_hop = dialog
            .confirmed
            .as_ref()
            .and_then(|confirmed| dialog.branches.get(confirmed.branch))
            .map(|branch| branch.hop);
        let Some(confirmed) = dialog.confirmed.as_mut() else {
            return Vec::new();
        };
        if now < confirmed.next_probe_at {
            return Vec::new();
        }
        confirmed.next_probe_at = now + Duration::from_secs(config.probe_interval_secs);
        let to_tagged = format!("{to};tag={}", confirmed.callee_tag);
        let mut probes = Vec::new();
        // Toward the caller, as a request from the callee.
        if let (true, false, Some(contact)) = (
            caller_live,
            confirmed.in_flight[End::Caller.index()],
            caller_contact,
        ) {
            confirmed.in_flight[End::Caller.index()] = true;
            probes.push(Probe {
                key: key.clone(),
                end: End::Caller,
                request_uri: contact,
                route: route_to_caller,
                from: to_tagged.clone(),
                to: from.clone(),
                call_id: key.0.clone(),
                cseq: confirmed.last_cseq_from_callee.unwrap_or(0),
                hop: caller_hop,
            });
        }
        // Toward the callee, as a request from the caller.
        if let (true, false, Some(contact), Some(hop)) = (
            callee_live,
            confirmed.in_flight[End::Callee.index()],
            confirmed.callee_contact.clone(),
            callee_hop,
        ) {
            confirmed.in_flight[End::Callee.index()] = true;
            probes.push(Probe {
                key: key.clone(),
                end: End::Callee,
                request_uri: contact,
                route: confirmed.route_to_callee.clone(),
                from,
                to: to_tagged,
                call_id: key.0.clone(),
                cseq: confirmed.last_cseq_from_caller,
                hop,
            });
        }
        probes
    }

    /// A probe to `end` of `key` came back with `outcome`. A `481` ends that
    /// end's dialog; `probe_failures` unanswered probes in a row do too.
    pub fn probe_result(
        &self,
        key: &DialogKey,
        end_probed: End,
        outcome: ProbeOutcome,
        config: &DialogStateConfig,
    ) -> Vec<DialogWatch> {
        let mut reports = Vec::new();
        if let Some(mut dialog) = self.dialogs.get_mut(key) {
            let index = end_probed.index();
            let gone = match dialog.confirmed.as_mut() {
                Some(confirmed) => {
                    confirmed.in_flight[index] = false;
                    match outcome {
                        ProbeOutcome::Alive => {
                            confirmed.failures[index] = 0;
                            false
                        }
                        ProbeOutcome::Gone => true,
                        ProbeOutcome::Unanswered => {
                            confirmed.failures[index] += 1;
                            confirmed.failures[index] >= config.probe_failures.max(1)
                        }
                    }
                }
                None => false,
            };
            if gone {
                if let Some(watch) = dialog.watch_mut(end_probed) {
                    reports.extend(
                        watch
                            .advance(DialogState::Terminated, None)
                            .then(|| watch.clone()),
                    );
                }
            }
        }
        self.forget_if_done(key);
        reports
    }

    /// Drop a dialog nobody is watching any more, and its branch index.
    fn forget_if_done(&self, key: &DialogKey) {
        let removed = self
            .dialogs
            .remove_if(key, |_, dialog| !dialog.has_live_watch());
        if let Some((_, dialog)) = removed {
            self.tracked.fetch_sub(1, Ordering::AcqRel);
            for branch in dialog.branches {
                self.by_branch.remove(&branch.via_branch);
            }
        }
    }
}

/// The interval an RFC 4028 `Session-Expires` value names.
pub fn session_expires_secs(value: &str) -> Option<u64> {
    value.split(';').next()?.trim().parse().ok()
}

#[cfg(test)]
mod tests;
