//! B2BUA actor model — per-leg state ownership with intercommunication.
//!
//! ## Architecture
//!
//! - **[`Leg`]**: Pure state for a single SIP dialog leg. Each leg owns its
//!   [`Dialog`] (Call-ID, tags, CSeq) and [`TransportInfo`] independently.
//!
//! - **[`CallActor`]**: Per-call supervisor. Holds A-leg + B-leg(s), coordinates
//!   forking, winner selection, and call teardown.
//!
//! - **[`LegRegistry`]**: Global routing table mapping SIP identifiers
//!   (Call-ID, Via branch) → internal call ID, so the dispatcher can route
//!   inbound SIP messages to the correct call.
//!
//! - **[`LegActor`]**: Async actor wrapping a `Leg` + channels.
//!   Classifies inbound SIP messages into [`CallEvent`]s for the dispatcher.
//!
//! ## Forking
//!
//! A `CallActor` can hold multiple B-legs. Each B-leg has independent dialog
//! state. The call actor tracks per-leg status and coordinates winner selection.
//!
//! ## Design
//!
//! - Each leg **owns** its dialog state via [`Dialog`].
//! - Legs are independent entities with separate transport bindings.
//! - `LegRegistry` provides SIP-level routing (Call-ID, branch → internal ID).
//! - Foundation for API-driven calls: create a `Leg` without an inbound INVITE.

mod call;
mod helpers;
mod leg;
mod leg_actor;
mod store;

#[cfg(test)]
mod tests;

// `siphon` is a published library crate and `b2bua::actor` is a public path, so
// every item keeps the name it had when this was one file. The submodules are
// private: splitting the file must not add a second public path to maintain.
pub use call::*;
pub use helpers::*;
pub use leg::*;
pub use leg_actor::*;
pub use store::*;

// ---------------------------------------------------------------------------

/// The dispatcher-owned B2BUA call store, published for read-only consumers
/// (the admin API `/admin/calls`) that need to enumerate active calls without
/// owning the dispatcher.
static GLOBAL_CALL_STORE: std::sync::OnceLock<std::sync::Arc<CallActorStore>> =
    std::sync::OnceLock::new();
/// Register the process-wide B2BUA call store. Called once at dispatcher
/// construction; a no-op if a store was already registered.
pub fn set_global_call_store(store: std::sync::Arc<CallActorStore>) {
    let _ = GLOBAL_CALL_STORE.set(store);
}
/// The process-wide B2BUA call store, or `None` in headless / unit-test
/// contexts that never constructed a dispatcher.
/// Per-minute spend of the answered calls in progress, keyed by ISO 4217
/// currency.
///
/// Iterates the live calls, so it is for the 30 s sweep and the dashboard poll
/// — never the per-message path. Unanswered calls are excluded: a ringing call
/// costs nothing yet, and counting it would make the burn rate jump on every
/// attempt including the ones that never connect.
pub fn spend_rate_by_currency(store: &CallActorStore) -> std::collections::HashMap<String, f64> {
    let mut rates: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    for entry in store.iter_calls() {
        let call = entry.value();
        if call.answered_at.is_none() {
            continue;
        }
        if let Some(route) = call.active_route() {
            if let Some(rate) = route.rate {
                let currency = route.currency.as_deref().unwrap_or("unknown").to_string();
                *rates.entry(currency).or_insert(0.0) += rate;
            }
        }
    }
    rates
}
pub fn global_call_store() -> Option<&'static std::sync::Arc<CallActorStore>> {
    GLOBAL_CALL_STORE.get()
}

// ---------------------------------------------------------------------------
// LegActor — async actor for B-leg message classification
