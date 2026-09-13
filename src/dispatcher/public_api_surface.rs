//! Pins every publicly-reachable item of this module by name.
//!
//! `siphon` is a published library crate and `lib.rs` declares `pub mod
//! dispatcher`, so each of these is `siphon::dispatcher::…` to an embedder.
//! 1.9.0 is a minor release, so none of them may move or disappear.
//!
//! The 1.9.0 split moves ~30,000 lines out of this file into `dispatcher/**`.
//! Each extraction re-exports what it took; forgetting one would compile fine
//! here and break an embedder at their next `cargo update`. Naming them
//! explicitly — no glob — turns that into a build failure in this crate.
//!
//! `siphon-bin` and the extension crates reach exactly six of these
//! (`run`, `DrainState`, `init_rtpengine`, `inject_python_singletons`,
//! `spawn_rtpengine_health_check`, `liveness_on_flow_close`); the rest are
//! reached from `control`, `script::api` and `admin` inside this crate.

#[allow(unused_imports)]
use super::{
    b2bua_accept_refer_call, b2bua_answer_call, b2bua_answer_call_anchored, b2bua_bridge_calls,
    b2bua_cancel_originated_call, b2bua_early_media_sdp, b2bua_local_tag,
    b2bua_media_set_ws_bridge_attached, b2bua_media_set_ws_tee, b2bua_media_target,
    b2bua_originate, b2bua_originate_dial, b2bua_originate_prepare, b2bua_progress_call,
    b2bua_progress_call_anchored, b2bua_refer_call, b2bua_reject_call, b2bua_reject_refer_call,
    b2bua_replace_peer, b2bua_route_call, b2bua_terminate_call, b2bua_unbridge_call,
    init_rtpengine, inject_python_singletons, liveness_on_flow_close, publish_store_gauges,
    ro_authorize_b2bua, run, spawn_rtpengine_health_check, BridgeAccepted, BridgeParams,
    DrainState, OriginateError, OriginateMedia, OriginateParams, PreparedOriginate, ProxyRfState,
    ReliableProvisional, RoAuthorizeOutcome, RouteError, RouteTarget,
};

/// Coercing to a fn pointer pins arity and types, not merely the name — a
/// split that "keeps" a function but changes its signature fails here too.
///
/// `run` is deliberately absent: it takes 24 arguments and naming its type
/// would be unreadable. The import above pins its existence; `server.rs`
/// pins its signature by calling it.
#[test]
fn signatures_are_pinned() {
    let _: fn(&str, Option<&str>) -> bool = super::b2bua_terminate_call;
    let _: fn(&str, u16, &str) -> bool = super::b2bua_reject_call;
    let _: fn(&str, u16, &str) -> bool = super::b2bua_reject_refer_call;
    let _: fn(&str) -> Option<String> = super::b2bua_local_tag;
    let _: fn(&str, Option<&str>) -> bool = super::b2bua_cancel_originated_call;
    let _: fn(&str, Option<String>) = super::b2bua_media_set_ws_tee;
    let _: fn(&str, bool) = super::b2bua_media_set_ws_bridge_attached;
    // Named, because clippy's type_complexity refuses the bare fn-pointer type.
    type AnchoredProgress = fn(&str, u16, &str, Option<&str>, Option<&str>) -> Result<(), String>;
    let _: AnchoredProgress = super::b2bua_progress_call_anchored;
    let _: fn(&str) -> Option<String> = super::b2bua_early_media_sdp;
}

/// The count is the tripwire: adding a public item to this module is a
/// deliberate act with a semver consequence, so it has to be recorded here
/// as well as in the import list above.
///
/// As the split proceeds an item's *declaration* moves into a submodule and
/// its public path is kept by a `pub use` here, so the surface is what this
/// file declares plus what it re-exports. Counting only declarations would
/// shrink with every extraction and stop being a tripwire.
#[test]
fn the_public_surface_is_pinned() {
    let source = include_str!("mod.rs");

    let declared = source
        .lines()
        .filter(|line| {
            let line = line.trim_end();
            (line.starts_with("pub fn ")
                || line.starts_with("pub async fn ")
                || line.starts_with("pub struct ")
                || line.starts_with("pub enum ")
                || line.starts_with("pub(crate) async fn ")
                || line.starts_with("pub(crate) fn ")
                || line.starts_with("pub(crate) struct ")
                || line.starts_with("pub(crate) enum "))
                && !line.starts_with("pub use")
        })
        .count();

    // `pub use path::{a, b};` (on one line or wrapped by rustfmt across
    // several) or `pub use path::a;`. A glob would make the surface
    // uncountable, so it is rejected rather than guessed at.
    let mut re_exported = 0;
    let mut lines = source.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        let Some(rest) = line
            .strip_prefix("pub use ")
            .or_else(|| line.strip_prefix("pub(crate) use "))
        else {
            continue;
        };
        assert!(
            !rest.contains('*'),
            "`{line}` re-exports a glob. The public surface of a published module has to be \
             countable and reviewable, so name the items."
        );
        let Some((_, head)) = rest.split_once('{') else {
            re_exported += 1;
            continue;
        };
        // A braced list rustfmt kept on one line ends with `};` here;
        // otherwise it continues until a line that is just `};`.
        let mut names = head.to_string();
        if !rest.trim_end().ends_with("};") {
            for next in lines.by_ref() {
                let next = next.trim();
                if next == "};" {
                    break;
                }
                names.push_str(next);
            }
        }
        re_exported += names
            .trim_end_matches("};")
            .split(',')
            .filter(|name| !name.trim().is_empty())
            .count();
    }

    // 45: the 39 the 1.9.0 split preserved, plus `b2bua_progress_call_anchored`
    // and `b2bua_early_media_sdp` for anchored early media, plus the 4
    // crate-internal control-adapter entry points the dial verb needs. All
    // additive, so a minor-compatible change — recorded here because that is
    // the tripwire.
    assert_eq!(
        declared + re_exported,
        45,
        "the dispatcher's public surface is {} items ({declared} declared here, \
         {re_exported} re-exported), not 45. Adding one is a semver commitment on a \
         published crate; removing one breaks embedders. An extraction should move the \
         declaration and add a `pub use`, leaving this total unchanged.",
        declared + re_exported,
    );
}
