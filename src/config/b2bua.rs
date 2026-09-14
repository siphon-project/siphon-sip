//! `b2bua:` knobs and `session_timer:` (RFC 4028).

use super::bool_true;
use serde::Deserialize;

/// B2BUA-wide configuration knobs.
///
/// Currently surfaces the default header policy applied to B2BUA calls when
/// the script doesn't pass `header_policy=` on `call.dial()`.  Names either a
/// built-in preset (e.g. `"transparent-b2bua@2026"`) or an operator-defined
/// one from the top-level `header_policies:` map — one namespace, and a name
/// that resolves to neither refuses to start.  An unset/empty value falls back
/// to `transparent-b2bua@2026`, which reproduces siphon's pre-policy B2BUA
/// behaviour (modulo the intentional `Proxy-Authenticate` strip).
///
/// ```yaml
/// b2bua:
///   default_header_policy: "ims-trust-domain-boundary@2026"
/// ```
#[derive(Debug, Deserialize, Clone, Default)]
pub struct B2buaConfig {
    /// Qualified preset name (`"<name>@<version>"`).  When `None`, falls
    /// back to `"transparent-b2bua@2026"`.
    pub default_header_policy: Option<String>,

    /// Default number-format policy applied to every B2BUA call when the
    /// script doesn't pass `number_policy=` on `call.dial()`/`call.fork()`.
    /// Names an entry in the top-level `number_policies:` map.  When `None`,
    /// no number normalization is applied unless a call opts in explicitly.
    pub default_number_policy: Option<String>,

    /// Default REFER transfer mode applied when an `@b2bua.on_refer` handler
    /// calls `accept_refer()` without an explicit `mode=`.
    ///
    /// - `"terminate"` (default) — siphon terminates the transfer: answer 202
    ///   locally, dial the Refer-To (or the handler's `target=`) as a new leg,
    ///   re-bridge the media, and BYE the referred-away leg. Correct for
    ///   trunk-facing SBCs (the far end need not support REFER) and keeps media
    ///   anchored. The new leg is dialled directly — `@b2bua.on_invite` does not
    ///   run again for it — so `accept_refer(number_policy=…, next_hop=…)` is
    ///   where the dial plan's shaping and steering are reapplied.
    /// - `"transparent"` — siphon re-emits the REFER on the far leg's own dialog
    ///   and relays the far end's 202 + `message/sipfrag` NOTIFYs back. Correct
    ///   for UA-to-UA (PBX / softphone) topologies.
    ///
    /// Unset → `"terminate"`.
    pub default_refer_mode: Option<String>,

    /// Whether an inbound `INVITE` carrying a `Replaces` (RFC 3891) may take
    /// over the dialog it names — the transferee half of attended transfer,
    /// and the shape of a directed call pickup.
    ///
    /// **Off unless enabled.** Possession of a dialog's identifiers is not
    /// proof of authorisation to end that dialog: RFC 3891 §5 calls out
    /// exactly this, the transferor hands the triple to the transferee by
    /// design, and anyone who can observe unprotected signalling reads it off
    /// the wire. Turning this on grants every party that reaches this node —
    /// subject to whatever admission `@b2bua.on_invite` applies — the ability
    /// to disconnect one party from a live call and take their place. That is
    /// a capability an operator opts into, not one an upgrade switches on.
    ///
    /// With it off, a `Replaces` naming a dialog this node hosts is declined
    /// `603` (RFC 3891 §3's answer for a dialog the UA is unwilling to
    /// replace) rather than being ignored — the INVITE never becomes an
    /// unrelated second call.
    ///
    /// **Enable it only where INVITEs are authenticated or the source is
    /// trusted.** `auth.require_proxy_digest()` in `@b2bua.on_invite` is what
    /// makes this safe on an untrusted edge; the takeover runs only after that
    /// handler admits the request, so a challenge or a `call.reject()` stops
    /// it.
    ///
    /// ```yaml
    /// b2bua:
    ///   accept_replaces: true
    /// ```
    pub accept_replaces: Option<bool>,

    /// Report every outbound B-leg INVITE at `info`, at the moment it is
    /// handed to the transport.
    ///
    /// **Off by default** — this is one line per call on the busiest path
    /// siphon has, so it is an operator's decision, not an upgrade's. The
    /// LCR lines that already log at `info` fire only on failover, which is
    /// why they need no knob.
    ///
    /// What it buys over logging the dial from the script: `call.dial()` only
    /// *records* an action that the framework executes after the handler
    /// returns, so a script-side line is written before the dial exists and
    /// still claims it when the destination fails to resolve. This line is
    /// emitted from the send itself, after routing, the header policy, the
    /// number policy, LCR tech-prefix/retarget and CLIR have all had their
    /// turn — so it reports the Request-URI that actually went on the wire,
    /// not the string the script passed in, and it carries the B-leg Call-ID
    /// the far end will quote back.
    ///
    /// Covers every B-leg INVITE — `call.dial()`, each `call.fork()` branch,
    /// each `call.route()` carrier attempt, and a REFER-terminate re-dial.
    ///
    /// ```yaml
    /// b2bua:
    ///   log_dial: true
    /// ```
    pub log_dial: Option<bool>,

    /// Ceiling on how long an answered B2BUA call may run, in seconds, for
    /// every call that does not set its own `call.dial(max_duration=…)`.
    ///
    /// **Unset by default** — an answered call is otherwise bounded by nothing
    /// except a peer BYE, a script `terminate()`, or the RFC 4028 session timer
    /// where that is configured *and* the far end honours it. This is the
    /// backstop for the rest: a carrier leg that goes silent with the dialog
    /// still up holds a call actor, a media anchor, a charging session and an
    /// RTP port pair until the process restarts.
    ///
    /// Measured from the answer, not from the dial — the ring is already
    /// bounded by `call.dial(timeout=…)`, and a cap that counted ring time
    /// would give a call that rang for 25 s less talk time than one that was
    /// picked up instantly.
    ///
    /// On expiry siphon BYEs both legs through the ordinary teardown: RFC 3326
    /// `Reason: Q.850;cause=102`, a CDR with `disconnect_initiator="timeout"`,
    /// Rf/Ro `ACR-STOP`, media released. No Python handler fires, the same as
    /// for a session-timer expiry.
    ///
    /// A call opts out with `call.dial(max_duration=0)`.
    ///
    /// ```yaml
    /// b2bua:
    ///   max_call_duration_secs: 14400    # 4h
    /// ```
    pub max_call_duration_secs: Option<u32>,
}

impl B2buaConfig {
    /// The header-policy name to apply when a call doesn't pass one.
    ///
    /// Unset, empty, or whitespace all mean "not configured" and resolve to
    /// [`DEFAULT_PRESET_NAME`](crate::b2bua::header_policy::DEFAULT_PRESET_NAME);
    /// anything else is taken verbatim and must exist in the registry (the
    /// load-time check in [`Config::validate_header_policies`](super::Config::validate_header_policies) proves it does).
    pub fn resolved_default_header_policy(&self) -> &str {
        match self.default_header_policy.as_deref().map(str::trim) {
            Some(name) if !name.is_empty() => name,
            _ => crate::b2bua::header_policy::DEFAULT_PRESET_NAME,
        }
    }

    /// Whether an inbound `Replaces` may take a dialog over. Defaults to
    /// `false` — see [`accept_replaces`](Self::accept_replaces).
    pub fn replaces_takeover_enabled(&self) -> bool {
        self.accept_replaces.unwrap_or(false)
    }

    /// Whether outbound B-leg INVITEs are reported at `info`. Defaults to
    /// `false` — see [`log_dial`](Self::log_dial).
    pub fn log_dial_enabled(&self) -> bool {
        self.log_dial.unwrap_or(false)
    }

    /// The default maximum answered call duration, or `None` for uncapped —
    /// see [`max_call_duration_secs`](Self::max_call_duration_secs).
    ///
    /// An explicit `0` normalises to `None` so that writing the knob down as
    /// "no limit" means the same thing as leaving it out, and matches the
    /// per-call `max_duration=0` opt-out.
    pub fn resolved_max_call_duration_secs(&self) -> Option<u32> {
        self.max_call_duration_secs.filter(|seconds| *seconds > 0)
    }

    /// Resolve the configured default REFER mode. `None`, empty, or an
    /// unrecognized value fall back to the safe trunk-facing default
    /// (`Terminate`); only an explicit `"transparent"` selects transparent
    /// forwarding.
    pub fn resolved_default_refer_mode(&self) -> crate::script::api::call::ReferMode {
        match self.default_refer_mode.as_deref().map(str::trim) {
            Some("transparent") => crate::script::api::call::ReferMode::Transparent,
            _ => crate::script::api::call::ReferMode::Terminate,
        }
    }
}

// ---------------------------------------------------------------------------
// Session timers (RFC 4028)
// ---------------------------------------------------------------------------

/// RFC 4028 session timer configuration for B2BUA mode.
///
/// Session timers prevent resource leaks from calls whose BYE was lost.
/// The B2BUA sends periodic re-INVITEs to keep the session alive and tears
/// down calls that fail to refresh within the negotiated interval.
///
/// Example siphon.yaml:
/// ```yaml
/// session_timer:
///   session_expires: 1800
///   min_se: 90
///   refresher: uac
///   enabled: true
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct SessionTimerConfig {
    /// Default Session-Expires value in seconds. Default: 1800 (30 minutes).
    #[serde(default = "default_session_expires")]
    pub session_expires: u32,
    /// Minimum acceptable Session-Expires (Min-SE header). Default: 90.
    #[serde(default = "default_min_se")]
    pub min_se: u32,
    /// Who sends the refresh re-INVITE: uac (default) or uas.
    #[serde(default = "default_refresher")]
    pub refresher: SessionRefresher,
    /// Enable/disable session timers entirely. Default: true.
    #[serde(default = "bool_true")]
    pub enabled: bool,
}

/// Who is responsible for sending refresh re-INVITEs (RFC 4028).
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionRefresher {
    /// The calling party (UAC) refreshes (default).
    Uac,
    /// The called party (UAS) refreshes.
    Uas,
    /// The B2BUA itself handles refresh re-INVITEs on both legs.
    B2bua,
}

fn default_session_expires() -> u32 {
    1800
}

fn default_min_se() -> u32 {
    90
}

fn default_refresher() -> SessionRefresher {
    SessionRefresher::Uac
}
