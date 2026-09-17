//! `control:` external remote-control plane.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// External remote-control plane (ARI/ESL-class)
// ---------------------------------------------------------------------------

/// External remote-control plane listener + per-app registry.
///
/// An out-of-process application drives B2BUA calls that a Python
/// `@b2bua.on_invite` handler explicitly hands over with `call.handover("app")`
/// (the ARI *Stasis* model). Two connection modes, same wire protocol:
/// a persistent inbound WebSocket per app (`listen`), and outbound
/// per-call-connect where siphon dials the app's `connect_url` at handover.
///
/// A management plane — treat it like the admin API. Off by default; enable it
/// deliberately and set per-app bearer tokens.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ControlConfig {
    /// Address for the inbound persistent-WebSocket listener
    /// (e.g. "127.0.0.1:9092"). `None` = only outbound per-call-connect apps
    /// are usable.
    #[serde(default)]
    pub listen: Option<String>,
    /// Registered control applications. An app not listed here can neither
    /// connect (unknown token) nor receive a handover (unknown app name).
    #[serde(default)]
    pub apps: Vec<ControlAppConfig>,
    /// Global resource caps + backpressure policy.
    #[serde(default)]
    pub limits: ControlLimits,
    /// Terminate TLS on `listen` (`wss://` instead of `ws://`). Absent leaves
    /// the listener plaintext, which is only safe on a loopback or a trusted
    /// segment — the bearer token is replayable by anything that can read it.
    #[serde(default)]
    pub tls: Option<ControlTlsConfig>,
    /// Hand every out-of-dialog INVITE to a control application, with no script.
    ///
    /// Without this the only way into the control plane is a script calling
    /// `call.handover(...)`, so a deployment whose policy lives entirely in its
    /// controller still has to ship a routing script that does nothing but
    /// forward — a second place for policy to live and a second thing to
    /// version. A script, when one is configured, still runs first and may hand
    /// over itself; this is what happens when no `@b2bua.on_invite` handler is
    /// registered to decide.
    #[serde(default)]
    pub inbound: Option<ControlInboundConfig>,
}

/// TLS for the inbound control listener (`control.tls`).
#[derive(Debug, Deserialize, Clone)]
pub struct ControlTlsConfig {
    /// PEM certificate chain siphon presents to connecting applications.
    pub certificate: String,
    /// PEM private key for `certificate`.
    pub private_key: String,
    /// PEM CA bundle that turns on **mutual** TLS: an application must present
    /// a certificate one of these CAs signed, on top of its bearer token.
    ///
    /// Worth it for a rail that crosses a network: the token is a single
    /// replayable secret, and a client certificate is a second factor that a
    /// leaked config file alone does not give an attacker.
    #[serde(default)]
    pub client_ca: Option<String>,
}

/// Script-free inbound handover (`control.inbound`).
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ControlInboundConfig {
    /// Which registered application receives the call. Must name an entry in
    /// `control.apps`, or config load fails.
    pub app: String,
    /// `deferred` (the default) holds the INVITE unanswered with the automatic
    /// `100 Trying`, exactly as `call.handover()` does; `answer` answers it and
    /// anchors the media first, as `call.handover(answer=True)` does.
    #[serde(default)]
    pub mode: Option<String>,
    /// How long the controller has to act before the handoff default fires.
    /// Falls back to `control.limits.handoff_deadline_ms`.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    /// `answer` mode only: the media profile to anchor with.
    #[serde(default)]
    pub profile: Option<String>,
    /// `answer` mode only: the per-call WebSocket bridge URI.
    #[serde(default)]
    pub ws_uri: Option<String>,
}

impl ControlInboundConfig {
    /// Whether the INVITE is answered and anchored before the handover.
    pub fn answer_first(&self) -> bool {
        self.mode.as_deref().is_some_and(|mode| mode == "answer")
    }
}

/// A single registered control application.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ControlAppConfig {
    /// The application name. `call.handover("<name>")` routes to this app, and
    /// the connection's `hello.args.app` must equal it.
    pub name: String,
    /// The bearer token this app presents (`Authorization: Bearer <token>` on
    /// the inbound upgrade, or the token siphon presents when dialing
    /// `connect_url`). Supports `${VAR}` expansion — keep the literal out of the
    /// YAML.
    #[serde(default)]
    pub token: String,
    /// When true, siphon dials `connect_url` per handed-over call and the
    /// accepting socket owns that call (the FreeSWITCH-outbound model — the
    /// documented default for multi-pod controllers). When false (default), the
    /// app connects in over `listen` and owns per round-robin assignment.
    #[serde(default)]
    pub per_call_connect: bool,
    /// The controller's WebSocket URL for `per_call_connect` mode
    /// (e.g. "ws://controller.internal:8443/siphon").
    #[serde(default)]
    pub connect_url: Option<String>,
    /// What to do if the owning connection is lost mid-call (owner
    /// disconnects): `hangup` (the default) or `continue`.
    ///
    /// `fallback` — re-dispatch the call through the Python handlers — is
    /// refused rather than accepted: it silently behaved as `hangup`, so an
    /// operator who chose it to keep calls alive got them torn down and nothing
    /// said so. Refused everywhere the policy is set, not only here: see
    /// [`unimplemented_on_lost`].
    #[serde(default)]
    pub on_lost: Option<String>,
    /// PEM bundle to verify the controller's certificate against when
    /// `connect_url` is `wss://`. Absent means the public (Mozilla) roots.
    ///
    /// Naming one **replaces** the public roots rather than adding to them: a
    /// controller behind a private CA should be the only certificate that works,
    /// and keeping the public roots alongside it would let a mis-issued public
    /// certificate through too.
    #[serde(default)]
    pub ca_file: Option<String>,
    /// Application-level event classes this app wants, beyond the per-call
    /// events its own channels produce.
    ///
    /// Opt-in and empty by default: these are not about a call the app owns, so
    /// sending them to every connected app would put a registration storm on
    /// the event queue of an application that only makes outbound calls.
    ///
    /// Known class: `registration` — `RegistrationChanged {aor, event,
    /// contacts}` on every registrar state change.
    #[serde(default)]
    pub events: Vec<String>,
}

/// The control-loss policies siphon implements, and the refusal for one it does
/// not.
///
/// `on_lost` is set in three places — `control.apps[].on_lost`,
/// `call.handover(on_lost=…)` and the `originate` verb — and the control-loss
/// path ends the call for every policy that is not `continue`. While only
/// config load knew which policies exist, the other two accepted `fallback` and
/// then hung the call up anyway, so the vocabulary lives here and all three ask
/// it rather than each keeping its own list to drift.
///
/// `None` when `policy` is implemented; otherwise the tail of a refusal, which
/// the caller prefixes with the setting the value came from.
pub fn unimplemented_on_lost(policy: &str) -> Option<String> {
    if policy == "hangup" || policy == "continue" {
        return None;
    }
    let mut refusal = format!(
        "is {policy:?}, which siphon does not implement — it is \"hangup\" (end the call, the \
         default) or \"continue\" (leave it running without an owner)."
    );
    if policy == "fallback" {
        refusal.push_str(
            " `fallback` would re-dispatch the call through the Python handlers, which does not \
             exist; it behaved as `hangup`.",
        );
    }
    Some(refusal)
}

/// Global control-plane resource caps + backpressure policy.
#[derive(Debug, Deserialize, Clone)]
pub struct ControlLimits {
    /// Bounded per-connection outbound event-queue depth. On overflow the
    /// `slow_consumer` policy applies (events only — replies are never dropped).
    #[serde(default = "ControlLimits::default_event_queue_depth")]
    pub event_queue_depth: usize,
    /// Overflow policy for a slow/stuck consumer: "drop_oldest" (default) or
    /// "disconnect".
    #[serde(default = "ControlLimits::default_slow_consumer")]
    pub slow_consumer: String,
    /// Grace window (seconds) after an owner disconnects during which a
    /// reconnecting controller of the same app may `resync` and re-claim its
    /// calls before `on_lost` fires. Default 10.
    #[serde(default = "ControlLimits::default_reattach_grace_secs")]
    pub reattach_grace_secs: u64,
    /// Default handoff deadline (milliseconds) applied when `call.handover()`
    /// does not pass an explicit `deadline_ms`. If no controller accepts and
    /// acts within it, the call degrades (503). Default 3000.
    #[serde(default = "ControlLimits::default_handoff_deadline_ms")]
    pub handoff_deadline_ms: u64,
}

impl Default for ControlLimits {
    fn default() -> Self {
        Self {
            event_queue_depth: Self::default_event_queue_depth(),
            slow_consumer: Self::default_slow_consumer(),
            reattach_grace_secs: Self::default_reattach_grace_secs(),
            handoff_deadline_ms: Self::default_handoff_deadline_ms(),
        }
    }
}

impl ControlLimits {
    fn default_event_queue_depth() -> usize {
        1024
    }
    fn default_slow_consumer() -> String {
        "drop_oldest".to_string()
    }
    fn default_reattach_grace_secs() -> u64 {
        10
    }
    fn default_handoff_deadline_ms() -> u64 {
        3000
    }
}
