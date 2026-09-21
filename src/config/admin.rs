//! `admin:` HTTP API and the `cors` block it shares with `metrics`.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// CORS (browser-facing HTTP endpoints)
// ---------------------------------------------------------------------------

/// Cross-Origin Resource Sharing policy for a browser-facing HTTP endpoint
/// (the Prometheus `/metrics` listener and/or the admin API).
///
/// A browser blocks a cross-origin `fetch()` of these endpoints unless the
/// server echoes an `Access-Control-Allow-Origin` header. Set this to let a
/// monitoring dashboard served from a different origin (e.g. a local dev
/// server on `http://localhost:5173`) read the endpoint. Leaving it unset
/// emits no CORS headers at all — same-origin callers and Prometheus scrapers
/// are unaffected either way, so this is opt-in and backwards compatible.
#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    /// Origins allowed to read this endpoint from a browser, echoed into
    /// `Access-Control-Allow-Origin`. Each entry is a full origin including
    /// scheme and port (`http://localhost:5173`, `https://dash.example.com`).
    /// A single `"*"` entry allows any origin — convenient for local
    /// development, but prefer an explicit list in production, especially for
    /// the admin API (which can force-unregister AoRs and lift bans). An empty
    /// list disables CORS.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

// ---------------------------------------------------------------------------
// HTTP admin API
// ---------------------------------------------------------------------------

/// HTTP admin API listener. Exposes liveness/readiness probes and registration
/// inspection on a dedicated port:
///   `GET /admin/health`              liveness — 200 while the process is alive
///   `GET /admin/ready`               readiness — 200, or 503 while draining
///   `GET /admin/stats`               uptime + active registration count
///   `GET /admin/registrations`       list all AoRs + contacts
///   `GET /admin/registrations/{aor}` one AoR's contacts
///   `DELETE /admin/registrations/{aor}` force-unregister an AoR
///   `GET /admin/bans`                list active auto-bans + remaining TTL
///   `DELETE /admin/bans/{ip}`        lift an auto-ban (also clears the kernel set)
///   `GET /metrics`                   Prometheus scrape (same body as the metrics port)
#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    /// Address to expose the admin API on (e.g. "0.0.0.0:9091").
    pub listen: String,
    /// Optional CORS policy so a browser dashboard served from another origin
    /// can `fetch()` the admin API (and the `/metrics` it also serves). Unset =
    /// no CORS headers (default). Prefer an explicit origin list here — the
    /// admin API can force-unregister AoRs and lift auto-bans.
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    /// Optional bearer-token auth for the admin API. The admin API can
    /// force-unregister AoRs and lift auto-bans, so when the embedded UI is
    /// exposed a token should protect at least the mutating routes. Unset =
    /// no auth (network-placement trust only, unchanged from before).
    #[serde(default)]
    pub auth: Option<AdminAuthConfig>,
    /// Optional embedded web dashboard served from this listener. Requires a
    /// binary built with the `ui` cargo feature; on a binary without it,
    /// `enabled: true` warns and no UI is served.
    #[serde(default)]
    pub ui: Option<AdminUiConfig>,
    /// Optional live log tail over the admin API (`GET /admin/logs/stream`).
    /// Unset = off.
    #[serde(default)]
    pub log_tail: Option<AdminLogTailConfig>,
    /// Optional bounded SIP message capture, for the dashboard's per-call
    /// ladder and search. Unset = off.
    #[serde(default)]
    pub capture: Option<AdminCaptureConfig>,
    /// Optional TLS on the admin listener. Unset = plaintext (unchanged).
    ///
    /// Without it the bearer token crosses the wire in the clear on every call,
    /// and so does everything the API returns — the registration list (number,
    /// contact address, expiry) and the live call list among it. That is why a
    /// controller driving `POST /admin/gateways/refresh` over anything but a
    /// tunnel needs this block.
    ///
    /// Same type and same hot reload as the SIP listeners: a certificate
    /// replaced under a running process is picked up on the next handshake, so
    /// cert-manager and certbot need no restart. `verify_client` makes it
    /// mutual, which is the stronger answer for a machine-to-machine caller
    /// than a bearer token on its own.
    #[serde(default)]
    pub tls: Option<crate::config::TlsServerConfig>,
}

/// Bounded SIP message capture exposed over the admin API.
///
/// Off by default, and refused at startup without `admin.auth.token` — the
/// captured messages are the signalling itself, complete with numbers and peer
/// addresses. This is a debugging facility and never a lawful-intercept one:
/// `lawful_intercept:` is that, with its own warrants, delivery and retention.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AdminCaptureConfig {
    /// Enable `GET /admin/capture/{call_id}` and `GET /admin/search`.
    #[serde(default)]
    pub enabled: bool,
    /// Total bytes retained before the oldest call is evicted. Default 32 MiB.
    #[serde(default = "default_capture_max_bytes")]
    pub max_bytes: usize,
    /// Calls retained before the oldest is evicted. Default 500.
    #[serde(default = "default_capture_max_calls")]
    pub max_calls: usize,
    /// Messages kept per call. Default 256 — enough for a ladder, bounded
    /// against a retransmission storm.
    #[serde(default = "default_capture_max_messages")]
    pub max_messages_per_call: usize,
    /// Keep headers but drop message bodies (SDP, MESSAGE content). Default
    /// false.
    #[serde(default)]
    pub redact_bodies: bool,
}

fn default_capture_max_bytes() -> usize {
    32 * 1024 * 1024
}

fn default_capture_max_calls() -> usize {
    500
}

fn default_capture_max_messages() -> usize {
    256
}

/// Live log tail exposed over the admin API.
///
/// Off by default, and refused at startup when `admin.auth.token` is unset: a
/// log stream carries call-ids, numbers and peer addresses, so it is gated on
/// the token regardless of `protect_reads` and there is nothing to gate it with
/// when no token exists.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AdminLogTailConfig {
    /// Enable `GET /admin/logs` and `GET /admin/logs/stream`. Default false.
    #[serde(default)]
    pub enabled: bool,
    /// Concurrent tail streams allowed. Each holds a bounded queue, so this
    /// caps the memory one client can pin on a server that has no connection
    /// limiting of its own. Default 4.
    #[serde(default = "default_log_tail_max_streams")]
    pub max_streams: usize,
}

fn default_log_tail_max_streams() -> usize {
    4
}

/// Bearer-token auth for the admin API (RFC 6750). When `token` is set, the
/// `DELETE` routes (force-unregister, lift-ban) require
/// `Authorization: Bearer <token>`; set `protect_reads` to require it on the
/// `GET` routes and `/metrics` too. Same-origin dashboard callers send the
/// token themselves; Prometheus scrapers of a `protect_reads` endpoint must be
/// configured with the bearer token.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AdminAuthConfig {
    /// Shared bearer token. Empty/unset disables auth. Supports `${VAR}`
    /// expansion, so keep the literal out of the YAML: `token: "${ADMIN_TOKEN}"`.
    #[serde(default)]
    pub token: Option<String>,
    /// Also require the token on the read routes (`GET`, `/metrics`,
    /// `/admin/metrics.json`), not only the mutating `DELETE` routes. Default
    /// false — reads stay open (back-compat), writes are gated as soon as a
    /// token is set.
    #[serde(default)]
    pub protect_reads: bool,
}

/// Embedded web-dashboard settings for the admin listener.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AdminUiConfig {
    /// Serve the embedded dashboard at the admin listener root (`/`). Default
    /// false. Requires a binary built with `--features ui`; otherwise a loud
    /// warning is logged and no UI is served.
    #[serde(default)]
    pub enabled: bool,
}
