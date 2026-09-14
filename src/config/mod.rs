//! YAML configuration — `siphon.yaml` deserialization via serde_yaml_ng.
//!
//! This module holds the top-level [`Config`], loading and load-time
//! validation, and the helpers shared across sections. Each YAML section's
//! types live in a submodule and are re-exported here, so every type is
//! reached as `crate::config::Name` regardless of which file defines it.

use crate::error::{Result, SiphonError};
use indexmap::IndexMap;
use regex::Regex;
use serde::Deserialize;
use std::path::Path;
use std::sync::LazyLock;

mod admin;
mod auth;
mod b2bua;
mod cdr;
mod charging;
mod control;
mod diameter;
mod gateway;
mod ims;
mod lawful_intercept;
mod listen;
mod media;
mod observability;
mod registrant;
mod registrar;
mod script;
mod security;
mod sip;
mod srs;
mod stir;
#[cfg(test)]
mod tests;
mod tls;

pub use admin::{
    AdminAuthConfig, AdminCaptureConfig, AdminConfig, AdminLogTailConfig, AdminUiConfig, CorsConfig,
};
pub use auth::{AkaCredential, AuthBackendType, AuthConfig, DatabaseAuthConfig, HttpAuthConfig};
pub use b2bua::{B2buaConfig, SessionRefresher, SessionTimerConfig};
pub use cdr::{CdrFileConfig, CdrHttpConfig, CdrSinkConfig, CdrSyslogConfig, CdrYamlConfig};
pub use charging::{RfConfig, RoConfig};
pub use control::{
    ControlAppConfig, ControlConfig, ControlInboundConfig, ControlLimits, ControlTlsConfig,
};
pub use diameter::{
    DiameterApplication, DiameterClientEntry, DiameterConfig, DiameterCxConfig,
    DiameterListenConfig, DiameterPeerEntry, DiameterRouteEntry, DiameterServerEntry,
    DiameterTenant, DiameterTenantIdentity, EventSinkConfig, EventSinkFileConfig,
};
pub use gateway::{
    GatewayConfig, GatewayDestConfig, GatewayGroupConfig, GatewayProbeConfig, LcrConfig,
};
pub use ims::{IpsecBackend, IpsecConfig, IscConfig, SbiYamlConfig};
pub use lawful_intercept::{
    LawfulInterceptConfig, LiSiprecConfig, LiTlsConfig, LiX1AdmfConfig, LiX1Config, LiX1TlsConfig,
    LiX2Config, LiX3Config,
};
pub use listen::{dscp_to_tos, parse_dscp, DomainConfig, ListenConfig, ListenEntry};
pub use media::{
    CodecFlagsConfig, MediaBackendKind, MediaConfig, MediaProfileConfig, NgFlagsConfig,
    RtpEngineEventsConfig, RtpEngineInstanceConfig, RtpEngineSetConfig, RtpProxyConfig,
    RtpProxyInstanceConfig, SiphonRtpConfig, SiphonRtpInstanceConfig,
};
pub use observability::{
    HepConfig, HepTransport, LogConfig, LogFormat, LogLevel, MetricsConfig, PrometheusConfig,
    TracingConfig,
};
pub use registrant::{
    RegistrantAkaConfig, RegistrantEntryConfig, RegistrantImsConfig, RegistrantIpsecConfig,
    RegistrantYamlConfig,
};
pub use registrar::{
    LivenessDeregMode, PostgresBackendConfig, RedisBackendConfig, RegistrarBackendType,
    RegistrarConfig, RegistrarLivenessConfig,
};
pub use script::{ReloadMode, ScriptConfig};
pub use security::{
    ApiBanConfig, ConnectionLimitsConfig, CrlfKeepaliveConfig, FailedAuthBanConfig, FirewallConfig,
    NatConfig, NatKeepaliveConfig, RateLimitConfig, ScannerBlockConfig, SecurityConfig,
    MIN_MAX_MESSAGE_BYTES,
};
pub use sip::{
    DialogBackendType, DialogConfig, NamedCacheConfig, ServerIdentityConfig, SubscribeStateConfig,
    TransactionConfig,
};
pub use srs::{SrsConfig, SrsFileConfig, SrsHttpConfig};
pub use stir::{StirConfig, StirSigningConfig, StirVerificationConfig};
pub use tls::{SniCertificate, TlsMethod, TlsServerConfig};

// ---------------------------------------------------------------------------
// Environment variable expansion — `${VAR}` and `${VAR:-default}`
// ---------------------------------------------------------------------------

static ENV_VAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}").expect("env var regex")
});

/// Expand `${VAR}` and `${VAR:-default}` patterns in a config string.
///
/// - `${VAR}` is replaced with the environment variable's value, or the empty
///   string if unset/empty.
/// - `${VAR:-fallback}` uses `fallback` when the variable is unset or empty.
fn expand_env_vars(input: &str) -> String {
    ENV_VAR_RE
        .replace_all(input, |caps: &regex::Captures| {
            let var_name = &caps[1];
            match std::env::var(var_name) {
                Ok(value) if !value.is_empty() => value,
                _ => caps
                    .get(2)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default(),
            }
        })
        .into_owned()
}

/// Allocator runtime tuning — how the process *manages* memory, distinct from
/// `metrics` (what it *measures*). The `siphon_glibc_*` gauges are always on
/// regardless of this block; it carries only the optional bounding knobs.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
pub struct MemoryConfig {
    /// glibc malloc tuning for the C-side / CPython raw-domain pool.
    #[serde(default)]
    pub glibc: GlibcMemoryConfig,
}

/// glibc `malloc` tuning. Both knobs default off — measure with the gauges
/// first, then bound only if the pool proves to be arena *retention* rather
/// than a true leak.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
pub struct GlibcMemoryConfig {
    /// `mallopt(M_ARENA_MAX, n)` — cap the number of glibc arenas (each a
    /// ~64 MB reservation). The primary lever against per-thread-arena
    /// retention under free-threaded concurrency. `None` = leave glibc's
    /// default (8 × CPUs). Applied once at startup, before the thread pools.
    #[serde(default)]
    pub arena_max: Option<usize>,

    /// Period in seconds for a background `malloc_trim(0)` that returns free
    /// arena memory to the OS. `0` = disabled.
    #[serde(default)]
    pub trim_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub listen: ListenConfig,
    pub domain: DomainConfig,
    #[serde(default)]
    pub script: ScriptConfig,
    #[serde(default)]
    pub registrar: RegistrarConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub log: LogConfig,

    // Optional top-level sections — all `None` when not present.
    // Rust holds them as data; wiring into the runtime happens in later phases.
    /// Public IP advertised in Via/Contact/SDP (e.g. EC2 public IP when binding 0.0.0.0).
    pub advertised_address: Option<String>,

    /// TLS certificate and key for the `listen.tls` listeners.
    pub tls: Option<TlsServerConfig>,

    /// Rate limiting, scanner UA blocking, trusted source CIDRs.
    pub security: Option<SecurityConfig>,

    /// NAT traversal: response Contact rewriting + keepalives (OPTIONS + CRLF).
    pub nat: Option<NatConfig>,

    /// SIP call tracing via HEP (Homer/captAgent).
    pub tracing: Option<TracingConfig>,

    /// Prometheus metrics endpoint.
    pub metrics: Option<MetricsConfig>,

    /// HTTP admin API (health/readiness probes + registration inspection).
    /// `None` = disabled.
    pub admin: Option<AdminConfig>,

    /// External remote-control plane (ARI/ESL-class). `None` = disabled.
    pub control: Option<ControlConfig>,

    /// Server and User-Agent header values injected into responses.
    pub server: Option<ServerIdentityConfig>,

    /// SIP transaction layer timer overrides.
    pub transaction: Option<TransactionConfig>,

    /// Allocator runtime tuning (glibc arena cap + periodic trim). The
    /// `siphon_glibc_*` gauges are always on; this block only adds the optional
    /// bounding knobs. `None` = gauges only, no tuning.
    pub memory: Option<MemoryConfig>,

    /// Dialog state tracking backend.
    pub dialog: Option<DialogConfig>,

    /// Named cache connections available to Python scripts via `cache.fetch(name, key)`.
    pub cache: Option<Vec<NamedCacheConfig>>,

    /// Media proxy (RTPEngine) configuration.
    pub media: Option<MediaConfig>,

    /// Gateway dispatcher (named groups with load balancing + health probing).
    pub gateway: Option<GatewayConfig>,

    /// RFC 4028 session timers for B2BUA mode.
    pub session_timer: Option<SessionTimerConfig>,

    /// B2BUA-wide knobs (header policy, etc.).
    #[serde(default)]
    pub b2bua: B2buaConfig,

    /// Home numbering plan (country code + trunk/international prefixes) that
    /// drives E.164 number normalization for identity headers.
    #[serde(default)]
    pub numbering: crate::numbers::policy::NumberingConfig,

    /// Named number-format policies (`"<name>@<version>" -> policy`) applied by
    /// `request.rewrite_identities()` / `call.dial(number_policy=…)`.
    #[serde(default)]
    pub number_policies:
        std::collections::HashMap<String, crate::numbers::policy::NumberPolicyConfig>,

    /// Operator-defined B2BUA header policies (`"<name>@<version>" -> policy`),
    /// selectable anywhere a built-in preset is: `b2bua.default_header_policy`
    /// and `call.dial(header_policy=…)` / `call.fork(header_policy=…)`.
    ///
    /// Each entry either extends a built-in preset or declares both directions
    /// in full; see
    /// [`HeaderPolicyConfig`](crate::b2bua::header_policy::HeaderPolicyConfig).
    /// Resolved and validated at load by
    /// [`Self::validate_header_policies`], so a policy that could never work
    /// stops the node at boot rather than at the first call across the
    /// boundary it was meant to guard.
    #[serde(default)]
    pub header_policies:
        std::collections::HashMap<String, crate::b2bua::header_policy::HeaderPolicyConfig>,

    /// Call Detail Records — billing and accounting.
    pub cdr: Option<CdrYamlConfig>,

    /// Outbound registration (UAC registrant) — maintain REGISTER bindings to upstream.
    pub registrant: Option<RegistrantYamlConfig>,

    /// Lawful Intercept — ETSI X1/X2/X3 + SIPREC (RFC 7866).
    pub lawful_intercept: Option<LawfulInterceptConfig>,

    /// Diameter peer connections and application routing table.
    pub diameter: Option<DiameterConfig>,

    /// IPsec SA management for P-CSCF (3GPP TS 33.203).
    pub ipsec: Option<IpsecConfig>,

    /// STIR/SHAKEN caller-ID attestation (RFC 8224/8225/8226, ATIS-1000074).
    /// Drives the `stir` Python namespace (`stir.sign()` / `stir.verify()`).
    pub stir: Option<StirConfig>,

    /// Initial Filter Criteria (3GPP TS 29.228) — S-CSCF iFC evaluation.
    pub isc: Option<IscConfig>,

    /// 5G SBI client configuration (Npcf, Nchf).
    pub sbi: Option<SbiYamlConfig>,

    /// Least-Cost Routing (LCR) external HTTP API. Drives the `lcr` Python
    /// namespace (`await lcr.route(call)`) — B2BUA-only. The API owns the
    /// cost-order decision; siphon caches it and executes the ordered route
    /// set against the `gateway` health/failover machinery.
    pub lcr: Option<LcrConfig>,

    /// Session Recording Server (SRS) — receive SIPREC INVITEs and record calls.
    pub srs: Option<SrsConfig>,

    /// Generic SUBSCRIBE dialog state (``proxy.subscribe_state``).  When
    /// ``cache`` references a configured named cache, dialogs are
    /// persisted through it so they survive restarts and are visible to
    /// other replicas.
    pub subscribe_state: Option<SubscribeStateConfig>,

    /// Rf offline-charging configuration (3GPP TS 32.299).  Drives
    /// automatic ACR-START / ACR-INTERIM / ACR-STOP on B2BUA and proxy
    /// call lifecycle events, plus ACR-EVENT for REGISTER.  When
    /// ``None`` (default), Rf is fully off — scripts can still call
    /// ``diameter.rf_acr_*`` manually as long as a Diameter peer is
    /// connected.
    pub rf: Option<RfConfig>,

    /// Ro online charging (Diameter Credit-Control, RFC 8506 / TS 32.299).
    /// When present and `enabled`, siphon reserves credit at call setup,
    /// re-authorizes on a configurable cadence (SCUR, voice) and does one-shot
    /// event charging for SMS/RCS (IEC). Absent/`enabled: false` = no online
    /// charging; scripts can still call ``diameter.ro_ccr_*`` manually.
    pub ro: Option<RoConfig>,

    /// Free-form per-extension configuration. Each entry's value is opaque
    /// to siphon-core and is interpreted by the extension that owns the
    /// name. A scalar string is conventionally treated as a path to a
    /// further configuration file; any other YAML form (mapping, sequence,
    /// number, bool) is passed through verbatim.
    ///
    /// ```yaml
    /// extensions:
    ///   foo: /etc/siphon/foo.yaml          # path form
    ///   bar:                                # inline form
    ///     listen: "0.0.0.0:8080"
    ///     workers: 4
    /// ```
    ///
    /// Extensions read their entry via [`Config::extension_path`] (when
    /// they expect an external file) or [`Config::extension_config`]
    /// (when they consume the value directly).
    #[serde(default)]
    pub extensions: Option<IndexMap<String, serde_yaml_ng::Value>>,
}

// ---------------------------------------------------------------------------
// Serde defaults shared across sections
// ---------------------------------------------------------------------------

fn bool_true() -> bool {
    true
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .map_err(|e| SiphonError::Config(format!("cannot read siphon.yaml: {e}")))?;
        let expanded = expand_env_vars(&content);
        let mut config = Self::from_str_raw(&expanded)?;
        config.anchor_script_paths(path);
        Ok(config)
    }

    /// Re-anchor a relative `script.path` / `script.include_paths` on the
    /// directory holding the config file.
    ///
    /// Both are resolved against the process working directory
    /// (`ScriptEngine::new` does `PathBuf::from(&config.path)`), which is fine
    /// when siphon is started from its config directory and wrong under any
    /// supervisor. systemd hands a unit `/` as its working directory, so the
    /// packaged `script.path: "scripts/proxy_default.py"` resolves to
    /// `/scripts/proxy_default.py`, the script load fails, and the service
    /// restart-loops — while the identical config starts by hand from
    /// `/etc/siphon`. Same trap for a container `WORKDIR` and for an embedding
    /// binary that chdirs.
    ///
    /// A relative entry therefore now prefers the config-relative location, the
    /// way nginx and Kamailio resolve a relative include. The rewrite only
    /// happens when the candidate actually exists, so a config that relies on
    /// the working directory keeps resolving exactly as before — this can make
    /// a previously-failing config start, never the reverse.
    ///
    /// Only applies to `from_file`: `from_str` has no file to anchor on.
    fn anchor_script_paths(&mut self, config_path: &Path) {
        let Some(config_dir) = config_path.parent() else {
            return;
        };
        // A bare `siphon.yaml` yields an empty parent, which would turn every
        // relative path into itself — nothing to anchor on.
        if config_dir.as_os_str().is_empty() {
            return;
        }

        let anchor = |value: &mut String| {
            if Path::new(&*value).is_absolute() {
                return;
            }
            let candidate = config_dir.join(&*value);
            if candidate.exists() {
                *value = candidate.to_string_lossy().into_owned();
            }
        };

        anchor(&mut self.script.path);
        for include_path in &mut self.script.include_paths {
            anchor(include_path);
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(yaml: &str) -> Result<Self> {
        let expanded = expand_env_vars(yaml);
        Self::from_str_raw(&expanded)
    }

    /// Parse YAML without env-var expansion (used after expansion is already done).
    fn from_str_raw(yaml: &str) -> Result<Self> {
        let config: Self = serde_yaml_ng::from_str(yaml)
            .map_err(|e| SiphonError::Config(format!("invalid siphon.yaml: {e}")))?;
        config.validate_backends()?;
        config.validate_cdr()?;
        config.validate_control_app_events()?;
        config.validate_control_apps()?;
        config.validate_control_inbound()?;
        config.validate_media_profiles()?;
        config.validate_header_policies()?;
        config.validate_lawful_intercept()?;
        config.validate_max_message_bytes()?;
        config.validate_control_tls()?;
        config.validate_control_connect_urls()?;
        Ok(config)
    }

    /// Reject a `control.tls` block siphon cannot serve.
    ///
    /// At load, because the alternative is a control listener that binds, looks
    /// healthy, and fails every handshake — which reads to an operator as a
    /// broken client rather than an unreadable key file. `control.tls` without
    /// `control.listen` is refused too: it says the operator believes the rail
    /// is encrypted, and there is no inbound rail at all.
    fn validate_control_tls(&self) -> Result<()> {
        let Some(control) = &self.control else {
            return Ok(());
        };
        let Some(tls) = &control.tls else {
            return Ok(());
        };
        if control.listen.is_none() {
            return Err(SiphonError::Config(
                "control.tls is set but control.listen is not — there is no inbound control \
                 listener to terminate TLS on. Remove control.tls, or add control.listen."
                    .to_string(),
            ));
        }
        crate::transport::tls::server_config(
            &tls.certificate,
            &tls.private_key,
            tls.client_ca.as_deref(),
            "control.tls",
        )
        .map_err(|error| SiphonError::Config(error.to_string()))?;
        Ok(())
    }

    /// Reject a per-call-connect app whose `connect_url` siphon cannot dial, and
    /// a `ca_file` that is not a readable CA bundle.
    ///
    /// At load rather than at the first handover: a controller siphon cannot
    /// reach means every handed-over call ends on the handoff default, so the
    /// box comes up healthy and answers every call with its timeout. That reads
    /// as a controller outage, not as a typo in a URL.
    fn validate_control_connect_urls(&self) -> Result<()> {
        let Some(control) = &self.control else {
            return Ok(());
        };
        for app in &control.apps {
            let Some(connect_url) = app.connect_url.as_deref() else {
                continue;
            };
            let target =
                crate::control::outbound::parse_connect_url(connect_url).map_err(|error| {
                    SiphonError::Config(format!(
                        "control.apps[{}].connect_url {connect_url:?}: {error}",
                        app.name
                    ))
                })?;
            match (&app.ca_file, target.tls) {
                // A CA bundle on a ws:// app is not merely redundant: it says
                // the operator believes this connection is verified, and it
                // is not encrypted at all.
                (Some(ca_file), false) => {
                    return Err(SiphonError::Config(format!(
                        "control.apps[{}] sets ca_file {ca_file:?} but its connect_url is                          ws://, which is not encrypted — use wss:// or drop the ca_file",
                        app.name
                    )))
                }
                (Some(ca_file), true) => {
                    crate::transport::client_tls::client_config(Some(ca_file)).map_err(
                        |error| {
                            SiphonError::Config(format!(
                                "control.apps[{}].ca_file: {error}",
                                app.name
                            ))
                        },
                    )?;
                }
                (None, _) => {}
            }
        }
        Ok(())
    }

    /// Reject a message-size ceiling too small to carry a SIP message.
    ///
    /// The ceiling bounds what one stream connection can make siphon buffer,
    /// so it is load-bearing for availability. A value below
    /// [`MIN_MAX_MESSAGE_BYTES`] would refuse ordinary INVITEs — an operator
    /// typo that turns into a total outage — so it is refused at load rather
    /// than answering 513 to every call.
    fn validate_max_message_bytes(&self) -> Result<()> {
        let Some(limit) = self.security.as_ref().and_then(|sec| sec.max_message_bytes) else {
            return Ok(());
        };
        if limit < MIN_MAX_MESSAGE_BYTES {
            return Err(SiphonError::Config(format!(
                "security.max_message_bytes is {limit}, below the {MIN_MAX_MESSAGE_BYTES} byte \
                 floor — a SIP INVITE with authentication and SDP does not fit, so every call \
                 would be answered 513 Message Too Large. Raise it or remove the field to take \
                 the default."
            )));
        }
        Ok(())
    }

    /// Reject an X3 content-delivery configuration the media backend cannot honour.
    ///
    /// X1 and X2 are backend-independent — provisioning is HTTPS and IRI is
    /// SIP signalling, so both behave identically on `rtpengine`, `rtpproxy`
    /// and `siphon-rtp`. X3 carries the content of communication, and the
    /// TS 103 221-2 framing lives in the media engine, so only the native
    /// `siphon-rtp` backend can emit it.
    ///
    /// | `deliveryType` | rtpengine | rtpproxy | siphon-rtp |
    /// |---|---|---|---|
    /// | `X2Only`  | yes | yes | yes |
    /// | `X3Only`  | no  | no  | yes |
    /// | `X2andX3` | no  | no  | yes |
    ///
    /// Refused at load rather than at the first warrant, following
    /// [`Self::validate_media_profiles`]: name the offending field, the
    /// backend that cannot honour it, and the remedy. The same rule is applied
    /// again at `ActivateTask`, because a task can be provisioned long after
    /// boot.
    fn validate_lawful_intercept(&self) -> Result<()> {
        let Some(lawful_intercept) = &self.lawful_intercept else {
            return Ok(());
        };
        if !lawful_intercept.enabled {
            return Ok(());
        }
        // `enabled: false` is the same as no block at all, so a node that has
        // turned content off is not held to the backend requirement.
        if !lawful_intercept.x3.as_ref().is_some_and(|x3| x3.enabled) {
            return Ok(());
        }

        let backend = self
            .media
            .as_ref()
            .map(|media| media.backend)
            .unwrap_or_default();
        if backend == MediaBackendKind::SiphonRtp {
            return Ok(());
        }

        Err(SiphonError::Config(format!(
            "lawful_intercept.x3 is configured, but media.backend is {:?}, which cannot \
             deliver X3 content of communication — ETSI TS 103 221-2 content framing is \
             implemented in the siphon-rtp media engine only. Set media.backend to \
             \"siphon-rtp\", or remove lawful_intercept.x3 and provision X2Only warrants \
             (X1 provisioning and X2 IRI delivery work on every backend).",
            backend.as_str(),
        )))
    }

    /// Refuse a `backend:` selector nothing dispatches to.
    ///
    /// Each of these deserialized happily and then did nothing useful at
    /// runtime: `registrar.backend: python` fell through to the in-memory arm,
    /// so registrations silently did not persist, and the two unimplemented
    /// `auth.backend` values made every credential check return
    /// `Unavailable`, so nobody could authenticate. Both failures surfaced at
    /// the first request rather than at startup, which is the wrong end: an
    /// option an operator can select has to either work or refuse to boot.
    fn validate_backends(&self) -> Result<()> {
        if self.registrar.backend == RegistrarBackendType::Python {
            return Err(SiphonError::Config(
                "registrar.backend: python selects a custom-hook backend that does not exist — \
                 there are no `@registrar.on_save` / `@registrar.on_lookup` hooks, and the \
                 setting silently behaved as `memory`, so registrations were not persisted. \
                 Use \"redis\" or \"postgres\" for shared persistence, or \"memory\" to be \
                 explicit about keeping bindings in-process."
                    .to_string(),
            ));
        }

        match self.auth.backend {
            AuthBackendType::Static | AuthBackendType::Http => Ok(()),
            AuthBackendType::Database => self.validate_database_auth(),
            AuthBackendType::DiameterCx => Err(SiphonError::Config(
                "auth.backend: diameter_cx is not a dispatchable backend — Cx MAR/MAA \
                 authentication is reachable from a script through \
                 `auth.require_ims_digest()`, which uses the `diameter:` peer configuration \
                 directly. Set auth.backend to \"static\" or \"http\" and call \
                 `require_ims_digest()` from the REGISTER handler."
                    .to_string(),
            )),
        }
    }

    /// Reject a CDR block that names its sinks twice.
    ///
    /// `backend` and `backends` are two ways to say the same thing, and picking
    /// one silently would send records somewhere the operator did not intend —
    /// either losing the collector or losing the durable file. Both spellings
    /// are named in the error so it is obvious which line to delete.
    fn validate_cdr(&self) -> Result<()> {
        let Some(cdr) = &self.cdr else {
            return Ok(());
        };
        if cdr.backend.is_some() && !cdr.backends.is_empty() {
            return Err(SiphonError::Config(format!(
                "cdr sets both `backend: {}` and `backends` ({} sink(s)) — they are two \
                 spellings of the same setting and siphon will not guess which one you meant. \
                 Keep `backends` for several sinks, or `backend` for one.",
                cdr.backend.as_deref().unwrap_or(""),
                cdr.backends.len()
            )));
        }
        Ok(())
    }

    /// Reject a `database` auth backend that cannot answer a credential lookup.
    ///
    /// Both failures here fail *closed* at runtime — no credential source means
    /// every digest check is `Unavailable`, so no subscriber registers — and a
    /// box that comes up healthy and rejects every REGISTER is worse than one
    /// that refuses to start.
    fn validate_database_auth(&self) -> Result<()> {
        let Some(database) = &self.auth.database else {
            return Err(SiphonError::Config(
                "auth.backend: database needs an `auth.database` block naming the \
                 connection URL and the query that returns the credential. Without one \
                 there is no credential source, so every digest check would fail and no \
                 subscriber could register."
                    .to_string(),
            ));
        };
        if !cfg!(feature = "postgres-backend") {
            return Err(SiphonError::Config(
                "auth.backend: database needs the `postgres-backend` cargo feature, which \
                 this binary was built without. Rebuild with it (it is on by default), or \
                 use \"static\" with `auth.users` or \"http\" with an `auth.http` endpoint."
                    .to_string(),
            ));
        }
        if !database.query.contains("$1") {
            return Err(SiphonError::Config(format!(
                "auth.database.query does not reference $1, so the digest username is never \
                 bound and the same credential would be returned for every subscriber. \
                 Query: {:?}",
                database.query
            )));
        }
        Ok(())
    }

    /// Reject an app-level event class siphon does not publish.
    ///
    /// A typo here is silent: the app subscribes to nothing, waits for events
    /// that never come, and there is no request/reply to carry the mistake
    /// back — `events` is read at start-up, not asked for at run time.
    fn validate_control_app_events(&self) -> Result<()> {
        const KNOWN: &[&str] = &["registration"];
        let Some(control) = &self.control else {
            return Ok(());
        };
        for app in &control.apps {
            for class in &app.events {
                if !KNOWN.contains(&class.as_str()) {
                    return Err(SiphonError::Config(format!(
                        "control.apps[{:?}].events names {class:?}, which siphon does not \
                         publish — the classes are: {}. An app subscribed to a name nothing \
                         sends waits forever and is told nothing.",
                        app.name,
                        KNOWN.join(", ")
                    )));
                }
            }
        }
        Ok(())
    }

    /// Reject a control-loss policy siphon does not implement.
    ///
    /// `fallback` parsed and then behaved as `hangup`, because re-dispatching a
    /// call through the Python handlers was never built. An operator who set it
    /// to keep calls alive when a controller dies got exactly the opposite, on
    /// every call, with nothing in the logs to say so.
    fn validate_control_apps(&self) -> Result<()> {
        let Some(control) = &self.control else {
            return Ok(());
        };
        for app in &control.apps {
            let Some(policy) = app.on_lost.as_deref() else {
                continue;
            };
            if policy != "hangup" && policy != "continue" {
                return Err(SiphonError::Config(format!(
                    "control.apps[{:?}].on_lost is {policy:?}, which siphon does not implement \
                     — it is \"hangup\" (end the call, the default) or \"continue\" (leave it \
                     running without an owner). {}",
                    app.name,
                    if policy == "fallback" {
                        "`fallback` would re-dispatch through the Python handlers, which does \
                         not exist; it behaved as `hangup`."
                    } else {
                        ""
                    }
                )));
            }
        }
        Ok(())
    }

    /// Reject a `control.inbound` that names an application nothing serves.
    ///
    /// Every inbound call would be handed to an app that cannot exist, and the
    /// handoff default would fire on each one — a deployment that answers every
    /// call with its timeout default, which is worse than refusing to start.
    fn validate_control_inbound(&self) -> Result<()> {
        let Some(control) = &self.control else {
            return Ok(());
        };
        let Some(inbound) = &control.inbound else {
            return Ok(());
        };
        if inbound.app.is_empty() {
            return Err(SiphonError::Config(
                "control.inbound.app is empty — name the application every inbound INVITE is \
                 handed to."
                    .to_string(),
            ));
        }
        if !control.apps.iter().any(|app| app.name == inbound.app) {
            let known: Vec<&str> = control.apps.iter().map(|app| app.name.as_str()).collect();
            return Err(SiphonError::Config(format!(
                "control.inbound.app is {:?}, which is not one of the configured control.apps \
                 ({}). Every inbound call would be handed to an application that cannot \
                 connect.",
                inbound.app,
                if known.is_empty() {
                    "none are configured".to_string()
                } else {
                    known.join(", ")
                }
            )));
        }
        if let Some(mode) = inbound.mode.as_deref() {
            if mode != "deferred" && mode != "answer" {
                return Err(SiphonError::Config(format!(
                    "control.inbound.mode is {mode:?} — it is \"deferred\" (hold the INVITE \
                     unanswered) or \"answer\" (answer and anchor media first)."
                )));
            }
        }
        Ok(())
    }

    /// Reject a media profile asking for something `media.backend` cannot do.
    ///
    /// Runs on every load path (`from_file` and `from_str` both route through
    /// `from_str_raw`), so a misconfigured box fails to start instead of coming
    /// up healthy and answering calls into a media path that was never wired.
    ///
    /// Only covers operator-declared `media.profiles` — a built-in profile is
    /// registered regardless of backend, so a script naming one the backend
    /// cannot honour is caught at the call instead (see the `rtpengine` script
    /// API's profile resolution).
    fn validate_media_profiles(&self) -> Result<()> {
        let Some(media) = &self.media else {
            return Ok(());
        };

        // Sorted so the error text is deterministic across runs (HashMap order).
        let mut names: Vec<&String> = media.profiles.keys().collect();
        names.sort_unstable();

        for name in names {
            let Some(profile) = media.profiles.get(name) else {
                continue;
            };
            for (direction, flags) in [("offer", &profile.offer), ("answer", &profile.answer)] {
                let unsupported = media.backend.unsupported_profile_fields(flags);
                if !unsupported.is_empty() {
                    return Err(SiphonError::Config(format!(
                        "media profile {name:?} sets {} on its {direction} flags, which the \
                         {} backend cannot honour — remove {} or set media.backend to a \
                         backend that supports {}",
                        unsupported.join(", "),
                        media.backend.as_str(),
                        if unsupported.len() == 1 {
                            "the field"
                        } else {
                            "those fields"
                        },
                        if unsupported.len() == 1 { "it" } else { "them" },
                    )));
                }

                // The engine refuses an out-of-range value at the control
                // plane — that is, on every media offer, at call time, on a
                // node that came up reporting perfectly healthy. Catching it
                // here turns "every call fails" into a boot failure that names
                // the profile.
                //
                // Which range applies depends on echo_long_tail: with it set
                // the field is a tail length rather than a search window, and
                // the engine checks it against a different bound. This used to
                // check one hardcoded 16..=1000 for both, which was the engine's
                // window range and not its tail range — so a long-tail profile
                // asking for 513-1000 passed here, loaded, registered, reported
                // healthy, and then failed every call with a 503, while the
                // error text named a range the engine did not accept. The
                // bounds now come from the proto crate both sides already
                // depend on: the two happen to coincide today, and restating
                // the digits is exactly how they came to disagree before.
                if let Some(window) = flags.echo_delay_search_ms {
                    let (low, high, meaning) = if flags.echo_long_tail {
                        (
                            siphon_rtp_proto::ECHO_LONG_TAIL_MS_MIN,
                            siphon_rtp_proto::ECHO_LONG_TAIL_MS_MAX,
                            "a tail length, because echo_long_tail is set",
                        )
                    } else {
                        (
                            siphon_rtp_proto::ECHO_DELAY_SEARCH_MS_MIN,
                            siphon_rtp_proto::ECHO_DELAY_SEARCH_MS_MAX,
                            "a search window",
                        )
                    };
                    if !(low..=high).contains(&window) {
                        return Err(SiphonError::Config(format!(
                            "media profile {name:?} sets echo_delay_search_ms to {window} on its \
                             {direction} flags, outside the {low}-{high} ms the engine accepts \
                             for {meaning} — it refuses the value on every offer, so a node \
                             carrying this config starts healthy and then fails every call"
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Reject a `header_policies:` entry that cannot compile, and a
    /// `b2bua.default_header_policy` that names no known policy.
    ///
    /// Runs on every load path, so a policy with a typo in an op token, a rule
    /// aimed at a framework-managed header, or a name nothing defines stops the
    /// node at boot. The default in particular used to warn and silently fall
    /// back to `transparent-b2bua@2026` — which is the *most* permissive
    /// posture, so a typo in the name of a trust-boundary control opened the
    /// boundary instead of closing it, on a node that came up reporting healthy.
    fn validate_header_policies(&self) -> Result<()> {
        let registry = crate::b2bua::header_policy::build_registry(&self.header_policies)
            .map_err(|error| SiphonError::Config(error.to_string()))?;

        let name = self.b2bua.resolved_default_header_policy();
        if !registry.contains_key(name) {
            let mut known: Vec<&str> = registry.keys().map(String::as_str).collect();
            known.sort_unstable();
            return Err(SiphonError::Config(format!(
                "b2bua.default_header_policy {name:?} names no known header policy — define it \
                 under header_policies:, or pick one of: {}",
                known.join(", ")
            )));
        }

        Ok(())
    }

    /// Returns true if the given host/IP is one of our configured local domains.
    pub fn is_local(&self, host: &str) -> bool {
        self.domain.local.iter().any(|d| d == host)
    }

    /// Path-form accessor for an extension entry.
    ///
    /// Returns `Some(path)` when the entry exists and its value is a YAML
    /// scalar string (the conventional form for "load my config from this
    /// file"). Returns `None` when the entry is absent or its value is an
    /// inline mapping/sequence — extensions that accept inline config
    /// should call [`Config::extension_config`] instead and walk the
    /// `serde_yaml_ng::Value` themselves.
    pub fn extension_path(&self, name: &str) -> Option<&Path> {
        self.extensions.as_ref()?.get(name)?.as_str().map(Path::new)
    }

    /// Raw-value accessor for an extension entry. Returns the entry's
    /// YAML value (any shape) for the extension to interpret. Returns
    /// `None` when the entry is absent.
    pub fn extension_config(&self, name: &str) -> Option<&serde_yaml_ng::Value> {
        self.extensions.as_ref()?.get(name)
    }
}
