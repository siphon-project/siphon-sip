//! `rf:` offline and `ro:` online charging (3GPP TS 32.299).

use super::default_true;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Rf offline charging (3GPP TS 32.299)
// ---------------------------------------------------------------------------

/// Top-level `rf:` configuration.
///
/// ```yaml
/// rf:
///   enabled: true
///   auto_emit_proxy: true        # ACR-START on 2xx-forward, ACR-STOP on in-dialog BYE
///   auto_emit_b2bua: true        # ACR-START on Answered, ACR-STOP on Bye/Terminated
///   auto_emit_register: true     # ACR-EVENT from registrar on_change
///   interim_interval_secs: 300   # 0 = disabled; CDF ACA-START Acct-Interim-Interval overrides
///   node_functionality: scscf    # scscf | pcscf | icscf | mrfc | mgcf | bgcf | as | ibcf
///   service_context_id: "32260@3gpp.org"   # TS 32.260 IMS = 32260, SMS = 32274, MMTel = 32275
///   peer: cdf1                   # optional explicit peer; default = first 'rf' route, else any peer
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct RfConfig {
    /// Master switch.  Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Emit ACR-START / ACR-INTERIM / ACR-STOP automatically from the
    /// proxy 2xx-forward and in-dialog-BYE paths.  Default: true.
    #[serde(default = "default_true")]
    pub auto_emit_proxy: bool,
    /// Emit ACR-START / ACR-INTERIM / ACR-STOP automatically from B2BUA
    /// `CallEvent::Answered` / `Bye` / `Terminated`.  Default: true.
    #[serde(default = "default_true")]
    pub auto_emit_b2bua: bool,
    /// Emit ACR-EVENT for every registration state change observed on
    /// the registrar's on-change broadcast channel.  Default: true.
    #[serde(default = "default_true")]
    pub auto_emit_register: bool,
    /// Default ACR-INTERIM cadence in seconds when the CDF does not
    /// return an ``Acct-Interim-Interval`` AVP in ACA-START.  Set to 0
    /// to disable periodic INTERIM.  Default: 0 (disabled).
    #[serde(default)]
    pub interim_interval_secs: u32,
    /// Node-Functionality value baked into auto-emitted records
    /// (TS 32.299 §7.2.111 — `scscf`, `pcscf`, `icscf`, `mrfc`, `mgcf`,
    /// `bgcf`, `as`, `ibcf`, `ecscf`, `atcf`, `mmtel`, `tpf`, `atgw`).
    /// Default: ``"scscf"``.
    #[serde(default = "default_rf_node_functionality")]
    pub node_functionality: String,
    /// Service-Context-Id (TS 32.299 §7.2.91).  Default:
    /// ``"32260@3gpp.org"`` (TS 32.260 IMS).
    #[serde(default = "default_rf_service_context_id")]
    pub service_context_id: String,
    /// Explicit Diameter peer name to send ACRs to.  When unset, the
    /// first peer registered with the manager is used (`any_client`).
    pub peer: Option<String>,
}

impl Default for RfConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_emit_proxy: true,
            auto_emit_b2bua: true,
            auto_emit_register: true,
            interim_interval_secs: 0,
            node_functionality: default_rf_node_functionality(),
            service_context_id: default_rf_service_context_id(),
            peer: None,
        }
    }
}

fn default_rf_node_functionality() -> String {
    "scscf".to_string()
}
fn default_rf_service_context_id() -> String {
    "32260@3gpp.org".to_string()
}

/// Ro online charging (Diameter Credit-Control) configuration.
///
/// **B2BUA-only.** Ro enforcement (reserve → re-authorize → *disconnect the
/// call* when credit runs out) requires siphon to own and be able to tear down
/// the session, which is a B2BUA capability. This matches 3GPP: online charging
/// is triggered by the **AS / MMTel-AS** (TS 32.275), never by the P-CSCF (a
/// P-CSCF is an *offline*/Rf node). There is no proxy-mode Ro auto-emit — run
/// the charging siphon as a B2BUA (e.g. an MMTel-AS on ISC). The raw
/// `diameter.ro_ccr_*` scripting API is available in any mode for manual use,
/// but auto-emit + mid-call teardown only fire on B2BUA calls.
///
/// Reserve-before-connect is **script-driven**: a `@b2bua.on_invite` handler
/// calls `await call.ro_authorize(...)` BEFORE `call.dial(...)`. On a grant it
/// dials the B-leg; on a denial it rejects with `credit_denied_status` and no
/// B-leg is ever created (prepaid: no call unless the OCS allows it). siphon
/// then runs the re-auth loop and disconnects mid-call on exhaustion, and sends
/// CCR-TERMINATION on BYE — all autonomously. There is no config auto-emit
/// because the correct prepaid gate has to sit before the script's dial
/// decision (some calls aren't charged at all).
///
/// ```yaml
/// ro:
///   enabled: true
///   reauth_interval_secs: 30      # customer cadence; the OCS-granted quota overrides
///   requested_seconds: 30         # Requested-Service-Unit CC-Time (0 = empty RSU, OCS decides)
///   node_functionality: as        # as (MMTel-AS, standard) | scscf | ...
///   service_context_id: "32260@3gpp.org"       # voice (SCUR); 32275 for MMTel-AS
///   sms_service_context_id: "32274@3gpp.org"   # SMS/RCS (IEC)
///   charge: orig                  # orig | term | both
///   charge_message: true          # one-shot IEC on SIP MESSAGE (SMS/RCS)
///   on_ocs_failure: terminate     # terminate (fail-closed) | continue (fail-open)
///   credit_denied_status: 402     # SIP status when the OCS denies at setup
///   rating_group: 100             # optional; presence selects the MSCC (multi-service) shape
///   peer: ocs1                    # optional explicit OCS peer
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct RoConfig {
    /// Master switch. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Fallback re-authorization cadence (seconds) when the OCS grants no
    /// CC-Time / Validity-Time. The OCS-granted quota is authoritative and
    /// overrides this. Default: 30.
    #[serde(default = "default_ro_interval")]
    pub reauth_interval_secs: u32,
    /// Requested-Service-Unit CC-Time (seconds) asked for on CCR-INITIAL/UPDATE.
    /// 0 = emit an empty RSU and let the OCS decide the quota. Default: 30.
    #[serde(default = "default_ro_interval")]
    pub requested_seconds: u32,
    /// Node-Functionality for the IMS-Information (TS 32.299 §7.2.111). The
    /// textbook Ro trigger is the AS/S-CSCF; `pcscf` reflects edge enforcement.
    /// Default: ``"pcscf"``.
    #[serde(default = "default_ro_node_functionality")]
    pub node_functionality: String,
    /// Service-Context-Id for voice SCUR (TS 32.260). Default ``"32260@3gpp.org"``.
    #[serde(default = "default_rf_service_context_id")]
    pub service_context_id: String,
    /// Service-Context-Id for SMS/RCS IEC (TS 32.274). Default ``"32274@3gpp.org"``.
    #[serde(default = "default_ro_sms_service_context_id")]
    pub sms_service_context_id: String,
    /// Which party to charge: ``"orig"`` | ``"term"`` | ``"both"``. Default ``"orig"``.
    #[serde(default = "default_ro_charge")]
    pub charge: String,
    /// When the chargeable clock starts: ``"answer"`` | ``"invite"``.
    /// Default ``"answer"``.
    ///
    /// ``answer`` counts reported usage from the 200 OK, which is what
    /// TS 32.260 means by chargeable duration. ``invite`` counts from the
    /// CCR-INITIAL — i.e. from the reservation, before any carrier was dialled
    /// — so ring time is billed. That was the only behaviour before this
    /// setting existed; it is kept for anyone who depended on it.
    ///
    /// Only the clock moves. The reservation still happens at INVITE, because
    /// reserve-before-connect is the entire point of the prepaid gate.
    #[serde(default = "default_ro_charge_from")]
    pub charge_from: String,
    /// One-shot IEC charging on SIP MESSAGE (SMS/RCS). Default: true.
    #[serde(default = "default_true")]
    pub charge_message: bool,
    /// Behavior when the OCS is unreachable / times out (Credit-Control-Failure-
    /// Handling): ``"terminate"`` (fail-closed) | ``"continue"`` (fail-open).
    /// Default ``"terminate"``.
    #[serde(default = "default_ro_ocs_failure")]
    pub on_ocs_failure: String,
    /// SIP status returned when the OCS denies credit at setup. Default: 402.
    #[serde(default = "default_ro_denied_status")]
    pub credit_denied_status: u16,
    /// Optional Rating-Group. When set (or `service_identifier`), the CCR uses
    /// the multi-service MSCC shape; otherwise single-service command-level.
    pub rating_group: Option<u32>,
    /// Optional Service-Identifier.
    pub service_identifier: Option<u32>,
    /// Explicit OCS peer name. When unset, the first registered peer is used.
    pub peer: Option<String>,
}

impl Default for RoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            reauth_interval_secs: default_ro_interval(),
            requested_seconds: default_ro_interval(),
            node_functionality: default_ro_node_functionality(),
            service_context_id: default_rf_service_context_id(),
            sms_service_context_id: default_ro_sms_service_context_id(),
            charge: default_ro_charge(),
            charge_from: default_ro_charge_from(),
            charge_message: true,
            on_ocs_failure: default_ro_ocs_failure(),
            credit_denied_status: default_ro_denied_status(),
            rating_group: None,
            service_identifier: None,
            peer: None,
        }
    }
}

fn default_ro_interval() -> u32 {
    30
}
fn default_ro_node_functionality() -> String {
    "pcscf".to_string()
}
fn default_ro_sms_service_context_id() -> String {
    "32274@3gpp.org".to_string()
}
/// Chargeable duration runs from the answer (TS 32.260 §5): a call that rings
/// and is never answered has no chargeable duration at all.
fn default_ro_charge_from() -> String {
    "answer".to_string()
}

fn default_ro_charge() -> String {
    "orig".to_string()
}
fn default_ro_ocs_failure() -> String {
    "terminate".to_string()
}
fn default_ro_denied_status() -> u16 {
    402
}
