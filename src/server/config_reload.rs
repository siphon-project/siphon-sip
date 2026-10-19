//! The reloader behind `POST /admin/config/reload`.
//!
//! Reads the file passed to `--config` again, validates it in full exactly as
//! startup does, and compares its document with the one the node is running.
//! Each top-level section is reported: `unchanged`, `applied` (every change in
//! it took effect now) or `restart_required` (at least one change in it only
//! takes effect on a restart, named by its dotted path).
//!
//! The comparison is of the untyped YAML trees, after `${VAR}` expansion, so a
//! comment, whitespace or key-order edit changes nothing. `server` and
//! `security` are compared one key deeper, because they hold fields that apply
//! at runtime beside fields that do not.
//!
//! A field that applies at runtime is listed in [`HOT_APPLIERS`]. Each applier
//! *builds* its new value from the validated config first; only when every
//! applier touched by the edit has built does any of them install its value,
//! and installing cannot fail. A reload is therefore applied whole or not at
//! all. Listeners, dialogs and transactions are never touched.
//!
//! The running baseline moves forward only for the fields that were applied, so
//! a field that needs a restart keeps being reported on every reload until the
//! process restarts with it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use tracing::{info, warn};

use crate::config::yaml::{Mapping, Value};
use crate::config::{Config, IdentityHeaders, SharedIdentityHeaders};
use crate::security::runtime::SecurityRuntime;
use crate::security::trust::TrustedCidrs;
use crate::security::BanPolicy;

/// Sections compared key by key rather than as a whole.
const SPLIT_SECTIONS: &[&str] = &["server", "security"];

/// Installs a value an applier built. Infallible by construction.
type Install = Box<dyn FnOnce() + Send>;

/// A built value, ready to install, and what building it noticed.
struct Prepared {
    install: Install,
    /// Reported under `warnings`: something in the file was skipped, not
    /// refused (a `trusted_cidrs` entry that is neither a CIDR nor an address).
    warnings: Vec<String>,
}

impl Prepared {
    fn new(install: Install) -> Self {
        Self {
            install,
            warnings: Vec::new(),
        }
    }
}

/// A group of fields that take effect without a restart.
struct HotApplier {
    /// The dotted paths this applier covers (`section.key`).
    paths: &'static [&'static str],
    /// Whether this node holds what the applier writes to. When it does not
    /// (a reloader built without the security runtime), its paths are
    /// reported as needing a restart.
    available: fn(&ReloadTargets) -> bool,
    /// Build the new value from the validated config, returning what installs
    /// it. An error refuses the whole reload with nothing changed.
    prepare: fn(&ReloadTargets, &Config) -> Result<Prepared, String>,
}

/// Every field `POST /admin/config/reload` applies at runtime, installed in
/// this order (the trusted list first, so a control enabled by the same
/// reload starts from it).
const HOT_APPLIERS: &[HotApplier] = &[
    HotApplier {
        paths: &["server.server_header", "server.user_agent_header"],
        available: |_| true,
        prepare: prepare_identity_headers,
    },
    HotApplier {
        paths: &["security.trusted_cidrs"],
        available: has_security,
        prepare: prepare_trusted_cidrs,
    },
    HotApplier {
        paths: &["security.rate_limit", "security.scanner_block"],
        available: has_security,
        prepare: prepare_security_filter,
    },
    HotApplier {
        paths: &["security.failed_auth_ban"],
        available: has_security,
        prepare: prepare_auto_ban,
    },
];

/// The live handles the appliers write to.
pub struct ReloadTargets {
    identity: SharedIdentityHeaders,
    product_name: &'static str,
    product_version: &'static str,
    security: Option<Arc<SecurityRuntime>>,
}

impl ReloadTargets {
    /// `identity` is the instance the dispatcher, UAC and registrant share;
    /// the product name and version give the default for an unset key.
    pub fn new(
        identity: SharedIdentityHeaders,
        product_name: &'static str,
        product_version: &'static str,
    ) -> Self {
        Self {
            identity,
            product_name,
            product_version,
            security: None,
        }
    }

    /// Apply the `security` fields through `runtime`, the one start-up
    /// installed them with. Without it they are reported as needing a restart.
    pub fn with_security(mut self, runtime: Arc<SecurityRuntime>) -> Self {
        self.security = Some(runtime);
        self
    }
}

fn has_security(targets: &ReloadTargets) -> bool {
    targets.security.is_some()
}

fn security_runtime(targets: &ReloadTargets) -> Result<Arc<SecurityRuntime>, String> {
    targets
        .security
        .clone()
        .ok_or_else(|| "no security runtime on this node".to_owned())
}

fn prepare_identity_headers(targets: &ReloadTargets, config: &Config) -> Result<Prepared, String> {
    let headers = Arc::new(IdentityHeaders::resolve(
        config.server.as_ref(),
        targets.product_name,
        targets.product_version,
    ));
    let identity = Arc::clone(&targets.identity);
    Ok(Prepared::new(Box::new(move || identity.store(headers))))
}

fn prepare_trusted_cidrs(targets: &ReloadTargets, config: &Config) -> Result<Prepared, String> {
    let runtime = security_runtime(targets)?;
    let entries = config
        .security
        .as_ref()
        .map_or(&[][..], |security| &security.trusted_cidrs);
    let (networks, invalid) = TrustedCidrs::parse(entries);
    let warnings = invalid
        .iter()
        .map(|entry| {
            format!("security.trusted_cidrs: '{entry}' is neither a CIDR nor an address, skipped")
        })
        .collect();
    Ok(Prepared {
        install: Box::new(move || runtime.apply_trusted(networks)),
        warnings,
    })
}

fn prepare_security_filter(targets: &ReloadTargets, config: &Config) -> Result<Prepared, String> {
    let runtime = security_runtime(targets)?;
    let security = config.security.clone();
    Ok(Prepared::new(Box::new(move || {
        runtime.apply_filter(security.as_ref())
    })))
}

fn prepare_auto_ban(targets: &ReloadTargets, config: &Config) -> Result<Prepared, String> {
    let runtime = security_runtime(targets)?;
    let policy = config
        .security
        .as_ref()
        .and_then(|security| security.failed_auth_ban.as_ref())
        .map(BanPolicy::from_config);
    Ok(Prepared::new(Box::new(move || {
        runtime.apply_auto_ban(policy)
    })))
}

/// Why a reload changed nothing.
#[derive(Debug, thiserror::Error)]
pub enum ConfigReloadError {
    /// The file could not be read, did not parse, or failed validation.
    #[error("{0}")]
    Invalid(String),
    /// The file validated, but a runtime value could not be built from it.
    #[error("{path}: {reason}")]
    Build { path: String, reason: String },
    /// The blocking read did not complete.
    #[error("the config file read did not complete: {0}")]
    Internal(String),
}

/// What became of one top-level section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionStatus {
    /// Nothing in it changed.
    Unchanged,
    /// Every change in it took effect.
    Applied,
    /// At least one change in it takes effect only on a restart.
    RestartRequired,
}

/// One section's outcome. The shape is the same for every status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SectionReport {
    pub status: SectionStatus,
    /// Dotted paths that took effect.
    pub applied: Vec<String>,
    /// Dotted paths that take effect only on a restart.
    pub restart_required: Vec<String>,
}

/// The reply to a reload that validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReloadReport {
    /// Every top-level key of either document, by name.
    pub sections: BTreeMap<String, SectionReport>,
    /// Every applied path, across sections.
    pub applied: Vec<String>,
    /// Every path still waiting on a restart, across sections.
    pub restart_required: Vec<String>,
    /// Notices about the reload that did not stop it.
    pub warnings: Vec<String>,
}

/// Re-reads, validates, diffs and applies the config file.
pub struct ConfigReloader {
    path: PathBuf,
    targets: ReloadTargets,
    /// The document the node is running. The lock also serialises reloads.
    baseline: tokio::sync::Mutex<Value>,
}

impl ConfigReloader {
    /// `baseline` is the document the node started from, as
    /// [`Config::load_with_document`] returned it.
    pub fn new(path: PathBuf, baseline: Value, targets: ReloadTargets) -> Self {
        Self {
            path,
            targets,
            baseline: tokio::sync::Mutex::new(baseline),
        }
    }

    /// Read the file again and apply what can be applied. On an error nothing
    /// changed, the baseline included.
    pub async fn reload(&self) -> Result<ReloadReport, ConfigReloadError> {
        let mut baseline = self.baseline.lock().await;
        let path = self.path.clone();
        let (config, document) =
            tokio::task::spawn_blocking(move || Config::load_with_document(&path))
                .await
                .map_err(|error| ConfigReloadError::Internal(error.to_string()))?
                .map_err(|error| ConfigReloadError::Invalid(error.to_string()))?;

        let changes = diff_documents(&baseline, &document);
        let changed: BTreeSet<&str> = changes.values().flatten().map(String::as_str).collect();

        // Build every value first; install only once all of them have built.
        let mut installs = Vec::new();
        let mut warnings = Vec::new();
        let mut hot = BTreeSet::new();
        for applier in HOT_APPLIERS {
            if !(applier.available)(&self.targets) {
                continue;
            }
            let touched: Vec<&str> = applier
                .paths
                .iter()
                .copied()
                .filter(|path| changed.contains(path))
                .collect();
            if touched.is_empty() {
                continue;
            }
            let prepared = (applier.prepare)(&self.targets, &config).map_err(|reason| {
                ConfigReloadError::Build {
                    path: touched.join(", "),
                    reason,
                }
            })?;
            installs.push(prepared.install);
            warnings.extend(prepared.warnings);
            hot.extend(touched);
        }
        for install in installs {
            install();
        }
        for path in &hot {
            adopt_path(&mut baseline, &document, path);
        }

        let mut report = build_report(changes, &hot);
        for warning in &warnings {
            warn!(file = %self.path.display(), "config reload: {warning}");
        }
        report.warnings = warnings;
        if !report.applied.is_empty() {
            info!(file = %self.path.display(), applied = ?report.applied, "config reloaded");
        }
        if !report.restart_required.is_empty() {
            warn!(
                file = %self.path.display(),
                restart_required = ?report.restart_required,
                "config reload: these changes take effect only on a restart"
            );
        }
        Ok(report)
    }
}

/// The changed dotted paths of each top-level key of either document. An
/// empty list is an unchanged section.
fn diff_documents(old: &Value, new: &Value) -> BTreeMap<String, Vec<String>> {
    let empty = Mapping::new();
    let old = old.as_mapping().unwrap_or(&empty);
    let new = new.as_mapping().unwrap_or(&empty);
    let mut sections = BTreeMap::new();
    for key in old.iter().chain(new.iter()).map(|(key, _)| key) {
        let name = key_name(key);
        if sections.contains_key(&name) {
            continue;
        }
        let before = present(old.get(key));
        let after = present(new.get(key));
        let changed = if SPLIT_SECTIONS.contains(&name.as_str()) {
            diff_section(&name, before, after)
        } else if before == after {
            Vec::new()
        } else {
            vec![name.clone()]
        };
        sections.insert(name, changed);
    }
    sections
}

/// The changed keys of a section compared key by key. A side that is not a
/// mapping (nor absent) is compared whole.
fn diff_section(name: &str, before: Option<&Value>, after: Option<&Value>) -> Vec<String> {
    let empty = Mapping::new();
    fn as_section<'a>(value: Option<&'a Value>, empty: &'a Mapping) -> Option<&'a Mapping> {
        match value {
            None => Some(empty),
            Some(value) => value.as_mapping(),
        }
    }
    let (Some(before), Some(after)) = (as_section(before, &empty), as_section(after, &empty))
    else {
        return vec![name.to_owned()];
    };
    let mut changed = BTreeSet::new();
    for key in before.iter().chain(after.iter()).map(|(key, _)| key) {
        if present(before.get(key)) != present(after.get(key)) {
            changed.insert(format!("{name}.{}", key_name(key)));
        }
    }
    changed.into_iter().collect()
}

/// A key set to null reads as the key not being there.
fn present(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| !value.is_null())
}

fn key_name(key: &Value) -> String {
    match key.as_str() {
        Some(name) => name.to_owned(),
        None => format!("{key:?}"),
    }
}

/// Copy one applied path from `document` into `baseline`, removing it when
/// the new document does not set it.
fn adopt_path(baseline: &mut Value, document: &Value, path: &str) {
    let Some((section, key)) = path.split_once('.') else {
        let new = present(document.get(path)).cloned();
        set_or_remove(baseline, path, new);
        return;
    };
    let new = present(document.get(section).and_then(|section| section.get(key))).cloned();
    if !baseline.is_mapping() {
        *baseline = Value::Mapping(Mapping::new());
    }
    if let Value::Mapping(top) = baseline {
        let entry = top.get(section).filter(|value| value.is_mapping()).cloned();
        let mut section_value = entry.unwrap_or_else(|| Value::Mapping(Mapping::new()));
        set_or_remove(&mut section_value, key, new);
        top.insert(Value::String(section.to_owned()), section_value);
    }
}

fn set_or_remove(target: &mut Value, key: &str, value: Option<Value>) {
    if !target.is_mapping() {
        *target = Value::Mapping(Mapping::new());
    }
    if let Value::Mapping(mapping) = target {
        match value {
            Some(value) => {
                mapping.insert(Value::String(key.to_owned()), value);
            }
            None => {
                mapping.remove(key);
            }
        }
    }
}

fn build_report(changes: BTreeMap<String, Vec<String>>, hot: &BTreeSet<&str>) -> ReloadReport {
    let mut report = ReloadReport {
        sections: BTreeMap::new(),
        applied: Vec::new(),
        restart_required: Vec::new(),
        warnings: Vec::new(),
    };
    for (name, paths) in changes {
        let (applied, restart_required): (Vec<String>, Vec<String>) = paths
            .into_iter()
            .partition(|path| hot.contains(path.as_str()));
        let status = if !restart_required.is_empty() {
            SectionStatus::RestartRequired
        } else if !applied.is_empty() {
            SectionStatus::Applied
        } else {
            SectionStatus::Unchanged
        };
        report.applied.extend(applied.iter().cloned());
        report
            .restart_required
            .extend(restart_required.iter().cloned());
        report.sections.insert(
            name,
            SectionReport {
                status,
                applied,
                restart_required,
            },
        );
    }
    report
}

#[cfg(test)]
#[path = "config_reload_tests.rs"]
mod tests;
