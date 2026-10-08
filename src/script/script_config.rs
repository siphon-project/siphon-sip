//! Operator-supplied structured configuration for the script: `script_config:`.
//!
//! A script holds dispatch logic. The tables that logic walks (routes, rule
//! lists, policy) belong to whoever operates the node, and change on a
//! different schedule than the code. This is where they live: a YAML document,
//! either inline under `script_config:` in `siphon.yaml` or in a file of its
//! own that the key names, read from the script through `siphon.config`.
//!
//! The document is held as one immutable snapshot behind an [`ArcSwap`]. A
//! reader takes the whole snapshot or none of it, so a lookup running on one
//! thread while a reload lands on another sees either the old document or the
//! new one, never a mix. A file that stops parsing does not replace anything:
//! the last good snapshot keeps serving and the failure is logged.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use serde_yaml_ng::{Mapping, Value};
use tracing::{debug, error, info, warn};

use crate::config::expand_env_vars;
use crate::error::{Result, SiphonError};

/// How long the watcher waits for one write burst to finish before it reads
/// the file. Same reasoning, and same value, as the script watcher's.
const COALESCE_WINDOW: Duration = Duration::from_millis(250);

/// Why a dotted key did not resolve to a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    /// A mapping on the way has no such key, or a sequence no such index.
    Missing {
        /// The key the caller asked for.
        key: String,
        /// The dotted prefix that does exist ("" for the document root).
        parent: String,
        /// The segment that was not found under `parent`.
        segment: String,
    },
    /// The path runs through a value that has no children.
    NotAContainer {
        /// The key the caller asked for.
        key: String,
        /// The dotted prefix that resolved to a scalar.
        parent: String,
        /// What that prefix holds: "a string", "a number", …
        found: &'static str,
    },
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LookupError::Missing {
                key,
                parent,
                segment,
            } => {
                write!(formatter, "script_config key {key:?} is not set")?;
                if parent.is_empty() {
                    write!(formatter, " (no {segment:?} at the top level)")
                } else {
                    write!(formatter, " (no {segment:?} under {parent:?})")
                }
            }
            LookupError::NotAContainer { key, parent, found } => write!(
                formatter,
                "script_config key {key:?} is not set ({parent:?} is {found}, not a mapping or a \
                 sequence)"
            ),
        }
    }
}

impl std::error::Error for LookupError {}

/// What a YAML value is, in the words an error message wants.
pub fn describe(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Sequence(_) => "a sequence",
        Value::Mapping(_) => "a mapping",
        Value::Tagged(_) => "a tagged value",
    }
}

/// Resolve `dotted_key` against `root`.
///
/// Each `.`-separated segment descends one level: into a mapping by key, into a
/// sequence by zero-based index. A mapping key written as an integer in YAML
/// (`31: ...`) is matched by the segment `31`. The empty key is the whole
/// document. A key that itself contains a dot cannot be named this way; fetch
/// its parent and index that.
pub fn lookup<'a>(
    root: &'a Value,
    dotted_key: &str,
) -> std::result::Result<&'a Value, LookupError> {
    if dotted_key.is_empty() {
        return Ok(root);
    }

    let mut current = root;
    let mut consumed = 0usize;
    for segment in dotted_key.split('.') {
        let parent = dotted_key[..consumed].trim_end_matches('.');
        let next = match current {
            Value::Mapping(mapping) => mapping_child(mapping, segment),
            Value::Sequence(items) => Some(segment)
                .filter(|segment| is_decimal(segment))
                .and_then(|segment| segment.parse::<usize>().ok())
                .and_then(|index| items.get(index)),
            other => {
                return Err(LookupError::NotAContainer {
                    key: dotted_key.to_owned(),
                    parent: parent.to_owned(),
                    found: describe(other),
                });
            }
        };
        current = next.ok_or_else(|| LookupError::Missing {
            key: dotted_key.to_owned(),
            parent: parent.to_owned(),
            segment: segment.to_owned(),
        })?;
        consumed += segment.len() + 1;
    }
    Ok(current)
}

/// The child of `mapping` a path segment names: the string key first, then the
/// integer key the same text spells.
fn mapping_child<'a>(mapping: &'a Mapping, segment: &str) -> Option<&'a Value> {
    if let Some(value) = mapping.get(segment) {
        return Some(value);
    }
    if !is_decimal(segment.strip_prefix('-').unwrap_or(segment)) {
        return None;
    }
    if let Ok(number) = segment.parse::<u64>() {
        return mapping.get(Value::Number(number.into()));
    }
    if let Ok(number) = segment.parse::<i64>() {
        return mapping.get(Value::Number(number.into()));
    }
    None
}

/// Whether `text` is one or more ASCII digits and nothing else. `str::parse`
/// alone also takes a leading `+`, and the segment `+31` names the string key
/// `"+31"`, a dialling prefix, not the integer key `31`.
fn is_decimal(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Check a parsed document is one a script can be handed as plain data, and
/// return it with an empty document normalised to an empty mapping.
///
/// The top level has to be a mapping, because every lookup is by key. Mapping
/// keys have to be scalars, because they become `dict` keys. Tags are refused
/// rather than dropped: `!!binary` or a custom tag silently turning into its
/// untagged content is a table that does not mean what its author wrote.
fn validated_document(document: Value) -> std::result::Result<Value, String> {
    let document = match document {
        Value::Null => Value::Mapping(Mapping::new()),
        other => other,
    };
    if !document.is_mapping() {
        return Err(format!(
            "the top level must be a mapping, found {}",
            describe(&document)
        ));
    }
    validate_value(&document, "")?;
    Ok(document)
}

fn validate_value(value: &Value, location: &str) -> std::result::Result<(), String> {
    let place = |child: &str| {
        if location.is_empty() {
            child.to_owned()
        } else {
            format!("{location}.{child}")
        }
    };
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
        Value::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                validate_value(item, &place(&index.to_string()))?;
            }
            Ok(())
        }
        Value::Mapping(mapping) => {
            for (key, child) in mapping {
                let name = match key {
                    Value::String(text) => text.clone(),
                    Value::Number(number) => number.to_string(),
                    Value::Bool(flag) => flag.to_string(),
                    other => {
                        return Err(format!(
                            "a mapping key must be a string, a number or a boolean, found {} {}",
                            describe(other),
                            if location.is_empty() {
                                "at the top level".to_owned()
                            } else {
                                format!("under {location:?}")
                            }
                        ));
                    }
                };
                validate_value(child, &place(&name))?;
            }
            Ok(())
        }
        Value::Tagged(tagged) => Err(format!(
            "YAML tags are not supported, found {} at {location:?}",
            tagged.tag
        )),
    }
}

/// Expand `${VAR}` / `${VAR:-default}` in `text`, parse it as YAML and check it.
fn parse_document(text: &str) -> std::result::Result<(String, Value), String> {
    let expanded = expand_env_vars(text);
    let document: Value = serde_yaml_ng::from_str(&expanded).map_err(|error| error.to_string())?;
    let document = validated_document(document)?;
    Ok((expanded, document))
}

/// What one [`ScriptConfigStore::reload`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// The store is not backed by a file; there is nothing to read again.
    NotFileBacked,
    /// The file reads the same as the snapshot being served.
    Unchanged,
    /// A new snapshot is being served.
    Reloaded,
    /// The file could not be read or parsed. The previous snapshot is still
    /// being served; the string is the reason.
    Failed(String),
}

/// The live `script_config` document.
#[derive(Debug)]
pub struct ScriptConfigStore {
    snapshot: ArcSwap<Value>,
    /// The file the document came from, when it came from one.
    source_path: Option<PathBuf>,
    /// The expanded text of the snapshot being served, so a watcher event that
    /// changed nothing (a touch, a sibling file in the same directory) does not
    /// swap in an identical document.
    served_text: Mutex<String>,
}

impl Default for ScriptConfigStore {
    fn default() -> Self {
        Self::empty()
    }
}

impl ScriptConfigStore {
    /// A store holding an empty document: every lookup misses.
    pub fn empty() -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(Value::Mapping(Mapping::new())),
            source_path: None,
            served_text: Mutex::new(String::new()),
        }
    }

    /// A store holding an inline document. It never changes.
    pub fn inline(document: Value) -> Result<Self> {
        let document = validated_document(document)
            .map_err(|reason| SiphonError::Config(format!("script_config: {reason}")))?;
        Ok(Self {
            snapshot: ArcSwap::from_pointee(document),
            source_path: None,
            served_text: Mutex::new(String::new()),
        })
    }

    /// A store backed by the YAML file at `path`.
    ///
    /// Fails when the file cannot be read or does not parse: at startup there
    /// is no last good snapshot to fall back on, and a script running against
    /// an empty table routes nothing while the node reports healthy.
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let text = std::fs::read_to_string(&path).map_err(|error| {
            SiphonError::Config(format!(
                "script_config: cannot read {}: {error}",
                path.display()
            ))
        })?;
        let (expanded, document) = parse_document(&text).map_err(|reason| {
            SiphonError::Config(format!(
                "script_config: {} is not a usable document: {reason}",
                path.display()
            ))
        })?;
        Ok(Self {
            snapshot: ArcSwap::from_pointee(document),
            source_path: Some(path),
            served_text: Mutex::new(expanded),
        })
    }

    /// Build the store from the `script_config:` value in `siphon.yaml`.
    ///
    /// Absent is an empty document, a string is the path of a YAML file, a
    /// mapping is the document itself. Anything else is refused.
    pub fn from_setting(setting: Option<&Value>) -> Result<Self> {
        match setting {
            None | Some(Value::Null) => Ok(Self::empty()),
            Some(Value::String(path)) => Self::from_file(path),
            Some(document @ Value::Mapping(_)) => Self::inline(document.clone()),
            Some(other) => Err(SiphonError::Config(format!(
                "script_config must be an inline mapping or the path of a YAML file, found {}",
                describe(other)
            ))),
        }
    }

    /// The document being served right now.
    pub fn snapshot(&self) -> Arc<Value> {
        self.snapshot.load_full()
    }

    /// The file this store reloads from, if any.
    pub fn source_path(&self) -> Option<&Path> {
        self.source_path.as_deref()
    }

    /// Read the file again and serve it, if it parses and differs.
    ///
    /// A file that cannot be read or parsed leaves the snapshot alone and is
    /// logged at `error` with the file and the reason.
    pub fn reload(&self) -> ReloadOutcome {
        let Some(path) = self.source_path.as_deref() else {
            return ReloadOutcome::NotFileBacked;
        };

        let parsed = std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read the file: {error}"))
            .and_then(|text| parse_document(&text));
        let (expanded, document) = match parsed {
            Ok(parsed) => parsed,
            Err(reason) => {
                error!(
                    path = %path.display(),
                    error = %reason,
                    "script_config reload failed; keeping the last good configuration"
                );
                return ReloadOutcome::Failed(reason);
            }
        };

        let mut served_text = self
            .served_text
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *served_text == expanded {
            debug!(path = %path.display(), "script_config unchanged; not reloading");
            return ReloadOutcome::Unchanged;
        }
        // Swapped under the lock so two reloads cannot leave the served text
        // describing a different document than the one being served.
        self.snapshot.store(Arc::new(document));
        *served_text = expanded;
        info!(path = %path.display(), "script_config reloaded");
        ReloadOutcome::Reloaded
    }
}

/// How often the watcher checks that the store it serves still exists.
const LIVENESS_POLL: Duration = Duration::from_secs(1);

/// Watch a file-backed store's file and reload the store when it changes.
/// Returns immediately; a no-op for a store that is not file-backed.
///
/// The watch is on the parent directory and is not filtered by file name:
/// editors replace a file by renaming a temporary over it, and a volume that is
/// updated by swapping a symlinked directory reports only the symlink. Whatever
/// moved, the file is read again and [`ScriptConfigStore::reload`] discards a
/// read that changed nothing.
///
/// The watcher holds the store weakly and exits once nothing else does, so it
/// never keeps a runtime from shutting down.
pub fn spawn_file_watcher(store: &Arc<ScriptConfigStore>) {
    use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc::{self, RecvTimeoutError};

    let Some(path) = store.source_path().map(Path::to_path_buf) else {
        return;
    };
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let store = Arc::downgrade(store);

    tokio::task::spawn_blocking(move || {
        let (sender, receiver) = mpsc::channel::<notify::Result<Event>>();
        let mut watcher = match RecommendedWatcher::new(sender, Config::default()) {
            Ok(watcher) => watcher,
            Err(error) => {
                error!(%error, "script_config: failed to create file watcher; reload disabled");
                return;
            }
        };
        if let Err(error) = watcher.watch(&directory, RecursiveMode::NonRecursive) {
            error!(
                %error,
                path = %directory.display(),
                "script_config: failed to watch directory; reload disabled"
            );
            return;
        }
        info!(path = %path.display(), "watching script_config file");

        loop {
            match receiver.recv_timeout(LIVENESS_POLL) {
                Ok(event) => {
                    if !is_change(&event) {
                        continue;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if store.strong_count() == 0 {
                        break;
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
            // Absorb the rest of the burst, so a half-written file is not read.
            while receiver.recv_timeout(COALESCE_WINDOW).is_ok() {}
            match store.upgrade() {
                Some(store) => {
                    store.reload();
                }
                None => break,
            }
        }
        debug!(path = %path.display(), "script_config watcher exiting (store dropped)");
    });
}

/// Whether a watcher event can mean the file's content is different now.
/// Reads of the file (ours included) are not.
fn is_change(event: &notify::Result<notify::Event>) -> bool {
    use notify::EventKind;

    match event {
        Ok(event) => matches!(
            event.kind,
            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
        ),
        Err(error) => {
            warn!(%error, "script_config: file watcher error");
            false
        }
    }
}

/// Reload a file-backed store on `SIGHUP`, for the life of the process. A no-op
/// for a store that is not file-backed.
///
/// Installed in both `script.reload` modes, like the script's own `SIGHUP`
/// reload: under `sighup` it is the only trigger, under `auto` a second one.
#[cfg(unix)]
pub fn spawn_sighup_reloader(store: Arc<ScriptConfigStore>) {
    use tokio::signal::unix::{signal, SignalKind};

    if store.source_path().is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut hangup = match signal(SignalKind::hangup()) {
            Ok(stream) => stream,
            Err(error) => {
                error!(%error, "script_config: failed to install the SIGHUP handler");
                return;
            }
        };
        while hangup.recv().await.is_some() {
            store.reload();
        }
    });
}

#[cfg(not(unix))]
pub fn spawn_sighup_reloader(_store: Arc<ScriptConfigStore>) {}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTING_TABLE: &str = concat!(
        "routes:\n",
        "  default:\n",
        "    gateway: carrier-a\n",
        "    weight: 10\n",
        "  prefixes:\n",
        "    - prefix: \"+1555\"\n",
        "      gateway: carrier-b\n",
        "    - prefix: \"+44\"\n",
        "      gateway: carrier-c\n",
        "country_codes:\n",
        "  31: nl\n",
        "limits:\n",
        "  ratio: 0.5\n",
        "  enabled: true\n",
        "  note: ~\n",
    );

    fn document(yaml: &str) -> Value {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    #[test]
    fn lookup_finds_a_top_level_key() {
        let root = document(ROUTING_TABLE);
        assert!(lookup(&root, "routes").unwrap().is_mapping());
    }

    #[test]
    fn lookup_descends_nested_mappings() {
        let root = document(ROUTING_TABLE);
        assert_eq!(
            lookup(&root, "routes.default.gateway").unwrap().as_str(),
            Some("carrier-a")
        );
        assert_eq!(
            lookup(&root, "routes.default.weight").unwrap().as_i64(),
            Some(10)
        );
        assert_eq!(lookup(&root, "limits.ratio").unwrap().as_f64(), Some(0.5));
        assert_eq!(
            lookup(&root, "limits.enabled").unwrap().as_bool(),
            Some(true)
        );
    }

    #[test]
    fn lookup_indexes_a_sequence() {
        let root = document(ROUTING_TABLE);
        assert_eq!(
            lookup(&root, "routes.prefixes.1.gateway").unwrap().as_str(),
            Some("carrier-c")
        );
    }

    #[test]
    fn lookup_matches_an_integer_mapping_key() {
        let root = document(ROUTING_TABLE);
        assert_eq!(
            lookup(&root, "country_codes.31").unwrap().as_str(),
            Some("nl")
        );
    }

    /// A dialling prefix is a string key. Spelled with its `+` it must not
    /// fall through to the integer key the digits alone would name, or to a
    /// sequence index.
    #[test]
    fn lookup_does_not_read_a_signed_segment_as_an_integer() {
        let root = document(concat!(
            "by_prefix:\n",
            "  \"+31\": gateway-nl.example.com\n",
            "  44: gateway-uk.example.com\n",
            "  -1: negative\n",
            "list: [first, second]\n",
        ));
        assert_eq!(
            lookup(&root, "by_prefix.+31").unwrap().as_str(),
            Some("gateway-nl.example.com")
        );
        assert_eq!(
            lookup(&root, "by_prefix.44").unwrap().as_str(),
            Some("gateway-uk.example.com")
        );
        assert_eq!(
            lookup(&root, "by_prefix.-1").unwrap().as_str(),
            Some("negative")
        );
        assert!(lookup(&root, "by_prefix.+44").is_err());
        assert!(lookup(&root, "by_prefix.+-1").is_err());
        assert!(lookup(&root, "list.+1").is_err());
        assert_eq!(lookup(&root, "list.1").unwrap().as_str(), Some("second"));
    }

    #[test]
    fn lookup_of_the_empty_key_is_the_whole_document() {
        let root = document(ROUTING_TABLE);
        assert_eq!(lookup(&root, "").unwrap(), &root);
    }

    #[test]
    fn lookup_returns_an_explicit_null() {
        let root = document(ROUTING_TABLE);
        assert!(lookup(&root, "limits.note").unwrap().is_null());
    }

    #[test]
    fn lookup_reports_a_missing_key_and_where_it_stopped() {
        let root = document(ROUTING_TABLE);
        let error = lookup(&root, "routes.backup.gateway").unwrap_err();
        assert_eq!(
            error,
            LookupError::Missing {
                key: "routes.backup.gateway".to_owned(),
                parent: "routes".to_owned(),
                segment: "backup".to_owned(),
            }
        );
        assert_eq!(
            error.to_string(),
            "script_config key \"routes.backup.gateway\" is not set (no \"backup\" under \
             \"routes\")"
        );
    }

    #[test]
    fn lookup_reports_a_missing_top_level_key() {
        let root = document(ROUTING_TABLE);
        assert_eq!(
            lookup(&root, "policies").unwrap_err().to_string(),
            "script_config key \"policies\" is not set (no \"policies\" at the top level)"
        );
    }

    #[test]
    fn lookup_reports_a_path_through_a_scalar() {
        let root = document(ROUTING_TABLE);
        let error = lookup(&root, "routes.default.gateway.host").unwrap_err();
        assert_eq!(
            error,
            LookupError::NotAContainer {
                key: "routes.default.gateway.host".to_owned(),
                parent: "routes.default.gateway".to_owned(),
                found: "a string",
            }
        );
        assert_eq!(
            error.to_string(),
            "script_config key \"routes.default.gateway.host\" is not set \
             (\"routes.default.gateway\" is a string, not a mapping or a sequence)"
        );
    }

    #[test]
    fn lookup_misses_a_sequence_index_out_of_range_or_not_a_number() {
        let root = document(ROUTING_TABLE);
        assert!(matches!(
            lookup(&root, "routes.prefixes.7"),
            Err(LookupError::Missing { .. })
        ));
        assert!(matches!(
            lookup(&root, "routes.prefixes.first"),
            Err(LookupError::Missing { .. })
        ));
    }

    #[test]
    fn describe_names_every_shape() {
        assert_eq!(describe(&Value::Null), "null");
        assert_eq!(describe(&Value::Bool(true)), "a boolean");
        assert_eq!(describe(&document("1")), "a number");
        assert_eq!(describe(&document("text")), "a string");
        assert_eq!(describe(&document("[1]")), "a sequence");
        assert_eq!(describe(&document("a: 1")), "a mapping");
        assert_eq!(describe(&document("!custom 1")), "a tagged value");
    }

    #[test]
    fn an_absent_setting_is_an_empty_document() {
        let store = ScriptConfigStore::from_setting(None).unwrap();
        assert!(store.source_path().is_none());
        assert!(lookup(&store.snapshot(), "anything").is_err());
        assert_eq!(store.reload(), ReloadOutcome::NotFileBacked);
    }

    #[test]
    fn an_inline_mapping_is_served_as_is() {
        let setting = document(ROUTING_TABLE);
        let store = ScriptConfigStore::from_setting(Some(&setting)).unwrap();
        assert!(store.source_path().is_none());
        assert_eq!(
            lookup(&store.snapshot(), "routes.default.gateway")
                .unwrap()
                .as_str(),
            Some("carrier-a")
        );
    }

    #[test]
    fn a_setting_that_is_neither_a_mapping_nor_a_path_is_refused() {
        let error = ScriptConfigStore::from_setting(Some(&document("[1, 2]")))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("inline mapping or the path of a YAML file")
                && error.contains("a sequence"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_non_scalar_mapping_key_is_refused() {
        let error = ScriptConfigStore::inline(document("routes:\n  [a, b]: 1\n"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("a mapping key must be") && error.contains("\"routes\""),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_tagged_value_is_refused() {
        let error = ScriptConfigStore::inline(document("routes:\n  secret: !vault abc\n"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("YAML tags are not supported") && error.contains("routes.secret"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_missing_file_is_an_error_at_startup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("absent.yaml");
        let setting = Value::String(path.to_string_lossy().into_owned());
        let error = ScriptConfigStore::from_setting(Some(&setting))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("script_config: cannot read") && error.contains("absent.yaml"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_file_that_does_not_parse_is_an_error_at_startup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("routes.yaml");
        std::fs::write(&path, "routes: [unterminated\n").unwrap();
        let error = ScriptConfigStore::from_file(&path).unwrap_err().to_string();
        assert!(
            error.contains("routes.yaml") && error.contains("not a usable document"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_file_whose_top_level_is_not_a_mapping_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("routes.yaml");
        std::fs::write(&path, "- one\n- two\n").unwrap();
        let error = ScriptConfigStore::from_file(&path).unwrap_err().to_string();
        assert!(
            error.contains("the top level must be a mapping, found a sequence"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn an_empty_file_is_an_empty_document() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("routes.yaml");
        std::fs::write(&path, "# nothing yet\n").unwrap();
        let store = ScriptConfigStore::from_file(&path).unwrap();
        assert!(store.snapshot().is_mapping());
    }

    #[test]
    fn a_file_is_expanded_with_the_main_config_rules() {
        // A name no other test reads or writes.
        std::env::set_var("SIPHON_SCRIPT_CONFIG_TEST_GATEWAY", "carrier-from-env");
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("routes.yaml");
        std::fs::write(
            &path,
            concat!(
                "gateway: \"${SIPHON_SCRIPT_CONFIG_TEST_GATEWAY}\"\n",
                "fallback: \"${SIPHON_SCRIPT_CONFIG_TEST_UNSET:-carrier-default}\"\n",
                "blank: \"${SIPHON_SCRIPT_CONFIG_TEST_UNSET}\"\n",
            ),
        )
        .unwrap();

        let store = ScriptConfigStore::from_file(&path).unwrap();
        let snapshot = store.snapshot();
        assert_eq!(
            lookup(&snapshot, "gateway").unwrap().as_str(),
            Some("carrier-from-env")
        );
        assert_eq!(
            lookup(&snapshot, "fallback").unwrap().as_str(),
            Some("carrier-default")
        );
        assert_eq!(lookup(&snapshot, "blank").unwrap().as_str(), Some(""));
    }

    #[test]
    fn reload_serves_the_new_document() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("routes.yaml");
        std::fs::write(&path, "gateway: carrier-a\n").unwrap();
        let store = ScriptConfigStore::from_file(&path).unwrap();

        std::fs::write(&path, "gateway: carrier-b\n").unwrap();
        assert_eq!(store.reload(), ReloadOutcome::Reloaded);
        assert_eq!(
            lookup(&store.snapshot(), "gateway").unwrap().as_str(),
            Some("carrier-b")
        );
    }

    #[test]
    fn reload_of_an_unchanged_file_keeps_the_same_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("routes.yaml");
        std::fs::write(&path, "gateway: carrier-a\n").unwrap();
        let store = ScriptConfigStore::from_file(&path).unwrap();
        let before = store.snapshot();

        assert_eq!(store.reload(), ReloadOutcome::Unchanged);
        assert!(Arc::ptr_eq(&before, &store.snapshot()));
    }

    #[test]
    fn reload_keeps_the_last_good_document_on_a_parse_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("routes.yaml");
        std::fs::write(&path, "gateway: carrier-a\n").unwrap();
        let store = ScriptConfigStore::from_file(&path).unwrap();

        std::fs::write(&path, "gateway: [unterminated\n").unwrap();
        let outcome = store.reload();
        assert!(
            matches!(outcome, ReloadOutcome::Failed(ref reason) if !reason.is_empty()),
            "unexpected outcome: {outcome:?}"
        );
        assert_eq!(
            lookup(&store.snapshot(), "gateway").unwrap().as_str(),
            Some("carrier-a"),
            "a file that does not parse must not replace the snapshot"
        );

        // And the next good write is picked up.
        std::fs::write(&path, "gateway: carrier-b\n").unwrap();
        assert_eq!(store.reload(), ReloadOutcome::Reloaded);
        assert_eq!(
            lookup(&store.snapshot(), "gateway").unwrap().as_str(),
            Some("carrier-b")
        );
    }

    #[test]
    fn reload_keeps_the_last_good_document_when_the_shape_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("routes.yaml");
        std::fs::write(&path, "gateway: carrier-a\n").unwrap();
        let store = ScriptConfigStore::from_file(&path).unwrap();

        std::fs::write(&path, "- not\n- a mapping\n").unwrap();
        assert!(matches!(store.reload(), ReloadOutcome::Failed(_)));
        assert_eq!(
            lookup(&store.snapshot(), "gateway").unwrap().as_str(),
            Some("carrier-a")
        );
    }

    #[test]
    fn reload_keeps_the_last_good_document_when_the_file_disappears() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("routes.yaml");
        std::fs::write(&path, "gateway: carrier-a\n").unwrap();
        let store = ScriptConfigStore::from_file(&path).unwrap();

        std::fs::remove_file(&path).unwrap();
        let outcome = store.reload();
        assert!(
            matches!(outcome, ReloadOutcome::Failed(ref reason) if reason.contains("cannot read")),
            "unexpected outcome: {outcome:?}"
        );
        assert_eq!(
            lookup(&store.snapshot(), "gateway").unwrap().as_str(),
            Some("carrier-a")
        );
    }

    /// Readers on many threads while a writer swaps between two documents: every
    /// snapshot a reader takes is one whole document, never half of each.
    #[test]
    fn concurrent_readers_never_see_a_torn_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("routes.yaml");
        let first = "primary: carrier-a\nsecondary: carrier-a\n";
        let second = "primary: carrier-b\nsecondary: carrier-b\n";
        std::fs::write(&path, first).unwrap();
        let store = Arc::new(ScriptConfigStore::from_file(&path).unwrap());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let readers: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut reads = 0u64;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let snapshot = store.snapshot();
                        let primary = lookup(&snapshot, "primary").unwrap().as_str();
                        let secondary = lookup(&snapshot, "secondary").unwrap().as_str();
                        assert_eq!(primary, secondary, "a snapshot mixed two documents");
                        reads += 1;
                    }
                    reads
                })
            })
            .collect();

        for round in 0..200 {
            std::fs::write(&path, if round % 2 == 0 { second } else { first }).unwrap();
            assert_eq!(store.reload(), ReloadOutcome::Reloaded);
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for reader in readers {
            assert!(reader.join().unwrap() > 0);
        }
    }

    #[test]
    fn only_content_changing_events_trigger_a_reload() {
        use notify::event::{AccessKind, CreateKind, ModifyKind, RemoveKind};
        use notify::{Event, EventKind};

        let event = |kind| Ok(Event::new(kind));
        assert!(is_change(&event(EventKind::Modify(ModifyKind::Any))));
        assert!(is_change(&event(EventKind::Create(CreateKind::Any))));
        assert!(is_change(&event(EventKind::Remove(RemoveKind::Any))));
        assert!(!is_change(&event(EventKind::Access(AccessKind::Any))));
        assert!(!is_change(&Err(notify::Error::generic("watch dropped"))));
    }

    /// The watcher end to end: a write to the file reaches the snapshot without
    /// anything calling `reload`.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_watcher_reloads_when_the_file_is_rewritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("routes.yaml");
        std::fs::write(&path, "gateway: carrier-a\n").unwrap();
        let store = Arc::new(ScriptConfigStore::from_file(&path).unwrap());
        spawn_file_watcher(&store);

        // Rewrite until the watcher has picked one up: the watch is installed
        // on a blocking thread, so the first write can precede it.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            std::fs::write(&path, format!("gateway: carrier-b\nattempt: {attempt}\n")).unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            let snapshot = store.snapshot();
            if lookup(&snapshot, "gateway").unwrap().as_str() == Some("carrier-b") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the watcher never reloaded the file"
            );
        }
    }

    /// Publish `text` the way a Kubernetes ConfigMap volume is updated: the
    /// content goes into a new directory and `..data` is swapped onto it by a
    /// rename, so `routes.yaml -> ..data/routes.yaml` changes without the file
    /// the store was given ever being written.
    #[cfg(unix)]
    fn publish_to_mount(mount: &Path, version: &str, text: &str) {
        use std::os::unix::fs::symlink;

        let directory = mount.join(format!("..{version}"));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("routes.yaml"), text).unwrap();
        let staged = mount.join("..data_tmp");
        let _ = std::fs::remove_file(&staged);
        symlink(format!("..{version}"), &staged).unwrap();
        std::fs::rename(&staged, mount.join("..data")).unwrap();
        let file = mount.join("routes.yaml");
        if std::fs::symlink_metadata(&file).is_err() {
            symlink("..data/routes.yaml", &file).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn reload_follows_a_swapped_symlinked_mount() {
        let mount = tempfile::tempdir().unwrap();
        publish_to_mount(mount.path(), "v1", "gateway: carrier-a\n");
        let store = ScriptConfigStore::from_file(mount.path().join("routes.yaml")).unwrap();
        assert_eq!(
            lookup(&store.snapshot(), "gateway").unwrap().as_str(),
            Some("carrier-a")
        );

        publish_to_mount(mount.path(), "v2", "gateway: carrier-b\n");
        assert_eq!(store.reload(), ReloadOutcome::Reloaded);
        assert_eq!(
            lookup(&store.snapshot(), "gateway").unwrap().as_str(),
            Some("carrier-b")
        );

        // A swap onto a table that does not parse keeps the last good one.
        publish_to_mount(mount.path(), "v3", "gateway: [unterminated\n");
        assert!(matches!(store.reload(), ReloadOutcome::Failed(_)));
        assert_eq!(
            lookup(&store.snapshot(), "gateway").unwrap().as_str(),
            Some("carrier-b")
        );
    }

    /// The watcher end to end on such a mount: nothing writes the file the
    /// store names, only `..data` moves, and the snapshot still follows.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn the_watcher_reloads_when_a_symlinked_mount_is_swapped() {
        let mount = tempfile::tempdir().unwrap();
        publish_to_mount(mount.path(), "v0", "gateway: carrier-a\n");
        let store =
            Arc::new(ScriptConfigStore::from_file(mount.path().join("routes.yaml")).unwrap());
        spawn_file_watcher(&store);

        // Swap until the watcher has picked one up: the watch is installed on
        // a blocking thread, so the first swap can precede it.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            publish_to_mount(
                mount.path(),
                &format!("v{attempt}"),
                &format!("gateway: carrier-b\nattempt: {attempt}\n"),
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
            let snapshot = store.snapshot();
            if lookup(&snapshot, "gateway").unwrap().as_str() == Some("carrier-b") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the watcher never reloaded the swapped mount"
            );
        }
    }

    /// SIGHUP reaches the store. Runs in a process of its own, since the
    /// signal goes to the whole process.
    #[cfg(target_os = "linux")]
    #[test]
    fn sighup_rereads_the_file() {
        crate::own_process::run(
            concat!(module_path!(), "::sighup_rereads_the_file"),
            sighup_rereads_the_file_in_this_process,
        );
    }

    #[cfg(target_os = "linux")]
    fn sighup_rereads_the_file_in_this_process() {
        use tokio::signal::unix::{signal, SignalKind};

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("routes.yaml");
            std::fs::write(&path, "gateway: carrier-a\n").unwrap();
            let store = Arc::new(ScriptConfigStore::from_file(&path).unwrap());

            // The reloader installs its handler from a spawned task. Until a
            // handler exists SIGHUP ends the process, so one is installed
            // here first; the reloader's own then shares the signal.
            let _held = signal(SignalKind::hangup()).unwrap();
            spawn_sighup_reloader(Arc::clone(&store));

            std::fs::write(&path, "gateway: carrier-b\n").unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                // SAFETY: `kill` with our own pid and a valid signal number.
                let sent = unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
                assert_eq!(sent, 0, "SIGHUP could not be sent");
                tokio::time::sleep(Duration::from_millis(100)).await;
                if lookup(&store.snapshot(), "gateway").unwrap().as_str() == Some("carrier-b") {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "SIGHUP never reloaded the file"
                );
            }
        });
    }

    /// A store that is not file-backed installs no SIGHUP handler at all.
    #[tokio::test]
    async fn the_sighup_reloader_is_a_no_op_for_an_inline_store() {
        let store = Arc::new(ScriptConfigStore::inline(document("gateway: carrier-a\n")).unwrap());
        spawn_sighup_reloader(Arc::clone(&store));
        tokio::task::yield_now().await;
        // Nothing was spawned that holds the store.
        assert_eq!(Arc::strong_count(&store), 1);
    }
}
