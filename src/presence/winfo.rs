//! RFC 3857 Watcher Information — tracks who is watching a presentity.
//!
//! Generates `application/watcherinfo+xml` bodies for NOTIFY requests
//! sent on the `presence.winfo` event package. XML is generated as
//! formatted strings (no external XML crate).

use std::fmt;

use dashmap::DashMap;

// ---------------------------------------------------------------------------
// WatcherStatus
// ---------------------------------------------------------------------------

/// Subscription status of a watcher per RFC 3857 §3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatcherStatus {
    /// The subscription is active and authorized.
    Active,
    /// The subscription is pending authorization.
    Pending,
    /// The subscription is waiting (server policy hold).
    Waiting,
    /// The subscription has been terminated.
    Terminated,
}

impl fmt::Display for WatcherStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            WatcherStatus::Active => "active",
            WatcherStatus::Pending => "pending",
            WatcherStatus::Waiting => "waiting",
            WatcherStatus::Terminated => "terminated",
        };
        write!(formatter, "{}", label)
    }
}

// ---------------------------------------------------------------------------
// WatcherEntry
// ---------------------------------------------------------------------------

/// A single watcher of a presentity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatcherEntry {
    /// The watcher's SIP URI (e.g. `sip:bob@example.com`).
    pub uri: String,
    /// Optional display name (e.g. "Bob").
    pub display_name: Option<String>,
    /// Current subscription status.
    pub status: WatcherStatus,
    /// The event package this subscription targets (typically `"presence"`).
    pub event: String,
    /// Seconds elapsed since the watcher subscribed, if known.
    pub duration_registered: Option<u64>,
}

// ---------------------------------------------------------------------------
// WatcherInfo
// ---------------------------------------------------------------------------

/// Watcher information document for a single presentity resource.
///
/// Serialises to `application/watcherinfo+xml` per RFC 3857.
#[derive(Debug, Clone)]
pub struct WatcherInfo {
    /// The presentity URI being watched (e.g. `sip:alice@example.com`).
    pub resource: String,
    /// The list of watchers for this resource.
    pub watchers: Vec<WatcherEntry>,
    /// Document state: `"full"` or `"partial"`.
    pub state: String,
    /// Monotonically increasing document version.
    pub version: u32,
}

impl WatcherInfo {
    /// Create a new full-state watcher info document for `resource`.
    pub fn new(resource: String) -> Self {
        WatcherInfo {
            resource,
            watchers: Vec::new(),
            state: "full".to_string(),
            version: 0,
        }
    }

    /// Append a watcher entry.
    pub fn add_watcher(&mut self, entry: WatcherEntry) {
        self.watchers.push(entry);
    }

    /// Bump the document version by one.
    pub fn increment_version(&mut self) {
        self.version += 1;
    }

    /// Render the watcher-info XML document per RFC 3857 §3.2.
    pub fn to_xml(&self) -> String {
        let mut output = String::with_capacity(512);
        output.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        output.push_str(&format!(
            "<watcherinfo xmlns=\"urn:ietf:params:xml:ns:watcherinfo\" version=\"{}\" state=\"{}\">\n",
            self.version, self.state,
        ));
        output.push_str(&format!(
            "  <watcher-list resource=\"{}\" package=\"presence\">\n",
            xml_escape(&self.resource),
        ));

        for (index, watcher) in self.watchers.iter().enumerate() {
            let identifier = index + 1;
            let mut attributes = format!(
                "id=\"{}\" status=\"{}\" event=\"{}\"",
                identifier,
                watcher.status,
                xml_escape(&watcher.event),
            );

            if let Some(ref display_name) = watcher.display_name {
                attributes.push_str(&format!(" display-name=\"{}\"", xml_escape(display_name)));
            }

            if let Some(duration) = watcher.duration_registered {
                attributes.push_str(&format!(" duration-registered=\"{}\"", duration));
            }

            output.push_str(&format!(
                "    <watcher {}>{}</watcher>\n",
                attributes,
                xml_escape(&watcher.uri),
            ));
        }

        output.push_str("  </watcher-list>\n");
        output.push_str("</watcherinfo>\n");
        output
    }

    /// The MIME content type for watcher-info documents.
    pub fn content_type() -> &'static str {
        "application/watcherinfo+xml"
    }
}

// ---------------------------------------------------------------------------
// WatcherInfoStore
// ---------------------------------------------------------------------------

/// Concurrent store of watcher information keyed by presentity URI.
///
/// Uses `DashMap` for lock-free concurrent access from multiple threads.
pub struct WatcherInfoStore {
    entries: DashMap<String, WatcherInfo>,
}

impl WatcherInfoStore {
    /// Create an empty store.
    pub fn new() -> Self {
        WatcherInfoStore {
            entries: DashMap::new(),
        }
    }

    /// Add a watcher to the given resource's watcher info.
    ///
    /// If no watcher info exists for `resource`, a new full-state document
    /// is created automatically.
    pub fn add_watcher(&self, resource: &str, watcher: WatcherEntry) {
        self.entries
            .entry(resource.to_string())
            .or_insert_with(|| WatcherInfo::new(resource.to_string()))
            .watchers
            .push(watcher);
    }

    /// Remove a watcher (by URI) from the given resource's watcher list.
    ///
    /// Returns quietly if the resource or watcher does not exist.
    pub fn remove_watcher(&self, resource: &str, watcher_uri: &str) {
        if let Some(mut info) = self.entries.get_mut(resource) {
            info.watchers.retain(|entry| entry.uri != watcher_uri);
        }
    }

    /// Get a snapshot of the watcher info for `resource`.
    pub fn get_info(&self, resource: &str) -> Option<WatcherInfo> {
        self.entries
            .get(resource)
            .map(|reference| reference.clone())
    }

    /// Return the number of watchers for `resource` (0 if not found).
    pub fn watcher_count(&self, resource: &str) -> usize {
        self.entries
            .get(resource)
            .map(|reference| reference.watchers.len())
            .unwrap_or(0)
    }
}

impl Default for WatcherInfoStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal XML escaping for attribute values and text content.
fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- WatcherStatus Display --

    #[test]
    fn watcher_status_display_active() {
        assert_eq!(WatcherStatus::Active.to_string(), "active");
    }

    #[test]
    fn watcher_status_display_pending() {
        assert_eq!(WatcherStatus::Pending.to_string(), "pending");
    }

    #[test]
    fn watcher_status_display_waiting() {
        assert_eq!(WatcherStatus::Waiting.to_string(), "waiting");
    }

    #[test]
    fn watcher_status_display_terminated() {
        assert_eq!(WatcherStatus::Terminated.to_string(), "terminated");
    }

    // -- WatcherInfo XML generation --

    #[test]
    fn xml_empty_watcher_list() {
        let info = WatcherInfo::new("sip:alice@example.com".to_string());
        let xml = info.to_xml();

        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("version=\"0\""));
        assert!(xml.contains("state=\"full\""));
        assert!(xml.contains("resource=\"sip:alice@example.com\""));
        assert!(xml.contains("package=\"presence\""));
        // No <watcher> elements.
        assert!(!xml.contains("<watcher "));
    }

    #[test]
    fn xml_single_watcher_with_display_name() {
        let mut info = WatcherInfo::new("sip:alice@example.com".to_string());
        info.add_watcher(WatcherEntry {
            uri: "sip:bob@example.com".to_string(),
            display_name: Some("Bob".to_string()),
            status: WatcherStatus::Active,
            event: "subscribe".to_string(),
            duration_registered: None,
        });

        let xml = info.to_xml();

        assert!(xml.contains("id=\"1\""));
        assert!(xml.contains("status=\"active\""));
        assert!(xml.contains("event=\"subscribe\""));
        assert!(xml.contains("display-name=\"Bob\""));
        assert!(xml.contains(">sip:bob@example.com</watcher>"));
        // No duration-registered when None.
        assert!(!xml.contains("duration-registered"));
    }

    #[test]
    fn xml_watcher_with_duration() {
        let mut info = WatcherInfo::new("sip:alice@example.com".to_string());
        info.add_watcher(WatcherEntry {
            uri: "sip:carol@example.com".to_string(),
            display_name: None,
            status: WatcherStatus::Pending,
            event: "subscribe".to_string(),
            duration_registered: Some(120),
        });

        let xml = info.to_xml();

        assert!(xml.contains("status=\"pending\""));
        assert!(xml.contains("duration-registered=\"120\""));
        // No display-name when None.
        assert!(!xml.contains("display-name"));
    }

    #[test]
    fn xml_multiple_watchers_sequential_ids() {
        let mut info = WatcherInfo::new("sip:alice@example.com".to_string());
        info.add_watcher(WatcherEntry {
            uri: "sip:bob@example.com".to_string(),
            display_name: Some("Bob".to_string()),
            status: WatcherStatus::Active,
            event: "subscribe".to_string(),
            duration_registered: Some(300),
        });
        info.add_watcher(WatcherEntry {
            uri: "sip:carol@example.com".to_string(),
            display_name: None,
            status: WatcherStatus::Waiting,
            event: "subscribe".to_string(),
            duration_registered: None,
        });

        let xml = info.to_xml();

        assert!(xml.contains("id=\"1\""));
        assert!(xml.contains("id=\"2\""));
        assert!(xml.contains(">sip:bob@example.com</watcher>"));
        assert!(xml.contains(">sip:carol@example.com</watcher>"));
    }

    #[test]
    fn xml_escapes_special_characters() {
        let mut info = WatcherInfo::new("sip:alice@example.com".to_string());
        info.add_watcher(WatcherEntry {
            uri: "sip:bob@example.com".to_string(),
            display_name: Some("Bob & \"Friends\"".to_string()),
            status: WatcherStatus::Active,
            event: "subscribe".to_string(),
            duration_registered: None,
        });

        let xml = info.to_xml();

        assert!(xml.contains("display-name=\"Bob &amp; &quot;Friends&quot;\""));
    }

    // -- Version incrementing --

    #[test]
    fn increment_version() {
        let mut info = WatcherInfo::new("sip:alice@example.com".to_string());
        assert_eq!(info.version, 0);

        info.increment_version();
        assert_eq!(info.version, 1);

        info.increment_version();
        assert_eq!(info.version, 2);

        let xml = info.to_xml();
        assert!(xml.contains("version=\"2\""));
    }

    // -- Content type --

    #[test]
    fn content_type() {
        assert_eq!(WatcherInfo::content_type(), "application/watcherinfo+xml");
    }

    // -- WatcherInfoStore --

    #[test]
    fn store_add_and_get() {
        let store = WatcherInfoStore::new();
        store.add_watcher(
            "sip:alice@example.com",
            WatcherEntry {
                uri: "sip:bob@example.com".to_string(),
                display_name: Some("Bob".to_string()),
                status: WatcherStatus::Active,
                event: "subscribe".to_string(),
                duration_registered: None,
            },
        );

        let info = store.get_info("sip:alice@example.com").unwrap();
        assert_eq!(info.resource, "sip:alice@example.com");
        assert_eq!(info.watchers.len(), 1);
        assert_eq!(info.watchers[0].uri, "sip:bob@example.com");
    }

    #[test]
    fn store_add_multiple_watchers() {
        let store = WatcherInfoStore::new();
        store.add_watcher(
            "sip:alice@example.com",
            WatcherEntry {
                uri: "sip:bob@example.com".to_string(),
                display_name: None,
                status: WatcherStatus::Active,
                event: "subscribe".to_string(),
                duration_registered: None,
            },
        );
        store.add_watcher(
            "sip:alice@example.com",
            WatcherEntry {
                uri: "sip:carol@example.com".to_string(),
                display_name: None,
                status: WatcherStatus::Pending,
                event: "subscribe".to_string(),
                duration_registered: None,
            },
        );

        assert_eq!(store.watcher_count("sip:alice@example.com"), 2);
    }

    #[test]
    fn store_remove_watcher() {
        let store = WatcherInfoStore::new();
        store.add_watcher(
            "sip:alice@example.com",
            WatcherEntry {
                uri: "sip:bob@example.com".to_string(),
                display_name: None,
                status: WatcherStatus::Active,
                event: "subscribe".to_string(),
                duration_registered: None,
            },
        );
        store.add_watcher(
            "sip:alice@example.com",
            WatcherEntry {
                uri: "sip:carol@example.com".to_string(),
                display_name: None,
                status: WatcherStatus::Active,
                event: "subscribe".to_string(),
                duration_registered: None,
            },
        );

        store.remove_watcher("sip:alice@example.com", "sip:bob@example.com");

        let info = store.get_info("sip:alice@example.com").unwrap();
        assert_eq!(info.watchers.len(), 1);
        assert_eq!(info.watchers[0].uri, "sip:carol@example.com");
    }

    #[test]
    fn store_remove_nonexistent_resource() {
        let store = WatcherInfoStore::new();
        // Should not panic.
        store.remove_watcher("sip:nobody@example.com", "sip:bob@example.com");
    }

    #[test]
    fn store_remove_nonexistent_watcher() {
        let store = WatcherInfoStore::new();
        store.add_watcher(
            "sip:alice@example.com",
            WatcherEntry {
                uri: "sip:bob@example.com".to_string(),
                display_name: None,
                status: WatcherStatus::Active,
                event: "subscribe".to_string(),
                duration_registered: None,
            },
        );

        store.remove_watcher("sip:alice@example.com", "sip:nobody@example.com");
        assert_eq!(store.watcher_count("sip:alice@example.com"), 1);
    }

    #[test]
    fn store_get_nonexistent_resource() {
        let store = WatcherInfoStore::new();
        assert!(store.get_info("sip:nobody@example.com").is_none());
    }

    #[test]
    fn store_watcher_count_nonexistent() {
        let store = WatcherInfoStore::new();
        assert_eq!(store.watcher_count("sip:nobody@example.com"), 0);
    }

    #[test]
    fn store_duplicate_watcher_uri() {
        let store = WatcherInfoStore::new();
        let watcher = WatcherEntry {
            uri: "sip:bob@example.com".to_string(),
            display_name: None,
            status: WatcherStatus::Active,
            event: "subscribe".to_string(),
            duration_registered: None,
        };

        store.add_watcher("sip:alice@example.com", watcher.clone());
        store.add_watcher("sip:alice@example.com", watcher);

        // Both are kept — deduplication is a policy decision for the caller.
        assert_eq!(store.watcher_count("sip:alice@example.com"), 2);
    }

    #[test]
    fn store_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(WatcherInfoStore::new());
        let mut handles = Vec::new();

        for index in 0..10 {
            let store_clone = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                store_clone.add_watcher(
                    "sip:alice@example.com",
                    WatcherEntry {
                        uri: format!("sip:watcher{}@example.com", index),
                        display_name: None,
                        status: WatcherStatus::Active,
                        event: "subscribe".to_string(),
                        duration_registered: None,
                    },
                );
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(store.watcher_count("sip:alice@example.com"), 10);
    }
}
