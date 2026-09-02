//! RFC 4662 Resource List Subscriptions and RLMI (Resource List Meta-Information).
//!
//! Provides resource list management for RLS (Resource List Server) functionality,
//! RLMI XML document generation, and multipart/related body assembly for
//! back-end SUBSCRIBE notifications carrying aggregated presence state.

use dashmap::DashMap;

// ---------------------------------------------------------------------------
// ResourceList — a named list of presentity URIs
// ---------------------------------------------------------------------------

/// A resource list that maps a list URI to its member presentity URIs.
///
/// Example list URI: `sip:friends@lists.example.com`
#[derive(Debug, Clone)]
pub struct ResourceList {
    /// The SIP URI that identifies this list (e.g. `sip:friends@lists.example.com`).
    pub uri: String,
    /// Optional human-readable display name for the list.
    pub name: Option<String>,
    /// Ordered list of member presentity URIs.
    pub members: Vec<String>,
}

// ---------------------------------------------------------------------------
// ResourceListStore — concurrent store of resource lists
// ---------------------------------------------------------------------------

/// Thread-safe store of resource lists, keyed by list URI.
pub struct ResourceListStore {
    lists: DashMap<String, ResourceList>,
}

impl ResourceListStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            lists: DashMap::new(),
        }
    }

    /// Insert or replace a resource list.
    pub fn add_list(&self, list: ResourceList) {
        self.lists.insert(list.uri.clone(), list);
    }

    /// Retrieve a clone of the list for the given URI, if it exists.
    pub fn get_list(&self, uri: &str) -> Option<ResourceList> {
        self.lists.get(uri).map(|entry| entry.value().clone())
    }

    /// Remove the list for the given URI.
    pub fn remove_list(&self, uri: &str) {
        self.lists.remove(uri);
    }

    /// Check whether a URI corresponds to a known resource list.
    pub fn is_list(&self, uri: &str) -> bool {
        self.lists.contains_key(uri)
    }

    /// Return the member URIs for a list. Returns an empty `Vec` if the list
    /// does not exist.
    pub fn expand(&self, uri: &str) -> Vec<String> {
        self.lists
            .get(uri)
            .map(|entry| entry.value().members.clone())
            .unwrap_or_default()
    }
}

impl Default for ResourceListStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RLMI document model
// ---------------------------------------------------------------------------

/// A single resource entry inside an RLMI document.
#[derive(Debug, Clone)]
pub struct RlmiResource {
    /// Presentity URI (e.g. `sip:alice@example.com`).
    pub uri: String,
    /// Optional display name.
    pub name: Option<String>,
    /// Instance state — one of `"active"`, `"pending"`, or `"terminated"`.
    pub state: String,
    /// Content-ID used to reference this resource's body part in the
    /// enclosing `multipart/related` message.
    pub cid: Option<String>,
}

/// An RLMI (Resource List Meta-Information) XML document as defined by
/// RFC 4662 §5.
#[derive(Debug, Clone)]
pub struct RlmiDocument {
    /// The list URI this document describes.
    pub uri: String,
    /// Optional display name for the list.
    pub name: Option<String>,
    /// `true` for a full-state notification, `false` for partial.
    pub full_state: bool,
    /// The resource entries contained in this document.
    pub resources: Vec<RlmiResource>,
}

impl RlmiDocument {
    /// Create a new RLMI document for the given list URI.
    pub fn new(uri: String, full_state: bool) -> Self {
        Self {
            uri,
            name: None,
            full_state,
            resources: Vec::new(),
        }
    }

    /// Append a resource entry.
    pub fn add_resource(&mut self, resource: RlmiResource) {
        self.resources.push(resource);
    }

    /// Serialize the document to RLMI XML (RFC 4662 §5).
    ///
    /// The `version` attribute is always emitted as `0` — the caller is
    /// responsible for tracking version numbers across NOTIFY transactions.
    pub fn to_xml(&self) -> String {
        let full_state_str = if self.full_state { "true" } else { "false" };

        let mut xml = String::with_capacity(512);
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(&format!(
            "<list xmlns=\"urn:ietf:params:xml:ns:rlmi\" uri=\"{}\" version=\"0\" fullState=\"{}\">\n",
            xml_escape(&self.uri),
            full_state_str,
        ));

        if let Some(ref list_name) = self.name {
            xml.push_str(&format!("  <name>{}</name>\n", xml_escape(list_name)));
        }

        for (index, resource) in self.resources.iter().enumerate() {
            xml.push_str(&format!(
                "  <resource uri=\"{}\">\n",
                xml_escape(&resource.uri),
            ));

            if let Some(ref resource_name) = resource.name {
                xml.push_str(&format!("    <name>{}</name>\n", xml_escape(resource_name),));
            }

            let instance_id = index + 1;
            match resource.cid {
                Some(ref content_id) => {
                    xml.push_str(&format!(
                        "    <instance id=\"{}\" state=\"{}\" cid=\"{}\"/>\n",
                        instance_id,
                        xml_escape(&resource.state),
                        xml_escape(content_id),
                    ));
                }
                None => {
                    xml.push_str(&format!(
                        "    <instance id=\"{}\" state=\"{}\"/>\n",
                        instance_id,
                        xml_escape(&resource.state),
                    ));
                }
            }

            xml.push_str("  </resource>\n");
        }

        xml.push_str("</list>\n");
        xml
    }
}

// ---------------------------------------------------------------------------
// Multipart body assembly
// ---------------------------------------------------------------------------

/// Assemble a `multipart/related` body containing the RLMI XML as the root
/// part followed by individual resource body parts.
///
/// # Arguments
///
/// * `rlmi_xml` — the serialized RLMI XML (from [`RlmiDocument::to_xml`]).
/// * `parts` — a slice of `(content_id, content_type, body)` tuples, one per
///   resource whose state is being conveyed.
///
/// # Returns
///
/// A `(boundary, full_body)` tuple. The caller should set the `Content-Type`
/// header to:
///
/// ```text
/// multipart/related;type="application/rlmi+xml";boundary=<boundary>
/// ```
pub fn build_multipart(rlmi_xml: &str, parts: &[(String, String, String)]) -> (String, String) {
    let boundary = format!("siphon-rls-{:016x}", random_boundary_seed());

    let mut body = String::with_capacity(rlmi_xml.len() + parts.len() * 256);

    // Root part — RLMI document
    body.push_str(&format!("--{}\r\n", boundary));
    body.push_str("Content-Type: application/rlmi+xml\r\n");
    body.push_str("Content-ID: <rlmi@localhost>\r\n");
    body.push_str("\r\n");
    body.push_str(rlmi_xml);
    body.push_str("\r\n");

    // Individual resource parts
    for (content_id, content_type, part_body) in parts {
        body.push_str(&format!("--{}\r\n", boundary));
        body.push_str(&format!("Content-Type: {}\r\n", content_type));
        body.push_str(&format!("Content-ID: <{}>\r\n", content_id));
        body.push_str("\r\n");
        body.push_str(part_body);
        body.push_str("\r\n");
    }

    // Closing boundary
    body.push_str(&format!("--{}--\r\n", boundary));

    (boundary, body)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal XML escaping for attribute values and text content.
fn xml_escape(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(character),
        }
    }
    output
}

/// Produce a pseudo-unique seed for the multipart boundary. Uses the current
/// thread ID and a monotonic instant to avoid collisions without pulling in a
/// full random number generator.
fn random_boundary_seed() -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    std::time::Instant::now().hash(&mut hasher);
    hasher.finish()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ResourceList ---------------------------------------------------------

    #[test]
    fn resource_list_creation() {
        let list = ResourceList {
            uri: "sip:friends@lists.example.com".to_string(),
            name: Some("Friends".to_string()),
            members: vec![
                "sip:alice@example.com".to_string(),
                "sip:bob@example.com".to_string(),
            ],
        };

        assert_eq!(list.uri, "sip:friends@lists.example.com");
        assert_eq!(list.name.as_deref(), Some("Friends"));
        assert_eq!(list.members.len(), 2);
    }

    #[test]
    fn resource_list_empty_members() {
        let list = ResourceList {
            uri: "sip:empty@lists.example.com".to_string(),
            name: None,
            members: Vec::new(),
        };

        assert!(list.members.is_empty());
        assert!(list.name.is_none());
    }

    // -- ResourceListStore ----------------------------------------------------

    #[test]
    fn store_add_and_get() {
        let store = ResourceListStore::new();
        let list = ResourceList {
            uri: "sip:team@lists.example.com".to_string(),
            name: Some("Team".to_string()),
            members: vec!["sip:alice@example.com".to_string()],
        };

        store.add_list(list);

        let retrieved = store.get_list("sip:team@lists.example.com");
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.name.as_deref(), Some("Team"));
        assert_eq!(retrieved.members.len(), 1);
    }

    #[test]
    fn store_is_list() {
        let store = ResourceListStore::new();
        assert!(!store.is_list("sip:unknown@lists.example.com"));

        store.add_list(ResourceList {
            uri: "sip:known@lists.example.com".to_string(),
            name: None,
            members: Vec::new(),
        });

        assert!(store.is_list("sip:known@lists.example.com"));
    }

    #[test]
    fn store_remove() {
        let store = ResourceListStore::new();
        store.add_list(ResourceList {
            uri: "sip:temp@lists.example.com".to_string(),
            name: None,
            members: vec!["sip:bob@example.com".to_string()],
        });

        assert!(store.is_list("sip:temp@lists.example.com"));
        store.remove_list("sip:temp@lists.example.com");
        assert!(!store.is_list("sip:temp@lists.example.com"));
    }

    #[test]
    fn store_remove_nonexistent_is_noop() {
        let store = ResourceListStore::new();
        store.remove_list("sip:ghost@lists.example.com");
        // No panic — just a no-op.
    }

    #[test]
    fn store_expand_existing() {
        let store = ResourceListStore::new();
        store.add_list(ResourceList {
            uri: "sip:friends@lists.example.com".to_string(),
            name: None,
            members: vec![
                "sip:alice@example.com".to_string(),
                "sip:bob@example.com".to_string(),
                "sip:carol@example.com".to_string(),
            ],
        });

        let members = store.expand("sip:friends@lists.example.com");
        assert_eq!(members.len(), 3);
        assert_eq!(members[0], "sip:alice@example.com");
        assert_eq!(members[2], "sip:carol@example.com");
    }

    #[test]
    fn store_expand_nonexistent_returns_empty() {
        let store = ResourceListStore::new();
        let members = store.expand("sip:nonexistent@lists.example.com");
        assert!(members.is_empty());
    }

    #[test]
    fn store_expand_empty_list() {
        let store = ResourceListStore::new();
        store.add_list(ResourceList {
            uri: "sip:empty@lists.example.com".to_string(),
            name: None,
            members: Vec::new(),
        });

        let members = store.expand("sip:empty@lists.example.com");
        assert!(members.is_empty());
    }

    #[test]
    fn store_replace_list() {
        let store = ResourceListStore::new();
        let uri = "sip:team@lists.example.com".to_string();

        store.add_list(ResourceList {
            uri: uri.clone(),
            name: Some("Old".to_string()),
            members: vec!["sip:alice@example.com".to_string()],
        });

        store.add_list(ResourceList {
            uri: uri.clone(),
            name: Some("New".to_string()),
            members: vec![
                "sip:bob@example.com".to_string(),
                "sip:carol@example.com".to_string(),
            ],
        });

        let list = store.get_list(&uri).unwrap();
        assert_eq!(list.name.as_deref(), Some("New"));
        assert_eq!(list.members.len(), 2);
    }

    #[test]
    fn store_concurrent_access() {
        use std::sync::Arc;

        let store = Arc::new(ResourceListStore::new());
        let mut handles = Vec::new();

        for index in 0..10 {
            let store_clone = Arc::clone(&store);
            let handle = std::thread::spawn(move || {
                let uri = format!("sip:list-{}@lists.example.com", index);
                store_clone.add_list(ResourceList {
                    uri: uri.clone(),
                    name: None,
                    members: vec![format!("sip:user-{}@example.com", index)],
                });
                assert!(store_clone.is_list(&uri));
                assert_eq!(store_clone.expand(&uri).len(), 1);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }
    }

    // -- RlmiDocument ---------------------------------------------------------

    #[test]
    fn rlmi_document_empty() {
        let document = RlmiDocument::new("sip:friends@lists.example.com".to_string(), true);

        let xml = document.to_xml();
        assert!(xml.contains("fullState=\"true\""));
        assert!(xml.contains("uri=\"sip:friends@lists.example.com\""));
        assert!(!xml.contains("<resource"));
    }

    #[test]
    fn rlmi_document_with_name() {
        let mut document = RlmiDocument::new("sip:friends@lists.example.com".to_string(), true);
        document.name = Some("Friends".to_string());

        let xml = document.to_xml();
        assert!(xml.contains("<name>Friends</name>"));
    }

    #[test]
    fn rlmi_document_partial_state() {
        let document = RlmiDocument::new("sip:friends@lists.example.com".to_string(), false);

        let xml = document.to_xml();
        assert!(xml.contains("fullState=\"false\""));
    }

    #[test]
    fn rlmi_document_with_resources() {
        let mut document = RlmiDocument::new("sip:friends@lists.example.com".to_string(), true);

        document.add_resource(RlmiResource {
            uri: "sip:alice@example.com".to_string(),
            name: Some("Alice".to_string()),
            state: "active".to_string(),
            cid: Some("alice@example.com".to_string()),
        });

        document.add_resource(RlmiResource {
            uri: "sip:bob@example.com".to_string(),
            name: None,
            state: "pending".to_string(),
            cid: None,
        });

        let xml = document.to_xml();

        // Check XML declaration
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));

        // Check namespace
        assert!(xml.contains("xmlns=\"urn:ietf:params:xml:ns:rlmi\""));

        // Check Alice's resource
        assert!(xml.contains("resource uri=\"sip:alice@example.com\""));
        assert!(xml.contains("<name>Alice</name>"));
        assert!(xml.contains("id=\"1\" state=\"active\" cid=\"alice@example.com\""));

        // Check Bob's resource (no name, no cid)
        assert!(xml.contains("resource uri=\"sip:bob@example.com\""));
        assert!(xml.contains("id=\"2\" state=\"pending\""));

        // Bob should NOT have a cid attribute
        // Find Bob's instance line and check it does not contain cid
        for line in xml.lines() {
            if line.contains("id=\"2\"") {
                assert!(!line.contains("cid="), "Bob's instance should not have cid");
            }
        }
    }

    #[test]
    fn rlmi_document_xml_escaping() {
        let mut document = RlmiDocument::new("sip:list@example.com".to_string(), true);

        document.add_resource(RlmiResource {
            uri: "sip:user@example.com".to_string(),
            name: Some("O'Brien & \"Friends\"".to_string()),
            state: "active".to_string(),
            cid: None,
        });

        let xml = document.to_xml();
        assert!(xml.contains("O&apos;Brien &amp; &quot;Friends&quot;"));
    }

    #[test]
    fn rlmi_document_terminated_resource() {
        let mut document = RlmiDocument::new("sip:friends@lists.example.com".to_string(), true);

        document.add_resource(RlmiResource {
            uri: "sip:gone@example.com".to_string(),
            name: None,
            state: "terminated".to_string(),
            cid: None,
        });

        let xml = document.to_xml();
        assert!(xml.contains("state=\"terminated\""));
    }

    // -- build_multipart ------------------------------------------------------

    #[test]
    fn multipart_with_parts() {
        let rlmi_xml = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<list xmlns=\"urn:ietf:params:xml:ns:rlmi\" ",
            "uri=\"sip:friends@lists.example.com\" ",
            "version=\"0\" fullState=\"true\">\n",
            "</list>\n",
        );

        let parts = vec![
            (
                "alice@example.com".to_string(),
                "application/pidf+xml".to_string(),
                "<presence entity=\"sip:alice@example.com\"/>".to_string(),
            ),
            (
                "bob@example.com".to_string(),
                "application/pidf+xml".to_string(),
                "<presence entity=\"sip:bob@example.com\"/>".to_string(),
            ),
        ];

        let (boundary, body) = build_multipart(rlmi_xml, &parts);

        // Boundary is non-empty and used in body
        assert!(!boundary.is_empty());
        assert!(boundary.starts_with("siphon-rls-"));

        // Root RLMI part
        assert!(body.contains("Content-Type: application/rlmi+xml"));
        assert!(body.contains(rlmi_xml));

        // Individual parts
        assert!(body.contains("Content-Type: application/pidf+xml"));
        assert!(body.contains("Content-ID: <alice@example.com>"));
        assert!(body.contains("Content-ID: <bob@example.com>"));
        assert!(body.contains("<presence entity=\"sip:alice@example.com\"/>"));

        // Closing boundary
        assert!(body.contains(&format!("--{}--", boundary)));

        // Count boundary occurrences (opening + 2 parts + closing)
        let boundary_marker = format!("--{}", boundary);
        let count = body.matches(&boundary_marker).count();
        // 3 opening boundaries (rlmi + 2 parts) + 1 closing = 4 occurrences of --boundary
        // but the closing --boundary-- also contains --boundary, so we count at least 4
        assert!(
            count >= 4,
            "expected at least 4 boundary markers, got {}",
            count
        );
    }

    #[test]
    fn multipart_no_parts() {
        let rlmi_xml = "<list/>\n";
        let parts: Vec<(String, String, String)> = Vec::new();

        let (boundary, body) = build_multipart(rlmi_xml, &parts);

        assert!(body.contains("Content-Type: application/rlmi+xml"));
        assert!(body.contains("<list/>\n"));
        assert!(body.contains(&format!("--{}--", boundary)));

        // Only the root part boundary + closing boundary
        let opening_boundary = format!("--{}\r\n", boundary);
        let opening_count = body.matches(&opening_boundary).count();
        assert_eq!(opening_count, 1, "should have exactly one opening part");
    }

    #[test]
    fn multipart_boundary_uniqueness() {
        let (boundary_a, _) = build_multipart("<list/>\n", &[]);
        // Small sleep to ensure different instant
        std::thread::sleep(std::time::Duration::from_millis(1));
        let (boundary_b, _) = build_multipart("<list/>\n", &[]);

        // Boundaries should differ across invocations (different Instant hashes)
        // This is probabilistic but practically guaranteed.
        assert_ne!(boundary_a, boundary_b);
    }

    // -- xml_escape -----------------------------------------------------------

    #[test]
    fn xml_escape_no_special_characters() {
        assert_eq!(xml_escape("hello world"), "hello world");
    }

    #[test]
    fn xml_escape_all_special_characters() {
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[test]
    fn xml_escape_empty_string() {
        assert_eq!(xml_escape(""), "");
    }

    // -- Integration: end-to-end flow -----------------------------------------

    #[test]
    fn end_to_end_rls_notification() {
        // 1. Set up a resource list
        let store = ResourceListStore::new();
        store.add_list(ResourceList {
            uri: "sip:friends@lists.example.com".to_string(),
            name: Some("Friends".to_string()),
            members: vec![
                "sip:alice@example.com".to_string(),
                "sip:bob@example.com".to_string(),
            ],
        });

        // 2. Expand the list
        let members = store.expand("sip:friends@lists.example.com");
        assert_eq!(members.len(), 2);

        // 3. Build RLMI document
        let mut document = RlmiDocument::new("sip:friends@lists.example.com".to_string(), true);
        document.name = Some("Friends".to_string());

        for member_uri in &members {
            document.add_resource(RlmiResource {
                uri: member_uri.clone(),
                name: None,
                state: "active".to_string(),
                cid: Some(member_uri.replace("sip:", "").clone()),
            });
        }

        let rlmi_xml = document.to_xml();

        // 4. Build multipart body with PIDF parts
        let parts: Vec<(String, String, String)> = members
            .iter()
            .map(|uri| {
                let content_id = uri.replace("sip:", "");
                let pidf = format!(
                    concat!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                        "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"{}\">\n",
                        "  <tuple id=\"t1\">\n",
                        "    <status><basic>open</basic></status>\n",
                        "  </tuple>\n",
                        "</presence>\n",
                    ),
                    uri,
                );
                (content_id, "application/pidf+xml".to_string(), pidf)
            })
            .collect();

        let (boundary, body) = build_multipart(&rlmi_xml, &parts);

        // Verify the assembled NOTIFY body is well-formed
        assert!(body.contains("application/rlmi+xml"));
        assert!(body.contains("application/pidf+xml"));
        assert!(body.contains("Content-ID: <alice@example.com>"));
        assert!(body.contains("Content-ID: <bob@example.com>"));
        assert!(body.contains(&format!("--{}--", boundary)));
    }
}
