//! SDP parser for codec filtering and attribute manipulation.
//!
//! Provides functionality to parse SDP bodies, extract/modify media lines
//! (`m=`) and codec attributes (`a=rtpmap`), filter codecs by name, and
//! get/set/remove arbitrary `a=` attributes at session and media level.
//!
//! This is NOT a full RFC 4566 parser — it handles the common cases needed for
//! SDP manipulation in a SIP proxy/B2BUA context.

use std::collections::HashSet;

/// A parsed media line from SDP.
#[derive(Debug, Clone)]
pub struct MediaLine {
    /// Media type: "audio", "video", "application", etc.
    pub media_type: String,
    /// Port number.
    pub port: u16,
    /// Protocol: "RTP/AVP", "RTP/SAVP", "RTP/SAVPF", "UDP/TLS/RTP/SAVPF", etc.
    pub protocol: String,
    /// Payload type numbers.
    pub formats: Vec<u16>,
    /// Codec attributes keyed by payload type.
    pub rtpmap: Vec<(u16, String)>,
    /// fmtp attributes keyed by payload type.
    pub fmtp: Vec<(u16, String)>,
    /// Other attributes (not rtpmap/fmtp) for this media section.
    pub other_attrs: Vec<String>,
}

impl MediaLine {
    /// Return the media-level `c=` connection value, if present.
    pub fn connection(&self) -> Option<&str> {
        self.other_attrs
            .iter()
            .find(|line| line.starts_with("c="))
            .map(|line| &line[2..])
    }

    /// Return all `a=` attribute values (the part after `a=`) from this media
    /// section, excluding `rtpmap` and `fmtp` (which are stored separately).
    pub fn attrs(&self) -> Vec<&str> {
        self.other_attrs
            .iter()
            .filter_map(|line| line.strip_prefix("a="))
            .collect()
    }

    /// Replace all `a=` lines in `other_attrs` with the given values.
    ///
    /// Non-`a=` lines (e.g. `c=`, `b=`) are preserved.
    pub fn set_attrs(&mut self, values: &[&str]) {
        self.other_attrs.retain(|line| !line.starts_with("a="));
        for value in values {
            self.other_attrs.push(format!("a={value}"));
        }
    }

    /// Get all values of `a=` attributes matching `name`, preserving order.
    ///
    /// For multiple `a=des:...` lines, returns all their values.
    pub fn get_attrs_by_name(&self, name: &str) -> Vec<&str> {
        self.other_attrs
            .iter()
            .filter_map(|line| line.strip_prefix("a="))
            .filter(|attr| attr_matches_name(attr, name))
            .map(attr_extract_value)
            .collect()
    }

    /// Replace all `a=` attributes matching `name` with new values, preserving position.
    ///
    /// Removes all existing `a=name:...` lines, then inserts the new values
    /// at the position of the first removed line (or appends if none existed).
    pub fn set_attrs_by_name(&mut self, name: &str, values: &[&str]) {
        // Find position of first match (for insertion point)
        let first_pos = self.other_attrs
            .iter()
            .position(|line| line.strip_prefix("a=").is_some_and(|a| attr_matches_name(a, name)));

        // Remove all matches
        self.other_attrs.retain(|line| {
            line.strip_prefix("a=")
                .map_or(true, |attr| !attr_matches_name(attr, name))
        });

        // Build new lines
        let new_lines: Vec<String> = values.iter().map(|value| {
            if value.is_empty() {
                format!("a={name}")
            } else {
                format!("a={name}:{value}")
            }
        }).collect();

        // Insert at original position, or append
        let insert_pos = first_pos.unwrap_or(self.other_attrs.len())
            .min(self.other_attrs.len());
        for (i, line) in new_lines.into_iter().enumerate() {
            self.other_attrs.insert(insert_pos + i, line);
        }
    }

    /// Get the value of the first `a=` attribute matching `name`.
    ///
    /// For `a=des:qos mandatory local sendrecv`, `get_attr("des")` returns
    /// `Some("qos mandatory local sendrecv")`.
    /// For flag attributes like `a=sendrecv`, returns `Some("")`.
    /// Returns `None` if no attribute with that name exists.
    pub fn get_attr(&self, name: &str) -> Option<&str> {
        self.other_attrs
            .iter()
            .filter_map(|line| line.strip_prefix("a="))
            .find(|attr| attr_matches_name(attr, name))
            .map(attr_extract_value)
    }

    /// Set (replace first or append) an `a=` attribute.
    ///
    /// `set_attr("des", "qos optional local sendrecv")` produces
    /// `a=des:qos optional local sendrecv`.
    /// `set_attr("sendrecv", "")` produces `a=sendrecv` (flag).
    pub fn set_attr(&mut self, name: &str, value: &str) {
        let new_line = if value.is_empty() {
            format!("a={name}")
        } else {
            format!("a={name}:{value}")
        };
        // Replace first match, or append.
        if let Some(pos) = self
            .other_attrs
            .iter()
            .position(|line| line.strip_prefix("a=").is_some_and(|a| attr_matches_name(a, name)))
        {
            self.other_attrs[pos] = new_line;
        } else {
            self.other_attrs.push(new_line);
        }
    }

    /// Remove all `a=` attributes matching `name`.
    pub fn remove_attr(&mut self, name: &str) {
        self.other_attrs.retain(|line| {
            line.strip_prefix("a=")
                .map_or(true, |attr| !attr_matches_name(attr, name))
        });
    }

    /// Check whether an `a=` attribute with the given name exists.
    pub fn has_attr(&self, name: &str) -> bool {
        self.other_attrs
            .iter()
            .filter_map(|line| line.strip_prefix("a="))
            .any(|attr| attr_matches_name(attr, name))
    }

    /// Return codec names derived from `rtpmap` entries and static payload
    /// type names for formats without an explicit `rtpmap`.
    pub fn codec_names(&self) -> Vec<String> {
        self.formats
            .iter()
            .filter_map(|&pt| {
                // Check rtpmap first.
                if let Some((_, codec)) = self.rtpmap.iter().find(|(rpt, _)| *rpt == pt) {
                    return Some(codec.split('/').next().unwrap_or(codec).to_string());
                }
                // Fall back to well-known static payload types.
                static_codec_name(pt).map(|name| name.to_string())
            })
            .collect()
    }
}

/// A parsed SDP body.
#[derive(Debug, Clone)]
pub struct SdpBody {
    /// Session-level lines (v=, o=, s=, c=, t=, etc.) before first m= line.
    pub session_lines: Vec<String>,
    /// Media sections.
    pub media_sections: Vec<MediaLine>,
}

impl SdpBody {
    /// Parse an SDP body from a string.
    pub fn parse(sdp: &str) -> Self {
        let mut session_lines = Vec::new();
        let mut media_sections = Vec::new();
        let mut current_media: Option<MediaLine> = None;

        for line in sdp.lines() {
            let line = line.trim_end_matches('\r');

            if line.starts_with("m=") {
                // Save previous media section
                if let Some(media) = current_media.take() {
                    media_sections.push(media);
                }
                // Parse new media line: m=audio 49170 RTP/AVP 0 8 97
                current_media = Some(parse_media_line(line));
            } else if let Some(ref mut media) = current_media {
                // We're inside a media section
                if line.starts_with("a=rtpmap:") {
                    // a=rtpmap:97 opus/48000/2
                    if let Some((pt, codec)) = parse_rtpmap(line) {
                        media.rtpmap.push((pt, codec));
                    }
                } else if line.starts_with("a=fmtp:") {
                    // a=fmtp:97 minptime=10;useinbandfec=1
                    if let Some((pt, params)) = parse_fmtp(line) {
                        media.fmtp.push((pt, params));
                    }
                } else {
                    media.other_attrs.push(line.to_string());
                }
            } else {
                // Session-level line
                session_lines.push(line.to_string());
            }
        }

        // Save last media section
        if let Some(media) = current_media {
            media_sections.push(media);
        }

        SdpBody {
            session_lines,
            media_sections,
        }
    }

    /// Filter codecs: keep only codecs whose names match the given list.
    ///
    /// Matching is case-insensitive. Codec names are compared against the
    /// encoding name in `a=rtpmap` (e.g., "PCMU", "PCMA", "opus", "telephone-event").
    ///
    /// Static payload types (0-95) without explicit rtpmap are matched by their
    /// well-known names.
    pub fn filter_codecs(&mut self, keep: &[&str]) {
        let keep_set: HashSet<String> = keep.iter().map(|s| s.to_lowercase()).collect();

        for media in &mut self.media_sections {
            let kept_pts: HashSet<u16> = media
                .formats
                .iter()
                .filter(|&&pt| {
                    // Check rtpmap first
                    if let Some(codec_name) = media.rtpmap.iter().find(|(rpt, _)| *rpt == pt) {
                        let name = codec_name.1.split('/').next().unwrap_or("");
                        return keep_set.contains(&name.to_lowercase());
                    }
                    // Fall back to well-known static payload types
                    if let Some(name) = static_codec_name(pt) {
                        return keep_set.contains(&name.to_lowercase());
                    }
                    false
                })
                .copied()
                .collect();

            media.formats.retain(|pt| kept_pts.contains(pt));
            media.rtpmap.retain(|(pt, _)| kept_pts.contains(pt));
            media.fmtp.retain(|(pt, _)| kept_pts.contains(pt));
        }
    }

    /// Remove codecs by name. Opposite of `filter_codecs`.
    pub fn remove_codecs(&mut self, remove: &[&str]) {
        let remove_set: HashSet<String> = remove.iter().map(|s| s.to_lowercase()).collect();

        for media in &mut self.media_sections {
            let removed_pts: HashSet<u16> = media
                .formats
                .iter()
                .filter(|&&pt| {
                    if let Some(codec_name) = media.rtpmap.iter().find(|(rpt, _)| *rpt == pt) {
                        let name = codec_name.1.split('/').next().unwrap_or("");
                        return remove_set.contains(&name.to_lowercase());
                    }
                    if let Some(name) = static_codec_name(pt) {
                        return remove_set.contains(&name.to_lowercase());
                    }
                    false
                })
                .copied()
                .collect();

            media.formats.retain(|pt| !removed_pts.contains(pt));
            media.rtpmap.retain(|(pt, _)| !removed_pts.contains(pt));
            media.fmtp.retain(|(pt, _)| !removed_pts.contains(pt));
        }
    }

    // -----------------------------------------------------------------
    // Session-level property accessors
    // -----------------------------------------------------------------

    /// Return the `o=` (origin) line value, if present.
    pub fn origin(&self) -> Option<&str> {
        self.session_lines
            .iter()
            .find(|line| line.starts_with("o="))
            .map(|line| &line[2..])
    }

    /// Return the `s=` (session name) line value, if present.
    pub fn session_name(&self) -> Option<&str> {
        self.session_lines
            .iter()
            .find(|line| line.starts_with("s="))
            .map(|line| &line[2..])
    }

    /// Return the session-level `c=` (connection) value, if present.
    pub fn connection(&self) -> Option<&str> {
        self.session_lines
            .iter()
            .find(|line| line.starts_with("c="))
            .map(|line| &line[2..])
    }

    // -----------------------------------------------------------------
    // Session-level attribute (a=) accessors
    // -----------------------------------------------------------------

    /// Return all session-level `a=` attribute values (the part after `a=`).
    pub fn session_attrs(&self) -> Vec<&str> {
        self.session_lines
            .iter()
            .filter_map(|line| line.strip_prefix("a="))
            .collect()
    }

    /// Replace all session-level `a=` lines with the given values.
    ///
    /// Non-`a=` lines (v=, o=, s=, c=, t=, etc.) are preserved.
    pub fn set_session_attrs(&mut self, values: &[&str]) {
        self.session_lines.retain(|line| !line.starts_with("a="));
        for value in values {
            self.session_lines.push(format!("a={value}"));
        }
    }

    /// Get the value of the first session-level `a=` attribute matching `name`.
    ///
    /// See [`MediaLine::get_attr`] for the name/value splitting rules.
    pub fn session_get_attr(&self, name: &str) -> Option<&str> {
        self.session_lines
            .iter()
            .filter_map(|line| line.strip_prefix("a="))
            .find(|attr| attr_matches_name(attr, name))
            .map(attr_extract_value)
    }

    /// Get all session-level `a=` attribute values matching `name`.
    pub fn session_get_attrs_by_name(&self, name: &str) -> Vec<&str> {
        self.session_lines
            .iter()
            .filter_map(|line| line.strip_prefix("a="))
            .filter(|attr| attr_matches_name(attr, name))
            .map(attr_extract_value)
            .collect()
    }

    /// Replace all session-level `a=` attributes matching `name` with new values.
    pub fn session_set_attrs_by_name(&mut self, name: &str, values: &[&str]) {
        let first_pos = self.session_lines
            .iter()
            .position(|line| line.strip_prefix("a=").is_some_and(|a| attr_matches_name(a, name)));
        self.session_lines.retain(|line| {
            line.strip_prefix("a=")
                .map_or(true, |attr| !attr_matches_name(attr, name))
        });
        let insert_pos = first_pos.unwrap_or(self.session_lines.len())
            .min(self.session_lines.len());
        for (i, value) in values.iter().enumerate() {
            let line = if value.is_empty() {
                format!("a={name}")
            } else {
                format!("a={name}:{value}")
            };
            self.session_lines.insert(insert_pos + i, line);
        }
    }

    /// Set (replace first or append) a session-level `a=` attribute.
    pub fn session_set_attr(&mut self, name: &str, value: &str) {
        let new_line = if value.is_empty() {
            format!("a={name}")
        } else {
            format!("a={name}:{value}")
        };
        if let Some(pos) = self
            .session_lines
            .iter()
            .position(|line| line.strip_prefix("a=").is_some_and(|a| attr_matches_name(a, name)))
        {
            self.session_lines[pos] = new_line;
        } else {
            self.session_lines.push(new_line);
        }
    }

    /// Remove all session-level `a=` attributes matching `name`.
    pub fn session_remove_attr(&mut self, name: &str) {
        self.session_lines.retain(|line| {
            line.strip_prefix("a=")
                .map_or(true, |attr| !attr_matches_name(attr, name))
        });
    }

    /// Check whether a session-level `a=` attribute with the given name exists.
    pub fn session_has_attr(&self, name: &str) -> bool {
        self.session_lines
            .iter()
            .filter_map(|line| line.strip_prefix("a="))
            .any(|attr| attr_matches_name(attr, name))
    }

    // -----------------------------------------------------------------
    // Media section operations
    // -----------------------------------------------------------------

    /// Remove all media sections matching the given media type (e.g. `"video"`).
    pub fn remove_media_by_type(&mut self, media_type: &str) {
        self.media_sections
            .retain(|media| media.media_type != media_type);
    }
}

impl std::fmt::Display for SdpBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for line in &self.session_lines {
            write!(f, "{line}\r\n")?;
        }

        for media in &self.media_sections {
            // m=audio 49170 RTP/AVP 0 8 97
            let formats: Vec<String> = media.formats.iter().map(|pt| pt.to_string()).collect();
            if formats.is_empty() {
                write!(
                    f,
                    "m={} {} {}\r\n",
                    media.media_type, media.port, media.protocol,
                )?;
            } else {
                write!(
                    f,
                    "m={} {} {} {}\r\n",
                    media.media_type,
                    media.port,
                    media.protocol,
                    formats.join(" ")
                )?;
            }

            // Other attributes first (c=, b=, etc.)
            for attr in &media.other_attrs {
                write!(f, "{attr}\r\n")?;
            }

            // rtpmap attributes
            for (pt, codec) in &media.rtpmap {
                write!(f, "a=rtpmap:{pt} {codec}\r\n")?;
            }

            // fmtp attributes
            for (pt, params) in &media.fmtp {
                write!(f, "a=fmtp:{pt} {params}\r\n")?;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Attribute name matching helpers
// ---------------------------------------------------------------------------

/// Check if an attribute value (after `a=`) matches the given name.
///
/// The attribute name is the part before the first `:`. For flag attributes
/// (no `:`), the entire string is the name.
fn attr_matches_name(attr_value: &str, name: &str) -> bool {
    let attr_name = attr_value.split(':').next().unwrap_or(attr_value);
    attr_name == name
}

/// Extract the value portion of an attribute (everything after the first `:`).
///
/// For `"des:qos mandatory local sendrecv"` returns `"qos mandatory local sendrecv"`.
/// For flag attributes like `"sendrecv"` returns `""`.
fn attr_extract_value(attr_value: &str) -> &str {
    match attr_value.split_once(':') {
        Some((_, value)) => value,
        None => "",
    }
}

// ---------------------------------------------------------------------------
// SDP line parsers
// ---------------------------------------------------------------------------

/// Parse an `m=` line into a MediaLine.
fn parse_media_line(line: &str) -> MediaLine {
    let content = line.strip_prefix("m=").unwrap_or(line);
    let parts: Vec<&str> = content.split_whitespace().collect();

    let media_type = parts.first().unwrap_or(&"audio").to_string();
    let port = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let protocol = parts.get(2).unwrap_or(&"RTP/AVP").to_string();
    let formats: Vec<u16> = parts.get(3..).unwrap_or(&[])
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    MediaLine {
        media_type,
        port,
        protocol,
        formats,
        rtpmap: Vec::new(),
        fmtp: Vec::new(),
        other_attrs: Vec::new(),
    }
}

/// Parse `a=rtpmap:97 opus/48000/2` → (97, "opus/48000/2")
fn parse_rtpmap(line: &str) -> Option<(u16, String)> {
    let content = line.strip_prefix("a=rtpmap:")?;
    let (pt_str, codec) = content.split_once(' ')?;
    let pt = pt_str.parse().ok()?;
    Some((pt, codec.to_string()))
}

/// Parse `a=fmtp:97 minptime=10` → (97, "minptime=10")
fn parse_fmtp(line: &str) -> Option<(u16, String)> {
    let content = line.strip_prefix("a=fmtp:")?;
    let (pt_str, params) = content.split_once(' ')?;
    let pt = pt_str.parse().ok()?;
    Some((pt, params.to_string()))
}

/// Well-known static codec names for payload types 0-34.
fn static_codec_name(pt: u16) -> Option<&'static str> {
    match pt {
        0 => Some("PCMU"),
        3 => Some("GSM"),
        4 => Some("G723"),
        5 => Some("DVI4"),
        6 => Some("DVI4"),
        7 => Some("LPC"),
        8 => Some("PCMA"),
        9 => Some("G722"),
        10 => Some("L16"),
        11 => Some("L16"),
        12 => Some("QCELP"),
        13 => Some("CN"),
        14 => Some("MPA"),
        15 => Some("G728"),
        18 => Some("G729"),
        25 => Some("CelB"),
        26 => Some("JPEG"),
        28 => Some("nv"),
        31 => Some("H261"),
        32 => Some("MPV"),
        33 => Some("MP2T"),
        34 => Some("H263"),
        _ => None,
    }
}

/// Rewrite an SDP body in a SIP message: filter codecs and return the new body + Content-Length.
pub fn rewrite_sdp_body(body: &str, keep_codecs: &[&str]) -> (String, usize) {
    let mut sdp = SdpBody::parse(body);
    sdp.filter_codecs(keep_codecs);
    let new_body = sdp.to_string();
    let length = new_body.len();
    (new_body, length)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SDP: &str = concat!(
        "v=0\r\n",
        "o=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n",
        "s=-\r\n",
        "c=IN IP4 10.0.0.1\r\n",
        "t=0 0\r\n",
        "m=audio 49170 RTP/AVP 0 8 97 101\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
        "a=rtpmap:97 opus/48000/2\r\n",
        "a=fmtp:97 minptime=10;useinbandfec=1\r\n",
        "a=rtpmap:101 telephone-event/8000\r\n",
        "a=fmtp:101 0-16\r\n",
    );

    #[test]
    fn parse_sdp_session_lines() {
        let sdp = SdpBody::parse(SAMPLE_SDP);
        assert_eq!(sdp.session_lines.len(), 5);
        assert!(sdp.session_lines[0].starts_with("v="));
    }

    #[test]
    fn parse_sdp_media_section() {
        let sdp = SdpBody::parse(SAMPLE_SDP);
        assert_eq!(sdp.media_sections.len(), 1);

        let media = &sdp.media_sections[0];
        assert_eq!(media.media_type, "audio");
        assert_eq!(media.port, 49170);
        assert_eq!(media.protocol, "RTP/AVP");
        assert_eq!(media.formats, vec![0, 8, 97, 101]);
    }

    #[test]
    fn parse_rtpmap_attributes() {
        let sdp = SdpBody::parse(SAMPLE_SDP);
        let media = &sdp.media_sections[0];

        assert_eq!(media.rtpmap.len(), 4);
        assert_eq!(media.rtpmap[0], (0, "PCMU/8000".to_string()));
        assert_eq!(media.rtpmap[1], (8, "PCMA/8000".to_string()));
        assert_eq!(media.rtpmap[2], (97, "opus/48000/2".to_string()));
        assert_eq!(media.rtpmap[3], (101, "telephone-event/8000".to_string()));
    }

    #[test]
    fn parse_fmtp_attributes() {
        let sdp = SdpBody::parse(SAMPLE_SDP);
        let media = &sdp.media_sections[0];

        assert_eq!(media.fmtp.len(), 2);
        assert_eq!(media.fmtp[0].0, 97);
        assert!(media.fmtp[0].1.contains("minptime=10"));
        assert_eq!(media.fmtp[1].0, 101);
    }

    #[test]
    fn filter_codecs_keep_pcmu_pcma() {
        let mut sdp = SdpBody::parse(SAMPLE_SDP);
        sdp.filter_codecs(&["PCMU", "PCMA"]);

        let media = &sdp.media_sections[0];
        assert_eq!(media.formats, vec![0, 8]);
        assert_eq!(media.rtpmap.len(), 2);
        assert!(media.fmtp.is_empty()); // opus and telephone-event fmtp removed
    }

    #[test]
    fn filter_codecs_case_insensitive() {
        let mut sdp = SdpBody::parse(SAMPLE_SDP);
        sdp.filter_codecs(&["pcmu", "Opus"]);

        let media = &sdp.media_sections[0];
        assert_eq!(media.formats, vec![0, 97]);
    }

    #[test]
    fn remove_codecs() {
        let mut sdp = SdpBody::parse(SAMPLE_SDP);
        sdp.remove_codecs(&["telephone-event"]);

        let media = &sdp.media_sections[0];
        assert_eq!(media.formats, vec![0, 8, 97]);
        assert!(!media.rtpmap.iter().any(|(_, c)| c.contains("telephone-event")));
    }

    #[test]
    fn serialize_roundtrip() {
        let sdp = SdpBody::parse(SAMPLE_SDP);
        let output = sdp.to_string();

        // Re-parse should produce same structure
        let reparsed = SdpBody::parse(&output);
        assert_eq!(reparsed.session_lines.len(), sdp.session_lines.len());
        assert_eq!(reparsed.media_sections.len(), sdp.media_sections.len());
        assert_eq!(
            reparsed.media_sections[0].formats,
            sdp.media_sections[0].formats
        );
    }

    #[test]
    fn filter_then_serialize() {
        let mut sdp = SdpBody::parse(SAMPLE_SDP);
        sdp.filter_codecs(&["PCMU", "PCMA"]);
        let output = sdp.to_string();

        assert!(output.contains("m=audio 49170 RTP/AVP 0 8"));
        assert!(output.contains("a=rtpmap:0 PCMU/8000"));
        assert!(output.contains("a=rtpmap:8 PCMA/8000"));
        assert!(!output.contains("opus"));
        assert!(!output.contains("telephone-event"));
    }

    #[test]
    fn rewrite_sdp_body_function() {
        let (new_body, length) = rewrite_sdp_body(SAMPLE_SDP, &["PCMU"]);
        assert!(new_body.contains("PCMU"));
        assert!(!new_body.contains("PCMA"));
        assert!(!new_body.contains("opus"));
        assert_eq!(length, new_body.len());
    }

    #[test]
    fn empty_sdp() {
        let sdp = SdpBody::parse("");
        assert!(sdp.session_lines.is_empty());
        assert!(sdp.media_sections.is_empty());
    }

    #[test]
    fn multiple_media_sections() {
        let sdp_str = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 0.0.0.0\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 5004 RTP/AVP 0 8\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "m=video 5006 RTP/AVP 96\r\n",
            "a=rtpmap:96 H264/90000\r\n",
        );

        let sdp = SdpBody::parse(sdp_str);
        assert_eq!(sdp.media_sections.len(), 2);
        assert_eq!(sdp.media_sections[0].media_type, "audio");
        assert_eq!(sdp.media_sections[1].media_type, "video");
    }

    #[test]
    fn static_codec_names() {
        assert_eq!(static_codec_name(0), Some("PCMU"));
        assert_eq!(static_codec_name(8), Some("PCMA"));
        assert_eq!(static_codec_name(9), Some("G722"));
        assert_eq!(static_codec_name(18), Some("G729"));
        assert_eq!(static_codec_name(99), None);
    }

    // -----------------------------------------------------------------
    // Attribute accessor tests
    // -----------------------------------------------------------------

    const SDP_WITH_ATTRS: &str = concat!(
        "v=0\r\n",
        "o=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n",
        "s=SIPhon\r\n",
        "c=IN IP4 10.0.0.1\r\n",
        "t=0 0\r\n",
        "a=group:BUNDLE audio video\r\n",
        "a=ice-lite\r\n",
        "m=audio 49170 RTP/AVP 0 8\r\n",
        "c=IN IP4 192.168.1.1\r\n",
        "a=sendrecv\r\n",
        "a=des:qos mandatory local sendrecv\r\n",
        "a=ptime:20\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
        "m=video 49172 RTP/AVP 96\r\n",
        "a=sendonly\r\n",
        "a=rtpmap:96 H264/90000\r\n",
    );

    #[test]
    fn attr_helpers() {
        assert!(attr_matches_name("sendrecv", "sendrecv"));
        assert!(attr_matches_name("des:qos mandatory", "des"));
        assert!(!attr_matches_name("des:qos mandatory", "sendrecv"));
        assert!(!attr_matches_name("sendrecv", "send"));

        assert_eq!(attr_extract_value("sendrecv"), "");
        assert_eq!(attr_extract_value("des:qos mandatory"), "qos mandatory");
        assert_eq!(attr_extract_value("ptime:20"), "20");
    }

    #[test]
    fn session_properties() {
        let sdp = SdpBody::parse(SDP_WITH_ATTRS);
        assert_eq!(
            sdp.origin(),
            Some("alice 2890844526 2890844526 IN IP4 10.0.0.1")
        );
        assert_eq!(sdp.session_name(), Some("SIPhon"));
        assert_eq!(sdp.connection(), Some("IN IP4 10.0.0.1"));
    }

    #[test]
    fn session_properties_missing() {
        let sdp = SdpBody::parse("v=0\r\nt=0 0\r\n");
        assert_eq!(sdp.origin(), None);
        assert_eq!(sdp.session_name(), None);
        assert_eq!(sdp.connection(), None);
    }

    #[test]
    fn session_attrs() {
        let sdp = SdpBody::parse(SDP_WITH_ATTRS);
        let attrs = sdp.session_attrs();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0], "group:BUNDLE audio video");
        assert_eq!(attrs[1], "ice-lite");
    }

    #[test]
    fn session_get_attr_with_value() {
        let sdp = SdpBody::parse(SDP_WITH_ATTRS);
        assert_eq!(sdp.session_get_attr("group"), Some("BUNDLE audio video"));
    }

    #[test]
    fn session_get_attr_flag() {
        let sdp = SdpBody::parse(SDP_WITH_ATTRS);
        assert_eq!(sdp.session_get_attr("ice-lite"), Some(""));
    }

    #[test]
    fn session_get_attr_missing() {
        let sdp = SdpBody::parse(SDP_WITH_ATTRS);
        assert_eq!(sdp.session_get_attr("nonexistent"), None);
    }

    #[test]
    fn session_has_attr() {
        let sdp = SdpBody::parse(SDP_WITH_ATTRS);
        assert!(sdp.session_has_attr("group"));
        assert!(sdp.session_has_attr("ice-lite"));
        assert!(!sdp.session_has_attr("sendrecv"));
    }

    #[test]
    fn session_set_attr_replace() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        sdp.session_set_attr("group", "BUNDLE audio");
        assert_eq!(sdp.session_get_attr("group"), Some("BUNDLE audio"));
        // Should not duplicate.
        assert_eq!(sdp.session_attrs().len(), 2);
    }

    #[test]
    fn session_set_attr_append() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        sdp.session_set_attr("msid-semantic", "WMS *");
        assert_eq!(sdp.session_get_attr("msid-semantic"), Some("WMS *"));
        assert_eq!(sdp.session_attrs().len(), 3);
    }

    #[test]
    fn session_set_attr_flag() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        sdp.session_set_attr("ice-options", "");
        assert!(sdp.session_has_attr("ice-options"));
        assert_eq!(sdp.session_get_attr("ice-options"), Some(""));
    }

    #[test]
    fn session_remove_attr() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        sdp.session_remove_attr("ice-lite");
        assert!(!sdp.session_has_attr("ice-lite"));
        assert!(sdp.session_has_attr("group"));
        assert_eq!(sdp.session_attrs().len(), 1);
    }

    #[test]
    fn set_session_attrs_bulk() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        sdp.set_session_attrs(&["tool:SIPhon", "recvonly"]);
        let attrs = sdp.session_attrs();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0], "tool:SIPhon");
        assert_eq!(attrs[1], "recvonly");
        // Non-a= lines preserved.
        assert!(sdp.origin().is_some());
        assert!(sdp.session_name().is_some());
    }

    #[test]
    fn media_connection() {
        let sdp = SdpBody::parse(SDP_WITH_ATTRS);
        assert_eq!(
            sdp.media_sections[0].connection(),
            Some("IN IP4 192.168.1.1")
        );
        assert_eq!(sdp.media_sections[1].connection(), None);
    }

    #[test]
    fn media_attrs() {
        let sdp = SdpBody::parse(SDP_WITH_ATTRS);
        let attrs = sdp.media_sections[0].attrs();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0], "sendrecv");
        assert_eq!(attrs[1], "des:qos mandatory local sendrecv");
        assert_eq!(attrs[2], "ptime:20");
    }

    #[test]
    fn media_get_attr() {
        let sdp = SdpBody::parse(SDP_WITH_ATTRS);
        let audio = &sdp.media_sections[0];
        assert_eq!(
            audio.get_attr("des"),
            Some("qos mandatory local sendrecv")
        );
        assert_eq!(audio.get_attr("ptime"), Some("20"));
        assert_eq!(audio.get_attr("sendrecv"), Some(""));
        assert_eq!(audio.get_attr("nonexistent"), None);
    }

    #[test]
    fn media_set_attr_replace() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        let audio = &mut sdp.media_sections[0];
        audio.set_attr("ptime", "30");
        assert_eq!(audio.get_attr("ptime"), Some("30"));
        assert_eq!(audio.attrs().len(), 3);
    }

    #[test]
    fn media_set_attr_append() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        let audio = &mut sdp.media_sections[0];
        audio.set_attr("maxptime", "60");
        assert_eq!(audio.get_attr("maxptime"), Some("60"));
        assert_eq!(audio.attrs().len(), 4);
    }

    #[test]
    fn media_set_attr_replace_flag_with_value() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        let video = &mut sdp.media_sections[1];
        assert_eq!(video.get_attr("sendonly"), Some(""));
        video.remove_attr("sendonly");
        video.set_attr("recvonly", "");
        assert!(video.has_attr("recvonly"));
        assert!(!video.has_attr("sendonly"));
    }

    #[test]
    fn media_remove_attr() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        let audio = &mut sdp.media_sections[0];
        audio.remove_attr("des");
        assert!(!audio.has_attr("des"));
        assert!(audio.has_attr("sendrecv"));
        assert!(audio.has_attr("ptime"));
    }

    #[test]
    fn media_has_attr() {
        let sdp = SdpBody::parse(SDP_WITH_ATTRS);
        let audio = &sdp.media_sections[0];
        assert!(audio.has_attr("sendrecv"));
        assert!(audio.has_attr("des"));
        assert!(audio.has_attr("ptime"));
        assert!(!audio.has_attr("rtcp"));
    }

    #[test]
    fn set_media_attrs_bulk() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        let audio = &mut sdp.media_sections[0];
        audio.set_attrs(&["sendonly", "ptime:30"]);
        let attrs = audio.attrs();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0], "sendonly");
        assert_eq!(attrs[1], "ptime:30");
        // Non-a= lines (c=) preserved.
        assert!(audio.connection().is_some());
    }

    #[test]
    fn media_codec_names() {
        let sdp = SdpBody::parse(SDP_WITH_ATTRS);
        let names = sdp.media_sections[0].codec_names();
        assert_eq!(names, vec!["PCMU", "PCMA"]);
    }

    #[test]
    fn media_codec_names_with_dynamic() {
        let sdp = SdpBody::parse(SAMPLE_SDP);
        let names = sdp.media_sections[0].codec_names();
        assert_eq!(names, vec!["PCMU", "PCMA", "opus", "telephone-event"]);
    }

    #[test]
    fn media_codec_names_static_only() {
        let sdp_str = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 0.0.0.0\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 5004 RTP/AVP 0 8 18\r\n",
        );
        let sdp = SdpBody::parse(sdp_str);
        let names = sdp.media_sections[0].codec_names();
        assert_eq!(names, vec!["PCMU", "PCMA", "G729"]);
    }

    #[test]
    fn remove_media_by_type() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        assert_eq!(sdp.media_sections.len(), 2);
        sdp.remove_media_by_type("video");
        assert_eq!(sdp.media_sections.len(), 1);
        assert_eq!(sdp.media_sections[0].media_type, "audio");
    }

    #[test]
    fn remove_media_by_type_nonexistent() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        sdp.remove_media_by_type("application");
        assert_eq!(sdp.media_sections.len(), 2);
    }

    #[test]
    fn roundtrip_after_attr_mutation() {
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        sdp.media_sections[0].set_attr("des", "qos optional local sendrecv");
        sdp.session_set_attr("ice-lite", "");

        let output = sdp.to_string();
        let reparsed = SdpBody::parse(&output);

        assert_eq!(
            reparsed.media_sections[0].get_attr("des"),
            Some("qos optional local sendrecv")
        );
        assert!(reparsed.session_has_attr("ice-lite"));
        assert_eq!(
            reparsed.media_sections[0].get_attr("ptime"),
            Some("20")
        );
    }

    #[test]
    fn qos_precondition_rewrite() {
        // The motivating use-case from the user.
        let mut sdp = SdpBody::parse(SDP_WITH_ATTRS);
        for media in &mut sdp.media_sections {
            if let Some(value) = media.get_attr("des") {
                if value.contains("mandatory") {
                    let new_value = value.replace("mandatory", "optional");
                    media.set_attr("des", &new_value);
                }
            }
        }
        let audio = &sdp.media_sections[0];
        assert_eq!(
            audio.get_attr("des"),
            Some("qos optional local sendrecv")
        );
    }

    // -----------------------------------------------------------------
    // Original tests
    // -----------------------------------------------------------------

    #[test]
    fn malformed_m_line_no_panic() {
        // m= with fewer than 4 tokens should not panic.
        let sdp_str = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 0.0.0.0\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 5060\r\n",
        );
        let sdp = SdpBody::parse(sdp_str);
        assert_eq!(sdp.media_sections.len(), 1);
        assert_eq!(sdp.media_sections[0].media_type, "audio");
        assert_eq!(sdp.media_sections[0].port, 5060);
        assert!(sdp.media_sections[0].formats.is_empty());
    }

    #[test]
    fn empty_formats_no_trailing_space() {
        // When all codecs are filtered out, the m= line should not have a trailing space.
        let sdp_str = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 0.0.0.0\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 49170 RTP/AVP 0 8\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
        );
        let mut sdp = SdpBody::parse(sdp_str);
        // Filter out everything — no codecs kept.
        sdp.filter_codecs(&["nonexistent"]);
        let output = sdp.to_string();
        assert!(
            output.contains("m=audio 49170 RTP/AVP\r\n"),
            "m= line should not have trailing space: {:?}",
            output
        );
    }

    #[test]
    fn filter_static_codecs_without_rtpmap() {
        // Some endpoints don't send rtpmap for static PTs
        let sdp_str = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 0.0.0.0\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 5004 RTP/AVP 0 8\r\n",
        );

        let mut sdp = SdpBody::parse(sdp_str);
        sdp.filter_codecs(&["PCMU"]);

        assert_eq!(sdp.media_sections[0].formats, vec![0]);
    }

    #[test]
    fn get_attrs_by_name_returns_all() {
        // SDP with two a=des: lines (local + remote preconditions)
        let sdp_str = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 0.0.0.0\r\n",
            "s=-\r\n",
            "c=IN IP4 0.0.0.0\r\n",
            "t=0 0\r\n",
            "m=audio 5004 RTP/AVP 0\r\n",
            "a=des:qos mandatory local sendrecv\r\n",
            "a=ptime:20\r\n",
            "a=des:qos mandatory remote sendrecv\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
        );
        let sdp = SdpBody::parse(sdp_str);
        let vals = sdp.media_sections[0].get_attrs_by_name("des");
        assert_eq!(vals.len(), 2);
        assert_eq!(vals[0], "qos mandatory local sendrecv");
        assert_eq!(vals[1], "qos mandatory remote sendrecv");
    }

    #[test]
    fn set_attrs_by_name_replaces_selectively() {
        let sdp_str = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 0.0.0.0\r\n",
            "s=-\r\n",
            "c=IN IP4 0.0.0.0\r\n",
            "t=0 0\r\n",
            "m=audio 5004 RTP/AVP 0\r\n",
            "a=des:qos mandatory local sendrecv\r\n",
            "a=ptime:20\r\n",
            "a=des:qos mandatory remote sendrecv\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
        );
        let mut sdp = SdpBody::parse(sdp_str);

        // Downgrade remote only
        sdp.media_sections[0].set_attrs_by_name("des", &[
            "qos mandatory local sendrecv",
            "qos optional remote sendrecv",
        ]);

        let vals = sdp.media_sections[0].get_attrs_by_name("des");
        assert_eq!(vals.len(), 2);
        assert_eq!(vals[0], "qos mandatory local sendrecv");
        assert_eq!(vals[1], "qos optional remote sendrecv");

        // ptime should be untouched
        assert_eq!(sdp.media_sections[0].get_attr("ptime"), Some("20"));
    }

    #[test]
    fn get_attrs_by_name_empty_when_missing() {
        let sdp = SdpBody::parse(SDP_WITH_ATTRS);
        assert!(sdp.media_sections[0].get_attrs_by_name("nonexistent").is_empty());
    }
}
