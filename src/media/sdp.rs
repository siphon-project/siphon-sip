//! SDP parser for codec filtering and attribute manipulation.
//!
//! Provides functionality to parse SDP bodies, extract/modify media lines
//! (`m=`) and codec attributes (`a=rtpmap`), filter codecs by name, and
//! get/set/remove arbitrary `a=` attributes at session and media level.
//!
//! This is NOT a full RFC 4566 parser — it handles the common cases needed for
//! SDP manipulation in a SIP proxy/B2BUA context. What it does not break out it
//! carries through as it arrived: a proxy or B2BUA has to pass on media it does
//! not model (T.38, WebRTC data channels, MSRP, floor control) intact.

/// A parsed media line from SDP.
#[derive(Debug, Clone)]
pub struct MediaLine {
    /// Media type: "audio", "video", "application", etc.
    pub media_type: String,
    /// Port number.
    pub port: u16,
    /// The number of ports an `m=<media> <port>/<count>` line gives
    /// (RFC 8866 §5.14), `None` when the line gives only the port.
    pub port_count: Option<u16>,
    /// Protocol: "RTP/AVP", "RTP/SAVPF", "UDP/TLS/RTP/SAVPF", "udptl", etc.
    /// Empty when the `m=` line has none.
    pub protocol: String,
    /// The media formats, verbatim and in order. RFC 8866 §5.14 makes each one
    /// a token: an RTP payload type number under an RTP protocol, and whatever
    /// the protocol defines otherwise (`t38`, `webrtc-datachannel`, `*`).
    pub formats: Vec<String>,
    /// Codec attributes keyed by payload type. An `a=rtpmap:` line whose
    /// payload type is not a number stays in `other_attrs` as it arrived.
    pub rtpmap: Vec<(u16, String)>,
    /// fmtp attributes keyed by format (RFC 8866 §6.15). An `a=fmtp:` line
    /// without parameters stays in `other_attrs` as it arrived.
    pub fmtp: Vec<(String, String)>,
    /// Other lines of this media section (everything but rtpmap/fmtp), kept in
    /// arrival order.  The serializer, not this vector, is what puts them into
    /// RFC 4566 §5 order — see [`PRE_ATTRIBUTE_PREFIXES`].
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
        let first_pos = self.other_attrs.iter().position(|line| {
            line.strip_prefix("a=")
                .is_some_and(|a| attr_matches_name(a, name))
        });

        // Remove all matches
        self.other_attrs.retain(|line| {
            line.strip_prefix("a=")
                .map_or(true, |attr| !attr_matches_name(attr, name))
        });

        // Build new lines
        let new_lines: Vec<String> = values
            .iter()
            .map(|value| {
                if value.is_empty() {
                    format!("a={name}")
                } else {
                    format!("a={name}:{value}")
                }
            })
            .collect();

        // Insert at original position, or append
        let insert_pos = first_pos
            .unwrap_or(self.other_attrs.len())
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
        if let Some(pos) = self.other_attrs.iter().position(|line| {
            line.strip_prefix("a=")
                .is_some_and(|a| attr_matches_name(a, name))
        }) {
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
    ///
    /// Only an RTP section has codecs: anywhere else a format is not a payload
    /// type, so the list is empty.
    pub fn codec_names(&self) -> Vec<String> {
        if !self.is_rtp() {
            return Vec::new();
        }
        self.formats
            .iter()
            .filter_map(|format| codec_name(&self.rtpmap, format))
            .map(str::to_string)
            .collect()
    }

    /// Whether this section carries RTP, which is what makes its formats RTP
    /// payload type numbers (RFC 8866 §5.14). `RTP/AVP`, `RTP/SAVPF`,
    /// `UDP/TLS/RTP/SAVPF` and `TCP/RTP/AVP` do; `udptl`, `UDP/DTLS/SCTP`,
    /// `TCP/MSRP` and a bare `udp` do not.
    pub fn is_rtp(&self) -> bool {
        self.protocol
            .split('/')
            .any(|part| part.eq_ignore_ascii_case("RTP"))
    }

    /// Keep the formats whose codec `keep` accepts, with their `rtpmap` and
    /// `fmtp` lines. `keep` gets the codec name, or `None` for a format that
    /// names no known codec.
    ///
    /// A section that is not RTP is left alone, since its formats are not
    /// codecs. An RTP section that would be left with no format is rejected
    /// instead (RFC 3264 §6, §8.2): port 0, and its first format stays because
    /// an `m=` line needs at least one (RFC 8866 §5.14).
    fn retain_codecs(&mut self, keep: impl Fn(Option<&str>) -> bool) {
        if !self.is_rtp() {
            return;
        }
        let rtpmap = &self.rtpmap;
        if self
            .formats
            .iter()
            .any(|format| keep(codec_name(rtpmap, format)))
        {
            self.formats
                .retain(|format| keep(codec_name(rtpmap, format)));
        } else if !self.formats.is_empty() {
            self.formats.truncate(1);
            self.port = 0;
            self.port_count = None;
        }
        let formats = &self.formats;
        self.rtpmap.retain(|(payload_type, _)| {
            formats.iter().any(|format| {
                format
                    .parse::<u16>()
                    .is_ok_and(|parsed| parsed == *payload_type)
            })
        });
        self.fmtp.retain(|(format, _)| formats.contains(format));
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
                if let Some(rtpmap) = parse_rtpmap(line) {
                    // a=rtpmap:97 opus/48000/2
                    media.rtpmap.push(rtpmap);
                } else if let Some(fmtp) = parse_fmtp(line) {
                    // a=fmtp:97 minptime=10;useinbandfec=1
                    media.fmtp.push(fmtp);
                } else {
                    // Everything else, an rtpmap or fmtp line that does not
                    // read as one included, goes back out as it came in.
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
    ///
    /// Only RTP sections are filtered, and a stream left with none of the
    /// codecs is rejected rather than emptied (see `MediaLine::retain_codecs`).
    pub fn filter_codecs(&mut self, keep: &[&str]) {
        for media in &mut self.media_sections {
            media.retain_codecs(|name| {
                name.is_some_and(|name| keep.iter().any(|wanted| wanted.eq_ignore_ascii_case(name)))
            });
        }
    }

    /// Remove codecs by name. Opposite of `filter_codecs`, with the same scope:
    /// RTP sections only, and a stream left with no codec is rejected.
    pub fn remove_codecs(&mut self, remove: &[&str]) {
        for media in &mut self.media_sections {
            media.retain_codecs(|name| match name {
                Some(name) => !remove
                    .iter()
                    .any(|unwanted| unwanted.eq_ignore_ascii_case(name)),
                None => true,
            });
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
        let first_pos = self.session_lines.iter().position(|line| {
            line.strip_prefix("a=")
                .is_some_and(|a| attr_matches_name(a, name))
        });
        self.session_lines.retain(|line| {
            line.strip_prefix("a=")
                .map_or(true, |attr| !attr_matches_name(attr, name))
        });
        let insert_pos = first_pos
            .unwrap_or(self.session_lines.len())
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
        if let Some(pos) = self.session_lines.iter().position(|line| {
            line.strip_prefix("a=")
                .is_some_and(|a| attr_matches_name(a, name))
        }) {
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

/// The media-description lines RFC 4566 §5 places between `m=` and the
/// attribute region, in the order it fixes for them.  `k=` is deprecated by
/// RFC 8866 but still has a defined slot, and a body that carries one has to be
/// re-emitted somewhere legal.
const PRE_ATTRIBUTE_PREFIXES: [&str; 4] = ["i=", "c=", "b=", "k="];

/// Whether `line` belongs ahead of the `a=` region rather than in it.
fn is_pre_attribute_line(line: &str) -> bool {
    PRE_ATTRIBUTE_PREFIXES
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

impl std::fmt::Display for SdpBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for line in &self.session_lines {
            write!(f, "{line}\r\n")?;
        }

        for media in &self.media_sections {
            // m=audio 49170 RTP/AVP 0 8 97, with only the fields the section
            // has: nothing invented for a line that arrived short, and no
            // trailing space.
            write!(f, "m={} {}", media.media_type, media.port)?;
            if let Some(count) = media.port_count {
                write!(f, "/{count}")?;
            }
            if !media.protocol.is_empty() {
                write!(f, " {}", media.protocol)?;
            }
            for format in &media.formats {
                write!(f, " {format}")?;
            }
            write!(f, "\r\n")?;

            // RFC 4566 §5 fixes the order inside a media description: m=,
            // i=, c=, b=, k=, then a=.  The parser buckets every line that is
            // not an rtpmap/fmtp into `other_attrs` in arrival order, so a body
            // that arrived with its c= behind an attribute would otherwise be
            // re-emitted in that same illegal order.  A strict parser (several
            // vendor SBCs) then reads the section as carrying no connection
            // address at all and answers 400 Bad Request on a body every
            // lenient parser accepts, which makes it a per-carrier mystery
            // rather than an obvious defect.  Partition on the way out instead.
            //
            // Relative order is preserved *within* each group: §5 fixes where
            // the groups go, not what the sender puts inside one, and the order
            // of repeated b= lines and of the attribute sequence carries
            // meaning.
            for prefix in PRE_ATTRIBUTE_PREFIXES {
                for line in media
                    .other_attrs
                    .iter()
                    .filter(|line| line.starts_with(prefix))
                {
                    write!(f, "{line}\r\n")?;
                }
            }

            // The attribute region.  A line legal nowhere in a media
            // description rides here rather than being dropped — this is a
            // serializer, not a validator.
            for line in media
                .other_attrs
                .iter()
                .filter(|line| !is_pre_attribute_line(line))
            {
                write!(f, "{line}\r\n")?;
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
///
/// `media-field = "m=" media SP port ["/" integer] SP proto 1*(SP fmt)`
/// (RFC 8866 §9). Every format is kept as the token it is, and a field the
/// line lacks is left empty rather than filled in.
fn parse_media_line(line: &str) -> MediaLine {
    let content = line.strip_prefix("m=").unwrap_or(line);
    let mut fields = content.split_whitespace();

    let media_type = fields.next().unwrap_or_default().to_string();
    let (port, port_count): (u16, Option<u16>) = match fields.next() {
        Some(field) => match field.split_once('/') {
            Some((port, count)) => (port.parse().unwrap_or(0), count.parse().ok()),
            None => (field.parse().unwrap_or(0), None),
        },
        None => (0, None),
    };
    let protocol = fields.next().unwrap_or_default().to_string();
    let formats = fields.map(str::to_string).collect();

    MediaLine {
        media_type,
        port,
        port_count,
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

/// Parse `a=fmtp:97 minptime=10` → ("97", "minptime=10"). The format is a
/// token like any other (RFC 8866 §6.15), so one that is not a payload type
/// number reads too.
fn parse_fmtp(line: &str) -> Option<(String, String)> {
    let content = line.strip_prefix("a=fmtp:")?;
    let (format, parameters) = content.split_once(' ')?;
    Some((format.to_string(), parameters.to_string()))
}

/// The codec an RTP format names: its `a=rtpmap:` encoding name, else the
/// RFC 3551 static name of its payload type. `None` for a format that is not a
/// payload type number or that names no known codec.
fn codec_name<'a>(rtpmap: &'a [(u16, String)], format: &str) -> Option<&'a str> {
    let payload_type = format.parse::<u16>().ok()?;
    match rtpmap.iter().find(|(mapped, _)| *mapped == payload_type) {
        Some((_, encoding)) => encoding.split('/').next(),
        None => static_codec_name(payload_type),
    }
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

/// Whether `name` is an SDP attribute name: `attribute-name = token` in the
/// RFC 8866 §9 grammar, one or more of ALPHA, DIGIT and ``!#$%&'*+-.^_`{|}~``.
///
/// A name outside that set can never be the name of an `a=` line, which is why
/// operator-configured names are held to it at load.
pub fn is_attribute_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_token_char)
}

/// RFC 8866 §9 `token-char`.
fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

/// Remove every `a=` line whose attribute name is one of `names`, at session and
/// media level alike, comparing names ASCII case-insensitively.
///
/// Works on the raw lines rather than a [`SdpBody`] parse and serialize, so every
/// line it keeps goes out exactly as it came in: its line ending, its position,
/// and the lines `SdpBody` does not model. Returns whether anything was removed.
/// A body with no matching line is neither copied nor rewritten.
pub fn strip_attributes(body: &mut Vec<u8>, names: &[String]) -> bool {
    if names.is_empty() {
        return false;
    }
    retain_lines(body, |line| !is_attribute_line_named(line, names))
}

/// Whether `line` is an `a=` line whose attribute name is one of `names`, ASCII
/// case-insensitively. The name runs from after `a=` to the first `:` or the end
/// of the line, so `msid` names `a=msid:…` and not `a=msid-semantic:…`.
pub(crate) fn is_attribute_line_named(line: &[u8], names: &[String]) -> bool {
    let Some(attribute) = line.strip_prefix(b"a=") else {
        return false;
    };
    let name_length = attribute
        .iter()
        .position(|&byte| matches!(byte, b':' | b'\r' | b'\n'))
        .unwrap_or(attribute.len());
    let name = &attribute[..name_length];
    names
        .iter()
        .any(|configured| configured.as_bytes().eq_ignore_ascii_case(name))
}

/// Drop the lines of `body` that `keep` refuses and leave every other line byte
/// for byte, line ending included. Lines are split after each `\n`, so a last
/// line with no terminator is a line too. Returns whether any line was dropped;
/// until the first one is, nothing is copied.
pub(crate) fn retain_lines(body: &mut Vec<u8>, mut keep: impl FnMut(&[u8]) -> bool) -> bool {
    let mut kept: Option<Vec<u8>> = None;
    let mut offset = 0;
    for line in body.split_inclusive(|&byte| byte == b'\n') {
        let keep_line = keep(line);
        match kept.as_mut() {
            Some(buffer) => {
                if keep_line {
                    buffer.extend_from_slice(line);
                }
            }
            None if !keep_line => {
                // The first line to go: everything before it stays as it was.
                let mut buffer = Vec::with_capacity(body.len());
                buffer.extend_from_slice(&body[..offset]);
                kept = Some(buffer);
            }
            None => {}
        }
        offset += line.len();
    }
    match kept {
        Some(buffer) => {
            *body = buffer;
            true
        }
        None => false,
    }
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
        assert_eq!(media.formats, vec!["0", "8", "97", "101"]);
        assert_eq!(media.port_count, None);
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
        assert_eq!(media.fmtp[0].0, "97");
        assert!(media.fmtp[0].1.contains("minptime=10"));
        assert_eq!(media.fmtp[1].0, "101");
    }

    #[test]
    fn filter_codecs_keep_pcmu_pcma() {
        let mut sdp = SdpBody::parse(SAMPLE_SDP);
        sdp.filter_codecs(&["PCMU", "PCMA"]);

        let media = &sdp.media_sections[0];
        assert_eq!(media.formats, vec!["0", "8"]);
        assert_eq!(media.rtpmap.len(), 2);
        assert!(media.fmtp.is_empty()); // opus and telephone-event fmtp removed
    }

    #[test]
    fn filter_codecs_case_insensitive() {
        let mut sdp = SdpBody::parse(SAMPLE_SDP);
        sdp.filter_codecs(&["pcmu", "Opus"]);

        let media = &sdp.media_sections[0];
        assert_eq!(media.formats, vec!["0", "97"]);
    }

    #[test]
    fn remove_codecs() {
        let mut sdp = SdpBody::parse(SAMPLE_SDP);
        sdp.remove_codecs(&["telephone-event"]);

        let media = &sdp.media_sections[0];
        assert_eq!(media.formats, vec!["0", "8", "97"]);
        assert!(!media
            .rtpmap
            .iter()
            .any(|(_, c)| c.contains("telephone-event")));
    }

    /// The media block of `sdp`, as emitted lines, from its `m=` onward.
    fn emitted_media_lines(sdp: &str) -> Vec<String> {
        let output = SdpBody::parse(sdp).to_string();
        let lines: Vec<&str> = output.lines().collect();
        let start = lines
            .iter()
            .position(|line| line.starts_with("m="))
            .expect("no media section in the emitted body");
        lines[start..].iter().map(|line| line.to_string()).collect()
    }

    #[test]
    fn serialize_repairs_a_connection_line_behind_an_attribute() {
        // RFC 4566 §5 fixes m=, i=, c=, b=, k=, then a= inside a media
        // description.  This offer carries its c= behind an attribute, which
        // several vendor SBCs reject with 400 Bad Request because they read the
        // section as having no connection address.  A parse/apply round-trip
        // has to repair that, not reproduce it.
        let raw = concat!(
            "v=0\r\n",
            "o=- 1 0 IN IP4 192.0.2.10\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 30168 RTP/AVP 8 101\r\n",
            "a=rtcp:30169\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "a=mid:audio\r\n",
            "a=sendrecv\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
        );

        // Asserted as an exact line sequence: a `contains` check passes just as
        // happily on the broken order, which is why the ordering bug survived
        // the serializer tests that were already here.
        assert_eq!(
            emitted_media_lines(raw),
            vec![
                "m=audio 30168 RTP/AVP 8 101",
                "c=IN IP4 192.0.2.10",
                "a=rtcp:30169",
                "a=mid:audio",
                "a=sendrecv",
                "a=rtpmap:8 PCMA/8000",
                "a=rtpmap:101 telephone-event/8000",
            ],
        );
    }

    #[test]
    fn serialize_orders_information_bandwidth_and_key_ahead_of_attributes() {
        // i=, b= and k= are displaced by the same arm as c= and need the same
        // repair.  Repeated b= lines keep their relative order — §5 fixes where
        // the group sits, not what the sender puts inside it.
        let raw = concat!(
            "v=0\r\n",
            "o=- 1 0 IN IP4 192.0.2.10\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 30168 RTP/AVP 8\r\n",
            "a=sendrecv\r\n",
            "b=TIAS:64000\r\n",
            "k=prompt\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "b=AS:64\r\n",
            "i=voice\r\n",
            "a=ptime:20\r\n",
        );

        assert_eq!(
            emitted_media_lines(raw),
            vec![
                "m=audio 30168 RTP/AVP 8",
                "i=voice",
                "c=IN IP4 192.0.2.10",
                "b=TIAS:64000",
                "b=AS:64",
                "k=prompt",
                "a=sendrecv",
                "a=ptime:20",
            ],
        );
    }

    #[test]
    fn serialize_leaves_a_conformant_media_section_untouched() {
        // The reorder is a repair, not a reshuffle: a section already in §5
        // order comes back byte-identical, so nothing that was on the wire
        // before this changes shape.
        let raw = concat!(
            "v=0\r\n",
            "o=- 1 0 IN IP4 192.0.2.10\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 30168 RTP/AVP 8 101\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "a=sendrecv\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=fmtp:101 0-15\r\n",
        );
        assert_eq!(SdpBody::parse(raw).to_string(), raw);
    }

    #[test]
    fn serialize_orders_every_media_section_independently() {
        // A second section is partitioned on its own lines, not against the
        // first one's — the audio c= must not migrate into the video block.
        let raw = concat!(
            "v=0\r\n",
            "o=- 1 0 IN IP4 192.0.2.10\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 30168 RTP/AVP 8\r\n",
            "a=sendrecv\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "m=video 30170 RTP/AVP 96\r\n",
            "a=recvonly\r\n",
            "c=IN IP4 192.0.2.11\r\n",
        );

        assert_eq!(
            emitted_media_lines(raw),
            vec![
                "m=audio 30168 RTP/AVP 8",
                "c=IN IP4 192.0.2.10",
                "a=sendrecv",
                "m=video 30170 RTP/AVP 96",
                "c=IN IP4 192.0.2.11",
                "a=recvonly",
            ],
        );
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
        assert_eq!(audio.get_attr("des"), Some("qos mandatory local sendrecv"));
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
        assert_eq!(reparsed.media_sections[0].get_attr("ptime"), Some("20"));
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
        assert_eq!(audio.get_attr("des"), Some("qos optional local sendrecv"));
    }

    // -----------------------------------------------------------------
    // Original tests
    // -----------------------------------------------------------------

    #[test]
    fn malformed_m_line_no_panic() {
        // m= with fewer than 4 tokens should not panic, and is not given a
        // protocol it never had: it goes back out as it came in.
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
        assert_eq!(sdp.media_sections[0].protocol, "");
        assert!(!sdp.media_sections[0].is_rtp());
        assert!(sdp.media_sections[0].formats.is_empty());
        assert_eq!(sdp.to_string(), sdp_str);
    }

    #[test]
    fn filter_codecs_rejects_a_stream_left_with_no_codec() {
        // RFC 8866 §5.14 requires at least one format on an m= line, so a
        // stream with none of the wanted codecs cannot be emptied. It is
        // rejected the RFC 3264 §6 way instead: port 0, one format kept.
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
        sdp.filter_codecs(&["nonexistent"]);
        assert_eq!(
            sdp.to_string(),
            concat!(
                "v=0\r\n",
                "o=- 0 0 IN IP4 0.0.0.0\r\n",
                "s=-\r\n",
                "t=0 0\r\n",
                "m=audio 0 RTP/AVP 0\r\n",
                "a=rtpmap:0 PCMU/8000\r\n",
            )
        );
    }

    #[test]
    fn removing_every_codec_rejects_the_stream_and_drops_its_port_count() {
        let mut sdp =
            SdpBody::parse("v=0\r\nm=audio 49170/2 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n");
        sdp.remove_codecs(&["PCMA"]);
        assert_eq!(sdp.media_sections[0].port_count, None);
        assert_eq!(
            sdp.to_string(),
            "v=0\r\nm=audio 0 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"
        );
    }

    #[test]
    fn filter_codecs_leaves_a_section_with_no_formats_as_it_is() {
        // Only a malformed m= line has no format to begin with. There is no
        // format to keep, so the port is not touched, and the line still goes
        // out without a trailing space.
        let mut sdp = SdpBody::parse("v=0\r\nm=audio 5060 RTP/AVP\r\n");
        sdp.filter_codecs(&["PCMU"]);
        assert_eq!(sdp.media_sections[0].port, 5060);
        assert_eq!(sdp.to_string(), "v=0\r\nm=audio 5060 RTP/AVP\r\n");
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

        assert_eq!(sdp.media_sections[0].formats, vec!["0"]);
    }

    // -----------------------------------------------------------------
    // Formats that are not RTP payload types (RFC 8866 §5.14)
    // -----------------------------------------------------------------

    /// Every section but the audio one has a format that is a token rather
    /// than a payload type number: T.38 fax, a WebRTC data channel, MSRP, and a
    /// floor-control stream whose format also keys an fmtp line.
    const MIXED_FORMATS_SDP: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 49170 RTP/AVP 8 101\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
        "a=rtpmap:101 telephone-event/8000\r\n",
        "a=fmtp:101 0-15\r\n",
        "m=image 49172 udptl t38\r\n",
        "a=T38FaxVersion:0\r\n",
        "a=T38FaxRateManagement:transferredTCF\r\n",
        "m=application 49174 UDP/DTLS/SCTP webrtc-datachannel\r\n",
        "a=sctp-port:5000\r\n",
        "m=message 49176 TCP/MSRP *\r\n",
        "a=accept-types:message/cpim text/plain\r\n",
        "m=application 49178 udp MCPTT\r\n",
        "a=fmtp:MCPTT mc_queueing;mc_priority=5\r\n",
    );

    #[test]
    fn token_formats_and_their_fmtp_survive_a_round_trip() {
        let sdp = SdpBody::parse(MIXED_FORMATS_SDP);
        assert_eq!(sdp.media_sections[1].formats, vec!["t38"]);
        assert_eq!(sdp.media_sections[2].formats, vec!["webrtc-datachannel"]);
        assert_eq!(sdp.media_sections[3].formats, vec!["*"]);
        assert_eq!(sdp.media_sections[4].formats, vec!["MCPTT"]);
        assert_eq!(
            sdp.media_sections[4].fmtp,
            vec![("MCPTT".to_string(), "mc_queueing;mc_priority=5".to_string())]
        );
        assert_eq!(sdp.to_string(), MIXED_FORMATS_SDP);
    }

    #[test]
    fn codec_filtering_leaves_sections_that_are_not_rtp_alone() {
        let without_telephone_event = |audio_line: &str| {
            MIXED_FORMATS_SDP
                .replace("m=audio 49170 RTP/AVP 8 101\r\n", audio_line)
                .replace("a=rtpmap:101 telephone-event/8000\r\n", "")
                .replace("a=fmtp:101 0-15\r\n", "")
        };

        let mut sdp = SdpBody::parse(MIXED_FORMATS_SDP);
        sdp.filter_codecs(&["PCMA"]);
        assert_eq!(
            sdp.to_string(),
            without_telephone_event("m=audio 49170 RTP/AVP 8\r\n")
        );

        // Removing both audio codecs rejects the audio stream and still leaves
        // every other section as it was.
        let mut sdp = SdpBody::parse(MIXED_FORMATS_SDP);
        sdp.remove_codecs(&["PCMA", "telephone-event"]);
        assert_eq!(
            sdp.to_string(),
            without_telephone_event("m=audio 0 RTP/AVP 8\r\n")
        );
    }

    #[test]
    fn sections_that_are_not_rtp_have_no_codecs() {
        let sdp = SdpBody::parse(MIXED_FORMATS_SDP);
        assert_eq!(
            sdp.media_sections[0].codec_names(),
            vec!["PCMA", "telephone-event"]
        );
        for media in &sdp.media_sections[1..] {
            assert!(media.codec_names().is_empty(), "{}", media.protocol);
        }
    }

    #[test]
    fn is_rtp_reads_the_protocol() {
        for protocol in [
            "RTP/AVP",
            "RTP/SAVP",
            "RTP/AVPF",
            "RTP/SAVPF",
            "UDP/TLS/RTP/SAVPF",
            "TCP/RTP/AVP",
            "TCP/TLS/RTP/AVP",
        ] {
            let sdp = SdpBody::parse(&format!("m=audio 5004 {protocol} 0\r\n"));
            assert!(sdp.media_sections[0].is_rtp(), "{protocol}");
        }
        for protocol in [
            "udptl",
            "UDP/DTLS/SCTP",
            "TCP/MSRP",
            "TCP/TLS/MSRP",
            "TCP/BFCP",
            "udp",
        ] {
            let sdp = SdpBody::parse(&format!("m=application 5004 {protocol} x\r\n"));
            assert!(!sdp.media_sections[0].is_rtp(), "{protocol}");
        }
    }

    #[test]
    fn port_count_survives_a_round_trip() {
        // `49170/2` used to fail the port parse and read as port 0, which
        // disables the stream.
        let raw = "v=0\r\nm=video 49170/2 RTP/AVP 31\r\n";
        let sdp = SdpBody::parse(raw);
        assert_eq!(sdp.media_sections[0].port, 49170);
        assert_eq!(sdp.media_sections[0].port_count, Some(2));
        assert_eq!(sdp.to_string(), raw);
    }

    #[test]
    fn unreadable_rtpmap_and_fmtp_lines_are_kept() {
        // Neither line breaks out into rtpmap/fmtp, so both stay among the
        // section's other lines instead of being deleted.
        let raw = concat!(
            "v=0\r\n",
            "m=audio 49170 RTP/AVP 97\r\n",
            "a=rtpmap:dynamic opus/48000/2\r\n",
            "a=fmtp:97\r\n",
        );
        let sdp = SdpBody::parse(raw);
        assert!(sdp.media_sections[0].rtpmap.is_empty());
        assert!(sdp.media_sections[0].fmtp.is_empty());
        assert_eq!(sdp.to_string(), raw);
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
        sdp.media_sections[0].set_attrs_by_name(
            "des",
            &[
                "qos mandatory local sendrecv",
                "qos optional remote sendrecv",
            ],
        );

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
        assert!(sdp.media_sections[0]
            .get_attrs_by_name("nonexistent")
            .is_empty());
    }

    fn attribute_names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn strip_attributes_removes_named_attributes_at_session_and_media_level() {
        let mut body = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.0.2.10\r\n",
            "s=-\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "t=0 0\r\n",
            "a=x-hidden\r\n",
            "a=msid-semantic: WMS stream-a\r\n",
            "m=audio 40000 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=msid:stream-a track-a\r\n",
            "a=x-hidden:detail\r\n",
            "a=sendrecv\r\n",
        )
        .as_bytes()
        .to_vec();

        assert!(strip_attributes(
            &mut body,
            &attribute_names(&["msid", "x-hidden"])
        ));
        // `msid-semantic` shares a prefix with `msid` and is a different
        // attribute, so it stays.
        assert_eq!(
            String::from_utf8(body).expect("utf-8"),
            concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 192.0.2.10\r\n",
                "s=-\r\n",
                "c=IN IP4 192.0.2.10\r\n",
                "t=0 0\r\n",
                "a=msid-semantic: WMS stream-a\r\n",
                "m=audio 40000 RTP/AVP 0\r\n",
                "a=rtpmap:0 PCMU/8000\r\n",
                "a=sendrecv\r\n",
            )
        );
    }

    #[test]
    fn strip_attributes_matches_names_case_insensitively() {
        for configured in ["msid", "MSID", "MsId"] {
            let mut body =
                b"v=0\r\na=msid:stream-a track-a\r\na=MSID:stream-b track-b\r\n".to_vec();
            assert!(
                strip_attributes(&mut body, &attribute_names(&[configured])),
                "{configured}"
            );
            assert_eq!(body, b"v=0\r\n".to_vec(), "{configured}");
        }
    }

    #[test]
    fn strip_attributes_removes_an_attribute_with_and_without_a_value() {
        let mut body = b"a=x-hidden\r\na=x-hidden:detail\r\na=x-hidden:\r\na=sendrecv\r\n".to_vec();
        assert!(strip_attributes(&mut body, &attribute_names(&["x-hidden"])));
        assert_eq!(body, b"a=sendrecv\r\n".to_vec());
    }

    #[test]
    fn strip_attributes_leaves_a_body_with_nothing_to_strip_byte_identical() {
        // Mixed line endings, a line `SdpBody` does not model and a last line
        // with no terminator: a serialize round trip would move some of it.
        let original =
            b"v=0\na=sendrecv\r\nx=unmodelled\r\na=msid-semantic: WMS\r\na=rtpmap:0 PCMU/8000"
                .to_vec();
        let mut body = original.clone();

        assert!(!strip_attributes(
            &mut body,
            &attribute_names(&["msid", "x-hidden"])
        ));
        assert_eq!(body, original);

        assert!(!strip_attributes(&mut body, &[]));
        assert_eq!(body, original);
    }

    #[test]
    fn strip_attributes_keeps_the_line_endings_of_the_lines_it_keeps() {
        let mut body = b"v=0\na=x-hidden\r\na=sendrecv\na=x-hidden".to_vec();
        assert!(strip_attributes(&mut body, &attribute_names(&["x-hidden"])));
        assert_eq!(body, b"v=0\na=sendrecv\n".to_vec());
    }

    #[test]
    fn strip_attributes_reads_only_the_name_of_an_attribute_line() {
        // The name appearing in a value, in another line type or after `a=`
        // somewhere other than the start of a line is not the attribute.
        let original =
            b"s=x-hidden\r\ni=a=x-hidden\r\na=label:x-hidden\r\n a=x-hidden\r\n".to_vec();
        let mut body = original.clone();
        assert!(!strip_attributes(
            &mut body,
            &attribute_names(&["x-hidden"])
        ));
        assert_eq!(body, original);
    }

    #[test]
    fn is_attribute_name_accepts_every_token_char() {
        for name in [
            "msid",
            "rtcp-fb",
            "X-Vendor_Tag.1",
            "AZaz09",
            "!#$%&'*+-.^_`{|}~",
        ] {
            assert!(is_attribute_name(name), "{name:?} was refused");
        }
    }

    #[test]
    fn is_attribute_name_refuses_what_is_not_a_token() {
        for name in [
            "",
            "a=msid",
            "msid:1",
            "ms id",
            "msid\r",
            "(msid)",
            "ms\"id",
            "m\u{e9}sid",
            "@",
            "[x]",
            "a/b",
            "a?",
            "<x>",
            "a,b",
            "a;b",
            "a\\b",
        ] {
            assert!(!is_attribute_name(name), "{name:?} was accepted");
        }
    }
}
