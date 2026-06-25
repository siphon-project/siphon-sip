//! Multipart MIME body parser for SIP messages.
//!
//! Parses `Content-Type: multipart/mixed; boundary=...` bodies into
//! individual parts.  Used by the SRS to extract SDP and recording
//! metadata from inbound SIPREC INVITEs (RFC 7866).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MultipartError {
    #[error("missing boundary parameter in Content-Type")]
    MissingBoundary,
    #[error("no parts found in multipart body")]
    NoParts,
    #[error("part missing Content-Type header")]
    MissingPartContentType,
}

/// A single part extracted from a multipart body.
#[derive(Debug, Clone)]
pub struct MimePart {
    /// Content-Type of this part (e.g. "application/sdp").
    pub content_type: String,
    /// Raw body bytes of this part.
    pub body: Vec<u8>,
}

/// Extract the `boundary` value from a Content-Type header.
///
/// Handles both `boundary=value` and `boundary="value"` forms.
pub fn extract_boundary(content_type: &str) -> Result<String, MultipartError> {
    // Find "boundary=" (case-insensitive)
    let lower = content_type.to_ascii_lowercase();
    let boundary_pos = lower
        .find("boundary=")
        .ok_or(MultipartError::MissingBoundary)?;

    let after_eq = &content_type[boundary_pos + 9..];

    // Strip optional quotes.
    let boundary = if let Some(stripped) = after_eq.strip_prefix('"') {
        // Quoted boundary — find closing quote.
        let end = stripped.find('"').unwrap_or(stripped.len());
        &stripped[..end]
    } else {
        // Unquoted — terminated by `;`, `,`, whitespace, or end of string.
        let end = after_eq
            .find(|character: char| character == ';' || character == ',' || character.is_whitespace())
            .unwrap_or(after_eq.len());
        &after_eq[..end]
    };

    if boundary.is_empty() {
        return Err(MultipartError::MissingBoundary);
    }

    Ok(boundary.to_string())
}

/// Parse a multipart body into its constituent parts.
///
/// The `content_type` must be the full Content-Type header value
/// (e.g. `multipart/mixed;boundary=srec-abc123`).  The `body` is the
/// raw message body bytes.
pub fn parse_multipart(content_type: &str, body: &[u8]) -> Result<Vec<MimePart>, MultipartError> {
    let boundary = extract_boundary(content_type)?;
    let delimiter = format!("--{boundary}");
    let close_delimiter = format!("--{boundary}--");

    let body_str = String::from_utf8_lossy(body);
    let mut parts = Vec::new();

    // Split by delimiter; skip preamble (before first delimiter) and
    // epilogue (after closing delimiter).
    let mut sections: Vec<&str> = body_str.split(&delimiter).collect();

    // Remove preamble (first element).
    if !sections.is_empty() {
        sections.remove(0);
    }

    for section in sections {
        // Stop at the closing delimiter (section starts with "--").
        let trimmed = section.trim_start_matches("\r\n").trim_start_matches('\n');
        if trimmed.starts_with("--") || trimmed.is_empty() {
            continue;
        }

        // Strip the closing delimiter suffix if present.
        let section = if let Some(before_close) = section.strip_suffix(&close_delimiter[delimiter.len()..]) {
            before_close
        } else {
            section
        };

        // Each part has headers separated from body by a blank line (\r\n\r\n).
        let header_end = if let Some(position) = section.find("\r\n\r\n") {
            position
        } else if let Some(position) = section.find("\n\n") {
            position
        } else {
            // No header/body separator — treat entire section as body with no headers.
            continue;
        };

        let header_block = &section[..header_end];
        let body_start = if section[header_end..].starts_with("\r\n\r\n") {
            header_end + 4
        } else {
            header_end + 2
        };
        let part_body = section[body_start..].trim_end_matches("\r\n").trim_end_matches('\n');

        // Extract Content-Type from the part headers.
        let mut part_content_type = None;
        for line in header_block.lines() {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("Content-Type:").or_else(|| line.strip_prefix("content-type:")) {
                part_content_type = Some(value.trim().to_string());
            }
        }

        let part_content_type = part_content_type.ok_or(MultipartError::MissingPartContentType)?;

        parts.push(MimePart {
            content_type: part_content_type,
            body: part_body.as_bytes().to_vec(),
        });
    }

    if parts.is_empty() {
        return Err(MultipartError::NoParts);
    }

    Ok(parts)
}

/// Find the first part with the given content type prefix.
///
/// Useful for extracting the SDP or metadata part from a SIPREC body.
pub fn find_part<'a>(parts: &'a [MimePart], content_type_prefix: &str) -> Option<&'a MimePart> {
    parts.iter().find(|part| part.content_type.starts_with(content_type_prefix))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_boundary_unquoted() {
        let content_type = "multipart/mixed;boundary=srec-abc123";
        let boundary = extract_boundary(content_type).unwrap();
        assert_eq!(boundary, "srec-abc123");
    }

    #[test]
    fn extract_boundary_quoted() {
        let content_type = "multipart/mixed; boundary=\"srec-abc123\"";
        let boundary = extract_boundary(content_type).unwrap();
        assert_eq!(boundary, "srec-abc123");
    }

    #[test]
    fn extract_boundary_with_spaces() {
        let content_type = "multipart/mixed; boundary=srec-abc123; charset=utf-8";
        let boundary = extract_boundary(content_type).unwrap();
        assert_eq!(boundary, "srec-abc123");
    }

    #[test]
    fn extract_boundary_missing() {
        let content_type = "application/sdp";
        assert!(extract_boundary(content_type).is_err());
    }

    #[test]
    fn extract_boundary_case_insensitive() {
        let content_type = "multipart/mixed; Boundary=MyBound";
        let boundary = extract_boundary(content_type).unwrap();
        assert_eq!(boundary, "MyBound");
    }

    #[test]
    fn parse_siprec_multipart_body() {
        let boundary = "srec-abc123";
        let body = concat!(
            "--srec-abc123\r\n",
            "Content-Type: application/sdp\r\n",
            "\r\n",
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=recvonly\r\n",
            "\r\n",
            "--srec-abc123\r\n",
            "Content-Type: application/rs-metadata+xml\r\n",
            "\r\n",
            "<?xml version=\"1.0\"?>\r\n",
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\r\n",
            "  <datamode>complete</datamode>\r\n",
            "</recording>\r\n",
            "\r\n",
            "--srec-abc123--\r\n",
        );

        let content_type = format!("multipart/mixed;boundary={boundary}");
        let parts = parse_multipart(&content_type, body.as_bytes()).unwrap();
        assert_eq!(parts.len(), 2);

        assert_eq!(parts[0].content_type, "application/sdp");
        let sdp = String::from_utf8_lossy(&parts[0].body);
        assert!(sdp.contains("v=0"));
        assert!(sdp.contains("a=recvonly"));

        assert_eq!(parts[1].content_type, "application/rs-metadata+xml");
        let xml = String::from_utf8_lossy(&parts[1].body);
        assert!(xml.contains("<recording"));
        assert!(xml.contains("<datamode>complete</datamode>"));
    }

    #[test]
    fn parse_empty_body() {
        let content_type = "multipart/mixed;boundary=test";
        assert!(parse_multipart(content_type, b"").is_err());
    }

    #[test]
    fn parse_single_part() {
        let body = concat!(
            "--boundary1\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "Hello, world!\r\n",
            "--boundary1--\r\n",
        );
        let parts = parse_multipart("multipart/mixed;boundary=boundary1", body.as_bytes()).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].content_type, "text/plain");
        assert_eq!(String::from_utf8_lossy(&parts[0].body), "Hello, world!");
    }

    #[test]
    fn find_part_by_content_type() {
        let parts = vec![
            MimePart {
                content_type: "application/sdp".to_string(),
                body: b"v=0\r\n".to_vec(),
            },
            MimePart {
                content_type: "application/rs-metadata+xml".to_string(),
                body: b"<recording/>".to_vec(),
            },
        ];

        let sdp = find_part(&parts, "application/sdp");
        assert!(sdp.is_some());
        assert_eq!(sdp.unwrap().content_type, "application/sdp");

        let metadata = find_part(&parts, "application/rs-metadata");
        assert!(metadata.is_some());

        let missing = find_part(&parts, "text/plain");
        assert!(missing.is_none());
    }

    #[test]
    fn parse_with_preamble_text() {
        let body = concat!(
            "This is the preamble and should be ignored.\r\n",
            "--boundary1\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "Part content\r\n",
            "--boundary1--\r\n",
        );
        let parts = parse_multipart("multipart/mixed;boundary=boundary1", body.as_bytes()).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(String::from_utf8_lossy(&parts[0].body), "Part content");
    }

    #[test]
    fn parse_three_parts() {
        let body = concat!(
            "--b\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "one\r\n",
            "--b\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<p>two</p>\r\n",
            "--b\r\n",
            "Content-Type: application/json\r\n",
            "\r\n",
            "{\"three\": 3}\r\n",
            "--b--\r\n",
        );
        let parts = parse_multipart("multipart/mixed;boundary=b", body.as_bytes()).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].content_type, "text/plain");
        assert_eq!(parts[1].content_type, "text/html");
        assert_eq!(parts[2].content_type, "application/json");
    }
}
