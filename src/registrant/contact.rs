//! The Contact header an outbound registration registers: the binding and the
//! IMS feature tags it advertises.

/// IMS Contact-header feature tags (3GPP TS 24.229 §5.1.1.2 / GSMA IR.92,
/// NG.114). These let the S-CSCF match iFCs and register the UE's MMTel /
/// voice / video / SMS services, and carry the instance ID for GRUU/outbound
/// (RFC 5626). Emitted after the `<sip:…>` of the Contact when present.
#[derive(Debug, Clone, Default)]
pub struct ImsContactParams {
    /// IMEI for `+sip.instance="<urn:gsma:imei:…>"` (RFC 5626 instance ID).
    /// `None` → no instance tag.
    pub instance_id: Option<String>,
    /// Emit the MMTel ICSI tag (`+g.3gpp.icsi-ref` mmtel).
    pub mmtel: bool,
    /// Emit `;video`.
    pub video: bool,
    /// Emit `+g.3gpp.mcptt` and the MCPTT ICSI (TS 24.379 clause 7.2.1).
    pub mcptt: bool,
    /// Emit `+g.3gpp.smsip` (SMS-over-IP).
    pub smsip: bool,
}

impl ImsContactParams {
    /// The tags `features` name (any of "mmtel", "video", "smsip", "mcptt",
    /// case-insensitive) beside `instance_id`; `Err` names an unknown one.
    pub fn from_features(instance_id: Option<String>, features: &[String]) -> Result<Self, String> {
        let mut params = Self {
            instance_id,
            ..Self::default()
        };
        for feature in features {
            match feature.to_ascii_lowercase().as_str() {
                "mmtel" => params.mmtel = true,
                "video" => params.video = true,
                "smsip" => params.smsip = true,
                "mcptt" => params.mcptt = true,
                _ => {
                    return Err(format!(
                        "unknown ims feature '{feature}' (mmtel, video, smsip, mcptt)"
                    ))
                }
            }
        }
        Ok(params)
    }
}

/// Build the Contact header value: `<contact_uri>` plus any IMS feature tags
/// (3GPP TS 24.229 §5.1.1.2 / GSMA IR.92). The instance ID, `q=1.0`, MMTel
/// ICSI, `video` and SMS-over-IP tags are emitted in handset order so the
/// S-CSCF registers the implied services. Without `ims`, just `<contact_uri>`.
pub(super) fn build_contact_header(contact_uri: &str, ims: Option<&ImsContactParams>) -> String {
    let mut header = format!("<{}>", contact_uri);
    if let Some(ims) = ims {
        if let Some(ref imei) = ims.instance_id {
            header.push_str(&format!(";+sip.instance=\"<urn:gsma:imei:{imei}>\""));
        }
        header.push_str(";q=1.0");
        // One `+g.3gpp.icsi-ref` parameter holds every ICSI as a comma-separated
        // list inside its quoted string (TS 24.229 clause 7.9.2, RFC 3840 §9).
        let mut icsi_references = Vec::new();
        if ims.mmtel {
            icsi_references.push("urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel");
        }
        if ims.mcptt {
            icsi_references.push("urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt");
        }
        if !icsi_references.is_empty() {
            header.push_str(&format!(
                ";+g.3gpp.icsi-ref=\"{}\"",
                icsi_references.join(",")
            ));
        }
        if ims.mcptt {
            header.push_str(";+g.3gpp.mcptt");
        }
        if ims.video {
            header.push_str(";video");
        }
        if ims.smsip {
            header.push_str(";+g.3gpp.smsip");
        }
    }
    header
}
