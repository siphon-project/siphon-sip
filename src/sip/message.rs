use crate::sip::headers::SipHeaders;
use crate::sip::uri::SipUri;

/// SIP Method as defined in RFC 3261
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    // Core methods
    Invite,
    Ack,
    Bye,
    Cancel,
    Options,
    Register,
    // Extension methods
    Info,
    Update,
    Prack,
    Subscribe,
    Notify,
    Refer,
    Message,
    Publish, // RFC 3903
    // Custom/unknown
    Extension(String),
}

impl Method {
    pub fn as_str(&self) -> &str {
        match self {
            Method::Invite => "INVITE",
            Method::Ack => "ACK",
            Method::Bye => "BYE",
            Method::Cancel => "CANCEL",
            Method::Options => "OPTIONS",
            Method::Register => "REGISTER",
            Method::Info => "INFO",
            Method::Update => "UPDATE",
            Method::Prack => "PRACK",
            Method::Subscribe => "SUBSCRIBE",
            Method::Notify => "NOTIFY",
            Method::Refer => "REFER",
            Method::Message => "MESSAGE",
            Method::Publish => "PUBLISH",
            Method::Extension(s) => s,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "INVITE" => Method::Invite,
            "ACK" => Method::Ack,
            "BYE" => Method::Bye,
            "CANCEL" => Method::Cancel,
            "OPTIONS" => Method::Options,
            "REGISTER" => Method::Register,
            "INFO" => Method::Info,
            "UPDATE" => Method::Update,
            "PRACK" => Method::Prack,
            "SUBSCRIBE" => Method::Subscribe,
            "NOTIFY" => Method::Notify,
            "REFER" => Method::Refer,
            "MESSAGE" => Method::Message,
            "PUBLISH" => Method::Publish,
            // RFC 3261 §7.1: the method is case-sensitive. The known methods
            // are matched case-insensitively for robustness on receive, but an
            // extension method MUST keep the case it arrived in — `Foo` and
            // `FOO` are different methods, and CSeq has to echo the
            // Request-Line exactly or the peer sees a method mismatch.
            _ => Method::Extension(s.to_string()),
        }
    }
}

/// SIP Version (typically SIP/2.0)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

impl Version {
    pub fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    pub fn sip_2_0() -> Self {
        Self { major: 2, minor: 0 }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SIP/{}.{}", self.major, self.minor)
    }
}

/// Request line (first line of SIP request)
#[derive(Debug, Clone)]
pub struct RequestLine {
    pub method: Method,
    pub request_uri: SipUri,
    pub version: Version,
}

/// Status line (first line of SIP response)
#[derive(Debug, Clone)]
pub struct StatusLine {
    pub version: Version,
    pub status_code: u16,
    pub reason_phrase: String,
}

/// Start line (either RequestLine or StatusLine)
#[derive(Debug, Clone)]
pub enum StartLine {
    Request(RequestLine),
    Response(StatusLine),
}

/// Complete SIP message (request or response)
#[derive(Debug, Clone)]
pub struct SipMessage {
    pub start_line: StartLine,
    pub headers: SipHeaders,
    pub body: Vec<u8>,
}

impl SipMessage {
    /// Check if this is a request
    pub fn is_request(&self) -> bool {
        matches!(self.start_line, StartLine::Request(_))
    }

    /// Check if this is a response
    pub fn is_response(&self) -> bool {
        matches!(self.start_line, StartLine::Response(_))
    }

    /// Get method if this is a request
    pub fn method(&self) -> Option<&Method> {
        match &self.start_line {
            StartLine::Request(req) => Some(&req.method),
            StartLine::Response(_) => None,
        }
    }

    /// Get status code if this is a response
    pub fn status_code(&self) -> Option<u16> {
        match &self.start_line {
            StartLine::Request(_) => None,
            StartLine::Response(resp) => Some(resp.status_code),
        }
    }

    /// Get request URI if this is a request
    pub fn request_uri(&self) -> Option<&SipUri> {
        match &self.start_line {
            StartLine::Request(req) => Some(&req.request_uri),
            StartLine::Response(_) => None,
        }
    }
}
