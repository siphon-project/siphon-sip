//! DNS resolution for SIP targets (RFC 3263).
//!
//! Implements the SIP server location procedure:
//! 1. If the target is a numeric IP, use it directly.
//! 2. If a port is specified, do A/AAAA lookup on the host.
//! 3. If no port, do SRV lookup (`_sip._udp.host`, `_sip._tcp.host`, etc.)
//!    and fall back to A/AAAA on port 5060 if no SRV records exist.

pub mod enum_naptr;
mod resolver;

pub use resolver::SipResolver;
