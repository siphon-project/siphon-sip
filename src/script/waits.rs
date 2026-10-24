//! Blocking calls siphon still needs, each released from the interpreter.
//!
//! `clippy.toml` disallows the blocking standard-library calls crate-wide; the
//! ones that remain go through here, where the wait runs with the interpreter
//! released if the calling thread holds it (`script::blocking::released`), so
//! no caller can wait attached by accident. One `#[allow]` per call here
//! instead of one at every call site.

use std::net::SocketAddr;

/// `getaddrinfo` for `host:port`, released from the interpreter for the
/// lookup (it can take seconds when DNS is unwell).
pub(crate) fn resolve_socket_addrs(address: &str) -> std::io::Result<Vec<SocketAddr>> {
    crate::script::blocking::released(|| {
        #[allow(clippy::disallowed_methods)] // the sanctioned, released lookup
        let resolved = std::net::ToSocketAddrs::to_socket_addrs(address);
        resolved.map(Iterator::collect)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_literal_address_resolves_to_itself() {
        let resolved = resolve_socket_addrs("192.0.2.10:5060").expect("literal");
        assert_eq!(
            resolved,
            vec!["192.0.2.10:5060".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn an_unresolvable_name_is_an_error() {
        assert!(resolve_socket_addrs("not a host:5060").is_err());
    }

    #[test]
    fn the_lookup_runs_released_when_attached() {
        pyo3::Python::initialize();
        let resolved = pyo3::Python::attach(|_| resolve_socket_addrs("[2001:db8::1]:5061"));
        assert_eq!(resolved.expect("literal").len(), 1);
    }
}
