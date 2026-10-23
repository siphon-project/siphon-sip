//! What one outbound registration looks like right now, for the consumers of
//! its state changes: `@registration.on_change` and the control plane's
//! `RegistrantChanged`.

use super::{RegistrantManager, RegistrantState};

/// The current state of one outbound registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrantStatus {
    /// Seconds until the binding the registrar granted runs out, `0` when
    /// there is none.
    pub expires_in: u64,
    /// Consecutive failed attempts.
    pub failure_count: u32,
    /// The registrar it registers with.
    pub registrar_uri: String,
    /// Where the registration stands.
    pub state: RegistrantState,
    /// The status of the last failed attempt, `None` once one succeeded.
    pub last_failure_status: Option<u16>,
}

impl RegistrantManager {
    /// The current state of the registration for `aor`, `None` when there is
    /// none.
    pub fn status(&self, aor: &str) -> Option<RegistrantStatus> {
        self.entries.get(aor).map(|entry| RegistrantStatus {
            expires_in: entry.expires_in(),
            failure_count: entry.failure_count,
            registrar_uri: entry.registrar_uri.clone(),
            state: entry.state,
            last_failure_status: entry.last_failure_status,
        })
    }

    /// The registration interval `aor` asks for in its REGISTER's `Expires`:
    /// the entry's own `interval`, else the manager's default. Every REGISTER
    /// the entry sends (the first, the answer to a 401, every refresh) asks for
    /// the same; until this existed they all asked for the default, so a
    /// per-entry `interval` was never sent.
    pub fn interval_for(&self, aor: &str) -> u32 {
        self.entries
            .get(aor)
            .map_or(self.default_interval, |entry| entry.interval_secs)
    }

    /// [`status`](Self::status) as `(expires_in, failure_count,
    /// registrar_uri)`, the shape this lookup had before it carried the state.
    pub fn entry_info(&self, aor: &str) -> Option<(u64, u32, String)> {
        self.status(aor).map(|status| {
            (
                status.expires_in,
                status.failure_count,
                status.registrar_uri,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::registrant::{RegistrantCredentials, RegistrantEntry};
    use crate::transport::Transport;

    fn manager() -> RegistrantManager {
        RegistrantManager::new(
            3600,
            Duration::from_secs(60),
            Duration::from_secs(300),
            crate::config::IdentityHeaders::default().shared(),
        )
    }

    fn entry(aor: &str) -> RegistrantEntry {
        RegistrantEntry::new(
            aor.to_string(),
            "sip:registrar.example.net:5060".to_string(),
            "192.0.2.40:5060".parse().expect("an address"),
            Transport::Udp,
            RegistrantCredentials::password("trunk".to_string(), "secret".to_string(), None),
            3600,
            None,
        )
    }

    #[test]
    fn a_registered_entry_reports_its_grant_and_no_failure() {
        let manager = manager();
        manager.add(entry("sip:trunk@example.net"));
        manager.handle_success("sip:trunk@example.net", 3600);

        let status = manager.status("sip:trunk@example.net").expect("a status");
        assert!(status.expires_in > 0);
        assert_eq!(status.failure_count, 0);
        assert_eq!(status.registrar_uri, "sip:registrar.example.net:5060");
        assert_eq!(status.state, RegistrantState::Registered);
        assert_eq!(status.last_failure_status, None);
    }

    #[test]
    fn a_failure_is_remembered_until_a_success_clears_it() {
        let manager = manager();
        manager.add(entry("sip:trunk@example.net"));
        manager.handle_failure("sip:trunk@example.net", 403, None);

        let failed = manager.status("sip:trunk@example.net").expect("a status");
        assert_eq!(failed.state, RegistrantState::Failed);
        assert_eq!(failed.failure_count, 1);
        assert_eq!(failed.last_failure_status, Some(403));
        assert_eq!(failed.expires_in, 0);

        manager.handle_success("sip:trunk@example.net", 600);
        let recovered = manager.status("sip:trunk@example.net").expect("a status");
        assert_eq!(recovered.last_failure_status, None);
        assert_eq!(recovered.failure_count, 0);
    }

    #[test]
    fn no_status_for_an_unknown_aor() {
        assert!(manager().status("sip:nobody@example.net").is_none());
        assert!(manager().entry_info("sip:nobody@example.net").is_none());
    }

    #[test]
    fn entry_info_is_the_status_as_a_tuple() {
        let manager = manager();
        manager.add(entry("sip:trunk@example.net"));
        manager.handle_success("sip:trunk@example.net", 3600);
        let (expires_in, failure_count, registrar) = manager
            .entry_info("sip:trunk@example.net")
            .expect("an entry");
        assert!(expires_in > 0);
        assert_eq!(failure_count, 0);
        assert_eq!(registrar, "sip:registrar.example.net:5060");
    }
}
