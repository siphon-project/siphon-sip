//! The RFC 4028 session timer a script runs on one B2BUA call:
//! `call.session_timer()`, and `b2bua.originate(session_timer={...})` for a call
//! siphon places.

use pyo3::exceptions::PyValueError;
use pyo3::PyResult;

use crate::config::SessionRefresher;

/// Per-call session timer override set by Python scripts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTimerOverride {
    pub session_expires: u32,
    pub min_se: u32,
    /// Who siphon would have refresh each dialog, where the negotiation leaves
    /// it the choice.
    pub refresher: SessionRefresher,
}

impl SessionTimerOverride {
    /// The session interval of a script's timer that names none, in seconds.
    pub const DEFAULT_EXPIRES: u32 = 1800;
    /// The `Min-SE` of a script's timer that names none, in seconds.
    pub const DEFAULT_MIN_SE: u32 = 90;
    /// The refresher of a script's timer that names none.
    pub const DEFAULT_REFRESHER: &'static str = "b2bua";

    /// A script's session timer, with `refresher` by name: `uac`, `uas` or
    /// `b2bua`, in any case. `ValueError` for any other name.
    pub fn from_script(session_expires: u32, min_se: u32, refresher: &str) -> PyResult<Self> {
        let Some(preference) = SessionRefresher::from_name(refresher) else {
            return Err(PyValueError::new_err(format!(
                "refresher must be \"uac\", \"uas\" or \"b2bua\", not {refresher:?}"
            )));
        };
        Ok(Self {
            session_expires,
            min_se,
            refresher: preference,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_script_timer_takes_a_refresher_by_name_in_any_case() {
        assert_eq!(
            SessionTimerOverride::from_script(900, 120, "UAC").expect("a refresher"),
            SessionTimerOverride {
                session_expires: 900,
                min_se: 120,
                refresher: SessionRefresher::Uac,
            }
        );
        assert_eq!(
            SessionTimerOverride::from_script(
                SessionTimerOverride::DEFAULT_EXPIRES,
                SessionTimerOverride::DEFAULT_MIN_SE,
                SessionTimerOverride::DEFAULT_REFRESHER,
            )
            .map(|timer| timer.refresher)
            .expect("the default refresher"),
            SessionRefresher::B2bua
        );
    }

    #[test]
    fn a_script_timer_refuses_a_refresher_siphon_cannot_negotiate() {
        pyo3::Python::initialize();
        let error = SessionTimerOverride::from_script(1800, 90, "sometimes")
            .expect_err("an unknown refresher");
        assert!(error.to_string().contains("refresher"), "{error}");
    }
}
