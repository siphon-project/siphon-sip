//! The name of a [`CallState`], as a script reads it (`call.state`) and a
//! controller sees it on the wire.

use super::CallState;

impl CallState {
    /// `"calling"`, `"ringing"`, `"answered"` or `"terminated"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            CallState::Calling => "calling",
            CallState::Ringing => "ringing",
            CallState::Answered => "answered",
            CallState::Terminated => "terminated",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_state_has_the_name_a_script_reads() {
        assert_eq!(CallState::Calling.as_str(), "calling");
        assert_eq!(CallState::Ringing.as_str(), "ringing");
        assert_eq!(CallState::Answered.as_str(), "answered");
        assert_eq!(CallState::Terminated.as_str(), "terminated");
    }
}
