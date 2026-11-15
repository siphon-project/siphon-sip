//! Handing the Diameter server its Rust request handlers.

use super::SiphonServer;
use crate::diameter::native::{self, NativeHandlerError, NativeHandlers};

impl SiphonServer {
    /// Answer the Diameter requests `handlers` names in Rust, without the
    /// script: see [`crate::diameter::native`]. May be called several times,
    /// once per crate that brings handlers; two handlers for the same
    /// (application id, command code) are a fatal error at startup.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use siphon::diameter::native::{NativeHandlers, NativeOutcome};
    /// use siphon::SiphonServer;
    ///
    /// let handlers = NativeHandlers::new().handle(16777251, 321, |request| async move {
    ///     Ok(NativeOutcome::Answer(request.answer(2001)))
    /// })?;
    /// SiphonServer::builder()
    ///     .config_path("siphon.yaml")
    ///     .register_diameter_handlers(handlers)
    ///     .run();
    /// ```
    pub fn register_diameter_handlers(mut self, handlers: NativeHandlers) -> Self {
        self.diameter_handlers.push(handlers);
        self
    }

    /// Number of (application id, command code) pairs registered on the
    /// builder, counting a pair registered twice twice.
    pub fn diameter_handler_count(&self) -> usize {
        self.diameter_handlers.iter().map(NativeHandlers::len).sum()
    }

    /// Put the registered handlers in force, before any Diameter connection
    /// exists. Exits when two of them claim the same command.
    pub(super) fn install_diameter_handlers(&mut self) {
        if self.diameter_handlers.is_empty() {
            return;
        }
        let merged = merge(std::mem::take(&mut self.diameter_handlers));
        if let Err(error) = merged.and_then(native::install) {
            eprintln!("Failed to register Diameter handlers: {error}");
            std::process::exit(1);
        }
    }
}

/// One set out of the sets each registration brought.
fn merge(sets: Vec<NativeHandlers>) -> Result<NativeHandlers, NativeHandlerError> {
    sets.into_iter()
        .try_fold(NativeHandlers::new(), NativeHandlers::merge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::native::NativeOutcome;

    fn one(application_id: u32, command_code: u32) -> NativeHandlers {
        NativeHandlers::new()
            .handle(application_id, command_code, |_request| async {
                Ok(NativeOutcome::Script)
            })
            .expect("a first handler")
    }

    #[test]
    fn registrations_accumulate_on_the_builder() {
        let server = SiphonServer::builder()
            .register_diameter_handlers(one(16_777_251, 318))
            .register_diameter_handlers(one(16_777_251, 316));
        assert_eq!(server.diameter_handler_count(), 2);
    }

    #[test]
    fn sets_from_several_registrations_become_one() {
        let merged = merge(vec![one(16_777_251, 318), one(16_777_216, 303)]).expect("distinct");
        assert_eq!(merged.len(), 2);
        assert!(merged.get(16_777_216, 303).is_some());
    }

    #[test]
    fn the_same_command_from_two_registrations_is_refused() {
        assert_eq!(
            merge(vec![one(16_777_251, 318), one(16_777_251, 318)]).err(),
            Some(NativeHandlerError::Duplicate {
                application_id: 16_777_251,
                command_code: 318,
            })
        );
    }
}
