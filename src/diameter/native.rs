//! Diameter requests answered by Rust handlers.
//!
//! A request whose (application id, command code) has a handler registered
//! here is answered, or relayed, by that handler on the tokio task that took
//! it off the connection: no interpreter attach, no executor job, no asyncio.
//! Every other request, and one whose handler returns
//! [`NativeOutcome::Script`], goes to `@diameter.on_request` as it always did.
//!
//! Both paths share what is around the handler: the admission limit and its
//! 3004, the DOIC report on the answer, the inbound metrics (labelled
//! `path="native"` or `path="script"`), and the relay driver
//! ([`NativeRequest::relay`] is what `request.forward_to` runs). The
//! `@diameter.on_reply` and `@diameter.on_request_completed` hooks belong to
//! the script path and do not run for a request a handler answered.
//!
//! A handler that returns an error or panics is answered
//! DIAMETER_UNABLE_TO_COMPLY (5012) and logged; a request is never left
//! without an answer.
//!
//! ```rust,no_run
//! use siphon::diameter::dictionary;
//! use siphon::diameter::native::{NativeHandlers, NativeOutcome};
//! use siphon::SiphonServer;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let handlers = NativeHandlers::new().handle(
//!     dictionary::S6A_APP_ID,
//!     dictionary::CMD_AUTHENTICATION_INFORMATION,
//!     |request| async move {
//!         if request.message().get_str(dictionary::avp::USER_NAME).is_none() {
//!             return Ok(NativeOutcome::Script);
//!         }
//!         let answer = request.answer_experimental(dictionary::VENDOR_3GPP, 5001);
//!         Ok(NativeOutcome::Answer(answer))
//!     },
//! )?;
//! SiphonServer::builder()
//!     .config_path("siphon.yaml")
//!     .register_diameter_handlers(handlers)
//!     .run();
//! # Ok(())
//! # }
//! ```

mod answer;
pub(crate) mod dispatch;
mod request;
mod testing;
#[cfg(test)]
pub(crate) mod tests;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

pub use super::relay::RelayOptions;
pub use answer::NativeAnswer;
pub use request::{peer_for_host, NativeRequest, RelayTarget};
pub use testing::{HarnessOutcome, NativeHarness};

/// What a handler failed with. It is logged, and the request is answered
/// DIAMETER_UNABLE_TO_COMPLY (5012).
pub type NativeError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// What a handler returns.
pub type NativeResult = Result<NativeOutcome, NativeError>;

/// The future a handler returns.
pub type NativeFuture = Pin<Box<dyn Future<Output = NativeResult> + Send + 'static>>;

/// A handler: the request in, what to do with it out. It runs on a tokio
/// worker, so it must not block and must not attach to the interpreter. It
/// bounds its own waits: nothing times a handler out.
pub type NativeHandler = Arc<dyn Fn(NativeRequest) -> NativeFuture + Send + Sync + 'static>;

/// What a handler decided.
#[derive(Debug)]
pub enum NativeOutcome {
    /// Send this answer. Build it with [`NativeRequest::answer`] or
    /// [`NativeRequest::answer_experimental`], or take the one
    /// [`NativeRequest::relay`] returns.
    Answer(NativeAnswer),
    /// Not served here: hand the request, as received, to
    /// `@diameter.on_request`.
    Script,
}

/// The handlers a composing binary hands to the Diameter server, keyed by
/// (application id, command code). Built once, before the server starts, and
/// not changed after.
#[derive(Clone, Default)]
pub struct NativeHandlers {
    handlers: HashMap<(u32, u32), NativeHandler>,
}

impl NativeHandlers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serve the requests of `command_code` in `application_id` with
    /// `handler`. A second handler for the same pair is an error.
    pub fn handle<F, Fut>(
        mut self,
        application_id: u32,
        command_code: u32,
        handler: F,
    ) -> Result<Self, NativeHandlerError>
    where
        F: Fn(NativeRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = NativeResult> + Send + 'static,
    {
        self.insert(
            (application_id, command_code),
            Arc::new(move |request| Box::pin(handler(request))),
        )?;
        Ok(self)
    }

    /// With every handler of `other` too. A pair both have is an error.
    pub fn merge(mut self, other: NativeHandlers) -> Result<Self, NativeHandlerError> {
        for (key, handler) in other.handlers {
            self.insert(key, handler)?;
        }
        Ok(self)
    }

    fn insert(
        &mut self,
        key: (u32, u32),
        handler: NativeHandler,
    ) -> Result<(), NativeHandlerError> {
        if self.handlers.contains_key(&key) {
            return Err(NativeHandlerError::Duplicate {
                application_id: key.0,
                command_code: key.1,
            });
        }
        self.handlers.insert(key, handler);
        Ok(())
    }

    /// The handler for `command_code` in `application_id`.
    pub fn get(&self, application_id: u32, command_code: u32) -> Option<&NativeHandler> {
        self.handlers.get(&(application_id, command_code))
    }

    /// The (application id, command code) pairs that have a handler.
    pub fn commands(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.handlers.keys().copied()
    }

    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

impl std::fmt::Debug for NativeHandlers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut commands: Vec<(u32, u32)> = self.commands().collect();
        commands.sort_unstable();
        formatter
            .debug_struct("NativeHandlers")
            .field("commands", &commands)
            .finish()
    }
}

/// Why a handler was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NativeHandlerError {
    #[error(
        "a native handler is already registered for application {application_id} command {command_code}"
    )]
    Duplicate {
        application_id: u32,
        command_code: u32,
    },
    #[error("the Diameter native handlers are already installed")]
    AlreadyInstalled,
}

/// The handlers of this process, set once before the Diameter server starts.
/// Read without a lock on every inbound request.
static INSTALLED: OnceLock<NativeHandlers> = OnceLock::new();

/// Put `handlers` in force for every inbound connection of this process.
/// Once: a second call is an error and changes nothing.
pub(crate) fn install(handlers: NativeHandlers) -> Result<(), NativeHandlerError> {
    INSTALLED
        .set(handlers)
        .map_err(|_| NativeHandlerError::AlreadyInstalled)
}

/// The handlers in force, None when none were registered.
pub(crate) fn installed() -> Option<&'static NativeHandlers> {
    INSTALLED.get()
}

/// The applications the installed handlers serve, as `(vendor_id,
/// application_id)` pairs for the capabilities exchange. An application the
/// dictionary does not know has no vendor to advertise it with and is left
/// to the tenant's `applications` list.
pub(crate) fn served_applications() -> Vec<(u32, u32)> {
    installed().map(applications_of).unwrap_or_default()
}

/// [`served_applications`] of `handlers`.
fn applications_of(handlers: &NativeHandlers) -> Vec<(u32, u32)> {
    let mut applications: Vec<(u32, u32)> = handlers
        .commands()
        .filter_map(|(application_id, _)| super::dictionary::app_name_by_id(application_id))
        .filter_map(super::dictionary::app_id_by_name)
        .collect();
    applications.sort_unstable();
    applications.dedup();
    applications
}
