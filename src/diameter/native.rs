//! Diameter requests answered by Rust handlers.
//!
//! A request whose (application id, command code) has a handler registered
//! here is answered, or relayed, by that handler on the tokio task that took
//! it off the connection: no interpreter attach, no executor job, no asyncio.
//! Every other request, and one whose handler returns
//! [`NativeOutcome::Script`], goes to `@diameter.on_request` as it always did.
//!
//! One catch-all handler ([`NativeHandlers::handle_any`]) may take what no
//! keyed handler is registered for.
//!
//! Both paths share what is around the handler: the admission limit and its
//! 3004, the DOIC report on the answer, the inbound metrics (labelled
//! `path="native"` or `path="script"`), and the relay driver
//! ([`NativeRequest::relay`] is what `request.forward_to` runs). The
//! `@diameter.on_reply` and `@diameter.on_request_completed` hooks belong to
//! the script path and do not run for a request a handler answered.
//!
//! A handler that returns an error, panics or outlasts
//! `script.handler_timeout_secs` is answered DIAMETER_UNABLE_TO_COMPLY (5012)
//! and logged; a request is never left without an answer.
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
mod runtime;
mod testing;
#[cfg(test)]
pub(crate) mod tests;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

pub use super::relay::RelayOptions;
pub use answer::NativeAnswer;
pub use request::{peer_for_host, peer_for_host_named, NativeRequest, PoolPick, RelayTarget};
pub(crate) use runtime::install as install_runtime;
pub use runtime::{event_sink, tenant_identity, tenants};
pub use testing::{HarnessOutcome, NativeHarness};

/// The application id of the base protocol's own commands (RFC 6733
/// section 2.4, "Diameter common messages").
const BASE_PROTOCOL: u32 = 0;

/// What a handler failed with. It is logged, and the request is answered
/// DIAMETER_UNABLE_TO_COMPLY (5012).
pub type NativeError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// What a handler returns.
pub type NativeResult = Result<NativeOutcome, NativeError>;

/// The future a handler returns.
pub type NativeFuture = Pin<Box<dyn Future<Output = NativeResult> + Send + 'static>>;

/// A handler: the request in, what to do with it out. It runs on a tokio
/// worker, so it must not block and must not attach to the interpreter. One
/// that is not done within `script.handler_timeout_secs` is dropped and the
/// request answered 5012.
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
/// (application id, command code), with at most one catch-all for what none
/// of them is keyed for. Built once, before the server starts, and not
/// changed after.
#[derive(Clone, Default)]
pub struct NativeHandlers {
    handlers: HashMap<(u32, u32), NativeHandler>,
    /// Serves every request no keyed handler is registered for.
    catch_all: Option<NativeHandler>,
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

    /// Serve with `handler` every request that no keyed handler is
    /// registered for, whatever its application and command: what a relay
    /// agent needs, which forwards applications it does not itself serve.
    /// It is asked only after the keyed lookup misses, and
    /// [`NativeOutcome::Script`] hands the request on to the script as for
    /// a command with no handler at all.
    ///
    /// It is not asked for a request of the base protocol (application id
    /// 0), which goes to the script as before.
    ///
    /// It names no application, so it adds nothing to what the capabilities
    /// exchange advertises: list what the node advertises under the tenant's
    /// `applications` (`relay` for an agent). A second catch-all is an error.
    pub fn handle_any<F, Fut>(mut self, handler: F) -> Result<Self, NativeHandlerError>
    where
        F: Fn(NativeRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = NativeResult> + Send + 'static,
    {
        self.insert_catch_all(Arc::new(move |request| Box::pin(handler(request))))?;
        Ok(self)
    }

    /// With every handler of `other` too. A pair both have is an error, and
    /// so is a catch-all in both.
    pub fn merge(mut self, other: NativeHandlers) -> Result<Self, NativeHandlerError> {
        for (key, handler) in other.handlers {
            self.insert(key, handler)?;
        }
        if let Some(handler) = other.catch_all {
            self.insert_catch_all(handler)?;
        }
        Ok(self)
    }

    fn insert_catch_all(&mut self, handler: NativeHandler) -> Result<(), NativeHandlerError> {
        if self.catch_all.is_some() {
            return Err(NativeHandlerError::DuplicateCatchAll);
        }
        self.catch_all = Some(handler);
        Ok(())
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

    /// The handler keyed for `command_code` in `application_id`.
    pub fn get(&self, application_id: u32, command_code: u32) -> Option<&NativeHandler> {
        self.handlers.get(&(application_id, command_code))
    }

    /// The catch-all handler, if one is registered.
    pub fn catch_all(&self) -> Option<&NativeHandler> {
        self.catch_all.as_ref()
    }

    /// The handler a request of `command_code` in `application_id` goes to:
    /// the one keyed for it, else the catch-all. The catch-all does not take
    /// the base protocol (application id 0): its commands are between two
    /// peers and are never relayed (RFC 6733 section 2.4).
    pub fn resolve(&self, application_id: u32, command_code: u32) -> Option<&NativeHandler> {
        self.get(application_id, command_code).or_else(|| {
            self.catch_all
                .as_ref()
                .filter(|_| application_id != BASE_PROTOCOL)
        })
    }

    /// The (application id, command code) pairs that have a keyed handler.
    pub fn commands(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.handlers.keys().copied()
    }

    /// How many keyed handlers there are; the catch-all is not counted.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether there is no handler at all, keyed or catch-all.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty() && self.catch_all.is_none()
    }
}

impl std::fmt::Debug for NativeHandlers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut commands: Vec<(u32, u32)> = self.commands().collect();
        commands.sort_unstable();
        formatter
            .debug_struct("NativeHandlers")
            .field("commands", &commands)
            .field("catch_all", &self.catch_all.is_some())
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
    #[error("a catch-all native handler is already registered")]
    DuplicateCatchAll,
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

/// The applications the installed keyed handlers serve, as `(vendor_id,
/// application_id)` pairs for the capabilities exchange. An application the
/// dictionary does not know has no vendor to advertise it with and is left
/// to the tenant's `applications` list. A catch-all names no application
/// and adds none.
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
