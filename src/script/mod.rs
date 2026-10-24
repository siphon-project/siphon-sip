//! Script engine — loads and hot-reloads Python scripts, manages the decorator
//! registry, and bridges between the Rust SIP core and Python policy logic.

pub mod api;
pub mod async_pool;
pub(crate) mod attach;
#[cfg(test)]
mod attached_scan_tests;
pub mod blocking;
pub(crate) mod deferred;
pub mod diameter_dispatch;
pub mod engine;
pub mod error_report;
pub mod handle;
pub mod handler_select;
pub mod inline_dispatch;
pub(crate) mod liveness;
pub mod py_executor;
pub mod runtime_info;
pub mod script_config;
#[cfg(test)]
pub(crate) mod stop_the_world_tests;
pub(crate) mod waits;
pub mod watcher;

pub(crate) use blocking::{awaitable, detach_block_on, ready};
pub(crate) use deferred::Deferred;
pub use handle::{HandlerHandle, ScriptHandle};
