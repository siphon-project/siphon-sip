//! Script engine — loads and hot-reloads Python scripts, manages the decorator
//! registry, and bridges between the Rust SIP core and Python policy logic.

pub mod api;
pub mod async_pool;
pub mod blocking;
pub mod diameter_dispatch;
pub mod engine;
pub mod handle;
pub mod handler_select;
pub mod inline_dispatch;
pub mod py_executor;
pub mod watcher;

pub(crate) use blocking::{awaitable, detach_block_on, ready};
pub use handle::{HandlerHandle, ScriptHandle};
