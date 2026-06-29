//! Script engine — loads and hot-reloads Python scripts, manages the decorator
//! registry, and bridges between the Rust SIP core and Python policy logic.

pub mod api;
pub mod async_pool;
pub mod blocking;
pub mod diameter_dispatch;
pub mod engine;
pub mod handle;
pub mod py_executor;

pub use handle::{HandlerHandle, ScriptHandle};
pub(crate) use blocking::detach_block_on;
