//! Script engine — loads and hot-reloads Python scripts, manages the decorator
//! registry, and bridges between the Rust SIP core and Python policy logic.

pub mod api;
pub mod async_pool;
pub mod engine;
pub mod handle;

pub use handle::{HandlerHandle, ScriptHandle};
