//! SIPhon — high-performance SIP proxy, B2BUA and IMS platform.

pub mod apiban;
pub mod auth;
pub mod b2bua;
pub mod cache;
pub mod config;
pub mod diameter;
pub mod dialog;
pub mod dispatcher;
pub mod dns;
pub mod hep;
pub mod error;
pub mod firewall;
pub mod nat;
pub mod presence;
pub mod proxy;
pub mod gateway;
pub mod registrant;
pub mod registrar;
pub mod rtpengine;
pub mod script;
pub mod sip;
pub mod transaction;
pub mod transport;
pub mod uac;
pub mod metrics;
pub mod admin;
pub mod cdr;
pub mod shutdown;
pub mod media;
pub mod ifc;
pub mod ipsec;
pub mod li;
pub mod sbi;
pub mod security;
pub mod server;
pub mod siprec;
pub mod stir;
pub mod srs;
pub mod subscribe_state;

pub use server::SiphonServer;

// Re-export the jemalloc allocator crate so the macro can name
// `$crate::tikv_jemallocator::Jemalloc` without a separate dependency.
// `tikv-jemalloc-sys` is a `links = "jemalloc"` crate, so only ONE version may
// exist in the dependency graph — using siphon's avoids any version skew or a
// "two jemalloc" link error. Gated to non-MSVC to match the dependency itself.
#[cfg(not(target_env = "msvc"))]
#[doc(hidden)]
pub use tikv_jemallocator;

/// Install jemalloc as the global allocator **and** bake siphon's page-decay
/// tuning into the calling binary, in one line. Invoke once at the top of
/// `main.rs`:
///
/// ```ignore
/// siphon::install_allocator!();                      // default decay config
/// siphon::install_allocator!("dirty_decay_ms:0");    // custom jemalloc conf
/// ```
///
/// # Why this is a macro
///
/// Both pieces only take effect when emitted in the **final binary crate**, so
/// the macro expands them *in your binary*:
///
/// 1. `#[global_allocator]` is honored by the language only in the root of the
///    final binary; a `static` with that attribute inside a dependency is
///    ignored.
/// 2. The `_rjem_malloc_conf` config symbol must be a *strong* definition in the
///    binary. jemalloc ships a **weak** `_rjem_malloc_conf = NULL` default that
///    already satisfies its own reference, so the linker has no undefined symbol
///    to resolve and won't pull a definition out of a `.rlib` (`#[used]` keeps
///    the symbol in its object but doesn't force the object into the link).
///    Emitting it in the binary is the only reliable way.
///
/// The default conf — `background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0`
/// — proactively returns freed pages to the OS, which is the win under
/// free-threaded-CPython worker-pool churn. Pass a literal to override it on a
/// memory-tight deployment. Invoking the macro twice is a compile error
/// (duplicate `#[global_allocator]`). On MSVC (where jemalloc isn't a dependency)
/// the macro expands to nothing, leaving the system allocator.
#[macro_export]
macro_rules! install_allocator {
    () => {
        $crate::install_allocator!(
            "background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0"
        );
    };
    ($conf:literal) => {
        #[cfg(not(target_env = "msvc"))]
        #[global_allocator]
        static __SIPHON_GLOBAL_ALLOC: $crate::tikv_jemallocator::Jemalloc =
            $crate::tikv_jemallocator::Jemalloc;

        // jemalloc reads this symbol at init. `tikv-jemalloc-sys` builds with the
        // `_rjem_` symbol prefix, so the config name is `_rjem_malloc_conf`.
        // `concat!(.., "\0")` NUL-terminates it for the C reader, and
        // `str::as_bytes` is const so it's a valid `static` initializer.
        #[cfg(not(target_env = "msvc"))]
        #[allow(non_upper_case_globals)]
        #[unsafe(export_name = "_rjem_malloc_conf")]
        pub static __SIPHON_MALLOC_CONF: &[u8] = concat!($conf, "\0").as_bytes();
    };
}
