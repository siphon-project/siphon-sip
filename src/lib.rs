//! SIPhon — high-performance SIP proxy, B2BUA and IMS platform.

pub mod admin;
pub mod apiban;
pub mod auth;
pub mod b2bua;
pub mod cache;
pub mod capture;
pub mod cdr;
pub mod config;
pub mod control;
pub mod cors;
pub mod dialog;
pub mod diameter;
pub mod dispatcher;
pub mod dns;
pub mod error;
pub mod file_sink;
pub mod firewall;
pub mod gateway;
pub mod hep;
pub mod ifc;
pub mod ipsec;
pub mod lcr;
pub mod li;
pub mod log_tail;
pub mod media;
pub mod metrics;
pub mod nat;
pub mod numbers;
pub mod presence;
pub mod proxy;
pub mod registrant;
pub mod registrar;
pub mod rtpengine;
pub mod sbi;
pub mod script;
pub mod security;
pub mod server;
pub mod shutdown;
pub mod sip;
pub mod siprec;
pub mod srs;
pub mod stir;
pub mod subscribe_state;
pub mod transaction;
pub mod transport;
pub mod uac;
pub mod xml_text;

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
        $crate::install_allocator!("background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0");
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

/// Test-only: run a test alone, in a child process of this test binary.
///
/// Some tests look at state that belongs to the whole process: resident memory,
/// a process-wide metrics gauge, or the `siphon` Python module in `sys.modules`
/// and the registries every install mounts from. Whatever the other tests in the
/// binary are doing moves that state, so such a test re-runs itself in a child
/// that runs nothing else, and the parent only judges the child's result.
#[cfg(test)]
pub(crate) mod own_process {
    /// Carries the name of the test a child process was started for.
    const CHILD: &str = "SIPHON_TEST_OWN_PROCESS";

    /// Run `test` in a child process that runs only the test named `full_name`,
    /// which is `concat!(module_path!(), "::<test fn>")` at the call site.
    ///
    /// Inside that child this just calls `test`. In the parent it waits for the
    /// child and panics with its output unless exactly that one test passed.
    pub(crate) fn run(full_name: &str, test: impl FnOnce()) {
        // The harness names a test by its module path without the crate.
        let test_name = full_name
            .split_once("::")
            .map_or(full_name, |(_, rest)| rest);
        if std::env::var(CHILD).as_deref() == Ok(test_name) {
            test();
            return;
        }

        let binary = std::env::current_exe().expect("path of the running test binary");
        let output = std::process::Command::new(binary)
            .args([test_name, "--exact", "--test-threads=1", "--nocapture"])
            .env(CHILD, test_name)
            .output()
            .expect("start the test in its own process");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "1 passed" as well as success: a name that matches no test also exits
        // 0, and must not count as the test having run.
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed"),
            "{test_name} did not pass in its own process ({}).\n--- stdout ---\n{stdout}\n\
             --- stderr ---\n{stderr}",
            output.status
        );
        eprint!("{stderr}");
    }
}
