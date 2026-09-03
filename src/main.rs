use clap::Parser;
use siphon::SiphonServer;

// Use jemalloc as the global allocator — eliminates glibc malloc arena
// contention that dominates the flame graph above ~10k cps on multi-core
// machines. See `Cargo.toml` for the rationale.
//
// Via the macro rather than a bare `#[global_allocator]`, so siphon's own
// binary gets the same page-decay tuning siphon ships for everyone else's.
// A bare attribute leaves `malloc_conf` unset, which means jemalloc's stock
// `background_thread:false` and `dirty_decay_ms:10000`: freed pages are only
// returned opportunistically, while an arena is being allocated *into*. A
// process that has just finished a burst is doing the opposite of that, so
// exactly when there is most to give back, nothing is running to give it —
// which is how RSS stays at its high-water mark long after the work is done.
siphon::install_allocator!();

#[derive(Parser)]
#[command(
    name = "siphon",
    about = "SIPhon — high-performance SIP proxy, B2BUA and IMS platform"
)]
struct Cli {
    /// Path to the configuration file
    #[arg(short = 'c', long = "config", default_value = "siphon.yaml")]
    config: String,
}

fn main() {
    let cli = Cli::parse();

    SiphonServer::builder()
        .product("SIPhon", env!("CARGO_PKG_VERSION"))
        .config_path(&cli.config)
        .run();
}
