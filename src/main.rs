use clap::Parser;
use siphon::SiphonServer;

// Use jemalloc as the global allocator — eliminates glibc malloc arena
// contention that dominates the flame graph above ~10k cps on multi-core
// machines. See `Cargo.toml` for the rationale.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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
