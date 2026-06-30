//! SIPhon binary with opt-in, feature-gated extension modules.
//!
//! This is a superset of the plain `siphon` binary shipped by the `siphon-sip`
//! crate. It produces the same `siphon` artifact but additionally composes
//! optional extension crates (SMPP today; HTTP and others later) behind cargo
//! features. Each module is off by default; build with e.g.
//! `cargo build -p siphon-bin --release --features smpp` to compile one in.
//!
//! Composition mirrors the proven downstream pattern:
//!   1. Load siphon's main config — it carries the `extensions:` map.
//!   2. `ext::register_all` registers every compiled-in module's Python
//!      namespace ([`SiphonServer::register_namespace_with`]) and runtime task
//!      ([`SiphonServer::register_task`]).
//!   3. Run siphon — modules whose feature is off, but whose `extensions.<name>`
//!      block is present, are skipped with a loud warning.

use clap::Parser;
use siphon::config::Config;
use siphon::SiphonServer;

mod ext;

// jemalloc as the global allocator + siphon's page-decay tuning, plus a boot
// probe that WARNs if jemalloc isn't actually active. The allocator only takes
// effect in the final binary crate (it does not propagate through the siphon-sip
// library dep), so it must be installed here. This macro re-exports siphon's own
// tikv-jemallocator, so there's no separate dependency to add and no
// `links = "jemalloc"` version skew.
siphon::install_allocator!();

#[derive(Parser)]
#[command(
    name = "siphon",
    about = "SIPhon — SIP proxy/B2BUA/IMS with opt-in extension modules (SMPP, …)"
)]
struct Cli {
    /// Path to the configuration file
    #[arg(short = 'c', long = "config", default_value = "siphon.yaml")]
    config: String,
}

fn main() {
    let cli = Cli::parse();

    // Load the config up front so the extension layer can read the
    // `extensions:` map before `run()` starts the script engine. `run()`
    // re-reads the file itself; one extra parse of a single file at startup is
    // negligible.
    let config = Config::from_file(&cli.config).unwrap_or_else(|error| {
        eprintln!("Failed to load {}: {error}", cli.config);
        std::process::exit(1);
    });

    let mut builder = SiphonServer::builder().product("SIPhon", env!("CARGO_PKG_VERSION"));
    builder = ext::register_all(builder, &config);
    builder.config_path(&cli.config).run();
}
