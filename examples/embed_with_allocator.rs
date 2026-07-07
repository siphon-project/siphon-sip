//! Example: install jemalloc + siphon's page-decay tuning in one line.
//!
//! `siphon::install_allocator!()` expands — here, in this binary crate — to a
//! jemalloc `#[global_allocator]` plus the baked `_rjem_malloc_conf` page-decay
//! tuning. Both are binary-crate-only constructs (see the macro docs for the two
//! linker reasons), so the macro emits them here. No `tikv-jemallocator`
//! dependency is needed — siphon re-exports it, keeping a single
//! `links = "jemalloc"` version in the graph.
//!
//! Run with:
//!   cargo run --example embed_with_allocator
//!
//! Expected output: a line confirming jemalloc is the active global allocator.
//! Verify the config symbol made it into the binary with:
//!   nm target/debug/examples/embed_with_allocator | grep _rjem_malloc_conf

// Override the decay config with, e.g.:
//   siphon::install_allocator!("background_thread:true,dirty_decay_ms:0");
siphon::install_allocator!();

fn main() {
    // Probe jemalloc the same way siphon's boot guard does. In a binary that
    // forgot the macro this returns false and `verify_global_allocator()` WARNs.
    let active = siphon::metrics::jemalloc_is_active();
    println!("jemalloc active as global allocator: {active}");

    assert!(
        active,
        "install_allocator!() should have made jemalloc the global allocator — \
         allocations are not routing through it"
    );

    println!("OK — siphon::install_allocator!() installed jemalloc + decay config");
}
