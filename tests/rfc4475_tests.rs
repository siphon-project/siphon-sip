// RFC 4475 torture tests.
//
// `rfc4475/mod.rs` already declares each submodule (basic_tests,
// comprehensive_tests, malformed_tests, edge_cases), so pulling that module
// in is enough — declaring the same files again here would load each one
// twice in this test binary (clippy::duplicate_mod).
#[path = "rfc4475/mod.rs"]
mod rfc4475_mod;
