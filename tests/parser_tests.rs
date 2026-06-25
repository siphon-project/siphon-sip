// Include unit tests.
//
// `unit/sip/mod.rs` already declares each submodule (parser_tests,
// builder_tests, uri_tests, headers_tests, message_tests), so pulling that
// module in is enough — declaring the same files again here would load each
// one twice in this test binary (clippy::duplicate_mod).
#[path = "unit/sip/mod.rs"]
mod unit_sip;
