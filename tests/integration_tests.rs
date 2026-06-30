//! Top-level integration test harness.
//!
//! Includes cross-module integration tests that verify interactions between
//! the SIP parser, builder, config, registrar, dialog store, and transaction layers.

#[path = "integration/auth_tests.rs"]
mod auth_tests;

#[path = "integration/security_tests.rs"]
mod security_tests;

#[path = "integration/b2bua_tests.rs"]
mod b2bua_tests;

#[path = "integration/cache_tests.rs"]
mod cache_tests;

#[path = "integration/proxy_tests.rs"]
mod proxy_tests;

#[path = "integration/rtpengine_tests.rs"]
mod rtpengine_tests;

#[path = "integration/siphon_rtp_tests.rs"]
mod siphon_rtp_tests;

#[path = "integration/rtpproxy_tests.rs"]
mod rtpproxy_tests;

#[path = "integration/diameter_tests.rs"]
mod diameter_tests;

#[path = "integration/transport_tests.rs"]
mod transport_tests;

#[path = "integration/li_tests.rs"]
mod li_tests;

#[path = "integration/admin_tests.rs"]
mod admin_tests;

#[path = "integration/nat_tests.rs"]
mod nat_tests;

#[path = "integration/dns_tests.rs"]
mod dns_tests;

#[path = "integration/gateway_tests.rs"]
mod gateway_tests;

#[path = "integration/cdr_tests.rs"]
mod cdr_tests;

#[path = "integration/presence_tests.rs"]
mod presence_tests;

#[path = "integration/media_tests.rs"]
mod media_tests;

#[path = "integration/srs_tests.rs"]
mod srs_tests;

#[path = "integration/ipsec_tests.rs"]
mod ipsec_tests;

#[path = "integration/stir_tests.rs"]
mod stir_tests;
