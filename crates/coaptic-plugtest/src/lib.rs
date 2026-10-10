//! Multi-implementation CoAP#4 plugtest harness with pcap capture and grading.
//!
//! This crate is **not** part of the `coaptic` library. The library stays
//! `no_std` with zero default runtime Cargo dependencies. Peers, pcap, and DTLS live
//! here as test/harness code.
//!
//! ```text
//! cargo test -p coaptic-plugtest
//! cargo test -p coaptic-plugtest --features dtls
//! cargo run -p coaptic-plugtest --bin dogfood
//! cargo run -p coaptic-plugtest --features oscore --bin dogfood -- --oscore
//! ```
//!
//! # Architecture
//!
//! - [`peer::Peer`] — start/stop a server, send a client request, poll, local
//!   UDP address. Backends: [`coaptic::CoapticPeer`] (App server + App client) and
//!   [`coap_rs::CoapRsPeer`] (`coap` / coap-rs). Add a new backend by
//!   implementing [`peer::Peer`].
//! - [`dogfood`] — timed coaptic ↔ coap-rs loops (GET/PUT/POST, Observe
//!   register/deregister, block-wise) plus a coaptic↔coaptic Observe notify
//!   collect. Mixed-stack Metrics must stay warm (fail-closed, not only
//!   `--compare`). `--oscore` (feature `oscore`) adds a protected
//!   coaptic↔coaptic GET/PUT/POST + Observe notify + Inner Block-wise
//!   loop and fails if the OSCORE path, protected notify, or protected
//!   Block is cold or a plain completion sneaks through. Observe notify
//!   and OSCORE stay between Coaptic peers in dogfood (`coap` 0.28 has no OSCORE).
//!   The TD runner collects NON notifications with either client backend against
//!   a Coaptic server. The coap-rs wrapper retains at most eight notifications of
//!   at most 2,048 wire bytes; overflow fails the run. This does not qualify the
//!   dependency runtime for production. Wall min/mean/p50/p99/max;
//!   [`coaptic::App::reset_metrics`] around each timed window; snapshot
//!   via [`coaptic::App::metrics`]. Optional `--json` writes schema
//!   `coaptic-dogfood/1`. `--compare PATH` fails if path-proving Metrics
//!   drop vs a checked-in baseline (including mixed-pair
//!   `sum(block1_assemble)` / `sum(block2_assemble)`); wall timings print
//!   as delta only. `progress` is informational; N=2 is a smoke lock, not
//!   a perf SLA.
//! - [`runner`] — each vendored TD × useful role pairs (coaptic server /
//!   coap-rs client, and the swap). Same-impl coaptic↔coaptic is also run
//!   for base GETs.
//! - [`pcap`] — records UDP payloads (and decrypted CoAP when DTLS unwraps).
//!   Writes PCAP (LINKTYPE_RAW IPv4/UDP). Ports, Message ID, Token, and
//!   timestamps are wild-carded by [`grade`].
//! - [`grade`] — deterministic field asserts from golden JSON
//!   (`expectations/catalog.json`).
//!
//! # DTLS
//!
//! Feature `dtls` pulls **webrtc-dtls** (the same stack coap-rs uses) as a
//! harness dependency. The `coaptic` **library** does not terminate DTLS and
//! stays zero-dep. The harness wraps UDP + webrtc-dtls as a sync
//! [`coaptic::storage::DatagramIo`] (`DtlsIo`) so `App::poll` and the App
//! client see plaintext CoAP. Mixed pairs (`coap-rs→coaptic`,
//! `coaptic→coap-rs`, `coaptic→coaptic`) run handshake + GET `/secure`.
//! `TD_COAP_DTLS_01` records the UDP handshake (cipher offer, selection, and
//! Finished) plus the decrypted GET. `TD_COAP_DTLS_02`–`03` stay skipped:
//! a plaintext `decrypt_error` alert is not graded, and each-flight handshake
//! loss is not injected. The backend has no RFC 7250 raw public key, so
//! `TD_COAP_DTLS_04`–`07` stay skipped. Separate X.509 tests are a different
//! qualification and do not relabel those TDs.
//!
//! # 6LoWPAN
//!
//! `TD_6LoWPAN_*` stay outside the accepted 0.0.10 qualification scope.
//!
//! Tracking: <https://github.com/jeffglousher/coaptic/issues/199>.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod catalog;
pub mod coap_rs;
pub mod coaptic;
pub mod dogfood;
pub mod grade;
pub mod pcap;
pub mod peer;
pub mod runner;
pub mod site;

#[cfg(feature = "dtls")]
pub mod dtls;

/// Vendored golden expectations (JSON). Ports / time are wildcards; CORE asserts type and echo MID/Token.
pub const CATALOG_JSON: &str = include_str!("../expectations/catalog.json");
