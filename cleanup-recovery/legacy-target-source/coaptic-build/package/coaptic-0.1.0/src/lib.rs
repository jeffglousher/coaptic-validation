//! Stand-alone [`no_std`] CoAP library: an approachable [`App`] face over
//! messages and bounded storage.
//!
//! Crate-root types are the happy path: [`App`], [`Request`], [`Response`],
//! [`Call`], [`Outgoing`], [`get`] / [`put`] / [`post`] / [`delete`] /
//! [`fetch`] / [`patch`] / [`ipatch`], [`Endpoint`], [`profiles`],
//! [`Code`], [`ContentFormat`], [`Method`], [`ProblemDetails`], and the
//! errors from [`bind`](app::AppBuilder::bind) / [`App::poll`] /
//! [`Outgoing::send`]. Engine slots, tables, Block/Q-Block types,
//! [`Ids`](message::Ids), and [`DatagramIo`](storage::DatagramIo) live in
//! [`storage`] / [`message`].
//!
//! # Happy path
//!
//! ```text
//! RX slot (+ body) --view--> Request
//! handler(Request) -> Response
//! Response --encode--> TX slot (+ body)
//!
//! Outgoing (get/put) --encode--> TX slot
//! poll matches Token + endpoint
//! RX --copy--> Response::payload  (non-Block: min(len, INLINE_PAYLOAD) = 128)
//! ```
//!
//! ```
//! use coaptic::{App, Request, Response, get, profiles};
//! # use coaptic::storage::DatagramIo;
//! # use coaptic::Endpoint;
//! # struct NullIo;
//! # impl DatagramIo for NullIo {
//! #     type Error = &'static str;
//! #     fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
//! #         Ok(None)
//! #     }
//! #     fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> { Ok(bytes.len()) }
//! # }
//!
//! fn get_temp(_req: Request<'_>) -> Response<'static> {
//!     Response::content(b"21.5")
//! }
//!
//! let mut app = App::profile::<profiles::Default>()
//!     .randomness(|bytes| getrandom::fill(bytes).is_ok())
//!     .block_wise::<true>()
//!     .route("sensors/temp", get(get_temp))
//!     .bind(NullIo)
//!     .unwrap();
//! app.poll(0).unwrap();
//!
//! let peer = Endpoint::v4([192, 0, 2, 2], 5683);
//! let call = app.get("sensors/temp").to(peer).send(0).unwrap();
//! app.poll(0).unwrap();
//! let _response = app.take_response(call);
//! ```
//!
//! Path arguments accept both `"sensors/temp"` and `&["sensors", "temp"]`
//! ([`app::IntoPath`]; empty segments are rejected). Handlers are
//! `fn(Request<'_>) -> Response`. One [`Response`] type covers handler
//! intent and a completed client exchange ([`App::take_response`]).
//! Non-Block [`Response::payload`] copies at most
//! [`app::INLINE_PAYLOAD`] (128) bytes; a longer piggybacked 2.05 with
//! `.block_wise::<false>()` is truncated —
//! [`Response::payload_truncated`] is `true`. Assembled Block2 / Q-Block2
//! is [`Response::body`]. Observe subscribe is [`Outgoing::observe`]; the
//! initial representation and later notifications use the same [`Call`].
//! [`Outgoing::deregister`] sends Observe=1. Structured 4.xx bodies use
//! [`Response::problem`]
//! (RFC 9290). Q-Block1 holes from `poll` use [`Response::missing_blocks`]
//! (RFC 9177, Content-Format 272). Caller-owned Echo issuance and verification use
//! [`app::AppBuilder::echo_policy`].
//!
//! # What you own
//!
//! The socket ([`storage::DatagramIo`]), the clock (`now_ms` into
//! [`App::poll`]), the destination of an outbound request, any domain
//! state that outlives a request, and — when the `oscore` feature is on —
//! the OSCORE `SecurityContext` (Master Secret, Sender/Recipient IDs,
//! replay window; feature `oscore`). There is no global App State. Supply
//! cryptographically secure entropy through [`app::AppBuilder::randomness`]
//! for Tokens, the initial Message ID and retransmission jitter. The library
//! itself does not call an OS RNG.
//!
//! # Modules
//!
//! - [`app`] — [`App`]: [`route`](app::AppBuilder::route), method routers,
//!   `fn(Request<'_>) -> Response`, [`App::poll`], [`App::notify`],
//!   outbound [`App::get`] / [`Outgoing::send`] / [`App::take_response`].
//! - [`message`] — [`decode`](message::decode) / [`encode`](message::encode)
//!   a datagram. No [`Engine`](storage::Engine) required.
//! - [`storage`] — [`Engine`](storage::Engine) over
//!   [`Storage`](storage::Storage); pools, tables,
//!   [`DatagramIo`](storage::DatagramIo), wrapping
//!   [`Metrics`] (`Engine::metrics` /
//!   [`App::metrics`](App::metrics)). Advanced:
//!   [`Access`](storage::Access) / [`AccessMut`](storage::AccessMut).
//! - `oscore` — pairwise OSCORE (feature `oscore`): caller-owned
//!   `SecurityContext`, `App::set_oscore`.
//! - [`profiles`] — [`profiles::Default`] (1472-byte datagrams) and
//!   [`profiles::Constrained`] (1152).
//!
//! Protocol copies: [`knowledge/rfcs/`][rfcs]. Architecture planning:
//! [GitHub project][plan]. This rustdoc does not restate wire format.
//! Integration tests live under `tests/` and `crates/coaptic-plugtest`.
//! Timed mixed-stack dogfood + Observe notify collect:
//! `cargo run -p coaptic-plugtest --bin dogfood`. CI compares `--iterations 2`
//! against `crates/coaptic-plugtest/baselines/` (`--compare`; Metrics floors
//! fail, including mixed-pair Block assemble sums; wall timings print as
//! delta; `progress` is informational).
//!
//! # Future / backlog
//!
//! Protocol support and qualification are tracked separately in the
//! repository issues. Passing individual scenarios does not establish full RFC
//! conformance. Engine BERT (SZX 7) codecs exist; App does not expose them.
//! Pairwise OSCORE (RFC 8613) is the `oscore` feature: a caller-owned
//! `SecurityContext` (Master Secret, Sender/Recipient IDs, replay
//! window). `App::set_oscore` attaches it; Engine does not store keys.
//! Group OSCORE, other ciphers, Outer Block-wise over OSCORE (proxy
//! hop-by-hop), and first-party DTLS remain backlog — the
//! `coaptic-plugtest` harness (feature `dtls`) wraps webrtc-dtls as a
//! [`DatagramIo`](storage::DatagramIo). Inner Block-wise (Block1/Block2:
//! fragment then protect) and Dual-class Max-Age / No-Response / ETag
//! placement are on the App path. Alternative networks (6LoWPAN,
//! LoRaWAN, …) are the same future / backlog.
//!
//! # Features
//!
//! - `alloc` — enable the allocator. Off by default.
//! - `std` — enable the standard library. Implies `alloc`.
//! - `oscore` — pairwise OSCORE (RFC 8613). Pulls RustCrypto `aes` /
//!   `ccm` / `hkdf` / `sha2`. Off by default so the crate stays zero-dep.
//!
//! [`no_std`]: https://doc.rust-lang.org/reference/names/preludes.html#the-no_std-prelude
//! [rfcs]: https://github.com/jeffglousher/coaptic/tree/main/knowledge/rfcs
//! [plan]: https://github.com/users/jeffglousher/projects/2

#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod app;
pub mod error;
pub mod message;
#[cfg(feature = "oscore")]
pub mod oscore;
pub mod storage;

pub use storage::profiles;

pub use app::{
    App, Call, CallFailure, EchoCheck, EchoDecision, EchoPolicy, Error, Method, Outgoing, Request,
    Response, ResponseError, delete, fetch, get, ipatch, patch, post, put,
};
pub use error::BuildError;
pub use message::{Code, ContentFormat, ProblemDetails};
pub use storage::{Endpoint, Metrics};
