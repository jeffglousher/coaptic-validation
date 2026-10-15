//! Approachable CoAP app: route inbound work, send outbound requests.
//!
//! ```text
//! RX slot (+ body) --view--> Request
//! handler(Request) -> Response
//! Response --encode--> TX slot (+ body)
//!
//! Outgoing (get/put) --encode--> TX slot
//! poll matches Token + endpoint
//! RX --copy--> Response::payload  (non-Block: min(len, INLINE_PAYLOAD) = 128)
//! Block2 / Q-Block2 --apply--> RX body --copy--> Response::body()
//! ```
//!
//! [`Request`] is a borrowed view for the handler call only. [`Response`] is
//! owned intent — the same type [`App::take_response`] yields for a
//! completed [`Call`]. Non-Block client payloads copy at most
//! [`INLINE_PAYLOAD`] (128) bytes; check
//! [`Response::payload_truncated`]. Assembled Block2 is
//! [`Response::body`]. The reactor owns per-slot state machines inside
//! [`App::poll`]. This module is not a seventh memory area and does **not**
//! own a global mutable shared bag. Domain data that outlives a request
//! stays outside `App`.
//!
//! ```
//! use coaptic::storage::DatagramIo;
//! use coaptic::{
//!     App, ContentFormat, Endpoint, Request, Response, get, profiles,
//! };
//!
//! fn get_temp(_req: Request<'_>) -> Response<'static> {
//!     Response::content(b"21.5").content_format(ContentFormat::TEXT_PLAIN)
//! }
//!
//! fn get_led(_: Request<'_>) -> Response<'static> {
//!     // Demo payload. Real LED state is firmware-owned, not an App bag.
//!     Response::content(b"off")
//! }
//!
//! fn put_led(_req: Request<'_>) -> Response<'static> {
//!     Response::changed()
//! }
//!
//! # struct NullIo;
//! # impl DatagramIo for NullIo {
//! #     type Error = &'static str;
//! #     fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
//! #         Ok(None)
//! #     }
//! #     fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> { Ok(bytes.len()) }
//! # }
//! let mut app = App::profile::<profiles::Default>()
//!     .randomness(|bytes| getrandom::fill(bytes).is_ok())
//!     .block_wise::<true>()
//!     .route("sensors/temp", get(get_temp))
//!     .route("leds/0", get(get_led).put(put_led))
//!     .well_known_core()
//!     .bind(NullIo)
//!     .unwrap();
//! app.poll(0).unwrap();
//!
//! let peer = Endpoint::v4([192, 0, 2, 2], 5683);
//! let call = app.get("sensors/temp").to(peer).send(0).unwrap();
//! app.poll(0).unwrap();
//! let _ = app.take_response(call);
//! ```
//!
//! Site capacity defaults to [`DEFAULT_ROUTES`] (8); raise it with
//! [`.routes::<16>()`](AppBuilder::routes) before bind. Paths accept
//! `"sensors/temp"` or `&["sensors", "temp"]` ([`IntoPath`]).
//!
//! Observe: return [`.observe`](Response::observe) on a successful GET, or
//! attach [`MethodRouter::observe`]; later representations are
//! [`App::notify`]. Server re-registration with the same peer, Token and route
//! advances the retained 24-bit sequence while replacing scheduling and OSCORE
//! request state. Sequence continuity after removal or restart is not retained.
//! Client subscribe/refresh uses [`Outgoing::observe`] /
//! [`Outgoing::reregister_call`]; cancellation uses
//! [`Outgoing::deregister`] on the same [`Call`]. Echo verification
//! (RFC 9175 4.01) is caller-owned through [`AppBuilder::echo_policy`]. Pairwise OSCORE
//! (feature `oscore`) is `App::set_oscore`.
//!
//! The happy path does not use [`Access`](crate::storage::Access) or
//! [`SlotId`]. Engine remains the advanced escape hatch
//! ([`App::engine_mut`]) for explicit slots, custom RST / remaining 4.xx,
//! and BERT edges (future / backlog).
mod client;
mod echo;
mod identity;
mod oscore;
mod request;
mod response;
mod routing;
mod site;

#[cfg(test)]
mod tests;

use core::marker::PhantomData;

use crate::error::{BlockTransferError, BuildError, EncodeError, SlotMessageError};
use crate::message::{
    BlockValue, Code, Echo, EncodedUint, Message, MessageId, NoResponse, Opt, OptionsBuilder,
    ParsedMessage, Transmission, Type, decode, encode, encode_uint,
};
use crate::storage::{
    BlockKey, BlockRole, BodySlots, DatagramIo, DatagramIoError, DatagramSlots, DedupEntry,
    DedupKey, DedupSlots, Endpoint, Engine, EngineBuilder, Exchanges, Memory, MemoryLayout,
    MemoryProfile, Metrics, Missing, ObserveInterest, ObserveKey, ObserveResource, ObserveSlots,
    OutgoingBlock, PendingCons, Present, QBlockRecover, Retransmit, SlotError, SlotId, Storage,
    WithBodies,
};

/// RFC 7252 default Max-Age when a registration or notify omits it.
pub(crate) const DEFAULT_MAX_AGE_SECS: u32 = 60;

pub use client::{
    Call, CallFailure, OBSERVE_REQUEST_BYTES, Outgoing, RESPONSE_OPTION_BYTES,
    RESPONSE_OPTION_COUNT,
};
pub use echo::{EchoCheck, EchoDecision, EchoPolicy};
use identity::{AppIds, Source as IdentitySource};
pub use identity::{IdentityError, RandomSource};
pub use request::{IntoPath, MAX_PATH_SEGMENTS, PathError, Request, split_path};
pub use response::{
    AppAssembled, INLINE_PAYLOAD, IntoResponse, LOCATION_MAX, RESPONSE_BODY, Response,
    ResponseError,
};
pub use routing::{
    HandlerFn, Method, MethodRouter, ObserveSource, delete, fetch, get, ipatch, patch, post, put,
};
pub use site::{
    DEFAULT_ROUTES, LINK_FORMAT_PER_ROUTE, LinkFormatScratch, Site, link_format_capacity,
};

use response::AssembledField;

/// Engine storage selected by [`AppBuilder::block_wise`].
pub(crate) type AppStore<P, const BLOCK_WISE: bool> = <P as MemoryLayout<BLOCK_WISE>>::Store;

/// CoAP app: profile memory + transport + a bounded [`Site`].
///
/// Handlers see a borrowed [`Request`] and return an owned [`Response`].
/// Outbound work is [`Self::get`] / [`Self::put`] → [`Outgoing::send`] →
/// [`Self::take_response`]. Non-Block [`Response::payload`] copies at most
/// [`INLINE_PAYLOAD`] (128) bytes; [`Response::payload_truncated`] is
/// `true` when the datagram was longer. Assembled Block2 / Q-Block2 is
/// [`Response::body`]. The reactor owns per-slot state machines
/// inside [`Self::poll`]. `N` is the maximum number of routes (default 8);
/// raise it with [`AppBuilder::routes`]. `BLOCK_WISE` is
/// [`AppBuilder::block_wise`]: `false` stores only [`Memory<P>`] (no body
/// pool arrays and no client Block2 assembled hold). You do not need
/// [`crate::storage::Access`] on this path — [`Self::engine_mut`] is the
/// advanced escape hatch.
pub struct App<
    P: MemoryProfile = crate::profiles::Default,
    T = (),
    const N: usize = DEFAULT_ROUTES,
    const BLOCK_WISE: bool = false,
> where
    P: MemoryLayout<BLOCK_WISE> + AppAssembled<BLOCK_WISE>,
{
    engine: Engine<AppStore<P, BLOCK_WISE>>,
    io: T,
    site: Site<N>,
    ids: AppIds,
    inbox: client::ClientInbox,
    lives: client::ClientLives,
    echo_policy: Option<EchoPolicy>,
    /// Last POST/PATCH/FETCH whose Dedup insert failed. A CON retransmit
    /// of that Message ID + peer is ACKed without a handler re-run until
    /// `due_ms` (fail-closed, not Miss). Not a seventh memory area.
    dedup_closed: Option<DedupClosed>,
    /// Caller-owned OSCORE context (`()` without the `oscore` feature).
    oscore: oscore::Field,
    /// Client Block2 / Q-Block2 snapshot for [`Self::take_response`].
    /// Present when `BLOCK_WISE`; zero-sized otherwise.
    assembled: AssembledField<P, BLOCK_WISE>,
}

/// Builder: [`App::profile`] → [`block_wise`](Self::block_wise) →
/// [`route`](Self::route) → [`bind`](Self::bind).
///
/// [`Self::block_wise`] is required before bind (typestate).
/// `.block_wise::<true>()` enables body pools for Block / Q-Block and the
/// client assembled-body hold; `.block_wise::<false>()` keeps datagram
/// slots only and does not reserve body-pool or assembled-hold RAM on
/// [`App`].
pub struct AppBuilder<
    P: MemoryProfile,
    Block = Missing,
    const N: usize = DEFAULT_ROUTES,
    const BLOCK_WISE: bool = false,
> {
    site: Site<N>,
    echo_policy: Option<EchoPolicy>,
    identity: Option<IdentitySource>,
    _p: PhantomData<P>,
    _b: PhantomData<Block>,
}

impl App {
    /// Start from a memory profile. Next: [`AppBuilder::block_wise`].
    #[must_use]
    pub const fn profile<P: MemoryProfile>() -> AppBuilder<P> {
        AppBuilder {
            site: Site::new(),
            echo_policy: None,
            identity: None,
            _p: PhantomData,
            _b: PhantomData,
        }
    }
}

impl<P: MemoryProfile, Block, const N: usize, const BLOCK_WISE: bool>
    AppBuilder<P, Block, N, BLOCK_WISE>
{
    /// Site table size (default [`DEFAULT_ROUTES`]). Call before
    /// [`Self::route`].
    ///
    /// # Panics
    ///
    /// If a route is already registered.
    #[must_use]
    pub fn routes<const M: usize>(self) -> AppBuilder<P, Block, M, BLOCK_WISE> {
        assert!(
            self.site.is_empty(),
            "call .routes::<M>() before .route(...)"
        );
        let well_known = self.site.has_well_known_core();
        let mut site = Site::new();
        if well_known {
            site.well_known_core();
        }
        AppBuilder {
            site,
            echo_policy: self.echo_policy,
            identity: self.identity,
            _p: PhantomData,
            _b: PhantomData,
        }
    }

    /// Bind `methods` on Uri-Path `path`.
    ///
    /// `path` is [`IntoPath`]: `"sensors/temp"` or `&["sensors", "temp"]`.
    /// `methods` is a site router ([`get`], [`put`], …), not an outbound
    /// [`App::get`] builder.
    #[must_use]
    pub fn route(mut self, path: impl IntoPath, methods: MethodRouter) -> Self {
        self.site.route(path, methods);
        self
    }

    /// Bind `methods` on a `'static` URI-Path (`"/leds/0"`).
    #[must_use]
    pub fn route_path(mut self, path: &'static str, methods: MethodRouter) -> Self {
        self.site.route_path(path, methods);
        self
    }

    /// Serve `/.well-known/core` from registered paths.
    ///
    /// Catalog scratch is [`LinkFormatScratch`] (compile-time
    /// [`link_format_capacity`] after [`Self::routes`]). Overflow is 5.00,
    /// not a truncated list.
    #[must_use]
    pub fn well_known_core(mut self) -> Self {
        self.site.well_known_core();
        self
    }

    /// Supply cryptographically secure bytes for Tokens, initial MID and RTO jitter.
    /// Required before bind; see [`RandomSource`]. The library does not call an OS RNG.
    /// Eight-byte Tokens are checked against all active App calls. MID allocation
    /// uses one sequence across local CON/NON requests, responses and Q windows.
    /// After 65536 allocations, reuse waits at least EXCHANGE_LIFETIME from the
    /// last allocation and requires pending transmissions to finish.
    ///
    /// Keep the App alive for the endpoint's lifetime. Recreating it at the same
    /// local endpoint requires a quiet EXCHANGE_LIFETIME interval or a caller-
    /// managed persistence strategy through the advanced Engine API. A random
    /// initial MID alone is not a restart collision guarantee.
    #[must_use]
    pub const fn randomness(mut self, source: RandomSource) -> Self {
        self.identity = Some(IdentitySource::Random(source));
        self
    }

    /// Predictable counters and minimum RTO, for reproducible tests only.
    /// Do not use this configuration on a production network.
    #[must_use]
    pub const fn deterministic_for_tests(mut self) -> Self {
        self.identity = Some(IdentitySource::Test);
        self
    }

    /// Install an explicit server Echo issuer/verifier. See [`EchoPolicy`].
    ///
    /// Off by default. Challenge/reject decisions produce 4.01 before body
    /// assembly or handler side effects. Only `EchoDecision::Accept` proceeds.
    #[must_use]
    pub const fn echo_policy(mut self, policy: EchoPolicy) -> Self {
        self.echo_policy = Some(policy);
        self
    }
}

impl<P: MemoryProfile, const N: usize, const PREV: bool> AppBuilder<P, Missing, N, PREV> {
    /// Enable or disable body pools, then [`AppBuilder::bind`].
    ///
    /// Shipped profiles use 4096 bytes per body slot, even
    /// [`crate::profiles::Constrained`]. Enabling this adds RX and TX body pools
    /// (8 KiB total for Constrained; 16 KiB for Default), a 4 KiB client
    /// assembled-body hold, and bookkeeping. Datagram sizes do not shrink
    /// that body quantum; size the complete `App` for your target.
    ///
    /// The flag is a const generic so [`App`] RAM matches Storage:
    /// `.block_wise::<false>()` does not reserve RX/TX body arrays or the
    /// client Block2 assembled hold. A piggybacked payload larger than
    /// [`INLINE_PAYLOAD`] (128) is still truncated on
    /// [`App::take_response`] in either mode; enable Block2 and read
    /// [`Response::body`] for the full representation.
    #[must_use]
    pub fn block_wise<const ENABLED: bool>(self) -> AppBuilder<P, Present, N, ENABLED> {
        AppBuilder {
            site: self.site,
            echo_policy: self.echo_policy,
            identity: self.identity,
            _p: PhantomData,
            _b: PhantomData,
        }
    }
}

impl<P, const N: usize> AppBuilder<P, Present, N, false>
where
    P: MemoryProfile + MemoryLayout<false, Store = Memory<P>>,
{
    /// Construct profile [`Memory`] (datagram pools only) and bind `io`.
    pub fn bind<T>(self, io: T) -> Result<App<P, T, N, false>, BuildError> {
        let engine = EngineBuilder::new()
            .profile::<P>()
            .block_wise(false)
            .build(Memory::<P>::new())?;
        Ok(App {
            engine,
            io,
            site: self.site,
            ids: AppIds::new(self.identity)?,
            inbox: client::ClientInbox::new(),
            lives: client::ClientLives::new(),
            echo_policy: self.echo_policy,
            dedup_closed: None,
            oscore: oscore::empty_field(),
            assembled: Default::default(),
        })
    }
}

impl<P, const N: usize> AppBuilder<P, Present, N, true>
where
    P: MemoryProfile + MemoryLayout<true, Store = Memory<P, WithBodies<P>>>,
{
    /// Construct profile [`Memory`] with body pools and bind `io`.
    pub fn bind<T>(self, io: T) -> Result<App<P, T, N, true>, BuildError> {
        let engine = EngineBuilder::new()
            .profile::<P>()
            .block_wise(true)
            .build(Memory::<P>::with_block_wise())?;
        Ok(App {
            engine,
            io,
            site: self.site,
            ids: AppIds::new(self.identity)?,
            inbox: client::ClientInbox::new(),
            lives: client::ClientLives::new(),
            echo_policy: self.echo_policy,
            dedup_closed: None,
            oscore: oscore::empty_field(),
            assembled: Default::default(),
        })
    }
}

impl<
    P: MemoryLayout<BLOCK_WISE> + AppAssembled<BLOCK_WISE>,
    T,
    const N: usize,
    const BLOCK_WISE: bool,
> App<P, T, N, BLOCK_WISE>
{
    /// Bind `methods` on Uri-Path `path`.
    ///
    /// `path` is [`IntoPath`]: `&["sensors", "temp"]` or `"sensors/temp"`.
    pub fn route(&mut self, path: impl IntoPath, methods: MethodRouter) -> &mut Self {
        self.site.route(path, methods);
        self
    }

    /// Bind `methods` on a `'static` URI-Path (`"/leds/0"`).
    pub fn route_path(&mut self, path: &'static str, methods: MethodRouter) -> &mut Self {
        self.site.route_path(path, methods);
        self
    }

    /// Serve `/.well-known/core` from registered paths.
    ///
    /// See [`AppBuilder::well_known_core`].
    pub const fn well_known_core(&mut self) -> &mut Self {
        self.site.well_known_core();
        self
    }

    /// Install an explicit server Echo issuer/verifier. See [`EchoPolicy`].
    pub const fn echo_policy(&mut self, policy: EchoPolicy) -> &mut Self {
        self.echo_policy = Some(policy);
        self
    }

    /// The site table.
    pub fn site(&mut self) -> &mut Site<N> {
        &mut self.site
    }

    /// Borrow the Engine (advanced path).
    ///
    /// The happy path is [`Self::poll`]. Use this when you need explicit
    /// slots or [`crate::storage::Access`].
    #[must_use]
    pub const fn engine(&self) -> &Engine<AppStore<P, BLOCK_WISE>> {
        &self.engine
    }

    /// Mutably borrow the Engine (advanced path).
    ///
    /// Escape hatch for explicit slots, [`crate::storage::Access`] /
    /// [`crate::storage::AccessMut`], custom RST / remaining 4.xx, and
    /// BERT edges (future / backlog). [`Self::poll`] already pins and
    /// releases; App handlers do not need this.
    pub const fn engine_mut(&mut self) -> &mut Engine<AppStore<P, BLOCK_WISE>> {
        &mut self.engine
    }

    /// Attach a caller-owned pairwise OSCORE context.
    ///
    /// There is exactly one context per App, with four live request bindings
    /// shared by in-flight requests and Observe registrations. Replacing it
    /// does not migrate live exchanges, tokens, replay state, or subscriptions;
    /// drain them first or use separate Apps for separate peers/key epochs.
    /// Timed Q-Block2 recovery for a live client GET uses a fresh protected
    /// request and retains its path, queries and selection options. Only the
    /// latest request binding is retained; late responses to earlier requests
    /// are not qualified. Timed server Q-Block1 reports retain the Token and
    /// request reference with the highest authenticated request Partial IV in
    /// the body sidecar, so reordered older payloads cannot replace it. Each
    /// report uses a fresh response Partial IV; failed sends retain bounded
    /// retry state and never reuse that sequence. Body completion/expiry drops
    /// the reference. This adds 24 bytes per body sidecar on the 64-bit host
    /// (96 bytes across Default RX/TX body slots), only with OSCORE enabled.
    /// Advanced receive bodies without a retained authenticated request or a
    /// live client Call return [`crate::oscore::Error::Unsupported`] without
    /// sending plaintext while a context is attached.
    /// Ordinary Q-Block2 response batches use fresh response Partial IVs and
    /// retain the request binding through assembly until response collection
    /// or cancellation. Recipient replay checks use the context's bounded
    /// 32-sequence window; this does not qualify Q Observe.
    ///
    /// Protected responses must match the Call endpoint and any piggybacked
    /// ACK Message ID before request-binding or notification replay state is
    /// consumed. Established notifications match the client Observe relation;
    /// unrelated protected responses are silently discarded. Authentication
    /// alone does not retire an ordinary request binding: rejected responses
    /// and failed ACK sends leave pending Calls usable. Collection, cancellation
    /// and terminal local failure release the binding; continuation replaces it.
    /// Response replay bookkeeping commits after critical-option validation and
    /// successful CON acknowledgment. This is in-memory admission, not a durable
    /// replay checkpoint barrier for application effects.
    ///
    /// Requires the `oscore` crate feature. You derive
    /// [`crate::oscore::SecurityContext`] (Master Secret, Sender/Recipient
    /// IDs, replay window). Engine does not store keys. Protect happens
    /// when a datagram is encoded into a TX slot, so CON retransmit
    /// reuses the same ciphertext.
    ///
    /// This slice covers a pairwise context on the happy-path
    /// request/response, Observe register/notify, Inner Block-wise
    /// (Block1/Block2: fragment, then protect), and Dual-class
    /// Max-Age / No-Response / ETag placement. Outer Block-wise (proxy
    /// hop-by-hop), group OSCORE, and other ciphers are out.
    ///
    /// Fail-closed while a context is attached: a non-empty datagram
    /// without an OSCORE option is rejected (4.01 on a request; a plain
    /// 2.xx or plain Block completion does not complete a [`Call`]).
    /// Empty ACK/RST stay unprotected (RFC 7252 reliability). AEAD
    /// failure is a silent drop.
    #[cfg(feature = "oscore")]
    pub fn set_oscore(&mut self, ctx: crate::oscore::SecurityContext) -> &mut Self {
        self.oscore = Some(ctx);
        self
    }

    /// Borrow the attached OSCORE context, if any.
    #[cfg(feature = "oscore")]
    #[must_use]
    pub const fn oscore(&self) -> Option<&crate::oscore::SecurityContext> {
        self.oscore.as_ref()
    }

    /// Mutably borrow the attached OSCORE context.
    #[cfg(feature = "oscore")]
    pub const fn oscore_mut(&mut self) -> Option<&mut crate::oscore::SecurityContext> {
        self.oscore.as_mut()
    }

    /// Copy of Engine reactor counters.
    ///
    /// Always-on wrapping `u32` fields at recv/send/`progress` sites. A
    /// `std` dogfood bin can print after a run:
    ///
    /// ```
    /// # use coaptic::storage::DatagramIo;
    /// # use coaptic::{App, Endpoint, profiles};
    /// # struct NullIo;
    /// # impl DatagramIo for NullIo {
    /// #     type Error = &'static str;
    /// #     fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
    /// #         Ok(None)
    /// #     }
    /// #     fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> { Ok(bytes.len()) }
    /// # }
    /// let mut app = App::profile::<profiles::Default>()
    ///     .randomness(|bytes| getrandom::fill(bytes).is_ok())
    ///     .block_wise::<false>()
    ///     .bind(NullIo)
    ///     .unwrap();
    /// app.poll(0).unwrap();
    /// let snap = app.metrics();
    /// assert_eq!(snap.progress, 1);
    /// ```
    ///
    /// See [`crate::storage::Metrics`] and [`Engine::metrics`].
    #[must_use]
    pub const fn metrics(&self) -> Metrics {
        self.engine.metrics()
    }

    /// Zero Engine reactor counters.
    pub fn reset_metrics(&mut self) {
        self.engine.reset_metrics();
    }

    /// Transport.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.io
    }

    /// Mutable transport.
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.io
    }

    /// Drop the app and keep the transport.
    #[must_use]
    pub fn into_io(self) -> T {
        self.io
    }
}

impl<P, T, const N: usize, const BLOCK_WISE: bool> App<P, T, N, BLOCK_WISE>
where
    P: MemoryLayout<BLOCK_WISE> + AppAssembled<BLOCK_WISE>,
    T: DatagramIo,
{
    /// One loop step: recv, progress, route, handler, send, release.
    ///
    /// `now_ms` is the caller clock (CON RTO, Observe Max-Age, Q-Block
    /// wait). No [`SlotId`] on this path.
    ///
    /// **Inbound.** Handlers see a borrowed [`Request`] and return an owned
    /// [`Response`]. Empty CON (code 0.00) is answered with empty RST
    /// (RFC 7252 ping). Incomplete Q-Block1 gets an empty ACK for CON;
    /// NON payloads get 2.31 only after a complete payload set, with the
    /// acknowledged Q-Block1 NUM. Successful Q-Block2 responses use all-NON
    /// payloads; a CON request receives a separate empty ACK before the set.
    /// Q recovery and partial-body expiry run after
    /// ingress; exhausted client Q downloads complete with [`CallFailure::TimedOut`].
    /// Incomplete classic Block1 is 2.31 (handler not
    /// run); a complete body is [`Request::body`]. Unrecognized critical
    /// options (not in the implemented set) and an OSCORE option with no
    /// attached context are 4.02 before the handler. A large response ships
    /// as Block2 / Q-Block2 from the TX body. Site misses are 4.04 / 4.05
    /// with [`Response::problem`]. Apply-error 4.08 uses problem details;
    /// Q-Block1 holes after `NON_RECEIVE_TIMEOUT` use
    /// [`Response::missing_blocks`]. An installed [`Self::echo_policy`] can
    /// challenge or reject with 4.01 before processing. Location-Path /
    /// Location-Query on the [`Response`]
    /// are written on the wire. [`Response::separate`] is an empty ACK
    /// to a CON request, then the completed representation in a new CON in
    /// the same poll (NON request → NON). Handlers are synchronous; App
    /// does not provide a deferred response completion handle. A retransmitted CON request (same
    /// Message ID + peer) is answered from the Dedup Table without a
    /// second handler call while the row is live (`EXCHANGE_LIFETIME`):
    /// the cached ACK bytes, or a pinned TX slot when the ACK does not
    /// fit the compact sidecar. POST / PATCH / FETCH never re-run on a
    /// live row (empty ACK if there is nothing to replay). If Dedup insert
    /// fails after the first POST / PATCH / FETCH (table full of
    /// never-expire rows), a retransmit is still ACKed without a handler
    /// re-run until `EXCHANGE_LIFETIME` (fail-closed, not Miss). GET / PUT /
    /// DELETE / iPATCH replay when a cache exists; without one, re-run is
    /// allowed (RFC 7252 §4.5 MAY). After `EXCHANGE_LIFETIME` expiry,
    /// Dedup Miss is a new exchange (POST / PATCH / FETCH may re-run).
    /// Proxy-Uri or Proxy-Scheme on a request is 5.05 before the site
    /// (origin; this crate is not a forward-proxy).
    /// Accepted CON responses also retain an empty ACK in this bounded table,
    /// including protected responses after reply collection. Replay is keyed
    /// by peer and Outer MID, without redelivering the response. Failed initial
    /// ACK sends do not install a replay. Rows expire at `EXCHANGE_LIFETIME`;
    /// table pressure can evict older App rows, so callers must size the profile
    /// for their concurrent request/notification history. This adds no body pool.
    /// An OSCORE CON retransmit is keyed on the *outer* Message ID so the
    /// cached protected ACK is replayed without a second unprotect.
    /// Classic Block2 ACKs use the same bounded cache, including protected
    /// fragments. Large replies can pin TX datagrams until expiry or pressure
    /// eviction; callers must budget reply history as well as active work.
    /// Observe register / deregister and
    /// [`ObserveSource`] notify run here. Pending notification signals are
    /// claimed after ingress: cancellation/re-registration cannot transfer a
    /// signal to a replacement row, and an earlier send failure preserves it.
    /// Caller-built notifications use
    /// [`Self::notify`]. Empty RST matching a notification Message ID
    /// drops that observer (RFC 7641 §4.5; RST has no Token).
    /// Max-Age expiry only makes representation data stale; it does not
    /// remove client or server Observe relations. CON notification retry
    /// exhaustion removes the server relation independently of Max-Age.
    /// Successful DELETE queues a terminal 4.04 CON for each server observer,
    /// preserving notification holds and retrying local send failures. Poll
    /// delivers these without requiring an ObserveSource. Each observer is
    /// removed after sending; pending CON delivery remains until ACK/give-up.
    ///
    /// **Outbound.** Token + peer match a [`Call`]; [`Self::take_response`]
    /// is the [`Response`]. Non-Block [`Response::payload`] copies at most
    /// [`INLINE_PAYLOAD`] (128) bytes ([`Response::payload_truncated`] when
    /// the datagram was longer). [`Response::body`] is the assembled Block2
    /// / Q-Block2 representation. Continues reuse the path from
    /// [`Outgoing::send`]. Uri-Query,
    /// Accept, ETag, If-Match / If-None-Match, and early Block2 are set on
    /// [`Outgoing`]. An Observe subscribe ([`Outgoing::observe`]) uses the
    /// same [`Call`].
    ///
    /// Retained Q-Block2 representations support block-zero and repeated
    /// Continue reselection without acknowledging the current set again.
    /// Future Continue sets must follow the issued window. Representation
    /// changes, retention after the final set and endpoint-wide congestion
    /// qualification remain separate from this bounded reselection behavior.
    ///
    /// **Retransmit.** Engine schedules CON RTO inside [`Engine::progress`]
    /// / [`Engine::poll_retransmit`] and does not send. This poll sends on
    /// [`Retransmit::Due`] and releases on [`Retransmit::GiveUp`]. A matching
    /// response (piggybacked ACK or separate CON/NON) clears that pending CON
    /// using the request Message ID. Empty RST matching a client outstanding
    /// request forgets the exchange. Empty ACK then silence, and lost NON,
    /// expire after RFC 7252 §4.8.2 `EXCHANGE_LIFETIME` / `NON_LIFETIME`.
    /// `now_ms` is the caller monotonic clock. Production CON jitter comes
    /// from the configured [`RandomSource`]; retransmits retain that schedule.
    /// Advanced slots / [`Access`](crate::storage::Access) / remaining RST
    /// policy / BERT (future / backlog): [`Self::engine_mut`].
    pub fn poll(&mut self, now_ms: u64) -> Result<(), Error<T::Error>> {
        poll_engine(
            &mut self.engine,
            &mut self.io,
            &self.site,
            &mut self.ids,
            &mut self.inbox,
            &mut self.lives,
            &mut self.oscore,
            self.echo_policy,
            &mut self.dedup_closed,
            now_ms,
        )
    }

    /// Send the current representation to server-side observers of `path`.
    /// Exact registered path segments select the route. Client subscriptions
    /// are separate, even when the peer and Token match an incoming observer.
    ///
    /// Honors notification NSTART. CON when the row
    /// [`ObserveInterest::must_confirm`]; otherwise NON. Returns how many
    /// notifications were sent. Domain data stays in `response` — `App`
    /// does not hold it. Successful notifications must keep the initial
    /// Content-Format, including its absence. A mismatch sends 4.06 without
    /// Observe and ends that relation. Non-success responses also omit Observe
    /// and end the relation after successful transmission (RFC 7641 §4.2).
    /// With body pools enabled, oversized notifications start classic Block2;
    /// protected notification block zero uses a fresh OSCORE Partial IV. The
    /// route handler must serve the same payload and ETag on retained-body
    /// follow-ups. Changes return `BlockTransferError::IdentityMismatch` before
    /// body output or transfer advancement. Other retained snapshot metadata
    /// and final-block recovery are not guaranteed.
    /// The body snapshot survives incomplete same-Token follow-up blocks,
    /// including send failure. Final-reply caching/completion, cancellation, replacement registration,
    /// matching notification RST or CON give-up releases it.
    /// Terminal responses use CON delivery. Pending CONs still count toward
    /// endpoint notification NSTART after the observer row has been removed.
    pub fn notify(
        &mut self,
        now_ms: u64,
        path: &[&str],
        response: Response<'static>,
    ) -> Result<usize, Error<T::Error>> {
        let resource = self.site.observe_resource(path);
        notify_engine(
            &mut self.engine,
            &mut self.io,
            &mut self.ids,
            &mut self.oscore,
            now_ms,
            resource,
            &response,
        )
    }

    /// Mark observers of `path` due. [`Self::poll`] encodes via
    /// [`ObserveSource`] when progress surfaces the row.
    ///
    /// Returns how many rows were marked. Use [`Self::notify`] when you
    /// already have the [`Response`].
    pub fn signal(&mut self, path: &[&str]) -> usize {
        let resource = self.site.observe_resource(path);
        self.engine.signal_observe_resource(resource)
    }
}

#[allow(clippy::too_many_arguments)]
fn poll_engine<Mem, T, const N: usize>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    site: &Site<N>,
    ids: &mut AppIds,
    inbox: &mut client::ClientInbox,
    lives: &mut client::ClientLives,
    oscore: &mut oscore::Field,
    echo_policy: Option<EchoPolicy>,
    dedup_closed: &mut Option<DedupClosed>,
    now_ms: u64,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + ObserveSlots + BodySlots + Exchanges + DedupSlots,
    T: DatagramIo,
{
    // RX pool full must not skip RTO / Observe / Q-Block recover. Surface
    // Saturated after those timers still run (RFC 7252 §4.2).
    // Local deadlines must progress even if receiving the next packet fails.
    expire_request_dedup(engine, dedup_closed, now_ms);
    client::expire_client_exchanges(engine, inbox, lives, oscore, now_ms);
    let (received, recv_saturated) = match engine.recv_from(io) {
        Ok(id) => (id, false),
        Err(DatagramIoError::Saturated) => (None, true),
        Err(e) => return Err(e.into()),
    };
    let progress = engine.progress_before_dispatch(now_ms);
    if let Some(retransmit) = progress.retransmit() {
        match retransmit {
            Retransmit::Due(pending) => {
                engine.send_tx(io, pending.tx_slot())?;
            }
            Retransmit::GiveUp(pending) => {
                client::give_up_client(engine, inbox, lives, oscore, pending.tx_slot());
                if let Some(interest) =
                    engine.reject_observe_notify(pending.message_id(), pending.endpoint())
                {
                    release_observe_response_body(engine, interest);
                }
                engine.release_tx(pending.tx_slot())?;
            }
        }
    }

    // Max-Age expires a representation, not an observation (RFC 7641
    // section 3.3.1). Only explicit CON-wait expiry terminates an interest.
    if let Some(crate::storage::ObserveExpiry::ClientOff(id)) = progress.observe_expired() {
        if let Some(interest) = engine.observe_interest(id) {
            let _ = engine.take_observe(interest.key());
            release_observe_response_body(engine, interest);
        }
    }

    if let Some(rx) = progress.rx_ready().or(received) {
        dispatch_rx(
            engine,
            io,
            site,
            inbox,
            lives,
            ids,
            oscore,
            echo_policy,
            dedup_closed,
            now_ms,
            rx,
        )?;
    }

    // Claim after ingress. Replacement registrations start with no pending
    // signal, so a reused slot cannot inherit the old relation's opportunity.
    if let Some(id) = progress
        .observe_notify()
        .and_then(|id| engine.claim_observe_notification(id, now_ms))
    {
        if let Some(interest) = engine.observe_interest(id) {
            let seq = interest.seq();
            if observe_endpoint_held(engine, interest.endpoint(), now_ms)
                >= usize::from(Transmission::NSTART)
            {
                let _ = engine.restore_observe_due(id, seq);
            } else {
                let response = if interest.is_deleted() {
                    Some(Response::not_found())
                } else {
                    site.observe_source(interest.resource())
                        .map(|source| source())
                };
                if let Some(response) = response {
                    if let Err(e) =
                        send_notification(engine, io, ids, oscore, now_ms, interest, &response, seq)
                    {
                        let _ = engine.restore_observe_due(id, seq);
                        return Err(e);
                    }
                } else {
                    let _ = engine.restore_observe_due(id, seq);
                }
            }
        }
    }

    // Process received payloads before advancing recovery or reclaiming an
    // exhausted partial body. No stale pre-dispatch opportunity is retained.
    let (recover, expired) = engine.next_qblock_recovery(now_ms);
    if let Some(key) = expired {
        client::qblock_give_up(engine, inbox, lives, oscore, key);
    }
    if let Some(recover) = recover {
        send_qblock_recover(
            engine,
            io,
            inbox,
            lives,
            ids,
            oscore,
            now_ms,
            recover,
            dedup_closed,
        )?;
    }
    if recv_saturated {
        return Err(Error::Saturated);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum InboundBody {
    None,
    Continue,
    QWait(Option<BlockValue>),
    Refused(Code),
    Complete(SlotId),
}

fn assemble_inbound_body<Mem>(
    engine: &mut Engine<Mem>,
    rx: SlotId,
    now_ms: u64,
    parsed: &ParsedMessage<'_>,
    oscore_request: oscore::Request,
) -> InboundBody
where
    Mem: Storage + DatagramSlots + BodySlots,
{
    #[cfg(not(feature = "oscore"))]
    let _ = oscore_request;
    // Classify from the first decode. Plain GET must not enter apply_*
    // (each stacks profile-sized Block IO scratch, then MissingBlock).
    if parsed.block1().is_some() {
        return match engine.apply_block1_rx(rx) {
            Ok(progress) if progress.complete() => InboundBody::Complete(progress.id()),
            Ok(_) => InboundBody::Continue,
            // Retransmit of an already-acked NUM (RFC 7959): replay 2.31, not 4.08.
            Err(BlockTransferError::Overlap | BlockTransferError::AlreadyComplete) => {
                InboundBody::Continue
            }
            Err(BlockTransferError::MissingBlock) => InboundBody::None,
            Err(BlockTransferError::NoBodyPools) => InboundBody::Refused(Code::BAD_OPTION),
            Err(BlockTransferError::Overflow) => {
                InboundBody::Refused(Code::REQUEST_ENTITY_TOO_LARGE)
            }
            Err(_) => InboundBody::Refused(Code::REQUEST_ENTITY_INCOMPLETE),
        };
    }
    if parsed.q_block1().is_some() {
        return match engine.apply_q_block1_rx(rx) {
            Ok(progress) if progress.complete() => {
                let _ = engine.note_q_receive(progress.id(), now_ms);
                InboundBody::Complete(progress.id())
            }
            Ok(progress) => {
                #[cfg(feature = "oscore")]
                if let Some(request) = oscore_request {
                    engine.remember_qblock1_request(progress.id(), parsed.token(), request);
                }
                let _ = engine.note_q_receive(progress.id(), now_ms);
                qblock1_wait(engine, rx, parsed)
            }
            Err(BlockTransferError::Duplicate) => {
                #[cfg(feature = "oscore")]
                if let Some(request) = oscore_request {
                    for index in 0..engine.capacities().rx_body_slots.unwrap_or(0) {
                        let id = SlotId::from_index(index);
                        if engine.rx_body_transfer(id).is_some_and(|transfer| {
                            transfer.role() == BlockRole::IncomingQBlock1
                                && Some(transfer.endpoint()) == engine.rx_endpoint(rx)
                                && transfer.identity().as_slice() == parsed.request_tag().next()
                        }) {
                            engine.remember_qblock1_request(id, parsed.token(), request);
                            break;
                        }
                    }
                }
                qblock1_wait(engine, rx, parsed)
            }
            Err(BlockTransferError::MissingBlock) => InboundBody::None,
            Err(BlockTransferError::NoBodyPools) => InboundBody::Refused(Code::BAD_OPTION),
            Err(BlockTransferError::Overflow) => {
                InboundBody::Refused(Code::REQUEST_ENTITY_TOO_LARGE)
            }
            Err(_) => InboundBody::Refused(Code::REQUEST_ENTITY_INCOMPLETE),
        };
    }
    InboundBody::None
}

// An empty ACK acknowledges a CON payload without promising a complete
// body. NON Continue is only due after a whole MAX_PAYLOADS_SET is present.
fn qblock1_wait<Mem: Storage + DatagramSlots + BodySlots>(
    engine: &Engine<Mem>,
    rx: SlotId,
    parsed: &ParsedMessage<'_>,
) -> InboundBody {
    let next = if parsed.ty() == Type::NonConfirmable {
        let peer = engine.rx_endpoint(rx);
        let tag = parsed.request_tag().next();
        (0..engine.capacities().rx_body_slots.unwrap_or(0)).find_map(|index| {
            let transfer = engine.rx_body_transfer(SlotId::from_index(index))?;
            if transfer.role() != BlockRole::IncomingQBlock1
                || Some(transfer.endpoint()) != peer
                || transfer.identity().as_slice() != tag
                || transfer.window_base() == 0
                || transfer.window_mask() != 0
            {
                return None;
            }
            BlockValue::new(transfer.window_base() - 1, true, transfer.szx()).ok()
        })
    } else {
        None
    };
    InboundBody::QWait(next)
}

/// Write a successfully unprotected Inner over the RX slot.
///
/// Block-wise assembly reads that slot (RFC 8613 §4.1.3.4.1). Encode or
/// `write_rx` failure is an error — not `Ok(())` that drops the Inner.
#[cfg(feature = "oscore")]
pub(crate) fn write_unprotected_rx<Mem, E>(
    engine: &mut Engine<Mem>,
    rx: SlotId,
    inner: &ParsedMessage<'_>,
    peer: Endpoint,
) -> Result<(), Error<E>>
where
    Mem: Storage + DatagramSlots,
{
    let mut inner_wire = Mem::RxScratch::default();
    let n = match inner.encode(inner_wire.as_mut()) {
        Ok(n) => n,
        Err(e) => {
            let _ = engine.release_rx(rx);
            return Err(Error::Message(SlotMessageError::Encode(e)));
        }
    };
    if let Err(e) = engine.write_rx(rx, &inner_wire.as_ref()[..n], peer) {
        let _ = engine.release_rx(rx);
        return Err(Error::Slot(e));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn send_qblock_recover<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    inbox: &mut client::ClientInbox,
    lives: &mut client::ClientLives,
    ids: &mut AppIds,
    oscore: &mut oscore::Field,
    now_ms: u64,
    recover: QBlockRecover,
    dedup_closed: &mut Option<DedupClosed>,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + BodySlots + DedupSlots + Exchanges + ObserveSlots,
    T: DatagramIo,
{
    if recover.role() == BlockRole::IncomingQBlock2
        && client::recover_qblock2(engine, io, inbox, lives, ids, oscore, now_ms, recover)?
    {
        return Ok(());
    }
    // Protected recovery requires an authenticated request binding. Advanced
    // body state without one must never fall back to plaintext.
    #[cfg(feature = "oscore")]
    if oscore::is_active(oscore) {
        return oscore::send_qblock1_recover(engine, io, ids, oscore, now_ms, recover);
    }
    match recover.role() {
        BlockRole::IncomingQBlock2 => {
            let mid = ids.next_for(engine, now_ms)?;
            let Some(tx) = engine.acquire_tx() else {
                return Err(Error::Saturated);
            };
            if let Err(e) =
                engine.encode_q_block2_recover_tx(recover, tx, Type::NonConfirmable, Code::GET, mid)
            {
                let _ = engine.release_tx(tx);
                return Err(Error::Block(e));
            }
            let send = engine.send_tx(io, tx);
            let _ = engine.release_tx(tx);
            send?;
            Ok(())
        }
        BlockRole::IncomingQBlock1 => {
            let mut nums = [0u32; 16];
            let n = recover.copy_missing_nums(&mut nums);
            let meta = SendResponse {
                dest: recover.key().endpoint(),
                ty: Type::NonConfirmable,
                mid: ids.next_for(engine, now_ms)?,
                token: recover.key().token(),
                no_response: NoResponse::DEFAULT,
                block2: None,
                q_block2: None,
                q_request: None,
                block1: None,
                oscore: oscore::no_request(),
                request: Code::GET,
            };
            send_response(
                engine,
                io,
                ids,
                meta,
                &Response::missing_blocks(nums.into_iter().take(n)),
                now_ms,
                oscore,
                dedup_closed,
            )
        }
        _ => Ok(()),
    }
}

/// 4.02 before [`Site::dispatch`]: unknown critical, OSCORE with no
/// attached context, or a malformed Block / Q-Block2 value.
fn bad_option_request(parsed: &ParsedMessage<'_>, oscore: &oscore::Field) -> bool {
    let mut tags = parsed.request_tag();
    let first = tags.next();
    let bad_tag = first.is_some_and(|tag| tag.len() > 8) || tags.next().is_some();
    bad_tag
        || (parsed.code() == Code::FETCH
            && (matches!(parsed.content_format(), Some(Err(_)))
                || parsed
                    .get_options(crate::message::OptionNumber::CONTENT_FORMAT)
                    .nth(1)
                    .is_some()))
        || parsed.unknown_critical().is_some()
        || (parsed.oscore().is_some() && !oscore::is_active(oscore))
        || matches!(parsed.block2(), Some(Err(_)))
        || parsed
            .q_block2()
            .any(|value| value.map_or(true, |block| block.is_bert()))
        || ((parsed.block1().is_some() || parsed.block2().is_some())
            && (parsed.q_block1().is_some() || parsed.q_block2().next().is_some()))
        || parsed
            .get_options(crate::message::OptionNumber::Q_BLOCK1)
            .nth(1)
            .is_some()
        || (parsed.q_block2().nth(1).is_some()
            && (parsed.observe().is_some()
                || parsed.q_block2().any(|q| {
                    q.is_ok_and(|q| {
                        q.more()
                            && q.num() % u32::from(crate::storage::BlockTransfer::MAX_PAYLOADS) == 0
                    })
                })))
        || matches!(parsed.block1(), Some(Err(_)))
}

fn valid_q_selections(parsed: &ParsedMessage<'_>) -> bool {
    let mut previous: Option<BlockValue> = None;
    for value in parsed.q_block2() {
        let Ok(value) = value else {
            return false;
        };
        if previous.is_some_and(|last| value.num() <= last.num() || value.szx() != last.szx()) {
            return false;
        }
        previous = Some(value);
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn dispatch_rx<Mem, T, const N: usize>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    site: &Site<N>,
    inbox: &mut client::ClientInbox,
    lives: &mut client::ClientLives,
    ids: &mut AppIds,
    oscore: &mut oscore::Field,
    echo_policy: Option<EchoPolicy>,
    dedup_closed: &mut Option<DedupClosed>,
    now_ms: u64,
    rx: SlotId,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + ObserveSlots + BodySlots + Exchanges + DedupSlots,
    T: DatagramIo,
{
    let Some(peer) = engine.rx_endpoint(rx) else {
        let _ = engine.release_rx(rx);
        return Ok(());
    };

    let mut scratch = Mem::RxScratch::default();
    let n = match copy_rx(engine, rx, scratch.as_mut()) {
        Ok(n) => n,
        Err(e) => {
            let _ = engine.release_rx(rx);
            return Err(e);
        }
    };

    let parsed = match decode(&scratch.as_ref()[..n]) {
        Ok(parsed) => parsed,
        Err(_) => {
            Metrics::inc(&mut engine.metrics_mut().rx_error);
            let _ = engine.release_rx(rx);
            return Ok(());
        }
    };

    if parsed.is_empty_ack_or_rst() {
        if parsed.is_empty_rst() {
            client::complete_client_rst(engine, inbox, lives, oscore, parsed.message_id(), peer);
        }
        if let Some(tx) = engine.match_empty_ack_rst(&parsed, peer) {
            let _ = engine.release_tx(tx);
            if parsed.is_empty_ack() {
                if let Err(error) = client::continue_qblock1_ack(
                    engine,
                    io,
                    inbox,
                    lives,
                    ids,
                    oscore,
                    now_ms,
                    parsed.message_id(),
                    peer,
                ) {
                    let _ = engine.release_rx(rx);
                    return Err(error);
                }
            }
        }
        if parsed.is_empty_ack() {
            let _ = engine.ack_observe_con(parsed.message_id(), peer);
        } else {
            // RST identifies a server notification by MID and endpoint. Its
            // request reference belongs to the removed server interest;
            // outgoing client bindings may independently use the same Token.
            if let Some(interest) = engine.reject_observe_notify(parsed.message_id(), peer) {
                release_observe_response_body(engine, interest);
            }
        }
        let _ = engine.release_rx(rx);
        return Ok(());
    }

    if parsed.is_empty() {
        let outcome = if parsed.ty() == Type::Confirmable {
            send_empty_rst(engine, io, peer, parsed.message_id())
        } else {
            Ok(())
        };
        let _ = engine.release_rx(rx);
        return outcome;
    }

    // Dedup keys the *outer* Message ID + peer. OSCORE CON retransmit
    // must replay the cached protected ACK before unprotect, or the
    // replay window consumes the Partial IV and the client never ACKs.
    if (parsed.code().is_request() || parsed.code().is_response())
        && parsed.ty() == Type::Confirmable
    {
        match replay_con_request(engine, io, peer, &parsed, now_ms, dedup_closed) {
            Replay::Hit(outcome) => {
                let _ = engine.release_rx(rx);
                return outcome;
            }
            Replay::Miss => {}
        }
    }

    // Match the Outer routing identity before OSCORE consumes a binding or
    // advances recipient replay/notification state. Inner authentication cannot
    // replace the Call's endpoint and piggybacked-ACK matching rules.
    if oscore::is_active(oscore)
        && parsed.oscore().is_some()
        && !parsed.code().is_request()
        && !client::has_response_target(engine, &parsed, peer)
    {
        let _ = engine.release_rx(rx);
        return Ok(());
    }

    let mut inner_scratch = Mem::RxScratch::default();
    let opened = match oscore::inbound(oscore, &parsed, inner_scratch.as_mut()) {
        Ok(opened) => opened,
        Err(e) => {
            let outcome =
                oscore_inbound_error(engine, io, ids, &parsed, peer, now_ms, e, dedup_closed);
            let _ = engine.release_rx(rx);
            return outcome;
        }
    };
    let (parsed, oscore_req, response_state) = match opened {
        Some((inner, req, response_state)) => {
            #[cfg(feature = "oscore")]
            {
                // Inner Block-wise (RFC 8613 §4.1.3.4.1): assembly reads
                // the RX slot. Replace the outer OSCORE datagram with the
                // opened Inner so Block1/Block2 see Class E options.
                write_unprotected_rx(engine, rx, &inner, peer)?;
                (inner, Some(req), response_state)
            }
            #[cfg(not(feature = "oscore"))]
            {
                (inner, req, response_state)
            }
        }
        None => (parsed, oscore::no_request(), oscore::ResponseState::None),
    };

    if !parsed.code().is_request() {
        let cache_ack = parsed.ty() == Type::Confirmable
            && parsed.unknown_critical().is_none()
            && lives.observe_format_admissible(
                Call::new(parsed.token(), peer),
                &parsed,
                now_ms,
                oscore::is_active(oscore),
            )
            && client::has_response_target(engine, &parsed, peer);
        let outcome = client::complete_client(
            engine,
            io,
            inbox,
            lives,
            ids,
            oscore,
            response_state,
            now_ms,
            peer,
            &parsed,
            rx,
        );
        // Only a successfully admitted response has earned an ACK replay.
        // A failed initial ACK must retry admission, not skip delivery.
        if outcome.is_ok() && cache_ack {
            remember_empty_ack(
                engine,
                peer,
                parsed.message_id(),
                now_ms,
                parsed.code(),
                dedup_closed,
            );
        }
        return outcome;
    }

    let no_response = NoResponse::from_message(&parsed).unwrap_or(NoResponse::DEFAULT);
    // Origin: Proxy-Uri / Proxy-Scheme MUST 5.05 (RFC 7252 §5.10.2).
    // Before the site so a missing Uri-Path is not 4.04.
    if parsed.proxy_uri().is_some() || parsed.proxy_scheme().is_some() {
        let meta = SendResponse {
            dest: peer,
            ty: parsed.ty(),
            mid: parsed.message_id(),
            token: parsed.token(),
            no_response,
            block2: None,
            q_block2: None,
            q_request: None,
            block1: None,
            oscore: oscore_req,
            request: parsed.code(),
        };
        let outcome = send_response(
            engine,
            io,
            ids,
            meta,
            &Response::problem(Code::PROXYING_NOT_SUPPORTED).title("Proxying Not Supported"),
            now_ms,
            oscore,
            dedup_closed,
        );
        let _ = engine.release_rx(rx);
        return outcome;
    }
    // Known-stack critical check and OSCORE-without-context run here,
    // before Site::dispatch. `knowledge/rfcs/rfc7252.txt` §5.4.1;
    // `knowledge/rfcs/rfc8613.txt` §8.2 (option 9 with no context).
    if bad_option_request(&parsed, oscore) {
        let meta = SendResponse {
            dest: peer,
            ty: parsed.ty(),
            mid: parsed.message_id(),
            token: parsed.token(),
            no_response,
            block2: None,
            q_block2: None,
            q_request: None,
            block1: None,
            oscore: oscore_req,
            request: parsed.code(),
        };
        let mut response = Response::problem(Code::BAD_OPTION).title("Bad Option");
        if let Some(number) = parsed.unknown_critical() {
            // A single u16 option fits the fixed problem payload. Preserve a
            // valid 4.02 fallback if the compact encoder's limits ever change.
            response = response
                .unprocessed_options(&[u64::from(number.get())])
                .unwrap_or(response);
        }
        let outcome = send_response(
            engine,
            io,
            ids,
            meta,
            &response,
            now_ms,
            oscore,
            dedup_closed,
        );
        let _ = engine.release_rx(rx);
        return outcome;
    }
    let block2 = parsed.block2().and_then(Result::ok);
    let q_block2 = parsed.q_block2().next().and_then(Result::ok);
    let block1 = parsed.block1().and_then(Result::ok).map(|value| BlockOpt {
        value,
        q_block: false,
        size2: None,
    });
    let meta = SendResponse {
        dest: peer,
        ty: parsed.ty(),
        mid: parsed.message_id(),
        token: parsed.token(),
        no_response,
        block2,
        q_block2,
        q_request: q_block2.map(|_| parsed),
        block1,
        oscore: oscore_req,
        request: parsed.code(),
    };

    // RFC 9177 section 4.3 requires 4.00 for missing Request-Tag or Size1.
    // Reject before admission/dispatch, preserving any existing partial body.
    let missing_q1_metadata = parsed.q_block1().is_some()
        && (parsed.request_tag().next().is_none() || !matches!(parsed.size1(), Some(Ok(_))));
    // RFC 8132 section 2.3.1 requires FETCH Content-Format, even for an
    // empty selection. Do not allocate partial bodies or call a handler.
    let missing_fetch_format = parsed.code() == Code::FETCH && parsed.content_format().is_none();
    if missing_q1_metadata || missing_fetch_format || !valid_q_selections(&parsed) {
        let outcome = send_response(
            engine,
            io,
            ids,
            SendResponse {
                block2: None,
                q_block2: None,
                q_request: None,
                ..meta
            },
            &Response::bad_request(),
            now_ms,
            oscore,
            dedup_closed,
        );
        let _ = engine.release_rx(rx);
        return outcome;
    }

    if let Some(policy) = echo_policy {
        let decision = policy(EchoCheck {
            echo: Echo::from_message(&parsed),
            peer,
            now_ms,
            oscore_protected: oscore::is_active(oscore),
        });
        match decision {
            EchoDecision::Accept => {}
            EchoDecision::Challenge(_) | EchoDecision::Reject => {
                let outcome = send_response(
                    engine,
                    io,
                    ids,
                    meta,
                    &unauthorized_echo(decision),
                    now_ms,
                    oscore,
                    dedup_closed,
                );
                let _ = engine.release_rx(rx);
                return outcome;
            }
        }
    }

    let assembled = assemble_inbound_body(engine, rx, now_ms, &parsed, oscore_req);
    match assembled {
        InboundBody::Continue => {
            let outcome = send_response(
                engine,
                io,
                ids,
                meta,
                &Response::new(Code::CONTINUE),
                now_ms,
                oscore,
                dedup_closed,
            );
            let _ = engine.release_rx(rx);
            return outcome;
        }
        InboundBody::QWait(continue_block) => {
            let outcome = if let Some(value) = continue_block {
                send_response(
                    engine,
                    io,
                    ids,
                    SendResponse {
                        block1: Some(BlockOpt {
                            value,
                            q_block: true,
                            size2: None,
                        }),
                        ..meta
                    },
                    &Response::new(Code::CONTINUE),
                    now_ms,
                    oscore,
                    dedup_closed,
                )
            } else if meta.ty == Type::Confirmable {
                // Body admission and authenticated replay state already advanced.
                // Retain the ACK before I/O so a failed send can be retried by
                // the peer without reopening the protected request.
                remember_empty_ack(
                    engine,
                    meta.dest,
                    meta.mid,
                    now_ms,
                    meta.request,
                    dedup_closed,
                );
                send_empty_ack(engine, io, meta.dest, meta.mid)
            } else {
                Ok(())
            };
            let _ = engine.release_rx(rx);
            return outcome;
        }
        InboundBody::Refused(code) => {
            // Apply errors (gap, SZX mismatch, overflow, …).
            // Classic Overlap / AlreadyComplete replay 2.31 above.
            // Window holes use `send_qblock_recover` → `Response::missing_blocks`.
            let outcome = send_response(
                engine,
                io,
                ids,
                meta,
                &Response::problem(code).title(match code {
                    Code::REQUEST_ENTITY_INCOMPLETE => "Request Entity Incomplete",
                    Code::REQUEST_ENTITY_TOO_LARGE => "Request Entity Too Large",
                    _ => "Block Transfer Rejected",
                }),
                now_ms,
                oscore,
                dedup_closed,
            );
            let _ = engine.release_rx(rx);
            return outcome;
        }
        InboundBody::None | InboundBody::Complete(_) => {}
    }

    let mut catalog = site::LinkFormatScratch::<N>::new();
    let (response, plan) = {
        let body = match assembled {
            InboundBody::Complete(id) => engine.rx_body_payload(id),
            InboundBody::None
            | InboundBody::Continue
            | InboundBody::QWait(_)
            | InboundBody::Refused(_) => None,
        };
        match Request::from_decoded(parsed, peer, body) {
            Ok(request) => {
                let plan = ObservePlan::from_request(site, &request);
                (site.dispatch(request, catalog.as_mut()), plan)
            }
            Err(request::PathError::BadUtf8 | request::PathError::EmptySegment) => (
                Response::problem(Code::BAD_REQUEST).title("Bad Request"),
                ObservePlan::idle(),
            ),
            Err(request::PathError::TooLong) => (
                Response::problem(Code::NOT_FOUND).title("Not Found"),
                ObservePlan::idle(),
            ),
        }
    };
    if let Err(error) = response.validate() {
        if let InboundBody::Complete(id) = assembled {
            let _ = engine.release_rx_body(id);
        }
        let _ = engine.release_rx(rx);
        return Err(Error::Response(error));
    }
    let response = apply_observe(engine, now_ms, peer, response, plan, oscore_req);

    let outcome = if response.is_separate() {
        send_separate(
            engine,
            io,
            ids,
            now_ms,
            meta,
            &response,
            oscore,
            dedup_closed,
        )
    } else {
        send_response(
            engine,
            io,
            ids,
            meta,
            &response,
            now_ms,
            oscore,
            dedup_closed,
        )
    };
    if let InboundBody::Complete(id) = assembled {
        let _ = engine.release_rx_body(id);
    }
    let _ = engine.release_rx(rx);
    outcome
}

#[derive(Clone, Copy)]
struct ObservePlan {
    register: bool,
    deregister: bool,
    delete: bool,
    has_source: bool,
    token: crate::message::Token,
    resource: ObserveResource,
}

impl ObservePlan {
    fn idle() -> Self {
        Self {
            register: false,
            deregister: false,
            delete: false,
            has_source: false,
            token: crate::message::Token::EMPTY,
            resource: ObserveResource::NONE,
        }
    }

    fn from_request<const N: usize>(site: &Site<N>, request: &Request<'_>) -> Self {
        Self {
            register: request.is_observe_register(),
            deregister: request.is_observe_deregister(),
            delete: request.method() == Some(Method::Delete),
            has_source: site.has_observe_source(request.path()),
            token: request.token(),
            resource: site.observe_resource(request.path()),
        }
    }
}

fn apply_observe<'a, S: Storage + ObserveSlots + BodySlots>(
    engine: &mut Engine<S>,
    now_ms: u64,
    peer: Endpoint,
    mut response: Response<'a>,
    plan: ObservePlan,
    oscore_req: oscore::Request,
) -> Response<'a> {
    let key = ObserveKey::new(plan.token, peer);

    let opted = response.observe_seq().is_some() || plan.has_source;
    response = response.without_observe();
    let previous = if plan.deregister || plan.register {
        engine.take_observe(key)
    } else {
        None
    };
    if let Some(interest) = previous {
        release_observe_response_body(engine, interest);
    }
    if plan.register && response.code().is_success() && opted {
        // Re-registration replaces scheduling and protection state, but the
        // same Token/resource must retain ordering across that replacement.
        let sequence = previous
            .filter(|interest| interest.resource() == plan.resource)
            .map_or(0, |interest| interest.seq().wrapping_add(1) & 0x00ff_ffff);
        let interest = ObserveInterest::new(plan.token, peer)
            .with_seq(sequence)
            .with_resource(plan.resource)
            .with_content_format(response.format());
        #[cfg(feature = "oscore")]
        let interest = interest.with_oscore(oscore_req);
        #[cfg(not(feature = "oscore"))]
        let _ = oscore_req;
        if engine.insert_observe(interest).is_some() {
            let max_age = response.max_age_secs().unwrap_or(DEFAULT_MAX_AGE_SECS);
            let _ = engine.refresh_observe_max_age(key, now_ms, max_age, None);
            response = response.observe(sequence);
        } else {
            response = response.without_observe();
        }
    }
    if plan.delete && response.code().is_success() {
        let _ = engine.mark_observe_resource_deleted(plan.resource);
    }
    response
}

fn notify_engine<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    ids: &mut AppIds,
    oscore: &mut oscore::Field,
    now_ms: u64,
    resource: ObserveResource,
    response: &Response<'_>,
) -> Result<usize, Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + ObserveSlots + BodySlots + DedupSlots,
    T: DatagramIo,
{
    response.validate().map_err(Error::Response)?;
    if resource.is_none() {
        return Ok(0);
    }
    let n = engine.capacities().observe_entries;
    let mut held = NotifyHeldCache::from_engine(engine, now_ms);
    let mut sent = 0usize;
    for i in 0..n {
        let id = SlotId::from_index(i);
        let Some(interest) = engine.observe_interest(id) else {
            continue;
        };
        if interest.key().is_client() || interest.resource() != resource {
            continue;
        }
        if held.count(engine, interest.endpoint(), now_ms)
            >= usize::from(crate::message::Transmission::NSTART)
        {
            Metrics::inc(&mut engine.metrics_mut().nstart_reject);
            continue;
        }
        let Some(seq) = engine.next_observe_seq(id) else {
            continue;
        };
        let Some(interest) = engine.observe_interest(id) else {
            continue;
        };
        let dest = interest.endpoint();
        if let Err(e) = send_notification(engine, io, ids, oscore, now_ms, interest, response, seq)
        {
            let _ = engine.restore_observe_due(id, seq);
            return Err(e);
        }
        held.add(dest);
        sent += 1;
    }
    Ok(sent)
}

/// Per-endpoint notification NSTART counts for one [`notify_engine`] pass.
///
/// Bounded scans of Observe and pending-CON tables, including terminal
/// delivery whose observer row is already removed, without double-counting.
/// Shipped profiles have ≤4 observe entries; the table covers 8 unique
/// endpoints and falls back to a full scan if that overflows (alloc backend).
const NOTIFY_HELD_CACHE: usize = 8;

struct NotifyHeldCache {
    endpoints: [Option<Endpoint>; NOTIFY_HELD_CACHE],
    held: [u8; NOTIFY_HELD_CACHE],
    overflow: bool,
}

impl NotifyHeldCache {
    fn from_engine<S: Storage + ObserveSlots + PendingCons>(
        engine: &Engine<S>,
        now_ms: u64,
    ) -> Self {
        let mut cache = Self {
            endpoints: [None; NOTIFY_HELD_CACHE],
            held: [0; NOTIFY_HELD_CACHE],
            overflow: false,
        };
        let n = engine.capacities().observe_entries;
        for i in 0..n {
            let Some(row) = engine.observe_interest(SlotId::from_index(i)) else {
                continue;
            };
            if !row.key().is_client() && row.is_notify_held(now_ms) {
                cache.add(row.endpoint());
            }
        }
        for i in 0..engine.capacities().tx_datagram_slots {
            if let Some(pending) = engine.pending_con(SlotId::from_index(i)) {
                if !pending_has_observe_hold(engine, pending, now_ms) {
                    cache.add(pending.endpoint());
                }
            }
        }
        cache
    }

    fn add(&mut self, endpoint: Endpoint) {
        if let Some(i) = self.index(endpoint) {
            self.held[i] = self.held[i].saturating_add(1);
            return;
        }
        if let Some(i) = self.endpoints.iter().position(Option::is_none) {
            self.endpoints[i] = Some(endpoint);
            self.held[i] = 1;
            return;
        }
        self.overflow = true;
    }

    fn index(&self, endpoint: Endpoint) -> Option<usize> {
        self.endpoints.iter().position(|row| *row == Some(endpoint))
    }

    fn count<S: Storage + ObserveSlots + PendingCons>(
        &self,
        engine: &Engine<S>,
        endpoint: Endpoint,
        now_ms: u64,
    ) -> usize {
        if let Some(i) = self.index(endpoint) {
            return usize::from(self.held[i]);
        }
        if self.overflow {
            return observe_endpoint_held(engine, endpoint, now_ms);
        }
        0
    }
}

fn observe_endpoint_held<S: Storage + ObserveSlots + PendingCons>(
    engine: &Engine<S>,
    endpoint: Endpoint,
    now_ms: u64,
) -> usize {
    let n = engine.capacities().observe_entries;
    let interests = (0..n)
        .filter(|&i| {
            engine
                .observe_interest(SlotId::from_index(i))
                .is_some_and(|row| {
                    !row.key().is_client()
                        && row.endpoint() == endpoint
                        && row.is_notify_held(now_ms)
                })
        })
        .count();
    interests
        + (0..engine.capacities().tx_datagram_slots)
            .filter(|&i| {
                engine
                    .pending_con(SlotId::from_index(i))
                    .is_some_and(|pending| {
                        pending.endpoint() == endpoint
                            && !pending_has_observe_hold(engine, pending, now_ms)
                    })
            })
            .count()
}

fn pending_has_observe_hold<S: Storage + ObserveSlots>(
    engine: &Engine<S>,
    pending: crate::storage::PendingCon,
    now_ms: u64,
) -> bool {
    (0..engine.capacities().observe_entries).any(|i| {
        engine
            .observe_interest(SlotId::from_index(i))
            .is_some_and(|row| {
                !row.key().is_client()
                    && row.endpoint() == pending.endpoint()
                    && row.is_notify_held(now_ms)
                    && (row.notify_hold().and_then(|hold| hold.con_mid())
                        == Some(pending.message_id())
                        || row.lifetime().and_then(|life| life.con_mid())
                            == Some(pending.message_id()))
            })
    })
}

#[allow(clippy::too_many_arguments)]
fn send_notification<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    ids: &mut AppIds,
    oscore: &mut oscore::Field,
    now_ms: u64,
    interest: ObserveInterest,
    response: &Response<'_>,
    seq: u32,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + ObserveSlots + BodySlots + DedupSlots,
    T: DatagramIo,
{
    response.validate().map_err(Error::Response)?;
    let mut notify = if interest.is_deleted() {
        Response::not_found()
    } else if response.code().is_success() && response.format() != interest.content_format() {
        Response::new(Code::NOT_ACCEPTABLE)
    } else {
        *response
    };
    // Terminal delivery remains tracked even after removing the observer row.
    let ty = if !notify.code().is_success() || interest.must_confirm(now_ms) {
        Type::Confirmable
    } else {
        Type::NonConfirmable
    };
    let mid = ids.next_for(engine, now_ms)?;
    if notify.code().is_success() {
        notify.set_observe(seq);
    } else {
        notify = notify.without_observe();
    }
    let dest = interest.endpoint();
    let token = interest.token();
    let key = BlockKey::new(token, dest);
    if let Some(body) = response_body_for(engine, key) {
        let _ = engine.release_tx_body(body);
    }

    let oscore_req = oscore::request_from_interest(interest);
    let meta = SendResponse {
        dest,
        ty,
        mid,
        token,
        no_response: NoResponse::DEFAULT,
        block2: None,
        q_block2: None,
        q_request: None,
        block1: None,
        oscore: oscore_req,
        request: Code::GET,
    };

    let Some(tx) = engine.acquire_tx() else {
        return Err(Error::Saturated);
    };
    let pending = (ty == Type::Confirmable).then_some((now_ms, mid, ids.jitter()));
    let outcome = match encode_notification(
        engine,
        tx,
        ty,
        mid,
        token,
        &notify,
        notify.payload(),
        oscore,
        oscore_req,
    ) {
        Ok(()) => finish_send(engine, io, tx, dest, pending),
        Err(Error::Message(SlotMessageError::Encode(EncodeError::BufferTooSmall))) => {
            let _ = engine.release_tx(tx);
            start_notify_block2(engine, io, meta, &notify, ty, pending, oscore)
        }
        Err(e) => {
            let _ = engine.release_tx(tx);
            Err(e)
        }
    };
    outcome?;
    if !notify.code().is_success() {
        let _ = engine.take_observe(interest.key());
        return Ok(());
    }

    let confirmable = ty == Type::Confirmable;
    let _ = engine.record_observe_notify(interest.key(), now_ms, mid, confirmable);
    if !confirmable {
        let max_age = notify.max_age_secs().unwrap_or(DEFAULT_MAX_AGE_SECS);
        let _ = engine.refresh_observe_max_age(interest.key(), now_ms, max_age, None);
    }
    Ok(())
}

fn start_notify_block2<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    meta: SendResponse,
    response: &Response<'_>,
    ty: Type,
    pending: Option<(u64, MessageId, u32)>,
    oscore_ctx: &mut oscore::Field,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + BodySlots + DedupSlots,
    T: DatagramIo,
{
    let key = response_block_key(meta.token, meta.dest, response)?;
    let id = match engine.start_block2(key, response.payload(), BlockValue::SZX_MAX) {
        Ok(id) => id,
        Err(BlockTransferError::NoBodyPools) => {
            return Err(Error::Message(SlotMessageError::Encode(
                EncodeError::BufferTooSmall,
            )));
        }
        Err(e) => return Err(Error::Block(e)),
    };
    let outcome = issue_classic(
        engine, io, meta, response, ty, meta.mid, id, pending, true, None, oscore_ctx,
    );
    if outcome.is_err() {
        let _ = engine.release_tx_body(id);
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn send_separate<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    ids: &mut AppIds,
    now_ms: u64,
    meta: SendResponse,
    response: &Response<'_>,
    oscore_ctx: &mut oscore::Field,
    dedup_closed: &mut Option<DedupClosed>,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + BodySlots + DedupSlots,
    T: DatagramIo,
{
    response.validate().map_err(Error::Response)?;
    if meta.q_block2.is_some() && response.code().is_success() {
        // Q bodies consistently use NON responses, including handlers that
        // request a separate response. The Q sender supplies the empty ACK.
        return send_response(
            engine,
            io,
            ids,
            meta,
            response,
            now_ms,
            oscore_ctx,
            dedup_closed,
        );
    }
    let key = BlockKey::new(meta.token, meta.dest);
    if let Some(id) = response_body_for(engine, key) {
        if engine.tx_body_transfer(id).is_some_and(|t| {
            matches!(
                t.role(),
                BlockRole::OutgoingBlock2 | BlockRole::OutgoingQBlock2
            )
        }) {
            let ty = match meta.ty {
                Type::Confirmable => Type::Acknowledgement,
                Type::NonConfirmable => Type::NonConfirmable,
                Type::Acknowledgement | Type::Reset => return Ok(()),
            };
            let mut meta = meta;
            if ty == Type::NonConfirmable {
                meta.mid = ids.next_for(engine, now_ms)?;
            }
            return continue_outgoing(
                engine,
                io,
                ids,
                now_ms,
                meta,
                response,
                ty,
                id,
                oscore_ctx,
                dedup_closed,
            );
        }
    }

    let ty = match meta.ty {
        Type::Confirmable => {
            send_empty_ack(engine, io, meta.dest, meta.mid)?;
            remember_empty_ack(
                engine,
                meta.dest,
                meta.mid,
                now_ms,
                meta.request,
                dedup_closed,
            );
            Type::Confirmable
        }
        Type::NonConfirmable => Type::NonConfirmable,
        Type::Acknowledgement | Type::Reset => return Ok(()),
    };

    if meta.no_response.suppresses(response.code()) {
        return Ok(());
    }

    let mid = ids.next_for(engine, now_ms)?;
    let pending = (ty == Type::Confirmable).then_some((now_ms, mid, ids.jitter()));

    let Some(tx) = engine.acquire_tx() else {
        return Err(Error::Saturated);
    };

    match encode_response(
        engine,
        tx,
        ty,
        mid,
        meta.token,
        response,
        response.payload(),
        None,
        meta.block1,
        oscore_ctx,
        meta.oscore,
    ) {
        Ok(()) => finish_send(engine, io, tx, meta.dest, pending),
        Err(Error::Message(SlotMessageError::Encode(EncodeError::BufferTooSmall))) => {
            // True size miss: Inner Block2 (also under OSCORE). Protocol
            // protect failures are `Error::Oscore`, not this arm.
            let _ = engine.release_tx(tx);
            let meta = SendResponse { mid, ..meta };
            start_outgoing(
                engine,
                io,
                ids,
                now_ms,
                meta,
                response,
                ty,
                key,
                oscore_ctx,
                dedup_closed,
            )
        }
        Err(e) => {
            let _ = engine.release_tx(tx);
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn send_response<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    ids: &mut AppIds,
    meta: SendResponse,
    response: &Response<'_>,
    now_ms: u64,
    oscore_ctx: &mut oscore::Field,
    dedup_closed: &mut Option<DedupClosed>,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + BodySlots + DedupSlots,
    T: DatagramIo,
{
    response.validate().map_err(Error::Response)?;
    if meta.no_response.suppresses(response.code()) {
        return match meta.ty {
            Type::Confirmable => {
                send_empty_ack(engine, io, meta.dest, meta.mid)?;
                remember_empty_ack(
                    engine,
                    meta.dest,
                    meta.mid,
                    now_ms,
                    meta.request,
                    dedup_closed,
                );
                Ok(())
            }
            Type::NonConfirmable | Type::Acknowledgement | Type::Reset => Ok(()),
        };
    }

    let ty = match meta.ty {
        Type::Confirmable => Type::Acknowledgement,
        Type::NonConfirmable => Type::NonConfirmable,
        Type::Acknowledgement | Type::Reset => return Ok(()),
    };

    let mut meta = meta;
    if ty == Type::NonConfirmable {
        meta.mid = ids.next_for(engine, now_ms)?;
    }

    let key = BlockKey::new(meta.token, meta.dest);
    if let Some(id) = response_body_for(engine, key).filter(|_| response.code().is_success()) {
        if engine.tx_body_transfer(id).is_some_and(|t| {
            matches!(
                t.role(),
                BlockRole::OutgoingBlock2 | BlockRole::OutgoingQBlock2
            )
        }) {
            return continue_outgoing(
                engine,
                io,
                ids,
                now_ms,
                meta,
                response,
                ty,
                id,
                oscore_ctx,
                dedup_closed,
            );
        }
    }

    if (meta.block2.is_some() || meta.q_block2.is_some()) && response.code().is_success() {
        return start_outgoing(
            engine,
            io,
            ids,
            now_ms,
            meta,
            response,
            ty,
            key,
            oscore_ctx,
            dedup_closed,
        );
    }

    let Some(tx) = acquire_tx_or_evict(engine) else {
        return Err(Error::Saturated);
    };

    match encode_response(
        engine,
        tx,
        ty,
        meta.mid,
        meta.token,
        response,
        response.payload(),
        None,
        meta.block1,
        oscore_ctx,
        meta.oscore,
    ) {
        Ok(()) => match remember_tx_reply(
            engine,
            tx,
            meta.dest,
            meta.mid,
            meta.ty,
            now_ms,
            meta.request,
            dedup_closed,
        ) {
            KeepTx::Yes => send_pinned_tx(engine, io, tx, meta.dest),
            KeepTx::No => finish_send(engine, io, tx, meta.dest, None),
        },
        Err(Error::Message(SlotMessageError::Encode(EncodeError::BufferTooSmall))) => {
            // True size miss: Inner Block2 (also under OSCORE). Protocol
            // protect failures are `Error::Oscore`, not this arm.
            let _ = engine.release_tx(tx);
            start_outgoing(
                engine,
                io,
                ids,
                now_ms,
                meta,
                response,
                ty,
                key,
                oscore_ctx,
                dedup_closed,
            )
        }
        Err(e) => {
            let _ = engine.release_tx(tx);
            Err(e)
        }
    }
}

fn response_block_key<E>(
    token: crate::message::Token,
    endpoint: Endpoint,
    response: &Response<'_>,
) -> Result<BlockKey, Error<E>> {
    let key = BlockKey::new(token, endpoint);
    match response.etag_bytes() {
        Some(tag) => Ok(key.with_identity(
            crate::storage::BodyTag::new(tag)
                .map_err(BlockTransferError::from)
                .map_err(Error::Block)?,
        )),
        None => Ok(key),
    }
}

fn release_observe_response_body<S: Storage + BodySlots>(
    engine: &mut Engine<S>,
    interest: ObserveInterest,
) {
    if !interest.key().is_client() {
        if let Some(id) =
            response_body_for(engine, BlockKey::new(interest.token(), interest.endpoint()))
        {
            let _ = engine.release_tx_body(id);
        }
    }
}

fn response_body_for<S: Storage + BodySlots>(engine: &Engine<S>, key: BlockKey) -> Option<SlotId> {
    (0..engine.capacities().tx_body_slots.unwrap_or(0)).find_map(|index| {
        let id = SlotId::from_index(index);
        let transfer = engine.tx_body_transfer(id)?;
        (transfer.token() == key.token()
            && transfer.endpoint() == key.endpoint()
            && matches!(
                transfer.role(),
                BlockRole::OutgoingBlock2 | BlockRole::OutgoingQBlock2
            ))
        .then_some(id)
    })
}

#[allow(clippy::too_many_arguments)]
fn start_outgoing<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    ids: &mut AppIds,
    now_ms: u64,
    meta: SendResponse,
    response: &Response<'_>,
    ty: Type,
    key: BlockKey,
    oscore_ctx: &mut oscore::Field,
    dedup_closed: &mut Option<DedupClosed>,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + BodySlots + DedupSlots,
    T: DatagramIo,
{
    let szx = szx_for(meta.block2, meta.q_block2);
    let started = if meta.q_block2.is_some() {
        let etag = response
            .etag_bytes()
            .ok_or(Error::Block(BlockTransferError::MissingIdentity))?;
        let key = key.with_identity(
            crate::storage::BodyTag::new(etag)
                .map_err(BlockTransferError::from)
                .map_err(Error::Block)?,
        );
        engine.start_q_block2(key, response.payload(), szx)
    } else {
        let key = response_block_key(key.token(), key.endpoint(), response)?;
        engine.start_block2(key, response.payload(), szx)
    };
    let id = match started {
        Ok(id) => id,
        Err(BlockTransferError::NoBodyPools) => {
            return Err(Error::Message(SlotMessageError::Encode(
                EncodeError::BufferTooSmall,
            )));
        }
        Err(e) => return Err(Error::Block(e)),
    };
    let selective = meta.q_block2.is_some_and(|q| !q.more() || q.num() != 0)
        || meta
            .q_request
            .is_some_and(|p| p.q_block2().nth(1).is_some());
    let outcome = if selective {
        issue_q_selection(
            engine,
            io,
            ids,
            now_ms,
            meta,
            response,
            ty,
            id,
            oscore_ctx,
            dedup_closed,
        )
    } else if meta.q_block2.is_some() {
        issue_q_window(
            engine,
            io,
            ids,
            now_ms,
            meta,
            response,
            ty,
            id,
            oscore_ctx,
            dedup_closed,
        )
    } else {
        issue_classic(
            engine,
            io,
            meta,
            response,
            ty,
            meta.mid,
            id,
            None,
            response.observe_seq().is_some(),
            Some((now_ms, dedup_closed)),
            oscore_ctx,
        )
    };
    // Selective requests are independent exchanges. A fresh handler body is
    // only a temporary snapshot; retaining it would leave an unadvanced window
    // occupying a body slot forever. Existing full-transfer state is handled
    // separately by continue_outgoing and survives recovery selections.
    if outcome.is_err() || selective {
        let _ = engine.release_tx_body(id);
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn continue_outgoing<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    ids: &mut AppIds,
    now_ms: u64,
    meta: SendResponse,
    response: &Response<'_>,
    ty: Type,
    id: SlotId,
    oscore_ctx: &mut oscore::Field,
    dedup_closed: &mut Option<DedupClosed>,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + BodySlots + DedupSlots,
    T: DatagramIo,
{
    let role = engine
        .tx_body_transfer(id)
        .map(|t| t.role())
        .ok_or(Error::Block(BlockTransferError::NoTransfer))?;
    match role {
        BlockRole::OutgoingQBlock2 => {
            let transfer = engine
                .tx_body_transfer(id)
                .ok_or(Error::Block(BlockTransferError::NoTransfer))?;
            if transfer.identity().as_slice() != response.etag_bytes()
                || engine.tx_body_payload(id) != Some(response.payload())
            {
                return Err(Error::Block(BlockTransferError::IdentityMismatch));
            }
            if meta.q_block2.is_some_and(|q| q.szx() != transfer.szx()) {
                return Err(Error::Block(BlockTransferError::SzxMismatch));
            }
            match meta.q_block2 {
                Some(q)
                    if !q.more()
                        // NUM=0 requests the body, never acknowledges a set.
                        // Repeated Continue requests reselect an already issued
                        // set without acknowledging or advancing it again.
                        || q.num() <= transfer.window_base()
                        || meta
                            .q_request
                            .is_some_and(|p| p.q_block2().nth(1).is_some())
                        || q.num() % u32::from(crate::storage::BlockTransfer::MAX_PAYLOADS)
                            != 0 =>
                {
                    issue_q_selection(
                        engine,
                        io,
                        ids,
                        now_ms,
                        meta,
                        response,
                        ty,
                        id,
                        oscore_ctx,
                        dedup_closed,
                    )
                }
                Some(q) => {
                    engine.ack_q_block2(id, q.num()).map_err(Error::Block)?;
                    issue_q_window(
                        engine,
                        io,
                        ids,
                        now_ms,
                        meta,
                        response,
                        ty,
                        id,
                        oscore_ctx,
                        dedup_closed,
                    )
                }
                None => issue_q_window(
                    engine,
                    io,
                    ids,
                    now_ms,
                    meta,
                    response,
                    ty,
                    id,
                    oscore_ctx,
                    dedup_closed,
                ),
            }
        }
        BlockRole::OutgoingBlock2 => {
            let transfer = engine
                .tx_body_transfer(id)
                .ok_or(Error::Block(BlockTransferError::NoTransfer))?;
            if transfer.identity().as_slice() != response.etag_bytes()
                || engine.tx_body_payload(id) != Some(response.payload())
            {
                return Err(Error::Block(BlockTransferError::IdentityMismatch));
            }
            issue_classic(
                engine,
                io,
                meta,
                response,
                ty,
                meta.mid,
                id,
                None,
                true,
                Some((now_ms, dedup_closed)),
                oscore_ctx,
            )
        }
        _ => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn issue_classic<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    meta: SendResponse,
    response: &Response<'_>,
    ty: Type,
    mid: MessageId,
    id: SlotId,
    pending: Option<(u64, MessageId, u32)>,
    retain_incomplete: bool,
    replay: Option<(u64, &mut Option<DedupClosed>)>,
    oscore_ctx: &mut oscore::Field,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + BodySlots + DedupSlots,
    T: DatagramIo,
{
    let range = match meta.block2 {
        Some(requested) => engine.requested_block2(id, requested),
        None => engine.next_block2(id),
    };
    let issued = match range {
        Ok(issued) => issued,
        Err(BlockTransferError::Gap) => {
            let _ = engine.release_tx_body(id);
            let tx = engine.acquire_tx().ok_or(Error::Saturated)?;
            let error = Response::bad_request();
            if let Err(e) = encode_response(
                engine,
                tx,
                ty,
                mid,
                meta.token,
                &error,
                error.payload(),
                None,
                meta.block1,
                oscore_ctx,
                meta.oscore,
            ) {
                let _ = engine.release_tx(tx);
                return Err(e);
            }
            return finish_send(engine, io, tx, meta.dest, pending);
        }
        Err(e) => return Err(Error::Block(e)),
    };
    let tx = encode_issued::<S, T>(engine, meta, response, ty, mid, issued, false, oscore_ctx)?;
    let keep = if let Some((now_ms, closed)) = replay.filter(|_| ty == Type::Acknowledgement) {
        remember_tx_reply(
            engine,
            tx,
            meta.dest,
            mid,
            meta.ty,
            now_ms,
            meta.request,
            closed,
        )
    } else {
        KeepTx::No
    };
    let cached = engine
        .lookup_dedup(DedupKey::new(mid, meta.dest))
        .and_then(|row| engine.dedup_entry(row))
        .is_some_and(|row| row.tx_pin() == Some(tx) || row.replay().is_some());
    // Once the final reply is retained, retry uses those exact wire bytes and
    // bypasses this body path. Reclaim now even if the first send fails.
    if issued.complete() && cached {
        let _ = engine.release_tx_body(id);
    }
    match keep {
        KeepTx::Yes => send_pinned_tx(engine, io, tx, meta.dest),
        KeepTx::No => finish_send(engine, io, tx, meta.dest, pending),
    }?;
    // Ordinary classic requests reconstruct independent snapshots. Observe
    // snapshots survive every incomplete follow-up, whose response correctly
    // omits Observe, until the last block is sent or lifecycle cleanup runs.
    if issued.complete() || !retain_incomplete {
        let _ = engine.release_tx_body(id);
    }
    Ok(())
}

// RFC 9177 section 4.4: M=0 asks for exactly NUM; a non-aligned
// M=1 asks for NUM through the end of its MAX_PAYLOADS_SET. Reissuing
// selections never advances or acknowledges a retained transfer's window.
fn q_response_mid<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    ids: &mut AppIds,
    now_ms: u64,
    meta: SendResponse,
    first_ty: Type,
    dedup_closed: &mut Option<DedupClosed>,
) -> Result<MessageId, Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + DedupSlots,
    T: DatagramIo,
{
    if first_ty == Type::Acknowledgement {
        // Preflight has succeeded. Cache before I/O so duplicate protected
        // requests can retry the ACK without re-entering the handler.
        remember_empty_ack(
            engine,
            meta.dest,
            meta.mid,
            now_ms,
            meta.request,
            dedup_closed,
        );
        send_empty_ack(engine, io, meta.dest, meta.mid)?;
        ids.next_for(engine, now_ms)
    } else {
        Ok(meta.mid)
    }
}

#[allow(clippy::too_many_arguments)]
fn issue_q_selection<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    ids: &mut AppIds,
    now_ms: u64,
    meta: SendResponse,
    response: &Response<'_>,
    first_ty: Type,
    id: SlotId,
    oscore_ctx: &mut oscore::Field,
    dedup_closed: &mut Option<DedupClosed>,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + BodySlots + DedupSlots,
    T: DatagramIo,
{
    let selections = || meta.q_request.into_iter().flat_map(ParsedMessage::q_block2);
    // Validate every requested starting range before the first send, so a
    // bad later option cannot turn a rejected request into partial output.
    for q in selections() {
        let q = q.map_err(|e| Error::Block(e.into()))?;
        engine.reissue_q_block2(id, q.num()).map_err(Error::Block)?;
    }
    let mut last_sent = None;
    for q in selections() {
        let q = q.map_err(|e| Error::Block(e.into()))?;
        let count = if q.more() {
            u32::from(crate::storage::BlockTransfer::MAX_PAYLOADS)
                - q.num() % u32::from(crate::storage::BlockTransfer::MAX_PAYLOADS)
        } else {
            1
        };
        for offset in 0..count {
            let num = q.num() + offset;
            if last_sent.is_some_and(|last| num <= last) {
                continue;
            }
            let issued = engine.reissue_q_block2(id, num).map_err(Error::Block)?;
            let mid = if last_sent.is_none() {
                q_response_mid(engine, io, ids, now_ms, meta, first_ty, dedup_closed)?
            } else {
                ids.next_for(engine, now_ms)?
            };
            let ty = Type::NonConfirmable;
            send_issued(
                engine, io, meta, response, ty, mid, issued, true, None, oscore_ctx,
            )?;
            last_sent = Some(num);
            if !issued.block().more() {
                return Ok(());
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn issue_q_window<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    ids: &mut AppIds,
    now_ms: u64,
    meta: SendResponse,
    response: &Response<'_>,
    first_ty: Type,
    id: SlotId,
    oscore_ctx: &mut oscore::Field,
    dedup_closed: &mut Option<DedupClosed>,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + BodySlots + DedupSlots,
    T: DatagramIo,
{
    let mut extra = 0u16;
    loop {
        let issued = match engine.next_q_block2(id) {
            Ok(issued) => issued,
            Err(BlockTransferError::OutsideWindow) => return Ok(()),
            Err(e) => return Err(Error::Block(e)),
        };
        let mid = if extra == 0 {
            q_response_mid(engine, io, ids, now_ms, meta, first_ty, dedup_closed)?
        } else {
            ids.next_for(engine, now_ms)?
        };
        let ty = Type::NonConfirmable;
        send_issued(
            engine, io, meta, response, ty, mid, issued, true, None, oscore_ctx,
        )?;
        extra = extra.saturating_add(1);
        if issued.complete() {
            let _ = engine.release_tx_body(id);
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn send_issued<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    meta: SendResponse,
    response: &Response<'_>,
    ty: Type,
    mid: MessageId,
    issued: OutgoingBlock,
    q_block: bool,
    pending: Option<(u64, MessageId, u32)>,
    oscore_ctx: &mut oscore::Field,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + BodySlots + DedupSlots,
    T: DatagramIo,
{
    let tx = encode_issued::<S, T>(engine, meta, response, ty, mid, issued, q_block, oscore_ctx)?;
    finish_send(engine, io, tx, meta.dest, pending)
}

#[allow(clippy::too_many_arguments)]
fn encode_issued<S, T>(
    engine: &mut Engine<S>,
    meta: SendResponse,
    response: &Response<'_>,
    ty: Type,
    mid: MessageId,
    issued: OutgoingBlock,
    q_block: bool,
    oscore_ctx: &mut oscore::Field,
) -> Result<SlotId, Error<T::Error>>
where
    S: Storage + DatagramSlots + BodySlots + DedupSlots,
    T: DatagramIo,
{
    let mut chunk = [0u8; 1024];
    let n = copy_issued(engine, issued, &mut chunk).map_err(Error::Block)?;
    let size2 = if q_block {
        engine.tx_body_transfer(issued.id()).map(|t| t.filled())
    } else {
        None
    };
    let Some(tx) = acquire_tx_or_evict(engine) else {
        return Err(Error::Saturated);
    };
    let block = Some(BlockOpt {
        value: issued.block(),
        q_block,
        size2,
    });
    if let Err(e) = encode_response(
        engine,
        tx,
        ty,
        mid,
        meta.token,
        response,
        &chunk[..n],
        block,
        meta.block1,
        oscore_ctx,
        meta.oscore,
    ) {
        let _ = engine.release_tx(tx);
        return Err(e);
    }
    Ok(tx)
}

fn copy_issued<S: Storage + BodySlots>(
    engine: &Engine<S>,
    issued: OutgoingBlock,
    dest: &mut [u8],
) -> Result<usize, BlockTransferError> {
    let payload = engine
        .tx_body_payload(issued.id())
        .ok_or(BlockTransferError::NoTransfer)?;
    let end = issued
        .offset()
        .checked_add(issued.len())
        .ok_or(BlockTransferError::Overflow)?;
    if end > payload.len() || issued.len() > dest.len() {
        return Err(BlockTransferError::Overflow);
    }
    dest[..issued.len()].copy_from_slice(&payload[issued.offset()..end]);
    Ok(issued.len())
}

#[allow(clippy::too_many_arguments)]
fn encode_response<S: Storage + DatagramSlots, E>(
    engine: &mut Engine<S>,
    tx: SlotId,
    ty: Type,
    mid: MessageId,
    token: crate::message::Token,
    response: &Response<'_>,
    payload: &[u8],
    block: Option<BlockOpt>,
    block1: Option<BlockOpt>,
    oscore_ctx: &mut oscore::Field,
    oscore_req: oscore::Request,
) -> Result<(), Error<E>> {
    response.validate().map_err(Error::Response)?;
    let cf = response.format().map(crate::ContentFormat::encode);
    let max_age = response.max_age_secs().map(EncodedUint::new);
    let observe = response
        .observe_seq()
        .map(|seq| encode_uint(seq & 0x00ff_ffff));
    let block_enc = block.map(|b| b.value.encode());
    let size2_enc = block
        .and_then(|b| b.size2)
        .map(|n| encode_uint(u32::try_from(n).unwrap_or(u32::MAX)));
    let block1_enc = block1.map(|b| b.value.encode());
    let echo = response.echo_option();
    let mut opts = OptionsBuilder::<{ 8 + 2 * LOCATION_MAX }>::new();
    let filled = (|| -> Result<(), EncodeError> {
        if let Some(etag) = response.etag_bytes() {
            push_opt(&mut opts, Opt::etag(etag))?;
        }
        if let Some(ref encoded) = observe {
            push_opt(&mut opts, Opt::observe(encoded))?;
        }
        for segment in response.location_paths() {
            push_opt(&mut opts, Opt::location_path(segment))?;
        }
        if let Some(ref encoded) = cf {
            push_opt(&mut opts, Opt::content_format(encoded))?;
        }
        if let Some(ref encoded) = max_age {
            push_opt(&mut opts, Opt::max_age(encoded))?;
        }
        for query in response.location_queries() {
            push_opt(&mut opts, Opt::location_query(query))?;
        }
        if let Some(ref encoded) = block_enc {
            if block.is_some_and(|b| b.q_block) {
                if let Some(ref size2) = size2_enc {
                    push_opt(&mut opts, Opt::size2(size2))?;
                }
                push_opt(&mut opts, Opt::q_block2(encoded))?;
            } else {
                push_opt(&mut opts, Opt::block2(encoded))?;
            }
        }
        if let Some(ref encoded) = block1_enc {
            push_opt(
                &mut opts,
                if block1.is_some_and(|b| b.q_block) {
                    Opt::q_block1(encoded)
                } else {
                    Opt::block1(encoded)
                },
            )?;
        }
        if let Some(ref echo) = echo {
            push_opt(&mut opts, Opt::echo(echo.as_slice()))?;
        }
        Ok(())
    })();
    match filled {
        Ok(()) => {
            let msg = Message::new(ty, response.code(), mid)
                .with_token(token)
                .with_options(opts.as_slice())
                .with_payload(payload);
            if block.is_some_and(|b| b.q_block)
                || (response.observe_seq().is_some() && ty != Type::Acknowledgement)
            {
                oscore::encode_notification(oscore_ctx, oscore_req, engine, tx, &msg)
            } else {
                oscore::encode_message(oscore_ctx, oscore_req, engine, tx, &msg)
            }
        }
        Err(EncodeError::OptionsFull) => {
            encode_options_full_500(engine, tx, ty, mid, token, oscore_ctx, oscore_req)
        }
        Err(e) => Err(Error::Message(SlotMessageError::Encode(e))),
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_notification<S: Storage + DatagramSlots, E>(
    engine: &mut Engine<S>,
    tx: SlotId,
    ty: Type,
    mid: MessageId,
    token: crate::message::Token,
    response: &Response<'_>,
    payload: &[u8],
    oscore_ctx: &mut oscore::Field,
    oscore_req: oscore::Request,
) -> Result<(), Error<E>> {
    response.validate().map_err(Error::Response)?;
    let cf = response.format().map(crate::ContentFormat::encode);
    let max_age = response.max_age_secs().map(EncodedUint::new);
    let observe = response
        .observe_seq()
        .map(|seq| encode_uint(seq & 0x00ff_ffff));
    let mut opts = OptionsBuilder::<{ 8 + 2 * LOCATION_MAX }>::new();
    let filled = (|| -> Result<(), EncodeError> {
        if let Some(etag) = response.etag_bytes() {
            push_opt(&mut opts, Opt::etag(etag))?;
        }
        if let Some(ref encoded) = observe {
            push_opt(&mut opts, Opt::observe(encoded))?;
        }
        if let Some(ref encoded) = cf {
            push_opt(&mut opts, Opt::content_format(encoded))?;
        }
        if let Some(ref encoded) = max_age {
            push_opt(&mut opts, Opt::max_age(encoded))?;
        }
        Ok(())
    })();
    match filled {
        Ok(()) => {
            let msg = Message::new(ty, response.code(), mid)
                .with_token(token)
                .with_options(opts.as_slice())
                .with_payload(payload);
            oscore::encode_notification(oscore_ctx, oscore_req, engine, tx, &msg)
        }
        Err(EncodeError::OptionsFull) => {
            encode_options_full_500(engine, tx, ty, mid, token, oscore_ctx, oscore_req)
        }
        Err(e) => Err(Error::Message(SlotMessageError::Encode(e))),
    }
}

pub(crate) fn push_opt<'a, const N: usize>(
    opts: &mut OptionsBuilder<'a, N>,
    opt: Opt<'a>,
) -> Result<(), EncodeError> {
    opts.push(opt)
        .map(|_| ())
        .map_err(|_| EncodeError::OptionsFull)
}

/// 5.00 when the response option list cannot be built.
///
/// Under attached OSCORE this is OSCORE-protected. It must not fall back
/// to plaintext.
pub(crate) fn encode_options_full_500<S: Storage + DatagramSlots, E>(
    engine: &mut Engine<S>,
    tx: SlotId,
    ty: Type,
    mid: MessageId,
    token: crate::message::Token,
    oscore_ctx: &oscore::Field,
    oscore_req: oscore::Request,
) -> Result<(), Error<E>> {
    let response = Response::problem(Code::INTERNAL_SERVER_ERROR).title("Options full");
    response.validate().map_err(Error::Response)?;
    let cf = response.format().map(crate::ContentFormat::encode);
    let mut opts = OptionsBuilder::<4>::new();
    if let Some(ref encoded) = cf {
        push_opt(&mut opts, Opt::content_format(encoded))
            .map_err(|e| Error::Message(SlotMessageError::Encode(e)))?;
    }
    let msg = Message::new(ty, response.code(), mid)
        .with_token(token)
        .with_options(opts.as_slice())
        .with_payload(response.payload());
    oscore::encode_message(oscore_ctx, oscore_req, engine, tx, &msg)
}

enum Replay<E> {
    Hit(Result<(), Error<E>>),
    Miss,
}

enum KeepTx {
    Yes,
    No,
}

/// Last POST/PATCH/FETCH whose Dedup insert failed. Compact: one key.
#[derive(Clone, Copy)]
struct DedupClosed {
    key: DedupKey,
    due_ms: u64,
}

/// GET / PUT / DELETE / iPATCH may re-run when a live Dedup row has no
/// replay (RFC 7252 §4.5 MAY). POST / PATCH / FETCH never re-run.
fn request_may_rerun_on_duplicate(code: Code) -> bool {
    matches!(code, Code::GET | Code::PUT | Code::DELETE | Code::IPATCH)
}

fn replay_con_request<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    peer: Endpoint,
    parsed: &ParsedMessage<'_>,
    now_ms: u64,
    dedup_closed: &mut Option<DedupClosed>,
) -> Replay<T::Error>
where
    S: Storage + DatagramSlots + DedupSlots,
    T: DatagramIo,
{
    let key = DedupKey::new(parsed.message_id(), peer);
    let Some(id) = engine.lookup_dedup(key) else {
        return replay_closed(engine, io, peer, parsed, now_ms, dedup_closed);
    };
    let Some(entry) = engine.dedup_entry(id) else {
        return replay_closed(engine, io, peer, parsed, now_ms, dedup_closed);
    };
    if entry.due_ms() != 0 && now_ms >= entry.due_ms() {
        release_dedup_row(engine, entry);
        return replay_closed(engine, io, peer, parsed, now_ms, dedup_closed);
    }
    if let Some(bytes) = entry.replay() {
        return Replay::Hit(send_replay_bytes(engine, io, peer, bytes));
    }
    if let Some(tx) = entry.tx_pin() {
        return Replay::Hit(engine.send_tx(io, tx).map(|_| ()).map_err(Into::into));
    }
    if request_may_rerun_on_duplicate(parsed.code()) {
        Replay::Miss
    } else {
        // Never silent: ACK the CON so the client stops RTO. Persist the
        // empty ACK so a later Miss-after-lifetime is the only re-run path.
        remember_empty_ack(
            engine,
            peer,
            parsed.message_id(),
            now_ms,
            parsed.code(),
            dedup_closed,
        );
        Replay::Hit(send_empty_ack(engine, io, peer, parsed.message_id()))
    }
}

/// POST / PATCH / FETCH: insert failure after the first response is
/// fail-closed (empty ACK), not Miss.
fn replay_closed<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    peer: Endpoint,
    parsed: &ParsedMessage<'_>,
    now_ms: u64,
    dedup_closed: &mut Option<DedupClosed>,
) -> Replay<T::Error>
where
    S: Storage + DatagramSlots + DedupSlots,
    T: DatagramIo,
{
    if request_may_rerun_on_duplicate(parsed.code()) {
        return Replay::Miss;
    }
    let Some(closed) = *dedup_closed else {
        return Replay::Miss;
    };
    if closed.key != DedupKey::new(parsed.message_id(), peer) {
        return Replay::Miss;
    }
    if closed.due_ms != 0 && now_ms >= closed.due_ms {
        *dedup_closed = None;
        return Replay::Miss;
    }
    remember_empty_ack(
        engine,
        peer,
        parsed.message_id(),
        now_ms,
        parsed.code(),
        dedup_closed,
    );
    Replay::Hit(send_empty_ack(engine, io, peer, parsed.message_id()))
}

fn send_replay_bytes<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    dest: Endpoint,
    bytes: &[u8],
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + DedupSlots,
    T: DatagramIo,
{
    let Some(tx) = acquire_tx_or_evict(engine) else {
        return Err(Error::Saturated);
    };
    if let Err(e) = engine.write_tx(tx, bytes, dest) {
        let _ = engine.release_tx(tx);
        return Err(Error::Slot(e));
    }
    let send = engine.send_tx(io, tx);
    let _ = engine.release_tx(tx);
    send?;
    Ok(())
}

fn send_pinned_tx<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    tx: SlotId,
    dest: Endpoint,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots,
    T: DatagramIo,
{
    if let Err(e) = engine.set_tx_endpoint(tx, dest) {
        let _ = engine.release_tx(tx);
        return Err(Error::Slot(e));
    }
    engine.send_tx(io, tx)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn remember_tx_reply<S: Storage + DatagramSlots + DedupSlots>(
    engine: &mut Engine<S>,
    tx: SlotId,
    dest: Endpoint,
    mid: MessageId,
    request_ty: Type,
    now_ms: u64,
    request: Code,
    dedup_closed: &mut Option<DedupClosed>,
) -> KeepTx {
    if request_ty != Type::Confirmable {
        return KeepTx::No;
    }
    let due = dedup_due_ms(now_ms);
    let mut entry = DedupEntry::new(mid, dest).with_due_ms(due);
    let copied = {
        let Ok(access) = engine.access_tx(tx) else {
            remember_empty_ack(engine, dest, mid, now_ms, request, dedup_closed);
            return KeepTx::No;
        };
        let slice = access.as_bytes();
        if slice.len() > S::TX_DATAGRAM_BYTES {
            None
        } else {
            let mut buf = S::TxScratch::default();
            buf.as_mut()[..slice.len()].copy_from_slice(slice);
            Some((buf, slice.len()))
        }
    };
    let Some((buf, n)) = copied else {
        return if note_dedup_store(engine, entry.with_tx_pin(tx), request, dedup_closed) {
            KeepTx::Yes
        } else {
            KeepTx::No
        };
    };
    if n <= DedupEntry::REPLAY_MAX {
        entry = entry.with_replay(&buf.as_ref()[..n]);
        let _ = note_dedup_store(engine, entry, request, dedup_closed);
        KeepTx::No
    } else if note_dedup_store(engine, entry.with_tx_pin(tx), request, dedup_closed) {
        KeepTx::Yes
    } else {
        KeepTx::No
    }
}

fn remember_empty_ack<S: Storage + DedupSlots>(
    engine: &mut Engine<S>,
    dest: Endpoint,
    mid: MessageId,
    now_ms: u64,
    request: Code,
    dedup_closed: &mut Option<DedupClosed>,
) {
    let mut buf = [0u8; 16];
    let Ok(n) = encode(&Message::empty_ack(mid), &mut buf) else {
        if !request_may_rerun_on_duplicate(request)
            && dedup_closed
                .as_ref()
                .is_none_or(|c| c.key != DedupKey::new(mid, dest))
        {
            *dedup_closed = Some(DedupClosed {
                key: DedupKey::new(mid, dest),
                due_ms: dedup_due_ms(now_ms),
            });
        }
        return;
    };
    let _ = note_dedup_store(
        engine,
        DedupEntry::new(mid, dest)
            .with_due_ms(dedup_due_ms(now_ms))
            .with_replay(&buf[..n]),
        request,
        dedup_closed,
    );
}

fn note_dedup_store<S: Storage + DedupSlots>(
    engine: &mut Engine<S>,
    entry: DedupEntry,
    request: Code,
    dedup_closed: &mut Option<DedupClosed>,
) -> bool {
    let key = entry.key();
    let due_ms = entry.due_ms();
    if store_request_dedup(engine, entry) {
        if dedup_closed.as_ref().is_some_and(|c| c.key == key) {
            *dedup_closed = None;
        }
        true
    } else {
        if !request_may_rerun_on_duplicate(request) {
            let already = dedup_closed.as_ref().is_some_and(|c| c.key == key);
            if !already {
                *dedup_closed = Some(DedupClosed { key, due_ms });
            }
        }
        false
    }
}

fn store_request_dedup<S: Storage + DedupSlots>(engine: &mut Engine<S>, entry: DedupEntry) -> bool {
    if !entry.has_usable_replay() {
        return false;
    }
    release_existing_dedup(engine, entry.key());
    if engine.insert_dedup(entry).is_some() {
        return true;
    }
    evict_oldest_app_dedup(engine) && engine.insert_dedup(entry).is_some()
}

fn release_existing_dedup<S: Storage + DedupSlots>(engine: &mut Engine<S>, key: DedupKey) {
    let Some(id) = engine.lookup_dedup(key) else {
        return;
    };
    if let Some(old) = engine.dedup_entry(id) {
        release_dedup_row(engine, old);
    } else {
        let _ = engine.remove_dedup(key);
    }
}

fn release_dedup_row<S: Storage + DedupSlots>(engine: &mut Engine<S>, entry: DedupEntry) {
    if let Some(pin) = entry.tx_pin() {
        let _ = engine.release_tx(pin);
    }
    let _ = engine.remove_dedup(entry.key());
}

fn dedup_due_ms(now_ms: u64) -> u64 {
    now_ms.saturating_add(u64::from(Transmission::EXCHANGE_LIFETIME_MS))
}

fn expire_request_dedup<S: Storage + DedupSlots>(
    engine: &mut Engine<S>,
    dedup_closed: &mut Option<DedupClosed>,
    now_ms: u64,
) {
    if let Some(closed) = *dedup_closed {
        if closed.due_ms != 0 && now_ms >= closed.due_ms {
            *dedup_closed = None;
        }
    }
    if engine.storage_mut().dedup().is_empty() {
        return;
    }
    let n = engine.capacities().dedup_entries;
    for i in 0..n {
        let Some(entry) = engine.dedup_entry(SlotId::from_index(i)) else {
            continue;
        };
        if entry.due_ms() != 0 && now_ms >= entry.due_ms() {
            release_dedup_row(engine, entry);
        }
    }
}

fn acquire_tx_or_evict<S: Storage + DatagramSlots + DedupSlots>(
    engine: &mut Engine<S>,
) -> Option<SlotId> {
    // This actor owns the pool. Reclaim an evictable reply before attempting
    // admission so a successful cache eviction is not counted as saturation.
    // A genuinely full pool still makes exactly one failing acquisition.
    if engine.tx_occupied() == engine.capacities().tx_datagram_slots {
        let _ = evict_one_dedup_pin(engine);
    }
    engine.acquire_tx()
}

fn evict_one_dedup_pin<S: Storage + DedupSlots>(engine: &mut Engine<S>) -> bool {
    let n = engine.capacities().dedup_entries;
    let mut best: Option<DedupEntry> = None;
    for i in 0..n {
        let Some(entry) = engine.dedup_entry(SlotId::from_index(i)) else {
            continue;
        };
        if entry.tx_pin().is_none() || entry.due_ms() == 0 {
            continue;
        }
        match best {
            Some(cur) if entry.due_ms() >= cur.due_ms() => {}
            _ => best = Some(entry),
        }
    }
    let Some(entry) = best else {
        return false;
    };
    if let Some(pin) = entry.tx_pin() {
        let _ = engine.release_tx(pin);
    }
    let _ = engine.remove_dedup(entry.key());
    let mut buf = [0u8; 16];
    if let Ok(n) = encode(&Message::empty_ack(entry.message_id()), &mut buf) {
        let row = DedupEntry::new(entry.message_id(), entry.endpoint())
            .with_due_ms(entry.due_ms())
            .with_replay(&buf[..n]);
        let _ = engine.insert_dedup(row);
    }
    true
}

fn evict_oldest_app_dedup<S: Storage + DedupSlots>(engine: &mut Engine<S>) -> bool {
    let n = engine.capacities().dedup_entries;
    let mut best: Option<DedupEntry> = None;
    for i in 0..n {
        let Some(entry) = engine.dedup_entry(SlotId::from_index(i)) else {
            continue;
        };
        if entry.due_ms() == 0 {
            continue;
        }
        match best {
            Some(cur) if entry.due_ms() >= cur.due_ms() => {}
            _ => best = Some(entry),
        }
    }
    let Some(entry) = best else {
        return false;
    };
    release_dedup_row(engine, entry);
    true
}

/// Send occupied TX `tx` to `dest`.
///
/// When `pending` is `Some`, admit the CON into the pending table **before**
/// `send_tx` so a second CON to the same peer cannot occupy TX without RTO
/// ([`Transmission::NSTART`](crate::message::Transmission::NSTART)). `None`
/// from [`Engine::record_pending_con`](Engine::record_pending_con) releases
/// the slot and returns [`Error::Saturated`]. An IO failure after admit
/// takes the pending mark and releases TX.
pub(crate) fn finish_send<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    tx: SlotId,
    dest: Endpoint,
    pending: Option<(u64, MessageId, u32)>,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons,
    T: DatagramIo,
{
    if let Err(e) = engine.set_tx_endpoint(tx, dest) {
        let _ = engine.release_tx(tx);
        return Err(Error::Slot(e));
    }
    if let Some((now_ms, mid, jitter)) = pending {
        if engine
            .record_pending_con(tx, dest, mid, now_ms, jitter)
            .is_none()
        {
            let _ = engine.release_tx(tx);
            return Err(Error::Saturated);
        }
        match engine.send_tx(io, tx) {
            Ok(_) => Ok(()),
            Err(e) => {
                let _ = engine.take_pending_con(mid, dest);
                let _ = engine.release_tx(tx);
                Err(e.into())
            }
        }
    } else {
        let send = engine.send_tx(io, tx);
        let _ = engine.release_tx(tx);
        send?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn oscore_inbound_error<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    ids: &mut AppIds,
    parsed: &crate::message::ParsedMessage<'_>,
    peer: Endpoint,
    now_ms: u64,
    err: oscore::InboundError,
    dedup_closed: &mut Option<DedupClosed>,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots + PendingCons + BodySlots + DedupSlots,
    T: DatagramIo,
{
    #[cfg(feature = "oscore")]
    {
        // AEAD / replay / OSCORE-option processing: silent drop (no 4.00
        // decrypt oracle). A response is never answered. Only a *plain*
        // request (no OSCORE option) while a context is attached is 4.01.
        if !parsed.code().is_request() || parsed.oscore().is_some() {
            return Ok(());
        }
        let _ = err;
        let meta = SendResponse {
            dest: peer,
            ty: parsed.ty(),
            mid: parsed.message_id(),
            token: parsed.token(),
            no_response: NoResponse::DEFAULT,
            block2: None,
            q_block2: None,
            q_request: None,
            block1: None,
            oscore: oscore::no_request(),
            request: parsed.code(),
        };
        send_response(
            engine,
            io,
            ids,
            meta,
            // Unprotected OSCORE processing error: Max-Age 0 so a
            // cacheable 4.01 does not stick in intermediaries
            // (`knowledge/rfcs/rfc8613.txt` §8.2 / §4.1.3.1).
            &Response::problem(Code::UNAUTHORIZED)
                .title("Unauthorized")
                .max_age(0),
            now_ms,
            &mut oscore::empty_field(),
            dedup_closed,
        )
    }
    #[cfg(not(feature = "oscore"))]
    {
        let _ = (engine, io, ids, parsed, peer, now_ms, err, dedup_closed);
        Ok(())
    }
}

fn unauthorized_echo(decision: EchoDecision) -> Response<'static> {
    let response = Response::problem(Code::UNAUTHORIZED)
        .title("Unauthorized")
        .max_age(0);
    match decision {
        EchoDecision::Challenge(challenge) => response.echo(challenge),
        EchoDecision::Reject | EchoDecision::Accept => response,
    }
}

fn szx_for(block2: Option<BlockValue>, q_block2: Option<BlockValue>) -> u8 {
    match q_block2.or(block2) {
        Some(block) if !block.is_bert() => block.szx(),
        _ => BlockValue::SZX_MAX,
    }
}

#[derive(Clone, Copy)]
struct BlockOpt {
    value: BlockValue,
    q_block: bool,
    size2: Option<usize>,
}

#[derive(Clone, Copy)]
struct SendResponse<'a> {
    dest: Endpoint,
    ty: Type,
    mid: MessageId,
    token: crate::message::Token,
    no_response: NoResponse,
    block2: Option<BlockValue>,
    q_block2: Option<BlockValue>,
    q_request: Option<ParsedMessage<'a>>,
    /// Echo of the request Block1 (RFC 7959 §2.5 Continue / final).
    block1: Option<BlockOpt>,
    /// Request Partial IV when the inbound request was OSCORE-protected.
    oscore: oscore::Request,
    /// Inbound request code (Dedup fail-closed for POST / PATCH / FETCH).
    request: Code,
}

fn copy_rx<S: Storage + DatagramSlots, E>(
    engine: &mut Engine<S>,
    rx: SlotId,
    dest: &mut [u8],
) -> Result<usize, Error<E>> {
    let access = engine.access_rx(rx)?;
    let src = access.as_bytes();
    if src.len() > dest.len() {
        return Err(Error::Message(SlotMessageError::Slot(
            SlotError::LengthExceedsSlot,
        )));
    }
    dest[..src.len()].copy_from_slice(src);
    Ok(src.len())
}

pub(crate) fn send_empty_ack<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    dest: Endpoint,
    mid: crate::message::MessageId,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots,
    T: DatagramIo,
{
    send_empty(engine, io, dest, Message::empty_ack(mid))
}

fn send_empty_rst<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    dest: Endpoint,
    mid: crate::message::MessageId,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots,
    T: DatagramIo,
{
    send_empty(engine, io, dest, Message::empty_rst(mid))
}

fn send_empty<S, T>(
    engine: &mut Engine<S>,
    io: &mut T,
    dest: Endpoint,
    msg: Message<'static>,
) -> Result<(), Error<T::Error>>
where
    S: Storage + DatagramSlots,
    T: DatagramIo,
{
    let Some(tx) = engine.acquire_tx() else {
        return Err(Error::Saturated);
    };
    if let Err(e) = engine.encode_tx(tx, &msg) {
        let _ = engine.release_tx(tx);
        return Err(Error::Message(e));
    }
    if let Err(e) = engine.set_tx_endpoint(tx, dest) {
        let _ = engine.release_tx(tx);
        return Err(Error::Slot(e));
    }
    let send = engine.send_tx(io, tx);
    let _ = engine.release_tx(tx);
    send?;
    Ok(())
}

/// Failure of [`App::poll`] or [`Outgoing::send`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error<E> {
    /// Fresh identity or randomized transmission schedule could not be obtained.
    Identity(IdentityError),
    /// Handler/notification response contains an invalid bounded option.
    Response(ResponseError),
    /// Absolute caller deadline has already elapsed; no request was sent.
    DeadlineElapsed,
    /// [`Engine::recv_from`] / [`Engine::send_tx`].
    Io(DatagramIoError<E>),
    /// Slot addressing or fill.
    Slot(SlotError),
    /// Decode / encode in a slot.
    Message(SlotMessageError),
    /// TX pool, client inbox, or outstanding Call table is full.
    Saturated,
    /// Block / Q-Block body start, issue, or recover encode failed.
    Block(BlockTransferError),
    /// Uri-Path has more than [`MAX_PATH_SEGMENTS`] segments.
    Path,
    /// The payload requires fragmentation, but App cannot retain its ETag,
    /// If-Match or If-None-Match semantics. Nothing has been sent. Use a payload
    /// fitting one datagram or construct a conditional transfer with [`Engine`].
    ConditionalUploadUnsupported,
    /// No-Response cannot be preserved by App's fragmented upload handshake.
    /// Nothing was sent; use a single datagram or caller-managed Engine transfer.
    NoResponseUploadUnsupported,
    /// App requires a response when registering Observe. Deregistration is allowed.
    NoResponseObserveUnsupported,
    /// No live subscription matches the cancellation's request identity/Call.
    ObserveCancellationMismatch,
    /// No live subscription matches the refresh request identity and Call.
    ObserveRefreshMismatch,
    /// Observe registration/cancellation is defined only for GET and FETCH.
    ObserveMethodUnsupported,
    /// Multiple subscriptions match; select one with `deregister_call`.
    ObserveCancellationAmbiguous,
    /// Observe request identity exceeds the App's 512 encoded-byte bound.
    ObserveRequestTooLarge,
    /// FETCH selection identity exceeds 512 encoded bytes. Nothing was sent;
    /// use a smaller selection or retain the request with the advanced Engine.
    FetchRequestTooLarge,
    /// RFC 8132 requires Content-Format on FETCH, even with an empty payload.
    /// Nothing was sent; select the format that describes the selection body.
    FetchContentFormatRequired,
    /// RFC 9177 requires a present Request-Tag for Q-Block1.
    RequestTagRequired,
    /// Another live operation at this peer already owns this Request-Tag.
    RequestTagInUse,
    /// OSCORE protect / unprotect failed (feature `oscore`).
    #[cfg(feature = "oscore")]
    Oscore(crate::oscore::Error),
}

impl<E> From<DatagramIoError<E>> for Error<E> {
    fn from(e: DatagramIoError<E>) -> Self {
        match e {
            DatagramIoError::Saturated => Self::Saturated,
            other => Self::Io(other),
        }
    }
}

impl<E> From<SlotError> for Error<E> {
    fn from(e: SlotError) -> Self {
        Self::Slot(e)
    }
}

impl<E> From<SlotMessageError> for Error<E> {
    fn from(e: SlotMessageError) -> Self {
        match e {
            SlotMessageError::Slot(slot) => Self::Slot(slot),
            other => Self::Message(other),
        }
    }
}

impl<E> core::fmt::Display for Error<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Identity(error) => write!(f, "{error}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Slot(e) => write!(f, "{e}"),
            Self::Message(e) => write!(f, "{e}"),
            Self::Response(error) => write!(f, "{error}"),
            Self::DeadlineElapsed => f.write_str("call deadline already elapsed"),
            Self::Saturated => f.write_str("a bounded table is saturated"),
            Self::Block(e) => write!(f, "{e}"),
            Self::Path => f.write_str("uri-path has too many segments"),
            Self::ObserveMethodUnsupported => f.write_str("Observe requires GET or FETCH"),
            Self::ObserveRefreshMismatch => {
                f.write_str("Observe refresh does not match a live subscription")
            }
            Self::ObserveCancellationMismatch => {
                f.write_str("Observe cancellation does not match a live request")
            }
            Self::ObserveCancellationAmbiguous => {
                f.write_str("Observe cancellation requires an explicit Call")
            }
            Self::ObserveRequestTooLarge => {
                f.write_str("Observe request identity exceeds 512 bytes")
            }
            Self::FetchContentFormatRequired => f.write_str("FETCH requires Content-Format"),
            Self::FetchRequestTooLarge => f.write_str("FETCH request identity exceeds 512 bytes"),
            Self::RequestTagRequired => f.write_str("Q-Block1 requires a Request-Tag"),
            Self::RequestTagInUse => f.write_str("Request-Tag already in use at this peer"),
            Self::NoResponseUploadUnsupported => {
                f.write_str("No-Response fragmented uploads are unsupported")
            }
            Self::NoResponseObserveUnsupported => {
                f.write_str("No-Response Observe registration is unsupported")
            }
            Self::ConditionalUploadUnsupported => {
                f.write_str("conditional fragmented uploads are unsupported")
            }
            #[cfg(feature = "oscore")]
            Self::Oscore(e) => write!(f, "{e}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for Error<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            Self::Io(e) => Some(e),
            Self::Slot(e) => Some(e),
            Self::Message(e) => Some(e),
            Self::Saturated | Self::DeadlineElapsed => None,
            Self::Block(e) => Some(e),
            Self::Response(e) => Some(e),
            Self::Path
            | Self::ConditionalUploadUnsupported
            | Self::NoResponseUploadUnsupported
            | Self::NoResponseObserveUnsupported
            | Self::ObserveMethodUnsupported
            | Self::ObserveRefreshMismatch
            | Self::ObserveCancellationMismatch
            | Self::ObserveCancellationAmbiguous
            | Self::FetchContentFormatRequired
            | Self::FetchRequestTooLarge
            | Self::ObserveRequestTooLarge
            | Self::RequestTagRequired
            | Self::RequestTagInUse => None,
            #[cfg(feature = "oscore")]
            Self::Oscore(e) => Some(e),
        }
    }
}
