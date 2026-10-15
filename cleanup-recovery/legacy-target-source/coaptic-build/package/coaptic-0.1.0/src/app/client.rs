//! Outbound App request: encode TX, match Token + peer, take a [`Response`].
//!
//! ```text
//! Outgoing --encode--> TX slot
//! poll matches Token + endpoint
//! take_response returns Some(Ok(remote)) or Some(Err(local failure))
//! RX --copy--> Response::payload  (non-Block: min(len, INLINE_PAYLOAD) = 128)
//! Block2 / Q-Block2 --apply--> RX body --copy--> Response::body()  (RESPONSE_BODY)
//! ```
//!
//! A 200-byte piggybacked 2.05 with [`.block_wise::<false>()`](super::AppBuilder::block_wise)
//! copies 128 bytes into [`Response::payload`]. Check
//! [`Response::payload_truncated`]. The full assembled representation is
//! [`Response::body`], not a 4KiB field on [`Response`].
//!
//! App holds at most four live client requests, including Observe
//! subscriptions and replies waiting for `take_response`. Resource-specific
//! profile limits can be lower. Exhaustion returns `Error::Saturated`.
//! Upload continuation and cleanup select request-body roles separately from
//! server response bodies, even at identical peer/Token/tag keys.
//! Each live call retains up to 256 URI-query bytes plus lengths for Block2
//! continuation identity. This bounded state adds about 1.1 KiB per App on
//! 64-bit hosts; it is separate from the optional assembled-body storage.
//! Unknown critical response options reject the response (RST for CON);
//! unknown elective options are retained in `Response::received_options`.
//! New Observe representations retain their initial Content-Format, including
//! absence. A fresh changed/malformed format terminates the Call with
//! `CallFailure::ObserveFormatMismatch` (RST for CON); stale representations do
//! not change this state. A 2.03 validation may omit Content-Format.
//! A matching ACK still stops retries. Replies retain at most 24 options and
//! 512 encoded header/Token/option bytes, with at most eight Location-Path and
//! eight Location-Query values. Overflow completes the call with
//! `CallFailure::ResponseMetadataBounds`, never a partial metadata snapshot.
//! Four reply rows plus one borrowed-response hold each contain a fixed
//! 512-byte header buffer. No allocation or additional assembled-body buffer
//! is used for metadata.
//!
//! [`Call`] is Token plus peer — not a [`SlotId`](crate::storage::SlotId).
//! [`App::poll`](super::App::poll) advances this alongside site routing on
//! the same socket. Continues reuse the path recorded at
//! [`Outgoing::send`]. Observe subscribe ([`Outgoing::observe`]) keeps the
//! same [`Call`] after the Exchange is cleared.
//! FETCH retains its encoded selection request (at most 512 bytes excluding
//! Token, Observe and ETag) in the existing per-call identity buffer. Block2
//! and Q-Block2 follow-ups preserve its body, Content-Format and conditions.
//! Download follow-ups retain If-Match, If-None-Match and Content-Format.
//! Classic Block2 also retains request ETag; Q-Block2 omits it to request
//! payloads instead of cache-validation responses. Two retained 8-byte tags
//! and their presence/condition flags cost at most 96 bytes across four Calls
//! including host alignment.
//! Larger FETCH requests return [`Error::FetchRequestTooLarge`] before I/O;
//! use caller-managed Engine transfers for larger selection bodies.

use crate::error::{BlockTransferError, EncodeError, SlotMessageError};
use crate::message::{
    BlockValue, Code, ContentFormat, Message, MessageId, Opt, OptionsBuilder, ParsedMessage, Token,
    Transmission, Type, encode_uint,
};
use crate::storage::{
    BlockKey, BlockRole, BodySlots, BodyTag, DatagramIo, DatagramSlots, Endpoint, Engine,
    ExchangeEntry, ExchangeKey, Exchanges, MemoryLayout, Missing, ObserveInterest, ObserveKey,
    ObserveSlots, OutgoingBlock, PendingCons, Present, SlotId, Storage,
};

use super::identity::AppIds;
use super::request::{IntoPath, MAX_PATH_SEGMENTS, Path, PathError, path_from_into};
use super::response::{AppAssembled, INLINE_PAYLOAD, Response};
use super::{App, Error, Method, push_opt};

/// Option slots for an outbound request (path + query + Table 4 extras).
const CLIENT_OPTION_SLOTS: usize = 10 + 2 * MAX_PATH_SEGMENTS;

/// Outstanding client exchange (Token + destination).
///
/// Identity for [`App::take_response`](super::App::take_response) and
/// [`App::cancel`](super::App::cancel). Not a
/// slot. After [`Outgoing::observe`], the same `Call` yields the initial
/// representation and later notifications.
///
/// Non-Block [`Response::payload`] is at most
/// [`INLINE_PAYLOAD`](super::INLINE_PAYLOAD) (128) bytes — see
/// [`Response::payload_truncated`]. Assembled Block2 is
/// [`Response::body`].
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
/// let peer = Endpoint::v4([192, 0, 2, 2], 5683);
/// let call = app.get("sensors/temp").to(peer).send(0).unwrap();
/// app.poll(0).unwrap();
/// let response = app.take_response(call);
/// # let _ = response;
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Call {
    token: Token,
    peer: Endpoint,
}

impl Call {
    pub(crate) const fn new(token: Token, peer: Endpoint) -> Self {
        Self { token, peer }
    }

    /// Token sent on the request (and expected on the response).
    #[must_use]
    pub const fn token(self) -> Token {
        self.token
    }

    /// Destination of the request / source of the matched response.
    #[must_use]
    pub const fn peer(self) -> Endpoint {
        self.peer
    }
}

/// Local terminal outcome of a client call, distinct from a remote CoAP response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallFailure {
    /// Caller cancelled this call locally (no deregistration is sent).
    Cancelled,
    /// Explicit cancellation could not be sent; local subscription is retired.
    CancellationFailed,
    /// Re-registration could not be sent; local subscription is retired.
    ReregistrationFailed,
    /// A new Observe representation changes or malforms its established format.
    ObserveFormatMismatch,
    /// A block continuation could not be sent. Poll returns the detailed error;
    /// the call is retired locally and remote effects remain uncertain.
    ContinuationFailed,
    /// Caller-supplied absolute deadline was reached.
    DeadlineExceeded,
    /// Retransmissions or the response lifetime were exhausted.
    TimedOut,
    /// Peer rejected the exchange with an empty Reset.
    Reset,
    /// Received blocks could not be assembled into the requested representation.
    BlockTransfer(BlockTransferError),
    /// Response metadata exceeds App's option count, byte, or Location count bound.
    ResponseMetadataBounds,
    /// Complete block representation exceeds App's fixed assembled-response hold.
    ResponseBodyBounds,
}
impl core::fmt::Display for CallFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("call cancelled"),
            Self::CancellationFailed => f.write_str("Observe cancellation send failed"),
            Self::ReregistrationFailed => f.write_str("Observe re-registration send failed"),
            Self::ObserveFormatMismatch => f.write_str("Observe notification format mismatch"),
            Self::ContinuationFailed => f.write_str("block continuation send failed"),
            Self::DeadlineExceeded => f.write_str("call deadline exceeded"),
            Self::TimedOut => f.write_str("request timed out"),
            Self::Reset => f.write_str("peer reset the request"),
            Self::ResponseMetadataBounds => f.write_str("response metadata exceeds App bounds"),
            Self::ResponseBodyBounds => f.write_str("response body exceeds App bounds"),
            Self::BlockTransfer(error) => write!(f, "response block transfer failed: {error}"),
        }
    }
}
#[cfg(feature = "std")]
impl std::error::Error for CallFailure {}

/// How many outstanding client [`Call`]s [`App`](super::App) holds.
///
/// Caps both the completed-reply inbox and the live-request table. A fifth
/// [`Outgoing::send`] without [`App::take_response`](super::App::take_response)
/// is [`Error::Saturated`] — no silent eviction.
pub(crate) const RESPONSE_INBOX: usize = 4;

/// Maximum options retained per client response, including unknown elective options.
pub const RESPONSE_OPTION_COUNT: usize = 24;
/// Maximum encoded header, Token and options retained per client response (no payload).
pub const RESPONSE_OPTION_BYTES: usize = 512;

/// Maximum canonical Observe request bytes retained per live Call for exact
/// cancellation matching, including a fixed four-byte header and payload.
/// Four App Call slots each reserve this space plus bounded length metadata.
/// Observe and ETag options are excluded; no hash replaces exact comparison.
pub const OBSERVE_REQUEST_BYTES: usize = 512;

#[derive(Clone, Copy, Debug)]
struct ReplyMeta {
    received_at_ms: u64,
    header: [u8; RESPONSE_OPTION_BYTES],
    header_len: u16,
    peer: Endpoint,
    payload: [u8; INLINE_PAYLOAD],
    payload_len: u16,
    payload_src_len: u16,
}

impl ReplyMeta {
    fn from_parsed(
        parsed: &ParsedMessage<'_>,
        peer: Endpoint,
        received_at_ms: u64,
    ) -> Result<Self, CallFailure> {
        let mut options = OptionsBuilder::<RESPONSE_OPTION_COUNT>::new();
        let mut locations = [0usize; 2];
        for option in parsed.options() {
            let index = match option.number() {
                crate::message::OptionNumber::LOCATION_PATH => Some(0),
                crate::message::OptionNumber::LOCATION_QUERY => Some(1),
                _ => None,
            };
            if let Some(index) = index {
                locations[index] += 1;
                if locations[index] > super::LOCATION_MAX {
                    return Err(CallFailure::ResponseMetadataBounds);
                }
            }
            options
                .push(option)
                .map_err(|_| CallFailure::ResponseMetadataBounds)?;
        }
        let message = Message::new(parsed.ty(), parsed.code(), parsed.message_id())
            .with_token(parsed.token())
            .with_options(options.as_slice());
        let mut header = [0; RESPONSE_OPTION_BYTES];
        let header_len = crate::message::encode(&message, &mut header)
            .map_err(|_| CallFailure::ResponseMetadataBounds)?;
        let src = parsed.payload();
        let n = src.len().min(INLINE_PAYLOAD);
        let mut payload = [0u8; INLINE_PAYLOAD];
        payload[..n].copy_from_slice(&src[..n]);
        Ok(Self {
            received_at_ms,
            header,
            header_len: header_len as u16,
            peer,
            payload,
            payload_len: n as u16,
            payload_src_len: u16::try_from(src.len()).unwrap_or(u16::MAX),
        })
    }

    fn response(&self) -> Response<'_> {
        // The stored header was produced by the encoder and is immutable.
        let parsed = crate::message::decode(&self.header[..usize::from(self.header_len)])
            .expect("encoded response header");
        let mut response = Response::from_client(
            parsed.code(),
            parsed.ty(),
            parsed.token(),
            parsed.message_id(),
            self.peer,
            &self.payload[..usize::from(self.payload_len)],
            parsed.content_format().and_then(Result::ok),
        )
        .with_payload_src_len(self.payload_src_len);
        if let Some(etag) = parsed
            .etag()
            .next()
            .filter(|tag| (1..=8).contains(&tag.len()))
        {
            response = response.etag(etag);
        }
        if let Some(seq) = parsed.observe().and_then(Result::ok) {
            response = response.observe(seq);
        }
        if let Some(age) = parsed.max_age().and_then(Result::ok) {
            response = response.max_age(age);
        }
        if let Ok(Some(echo)) = crate::message::Echo::from_message(&parsed) {
            response = response.echo(echo);
        }
        for path in parsed.location_path().flatten() {
            if path.len() <= 255 && path != "." && path != ".." {
                response = response.location_path(path);
            }
        }
        for query in parsed.location_query().flatten() {
            if query.len() <= 255 {
                response = response.location_query(query);
            }
        }
        response.with_received_header(parsed, self.received_at_ms)
    }
}

#[derive(Clone, Copy, Debug)]
struct InboxRow {
    complete: bool,
    call: Call,
    meta: Result<ReplyMeta, CallFailure>,
    body: Option<SlotId>,
}

/// Bounded completed-reply table (not a seventh memory area).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClientInbox {
    rows: [Option<InboxRow>; RESPONSE_INBOX],
    held: Option<ReplyMeta>,
}

impl ClientInbox {
    pub(crate) const fn new() -> Self {
        Self {
            rows: [None; RESPONSE_INBOX],
            held: None,
        }
    }

    /// Store a completed reply. Same [`Call`] overwrites (Observe).
    ///
    /// Returns the previous body slot to release. `Err` if every row is a
    /// different Call — caller must not evict an untaken reply.
    fn insert(
        &mut self,
        call: Call,
        meta: Result<ReplyMeta, CallFailure>,
        body: Option<SlotId>,
    ) -> Result<Option<SlotId>, ()> {
        if let Some(slot) = self.rows.iter_mut().find(|row| {
            row.as_ref()
                .is_some_and(|row| row.call.token == call.token && row.call.peer == call.peer)
        }) {
            let prev = slot.take().and_then(|row| row.body);
            *slot = Some(InboxRow {
                complete: true,
                call,
                meta,
                body,
            });
            return Ok(prev);
        }
        if let Some(slot) = self.rows.iter_mut().find(|row| row.is_none()) {
            *slot = Some(InboxRow {
                complete: true,
                call,
                meta,
                body,
            });
            return Ok(None);
        }
        Err(())
    }

    fn discard(&mut self, call: Call) {
        for row in &mut self.rows {
            if row.as_ref().is_some_and(|row| row.call == call) {
                *row = None;
            }
        }
    }

    fn contains(&self, call: Call) -> bool {
        self.rows
            .iter()
            .flatten()
            .any(|row| row.call == call && row.complete)
    }
    fn partial_meta(&self, call: Call, body: SlotId) -> Option<ReplyMeta> {
        self.rows
            .iter()
            .flatten()
            .find(|row| row.call == call && !row.complete && row.body == Some(body))?
            .meta
            .ok()
    }

    fn retain_partial(
        &mut self,
        call: Call,
        meta: ReplyMeta,
        body: SlotId,
    ) -> Result<Option<SlotId>, ()> {
        if self.partial_meta(call, body).is_some() {
            return Ok(None);
        }
        let previous = self.insert(call, Ok(meta), Some(body))?;
        if let Some(row) = self.rows.iter_mut().flatten().find(|row| row.call == call) {
            row.complete = false;
        }
        Ok(previous)
    }

    fn take(&mut self, call: Call) -> Option<(Result<Response<'_>, CallFailure>, Option<SlotId>)> {
        let i = self.rows.iter().position(|row| {
            row.as_ref().is_some_and(|row| {
                row.complete && row.call.token == call.token && row.call.peer == call.peer
            })
        })?;
        let row = self.rows[i].take()?;
        let response = match row.meta {
            Ok(meta) => {
                self.held = Some(meta);
                Ok(self.held.as_ref().expect("stored reply").response())
            }
            Err(error) => {
                self.held = None;
                Err(error)
            }
        };
        Some((response, row.body))
    }
}

/// Owned query values retained across Block2 requests, in original order.
#[derive(Clone, Copy, Debug)]
struct RetainedQueries {
    bytes: [u8; 256],
    lengths: [u16; MAX_PATH_SEGMENTS],
    count: usize,
}

impl RetainedQueries {
    fn new(queries: &[&str]) -> Result<Self, EncodeError> {
        let mut retained = Self {
            bytes: [0; 256],
            lengths: [0; MAX_PATH_SEGMENTS],
            count: queries.len(),
        };
        if queries.len() > MAX_PATH_SEGMENTS {
            return Err(EncodeError::OptionValueTooLong);
        }
        let mut offset = 0;
        for (i, query) in queries.iter().enumerate() {
            if query.len() > 255 || query.len() > retained.bytes.len() - offset {
                return Err(EncodeError::OptionValueTooLong);
            }
            retained.bytes[offset..offset + query.len()].copy_from_slice(query.as_bytes());
            retained.lengths[i] = query.len() as u16;
            offset += query.len();
        }
        Ok(retained)
    }

    fn values(&self) -> impl Iterator<Item = &str> {
        let mut offset = 0;
        self.lengths[..self.count].iter().map(move |len| {
            let end = offset + usize::from(*len);
            let value = core::str::from_utf8(&self.bytes[offset..end]).expect("copied UTF-8 query");
            offset = end;
            value
        })
    }
}

/// Exact canonical request identity for Observe cancellation and FETCH follow-ups.
/// Fixed header/Token; Observe and ETag are omitted. Includes the FETCH body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObserveRequest {
    bytes: [u8; OBSERVE_REQUEST_BYTES],
    len: usize,
}

impl ObserveRequest {
    fn same_target(&self, other: &Self) -> bool {
        use crate::message::OptionNumber as N;
        let left = crate::message::decode(&self.bytes[..self.len]).expect("encoded identity");
        let right = crate::message::decode(&other.bytes[..other.len]).expect("encoded identity");
        let cache_key = |number: N| {
            !number.is_no_cache_key()
                && !matches!(number, N::BLOCK1 | N::BLOCK2 | N::Q_BLOCK1 | N::Q_BLOCK2)
        };
        left.code() == right.code()
            && (left.code() != Code::FETCH || left.payload() == right.payload())
            && left
                .options()
                .filter(|option| cache_key(option.number()))
                .map(|option| (option.number(), option.value()))
                .eq(right
                    .options()
                    .filter(|option| cache_key(option.number()))
                    .map(|option| (option.number(), option.value())))
    }
}

#[derive(Clone, Copy, Debug)]
struct LiveCall {
    call: Call,
    queries: RetainedQueries,
    accept: Option<ContentFormat>,
    request_tag: BodyTag,
    if_match: BodyTag,
    if_none_match: bool,
    etag: BodyTag,
    path: Path<'static>,
    code: Code,
    ty: Type,
    content_format: Option<ContentFormat>,
    echo: Option<crate::message::Echo>,
    no_response: Option<crate::message::NoResponse>,
    observe: OutgoingObserve,
    observed: Option<(u32, u64)>,
    observed_format: Option<Option<ContentFormat>>,
    request_identity: Option<ObserveRequest>,
    /// When the outstanding request may be forgotten (`0` = never).
    due_ms: u64,
    deadline_ms: Option<u64>,
}

/// Path / type for an outstanding client request (Block1 / Block2 Continue).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClientLives {
    rows: [Option<LiveCall>; RESPONSE_INBOX],
}

impl ClientLives {
    pub(crate) const fn new() -> Self {
        Self {
            rows: [None; RESPONSE_INBOX],
        }
    }

    fn can_admit(&self, token: Token, peer: Endpoint) -> bool {
        self.rows.iter().any(|row| match row {
            None => true,
            Some(live) => live.call.token == token && live.call.peer == peer,
        })
    }

    fn insert(&mut self, live: LiveCall) {
        if let Some(existing) = self.rows.iter_mut().find(|row| {
            row.as_ref().is_some_and(|row| {
                row.call.token == live.call.token && row.call.peer == live.call.peer
            })
        }) {
            *existing = Some(live);
            return;
        }
        if let Some(slot) = self.rows.iter_mut().find(|row| row.is_none()) {
            *slot = Some(live);
        }
    }

    fn get(&self, call: Call) -> Option<LiveCall> {
        self.rows.iter().copied().find_map(|row| {
            row.filter(|row| row.call.token == call.token && row.call.peer == call.peer)
        })
    }

    fn observe_fresh(&self, call: Call, parsed: &ParsedMessage<'_>, now_ms: u64) -> bool {
        let Some(sequence) = observation_start(parsed) else {
            return true;
        };
        let Some((previous, received)) = self.get(call).and_then(|live| live.observed) else {
            return true;
        };
        let delta = sequence.wrapping_sub(previous) & 0x00ff_ffff;
        (delta != 0 && delta < 0x0080_0000) || now_ms.saturating_sub(received) > 128_000
    }

    pub(crate) fn observe_format_admissible(
        &self,
        call: Call,
        parsed: &ParsedMessage<'_>,
        now_ms: u64,
        protected: bool,
    ) -> bool {
        (!protected && !self.observe_fresh(call, parsed, now_ms))
            || self.observe_format_matches(call, parsed)
    }

    fn observe_format_matches(&self, call: Call, parsed: &ParsedMessage<'_>) -> bool {
        if observation_start(parsed).is_none() {
            return true;
        }
        if parsed
            .content_format()
            .is_some_and(|format| format.is_err())
            || parsed
                .get_options(crate::message::OptionNumber::CONTENT_FORMAT)
                .count()
                > 1
        {
            return false;
        }
        // 2.03 may validate a cached representation without repeating its format.
        if parsed.code() == Code::VALID && parsed.content_format().is_none() {
            return true;
        }
        self.get(call)
            .and_then(|live| live.observed_format)
            .is_none_or(|initial| initial == parsed.content_format().and_then(Result::ok))
    }

    fn record_observation(&mut self, call: Call, parsed: &ParsedMessage<'_>, now_ms: u64) {
        if let Some(sequence) = observation_start(parsed) {
            if let Some(live) = self
                .rows
                .iter_mut()
                .flatten()
                .find(|live| live.call == call)
            {
                live.observed = Some((sequence, now_ms));
                if live.observed_format.is_none()
                    && (parsed.code() != Code::VALID || parsed.content_format().is_some())
                {
                    live.observed_format = Some(parsed.content_format().and_then(Result::ok));
                }
            }
        }
    }

    fn upload_key(&self, call: Call) -> BlockKey {
        BlockKey::new(call.token, call.peer).with_identity(
            self.get(call)
                .map(|live| live.request_tag)
                .unwrap_or(BodyTag::ABSENT),
        )
    }

    fn remove(&mut self, call: Call) {
        if let Some(slot) = self.rows.iter_mut().find(|row| {
            row.as_ref()
                .is_some_and(|row| row.call.token == call.token && row.call.peer == call.peer)
        }) {
            *slot = None;
        }
    }

    fn observe_call<E>(
        &self,
        peer: Endpoint,
        identity: ObserveRequest,
        target: Option<Call>,
        is_live: impl Fn(Call) -> bool,
    ) -> Result<Call, Error<E>> {
        let mut matches = self.rows.iter().flatten().filter(|live| {
            live.call.peer == peer
                && live.observe == OutgoingObserve::Register
                && live.due_ms != 0
                && is_live(live.call)
                && live.request_identity == Some(identity)
                && target.is_none_or(|call| live.call == call)
        });
        let call = matches
            .next()
            .ok_or(Error::ObserveCancellationMismatch)?
            .call;
        if matches.next().is_some() {
            return Err(Error::ObserveCancellationAmbiguous);
        }
        Ok(call)
    }
}

// RFC 7959 section 2.6: only block zero carries a new notification.
fn observation_start(parsed: &ParsedMessage<'_>) -> Option<u32> {
    if !parsed.code().is_success()
        || parsed
            .block2()
            .is_some_and(|block| block.is_ok_and(|block| block.num() != 0))
        || parsed
            .q_block2()
            .any(|block| block.is_ok_and(|block| block.num() != 0))
    {
        return None;
    }
    parsed.observe().and_then(Result::ok)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutgoingObserve {
    Off,
    Register,
    Deregister,
}

/// Outbound request builder: [`App::get`](super::App::get) / [`App::put`](super::App::put).
///
/// Distinct from the site routers [`get`](super::get) / [`put`](super::put).
/// Chain [`.to`](Self::to), optional [`.payload`](Self::payload) /
/// [`.non`](Self::non) / [`.query`](Self::query) / [`.accept`](Self::accept) /
/// [`.etag`](Self::etag) / [`.if_match`](Self::if_match) /
/// [`.if_none_match`](Self::if_none_match) / [`.observe`](Self::observe) /
/// [`.deregister`](Self::deregister) / [`.block2`](Self::block2) /
/// [`.q_block1`](Self::q_block1) / [`.q_block2`](Self::q_block2), then
/// [`.send`](Self::send). Default type is CON. Path sugar is
/// [`super::IntoPath`] (`"sensors/temp"` or `&["sensors", "temp"]`).
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
/// let peer = Endpoint::v4([192, 0, 2, 2], 5683);
/// let call = app.get("sensors/temp").to(peer).send(0).unwrap();
/// app.poll(0).unwrap();
/// let _ = app.take_response(call);
/// ```
pub struct Outgoing<'a, P, T, const N: usize, Dest = Missing, const BLOCK_WISE: bool = false>
where
    P: crate::storage::MemoryProfile + MemoryLayout<BLOCK_WISE> + AppAssembled<BLOCK_WISE>,
{
    app: &'a mut App<P, T, N, BLOCK_WISE>,
    code: Code,
    ty: Type,
    dest: Option<Endpoint>,
    path: Result<Path<'static>, PathError>,
    payload: &'a [u8],
    content_format: Option<ContentFormat>,
    echo: Option<crate::message::Echo>,
    no_response: Option<crate::message::NoResponse>,
    accept: Option<ContentFormat>,
    request_tag: BodyTag,
    etag: Option<&'a [u8]>,
    if_match: Option<&'a [u8]>,
    if_none_match: bool,
    queries: [&'a str; MAX_PATH_SEGMENTS],
    query_n: u8,
    q_block1: bool,
    q_block2: bool,
    block2: Option<BlockValue>,
    observe: OutgoingObserve,
    observe_target: Option<Call>,
    deadline_ms: Option<u64>,
    _dest: core::marker::PhantomData<Dest>,
}

impl<P, T, const N: usize, const BLOCK_WISE: bool> App<P, T, N, BLOCK_WISE>
where
    P: crate::storage::MemoryProfile + MemoryLayout<BLOCK_WISE> + AppAssembled<BLOCK_WISE>,
{
    /// CON GET builder. Next: [`Outgoing::to`].
    ///
    /// Distinct from the site router [`get`](super::get).
    /// `path` is [`IntoPath`]: `"sensors/temp"` or `&["sensors", "temp"]`.
    #[must_use]
    pub fn get(&mut self, path: impl IntoPath) -> Outgoing<'_, P, T, N, Missing, BLOCK_WISE> {
        self.request(Method::Get, path)
    }

    /// CON PUT builder. Next: [`Outgoing::to`].
    #[must_use]
    pub fn put(&mut self, path: impl IntoPath) -> Outgoing<'_, P, T, N, Missing, BLOCK_WISE> {
        self.request(Method::Put, path)
    }

    /// CON POST builder. Next: [`Outgoing::to`].
    #[must_use]
    pub fn post(&mut self, path: impl IntoPath) -> Outgoing<'_, P, T, N, Missing, BLOCK_WISE> {
        self.request(Method::Post, path)
    }

    /// CON DELETE builder. Next: [`Outgoing::to`].
    #[must_use]
    pub fn delete(&mut self, path: impl IntoPath) -> Outgoing<'_, P, T, N, Missing, BLOCK_WISE> {
        self.request(Method::Delete, path)
    }

    /// CON FETCH builder. Set [`Outgoing::content_format`] for the selection
    /// body (also required for an empty selection), then [`Outgoing::to`].
    #[must_use]
    pub fn fetch(&mut self, path: impl IntoPath) -> Outgoing<'_, P, T, N, Missing, BLOCK_WISE> {
        self.request(Method::Fetch, path)
    }

    /// CON PATCH builder. Next: [`Outgoing::to`].
    #[must_use]
    pub fn patch(&mut self, path: impl IntoPath) -> Outgoing<'_, P, T, N, Missing, BLOCK_WISE> {
        self.request(Method::Patch, path)
    }

    /// CON iPATCH builder. Next: [`Outgoing::to`].
    #[must_use]
    pub fn ipatch(&mut self, path: impl IntoPath) -> Outgoing<'_, P, T, N, Missing, BLOCK_WISE> {
        self.request(Method::IPatch, path)
    }

    /// CON request builder for `method`. Next: [`Outgoing::to`].
    #[must_use]
    pub fn request(
        &mut self,
        method: Method,
        path: impl IntoPath,
    ) -> Outgoing<'_, P, T, N, Missing, BLOCK_WISE> {
        Outgoing {
            app: self,
            code: method.code(),
            ty: Type::Confirmable,
            dest: None,
            path: path_from_into(path),
            payload: &[],
            content_format: None,
            echo: None,
            no_response: None,
            accept: None,
            request_tag: BodyTag::ABSENT,
            etag: None,
            if_match: None,
            if_none_match: false,
            queries: [""; MAX_PATH_SEGMENTS],
            query_n: 0,
            q_block1: false,
            q_block2: false,
            block2: None,
            observe: OutgoingObserve::Off,
            observe_target: None,
            deadline_ms: None,
            _dest: core::marker::PhantomData,
        }
    }
}

impl<P, T, const N: usize, const BLOCK_WISE: bool> App<P, T, N, BLOCK_WISE>
where
    P: crate::storage::MemoryProfile + MemoryLayout<BLOCK_WISE> + AppAssembled<BLOCK_WISE>,
{
    /// Take the matched [`Response`] for `call`, if [`App::poll`](Self::poll)
    /// has completed it.
    ///
    /// **Non-Block payload is at most [`super::INLINE_PAYLOAD`] (128) bytes.** A
    /// 200-byte piggybacked 2.05 with
    /// [`.block_wise::<false>()`](super::AppBuilder::block_wise) copies 128
    /// bytes into [`Response::payload`]. Check
    /// [`Response::payload_truncated`] / [`Response::payload_src_len`].
    /// [`Response`] does not own a 4KiB copy.
    ///
    /// When `BLOCK_WISE` and Block2 / Q-Block2 assembled, copies the RX
    /// body into an App hold and returns [`Response::body`] borrowed from
    /// that hold (released from the Engine). Representations above
    /// [`super::RESPONSE_BODY`] fail with [`CallFailure::ResponseBodyBounds`],
    /// even when a custom Engine profile can assemble more bytes. A later [`Self::take_response`] or
    /// [`Self::poll`] overwrites the hold. Datagram App has no hold. After
    /// [`Outgoing::observe`], the same `call` yields the initial
    /// representation and later notifications.
    /// Plaintext/DTLS notifications obey RFC 7641 serial-number ordering
    /// and its strict 128-second fallback. Stale CON notifications are ACKed
    /// without replacing data or refreshing Max-Age. OSCORE notifications use
    /// authenticated Partial-IV ordering instead. For block-wise notifications,
    /// ordering is established by the first accepted block, before completion.
    /// Max-Age expiry does not cancel the subscription. Use the retained
    /// `received_at_ms` and `max_age_secs` (default 60 seconds when absent)
    /// to assess representation freshness against the same monotonic clock.
    /// A response without Observe ends the subscription; explicit cancellation
    /// and deadlines also release it. Unrecognized plaintext CON responses
    /// receive Reset so the peer can stop notifying.
    /// `None` means pending/unknown/already taken. `Some(Ok(_))` is an actual
    /// remote response, including remote 4.xx/5.xx. `Some(Err(_))` is a local
    /// terminal outcome; no synthetic CoAP response code is invented.
    /// Location, Max-Age, Echo and raw options are retained within
    /// [`RESPONSE_OPTION_COUNT`] / [`RESPONSE_OPTION_BYTES`]. Block-wise replies
    /// retain the first accepted fragment's header metadata; no response is
    /// exposed until assembly completes. Metadata and assembled bytes borrow App.
    pub fn take_response(&mut self, call: Call) -> Option<Result<Response<'_>, CallFailure>> {
        let (response, body) = self.inbox.take(call)?;
        if !client_observe_live(&self.engine, call) {
            self.lives.remove(call);
            super::oscore::cancel(&mut self.oscore, call.token());
        }
        if let Some(id) = body {
            if let Some(bytes) = rx_body_payload(&self.engine, id) {
                P::store(&mut self.assembled, bytes);
            }
            release_rx_body(&mut self.engine, id);
            if let Some(bytes) = P::view(&self.assembled) {
                return Some(response.map(|response| response.with_assembled(bytes)));
            }
        }
        Some(response)
    }
    /// Cancel an active call and reclaim its exchange, body, Observe and OSCORE
    /// state. The next `take_response` yields `Err(CallFailure::Cancelled)`.
    /// No wire message is sent; use `Outgoing::deregister` for Observe signaling.
    /// Returns false for unknown/already terminal ordinary calls.
    pub fn cancel(&mut self, call: Call) -> bool {
        if self.lives.get(call).is_none()
            || (self.inbox.contains(call) && !client_observe_live(&self.engine, call))
        {
            return false;
        }
        fail_call(
            &mut self.engine,
            &mut self.inbox,
            &mut self.lives,
            &mut self.oscore,
            call,
            CallFailure::Cancelled,
            true,
        );
        true
    }
}

impl<'a, P, T, const N: usize, Dest, const BLOCK_WISE: bool> Outgoing<'a, P, T, N, Dest, BLOCK_WISE>
where
    P: crate::storage::MemoryProfile + MemoryLayout<BLOCK_WISE> + AppAssembled<BLOCK_WISE>,
{
    /// Destination endpoint (Token matching uses this peer).
    #[must_use]
    pub fn to(self, peer: Endpoint) -> Outgoing<'a, P, T, N, Present, BLOCK_WISE> {
        Outgoing {
            app: self.app,
            code: self.code,
            ty: self.ty,
            dest: Some(peer),
            path: self.path,
            payload: self.payload,
            content_format: self.content_format,
            echo: self.echo,
            no_response: self.no_response,
            accept: self.accept,
            request_tag: self.request_tag,
            etag: self.etag,
            if_match: self.if_match,
            if_none_match: self.if_none_match,
            queries: self.queries,
            query_n: self.query_n,
            q_block1: self.q_block1,
            q_block2: self.q_block2,
            block2: self.block2,
            observe: self.observe,
            observe_target: self.observe_target,
            deadline_ms: self.deadline_ms,
            _dest: core::marker::PhantomData,
        }
    }

    /// Absolute deadline in the same monotonic millisecond clock as `send`/`poll`.
    /// A deadline at/before `send` is refused before I/O. At `poll`, the deadline
    /// wins over a response processed at that same time. Covers all fragments
    /// and the entire Observe subscription until cancelled/deregistered.
    #[must_use]
    pub const fn deadline(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = Some(deadline_ms);
        self
    }

    /// Request body. A payload that does not fit one datagram is sent as
    /// Block1 (or Q-Block1 after [`.q_block1`](Self::q_block1)) when
    /// block-wise is enabled.
    #[must_use]
    pub const fn payload(mut self, payload: &'a [u8]) -> Self {
        self.payload = payload;
        self
    }

    /// Content-Format option.
    #[must_use]
    pub const fn content_format(mut self, format: ContentFormat) -> Self {
        self.content_format = Some(format);
        self
    }

    /// Express disinterest in selected response classes (RFC 7967).
    ///
    /// An explicit zero bitmap is retained on the wire. Server suppression is
    /// optional: returned responses remain observable. Silence is never reported
    /// as success; use [`Self::deadline`] for a partial mask, or [`App::cancel`]
    /// to cease listening when suppressing all classes. Empty ACKs only stop RTO.
    /// Fragmented uploads and suppressed Observe registration are explicit App
    /// boundaries; use Engine for caller-managed interactions in those cases.
    #[must_use]
    pub const fn no_response(mut self, value: crate::message::NoResponse) -> Self {
        self.no_response = Some(value);
        self
    }

    /// Echo a server-provided freshness challenge (RFC 9175).
    ///
    /// The caller must use this only for the endpoint that supplied the Echo,
    /// and preserve its security context and Inner/Outer protection class.
    /// App retains the value on every upload fragment and download continuation.
    /// Use [`Response::echo_option`] after a 4.01 response or preemptive challenge;
    /// retries are explicit so the caller can decide whether an unsafe operation
    /// is still fresh. This setter does not authenticate a challenge or retry a call.
    #[must_use]
    pub const fn echo(mut self, echo: crate::message::Echo) -> Self {
        self.echo = Some(echo);
        self
    }

    /// Accept option, retained on every Block1, Q-Block1 and Block2 request.
    #[must_use]
    pub const fn accept(mut self, format: ContentFormat) -> Self {
        self.accept = Some(format);
        self
    }

    /// Request-Tag for this operation (RFC 9175 sections 3.3/3.4).
    ///
    /// The caller supplies a unique value for each distinct Q-Block1 body and
    /// owns uniqueness across App instances/restarts. Active reuse at the same
    /// peer is refused. A present empty tag is distinct from absence. App emits
    /// one tag, retaining it for upload fragments and Block2 follow-ups.
    /// The App receive path also supports one tag and explicitly rejects longer
    /// values or multiple tags rather than silently ignoring identity components.
    #[must_use]
    pub const fn request_tag(mut self, tag: BodyTag) -> Self {
        self.request_tag = tag;
        self
    }

    /// ETag option (conditional GET / validation).
    /// A payload requiring Block1/Q-Block1 fragmentation returns
    /// [`Error::ConditionalUploadUnsupported`]; conditional upload retention is not implemented.
    #[must_use]
    pub const fn etag(mut self, tag: &'a [u8]) -> Self {
        self.etag = Some(tag);
        self
    }

    /// If-Match option.
    /// A payload requiring Block1/Q-Block1 fragmentation returns
    /// [`Error::ConditionalUploadUnsupported`], before sending, rather than losing the condition.
    #[must_use]
    pub const fn if_match(mut self, tag: &'a [u8]) -> Self {
        self.if_match = Some(tag);
        self
    }

    /// If-None-Match option.
    /// A payload requiring Block1/Q-Block1 fragmentation returns
    /// [`Error::ConditionalUploadUnsupported`], before sending, rather than losing the condition.
    #[must_use]
    pub const fn if_none_match(mut self) -> Self {
        self.if_none_match = true;
        self
    }

    /// Append a Uri-Query value. Total query bytes are bounded to 256 at send;
    /// each value is bounded to 255 bytes. Empty values are retained. More than
    /// [`super::MAX_PATH_SEGMENTS`] values are rejected at send. Values and
    /// their order are retained across Block1, Q-Block1 and Block2 requests.
    #[must_use]
    pub fn query(mut self, value: &'a str) -> Self {
        let n = usize::from(self.query_n);
        if n < MAX_PATH_SEGMENTS {
            self.queries[n] = value;
            self.query_n += 1;
        } else {
            self.query_n = (MAX_PATH_SEGMENTS + 1) as u8;
        }
        self
    }

    /// Ask for Block2 on the first GET (early size negotiation).
    #[must_use]
    pub const fn block2(mut self, block: BlockValue) -> Self {
        self.block2 = Some(block);
        self
    }

    /// Send as NON (no pending CON). Default is CON.
    #[must_use]
    pub const fn non(mut self) -> Self {
        self.ty = Type::NonConfirmable;
        self
    }

    /// Send a large body with Q-Block1 (windowed) instead of classic Block1.
    /// Requires [`Self::request_tag`]; absent tags are refused before I/O.
    /// CON uploads keep one payload outstanding and advance on its matching
    /// empty ACK. [`Self::non`] keeps each payload NON and sends bounded sets.
    /// Valid 4.08 missing-block reports for NON uploads reissue at most one
    /// payload set, preserving the original ranges and request options.
    /// Malformed, oversized or unsent-range reports are silently discarded.
    /// This per-upload limit does not establish endpoint-wide congestion control.
    #[must_use]
    pub const fn q_block1(mut self) -> Self {
        self.q_block1 = true;
        self
    }

    /// Ask for the entire Q-Block2 body (NUM 0, M=1, SZX 1024).
    /// The peer may still use classic Block2.
    #[must_use]
    pub const fn q_block2(mut self) -> Self {
        self.q_block2 = true;
        self
    }

    /// GET/FETCH Observe=0 (register). Later notifications use the same
    /// [`Call`] / [`App::take_response`](App::take_response).
    /// App retains up to 512 encoded bytes of canonical request identity
    /// (excluding ETag and Observe) for exact cancellation matching. Larger
    /// requests are refused before I/O; use Engine for caller-owned retention.
    /// Repeated subscriptions to the same peer and cache-key target return the
    /// existing Call without I/O, new state, or deadline changes (RFC 7641 §3.1).
    /// FETCH payloads distinguish selections; ETag, NoCacheKey options and block
    /// controls do not create a second subscription. The caller distributes the
    /// single response stream to its consumers. Use [`Self::reregister_call`]
    /// to refresh the request explicitly; cancellation ends the shared Call.
    #[must_use]
    pub const fn observe(mut self) -> Self {
        self.observe = OutgoingObserve::Register;
        self.observe_target = None;
        self
    }

    /// Refresh a specific live subscription with Observe=0 and the same Token.
    /// Repeat the original method, path, options and payload; ETags may differ.
    /// Mismatch is refused before I/O. Notification ordering and the existing
    /// absolute deadline survive the refresh (a new deadline may shorten it).
    /// Pending transmissions and queued representations are retired before send.
    /// On send failure, the local subscription terminates with
    /// [`CallFailure::ReregistrationFailed`]; remote state remains uncertain.
    /// The caller schedules refresh, including RFC 7641 section 3.3's randomized
    /// delay after Max-Age. App does not automatically refresh subscriptions.
    #[must_use]
    pub const fn reregister_call(mut self, call: Call) -> Self {
        self.observe = OutgoingObserve::Register;
        self.observe_target = Some(call);
        self
    }

    /// GET/FETCH Observe=1 (deregister). Reuses the uniquely matching live Call.
    /// Repeat the registration request's method, path, options and payload;
    /// ETags may differ. A mismatch or ambiguous match is refused before I/O.
    /// [`Self::deregister_call`] also validates the explicit Call handle.
    /// After validation, cancellation retires the old local subscription,
    /// queued notifications and pending transmissions. If sending fails,
    /// `take_response` reports [`CallFailure::CancellationFailed`]; remote
    /// cancellation is uncertain and must not be assumed successful.
    #[must_use]
    pub const fn deregister(mut self) -> Self {
        self.observe = OutgoingObserve::Deregister;
        self.observe_target = None;
        self
    }

    /// Cancel a specific subscription, with the same request checks as
    /// [`Self::deregister`]. The Call must still be live at the selected peer.
    #[must_use]
    pub const fn deregister_call(mut self, call: Call) -> Self {
        self.observe = OutgoingObserve::Deregister;
        self.observe_target = Some(call);
        self
    }
}

impl<P, T, const N: usize, const BLOCK_WISE: bool> Outgoing<'_, P, T, N, Present, BLOCK_WISE>
where
    P: crate::storage::MemoryProfile + MemoryLayout<BLOCK_WISE> + AppAssembled<BLOCK_WISE>,
    T: DatagramIo,
{
    /// Encode the request, record the Exchange, and send.
    ///
    /// `now_ms` starts CON RTO on Engine with injected random jitter. Later
    /// [`App::poll`](App::poll) sends Due retransmits when that clock
    /// advances. Returns a [`Call`] for [`App::take_response`](App::take_response).
    /// Production Tokens use eight injected random bytes; Message IDs use a
    /// randomly initialized counter and bounded reuse guard. See
    /// [`super::AppBuilder::randomness`]. This crate does not call an OS RNG. A payload that does
    /// not fit one datagram starts Block1 / Q-Block1 when block-wise is on.
    ///
    /// On failure, local request state is retired, including any partial
    /// upload and OSCORE request binding. An error does not prove that the
    /// peer received no datagrams or performed no action; retry policy must
    /// account for that uncertainty. Security sequence numbers are not reset.
    ///
    /// [`Error::Saturated`] if four Calls are already outstanding (inbox /
    /// lives cap) and this Token is not one of them.
    pub fn send(self, now_ms: u64) -> Result<Call, Error<T::Error>> {
        if self.deadline_ms.is_some_and(|deadline| deadline <= now_ms) {
            return Err(Error::DeadlineElapsed);
        }
        if self.code == Code::FETCH && self.content_format.is_none() {
            return Err(Error::FetchContentFormatRequired);
        }
        let dest = self.dest.expect("typestate: to() was called");
        let path = self.path.map_err(|_| Error::Path)?;
        let observe = self.observe;
        let refreshing = observe == OutgoingObserve::Register && self.observe_target.is_some();
        let replacing = observe == OutgoingObserve::Deregister || refreshing;
        if observe != OutgoingObserve::Off && !matches!(self.code, Code::GET | Code::FETCH) {
            return Err(Error::ObserveMethodUnsupported);
        }
        if self.no_response.is_some() && self.q_block1 {
            return Err(Error::NoResponseUploadUnsupported);
        }
        if self.no_response.is_some_and(|value| value.get() != 0)
            && observe == OutgoingObserve::Register
        {
            return Err(Error::NoResponseObserveUnsupported);
        }
        let queries = self.queries;
        let query_n = usize::from(self.query_n);
        if query_n > MAX_PATH_SEGMENTS {
            return Err(Error::Message(SlotMessageError::Encode(
                EncodeError::OptionValueTooLong,
            )));
        }
        let if_match = BodyTag::from_first(self.if_match).map_err(|_| {
            Error::Message(SlotMessageError::Encode(EncodeError::OptionValueTooLong))
        })?;
        let etag = BodyTag::from_first(self.etag).map_err(|_| {
            Error::Message(SlotMessageError::Encode(EncodeError::OptionValueTooLong))
        })?;
        let retained_queries = RetainedQueries::new(&queries[..query_n])
            .map_err(|e| Error::Message(SlotMessageError::Encode(e)))?;
        let mut spec = ClientSend {
            dest,
            ty: self.ty,
            code: self.code,
            token: Token::EMPTY,
            path: path.segments(),
            payload: self.payload,
            content_format: self.content_format,
            echo: self.echo,
            no_response: self.no_response,
            accept: self.accept,
            request_tag: self.request_tag,
            etag: self.etag,
            if_match: self.if_match,
            if_none_match: self.if_none_match,
            queries: &queries[..query_n],
            q_block1: self.q_block1,
            q_block2: self.q_block2,
            block2: self.block2,
            observe,
        };
        let request_identity = if observe == OutgoingObserve::Off && self.code != Code::FETCH {
            None
        } else {
            Some(
                request_identity_identity(&spec).map_err(|error| match error {
                    EncodeError::BufferTooSmall if observe == OutgoingObserve::Off => {
                        Error::FetchRequestTooLarge
                    }
                    EncodeError::BufferTooSmall => Error::ObserveRequestTooLarge,
                    other => Error::Message(SlotMessageError::Encode(other)),
                })?,
            )
        };
        if observe == OutgoingObserve::Register && !refreshing {
            let identity = request_identity.as_ref().expect("Observe identity");
            if let Some(existing) = self.app.lives.rows.iter().flatten().find(|live| {
                live.call.peer == dest
                    && live.observe == OutgoingObserve::Register
                    && live.due_ms != 0
                    && (!self.app.inbox.contains(live.call)
                        || client_observe_live(&self.app.engine, live.call))
                    && live
                        .request_identity
                        .as_ref()
                        .is_some_and(|original| original.same_target(identity))
            }) {
                return Ok(existing.call);
            }
        }
        let token = if replacing {
            self.app
                .lives
                .observe_call::<T::Error>(
                    dest,
                    request_identity.expect("Observe identity"),
                    self.observe_target,
                    |call| {
                        !self.app.inbox.contains(call)
                            || client_observe_live(&self.app.engine, call)
                    },
                )
                .map_err(|error| {
                    if refreshing {
                        Error::ObserveRefreshMismatch
                    } else {
                        error
                    }
                })?
                .token()
        } else {
            self.app.next_token()?
        };
        if !self.app.lives.can_admit(token, dest) {
            return Err(Error::Saturated);
        }
        if self.q_block1 && self.request_tag.is_absent() {
            return Err(Error::RequestTagRequired);
        }
        if !self.request_tag.is_absent()
            && self.app.lives.rows.iter().flatten().any(|live| {
                live.call.peer == dest
                    && live.request_tag == self.request_tag
                    && live.call.token != token
            })
        {
            return Err(Error::RequestTagInUse);
        }
        let prior = refreshing
            .then(|| self.app.lives.get(Call::new(token, dest)))
            .flatten();
        let deadline_ms = match (self.deadline_ms, prior.and_then(|live| live.deadline_ms)) {
            (Some(new), Some(old)) => Some(new.min(old)),
            (new, old) => new.or(old),
        };
        if deadline_ms.is_some_and(|deadline| deadline <= now_ms) {
            return Err(Error::DeadlineElapsed);
        }
        spec.token = token;
        if replacing {
            // A new request reuses this Token. Do not retain old CONs, body
            // fragments or authenticated request bindings under that identity.
            abandon_send(&mut self.app.engine, &mut self.app.oscore, token, dest);
            fail_call(
                &mut self.app.engine,
                &mut self.app.inbox,
                &mut self.app.lives,
                &mut self.app.oscore,
                Call::new(token, dest),
                if refreshing {
                    CallFailure::ReregistrationFailed
                } else {
                    CallFailure::CancellationFailed
                },
                true,
            );
        }
        let call = send_client(
            &mut self.app.engine,
            &mut self.app.io,
            &mut self.app.ids,
            &mut self.app.oscore,
            now_ms,
            spec,
        );
        let call = match call {
            Ok(call) => call,
            Err(error) => {
                abandon_send(&mut self.app.engine, &mut self.app.oscore, token, dest);
                return Err(error);
            }
        };
        if replacing {
            self.app.inbox.discard(call);
        }
        self.app.lives.insert(LiveCall {
            call,
            queries: retained_queries,
            accept: self.accept,
            request_tag: self.request_tag,
            if_match,
            if_none_match: self.if_none_match,
            etag,
            path,
            code: self.code,
            ty: self.ty,
            content_format: self.content_format,
            echo: self.echo,
            no_response: self.no_response,
            observe,
            observed: prior.and_then(|live| live.observed),
            observed_format: prior.and_then(|live| live.observed_format),
            request_identity,
            deadline_ms,
            due_ms: now_ms.saturating_add(u64::from(if self.ty == Type::NonConfirmable {
                Transmission::NON_LIFETIME_MS
            } else {
                Transmission::EXCHANGE_LIFETIME_MS
            })),
        });
        Ok(call)
    }
}

impl<
    P: MemoryLayout<BLOCK_WISE> + AppAssembled<BLOCK_WISE>,
    T,
    const N: usize,
    const BLOCK_WISE: bool,
> App<P, T, N, BLOCK_WISE>
{
    fn next_token<E>(&mut self) -> Result<Token, Error<E>> {
        for _ in 0..8 {
            let token = self.ids.token().map_err(Error::Identity)?;
            if !self
                .lives
                .rows
                .iter()
                .flatten()
                .any(|live| live.call.token() == token)
            {
                return Ok(token);
            }
        }
        Err(Error::Identity(super::IdentityError::TokenExhausted))
    }
}

struct ClientSend<'a> {
    dest: Endpoint,
    ty: Type,
    code: Code,
    token: Token,
    path: &'a [&'a str],
    payload: &'a [u8],
    content_format: Option<ContentFormat>,
    echo: Option<crate::message::Echo>,
    no_response: Option<crate::message::NoResponse>,
    accept: Option<ContentFormat>,
    request_tag: BodyTag,
    etag: Option<&'a [u8]>,
    if_match: Option<&'a [u8]>,
    if_none_match: bool,
    queries: &'a [&'a str],
    q_block1: bool,
    q_block2: bool,
    block2: Option<BlockValue>,
    observe: OutgoingObserve,
}

// One option builder feeds both wire encoding and exact cancellation identity.
fn with_client_options<R>(
    spec: &ClientSend<'_>,
    identity_only: bool,
    use_options: impl FnOnce(&[Opt<'_>]) -> R,
) -> Result<R, EncodeError> {
    let cf = spec.content_format.map(ContentFormat::encode);
    let no_response = spec.no_response.map(crate::message::NoResponse::encode);
    let acc = spec.accept.map(ContentFormat::encode);
    let q2 = spec
        .q_block2
        .then(|| BlockValue::new(0, true, BlockValue::SZX_MAX))
        .and_then(Result::ok)
        .map(BlockValue::encode);
    let b2 = spec.block2.map(BlockValue::encode);
    let mut opts = OptionsBuilder::<CLIENT_OPTION_SLOTS>::new();
    let filled = (|| -> Result<(), EncodeError> {
        if let Some(tag) = spec.if_match {
            push_opt(&mut opts, Opt::if_match(tag))?;
        }
        if !identity_only {
            if let Some(tag) = spec.etag {
                push_opt(&mut opts, Opt::etag(tag))?;
            }
        }
        if spec.if_none_match {
            push_opt(&mut opts, Opt::if_none_match())?;
        }
        if !identity_only {
            match spec.observe {
                OutgoingObserve::Register => {
                    push_opt(&mut opts, Opt::observe_register())?;
                }
                OutgoingObserve::Deregister => {
                    push_opt(&mut opts, Opt::observe_deregister())?;
                }
                OutgoingObserve::Off => {}
            }
        }
        for segment in spec.path {
            push_opt(&mut opts, Opt::uri_path(segment))?;
        }
        if let Some(ref encoded) = cf {
            push_opt(&mut opts, Opt::content_format(encoded))?;
        }
        for query in spec.queries {
            push_opt(&mut opts, Opt::uri_query(query))?;
        }
        if let Some(ref encoded) = acc {
            push_opt(&mut opts, Opt::accept(encoded))?;
        }
        if let Some(ref encoded) = b2 {
            push_opt(&mut opts, Opt::block2(encoded))?;
        }
        if let Some(ref encoded) = q2 {
            push_opt(&mut opts, Opt::q_block2(encoded))?;
        }
        if let Some(ref value) = no_response {
            push_opt(&mut opts, Opt::no_response(value))?;
        }
        if let Some(echo) = spec.echo.as_ref() {
            push_opt(&mut opts, Opt::echo(echo.as_slice()))?;
        }
        if let Some(tag) = spec.request_tag.as_slice() {
            push_opt(&mut opts, Opt::request_tag(tag))?;
        }
        Ok(())
    })();
    filled?;
    Ok(use_options(opts.as_slice()))
}

fn request_identity_identity(spec: &ClientSend<'_>) -> Result<ObserveRequest, EncodeError> {
    with_client_options(spec, true, |options| {
        let mut identity = ObserveRequest {
            bytes: [0; OBSERVE_REQUEST_BYTES],
            len: 0,
        };
        let message = Message::new(Type::Confirmable, spec.code, MessageId::new(0))
            .with_options(options)
            .with_payload(spec.payload);
        identity.len = crate::message::encode(&message, &mut identity.bytes)?;
        Ok(identity)
    })?
}

fn send_client<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
    spec: ClientSend<'_>,
) -> Result<Call, Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots,
    T: DatagramIo,
{
    if spec.path.len() > MAX_PATH_SEGMENTS {
        return Err(Error::Path);
    }
    let mid = ids.next_for(engine, now_ms)?;
    let Some(tx) = engine.acquire_tx() else {
        return Err(Error::Saturated);
    };
    let encoded = with_client_options(&spec, false, |options| {
        let msg = Message::new(spec.ty, spec.code, mid)
            .with_token(spec.token)
            .with_options(options)
            .with_payload(spec.payload);
        super::oscore::encode_request(oscore, engine, tx, &msg)
    });
    let encoded = match encoded {
        Ok(result) => result,
        Err(error) => {
            let _ = engine.release_tx(tx);
            return Err(Error::Message(SlotMessageError::Encode(error)));
        }
    };
    match encoded {
        Ok(_) => finish_client_send(
            engine,
            io,
            tx,
            spec.dest,
            spec.ty,
            now_ms,
            mid,
            ids.jitter(),
        )
        .map(|()| Call::new(spec.token, spec.dest)),
        Err(Error::Message(SlotMessageError::Encode(EncodeError::BufferTooSmall))) => {
            if spec.no_response.is_some() {
                let _ = engine.release_tx(tx);
                return Err(Error::NoResponseUploadUnsupported);
            }
            // These conditions cannot be dropped while changing to Block1.
            // Until the App retains their transfer-specific semantics, refuse
            // fragmentation instead of turning a conditional write into an
            // unconditional one (RFC 7959 section 2.10).
            if spec.if_match.is_some() || spec.if_none_match || spec.etag.is_some() {
                let _ = engine.release_tx(tx);
                return Err(Error::ConditionalUploadUnsupported);
            }
            // Inner Block-wise: fragment first, then protect each
            // datagram (RFC 8613 §4.1.3.4.1). Same path with OSCORE on.
            // Protocol protect failures are `Error::Oscore`, not this arm.
            send_client_block1(
                engine,
                io,
                ids,
                oscore,
                now_ms,
                spec.dest,
                spec.ty,
                spec.code,
                spec.token,
                spec.path,
                spec.queries,
                spec.accept,
                spec.payload,
                spec.request_tag,
                spec.content_format,
                spec.echo,
                spec.q_block1,
                tx,
            )
        }
        Err(e) => {
            let _ = engine.release_tx(tx);
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn send_client_block1<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
    dest: Endpoint,
    ty: Type,
    code: Code,
    token: Token,
    path: &[&str],
    queries: &[&str],
    accept: Option<ContentFormat>,
    payload: &[u8],
    request_tag: BodyTag,
    content_format: Option<ContentFormat>,
    echo: Option<crate::message::Echo>,
    q_block1: bool,
    tx: SlotId,
) -> Result<Call, Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots,
    T: DatagramIo,
{
    let key = BlockKey::new(token, dest).with_identity(request_tag);
    let started = if q_block1 {
        engine.start_q_block1(key, payload, BlockValue::SZX_MAX)
    } else {
        engine.start_block1(key, payload, BlockValue::SZX_MAX)
    };
    let body = match started {
        Ok(id) => id,
        Err(BlockTransferError::NoBodyPools) => {
            let _ = engine.release_tx(tx);
            return Err(Error::Message(SlotMessageError::Encode(
                EncodeError::BufferTooSmall,
            )));
        }
        Err(e) => {
            let _ = engine.release_tx(tx);
            return Err(Error::Block(e));
        }
    };
    let outcome = if q_block1 {
        issue_q_block1_window(
            engine,
            io,
            ids,
            oscore,
            now_ms,
            dest,
            ty,
            code,
            token,
            path,
            queries,
            accept,
            content_format,
            echo,
            body,
            Some(tx),
            None,
        )
        .map(|_| ())
    } else {
        issue_block1(
            engine,
            io,
            ids,
            oscore,
            now_ms,
            dest,
            ty,
            code,
            token,
            path,
            queries,
            accept,
            content_format,
            echo,
            body,
            Some(tx),
        )
    };
    if outcome.is_err() {
        let _ = engine.release_tx_body(body);
    }
    outcome?;
    Ok(Call::new(token, dest))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn complete_client<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    inbox: &mut ClientInbox,
    lives: &mut ClientLives,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    response_state: super::oscore::ResponseState,
    now_ms: u64,
    peer: Endpoint,
    parsed: &ParsedMessage<'_>,
    rx: SlotId,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots + ObserveSlots,
    T: DatagramIo,
{
    let via_exchange = matching_exchange(engine, parsed, peer);
    let via_observe = matching_observe(engine, parsed, peer);
    if via_exchange.is_none() && !via_observe {
        let outcome = if parsed.ty() == Type::Confirmable {
            super::send_empty_rst(engine, io, peer, parsed.message_id())
        } else {
            Ok(())
        };
        let _ = engine.release_rx(rx);
        return outcome;
    }
    // RFC 7252 sections 5.4.1 and 4.2: reject the response, not an
    // otherwise matching ACK. No inbox/body/Observe state may accept it.
    if parsed.unknown_critical().is_some() {
        if parsed.ty() == Type::Acknowledgement {
            if let Some(entry) = via_exchange {
                if let Some(tx) = engine.take_pending_con(entry.message_id(), peer) {
                    let _ = engine.release_tx(tx);
                }
            }
        }
        let outcome = if parsed.ty() == Type::Confirmable {
            super::send_empty_rst(engine, io, peer, parsed.message_id())
        } else {
            Ok(())
        };
        let _ = engine.release_rx(rx);
        return outcome;
    }
    let call = Call::new(parsed.token(), peer);
    let fresh = super::oscore::is_active(oscore) || lives.observe_fresh(call, parsed, now_ms);
    if !lives.observe_format_admissible(call, parsed, now_ms, super::oscore::is_active(oscore)) {
        let outcome = if parsed.ty() == Type::Confirmable {
            super::send_empty_rst(engine, io, peer, parsed.message_id())
        } else {
            Ok(())
        };
        fail_call(
            engine,
            inbox,
            lives,
            oscore,
            call,
            CallFailure::ObserveFormatMismatch,
            true,
        );
        let _ = engine.release_rx(rx);
        return outcome;
    }
    if parsed.ty() == Type::Confirmable {
        if let Err(e) = super::send_empty_ack(engine, io, peer, parsed.message_id()) {
            let _ = engine.release_rx(rx);
            return Err(e);
        }
    }
    if let Err(error) = super::oscore::commit_response(oscore, response_state) {
        let _ = engine.release_rx(rx);
        return Err(error);
    }
    // A matching piggybacked ACK ends retransmission even if its Observe
    // value is stale. A delayed NON/CON notification cannot acknowledge a
    // concurrently refreshed request merely by sharing its Token.
    if parsed.ty() == Type::Acknowledgement {
        if let Some(entry) = via_exchange {
            if let Some(tx) = engine.take_pending_con(entry.message_id(), peer) {
                let _ = engine.release_tx(tx);
            }
        }
    }
    // ACK stale CON notifications too, but do not refresh their lifetime,
    // replace the inbox, or alter assembly. OSCORE already authenticated and
    // ordered notifications by Partial IV (RFC 8613 section 4.1.3.5.2).
    if !fresh {
        let _ = engine.release_rx(rx);
        return Ok(());
    }
    // Piggybacked ACK shares the request MID. A separate CON/NON response
    // uses a new MID; stop RTO using the exchange's request MID.
    if let Some(entry) = via_exchange {
        if let Some(tx) = engine.take_pending_con(entry.message_id(), peer) {
            let _ = engine.release_tx(tx);
        }
    }
    if let Some(tx) = engine.take_pending_con(parsed.message_id(), peer) {
        let _ = engine.release_tx(tx);
    }

    if let Some(body) = upload_body(engine, lives.upload_key(Call::new(parsed.token(), peer))) {
        if let Some(transfer) = engine.tx_body_transfer(body) {
            if matches!(
                transfer.role(),
                BlockRole::OutgoingBlock1 | BlockRole::OutgoingQBlock1
            ) {
                if transfer.role() == BlockRole::OutgoingQBlock1
                    && parsed.code() == Code::REQUEST_ENTITY_INCOMPLETE
                    && parsed.content_format() == Some(Ok(ContentFormat::MISSING_BLOCKS))
                    && lives
                        .get(Call::new(parsed.token(), peer))
                        .is_some_and(|live| live.ty == Type::NonConfirmable)
                {
                    let outcome = reissue_qblock1_missing(
                        engine, io, lives, ids, oscore, now_ms, parsed, peer, body,
                    );
                    if outcome.is_err() {
                        abandon_send(engine, oscore, parsed.token(), peer);
                        fail_call(
                            engine,
                            inbox,
                            lives,
                            oscore,
                            Call::new(parsed.token(), peer),
                            CallFailure::ContinuationFailed,
                            true,
                        );
                    }
                    let _ = engine.release_rx(rx);
                    return outcome;
                }
                if parsed.code() == Code::CONTINUE {
                    let outcome = continue_block1_tx(
                        engine,
                        io,
                        lives,
                        ids,
                        oscore,
                        now_ms,
                        parsed.token(),
                        parsed.q_block1().and_then(Result::ok),
                        peer,
                        body,
                    );
                    if outcome.is_err() {
                        abandon_send(engine, oscore, parsed.token(), peer);
                        fail_call(
                            engine,
                            inbox,
                            lives,
                            oscore,
                            Call::new(parsed.token(), peer),
                            CallFailure::ContinuationFailed,
                            true,
                        );
                    }
                    let _ = engine.release_rx(rx);
                    return outcome;
                }
                let _ = engine.release_tx_body(body);
            }
        }
    }

    let metadata = match ReplyMeta::from_parsed(parsed, peer, now_ms) {
        Ok(metadata) => metadata,
        Err(error) => {
            fail_call(
                engine,
                inbox,
                lives,
                oscore,
                Call::new(parsed.token(), peer),
                error,
                true,
            );
            let _ = engine.release_rx(rx);
            return Ok(());
        }
    };

    // Classify from the already-decoded response. A plain 2.05 must not
    // stack Block IO scratch via MissingBlock probes.
    if parsed.block2().is_some() {
        match engine.apply_block2_rx(rx) {
            Ok(progress) if progress.complete() => {
                lives.record_observation(Call::new(parsed.token(), peer), parsed, now_ms);
                finish_assembled(
                    engine,
                    inbox,
                    lives,
                    oscore,
                    parsed,
                    peer,
                    rx,
                    progress.id(),
                    metadata,
                    via_exchange.is_some(),
                );
                return Ok(());
            }
            Ok(progress) => {
                lives.record_observation(Call::new(parsed.token(), peer), parsed, now_ms);
                match inbox.retain_partial(Call::new(parsed.token(), peer), metadata, progress.id())
                {
                    Ok(Some(previous)) if previous != progress.id() => {
                        let _ = engine.release_rx_body(previous);
                    }
                    Ok(_) => {}
                    Err(()) => {
                        let _ = engine.release_rx_body(progress.id());
                        let _ = engine.release_rx(rx);
                        return Err(Error::Saturated);
                    }
                }
                take_exchange(engine, parsed, peer);
                let outcome = send_block2_continue(
                    engine,
                    io,
                    lives,
                    ids,
                    oscore,
                    now_ms,
                    parsed,
                    peer,
                    progress.id(),
                );
                if outcome.is_err() {
                    abandon_send(engine, oscore, parsed.token(), peer);
                    fail_call(
                        engine,
                        inbox,
                        lives,
                        oscore,
                        Call::new(parsed.token(), peer),
                        CallFailure::ContinuationFailed,
                        true,
                    );
                }
                let _ = engine.release_rx(rx);
                return outcome;
            }
            Err(BlockTransferError::Overlap | BlockTransferError::AlreadyComplete) => {
                let _ = engine.release_rx(rx);
                return Ok(());
            }
            Err(BlockTransferError::MissingBlock | BlockTransferError::NoBodyPools) => {}
            Err(e) => {
                fail_call(
                    engine,
                    inbox,
                    lives,
                    oscore,
                    Call::new(parsed.token(), peer),
                    CallFailure::BlockTransfer(e),
                    true,
                );
                let _ = engine.release_rx(rx);
                return Ok(());
            }
        }
    } else if parsed.q_block2().next().is_some() {
        match engine.apply_q_block2_rx(rx) {
            Ok(progress) if progress.complete() => {
                lives.record_observation(Call::new(parsed.token(), peer), parsed, now_ms);
                let _ = engine.note_q_receive(progress.id(), now_ms);
                finish_assembled(
                    engine,
                    inbox,
                    lives,
                    oscore,
                    parsed,
                    peer,
                    rx,
                    progress.id(),
                    metadata,
                    via_exchange.is_some(),
                );
                return Ok(());
            }
            Ok(progress) => {
                lives.record_observation(Call::new(parsed.token(), peer), parsed, now_ms);
                match inbox.retain_partial(Call::new(parsed.token(), peer), metadata, progress.id())
                {
                    Ok(Some(previous)) if previous != progress.id() => {
                        let _ = engine.release_rx_body(previous);
                    }
                    Ok(_) => {}
                    Err(()) => {
                        let _ = engine.release_rx_body(progress.id());
                        let _ = engine.release_rx(rx);
                        return Err(Error::Saturated);
                    }
                }
                let _ = engine.note_q_receive(progress.id(), now_ms);
                let outcome = if needs_q_continue(engine, progress.id()) {
                    take_exchange(engine, parsed, peer);
                    send_q_block2_continue(
                        engine,
                        io,
                        lives,
                        ids,
                        oscore,
                        now_ms,
                        parsed,
                        peer,
                        progress.id(),
                    )
                } else {
                    Ok(())
                };
                if outcome.is_err() {
                    abandon_send(engine, oscore, parsed.token(), peer);
                    fail_call(
                        engine,
                        inbox,
                        lives,
                        oscore,
                        Call::new(parsed.token(), peer),
                        CallFailure::ContinuationFailed,
                        true,
                    );
                }
                let _ = engine.release_rx(rx);
                return outcome;
            }
            Err(BlockTransferError::MissingBlock | BlockTransferError::NoBodyPools) => {}
            Err(e) => {
                fail_call(
                    engine,
                    inbox,
                    lives,
                    oscore,
                    Call::new(parsed.token(), peer),
                    CallFailure::BlockTransfer(e),
                    true,
                );
                let _ = engine.release_rx(rx);
                return Ok(());
            }
        }
    }

    lives.record_observation(Call::new(parsed.token(), peer), parsed, now_ms);
    accept_client_observe(engine, lives, parsed, peer, now_ms, via_exchange.is_some());
    take_exchange(engine, parsed, peer);
    store_reply(
        engine,
        inbox,
        Call::new(parsed.token(), peer),
        metadata,
        None,
    );
    let _ = engine.release_rx(rx);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_assembled<Mem>(
    engine: &mut Engine<Mem>,
    inbox: &mut ClientInbox,
    lives: &mut ClientLives,
    oscore: &mut super::oscore::Field,
    parsed: &ParsedMessage<'_>,
    peer: Endpoint,
    rx: SlotId,
    body: SlotId,
    metadata: ReplyMeta,
    via_exchange: bool,
) where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots + ObserveSlots,
{
    let call = Call::new(parsed.token(), peer);
    if engine
        .rx_body_payload(body)
        .is_some_and(|bytes| bytes.len() > super::RESPONSE_BODY)
    {
        fail_call(
            engine,
            inbox,
            lives,
            oscore,
            call,
            CallFailure::ResponseBodyBounds,
            true,
        );
        let _ = engine.release_rx(rx);
        return;
    }
    let metadata = inbox.partial_meta(call, body).unwrap_or(metadata);
    let original = crate::message::decode(&metadata.header[..usize::from(metadata.header_len)])
        .expect("encoded response header");
    accept_client_observe(
        engine,
        lives,
        &original,
        peer,
        metadata.received_at_ms,
        via_exchange,
    );
    take_exchange(engine, parsed, peer);
    store_reply(
        engine,
        inbox,
        Call::new(parsed.token(), peer),
        metadata,
        Some(body),
    );
    let _ = engine.release_rx(rx);
}

fn store_reply<Mem: Storage + BodySlots>(
    engine: &mut Engine<Mem>,
    inbox: &mut ClientInbox,
    call: Call,
    meta: ReplyMeta,
    body: Option<SlotId>,
) {
    match inbox.insert(call, Ok(meta), body) {
        Ok(prev) => {
            if let Some(id) = prev {
                if Some(id) != body {
                    let _ = engine.release_rx_body(id);
                }
            }
        }
        Err(()) => {
            if let Some(id) = body {
                let _ = engine.release_rx_body(id);
            }
        }
    }
}

/// Check unencrypted routing fields before touching protected response state.
pub(super) fn has_response_target<Mem: Storage + Exchanges + ObserveSlots>(
    engine: &Engine<Mem>,
    parsed: &ParsedMessage<'_>,
    peer: Endpoint,
) -> bool {
    matching_exchange(engine, parsed, peer).is_some() || matching_observe(engine, parsed, peer)
}

fn matching_observe<Mem: Storage + ObserveSlots>(
    engine: &Engine<Mem>,
    parsed: &ParsedMessage<'_>,
    peer: Endpoint,
) -> bool {
    parsed.code().is_response()
        && matches!(parsed.ty(), Type::Confirmable | Type::NonConfirmable)
        && engine
            .lookup_observe(ObserveKey::new_client(parsed.token(), peer))
            .is_some()
}

fn matching_exchange<Mem: Storage + Exchanges>(
    engine: &Engine<Mem>,
    parsed: &ParsedMessage<'_>,
    peer: Endpoint,
) -> Option<crate::storage::ExchangeEntry> {
    let id = engine.lookup_exchange(ExchangeKey::new(parsed.token(), peer))?;
    let entry = engine.exchange_entry(id)?;
    entry.matches_response(parsed).then_some(entry)
}

fn take_exchange<Mem: Storage + Exchanges>(
    engine: &mut Engine<Mem>,
    parsed: &ParsedMessage<'_>,
    peer: Endpoint,
) {
    let _ = engine.take_exchange(ExchangeKey::new(parsed.token(), peer));
}

fn needs_q_continue<Mem: Storage + BodySlots>(engine: &Engine<Mem>, id: SlotId) -> bool {
    let Some(transfer) = engine.rx_body_transfer(id) else {
        return false;
    };
    transfer.role() == BlockRole::IncomingQBlock2
        && !transfer.is_complete()
        && transfer.q_holes().is_none()
        && transfer.window_mask() == 0
        && transfer.window_base() > 0
}

#[allow(clippy::too_many_arguments)]
fn send_block2_continue<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    lives: &ClientLives,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
    parsed: &ParsedMessage<'_>,
    peer: Endpoint,
    body: SlotId,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots,
    T: DatagramIo,
{
    let Some(transfer) = engine.rx_body_transfer(body) else {
        return Ok(());
    };
    let Ok(block) = BlockValue::new(transfer.next_num(), false, transfer.szx()) else {
        return Ok(());
    };
    send_followup(
        engine,
        io,
        lives,
        ids,
        oscore,
        now_ms,
        parsed.token(),
        peer,
        Some(block),
        &[],
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn send_q_block2_continue<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    lives: &ClientLives,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
    parsed: &ParsedMessage<'_>,
    peer: Endpoint,
    body: SlotId,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots,
    T: DatagramIo,
{
    let Some(transfer) = engine.rx_body_transfer(body) else {
        return Ok(());
    };
    let Ok(block) = BlockValue::new(transfer.window_base(), true, transfer.szx()) else {
        return Ok(());
    };
    send_followup(
        engine,
        io,
        lives,
        ids,
        oscore,
        now_ms,
        parsed.token(),
        peer,
        None,
        &[block],
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn recover_qblock2<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    inbox: &mut ClientInbox,
    lives: &mut ClientLives,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
    recover: crate::storage::QBlockRecover,
) -> Result<bool, Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots + ObserveSlots,
    T: DatagramIo,
{
    let call = Call::new(recover.key().token(), recover.key().endpoint());
    if lives.get(call).is_none() {
        return Ok(false);
    }
    let mut nums = [0; crate::storage::BlockTransfer::MAX_PAYLOADS as usize];
    let count = recover.copy_missing_nums(&mut nums);
    let mut blocks = [BlockValue::new(0, false, 0).expect("valid block");
        crate::storage::BlockTransfer::MAX_PAYLOADS as usize];
    for (block, num) in blocks.iter_mut().zip(&nums[..count]) {
        *block = BlockValue::new(*num, false, recover.szx())
            .map_err(BlockTransferError::from)
            .map_err(Error::Block)?;
    }
    let outcome = send_followup(
        engine,
        io,
        lives,
        ids,
        oscore,
        now_ms,
        call.token(),
        call.peer(),
        None,
        &blocks[..count],
        Some(Type::NonConfirmable),
    );
    if outcome.is_err() {
        abandon_send(engine, oscore, call.token(), call.peer());
        fail_call(
            engine,
            inbox,
            lives,
            oscore,
            call,
            CallFailure::ContinuationFailed,
            true,
        );
    }
    outcome.map(|()| true)
}

#[allow(clippy::too_many_arguments)]
fn send_followup<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    lives: &ClientLives,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
    token: Token,
    peer: Endpoint,
    block2: Option<BlockValue>,
    q_block2: &[BlockValue],
    recovery_ty: Option<Type>,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges,
    T: DatagramIo,
{
    let live = lives.get(Call::new(token, peer));
    let ty = recovery_ty.unwrap_or_else(|| live.map(|live| live.ty).unwrap_or(Type::Confirmable));
    let code = live.map(|live| live.code).unwrap_or(Code::GET);
    let mut opts = OptionsBuilder::<
        { CLIENT_OPTION_SLOTS + crate::storage::BlockTransfer::MAX_PAYLOADS as usize - 1 },
    >::new();
    let accept = live.and_then(|live| live.accept).map(ContentFormat::encode);
    let no_response = live
        .and_then(|live| live.no_response)
        .map(crate::message::NoResponse::encode);
    let b2 = block2.map(BlockValue::encode);
    let mut q2 = [encode_uint(0); crate::storage::BlockTransfer::MAX_PAYLOADS as usize];
    if q_block2.len() > q2.len() {
        return Err(Error::Message(SlotMessageError::Encode(
            EncodeError::OptionsFull,
        )));
    }
    for (encoded, block) in q2.iter_mut().zip(q_block2) {
        *encoded = block.encode();
    }
    let fetch = live
        .as_ref()
        .filter(|live| live.code == Code::FETCH)
        .and_then(|live| live.request_identity.as_ref())
        .map(|identity| {
            crate::message::decode(&identity.bytes[..identity.len])
                .expect("encoded request identity")
        });
    let cf = live
        .and_then(|live| live.content_format)
        .map(ContentFormat::encode);
    let filled = (|| -> Result<(), EncodeError> {
        if let Some(live) = live.as_ref() {
            if let Some(tag) = live.if_match.as_slice() {
                push_opt(&mut opts, Opt::if_match(tag))?;
            }
            if live.if_none_match {
                push_opt(&mut opts, Opt::if_none_match())?;
            }
            // RFC 9177 section 4.4: Q missing requests avoid ETag validation
            // replies (2.03) without payload. Classic Block2 retains it.
            if q_block2.is_empty() {
                if let Some(tag) = live.etag.as_slice() {
                    push_opt(&mut opts, Opt::etag(tag))?;
                }
            }
        }
        if let Some(ref encoded) = cf {
            push_opt(&mut opts, Opt::content_format(encoded))?;
        }
        if let Some(live) = live.as_ref() {
            for segment in live.path.segments() {
                push_opt(&mut opts, Opt::uri_path(segment))?;
            }
        }
        if let Some(live) = live.as_ref() {
            for query in live.queries.values() {
                push_opt(&mut opts, Opt::uri_query(query))?;
            }
        }
        if let Some(ref encoded) = accept {
            push_opt(&mut opts, Opt::accept(encoded))?;
        }
        if let Some(ref encoded) = b2 {
            push_opt(&mut opts, Opt::block2(encoded))?;
        }
        for encoded in &q2[..q_block2.len()] {
            push_opt(&mut opts, Opt::q_block2(encoded))?;
        }
        if let Some(ref value) = no_response {
            push_opt(&mut opts, Opt::no_response(value))?;
        }
        if let Some(echo) = live.as_ref().and_then(|live| live.echo.as_ref()) {
            push_opt(&mut opts, Opt::echo(echo.as_slice()))?;
        }
        if let Some(tag) = live.as_ref().and_then(|live| live.request_tag.as_slice()) {
            push_opt(&mut opts, Opt::request_tag(tag))?;
        }
        Ok(())
    })();
    if let Err(e) = filled {
        return Err(Error::Message(SlotMessageError::Encode(e)));
    }
    let mid = ids.next_for(engine, now_ms)?;
    let msg = Message::new(ty, code, mid)
        .with_token(token)
        .with_options(opts.as_slice())
        .with_payload(
            fetch
                .as_ref()
                .map(|request| request.payload())
                .unwrap_or(&[]),
        );
    let Some(tx) = engine.acquire_tx() else {
        return Err(Error::Saturated);
    };
    if let Err(e) = super::oscore::encode_request(oscore, engine, tx, &msg) {
        let _ = engine.release_tx(tx);
        return Err(e);
    }
    match engine.record_request(tx, peer) {
        Ok(Some(_)) => {}
        Ok(None) => {
            let _ = engine.release_tx(tx);
            return Err(Error::Saturated);
        }
        Err(e) => {
            let _ = engine.release_tx(tx);
            return Err(e.into());
        }
    }
    let pending = (ty == Type::Confirmable).then_some((now_ms, mid, ids.jitter()));
    super::finish_send(engine, io, tx, peer, pending)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn reissue_qblock1_missing<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    lives: &ClientLives,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
    parsed: &ParsedMessage<'_>,
    peer: Endpoint,
    body: SlotId,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots,
    T: DatagramIo,
{
    let mut nums = [0; crate::storage::BlockTransfer::MAX_PAYLOADS as usize];
    let Ok(count) = crate::message::MissingBlocks::decode(parsed.payload(), &mut nums) else {
        return Ok(()); // RFC 9177 section 5: silently drop malformed ordering.
    };
    let Some(transfer) = engine.tx_body_transfer(body) else {
        return Ok(());
    };
    // Preflight the entire report, including only previously issued payloads.
    // A valid first NUM cannot cause output before an invalid later NUM.
    for &num in &nums[..count] {
        if num >= transfer.next_num() || engine.reissue_q_block1(body, num).is_err() {
            return Ok(());
        }
    }
    let Some(live) = lives.get(Call::new(parsed.token(), peer)) else {
        return Ok(());
    };
    let mut queries = [""; MAX_PATH_SEGMENTS];
    let mut query_n = 0;
    for query in live.queries.values() {
        queries[query_n] = query;
        query_n += 1;
    }
    for &num in &nums[..count] {
        let issued = engine.reissue_q_block1(body, num).map_err(Error::Block)?;
        send_block1_issued(
            engine,
            io,
            ids,
            oscore,
            now_ms,
            peer,
            Type::NonConfirmable,
            live.code,
            parsed.token(),
            live.path.segments(),
            &queries[..query_n],
            live.accept,
            live.content_format,
            live.echo,
            issued,
            true,
            None,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn continue_qblock1_ack<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    inbox: &mut ClientInbox,
    lives: &mut ClientLives,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
    mid: MessageId,
    peer: Endpoint,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots + ObserveSlots,
    T: DatagramIo,
{
    // Called only after a matching pending CON was taken. Duplicate/wrong
    // endpoint/MID ACKs cannot drive the next payload.
    let Some(entry) = exchange_for_mid(engine, mid, peer) else {
        return Ok(());
    };
    let call = Call::new(entry.token(), peer);
    let Some(live) = lives.get(call) else {
        return Ok(());
    };
    if live.ty != Type::Confirmable {
        return Ok(());
    }
    let Some(body) = upload_body(engine, lives.upload_key(call)) else {
        return Ok(());
    };
    let Some(transfer) = engine.tx_body_transfer(body) else {
        return Ok(());
    };
    if transfer.role() != BlockRole::OutgoingQBlock1 || transfer.is_complete() {
        return Ok(());
    }
    let outcome = (|| {
        if transfer.window_mask() == (1u16 << crate::storage::BlockTransfer::MAX_PAYLOADS) - 1 {
            // Every earlier payload was individually ACKed before the next
            // was issued, so this ACK confirms the entire current set.
            engine
                .ack_q_block1(body, transfer.num())
                .map_err(Error::Block)?;
        }
        continue_block1_tx(
            engine,
            io,
            lives,
            ids,
            oscore,
            now_ms,
            call.token(),
            None,
            peer,
            body,
        )
    })();
    if outcome.is_err() {
        abandon_send(engine, oscore, call.token(), peer);
        fail_call(
            engine,
            inbox,
            lives,
            oscore,
            call,
            CallFailure::ContinuationFailed,
            true,
        );
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn continue_block1_tx<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    lives: &ClientLives,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
    token: Token,
    q_ack: Option<BlockValue>,
    peer: Endpoint,
    body: SlotId,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots,
    T: DatagramIo,
{
    let Some(transfer) = engine.tx_body_transfer(body) else {
        return Ok(());
    };
    if transfer.is_complete() {
        return Ok(());
    }
    let live = lives.get(Call::new(token, peer));
    let ty = live.map(|live| live.ty).unwrap_or(Type::Confirmable);
    let code = live.map(|live| live.code).unwrap_or(Code::PUT);
    let path = live.map(|live| live.path);
    let content_format = live.and_then(|live| live.content_format);
    let echo = live.and_then(|live| live.echo);
    let segments: &[&str] = path.as_ref().map_or(&[], Path::segments);
    let mut queries = [""; MAX_PATH_SEGMENTS];
    let mut query_n = 0;
    if let Some(live) = live.as_ref() {
        for query in live.queries.values() {
            queries[query_n] = query;
            query_n += 1;
        }
    }
    let accept = live.and_then(|live| live.accept);
    match transfer.role() {
        BlockRole::OutgoingBlock1 => {
            let _ = engine.take_exchange(ExchangeKey::new(token, peer));
            issue_block1(
                engine,
                io,
                ids,
                oscore,
                now_ms,
                peer,
                ty,
                code,
                token,
                segments,
                &queries[..query_n],
                accept,
                content_format,
                echo,
                body,
                None,
            )
        }
        BlockRole::OutgoingQBlock1 => {
            if let Some(q) = q_ack {
                engine.ack_q_block1(body, q.num()).map_err(Error::Block)?;
            }
            issue_q_block1_window(
                engine,
                io,
                ids,
                oscore,
                now_ms,
                peer,
                ty,
                code,
                token,
                segments,
                &queries[..query_n],
                accept,
                content_format,
                echo,
                body,
                None,
                Some((token, peer)),
            )
            .map(|_| ())
        }
        _ => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn issue_block1<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
    dest: Endpoint,
    ty: Type,
    code: Code,
    token: Token,
    path: &[&str],
    queries: &[&str],
    accept: Option<ContentFormat>,
    content_format: Option<ContentFormat>,
    echo: Option<crate::message::Echo>,
    body: SlotId,
    tx: Option<SlotId>,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots,
    T: DatagramIo,
{
    let issued = engine.next_block1(body).map_err(Error::Block)?;
    send_block1_issued(
        engine,
        io,
        ids,
        oscore,
        now_ms,
        dest,
        ty,
        code,
        token,
        path,
        queries,
        accept,
        content_format,
        echo,
        issued,
        false,
        tx,
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_q_block1_window<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
    dest: Endpoint,
    first_ty: Type,
    code: Code,
    token: Token,
    path: &[&str],
    queries: &[&str],
    accept: Option<ContentFormat>,
    content_format: Option<ContentFormat>,
    echo: Option<crate::message::Echo>,
    body: SlotId,
    mut tx: Option<SlotId>,
    take_first: Option<(Token, Endpoint)>,
) -> Result<bool, Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots,
    T: DatagramIo,
{
    let mut sent = false;
    loop {
        let issued = match engine.next_q_block1(body) {
            Ok(issued) => issued,
            Err(BlockTransferError::OutsideWindow) => return Ok(sent),
            Err(e) => return Err(Error::Block(e)),
        };
        if !sent {
            if let Some((tok, ep)) = take_first {
                let _ = engine.take_exchange(ExchangeKey::new(tok, ep));
            }
        }
        let ty = first_ty;
        send_block1_issued(
            engine,
            io,
            ids,
            oscore,
            now_ms,
            dest,
            ty,
            code,
            token,
            path,
            queries,
            accept,
            content_format,
            echo,
            issued,
            true,
            tx.take(),
        )?;
        sent = true;
        // CON uploads have one outstanding payload; the matching empty ACK
        // opens the next send. NON retains its bounded payload-set burst.
        if first_ty == Type::Confirmable || issued.complete() {
            return Ok(true);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn send_block1_issued<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    ids: &mut AppIds,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
    dest: Endpoint,
    ty: Type,
    code: Code,
    token: Token,
    path: &[&str],
    queries: &[&str],
    accept: Option<ContentFormat>,
    content_format: Option<ContentFormat>,
    echo: Option<crate::message::Echo>,
    issued: OutgoingBlock,
    q_block1: bool,
    tx: Option<SlotId>,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots,
    T: DatagramIo,
{
    let mut chunk = [0u8; 1024];
    let n = copy_tx_range(engine, issued, &mut chunk).map_err(Error::Block)?;
    let tag = engine
        .tx_body_transfer(issued.id())
        .map(|t| t.identity())
        .unwrap_or(BodyTag::ABSENT);
    let size1 = engine
        .tx_body_transfer(issued.id())
        .map(|t| t.filled())
        .and_then(|len| u32::try_from(len).ok());
    let tx = match tx {
        Some(tx) => tx,
        None => engine.acquire_tx().ok_or(Error::Saturated)?,
    };
    let mid = match ids.next_for(engine, now_ms) {
        Ok(mid) => mid,
        Err(error) => {
            let _ = engine.release_tx(tx);
            return Err(error);
        }
    };
    let cf = content_format.map(ContentFormat::encode);
    let acc = accept.map(ContentFormat::encode);
    let blk = issued.block().encode();
    let size = size1.map(encode_uint);
    let mut opts = OptionsBuilder::<CLIENT_OPTION_SLOTS>::new();
    let filled = (|| -> Result<(), EncodeError> {
        for segment in path {
            push_opt(&mut opts, Opt::uri_path(segment))?;
        }
        if let Some(ref encoded) = cf {
            push_opt(&mut opts, Opt::content_format(encoded))?;
        }
        for query in queries {
            push_opt(&mut opts, Opt::uri_query(query))?;
        }
        if let Some(ref encoded) = acc {
            push_opt(&mut opts, Opt::accept(encoded))?;
        }
        if q_block1 {
            push_opt(&mut opts, Opt::q_block1(&blk))?;
        } else {
            push_opt(&mut opts, Opt::block1(&blk))?;
        }
        if let Some(ref encoded) = size {
            push_opt(&mut opts, Opt::size1(encoded))?;
        }
        if let Some(echo) = echo.as_ref() {
            push_opt(&mut opts, Opt::echo(echo.as_slice()))?;
        }
        if let Some(tag) = tag.as_slice() {
            push_opt(&mut opts, Opt::request_tag(tag))?;
        }
        Ok(())
    })();
    if let Err(e) = filled {
        let _ = engine.release_tx(tx);
        return Err(Error::Message(SlotMessageError::Encode(e)));
    }
    let msg = Message::new(ty, code, mid)
        .with_token(token)
        .with_options(opts.as_slice())
        .with_payload(&chunk[..n]);
    if let Err(e) = super::oscore::encode_request(oscore, engine, tx, &msg) {
        let _ = engine.release_tx(tx);
        return Err(e);
    }
    finish_client_send(engine, io, tx, dest, ty, now_ms, mid, ids.jitter())
}

#[allow(clippy::too_many_arguments)]
fn finish_client_send<Mem, T>(
    engine: &mut Engine<Mem>,
    io: &mut T,
    tx: SlotId,
    dest: Endpoint,
    ty: Type,
    now_ms: u64,
    mid: MessageId,
    jitter: u32,
) -> Result<(), Error<T::Error>>
where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges,
    T: DatagramIo,
{
    match engine.record_request(tx, dest) {
        Ok(Some(_)) => {}
        Ok(None) => {
            let _ = engine.release_tx(tx);
            return Err(Error::Saturated);
        }
        Err(e) => {
            let _ = engine.release_tx(tx);
            return Err(e.into());
        }
    }
    let pending = (ty == Type::Confirmable).then_some((now_ms, mid, jitter));
    match super::finish_send(engine, io, tx, dest, pending) {
        Ok(()) => Ok(()),
        Err(e) => {
            drop_exchange_for_tx(engine, tx);
            Err(e)
        }
    }
}

// A send can fail after earlier Q-Block datagrams went out. No Call is
// returned, so retire all local state owned by this request. Never rewind
// OSCORE sequence numbers: a transport error does not prove non-delivery.
fn abandon_send<Mem>(
    engine: &mut Engine<Mem>,
    oscore: &mut super::oscore::Field,
    token: Token,
    peer: Endpoint,
) where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots,
{
    let _ = engine.take_exchange(ExchangeKey::new(token, peer));
    for i in 0..engine.capacities().tx_datagram_slots {
        let id = SlotId::from_index(i);
        let Some(pending) = engine.pending_con(id) else {
            continue;
        };
        if engine.tx_endpoint(id) == Some(peer)
            && engine
                .decode_tx(id)
                .is_ok_and(|message| message.token() == token && message.code().is_request())
        {
            let _ = engine.take_pending_con(pending.message_id(), peer);
            let _ = engine.release_tx(id);
        }
    }
    for i in 0..engine.capacities().tx_body_slots.unwrap_or(0) {
        let id = SlotId::from_index(i);
        if engine.tx_body_transfer(id).is_some_and(|transfer| {
            transfer.key().token() == token
                && transfer.key().endpoint() == peer
                && matches!(
                    transfer.role(),
                    BlockRole::OutgoingBlock1 | BlockRole::OutgoingQBlock1
                )
        }) {
            let _ = engine.release_tx_body(id);
        }
    }
    super::oscore::cancel(oscore, token);
}

fn drop_exchange_for_tx<Mem: Storage + Exchanges>(engine: &mut Engine<Mem>, tx: SlotId) {
    let n = engine.capacities().tx_datagram_slots;
    for i in 0..n {
        let id = SlotId::from_index(i);
        let Some(entry) = engine.exchange_entry(id) else {
            continue;
        };
        if entry.tx_slot() != tx {
            continue;
        }
        let _ = engine.take_exchange(entry.key());
        return;
    }
}

fn copy_tx_range<Mem: Storage + BodySlots>(
    engine: &Engine<Mem>,
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

fn upload_body<Mem: Storage + BodySlots>(engine: &Engine<Mem>, key: BlockKey) -> Option<SlotId> {
    engine
        .lookup_tx_body_role(key, BlockRole::OutgoingBlock1)
        .or_else(|| engine.lookup_tx_body_role(key, BlockRole::OutgoingQBlock1))
}

fn rx_body_payload<Mem: Storage + BodySlots>(engine: &Engine<Mem>, id: SlotId) -> Option<&[u8]> {
    engine.rx_body_payload(id)
}

fn release_rx_body<Mem: Storage + BodySlots>(engine: &mut Engine<Mem>, id: SlotId) {
    let _ = engine.release_rx_body(id);
}

fn client_observe_live<Mem: Storage + ObserveSlots>(engine: &Engine<Mem>, call: Call) -> bool {
    let key = ObserveKey::new_client(call.token(), call.peer());
    engine.lookup_observe(key).is_some()
}

fn accept_client_observe<Mem>(
    engine: &mut Engine<Mem>,
    lives: &ClientLives,
    parsed: &ParsedMessage<'_>,
    peer: Endpoint,
    now_ms: u64,
    via_exchange: bool,
) where
    Mem: Storage + ObserveSlots,
{
    let key = ObserveKey::new_client(parsed.token(), peer);
    let live = lives.get(Call::new(parsed.token(), peer));
    if live.is_some_and(|live| live.observe == OutgoingObserve::Deregister) {
        let _ = engine.take_observe(key);
        return;
    }
    let subscribed = live.is_some_and(|live| live.observe == OutgoingObserve::Register)
        || engine.lookup_observe(key).is_some();
    if subscribed && parsed.observe().and_then(Result::ok).is_some() && parsed.code().is_success() {
        let _ = engine.insert_observe(ObserveInterest::new_client(parsed.token(), peer));
        let max_age = parsed
            .max_age()
            .and_then(Result::ok)
            .unwrap_or(super::DEFAULT_MAX_AGE_SECS);
        let _ = engine.refresh_observe_max_age(key, now_ms, max_age, None);
    } else if via_exchange || subscribed {
        let _ = engine.take_observe(key);
    }
}

/// Retransmission give-up completes the call rather than silently losing it.
pub(crate) fn give_up_client<Mem>(
    engine: &mut Engine<Mem>,
    inbox: &mut ClientInbox,
    lives: &mut ClientLives,
    oscore: &mut super::oscore::Field,
    tx: SlotId,
) where
    Mem: Storage + DatagramSlots + Exchanges + BodySlots + ObserveSlots + PendingCons,
{
    if let Some(entry) = exchange_for_tx(engine, tx) {
        fail_call(
            engine,
            inbox,
            lives,
            oscore,
            Call::new(entry.token(), entry.endpoint()),
            CallFailure::TimedOut,
            false,
        );
    }
}

fn exchange_for_tx<Mem: Storage + Exchanges>(
    engine: &Engine<Mem>,
    tx: SlotId,
) -> Option<ExchangeEntry> {
    let n = engine.capacities().tx_datagram_slots;
    (0..n).find_map(|i| {
        let entry = engine.exchange_entry(SlotId::from_index(i))?;
        (entry.tx_slot() == tx).then_some(entry)
    })
}

fn exchange_for_mid<Mem: Storage + Exchanges>(
    engine: &Engine<Mem>,
    message_id: MessageId,
    peer: Endpoint,
) -> Option<ExchangeEntry> {
    let n = engine.capacities().tx_datagram_slots;
    (0..n).find_map(|i| {
        let entry = engine.exchange_entry(SlotId::from_index(i))?;
        (entry.message_id() == message_id && entry.endpoint() == peer).then_some(entry)
    })
}

// Retire a timed-out Q download in the same poll that reclaims its body.
// The inbox must not keep a partial SlotId that another transfer can reuse.
pub(crate) fn qblock_give_up<Mem>(
    engine: &mut Engine<Mem>,
    inbox: &mut ClientInbox,
    lives: &mut ClientLives,
    oscore: &mut super::oscore::Field,
    key: ExchangeKey,
) where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots + ObserveSlots,
{
    let call = Call::new(key.token(), key.endpoint());
    if lives.get(call).is_some() {
        fail_call(
            engine,
            inbox,
            lives,
            oscore,
            call,
            CallFailure::TimedOut,
            true,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn fail_call<Mem>(
    engine: &mut Engine<Mem>,
    inbox: &mut ClientInbox,
    lives: &mut ClientLives,
    oscore: &mut super::oscore::Field,
    call: Call,
    failure: CallFailure,
    release_pending: bool,
) where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots + ObserveSlots,
{
    let key = ExchangeKey::new(call.token(), call.peer());
    if let Some(entry) = engine.take_exchange(key) {
        // NON/empty ACK may have released and reused the old TX slot. Only
        // a matching pending CON still establishes ownership of that slot.
        if release_pending {
            if let Some(tx) = engine.take_pending_con(entry.message_id(), entry.endpoint()) {
                let _ = engine.release_tx(tx);
            }
        }
    }
    let _ = engine.take_observe(ObserveKey::new_client(call.token(), call.peer()));
    if let Ok(Some(body)) = inbox.insert(call, Err(failure), None) {
        let _ = engine.release_rx_body(body);
    }
    for i in 0..engine.capacities().rx_body_slots.unwrap_or(0) {
        let id = SlotId::from_index(i);
        if engine.rx_body_transfer(id).is_some_and(|transfer| {
            transfer.key().token() == call.token()
                && transfer.key().endpoint() == call.peer()
                && matches!(
                    transfer.role(),
                    BlockRole::IncomingBlock2 | BlockRole::IncomingQBlock2
                )
        }) {
            let _ = engine.release_rx_body(id);
        }
    }
    if let Some(body) = upload_body(engine, lives.upload_key(call)) {
        if engine.tx_body_transfer(body).is_some_and(|transfer| {
            matches!(
                transfer.role(),
                BlockRole::OutgoingBlock1 | BlockRole::OutgoingQBlock1
            )
        }) {
            let _ = engine.release_tx_body(body);
        }
    }
    super::oscore::cancel(oscore, call.token());
    // Untaken failures occupy the same bounded completion budget as replies.
    for live in lives
        .rows
        .iter_mut()
        .flatten()
        .filter(|live| live.call == call)
    {
        live.due_ms = 0;
        live.deadline_ms = None;
    }
}

pub(crate) fn complete_client_rst<Mem>(
    engine: &mut Engine<Mem>,
    inbox: &mut ClientInbox,
    lives: &mut ClientLives,
    oscore: &mut super::oscore::Field,
    message_id: MessageId,
    peer: Endpoint,
) where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots + ObserveSlots,
{
    let entry = engine
        .lookup_pending_con(message_id, peer)
        .and_then(|tx| exchange_for_tx(engine, tx))
        .or_else(|| exchange_for_mid(engine, message_id, peer));
    if let Some(entry) = entry {
        fail_call(
            engine,
            inbox,
            lives,
            oscore,
            Call::new(entry.token(), entry.endpoint()),
            CallFailure::Reset,
            false,
        );
    }
}

pub(crate) fn expire_client_exchanges<Mem>(
    engine: &mut Engine<Mem>,
    inbox: &mut ClientInbox,
    lives: &mut ClientLives,
    oscore: &mut super::oscore::Field,
    now_ms: u64,
) where
    Mem: Storage + DatagramSlots + PendingCons + Exchanges + BodySlots + ObserveSlots,
{
    let mut due = [None; RESPONSE_INBOX];
    for (i, live) in lives.rows.iter().enumerate() {
        let Some(live) = *live else {
            continue;
        };
        if inbox.contains(live.call) && !client_observe_live(engine, live.call) {
            continue;
        }
        let failure = if live.deadline_ms.is_some_and(|deadline| now_ms >= deadline) {
            Some(CallFailure::DeadlineExceeded)
        } else if live.due_ms != 0
            && now_ms >= live.due_ms
            && engine
                .lookup_exchange(ExchangeKey::new(live.call.token(), live.call.peer()))
                .is_some()
        {
            Some(CallFailure::TimedOut)
        } else {
            None
        };
        due[i] = failure.map(|failure| (live.call, failure));
    }
    for (call, failure) in due.into_iter().flatten() {
        fail_call(engine, inbox, lives, oscore, call, failure, true);
    }
}
