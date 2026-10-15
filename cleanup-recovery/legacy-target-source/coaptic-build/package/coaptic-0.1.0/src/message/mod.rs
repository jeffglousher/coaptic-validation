//! CoAP messages: header, token, options, and payload.
//!
//! [`decode`] and [`encode`] operate on a datagram buffer (the UDP payload).
//! They do not require [`crate::storage::Engine`]. The [`crate::App`] happy
//! path does not call these directly — handlers see [`crate::Request`] /
//! [`crate::Response`].
//!
//! [`Ids`] is a wrapping Message ID counter; [`Token::mint`] copies caller
//! entropy ([`TokenSource`]). The core does not call an OS RNG.
//! [`OptionsBuilder`] collects [`Opt`] values in any order.
//! [`ProblemDetails`] is RFC 9290 concise problem details (crate-root;
//! [`crate::Response::problem`]). [`MissingBlocks`] is RFC 9177
//! missing-blocks CBOR-seq ([`crate::Response::missing_blocks`]).
//! [`Echo`] is RFC 9175; App applies 4.01 when
//! [`crate::app::AppBuilder::echo_policy`] is set. [`BlockValue`] SZX 7
//! is Engine BERT (future / backlog on the App face).
//!
//! Optional, not used by [`decode`]:
//! [`ParsedMessage::check_rfc7252_options`] (Table 4 unrecognized
//! critical), [`ParsedMessage::unknown_critical`] (implemented stack),
//! and [`ParsedMessage::check_rfc7252_formats`] (known option, wrong
//! format). [`crate::App`] 4.02s [`ParsedMessage::unknown_critical`] and
//! an OSCORE option with no attached context.
//!
//! Wire format lives in `knowledge/rfcs/`. This module does not restate it.

mod builder;
mod decode;
mod echo;
mod encode;
mod hop;
mod id;
mod missing_blocks;
mod no_response;
mod option;
mod precondition;
mod problem;
pub mod value;

#[cfg(test)]
mod tests;

pub use builder::OptionsBuilder;
pub use decode::{ParsedMessage, decode};
pub use echo::{Echo, EchoFreshness};
#[cfg(feature = "oscore")]
pub(crate) use encode::write_option;
pub use encode::{Message, encode};
pub use hop::HopLimit;
pub use id::{Ids, TokenSource};
pub use missing_blocks::{MissingBlocks, MissingBlocksError};
pub use no_response::NoResponse;
pub use option::{Opt, OptionNumber, Options};
pub use precondition::Precondition;
pub use problem::{ProblemDetails, ProblemError, ProblemOptions, ProblemText, WritingDirection};
pub use value::{
    BlockOptions, BlockValue, ContentFormat, EncodedUint, OBSERVE_DEREGISTER, OBSERVE_REGISTER,
    OBSERVE_SEQUENCE_MASK, OpaqueOptions, OptionValueFormat, OptionsByNumber, StringOptions,
    decode_block, decode_observe, decode_uint, decode_uint16, encode_block, encode_observe,
    encode_uint,
};

pub use crate::error::{OptionsFull, ValueError};

use core::fmt;

/// CoAP message type (header T field).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Type {
    /// Confirmable (CON).
    Confirmable,
    /// Non-confirmable (NON).
    NonConfirmable,
    /// Acknowledgement (ACK).
    Acknowledgement,
    /// Reset (RST).
    Reset,
}

impl Type {
    /// Decode the 2-bit T field. `None` if `bits` is outside 0..=3.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Confirmable),
            1 => Some(Self::NonConfirmable),
            2 => Some(Self::Acknowledgement),
            3 => Some(Self::Reset),
            _ => None,
        }
    }

    /// Encode as the 2-bit T field.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::Confirmable => 0,
            Self::NonConfirmable => 1,
            Self::Acknowledgement => 2,
            Self::Reset => 3,
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Confirmable => "CON",
            Self::NonConfirmable => "NON",
            Self::Acknowledgement => "ACK",
            Self::Reset => "RST",
        })
    }
}

/// 16-bit CoAP Message ID.
///
/// Sequence generation is [`Ids`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MessageId(u16);

impl MessageId {
    /// Wrap a raw Message ID.
    #[must_use]
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    /// Raw Message ID.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Wrapping add. [`Ids`] holds the counter when minting a stream of IDs.
    #[must_use]
    pub const fn wrapping_add(self, n: u16) -> Self {
        Self(self.0.wrapping_add(n))
    }
}

impl From<u16> for MessageId {
    fn from(id: u16) -> Self {
        Self(id)
    }
}

/// CoAP Token (0–8 bytes).
///
/// Construct with [`Token::new`] or [`Token::mint`]. Lengths above
/// [`Token::MAX_LEN`] are rejected. After a bound check (decode TKL,
/// mint length), use [`Token::from_checked`]. Minting uses caller
/// entropy; the core does not call an OS RNG.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Token {
    bytes: [u8; 8],
    len: u8,
}

impl Token {
    /// Empty token (TKL 0).
    pub const EMPTY: Self = Self {
        bytes: [0; 8],
        len: 0,
    };

    /// Maximum Token length in bytes (RFC 7252 TKL).
    pub const MAX_LEN: usize = 8;

    /// Copy `bytes` into a token. `None` if `bytes` is longer than [`Self::MAX_LEN`].
    #[inline]
    #[must_use]
    pub const fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > Self::MAX_LEN {
            None
        } else {
            Some(Self::from_checked(bytes))
        }
    }

    /// Copy at most [`Self::MAX_LEN`] bytes. Does not allocate or panic.
    ///
    /// [`decode`] uses this after the TKL nibble and
    /// remaining-length checks. Prefer [`Self::new`] when the length is not
    /// already proven. Longer input is truncated to [`Self::MAX_LEN`].
    #[inline]
    #[must_use]
    pub const fn from_checked(bytes: &[u8]) -> Self {
        let n = if bytes.len() > Self::MAX_LEN {
            Self::MAX_LEN
        } else {
            bytes.len()
        };
        let mut token = Self::EMPTY;
        let mut i = 0;
        while i < n {
            token.bytes[i] = bytes[i];
            i += 1;
        }
        token.len = n as u8;
        token
    }

    /// Token length in bytes (0–8).
    #[inline]
    #[must_use]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Whether the token is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Token bytes, without padding.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl Default for Token {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Token").field(&self.as_bytes()).finish()
    }
}

/// CoAP Code (`class.detail`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Code(u8);

const fn pack_code(class: u8, detail: u8) -> u8 {
    (class << 5) | detail
}

impl Code {
    /// Empty message (0.00).
    pub const EMPTY: Self = Self(0);
    /// GET (0.01).
    pub const GET: Self = Self(1);
    /// POST (0.02).
    pub const POST: Self = Self(2);
    /// PUT (0.03).
    pub const PUT: Self = Self(3);
    /// DELETE (0.04).
    pub const DELETE: Self = Self(4);
    /// FETCH (0.05). RFC 8132. The library does not invent FETCH policy.
    pub const FETCH: Self = Self(5);
    /// PATCH (0.06). RFC 8132. The library does not invent PATCH policy.
    pub const PATCH: Self = Self(6);
    /// iPATCH (0.07). RFC 8132. The library does not invent iPATCH policy.
    pub const IPATCH: Self = Self(7);

    /// 2.01 Created.
    pub const CREATED: Self = Self(pack_code(2, 1));
    /// 2.02 Deleted.
    pub const DELETED: Self = Self(pack_code(2, 2));
    /// 2.03 Valid.
    pub const VALID: Self = Self(pack_code(2, 3));
    /// 2.04 Changed.
    pub const CHANGED: Self = Self(pack_code(2, 4));
    /// 2.05 Content.
    pub const CONTENT: Self = Self(pack_code(2, 5));
    /// 2.31 Continue (RFC 7959). The library does not invent when to send it.
    pub const CONTINUE: Self = Self(pack_code(2, 31));

    /// 4.00 Bad Request.
    pub const BAD_REQUEST: Self = Self(pack_code(4, 0));
    /// 4.01 Unauthorized.
    pub const UNAUTHORIZED: Self = Self(pack_code(4, 1));
    /// 4.02 Bad Option.
    pub const BAD_OPTION: Self = Self(pack_code(4, 2));
    /// 4.03 Forbidden.
    pub const FORBIDDEN: Self = Self(pack_code(4, 3));
    /// 4.04 Not Found.
    pub const NOT_FOUND: Self = Self(pack_code(4, 4));
    /// 4.05 Method Not Allowed.
    pub const METHOD_NOT_ALLOWED: Self = Self(pack_code(4, 5));
    /// 4.06 Not Acceptable.
    pub const NOT_ACCEPTABLE: Self = Self(pack_code(4, 6));
    /// 4.08 Request Entity Incomplete (RFC 7959 / RFC 9177).
    ///
    /// The library does not invent 4.08 policy.
    pub const REQUEST_ENTITY_INCOMPLETE: Self = Self(pack_code(4, 8));
    /// 4.09 Conflict (RFC 8132). The library does not invent 4.09 policy.
    pub const CONFLICT: Self = Self(pack_code(4, 9));
    /// 4.12 Precondition Failed.
    pub const PRECONDITION_FAILED: Self = Self(pack_code(4, 12));
    /// 4.13 Request Entity Too Large.
    pub const REQUEST_ENTITY_TOO_LARGE: Self = Self(pack_code(4, 13));
    /// 4.15 Unsupported Content-Format.
    pub const UNSUPPORTED_CONTENT_FORMAT: Self = Self(pack_code(4, 15));
    /// 4.22 Unprocessable Entity (RFC 8132). The library does not invent 4.22 policy.
    pub const UNPROCESSABLE_ENTITY: Self = Self(pack_code(4, 22));

    /// 5.00 Internal Server Error.
    pub const INTERNAL_SERVER_ERROR: Self = Self(pack_code(5, 0));
    /// 5.01 Not Implemented.
    pub const NOT_IMPLEMENTED: Self = Self(pack_code(5, 1));
    /// 5.02 Bad Gateway.
    pub const BAD_GATEWAY: Self = Self(pack_code(5, 2));
    /// 5.03 Service Unavailable.
    pub const SERVICE_UNAVAILABLE: Self = Self(pack_code(5, 3));
    /// 5.04 Gateway Timeout.
    pub const GATEWAY_TIMEOUT: Self = Self(pack_code(5, 4));
    /// 5.05 Proxying Not Supported.
    pub const PROXYING_NOT_SUPPORTED: Self = Self(pack_code(5, 5));
    /// 5.08 Hop Limit Reached (RFC 8768). The library does not invent 5.08 policy.
    pub const HOP_LIMIT_REACHED: Self = Self(pack_code(5, 8));

    /// Wrap a raw code byte.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// Build from class (0–7) and detail (0–31).
    #[must_use]
    pub const fn from_class_detail(class: u8, detail: u8) -> Option<Self> {
        if class > 7 || detail > 31 {
            None
        } else {
            Some(Self(pack_code(class, detail)))
        }
    }

    /// Raw code byte.
    #[must_use]
    pub const fn as_raw(self) -> u8 {
        self.0
    }

    /// 3-bit class.
    #[must_use]
    pub const fn class(self) -> u8 {
        self.0 >> 5
    }

    /// 5-bit detail.
    #[must_use]
    pub const fn detail(self) -> u8 {
        self.0 & 0x1f
    }

    /// Code 0.00.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Request method (class 0, not empty).
    #[must_use]
    pub const fn is_request(self) -> bool {
        self.class() == 0 && !self.is_empty()
    }

    /// Safe request method (GET / FETCH). Responses are not safe.
    ///
    /// See `knowledge/rfcs/rfc7252.txt` and `knowledge/rfcs/rfc8132.txt`.
    #[must_use]
    pub const fn is_safe(self) -> bool {
        matches!(self, Self::GET | Self::FETCH)
    }

    /// Idempotent request method (GET / PUT / DELETE / FETCH / iPATCH).
    ///
    /// Responses are not idempotent. See `knowledge/rfcs/rfc7252.txt` and
    /// `knowledge/rfcs/rfc8132.txt`.
    #[must_use]
    pub const fn is_idempotent(self) -> bool {
        matches!(
            self,
            Self::GET | Self::PUT | Self::DELETE | Self::FETCH | Self::IPATCH
        )
    }

    /// Response (class 2, 4, or 5).
    #[must_use]
    pub const fn is_response(self) -> bool {
        matches!(self.class(), 2 | 4 | 5)
    }

    /// Class 2.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.class() == 2
    }

    /// Class 4.
    #[must_use]
    pub const fn is_client_error(self) -> bool {
        self.class() == 4
    }

    /// Class 5.
    #[must_use]
    pub const fn is_server_error(self) -> bool {
        self.class() == 5
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02}", self.class(), self.detail())
    }
}

/// Parsed 4-byte CoAP header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    version: u8,
    ty: Type,
    tkl: u8,
    code: Code,
    id: MessageId,
}

impl Header {
    /// Version field. Successful [`decode`] yields 1.
    #[must_use]
    pub const fn version(self) -> u8 {
        self.version
    }

    /// Message type.
    #[must_use]
    pub const fn ty(self) -> Type {
        self.ty
    }

    /// Token length nibble (0–8 after a successful [`decode`]).
    #[must_use]
    pub const fn token_length(self) -> u8 {
        self.tkl
    }

    /// Code.
    #[must_use]
    pub const fn code(self) -> Code {
        self.code
    }

    /// Message ID.
    #[must_use]
    pub const fn message_id(self) -> MessageId {
        self.id
    }

    pub(crate) const fn new(version: u8, ty: Type, tkl: u8, code: Code, id: MessageId) -> Self {
        Self {
            version,
            ty,
            tkl,
            code,
            id,
        }
    }
}

/// Empty ACK for `id`. See [`Message::empty_ack`].
#[must_use]
pub const fn empty_ack(id: MessageId) -> Message<'static> {
    Message::empty_ack(id)
}

/// Empty RST for `id`. See [`Message::empty_rst`].
#[must_use]
pub const fn empty_rst(id: MessageId) -> Message<'static> {
    Message::empty_rst(id)
}

/// RFC 7252 §4.8 defaults plus the initial-RTO helper.
///
/// The core does not draw randomness. Callers pass jitter into
/// [`Self::initial_timeout_ms`] (or `0` for the ACK_TIMEOUT floor).
/// Scheduling is [`crate::storage::PendingCon`] / [`crate::storage::Engine::poll_retransmit`].
/// See `knowledge/rfcs/rfc7252.txt` §4.2 / §4.8.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transmission;

impl Transmission {
    /// `ACK_TIMEOUT` in milliseconds.
    pub const ACK_TIMEOUT_MS: u32 = 2_000;
    /// `ACK_RANDOM_FACTOR` numerator (`3 / 2` = 1.5).
    pub const ACK_RANDOM_FACTOR_NUM: u16 = 3;
    /// `ACK_RANDOM_FACTOR` denominator (`3 / 2` = 1.5).
    pub const ACK_RANDOM_FACTOR_DEN: u16 = 2;
    /// Extra milliseconds jitter may add (`ACK_TIMEOUT * (ACK_RANDOM_FACTOR - 1)`).
    pub const ACK_RANDOM_SPAN_MS: u32 = Self::ACK_TIMEOUT_MS / Self::ACK_RANDOM_FACTOR_DEN as u32
        * (Self::ACK_RANDOM_FACTOR_NUM - Self::ACK_RANDOM_FACTOR_DEN) as u32;
    /// `MAX_RETRANSMIT`.
    pub const MAX_RETRANSMIT: u8 = 4;
    /// `NSTART`.
    pub const NSTART: u8 = 1;
    /// `MAX_TRANSMIT_SPAN` (milliseconds). RFC 7252 §4.8.2 default.
    pub const MAX_TRANSMIT_SPAN_MS: u32 = 45_000;
    /// `EXCHANGE_LIFETIME` (milliseconds). RFC 7252 §4.8.2 default.
    pub const EXCHANGE_LIFETIME_MS: u32 = 247_000;
    /// `NON_LIFETIME` (milliseconds). RFC 7252 §4.8.2 default.
    pub const NON_LIFETIME_MS: u32 = 145_000;

    /// Initial timeout: `ACK_TIMEOUT` plus `min(jitter_ms, ACK_RANDOM_SPAN_MS)`.
    ///
    /// `jitter_ms = 0` is the RFC minimum. The core does not call an RNG;
    /// the caller supplies jitter (or a deterministic value).
    #[must_use]
    pub const fn initial_timeout_ms(jitter_ms: u32) -> u32 {
        let extra = if jitter_ms > Self::ACK_RANDOM_SPAN_MS {
            Self::ACK_RANDOM_SPAN_MS
        } else {
            jitter_ms
        };
        Self::ACK_TIMEOUT_MS.saturating_add(extra)
    }
}

/// RFC 7641 §4.5 / §4.5.1 notification transmission constants.
///
/// Colocated on [`crate::storage::ObserveInterest`]. The core does not send and does
/// not invent RST / 4.02 policy. See `knowledge/rfcs/rfc7641.txt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObserveTransmission;

impl ObserveTransmission {
    /// 24 hours in milliseconds. A mostly-NON notifier must send CON this often.
    pub const CONFIRM_INTERVAL_MS: u64 = 24 * 60 * 60 * 1_000;
    /// Default NON notify spacing when the caller has no RTT estimate.
    pub const NON_TIMEOUT_MS: u32 = 3_000;
}

/// RFC 9177 §7.2 NON receive-pacing defaults.
///
/// The caller owns the clock (`now_ms`). Engine arms
/// [`crate::storage::QBlockReceiveWait`] on an incoming Q-Block sidecar
/// ([`crate::storage::Engine::note_q_receive`] or the first
/// [`crate::storage::Engine::progress`] that sees holes) and surfaces
/// [`crate::storage::QBlockRecover`] when [`Self::NON_RECEIVE_TIMEOUT_MS`]
/// (exponentially doubled) is due. App::poll sends Q-Block2 recover or
/// Q-Block1 4.08 missing-blocks. See `knowledge/rfcs/rfc9177.txt` §7.2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QBlockTransmission;

impl QBlockTransmission {
    /// `NON_TIMEOUT` (same default as [`Transmission::ACK_TIMEOUT_MS`]).
    pub const NON_TIMEOUT_MS: u32 = Transmission::ACK_TIMEOUT_MS;
    /// `NON_RECEIVE_TIMEOUT` (twice [`Self::NON_TIMEOUT_MS`]).
    pub const NON_RECEIVE_TIMEOUT_MS: u32 = Self::NON_TIMEOUT_MS.saturating_mul(2);
    /// `NON_MAX_RETRANSMIT` (same default as [`Transmission::MAX_RETRANSMIT`]).
    pub const NON_MAX_RETRANSMIT: u8 = Transmission::MAX_RETRANSMIT;
}
