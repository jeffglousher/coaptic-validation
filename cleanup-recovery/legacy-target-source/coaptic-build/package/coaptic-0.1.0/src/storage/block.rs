//! Block / Q-Block transfer sidecar for a body slot.
//!
//! Each occupied Incoming / Outgoing Body Slot holds one contiguous body and
//! the Block or Q-Block state for that body. Individual CoAP
//! messages stay in ordinary datagram slots. Incoming and outgoing Q-Block1 /
//! Q-Block2 use a fixed `MAX_PAYLOADS` window (RFC 9177 §7.2 default 10).
//! Incoming window holes surface as [`QBlockRecover`] when
//! [`QBlockReceiveWait`] is due; outgoing reissue reads the complete body
//! without changing window state. BERT (SZX 7) packs multiple 1024-byte
//! ranges into one payload. Request-Tag / ETag body identity lives on
//! [`BlockKey`]. CON RTO lives on [`super::PendingCon`], not on this sidecar.
//! Q-Block `NON_RECEIVE_TIMEOUT` lives on [`QBlockReceiveWait`] here. See
//! `knowledge/rfcs/rfc7959.txt`,
//! `knowledge/rfcs/rfc9175.txt`, `knowledge/rfcs/rfc9177.txt`, and
//! `knowledge/rfcs/rfc8323.txt`.

use super::Access;
use super::AccessMut;
use super::endpoint::Endpoint;
use super::slot::{SlotError, SlotId};
use crate::error::{BlockTransferError, ValueError};
use crate::message::{BlockValue, QBlockTransmission, Token};

/// Request-Tag or ETag body identity (opaque, 0..=8 bytes).
///
/// [`Self::ABSENT`] is distinct from a present empty Request-Tag
/// (`knowledge/rfcs/rfc9175.txt`). ETag uses the same storage (1..=8 on the
/// wire). Not a seventh core area; sidecar on [`BlockKey`] / [`BlockTransfer`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BodyTag {
    bytes: [u8; 8],
    /// `0xff` = absent. `0..=8` = present with that length.
    n: u8,
}

impl BodyTag {
    /// No Request-Tag / ETag on the wire.
    pub const ABSENT: Self = Self {
        bytes: [0; 8],
        n: 0xff,
    };

    /// Present empty Request-Tag (zero-length option).
    pub const EMPTY: Self = Self {
        bytes: [0; 8],
        n: 0,
    };

    /// Present tag from `bytes` (0..=8).
    pub fn new(bytes: &[u8]) -> Result<Self, ValueError> {
        if bytes.len() > 8 {
            return Err(ValueError::OpaqueLength);
        }
        let mut tag = Self::EMPTY;
        tag.n = bytes.len() as u8;
        tag.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(tag)
    }

    /// First Request-Tag or ETag value, or [`Self::ABSENT`].
    pub fn from_first(bytes: Option<&[u8]>) -> Result<Self, ValueError> {
        match bytes {
            None => Ok(Self::ABSENT),
            Some(b) => Self::new(b),
        }
    }

    /// Whether this is the absent option (not a present empty value).
    #[must_use]
    pub const fn is_absent(self) -> bool {
        self.n == 0xff
    }

    /// Present value bytes, or `None` when absent.
    #[must_use]
    pub fn as_slice(&self) -> Option<&[u8]> {
        if self.n > 8 {
            None
        } else {
            Some(&self.bytes[..self.n as usize])
        }
    }
}

/// Lookup identity for one block-wise body.
///
/// Token plus the remote [`Endpoint`] is the RFC 7252 match. [`BodyTag`] is
/// Request-Tag (request body) or ETag (response body). This is not a Dedup
/// key (Message ID) and not a seventh core area; it is sidecar on the body
/// slot. Request/response transfer roles are matched separately; identical
/// keys can coexist in opposite directions. See `knowledge/rfcs/rfc9175.txt`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BlockKey {
    token: Token,
    endpoint: Endpoint,
    identity: BodyTag,
}

impl BlockKey {
    /// Identity for one Token at `endpoint` with absent Request-Tag / ETag.
    #[must_use]
    pub const fn new(token: Token, endpoint: Endpoint) -> Self {
        Self {
            token,
            endpoint,
            identity: BodyTag::ABSENT,
        }
    }

    /// Same Token and endpoint with `identity` (Request-Tag or ETag).
    #[must_use]
    pub const fn with_identity(self, identity: BodyTag) -> Self {
        Self { identity, ..self }
    }

    /// Token of the block-wise exchange.
    #[must_use]
    pub const fn token(self) -> Token {
        self.token
    }

    /// Remote endpoint of the block-wise exchange.
    #[must_use]
    pub const fn endpoint(self) -> Endpoint {
        self.endpoint
    }

    /// Request-Tag or ETag stored for this body. Absent is a distinct value.
    #[must_use]
    pub const fn identity(self) -> BodyTag {
        self.identity
    }
}

/// Which body-pool direction this sidecar describes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BlockRole {
    /// Incoming Block1: client → server request body.
    IncomingBlock1,
    /// Incoming Block2: server → client response body.
    IncomingBlock2,
    /// Incoming Q-Block1: client → server request body (RFC 9177 window).
    IncomingQBlock1,
    /// Incoming Q-Block2: server → client response body (RFC 9177 window).
    IncomingQBlock2,
    /// Outgoing Block1: client → server request body.
    OutgoingBlock1,
    /// Outgoing Block2: server → client response body.
    OutgoingBlock2,
    /// Outgoing Q-Block1: client → server request body (RFC 9177 window).
    OutgoingQBlock1,
    /// Outgoing Q-Block2: server → client response body (RFC 9177 window).
    OutgoingQBlock2,
}

impl BlockRole {
    /// Incoming Block1 / Block2 / Q-Block1 / Q-Block2 (RX body pool).
    #[must_use]
    pub const fn is_incoming(self) -> bool {
        matches!(
            self,
            Self::IncomingBlock1
                | Self::IncomingBlock2
                | Self::IncomingQBlock1
                | Self::IncomingQBlock2
        )
    }

    /// Outgoing Block1 / Block2 / Q-Block1 / Q-Block2 (TX body pool).
    #[must_use]
    pub const fn is_outgoing(self) -> bool {
        matches!(
            self,
            Self::OutgoingBlock1
                | Self::OutgoingBlock2
                | Self::OutgoingQBlock1
                | Self::OutgoingQBlock2
        )
    }

    /// Incoming or outgoing Q-Block1 / Q-Block2.
    #[must_use]
    pub const fn is_q_block(self) -> bool {
        matches!(
            self,
            Self::IncomingQBlock1
                | Self::IncomingQBlock2
                | Self::OutgoingQBlock1
                | Self::OutgoingQBlock2
        )
    }
}

/// Result of writing one incoming Block1 / Block2 range into a body slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockProgress {
    id: SlotId,
    filled: usize,
    complete: bool,
}

impl BlockProgress {
    pub(crate) const fn new(id: SlotId, filled: usize, complete: bool) -> Self {
        Self {
            id,
            filled,
            complete,
        }
    }

    /// Body slot that holds this transfer.
    #[must_use]
    pub const fn id(self) -> SlotId {
        self.id
    }

    /// Bytes assembled so far (complete-body length when [`Self::complete`]).
    #[must_use]
    pub const fn filled(self) -> usize {
        self.filled
    }

    /// Whether M=0 was accepted and the length is consistent.
    #[must_use]
    pub const fn complete(self) -> bool {
        self.complete
    }
}

/// One issued outgoing Block / Q-Block range. Bytes live in the body slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutgoingBlock {
    id: SlotId,
    block: BlockValue,
    offset: usize,
    len: usize,
    complete: bool,
}

impl OutgoingBlock {
    pub(crate) const fn new(
        id: SlotId,
        block: BlockValue,
        offset: usize,
        len: usize,
        complete: bool,
    ) -> Self {
        Self {
            id,
            block,
            offset,
            len,
            complete,
        }
    }

    /// Body slot that holds the complete body.
    #[must_use]
    pub const fn id(self) -> SlotId {
        self.id
    }

    /// NUM / M / SZX for this issued block.
    #[must_use]
    pub const fn block(self) -> BlockValue {
        self.block
    }

    /// Byte offset of this block in the complete body.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Payload length of this block.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len
    }

    /// Whether this issued block has no payload bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Whether this was the last block (M=0).
    #[must_use]
    pub const fn complete(self) -> bool {
        self.complete
    }
}

/// One incoming Q-Block missing-block recover opportunity.
///
/// Gaps are unset bits in the current `MAX_PAYLOADS` window that are already
/// known missing: below the highest received NUM in that window, or at/before
/// the M=0 NUM. [`hole_mask`](Self::hole_mask) bit `i` is window-relative
/// (`window_base + i`). The core does not send and does not invent 4.08 /
/// 2.31 / RST. [`Engine::progress`](super::Engine::progress) surfaces this
/// only when [`QBlockReceiveWait`] is due (caller `now_ms`). Incoming Q-Block2
/// recover uses repeatable Q-Block2 options (RFC 9177 §4.4); incoming
/// Q-Block1 4.08 encoding stays with the caller (App uses missing-blocks).
///
/// See `knowledge/rfcs/rfc9177.txt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QBlockRecover {
    id: SlotId,
    key: BlockKey,
    role: BlockRole,
    missing_num: u32,
    hole_mask: u16,
    window_base: u32,
    szx: u8,
}

impl QBlockRecover {
    pub(crate) const fn new(
        id: SlotId,
        key: BlockKey,
        role: BlockRole,
        missing_num: u32,
        hole_mask: u16,
        window_base: u32,
        szx: u8,
    ) -> Self {
        Self {
            id,
            key,
            role,
            missing_num,
            hole_mask,
            window_base,
            szx,
        }
    }

    /// Incoming body slot that holds this transfer.
    #[must_use]
    pub const fn id(self) -> SlotId {
        self.id
    }

    /// Token + endpoint identity of the transfer.
    #[must_use]
    pub const fn key(self) -> BlockKey {
        self.key
    }

    /// Incoming Q-Block1 or Q-Block2 role.
    #[must_use]
    pub const fn role(self) -> BlockRole {
        self.role
    }

    /// First known missing NUM (ascending).
    #[must_use]
    pub const fn missing_num(self) -> u32 {
        self.missing_num
    }

    /// Known holes in the current window (`bit i` is `window_base + i`).
    #[must_use]
    pub const fn hole_mask(self) -> u16 {
        self.hole_mask
    }

    /// First NUM of the current Q-Block window.
    #[must_use]
    pub const fn window_base(self) -> u32 {
        self.window_base
    }

    /// SZX locked for this transfer (used when encoding recover options).
    #[must_use]
    pub const fn szx(self) -> u8 {
        self.szx
    }

    /// How many known missing NUMs are in [`Self::hole_mask`].
    #[must_use]
    pub const fn missing_count(self) -> u8 {
        self.hole_mask.count_ones() as u8
    }

    /// Whether `num` is a known hole in this window.
    #[must_use]
    pub const fn contains(self, num: u32) -> bool {
        if num < self.window_base {
            return false;
        }
        let idx = num - self.window_base;
        if idx >= BlockTransfer::MAX_PAYLOADS as u32 {
            return false;
        }
        self.hole_mask & (1u16 << idx) != 0
    }

    /// Copy known missing NUMs (ascending) into `out`. Returns how many written.
    pub fn copy_missing_nums(self, out: &mut [u32]) -> usize {
        let mut n = 0usize;
        let mut i = 0u32;
        while i < u32::from(BlockTransfer::MAX_PAYLOADS) && n < out.len() {
            if self.hole_mask & (1u16 << i) != 0 {
                out[n] = self.window_base + i;
                n += 1;
            }
            i += 1;
        }
        n
    }
}

/// Incoming Q-Block `NON_RECEIVE_TIMEOUT` wait (RFC 9177 §7.2).
///
/// The caller owns the clock. [`Self::new`] arms from `now_ms` +
/// [`QBlockTransmission::NON_RECEIVE_TIMEOUT_MS`]. [`Engine::progress`](super::Engine::progress)
/// fires [`QBlockRecover`] when [`Self::is_due`]; each fire doubles the wait
/// (same posture as [`super::PendingRto`]). After
/// [`QBlockTransmission::NON_MAX_RETRANSMIT`] recovers without a filling
/// receive, progress releases the partial body. See
/// `knowledge/rfcs/rfc9177.txt` §7.2.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QBlockReceiveWait {
    attempts: u8,
    next_timeout_ms: u64,
    timeout_ms: u32,
}

impl QBlockReceiveWait {
    /// Initial wait: recover counter 0, due at `now_ms + NON_RECEIVE_TIMEOUT`.
    #[must_use]
    pub const fn new(now_ms: u64) -> Self {
        let timeout_ms = QBlockTransmission::NON_RECEIVE_TIMEOUT_MS;
        Self {
            attempts: 0,
            timeout_ms,
            next_timeout_ms: now_ms.saturating_add(timeout_ms as u64),
        }
    }

    /// Recover requests already sent for this wait (0 after arm / last receive).
    #[must_use]
    pub const fn attempts(self) -> u8 {
        self.attempts
    }

    /// Absolute millisecond time when this wait fires (`now_ms` domain).
    #[must_use]
    pub const fn next_timeout_ms(self) -> u64 {
        self.next_timeout_ms
    }

    /// Current wait duration in milliseconds.
    #[must_use]
    pub const fn timeout_ms(self) -> u32 {
        self.timeout_ms
    }

    /// Whether `now_ms` is at or past [`Self::next_timeout_ms`].
    #[must_use]
    pub const fn is_due(self, now_ms: u64) -> bool {
        now_ms >= self.next_timeout_ms
    }

    /// After a due recover: doubled wait and incremented counter, or `None`
    /// when [`QBlockTransmission::NON_MAX_RETRANSMIT`] is already reached.
    ///
    /// Next due is `now_ms` plus the doubled timeout (late polls shift the
    /// schedule; the core does not burst catch-up).
    #[must_use]
    pub const fn next_attempt(self, now_ms: u64) -> Option<Self> {
        if self.attempts >= QBlockTransmission::NON_MAX_RETRANSMIT {
            return None;
        }
        let timeout_ms = self.timeout_ms.saturating_mul(2);
        Some(Self {
            attempts: self.attempts.saturating_add(1),
            timeout_ms,
            next_timeout_ms: now_ms.saturating_add(timeout_ms as u64),
        })
    }
}

/// Current Q-Block `MAX_PAYLOADS_SET` (RFC 9177 §2 / §7.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QWindow {
    base: u32,
    mask: u16,
    final_num: Option<u32>,
    final_payload_len: u16,
}

/// Exact bounded request matchability context, not a hash. Token/MID and block
/// control options may change, but method and cache-key options may not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestBinding {
    bytes: [u8; BlockTransfer::REQUEST_IDENTITY_BYTES],
    len: u16,
}
impl RequestBinding {
    pub(crate) fn from_message(
        message: &crate::message::ParsedMessage<'_>,
    ) -> Result<Self, BlockTransferError> {
        use crate::message::{OptionNumber as N, OptionValueFormat};
        let mut binding = Self {
            bytes: [0; BlockTransfer::REQUEST_IDENTITY_BYTES],
            len: 1,
        };
        binding.bytes[0] = message.code().as_raw();
        for option in message.options() {
            let number = option.number();
            if number.is_no_cache_key()
                || matches!(number, N::BLOCK1 | N::BLOCK2 | N::Q_BLOCK1 | N::Q_BLOCK2)
            {
                continue;
            }
            let mut value = option.value();
            if option.value_format() == Some(OptionValueFormat::Uint) {
                // RFC 7252 uint encodings with leading zeros have equal values.
                while value.first() == Some(&0) {
                    value = &value[1..];
                }
            }
            let start = usize::from(binding.len);
            let end = start
                .checked_add(4)
                .and_then(|n| n.checked_add(value.len()))
                .ok_or(BlockTransferError::Overflow)?;
            if end > binding.bytes.len() {
                return Err(BlockTransferError::Overflow);
            }
            binding.bytes[start..start + 2].copy_from_slice(&number.get().to_be_bytes());
            binding.bytes[start + 2..start + 4]
                .copy_from_slice(&(value.len() as u16).to_be_bytes());
            binding.bytes[start + 4..end].copy_from_slice(value);
            binding.len = end as u16;
        }
        Ok(binding)
    }
}

/// Block transfer sidecar stored next to one body-slot buffer.
///
/// Classic Block is in-order: the next NUM must be [`Self::next_num`]. Incoming
/// Q-Block tracks a [`Self::MAX_PAYLOADS`]-wide bitmap on the current window
/// and allows out-of-order NUMs inside that window. Outgoing Q-Block issues
/// unsent NUMs in that same window (increasing NUM; RFC 9177 §4.3) and
/// advances on a peer window ACK. BERT (SZX 7) is classic Block with
/// multi-block payloads. See `knowledge/rfcs/rfc7959.txt`,
/// `knowledge/rfcs/rfc9177.txt`, and `knowledge/rfcs/rfc8323.txt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockTransfer {
    key: BlockKey,
    role: BlockRole,
    num: u32,
    szx: u8,
    more: bool,
    next_num: u32,
    filled: usize,
    complete: bool,
    expected_len: Option<u32>,
    q: Option<QWindow>,
    q_receive: Option<QBlockReceiveWait>,
    pub(crate) request_binding: Option<RequestBinding>,
    // Highest authenticated request PIV and its Token for timed Q-Block1 reports.
    #[cfg(feature = "oscore")]
    pub(crate) oscore_request: Option<(Token, crate::oscore::RequestRef)>,
}

impl BlockTransfer {
    /// RFC 9177 §7.2 default `MAX_PAYLOADS`; this crate's Q-Block window size.
    pub const MAX_PAYLOADS: u8 = 10;

    /// Maximum retained method/cache-key bytes for datagram request assembly.
    /// Each option uses four framing bytes plus its value. Larger identities
    /// are refused before body mutation. Direct range APIs leave matching to
    /// their caller; RX-datagram APIs retain this context in the body sidecar.
    pub const REQUEST_IDENTITY_BYTES: usize = 512;

    /// Incoming sidecar after the first accepted block.
    ///
    /// `role` must be [`BlockRole::IncomingBlock1`] or
    /// [`BlockRole::IncomingBlock2`]. Classic Block starts at NUM 0.
    pub fn incoming(
        key: BlockKey,
        role: BlockRole,
        block: BlockValue,
        payload_len: usize,
        capacity: usize,
        expected_len: Option<u32>,
    ) -> Result<Self, BlockTransferError> {
        if !role.is_incoming() || role.is_q_block() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        if block.num() != 0 {
            return Err(BlockTransferError::Gap);
        }
        let mut transfer = Self {
            key,
            role,
            num: 0,
            szx: block.szx(),
            more: block.more(),
            next_num: 0,
            filled: 0,
            complete: false,
            expected_len,
            q: None,
            q_receive: None,
            request_binding: None,
            #[cfg(feature = "oscore")]
            oscore_request: None,
        };
        transfer.accept_incoming(block, payload_len, capacity)?;
        Ok(transfer)
    }

    /// Incoming Block1 sidecar after the first accepted block.
    pub fn incoming_block1(
        key: BlockKey,
        block: BlockValue,
        payload_len: usize,
        capacity: usize,
        expected_len: Option<u32>,
    ) -> Result<Self, BlockTransferError> {
        Self::incoming(
            key,
            BlockRole::IncomingBlock1,
            block,
            payload_len,
            capacity,
            expected_len,
        )
    }

    /// Incoming Block2 sidecar after the first accepted block.
    pub fn incoming_block2(
        key: BlockKey,
        block: BlockValue,
        payload_len: usize,
        capacity: usize,
        expected_len: Option<u32>,
    ) -> Result<Self, BlockTransferError> {
        Self::incoming(
            key,
            BlockRole::IncomingBlock2,
            block,
            payload_len,
            capacity,
            expected_len,
        )
    }

    /// Incoming Q-Block sidecar after the first accepted block.
    ///
    /// `role` must be [`BlockRole::IncomingQBlock1`] or
    /// [`BlockRole::IncomingQBlock2`]. The first datagram may be any NUM in
    /// window 0 (`0..MAX_PAYLOADS`). See `knowledge/rfcs/rfc9177.txt`.
    pub fn incoming_q(
        key: BlockKey,
        role: BlockRole,
        block: BlockValue,
        payload_len: usize,
        capacity: usize,
        expected_len: Option<u32>,
    ) -> Result<Self, BlockTransferError> {
        if !role.is_incoming() || !role.is_q_block() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        if block.is_bert() {
            return Err(BlockTransferError::Value(ValueError::IllegalSzx));
        }
        let mut transfer = Self {
            key,
            role,
            num: 0,
            szx: block.szx(),
            more: block.more(),
            next_num: 0,
            filled: 0,
            complete: false,
            expected_len,
            q: Some(QWindow {
                base: 0,
                mask: 0,
                final_num: None,
                final_payload_len: 0,
            }),
            q_receive: None,
            request_binding: None,
            #[cfg(feature = "oscore")]
            oscore_request: None,
        };
        transfer.accept_q_incoming(block, payload_len, capacity)?;
        Ok(transfer)
    }

    /// Incoming Q-Block1 sidecar after the first accepted block.
    pub fn incoming_q_block1(
        key: BlockKey,
        block: BlockValue,
        payload_len: usize,
        capacity: usize,
        expected_len: Option<u32>,
    ) -> Result<Self, BlockTransferError> {
        Self::incoming_q(
            key,
            BlockRole::IncomingQBlock1,
            block,
            payload_len,
            capacity,
            expected_len,
        )
    }

    /// Incoming Q-Block2 sidecar after the first accepted block.
    pub fn incoming_q_block2(
        key: BlockKey,
        block: BlockValue,
        payload_len: usize,
        capacity: usize,
        expected_len: Option<u32>,
    ) -> Result<Self, BlockTransferError> {
        Self::incoming_q(
            key,
            BlockRole::IncomingQBlock2,
            block,
            payload_len,
            capacity,
            expected_len,
        )
    }

    /// Outgoing sidecar for a complete body already in the slot.
    ///
    /// `role` must be [`BlockRole::OutgoingBlock1`] or
    /// [`BlockRole::OutgoingBlock2`].
    pub fn outgoing(
        key: BlockKey,
        role: BlockRole,
        body_len: usize,
        szx: u8,
        capacity: usize,
    ) -> Result<Self, BlockTransferError> {
        if !role.is_outgoing() || role.is_q_block() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        Self::outgoing_common(key, role, body_len, szx, capacity, None)
    }

    /// Outgoing Q-Block sidecar for a complete body already in the slot.
    ///
    /// `role` must be [`BlockRole::OutgoingQBlock1`] or
    /// [`BlockRole::OutgoingQBlock2`]. Issues stay inside the current
    /// `MAX_PAYLOADS` window until [`Self::ack_q_window`]. See
    /// `knowledge/rfcs/rfc9177.txt`.
    pub fn outgoing_q(
        key: BlockKey,
        role: BlockRole,
        body_len: usize,
        szx: u8,
        capacity: usize,
    ) -> Result<Self, BlockTransferError> {
        if !role.is_outgoing() || !role.is_q_block() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        if szx == BlockValue::SZX_BERT {
            return Err(BlockTransferError::Value(ValueError::IllegalSzx));
        }
        Self::outgoing_common(
            key,
            role,
            body_len,
            szx,
            capacity,
            Some(QWindow {
                base: 0,
                mask: 0,
                final_num: None,
                final_payload_len: 0,
            }),
        )
    }

    fn outgoing_common(
        key: BlockKey,
        role: BlockRole,
        body_len: usize,
        szx: u8,
        capacity: usize,
        q: Option<QWindow>,
    ) -> Result<Self, BlockTransferError> {
        let _ = BlockValue::size_from_szx(szx)?;
        if body_len > capacity {
            return Err(BlockTransferError::Overflow);
        }
        if let Ok(len) = u32::try_from(body_len) {
            Ok(Self {
                key,
                role,
                num: 0,
                szx,
                more: false,
                next_num: 0,
                filled: body_len,
                complete: false,
                expected_len: Some(len),
                q,
                q_receive: None,
                request_binding: None,
                #[cfg(feature = "oscore")]
                oscore_request: None,
            })
        } else {
            Err(BlockTransferError::Overflow)
        }
    }

    /// Outgoing Block1 sidecar for a complete body already in the slot.
    pub fn outgoing_block1(
        key: BlockKey,
        body_len: usize,
        szx: u8,
        capacity: usize,
    ) -> Result<Self, BlockTransferError> {
        Self::outgoing(key, BlockRole::OutgoingBlock1, body_len, szx, capacity)
    }

    /// Outgoing Block2 sidecar for a complete body already in the slot.
    pub fn outgoing_block2(
        key: BlockKey,
        body_len: usize,
        szx: u8,
        capacity: usize,
    ) -> Result<Self, BlockTransferError> {
        Self::outgoing(key, BlockRole::OutgoingBlock2, body_len, szx, capacity)
    }

    /// Outgoing Q-Block1 sidecar for a complete body already in the slot.
    pub fn outgoing_q_block1(
        key: BlockKey,
        body_len: usize,
        szx: u8,
        capacity: usize,
    ) -> Result<Self, BlockTransferError> {
        Self::outgoing_q(key, BlockRole::OutgoingQBlock1, body_len, szx, capacity)
    }

    /// Outgoing Q-Block2 sidecar for a complete body already in the slot.
    pub fn outgoing_q_block2(
        key: BlockKey,
        body_len: usize,
        szx: u8,
        capacity: usize,
    ) -> Result<Self, BlockTransferError> {
        Self::outgoing_q(key, BlockRole::OutgoingQBlock2, body_len, szx, capacity)
    }

    /// Lookup identity.
    #[must_use]
    pub const fn key(self) -> BlockKey {
        self.key
    }

    /// Token of the transfer.
    #[must_use]
    pub const fn token(self) -> Token {
        self.key.token()
    }

    /// Remote endpoint of the transfer.
    #[must_use]
    pub const fn endpoint(self) -> Endpoint {
        self.key.endpoint()
    }

    /// Request-Tag or ETag stored on this transfer.
    #[must_use]
    pub const fn identity(self) -> BodyTag {
        self.key.identity()
    }

    /// Incoming or outgoing Block / Q-Block role.
    #[must_use]
    pub const fn role(self) -> BlockRole {
        self.role
    }

    /// Whether this transfer is locked to BERT (SZX 7).
    #[must_use]
    pub const fn is_bert(self) -> bool {
        self.szx == BlockValue::SZX_BERT
    }

    /// Whether this sidecar is a Q-Block window (incoming or outgoing).
    #[must_use]
    pub const fn is_q_block(self) -> bool {
        self.role.is_q_block()
    }

    /// Last accepted (incoming) or last issued (outgoing) NUM.
    #[must_use]
    pub const fn num(self) -> u32 {
        self.num
    }

    /// SZX locked for this transfer.
    #[must_use]
    pub const fn szx(self) -> u8 {
        self.szx
    }

    /// M flag of the last accepted or issued block.
    #[must_use]
    pub const fn more(self) -> bool {
        self.more
    }

    /// Next NUM classic Block will accept or issue.
    #[must_use]
    pub const fn next_num(self) -> u32 {
        self.next_num
    }

    /// Bytes assembled (incoming) or complete-body length (outgoing).
    #[must_use]
    pub const fn filled(self) -> usize {
        self.filled
    }

    /// Whether the transfer has accepted M=0 or issued the last outgoing block.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.complete
    }

    /// Initial Size1 / Size2 indication, or the outgoing body length.
    ///
    /// Classic Block (including BERT) treats this as an estimate; completion
    /// follows M=0 and actual bytes remain bounded by the body slot. Q-Block
    /// requires an exact body length.
    #[must_use]
    pub const fn expected_len(self) -> Option<u32> {
        self.expected_len
    }

    /// First NUM of the current Q-Block window (`MAX_PAYLOADS_SET`).
    #[must_use]
    pub const fn window_base(self) -> u32 {
        match self.q {
            Some(q) => q.base,
            None => 0,
        }
    }

    /// Bitmask of received NUMs in the current window (`bit i` is `base + i`).
    #[must_use]
    pub const fn window_mask(self) -> u16 {
        match self.q {
            Some(q) => q.mask,
            None => 0,
        }
    }

    /// Known incoming Q-Block holes in the current window, if any.
    ///
    /// Returns `(first_missing_num, hole_mask)` when the transfer is
    /// incomplete and at least one unset bit sits below the highest received
    /// NUM, or at/before the M=0 NUM. A contiguous prefix with more blocks
    /// still expected is not a recover opportunity (those payloads may still
    /// be in flight). Classic Block and outgoing Q-Block return `None`.
    ///
    /// See `knowledge/rfcs/rfc9177.txt`.
    #[must_use]
    pub const fn q_holes(self) -> Option<(u32, u16)> {
        if !self.role.is_incoming() || !self.role.is_q_block() || self.complete {
            return None;
        }
        let Some(q) = self.q else {
            return None;
        };
        if q.mask == 0 {
            return None;
        }
        let max = Self::MAX_PAYLOADS as u32;
        let end = if let Some(final_num) = q.final_num {
            let idx = final_num - q.base;
            if idx >= max { max } else { idx + 1 }
        } else {
            15 - q.mask.leading_zeros()
        };
        let mut holes = 0u16;
        let mut i = 0u32;
        while i < end {
            let bit = 1u16 << i;
            if q.mask & bit == 0 {
                holes |= bit;
            }
            i += 1;
        }
        if holes == 0 {
            None
        } else {
            Some((q.base + holes.trailing_zeros(), holes))
        }
    }

    /// Armed [`QBlockReceiveWait`] for incoming Q-Block holes, if any.
    #[must_use]
    pub const fn q_receive(self) -> Option<QBlockReceiveWait> {
        self.q_receive
    }

    /// Arm or clear [`QBlockReceiveWait`] from caller `now_ms`.
    ///
    /// Holes reset the wait to [`QBlockReceiveWait::new`]. A complete window
    /// or a contiguous prefix still in flight clears it. No-op for classic
    /// Block and outgoing Q-Block. Does not send.
    pub fn note_q_receive(&mut self, now_ms: u64) {
        if !self.role.is_incoming() || !self.role.is_q_block() {
            return;
        }
        if self.q_holes().is_some() {
            self.q_receive = Some(QBlockReceiveWait::new(now_ms));
        } else {
            self.q_receive = None;
        }
    }

    /// Record a due recover: doubled wait, or `None` when max retransmit is
    /// already reached (caller should drop the partial body).
    pub fn note_q_recover(&mut self, now_ms: u64) -> Option<QBlockReceiveWait> {
        let next = self.q_receive.and_then(|wait| wait.next_attempt(now_ms))?;
        self.q_receive = Some(next);
        Some(next)
    }

    /// Accept one in-order incoming block. Returns the write offset.
    pub fn accept_incoming(
        &mut self,
        block: BlockValue,
        payload_len: usize,
        capacity: usize,
    ) -> Result<usize, BlockTransferError> {
        if !self.role.is_incoming() || self.role.is_q_block() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        if self.complete {
            return Err(BlockTransferError::AlreadyComplete);
        }
        if block.szx() != self.szx {
            return Err(BlockTransferError::SzxMismatch);
        }
        if block.num() < self.next_num {
            return Err(BlockTransferError::Overlap);
        }
        if block.num() > self.next_num {
            return Err(BlockTransferError::Gap);
        }

        if block.is_bert() {
            return self.accept_bert_incoming(block, payload_len, capacity);
        }

        let size = usize::from(block.size());
        if block.more() {
            if payload_len != size {
                return Err(BlockTransferError::PayloadLength);
            }
        } else if payload_len > size {
            return Err(BlockTransferError::PayloadLength);
        }

        let offset = block_offset(block.num(), size)?;
        let end = offset
            .checked_add(payload_len)
            .ok_or(BlockTransferError::Overflow)?;
        if end > capacity {
            return Err(BlockTransferError::Overflow);
        }

        self.num = block.num();
        self.more = block.more();
        self.filled = end;
        self.next_num = block
            .num()
            .checked_add(1)
            .ok_or(BlockTransferError::Overflow)?;
        self.complete = !block.more();
        Ok(offset)
    }

    fn accept_bert_incoming(
        &mut self,
        block: BlockValue,
        payload_len: usize,
        capacity: usize,
    ) -> Result<usize, BlockTransferError> {
        if !block.is_bert() {
            return Err(BlockTransferError::SzxMismatch);
        }
        let size = usize::from(BlockValue::SIZE_MAX);
        if block.more() && (payload_len == 0 || payload_len % size != 0) {
            return Err(BlockTransferError::PayloadLength);
        }
        let offset = block_offset(block.num(), size)?;
        let end = offset
            .checked_add(payload_len)
            .ok_or(BlockTransferError::Overflow)?;
        if end > capacity {
            return Err(BlockTransferError::Overflow);
        }

        let nblocks =
            u32::try_from(payload_len / size).map_err(|_| BlockTransferError::Overflow)?;
        self.num = block.num();
        self.more = block.more();
        self.filled = end;
        self.next_num = block
            .num()
            .checked_add(nblocks)
            .ok_or(BlockTransferError::Overflow)?;
        self.complete = !block.more();
        Ok(offset)
    }

    /// Accept one incoming Q-Block in the current window. Returns the write offset.
    ///
    /// Out-of-order NUMs inside `[window_base, window_base + MAX_PAYLOADS)` are
    /// stored. Duplicates and NUMs outside that window are rejected. The window
    /// advances when every slot in the current `MAX_PAYLOADS_SET` is filled.
    /// The body completes when the M=0 block is stored and the prefix has no
    /// gaps. See `knowledge/rfcs/rfc9177.txt`.
    pub fn accept_q_incoming(
        &mut self,
        block: BlockValue,
        payload_len: usize,
        capacity: usize,
    ) -> Result<usize, BlockTransferError> {
        if !self.role.is_q_block() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        if block.is_bert() {
            return Err(BlockTransferError::Value(ValueError::IllegalSzx));
        }
        if self.complete {
            return Err(BlockTransferError::AlreadyComplete);
        }
        if block.szx() != self.szx {
            return Err(BlockTransferError::SzxMismatch);
        }

        let expected_len = self.expected_len;
        let q = self
            .q
            .as_mut()
            .ok_or(BlockTransferError::IdentityMismatch)?;
        if block.num() < q.base {
            return Err(BlockTransferError::Duplicate);
        }
        let idx = block.num() - q.base;
        if idx >= u32::from(Self::MAX_PAYLOADS) {
            return Err(BlockTransferError::OutsideWindow);
        }
        let bit = 1u16 << idx;
        if q.mask & bit != 0 {
            return Err(BlockTransferError::Duplicate);
        }
        if let Some(final_num) = q.final_num {
            if block.num() > final_num {
                return Err(BlockTransferError::LengthInconsistent);
            }
        }
        if !block.more() {
            let after = idx.saturating_add(1);
            if after < u32::from(Self::MAX_PAYLOADS) && (q.mask >> after) != 0 {
                return Err(BlockTransferError::LengthInconsistent);
            }
        }

        let size = usize::from(block.size());
        if block.more() {
            if payload_len != size {
                return Err(BlockTransferError::PayloadLength);
            }
        } else if payload_len > size {
            return Err(BlockTransferError::PayloadLength);
        }
        let final_payload_len =
            u16::try_from(payload_len).map_err(|_| BlockTransferError::Overflow)?;

        let offset = block_offset(block.num(), size)?;
        let end = offset
            .checked_add(payload_len)
            .ok_or(BlockTransferError::Overflow)?;
        if end > capacity {
            return Err(BlockTransferError::Overflow);
        }
        if let Some(expected) = expected_len {
            let expected = usize::try_from(expected).map_err(|_| BlockTransferError::Overflow)?;
            if end > expected || (!block.more() && end != expected) {
                return Err(BlockTransferError::LengthInconsistent);
            }
        }

        q.mask |= bit;
        if !block.more() {
            q.final_num = Some(block.num());
            q.final_payload_len = final_payload_len;
        }

        let window_full = (1u16 << Self::MAX_PAYLOADS) - 1;
        while q.mask == window_full && q.final_num.is_none() {
            q.base = q
                .base
                .checked_add(u32::from(Self::MAX_PAYLOADS))
                .ok_or(BlockTransferError::Overflow)?;
            q.mask = 0;
        }

        let contig = q
            .base
            .checked_add(q.mask.trailing_ones())
            .ok_or(BlockTransferError::Overflow)?;
        if let Some(final_num) = q.final_num {
            if contig > final_num {
                self.filled = block_offset(final_num, size)?
                    .checked_add(usize::from(q.final_payload_len))
                    .ok_or(BlockTransferError::Overflow)?;
                self.complete = true;
                self.next_num = final_num
                    .checked_add(1)
                    .ok_or(BlockTransferError::Overflow)?;
            } else {
                self.filled = block_offset(contig, size)?;
                self.complete = false;
                self.next_num = contig;
            }
        } else {
            self.filled = block_offset(contig, size)?;
            self.complete = false;
            self.next_num = contig;
        }

        self.num = block.num();
        self.more = block.more();
        Ok(offset)
    }

    /// Issue the next in-order outgoing classic block. Returns `(block, offset, len)`.
    ///
    /// BERT (SZX 7) issues the remaining body as one multi-block payload.
    /// Use [`Self::issue_bert_outgoing`] to cap the datagram payload.
    pub fn issue_outgoing(&mut self) -> Result<(BlockValue, usize, usize), BlockTransferError> {
        if !self.role.is_outgoing() || self.role.is_q_block() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        if self.complete {
            return Err(BlockTransferError::AlreadyComplete);
        }
        if self.is_bert() {
            return self.issue_bert_outgoing(self.filled);
        }
        self.issue_range(self.next_num)
    }

    /// Issue one BERT payload of at most `max_payload` bytes.
    ///
    /// Non-final payloads are a positive multiple of 1024. NUM advances by
    /// `payload_len / 1024`. Q-Block is rejected. See
    /// `knowledge/rfcs/rfc8323.txt`.
    pub fn issue_bert_outgoing(
        &mut self,
        max_payload: usize,
    ) -> Result<(BlockValue, usize, usize), BlockTransferError> {
        if !self.role.is_outgoing() || self.role.is_q_block() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        if !self.is_bert() {
            return Err(BlockTransferError::SzxMismatch);
        }
        if self.complete {
            return Err(BlockTransferError::AlreadyComplete);
        }
        let size = usize::from(BlockValue::SIZE_MAX);
        let offset = block_offset(self.next_num, size)?;
        if offset > self.filled || (offset == self.filled && self.filled > 0) {
            return Err(BlockTransferError::Gap);
        }
        let remaining = self.filled - offset;
        let len = if remaining <= max_payload {
            remaining
        } else {
            (max_payload / size) * size
        };
        if remaining > 0 && len == 0 {
            return Err(BlockTransferError::PayloadLength);
        }
        if remaining > len && (len == 0 || len % size != 0) {
            return Err(BlockTransferError::PayloadLength);
        }
        let more = remaining > len;
        let block = BlockValue::bert(self.next_num, more)?;
        let nblocks = u32::try_from(len / size).map_err(|_| BlockTransferError::Overflow)?;
        self.num = self.next_num;
        self.more = more;
        self.next_num = self
            .next_num
            .checked_add(nblocks)
            .ok_or(BlockTransferError::Overflow)?;
        self.complete = !more;
        Ok((block, offset, len))
    }

    /// Issue the next unsent NUM in the current Q-Block window.
    ///
    /// Sends in increasing NUM order inside `[window_base, window_base +
    /// MAX_PAYLOADS)` (RFC 9177 §4.3). A full window with more body remaining
    /// returns [`BlockTransferError::OutsideWindow`] until [`Self::ack_q_window`].
    pub fn issue_q_outgoing(&mut self) -> Result<(BlockValue, usize, usize), BlockTransferError> {
        if !self.role.is_outgoing() || !self.role.is_q_block() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        if self.complete {
            return Err(BlockTransferError::AlreadyComplete);
        }
        let q = self.q.ok_or(BlockTransferError::IdentityMismatch)?;
        let idx = q.mask.trailing_ones();
        if idx >= u32::from(Self::MAX_PAYLOADS) {
            return Err(BlockTransferError::OutsideWindow);
        }
        let num = q
            .base
            .checked_add(idx)
            .ok_or(BlockTransferError::Overflow)?;
        self.issue_range(num)
    }

    /// Reissue one Q-Block payload from the complete body already in the slot.
    ///
    /// RFC 9177 §4.3 / §4.4: the sender retransmits a missing payload using
    /// the same NUM, SZX, and M as originally sent. The complete body remains
    /// the cached copy, so `num` may be in the current window or a previous
    /// one. Does not change window state. Does not invent 4.08 / 2.31.
    pub fn reissue_q_outgoing(
        &self,
        num: u32,
    ) -> Result<(BlockValue, usize, usize), BlockTransferError> {
        if !self.role.is_outgoing() || !self.role.is_q_block() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        self.outgoing_range(num)
    }

    /// Advance the outgoing Q-Block window after a peer window ACK.
    ///
    /// An individual empty ACK (code 0.00) is not a window ACK. A caller
    /// tracking every CON payload may advance once the whole set is confirmed.
    /// This method does not inspect response codes; otherwise the caller supplies
    /// the RFC 9177 NUM:
    ///
    /// - [`BlockRole::OutgoingQBlock1`]: `num` is the Q-Block1 NUM from a
    ///   Continue (RFC 9177 §4.3: all blocks through `num` received). Advances
    ///   when that NUM is the last of the current `MAX_PAYLOADS_SET`.
    /// - [`BlockRole::OutgoingQBlock2`]: `num` is the Continue Q-Block2 NUM
    ///   (RFC 9177 §4.4: `num % MAX_PAYLOADS == 0` and `num != 0`). Confirms
    ///   the previous set (through `num - 1`) and opens the window at `num`.
    ///
    /// Returns the body length and whether the last block has already been
    /// issued. Does not invent 2.31 / 4.08 policy.
    pub fn ack_q_window(&mut self, num: u32) -> Result<(usize, bool), BlockTransferError> {
        if !self.role.is_outgoing() || !self.role.is_q_block() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        if self.complete {
            return Err(BlockTransferError::AlreadyComplete);
        }
        let max = u32::from(Self::MAX_PAYLOADS);
        let window_full = (1u16 << Self::MAX_PAYLOADS) - 1;
        match self.role {
            BlockRole::OutgoingQBlock1 => {
                let q = self
                    .q
                    .as_mut()
                    .ok_or(BlockTransferError::IdentityMismatch)?;
                if num < q.base {
                    return Err(BlockTransferError::Duplicate);
                }
                let idx = num - q.base;
                if idx >= max {
                    return Err(BlockTransferError::OutsideWindow);
                }
                if idx != max - 1 {
                    return Err(BlockTransferError::Gap);
                }
                let needed = (1u16 << (idx + 1)) - 1;
                if q.mask & needed != needed {
                    return Err(BlockTransferError::Gap);
                }
                q.base = num.checked_add(1).ok_or(BlockTransferError::Overflow)?;
                q.mask = 0;
            }
            BlockRole::OutgoingQBlock2 => {
                if num == 0 || num % max != 0 {
                    return Err(BlockTransferError::Gap);
                }
                let q = self
                    .q
                    .as_mut()
                    .ok_or(BlockTransferError::IdentityMismatch)?;
                let next = q
                    .base
                    .checked_add(max)
                    .ok_or(BlockTransferError::Overflow)?;
                if num < next {
                    return Err(BlockTransferError::Duplicate);
                }
                if num > next {
                    return Err(BlockTransferError::OutsideWindow);
                }
                if q.mask != window_full {
                    return Err(BlockTransferError::Gap);
                }
                q.base = num;
                q.mask = 0;
            }
            _ => return Err(BlockTransferError::IdentityMismatch),
        }
        Ok((self.filled, self.complete))
    }

    fn outgoing_range(&self, num: u32) -> Result<(BlockValue, usize, usize), BlockTransferError> {
        let size = usize::from(BlockValue::size_from_szx(self.szx)?);
        let offset = block_offset(num, size)?;
        if offset > self.filled || (offset == self.filled && self.filled > 0) {
            return Err(BlockTransferError::Gap);
        }
        let remaining = self.filled - offset;
        let len = remaining.min(size);
        let more = remaining > size;
        let block = BlockValue::new(num, more, self.szx)?;
        Ok((block, offset, len))
    }

    fn issue_range(&mut self, num: u32) -> Result<(BlockValue, usize, usize), BlockTransferError> {
        if let Some(q) = self.q.as_ref() {
            if num < q.base {
                return Err(BlockTransferError::Duplicate);
            }
            let idx = num - q.base;
            if idx >= u32::from(Self::MAX_PAYLOADS) {
                return Err(BlockTransferError::OutsideWindow);
            }
            let bit = 1u16 << idx;
            if q.mask & bit != 0 {
                return Err(BlockTransferError::Duplicate);
            }
        }

        let (block, offset, len) = self.outgoing_range(num)?;

        if let Some(q) = self.q.as_mut() {
            let idx = num - q.base;
            q.mask |= 1u16 << idx;
        }

        self.num = num;
        self.more = block.more();
        self.next_num = num.checked_add(1).ok_or(BlockTransferError::Overflow)?;
        self.complete = !block.more();
        Ok((block, offset, len))
    }
}

pub(crate) fn block_offset(num: u32, size: usize) -> Result<usize, BlockTransferError> {
    usize::try_from(num)
        .ok()
        .and_then(|n| n.checked_mul(size))
        .ok_or(BlockTransferError::Overflow)
}

/// Same Request-Tag / ETag and endpoint, possibly a different Token.
///
/// Used when Q-Block datagrams of one body carry distinct Tokens
/// (`knowledge/rfcs/rfc9177.txt`). Absent identity is not a unique key.
#[must_use]
pub(crate) fn same_body_identity(transfer: BlockTransfer, key: BlockKey, role: BlockRole) -> bool {
    !key.identity().is_absent()
        && transfer.role() == role
        && transfer.endpoint() == key.endpoint()
        && transfer.identity() == key.identity()
}

/// Start a classic or Q-Block incoming sidecar from `role`.
pub(crate) fn start_incoming(
    key: BlockKey,
    role: BlockRole,
    block: BlockValue,
    payload_len: usize,
    capacity: usize,
    expected_len: Option<u32>,
) -> Result<BlockTransfer, BlockTransferError> {
    if role.is_q_block() {
        BlockTransfer::incoming_q(key, role, block, payload_len, capacity, expected_len)
    } else {
        BlockTransfer::incoming(key, role, block, payload_len, capacity, expected_len)
    }
}

/// Accept the next classic or Q-Block incoming range from `transfer.role()`.
pub(crate) fn accept_incoming_role(
    transfer: &mut BlockTransfer,
    block: BlockValue,
    payload_len: usize,
    capacity: usize,
) -> Result<usize, BlockTransferError> {
    if transfer.role().is_q_block() {
        transfer.accept_q_incoming(block, payload_len, capacity)
    } else {
        transfer.accept_incoming(block, payload_len, capacity)
    }
}

/// Write `payload` at `offset`. `contiguous` is the visible prefix (Q-Block holes).
///
/// When `contiguous` is `None`, the filled length becomes `offset + payload.len()`
/// (classic in-order).
pub(crate) fn store_incoming(
    buf: &mut [u8],
    filled: &mut usize,
    offset: usize,
    payload: &[u8],
    contiguous: Option<usize>,
) -> Result<(), BlockTransferError> {
    let end = offset
        .checked_add(payload.len())
        .ok_or(BlockTransferError::Overflow)?;
    if end > buf.len() {
        return Err(BlockTransferError::Overflow);
    }
    buf[offset..end].copy_from_slice(payload);
    *filled = contiguous.unwrap_or(end);
    Ok(())
}

/// Byte and transfer access shared by [`super::BodyPool`] and the alloc body pool.
pub(crate) trait BodyOps {
    fn payload(&self, id: SlotId) -> Option<&[u8]>;
    fn transfer(&self, id: SlotId) -> Option<BlockTransfer>;
    fn set_transfer(&mut self, id: SlotId, transfer: BlockTransfer) -> Result<(), SlotError>;
    fn lookup(&self, key: BlockKey) -> Option<SlotId>;
    fn admit_incoming(
        &mut self,
        key: BlockKey,
        role: BlockRole,
        block: BlockValue,
        payload: &[u8],
        expected_len: Option<u32>,
    ) -> Result<SlotId, BlockTransferError>;
    fn write_incoming(
        &mut self,
        id: SlotId,
        role: BlockRole,
        block: BlockValue,
        payload: &[u8],
    ) -> Result<BlockProgress, BlockTransferError>;
    fn apply_incoming(
        &mut self,
        key: BlockKey,
        role: BlockRole,
        block: BlockValue,
        payload: &[u8],
        expected_len: Option<u32>,
    ) -> Result<BlockProgress, BlockTransferError>;
    fn start_outgoing(
        &mut self,
        key: BlockKey,
        role: BlockRole,
        body: &[u8],
        szx: u8,
    ) -> Result<SlotId, BlockTransferError>;
    fn next_outgoing(
        &mut self,
        id: SlotId,
        role: BlockRole,
    ) -> Result<OutgoingBlock, BlockTransferError>;
    fn next_bert_outgoing(
        &mut self,
        id: SlotId,
        role: BlockRole,
        max_payload: usize,
    ) -> Result<OutgoingBlock, BlockTransferError>;
    fn ack_outgoing(
        &mut self,
        id: SlotId,
        role: BlockRole,
        num: u32,
    ) -> Result<BlockProgress, BlockTransferError>;
    fn access(&mut self, id: SlotId) -> Result<Access<'_>, SlotError>;
    fn access_mut(&mut self, id: SlotId) -> Result<AccessMut<'_>, SlotError>;
}

/// Copy `payload` into `buf` at `offset` and record the filled length.
pub(crate) fn write_range(
    buf: &mut [u8],
    filled: &mut usize,
    offset: usize,
    payload: &[u8],
) -> Result<(), BlockTransferError> {
    let end = offset
        .checked_add(payload.len())
        .ok_or(BlockTransferError::Overflow)?;
    if end > buf.len() {
        return Err(BlockTransferError::Overflow);
    }
    buf[offset..end].copy_from_slice(payload);
    *filled = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BlockKey, BlockRole, BlockTransfer, BodyTag};
    use crate::error::{BlockTransferError, ValueError};
    use crate::message::{BlockValue, QBlockTransmission, Token};
    use crate::storage::Endpoint;

    fn key() -> BlockKey {
        BlockKey::new(
            Token::new(&[0xaa, 0xbb]).expect("token"),
            Endpoint::v4([192, 0, 2, 1], 5683),
        )
    }

    fn szx16(num: u32, more: bool) -> BlockValue {
        BlockValue::from_size(num, more, 16).expect("szx 0")
    }

    #[test]
    fn incoming_single_block_completes() {
        let t =
            BlockTransfer::incoming_block1(key(), szx16(0, false), 8, 4096, None).expect("admit");
        assert_eq!(t.role(), BlockRole::IncomingBlock1);
        assert_eq!(t.num(), 0);
        assert!(!t.more());
        assert_eq!(t.filled(), 8);
        assert!(t.is_complete());
        assert_eq!(t.next_num(), 1);
    }

    #[test]
    fn incoming_multi_block_in_order() {
        let mut t = BlockTransfer::incoming_block1(key(), szx16(0, true), 16, 4096, Some(40))
            .expect("first");
        assert!(!t.is_complete());
        assert_eq!(t.filled(), 16);
        assert_eq!(t.accept_incoming(szx16(1, true), 16, 4096).expect("2"), 16);
        assert_eq!(
            t.accept_incoming(szx16(2, false), 8, 4096).expect("last"),
            32
        );
        assert!(t.is_complete());
        assert_eq!(t.filled(), 40);
    }

    #[test]
    fn incoming_rejects_gap_overlap_szx_overflow() {
        assert_eq!(
            BlockTransfer::incoming_block1(key(), szx16(1, false), 8, 4096, None)
                .expect_err("num 1"),
            BlockTransferError::Gap
        );

        let mut t =
            BlockTransfer::incoming_block1(key(), szx16(0, true), 16, 4096, None).expect("first");
        assert_eq!(
            t.accept_incoming(szx16(2, true), 16, 4096)
                .expect_err("gap"),
            BlockTransferError::Gap
        );
        assert_eq!(
            t.accept_incoming(szx16(0, true), 16, 4096)
                .expect_err("overlap"),
            BlockTransferError::Overlap
        );
        let szx1024 = BlockValue::from_size(1, true, 1024).expect("1024");
        assert_eq!(
            t.accept_incoming(szx1024, 1024, 4096).expect_err("szx"),
            BlockTransferError::SzxMismatch
        );

        let big = BlockValue::from_size(0, true, 1024).expect("1024");
        let mut full = BlockTransfer::incoming_block1(key(), big, 1024, 4096, None).expect("b0");
        for n in 1..4 {
            let b = BlockValue::from_size(n, true, 1024).expect("blk");
            full.accept_incoming(b, 1024, 4096).expect("fit");
        }
        let extra = BlockValue::from_size(4, false, 1024).expect("overflow");
        assert_eq!(
            full.accept_incoming(extra, 1, 4096).expect_err("cap"),
            BlockTransferError::Overflow
        );
    }

    #[test]
    fn classic_size_estimates_do_not_control_completion_or_capacity() {
        for role in [BlockRole::IncomingBlock1, BlockRole::IncomingBlock2] {
            for hint in [
                None,
                Some(0),
                Some(1),
                Some(16),
                Some(24),
                Some(25),
                Some(u32::MAX),
            ] {
                for bert in [false, true] {
                    let first_len = if bert { 1024 } else { 16 };
                    let block = |num, more| {
                        if bert {
                            BlockValue::bert(num, more).expect("bert")
                        } else {
                            szx16(num, more)
                        }
                    };
                    let mut t = BlockTransfer::incoming(
                        key(),
                        role,
                        block(0, true),
                        first_len,
                        first_len + 8,
                        hint,
                    )
                    .expect("estimate does not limit bytes");
                    assert!(!t.is_complete(), "M=1 even when estimate is exhausted");
                    assert_eq!(t.expected_len(), hint);
                    let before = t;
                    assert_eq!(
                        t.accept_incoming(block(1, false), 9, first_len + 8),
                        Err(BlockTransferError::Overflow)
                    );
                    assert_eq!(t, before, "refusal preserves transfer");
                    assert_eq!(
                        t.accept_incoming(block(1, false), 8, first_len + 8),
                        Ok(first_len)
                    );
                    assert!(t.is_complete(), "M=0 despite inaccurate estimate");
                    assert_eq!(t.filled(), first_len + 8);
                }
            }
        }
    }

    #[test]
    fn q_size_indications_still_require_exact_length() {
        for role in [BlockRole::IncomingQBlock1, BlockRole::IncomingQBlock2] {
            for hint in [0, 7, 9, u32::MAX] {
                assert_eq!(
                    BlockTransfer::incoming_q(key(), role, szx16(0, false), 8, 4096, Some(hint)),
                    Err(BlockTransferError::LengthInconsistent)
                );
            }
            let t = BlockTransfer::incoming_q(key(), role, szx16(0, false), 8, 4096, Some(8))
                .expect("exact");
            assert!(t.is_complete());
            assert_eq!(t.filled(), 8);
        }
    }

    #[test]
    fn outgoing_issues_in_order() {
        let mut t = BlockTransfer::outgoing_block2(key(), 40, 0, 4096).expect("start");
        assert_eq!(t.role(), BlockRole::OutgoingBlock2);
        let (b0, off0, len0) = t.issue_outgoing().expect("b0");
        assert_eq!((b0.num(), b0.more(), off0, len0), (0, true, 0, 16));
        let (b1, off1, len1) = t.issue_outgoing().expect("b1");
        assert_eq!((b1.num(), b1.more(), off1, len1), (1, true, 16, 16));
        let (b2, off2, len2) = t.issue_outgoing().expect("b2");
        assert_eq!((b2.num(), b2.more(), off2, len2), (2, false, 32, 8));
        assert!(t.is_complete());
        assert_eq!(
            t.issue_outgoing().expect_err("done"),
            BlockTransferError::AlreadyComplete
        );
    }

    #[test]
    fn outgoing_rejects_body_past_capacity() {
        assert_eq!(
            BlockTransfer::outgoing_block2(key(), 4097, 6, 4096).expect_err("cap"),
            BlockTransferError::Overflow
        );
    }

    #[test]
    fn incoming_block2_single_and_multi() {
        let t =
            BlockTransfer::incoming_block2(key(), szx16(0, false), 8, 4096, None).expect("admit");
        assert_eq!(t.role(), BlockRole::IncomingBlock2);
        assert!(t.role().is_incoming());
        assert!(!t.role().is_outgoing());
        assert_eq!(t.num(), 0);
        assert!(!t.more());
        assert_eq!(t.filled(), 8);
        assert!(t.is_complete());

        let mut multi = BlockTransfer::incoming_block2(key(), szx16(0, true), 16, 4096, Some(40))
            .expect("first");
        assert_eq!(
            multi.accept_incoming(szx16(1, true), 16, 4096).expect("2"),
            16
        );
        assert_eq!(
            multi
                .accept_incoming(szx16(2, false), 8, 4096)
                .expect("last"),
            32
        );
        assert!(multi.is_complete());
        assert_eq!(multi.filled(), 40);
    }

    #[test]
    fn incoming_block2_rejects_gap_overlap_szx_overflow() {
        assert_eq!(
            BlockTransfer::incoming_block2(key(), szx16(1, false), 8, 4096, None)
                .expect_err("num 1"),
            BlockTransferError::Gap
        );

        let mut t =
            BlockTransfer::incoming_block2(key(), szx16(0, true), 16, 4096, None).expect("first");
        assert_eq!(
            t.accept_incoming(szx16(2, true), 16, 4096)
                .expect_err("gap"),
            BlockTransferError::Gap
        );
        assert_eq!(
            t.accept_incoming(szx16(0, true), 16, 4096)
                .expect_err("overlap"),
            BlockTransferError::Overlap
        );
        let szx1024 = BlockValue::from_size(1, true, 1024).expect("1024");
        assert_eq!(
            t.accept_incoming(szx1024, 1024, 4096).expect_err("szx"),
            BlockTransferError::SzxMismatch
        );

        let big = BlockValue::from_size(0, true, 1024).expect("1024");
        let mut full = BlockTransfer::incoming_block2(key(), big, 1024, 4096, None).expect("b0");
        for n in 1..4 {
            let b = BlockValue::from_size(n, true, 1024).expect("blk");
            full.accept_incoming(b, 1024, 4096).expect("fit");
        }
        let extra = BlockValue::from_size(4, false, 1024).expect("overflow");
        assert_eq!(
            full.accept_incoming(extra, 1, 4096).expect_err("cap"),
            BlockTransferError::Overflow
        );
    }

    #[test]
    fn outgoing_block1_issues_in_order() {
        let mut t = BlockTransfer::outgoing_block1(key(), 40, 0, 4096).expect("start");
        assert_eq!(t.role(), BlockRole::OutgoingBlock1);
        assert!(t.role().is_outgoing());
        assert!(!t.role().is_incoming());
        let (b0, off0, len0) = t.issue_outgoing().expect("b0");
        assert_eq!((b0.num(), b0.more(), off0, len0), (0, true, 0, 16));
        let (b1, off1, len1) = t.issue_outgoing().expect("b1");
        assert_eq!((b1.num(), b1.more(), off1, len1), (1, true, 16, 16));
        let (b2, off2, len2) = t.issue_outgoing().expect("b2");
        assert_eq!((b2.num(), b2.more(), off2, len2), (2, false, 32, 8));
        assert!(t.is_complete());
        assert_eq!(
            t.issue_outgoing().expect_err("done"),
            BlockTransferError::AlreadyComplete
        );
    }

    #[test]
    fn outgoing_block1_rejects_body_past_capacity() {
        assert_eq!(
            BlockTransfer::outgoing_block1(key(), 4097, 6, 4096).expect_err("cap"),
            BlockTransferError::Overflow
        );
    }

    #[test]
    fn constructors_reject_wrong_direction_role() {
        assert_eq!(
            BlockTransfer::incoming(
                key(),
                BlockRole::OutgoingBlock1,
                szx16(0, false),
                8,
                4096,
                None
            )
            .expect_err("out as in"),
            BlockTransferError::IdentityMismatch
        );
        assert_eq!(
            BlockTransfer::outgoing(key(), BlockRole::IncomingBlock2, 8, 0, 4096)
                .expect_err("in as out"),
            BlockTransferError::IdentityMismatch
        );
        assert_eq!(
            BlockTransfer::incoming(
                key(),
                BlockRole::IncomingQBlock1,
                szx16(0, false),
                8,
                4096,
                None
            )
            .expect_err("q as classic"),
            BlockTransferError::IdentityMismatch
        );
        assert_eq!(
            BlockTransfer::incoming_q(
                key(),
                BlockRole::IncomingBlock1,
                szx16(0, false),
                8,
                4096,
                None
            )
            .expect_err("classic as q"),
            BlockTransferError::IdentityMismatch
        );
        assert_eq!(
            BlockTransfer::outgoing(key(), BlockRole::OutgoingQBlock1, 8, 0, 4096)
                .expect_err("q as classic"),
            BlockTransferError::IdentityMismatch
        );
        assert_eq!(
            BlockTransfer::outgoing_q(key(), BlockRole::OutgoingBlock2, 8, 0, 4096)
                .expect_err("classic as q out"),
            BlockTransferError::IdentityMismatch
        );
        assert_eq!(
            BlockTransfer::incoming_q(
                key(),
                BlockRole::OutgoingQBlock1,
                szx16(0, false),
                8,
                4096,
                None
            )
            .expect_err("out q as in q"),
            BlockTransferError::IdentityMismatch
        );
    }

    #[test]
    fn incoming_cannot_issue_outgoing_and_vice_versa() {
        let mut incoming =
            BlockTransfer::incoming_block2(key(), szx16(0, true), 16, 4096, None).expect("in");
        assert_eq!(
            incoming.issue_outgoing().expect_err("in"),
            BlockTransferError::IdentityMismatch
        );
        let mut outgoing = BlockTransfer::outgoing_block1(key(), 16, 0, 4096).expect("out");
        assert_eq!(
            outgoing
                .accept_incoming(szx16(0, false), 8, 4096)
                .expect_err("out"),
            BlockTransferError::IdentityMismatch
        );
        let mut q_out = BlockTransfer::outgoing_q_block1(key(), 16, 0, 4096).expect("q out");
        assert_eq!(
            q_out.issue_outgoing().expect_err("q via classic"),
            BlockTransferError::IdentityMismatch
        );
        assert_eq!(
            outgoing.issue_q_outgoing().expect_err("classic via q"),
            BlockTransferError::IdentityMismatch
        );
    }

    #[test]
    fn q_block_out_of_order_within_window() {
        let mut t = BlockTransfer::incoming_q_block1(key(), szx16(2, false), 8, 4096, Some(40))
            .expect("num 2 first");
        assert_eq!(t.role(), BlockRole::IncomingQBlock1);
        assert!(t.is_q_block());
        assert_eq!(t.window_base(), 0);
        assert_eq!(t.filled(), 0);
        assert!(!t.is_complete());
        assert_eq!(t.accept_q_incoming(szx16(0, true), 16, 4096).expect("0"), 0);
        assert_eq!(t.filled(), 16);
        assert_eq!(t.next_num(), 1);
        assert_eq!(
            t.accept_q_incoming(szx16(1, true), 16, 4096).expect("1"),
            16
        );
        assert!(t.is_complete());
        assert_eq!(t.filled(), 40);
    }

    #[test]
    fn q_block_duplicate_and_outside_window() {
        let mut t =
            BlockTransfer::incoming_q_block2(key(), szx16(0, true), 16, 4096, None).expect("0");
        assert_eq!(t.role(), BlockRole::IncomingQBlock2);
        assert_eq!(
            t.accept_q_incoming(szx16(0, true), 16, 4096)
                .expect_err("dup"),
            BlockTransferError::Duplicate
        );
        assert_eq!(
            t.accept_q_incoming(
                szx16(u32::from(BlockTransfer::MAX_PAYLOADS), true),
                16,
                4096
            )
            .expect_err("next window"),
            BlockTransferError::OutsideWindow
        );
    }

    #[test]
    fn q_block_advances_window_then_completes() {
        let last = u32::from(BlockTransfer::MAX_PAYLOADS) + 1;
        let expected = (last as usize) * 16 + 8;
        let mut t = BlockTransfer::incoming_q_block1(
            key(),
            szx16(0, true),
            16,
            4096,
            Some(expected as u32),
        )
        .expect("0");
        for n in 1..BlockTransfer::MAX_PAYLOADS {
            t.accept_q_incoming(szx16(u32::from(n), true), 16, 4096)
                .expect("window 0");
        }
        assert_eq!(t.window_base(), u32::from(BlockTransfer::MAX_PAYLOADS));
        assert_eq!(t.window_mask(), 0);
        assert!(!t.is_complete());
        t.accept_q_incoming(szx16(last, false), 8, 4096)
            .expect("final first");
        assert!(!t.is_complete());
        t.accept_q_incoming(
            szx16(u32::from(BlockTransfer::MAX_PAYLOADS), true),
            16,
            4096,
        )
        .expect("gap fill");
        assert!(t.is_complete());
        assert_eq!(t.filled(), expected);
    }

    #[test]
    fn outgoing_q_block1_full_window_then_advance() {
        let body_len = usize::from(BlockTransfer::MAX_PAYLOADS) * 16 + 8;
        let mut t = BlockTransfer::outgoing_q_block1(key(), body_len, 0, 4096).expect("start");
        assert_eq!(t.role(), BlockRole::OutgoingQBlock1);
        assert!(t.role().is_outgoing());
        assert!(t.is_q_block());
        assert_eq!(t.window_base(), 0);
        assert_eq!(t.window_mask(), 0);

        for n in 0..BlockTransfer::MAX_PAYLOADS {
            let (b, off, len) = t.issue_q_outgoing().expect("window");
            assert_eq!(b.num(), u32::from(n));
            assert!(b.more());
            assert_eq!(off, usize::from(n) * 16);
            assert_eq!(len, 16);
        }
        assert_eq!(t.window_mask(), (1u16 << BlockTransfer::MAX_PAYLOADS) - 1);
        assert!(!t.is_complete());
        assert_eq!(
            t.issue_q_outgoing().expect_err("need ack"),
            BlockTransferError::OutsideWindow
        );

        let last = u32::from(BlockTransfer::MAX_PAYLOADS) - 1;
        t.ack_q_window(last).expect("continue");
        assert_eq!(t.window_base(), u32::from(BlockTransfer::MAX_PAYLOADS));
        assert_eq!(t.window_mask(), 0);

        let (last_b, last_off, last_len) = t.issue_q_outgoing().expect("final");
        assert_eq!(last_b.num(), u32::from(BlockTransfer::MAX_PAYLOADS));
        assert!(!last_b.more());
        assert_eq!(last_off, usize::from(BlockTransfer::MAX_PAYLOADS) * 16);
        assert_eq!(last_len, 8);
        assert!(t.is_complete());
        assert_eq!(
            t.issue_q_outgoing().expect_err("done"),
            BlockTransferError::AlreadyComplete
        );
    }

    #[test]
    fn outgoing_q_block2_continue_advances() {
        let body_len = usize::from(BlockTransfer::MAX_PAYLOADS) * 16 + 8;
        let mut t = BlockTransfer::outgoing_q_block2(key(), body_len, 0, 4096).expect("start");
        assert_eq!(t.role(), BlockRole::OutgoingQBlock2);
        for _ in 0..BlockTransfer::MAX_PAYLOADS {
            t.issue_q_outgoing().expect("window");
        }
        assert_eq!(
            t.ack_q_window(0).expect_err("not continue"),
            BlockTransferError::Gap
        );
        assert_eq!(
            t.ack_q_window(9).expect_err("q1-shaped"),
            BlockTransferError::Gap
        );
        t.ack_q_window(u32::from(BlockTransfer::MAX_PAYLOADS))
            .expect("continue");
        assert_eq!(t.window_base(), u32::from(BlockTransfer::MAX_PAYLOADS));
        let (last, _, len) = t.issue_q_outgoing().expect("final");
        assert_eq!(last.num(), u32::from(BlockTransfer::MAX_PAYLOADS));
        assert!(!last.more());
        assert_eq!(len, 8);
        assert!(t.is_complete());
    }

    #[test]
    fn outgoing_q_complete_body_szx16_and_szx1024() {
        let mut t16 = BlockTransfer::outgoing_q_block1(key(), 40, 0, 4096).expect("16");
        let (b0, _, _) = t16.issue_q_outgoing().expect("0");
        assert_eq!((b0.num(), b0.more(), b0.szx()), (0, true, 0));
        let (b1, _, _) = t16.issue_q_outgoing().expect("1");
        assert_eq!((b1.num(), b1.more()), (1, true));
        let (b2, off, len) = t16.issue_q_outgoing().expect("2");
        assert_eq!((b2.num(), b2.more(), off, len), (2, false, 32, 8));
        assert!(t16.is_complete());

        let mut t1024 = BlockTransfer::outgoing_q_block2(key(), 2048, 6, 4096).expect("1024");
        let (c0, _, len0) = t1024.issue_q_outgoing().expect("0");
        assert_eq!((c0.num(), c0.more(), c0.szx(), len0), (0, true, 6, 1024));
        let (c1, off1, len1) = t1024.issue_q_outgoing().expect("1");
        assert_eq!((c1.num(), c1.more(), off1, len1), (1, false, 1024, 1024));
        assert!(t1024.is_complete());
    }

    #[test]
    fn outgoing_q_rejects_body_past_capacity() {
        assert_eq!(
            BlockTransfer::outgoing_q_block1(key(), 4097, 6, 4096).expect_err("cap"),
            BlockTransferError::Overflow
        );
        assert_eq!(
            BlockTransfer::outgoing_q_block2(key(), 4097, 6, 4096).expect_err("cap"),
            BlockTransferError::Overflow
        );
    }

    #[test]
    fn incoming_q_holes_below_highest_and_before_m0() {
        let mut t =
            BlockTransfer::incoming_q_block2(key(), szx16(0, true), 16, 4096, None).expect("0");
        assert_eq!(t.q_holes(), None);

        t.accept_q_incoming(szx16(2, true), 16, 4096).expect("2");
        let (first, mask) = t.q_holes().expect("gap");
        assert_eq!(first, 1);
        assert_eq!(mask, 0b0010);

        t.accept_q_incoming(szx16(1, true), 16, 4096).expect("fill");
        assert_eq!(t.q_holes(), None);

        let mut m0 = BlockTransfer::incoming_q_block1(key(), szx16(2, false), 8, 4096, Some(40))
            .expect("m0 first");
        let (first, mask) = m0.q_holes().expect("holes before m0");
        assert_eq!(first, 0);
        assert_eq!(mask, 0b0011);
        m0.accept_q_incoming(szx16(0, true), 16, 4096).expect("0");
        m0.accept_q_incoming(szx16(1, true), 16, 4096).expect("1");
        assert!(m0.is_complete());
        assert_eq!(m0.q_holes(), None);
    }

    #[test]
    fn incoming_q_receive_wait_arms_and_doubles() {
        let mut t =
            BlockTransfer::incoming_q_block2(key(), szx16(0, true), 16, 4096, None).expect("0");
        t.note_q_receive(10);
        assert!(t.q_receive().is_none());
        t.accept_q_incoming(szx16(2, false), 8, 4096).expect("2");
        t.note_q_receive(10);
        let wait = t.q_receive().expect("armed");
        assert_eq!(wait.attempts(), 0);
        assert_eq!(
            wait.next_timeout_ms(),
            10 + u64::from(QBlockTransmission::NON_RECEIVE_TIMEOUT_MS)
        );
        assert!(!wait.is_due(10));
        assert!(wait.is_due(10 + u64::from(QBlockTransmission::NON_RECEIVE_TIMEOUT_MS)));
        let next = t
            .note_q_recover(10 + u64::from(QBlockTransmission::NON_RECEIVE_TIMEOUT_MS))
            .expect("double");
        assert_eq!(next.attempts(), 1);
        assert_eq!(
            next.timeout_ms(),
            QBlockTransmission::NON_RECEIVE_TIMEOUT_MS.saturating_mul(2)
        );
        t.accept_q_incoming(szx16(1, true), 16, 4096).expect("fill");
        t.note_q_receive(100);
        assert!(t.q_receive().is_none());
    }

    #[test]
    fn outgoing_q_reissue_reads_body_without_window_change() {
        let mut t = BlockTransfer::outgoing_q_block2(key(), 40, 0, 4096).expect("start");
        t.issue_q_outgoing().expect("0");
        t.issue_q_outgoing().expect("1");
        t.issue_q_outgoing().expect("2");
        assert!(t.is_complete());
        let mask = t.window_mask();
        let (b, off, len) = t.reissue_q_outgoing(1).expect("reissue");
        assert_eq!((b.num(), b.more(), b.szx(), off, len), (1, true, 0, 16, 16));
        assert_eq!(t.window_mask(), mask);
        assert_eq!(
            t.reissue_q_outgoing(3).expect_err("past body"),
            BlockTransferError::Gap
        );
        let incoming =
            BlockTransfer::incoming_q_block2(key(), szx16(0, true), 16, 4096, None).expect("in");
        assert_eq!(
            incoming.reissue_q_outgoing(0).expect_err("in"),
            BlockTransferError::IdentityMismatch
        );
    }

    #[test]
    fn body_tag_absent_empty_and_present() {
        assert!(BodyTag::ABSENT.is_absent());
        assert_eq!(BodyTag::ABSENT.as_slice(), None);
        assert!(!BodyTag::EMPTY.is_absent());
        assert_eq!(BodyTag::EMPTY.as_slice(), Some(&b""[..]));
        let tag = BodyTag::new(b"etag12").expect("tag");
        assert_eq!(tag.as_slice(), Some(&b"etag12"[..]));
        assert_eq!(BodyTag::new(&[0; 9]), Err(ValueError::OpaqueLength));
        assert_eq!(BodyTag::from_first(None).expect("absent"), BodyTag::ABSENT);
        assert_eq!(
            BodyTag::from_first(Some(b"ab")).expect("first").as_slice(),
            Some(&b"ab"[..])
        );
        let a = BlockKey::new(key().token(), key().endpoint());
        let b = a.with_identity(tag);
        assert_ne!(a, b);
        assert_eq!(b.identity(), tag);
        assert!(a.identity().is_absent());
    }

    #[test]
    fn bert_incoming_multi_block_then_final() {
        let expected = 3072 + 5120 + 4711;
        let mut t = BlockTransfer::incoming_block1(
            key(),
            BlockValue::bert(0, true).expect("bert"),
            3072,
            16384,
            Some(expected as u32),
        )
        .expect("3072");
        assert!(t.is_bert());
        assert_eq!(t.szx(), BlockValue::SZX_BERT);
        assert_eq!(t.filled(), 3072);
        assert_eq!(t.next_num(), 3);
        assert!(!t.is_complete());
        assert_eq!(
            t.accept_incoming(BlockValue::bert(3, true).expect("bert"), 5120, 16384)
                .expect("5120"),
            3072
        );
        assert_eq!(t.next_num(), 8);
        assert_eq!(
            t.accept_incoming(BlockValue::bert(8, false).expect("bert"), 4711, 16384)
                .expect("final"),
            8192
        );
        assert!(t.is_complete());
        assert_eq!(t.filled(), expected);
    }

    #[test]
    fn bert_incoming_rejects_non_multiple_and_szx_mix() {
        assert_eq!(
            BlockTransfer::incoming_block1(
                key(),
                BlockValue::bert(0, true).expect("bert"),
                2048 + 1,
                8192,
                None
            )
            .expect_err("not multiple"),
            BlockTransferError::PayloadLength
        );
        let mut t = BlockTransfer::incoming_block1(
            key(),
            BlockValue::bert(0, true).expect("bert"),
            1024,
            4096,
            None,
        )
        .expect("first");
        let classic = BlockValue::from_size(1, false, 1024).expect("szx6");
        assert_eq!(
            t.accept_incoming(classic, 1024, 4096).expect_err("mix"),
            BlockTransferError::SzxMismatch
        );
        assert_eq!(
            BlockTransfer::incoming_q_block1(
                key(),
                BlockValue::bert(0, true).expect("bert"),
                1024,
                4096,
                None
            )
            .expect_err("q bert"),
            BlockTransferError::Value(ValueError::IllegalSzx)
        );
    }

    #[test]
    fn bert_outgoing_caps_payload_and_advances_num() {
        let mut t =
            BlockTransfer::outgoing_block2(key(), 8192 + 16384 + 5683, 7, 32768).expect("start");
        assert!(t.is_bert());
        let (b0, off0, len0) = t.issue_bert_outgoing(8192).expect("first");
        assert!(b0.is_bert());
        assert_eq!((b0.num(), b0.more(), off0, len0), (0, true, 0, 8192));
        assert_eq!(t.next_num(), 8);
        let (b1, off1, len1) = t.issue_bert_outgoing(16384).expect("16384");
        assert_eq!((b1.num(), b1.more(), off1, len1), (8, true, 8192, 16384));
        assert_eq!(t.next_num(), 24);
        let (b2, off2, len2) = t.issue_bert_outgoing(8192).expect("final");
        assert_eq!((b2.num(), b2.more(), off2, len2), (24, false, 24576, 5683));
        assert!(t.is_complete());
        assert_eq!(
            t.issue_bert_outgoing(1024).expect_err("done"),
            BlockTransferError::AlreadyComplete
        );
    }

    #[test]
    fn bert_outgoing_rejects_q_and_too_small_max() {
        assert_eq!(
            BlockTransfer::outgoing_q_block1(key(), 2048, 7, 4096).expect_err("q"),
            BlockTransferError::Value(ValueError::IllegalSzx)
        );
        let mut t = BlockTransfer::outgoing_block1(key(), 4096, 7, 4096).expect("bert");
        assert_eq!(
            t.issue_bert_outgoing(500).expect_err("tiny"),
            BlockTransferError::PayloadLength
        );
        let (b, _, len) = t.issue_outgoing().expect("whole remaining");
        assert!(b.is_bert());
        assert!(!b.more());
        assert_eq!(len, 4096);
    }
}
