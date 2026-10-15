//! Builder, parse, encode, and slot-glue errors.

use crate::message::OptionNumber;
use crate::storage::SlotError;

/// Failure to construct an [`Engine`](crate::storage::Engine).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    /// App requires an explicit entropy source or test-only deterministic mode.
    RandomnessRequired,
    /// App's entropy source failed during initial Message ID selection.
    RandomnessUnavailable,
    /// Builder sizes do not match the [`Storage`](crate::storage::Storage) being moved in.
    SizeMismatch,
    /// Enabled body slot bytes are not a multiple of 1024 (max Block/Q-Block SZX).
    ///
    /// Same quantum as [`crate::message::BlockValue::SIZE_MAX`].
    BodyBytesNotMultipleOf1024,
    /// `.block_wise(false)` but storage or the builder includes body pools.
    UnexpectedBodyPools,
    /// `.block_wise(true)` but storage has no body pools.
    MissingBodyPools,
    /// Enabled body slot count or bytes is zero. Zero is not “disabled.”
    ZeroBodyCapacity,
    /// Some body capacity fields are set and others are not.
    IncompleteBodyCapacities,
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RandomnessRequired => f.write_str("App randomness must be configured"),
            Self::RandomnessUnavailable => f.write_str("App randomness unavailable"),
            Self::SizeMismatch => f.write_str("storage sizes do not match the builder"),
            Self::BodyBytesNotMultipleOf1024 => {
                f.write_str("body slot bytes must be a multiple of 1024")
            }
            Self::UnexpectedBodyPools => {
                f.write_str("body pools are present but block-wise is disabled")
            }
            Self::MissingBodyPools => {
                f.write_str("block-wise is enabled but storage has no body pools")
            }
            Self::ZeroBodyCapacity => {
                f.write_str("enabled body capacity must not be zero slots or zero bytes")
            }
            Self::IncompleteBodyCapacities => {
                f.write_str("body capacity fields must be all set or all absent")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BuildError {}

/// Failure to decode a CoAP datagram.
///
/// Wire-format failures are distinct from [`Self::UnrecognizedCritical`] and
/// [`Self::BadOptionFormat`], which are structured reports for optional
/// RFC 7252 checks. [`crate::message::decode`] does not invent 4.02 / RST
/// policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// Buffer shorter than the 4-byte header.
    TruncatedHeader,
    /// Version field is not 1.
    UnsupportedVersion,
    /// Token length nibble is 9–15.
    BadTokenLength,
    /// Buffer ends before the token bytes given by TKL.
    TruncatedToken,
    /// Option header, extended field, or value overruns the buffer.
    TruncatedOption,
    /// Option delta nibble is 15 but the byte is not the payload marker.
    ReservedOptionDelta,
    /// Option length nibble is 15.
    ReservedOptionLength,
    /// Running option number exceeded 65535.
    OptionNumberOverflow,
    /// Empty message (code 0.00) has a token, options, or payload.
    EmptyMessageNotEmpty,
    /// Payload marker 0xFF with no following payload bytes.
    PayloadMarkerWithoutPayload,
    /// Critical option number is not among the RFC 7252 options.
    ///
    /// Returned by [`crate::message::ParsedMessage::check_rfc7252_options`],
    /// not by [`crate::message::decode`]. The caller chooses the protocol
    /// response.
    UnrecognizedCritical(OptionNumber),
    /// A known RFC 7252 option has a value that does not match its Table 4
    /// format.
    ///
    /// Returned by [`crate::message::ParsedMessage::check_rfc7252_formats`],
    /// not by [`crate::message::decode`] or
    /// [`crate::message::ParsedMessage::check_rfc7252_options`]. The caller
    /// chooses the protocol response.
    BadOptionFormat(OptionNumber),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("truncated CoAP header"),
            Self::UnsupportedVersion => f.write_str("unsupported CoAP version"),
            Self::BadTokenLength => f.write_str("token length is 9-15"),
            Self::TruncatedToken => f.write_str("truncated token"),
            Self::TruncatedOption => f.write_str("truncated option"),
            Self::ReservedOptionDelta => f.write_str("reserved option delta 15"),
            Self::ReservedOptionLength => f.write_str("reserved option length 15"),
            Self::OptionNumberOverflow => f.write_str("option number overflow"),
            Self::EmptyMessageNotEmpty => f.write_str("empty message is not empty"),
            Self::PayloadMarkerWithoutPayload => f.write_str("payload marker without payload"),
            Self::UnrecognizedCritical(n) => {
                write!(f, "unrecognized critical option {}", n.get())
            }
            Self::BadOptionFormat(n) => {
                write!(f, "RFC 7252 option {} has the wrong format", n.get())
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

/// Failure to encode a CoAP datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// Output buffer is shorter than the encoded message.
    BufferTooSmall,
    /// Empty message (code 0.00) has a token, options, or payload.
    EmptyMessageNotEmpty,
    /// Option numbers are not in non-decreasing order.
    OptionsNotAscending,
    /// Option value cannot be encoded (length above the 14-extended maximum).
    OptionValueTooLong,
    /// [`crate::message::OptionsBuilder`] has no free slot.
    ///
    /// Distinct from [`Self::OptionsNotAscending`]: the numbers were valid
    /// but the fixed list was full. App maps this to 5.00 (server) or a
    /// failed send (client) instead of dropping options.
    OptionsFull,
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall => f.write_str("encode buffer is too small"),
            Self::EmptyMessageNotEmpty => f.write_str("empty message is not empty"),
            Self::OptionsNotAscending => f.write_str("option numbers are not ascending"),
            Self::OptionValueTooLong => f.write_str("option value is too long"),
            Self::OptionsFull => f.write_str("options builder is full"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}

/// Failure to decode an option value as empty, opaque, uint, string, or Block.
///
/// Distinct from [`ParseError`]: wire decode keeps option values opaque.
/// See `knowledge/rfcs/rfc7252.txt` §3.2 and `knowledge/rfcs/rfc7959.txt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueError {
    /// Bytes are not a UTF-8 string option value.
    InvalidUtf8,
    /// Integer does not fit the target width.
    UintOverflow,
    /// Block/Q-Block SZX is not 0..=6 or BERT 7, or the size is not a legal SZX size.
    IllegalSzx,
    /// Block/Q-Block NUM does not fit in 20 bits (3-byte option value).
    BlockNumOverflow,
    /// Opaque option value is longer than 8 bytes (ETag / Request-Tag).
    OpaqueLength,
    /// Echo option value is empty or longer than 40 bytes.
    EchoLength,
    /// Hop-Limit option value is not exactly one byte in `1..=255`.
    HopLimit,
    /// No-Response option value is longer than one byte.
    NoResponseLength,
}

impl core::fmt::Display for ValueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidUtf8 => f.write_str("option value is not UTF-8"),
            Self::UintOverflow => f.write_str("uint option value does not fit the target"),
            Self::IllegalSzx => f.write_str("block SZX is not 0..=6 or BERT 7"),
            Self::BlockNumOverflow => f.write_str("block NUM does not fit in 20 bits"),
            Self::OpaqueLength => f.write_str("opaque option value is longer than 8 bytes"),
            Self::EchoLength => f.write_str("Echo option value is empty or longer than 40 bytes"),
            Self::HopLimit => {
                f.write_str("Hop-Limit option value is not exactly one byte in 1..=255")
            }
            Self::NoResponseLength => {
                f.write_str("No-Response option value is longer than one byte")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValueError {}

/// [`OptionsBuilder`](crate::message::OptionsBuilder) has no free slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptionsFull;

impl core::fmt::Display for OptionsFull {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("options builder is full")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OptionsFull {}

/// Failure to decode or encode a CoAP datagram in an occupied slot.
///
/// Slot occupancy is distinct from [`ParseError`] / [`EncodeError`]. The
/// library does not invent 4.02 / RST policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotMessageError {
    /// The slot is free or the identifier is out of range.
    Slot(SlotError),
    /// Occupied bytes are not a well-formed CoAP datagram.
    Parse(ParseError),
    /// Encoding failed (buffer too small, empty-message rules, or options).
    Encode(EncodeError),
}

impl core::fmt::Display for SlotMessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Slot(e) => write!(f, "{e}"),
            Self::Parse(e) => write!(f, "{e}"),
            Self::Encode(e) => write!(f, "{e}"),
        }
    }
}

impl From<SlotError> for SlotMessageError {
    fn from(e: SlotError) -> Self {
        Self::Slot(e)
    }
}

impl From<ParseError> for SlotMessageError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl From<EncodeError> for SlotMessageError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SlotMessageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Slot(e) => Some(e),
            Self::Parse(e) => Some(e),
            Self::Encode(e) => Some(e),
        }
    }
}

/// Failure of a Block / Q-Block body-slot transfer.
///
/// These are structured reports for the body-pool state machine. The library
/// does not invent 4.02 / 4.08 / RST policy. See
/// `knowledge/rfcs/rfc7959.txt` and `knowledge/rfcs/rfc9177.txt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockTransferError {
    /// Storage has no body pools (`.block_wise(false)`).
    NoBodyPools,
    /// Body pool is full; no slot can be admitted.
    Saturated,
    /// Slot addressing or occupancy failure.
    Slot(SlotError),
    /// Occupied body slot has no transfer sidecar.
    NoTransfer,
    /// Token or remote endpoint does not match the slot's transfer.
    IdentityMismatch,
    /// Block1 / Block2 / Q-Block1 / Q-Block2 option is missing from the datagram.
    MissingBlock,
    /// NUM is below the next expected block (already filled).
    Overlap,
    /// NUM is above the next expected block (classic Block is in-order).
    Gap,
    /// NUM is outside the current Q-Block `MAX_PAYLOADS` window.
    OutsideWindow,
    /// NUM is already received in this Q-Block transfer.
    Duplicate,
    /// SZX differs from the SZX locked on the first block.
    SzxMismatch,
    /// Block range would exceed the body-slot byte capacity.
    Overflow,
    /// Q-Block length conflicts with Size1 / Size2 or an earlier final block.
    LengthInconsistent,
    /// An incoming Q-Block payload lacks its mandatory Size1 / Size2 option.
    MissingSize,
    /// Q-Block1 requires Request-Tag; Q-Block2 requires a nonempty ETag.
    MissingIdentity,
    /// Transfer already completed (M=0 accepted or last Block2 issued).
    AlreadyComplete,
    /// Payload length is not valid for this NUM / M / SZX.
    PayloadLength,
    /// Option-value decode failed (illegal SZX, NUM overflow, …).
    Value(ValueError),
    /// Occupied datagram is not a well-formed CoAP message.
    Parse(ParseError),
    /// Encoding a Block1 / Block2 datagram failed.
    Encode(EncodeError),
}

impl core::fmt::Display for BlockTransferError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoBodyPools => f.write_str("body pools are absent"),
            Self::Saturated => f.write_str("body pool is saturated"),
            Self::Slot(e) => write!(f, "{e}"),
            Self::NoTransfer => f.write_str("body slot has no block transfer"),
            Self::IdentityMismatch => f.write_str("block transfer identity does not match"),
            Self::MissingBlock => {
                f.write_str("Block1, Block2, Q-Block1, or Q-Block2 option is missing")
            }
            Self::Overlap => f.write_str("block NUM overlaps an already filled range"),
            Self::Gap => f.write_str("block NUM skips the next expected block"),
            Self::OutsideWindow => f.write_str("block NUM is outside the current Q-Block window"),
            Self::Duplicate => f.write_str("block NUM is already received"),
            Self::SzxMismatch => f.write_str("block SZX does not match the transfer"),
            Self::Overflow => f.write_str("block exceeds body slot capacity"),
            Self::LengthInconsistent => {
                f.write_str("Q-Block length conflicts with Size1/Size2 or final block")
            }
            Self::MissingIdentity => f.write_str("Q-Block requires a body identity"),
            Self::MissingSize => f.write_str("Q-Block payload requires Size1/Size2"),
            Self::AlreadyComplete => f.write_str("block transfer is already complete"),
            Self::PayloadLength => f.write_str("block payload length is not valid for NUM/M/SZX"),
            Self::Value(e) => write!(f, "{e}"),
            Self::Parse(e) => write!(f, "{e}"),
            Self::Encode(e) => write!(f, "{e}"),
        }
    }
}

impl From<SlotError> for BlockTransferError {
    fn from(e: SlotError) -> Self {
        Self::Slot(e)
    }
}

impl From<ValueError> for BlockTransferError {
    fn from(e: ValueError) -> Self {
        Self::Value(e)
    }
}

impl From<ParseError> for BlockTransferError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl From<EncodeError> for BlockTransferError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BlockTransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Slot(e) => Some(e),
            Self::Value(e) => Some(e),
            Self::Parse(e) => Some(e),
            Self::Encode(e) => Some(e),
            _ => None,
        }
    }
}
