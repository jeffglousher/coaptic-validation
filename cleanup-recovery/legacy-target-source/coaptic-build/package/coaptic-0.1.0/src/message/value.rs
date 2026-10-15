//! RFC 7252 option value formats: empty, opaque, uint, and string.
//!
//! Block1 / Block2 / Size2 (RFC 7959) and Q-Block1 / Q-Block2 (RFC 9177)
//! reuse the uint codec. They are not in RFC 7252 Table 4. [`BlockValue`]
//! holds NUM/M/SZX; Q-Block uses the same bitfields. Hop-Limit (RFC 8768)
//! and No-Response (RFC 7967) also reuse uint. Request-Tag and Echo
//! (RFC 9175) are opaque.
//!
//! These codecs operate on option *value* bytes after
//! [`crate::message::decode`] / before [`crate::message::encode`]. They do
//! not parse option headers. Wire format lives in
//! `knowledge/rfcs/rfc7252.txt`, `knowledge/rfcs/rfc7959.txt`,
//! `knowledge/rfcs/rfc7967.txt`, `knowledge/rfcs/rfc8768.txt`,
//! `knowledge/rfcs/rfc9175.txt`, and `knowledge/rfcs/rfc9177.txt`. This
//! module does not restate it.

use core::fmt;

use crate::error::{ParseError, ValueError};

use super::decode::ParsedMessage;
use super::hop::HopLimit;
use super::no_response::NoResponse;
use super::option::{Opt, OptionNumber, Options};
use super::precondition::Precondition;

/// RFC 7252 default Max-Age (seconds) when the option is absent.
///
/// An empty Max-Age *value* is uint 0, which is not this default.
pub const MAX_AGE_DEFAULT: u32 = 60;

/// Observe register value on a GET (RFC 7641). See `knowledge/rfcs/rfc7641.txt`.
pub const OBSERVE_REGISTER: u32 = 0;

/// Observe deregister value on a GET (RFC 7641). See `knowledge/rfcs/rfc7641.txt`.
pub const OBSERVE_DEREGISTER: u32 = 1;

/// 24-bit mask for Observe notification sequence numbers (RFC 7641).
///
/// See `knowledge/rfcs/rfc7641.txt`.
pub const OBSERVE_SEQUENCE_MASK: u32 = 0x00ff_ffff;

const fn is_observe_method(code: crate::message::Code) -> bool {
    matches!(
        code,
        crate::message::Code::GET | crate::message::Code::FETCH
    )
}

/// RFC 7252 §3.2 option value format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptionValueFormat {
    /// Zero-length value.
    Empty,
    /// Opaque byte string.
    Opaque,
    /// Unsigned integer in network byte order.
    Uint,
    /// UTF-8 string.
    String,
}

/// Stack-encoded uint option value (0–4 bytes, leading zeros omitted).
///
/// Zero encodes as the empty value. Hold this while an [`Opt`] borrows it.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EncodedUint {
    buf: [u8; 4],
    len: u8,
}

impl EncodedUint {
    /// Encode `n` without leading zero bytes.
    #[must_use]
    pub const fn new(n: u32) -> Self {
        let b = n.to_be_bytes();
        let start = if b[0] != 0 {
            0
        } else if b[1] != 0 {
            1
        } else if b[2] != 0 {
            2
        } else if b[3] != 0 {
            3
        } else {
            4
        };
        let len = 4 - start;
        let mut buf = [0u8; 4];
        let mut i = 0;
        while i < len {
            buf[i] = b[start + i];
            i += 1;
        }
        Self {
            buf,
            len: len as u8,
        }
    }

    /// Encoded bytes (empty when `n` was 0).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.buf.split_at(self.len as usize).0
    }

    /// Encoded length in bytes (0–4).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether this is the empty encoding of 0.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for EncodedUint {
    fn default() -> Self {
        Self::new(0)
    }
}

impl From<u16> for EncodedUint {
    fn from(n: u16) -> Self {
        Self::new(u32::from(n))
    }
}

impl From<u32> for EncodedUint {
    fn from(n: u32) -> Self {
        Self::new(n)
    }
}

impl From<ContentFormat> for EncodedUint {
    fn from(cf: ContentFormat) -> Self {
        cf.encode()
    }
}

impl From<BlockValue> for EncodedUint {
    fn from(block: BlockValue) -> Self {
        block.encode()
    }
}

impl fmt::Debug for EncodedUint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EncodedUint")
            .field(&self.as_bytes())
            .finish()
    }
}

/// Encode a uint option value on the stack. Leading zeros are omitted.
#[must_use]
pub const fn encode_uint(n: u32) -> EncodedUint {
    EncodedUint::new(n)
}

/// Decode a uint option value.
///
/// Accepts any length, including leading zeros, as long as the integer fits
/// in `u32`. The empty value is 0.
pub fn decode_uint(bytes: &[u8]) -> Result<u32, ValueError> {
    let mut n = 0u32;
    for &b in bytes {
        n = n
            .checked_mul(256)
            .and_then(|n| n.checked_add(u32::from(b)))
            .ok_or(ValueError::UintOverflow)?;
    }
    Ok(n)
}

/// Decode a uint option value that must fit in `u16`.
pub fn decode_uint16(bytes: &[u8]) -> Result<u16, ValueError> {
    u16::try_from(decode_uint(bytes)?).map_err(|_| ValueError::UintOverflow)
}

/// Encode an Observe option value (uint, 0–3 bytes).
///
/// Register is [`OBSERVE_REGISTER`], deregister is [`OBSERVE_DEREGISTER`].
/// Notification sequence numbers use the 24 least significant bits
/// ([`OBSERVE_SEQUENCE_MASK`]). Reuses [`encode_uint`]. See
/// `knowledge/rfcs/rfc7641.txt`.
#[must_use]
pub const fn encode_observe(n: u32) -> EncodedUint {
    encode_uint(n & OBSERVE_SEQUENCE_MASK)
}

/// Decode an Observe option value.
///
/// Rejects more than 3 value bytes (RFC 7641 length). Otherwise reuses
/// [`decode_uint`]. See `knowledge/rfcs/rfc7641.txt`.
pub fn decode_observe(bytes: &[u8]) -> Result<u32, ValueError> {
    if bytes.len() > 3 {
        return Err(ValueError::UintOverflow);
    }
    decode_uint(bytes)
}

/// Encode a Block / Q-Block option value (uint, 0–3 bytes).
///
/// See [`BlockValue::encode`].
#[must_use]
pub const fn encode_block(value: BlockValue) -> EncodedUint {
    value.encode()
}

/// Decode a Block / Q-Block option value.
///
/// See [`BlockValue::decode`].
pub fn decode_block(bytes: &[u8]) -> Result<BlockValue, ValueError> {
    BlockValue::decode(bytes)
}

/// UTF-8 view of a string option value. Does not allocate.
pub fn as_str(bytes: &[u8]) -> Result<&str, ValueError> {
    core::str::from_utf8(bytes).map_err(|_| ValueError::InvalidUtf8)
}

/// CoAP Content-Format identifier (Content-Format / Accept).
///
/// Initial RFC 7252 registry entries are associated constants. Other IDs use
/// [`ContentFormat::new`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentFormat(u16);

impl ContentFormat {
    /// `text/plain; charset=utf-8`.
    pub const TEXT_PLAIN: Self = Self(0);
    /// `application/link-format`.
    pub const LINK_FORMAT: Self = Self(40);
    /// `application/xml`.
    pub const XML: Self = Self(41);
    /// `application/octet-stream`.
    pub const OCTET_STREAM: Self = Self(42);
    /// `application/exi`.
    pub const EXI: Self = Self(47);
    /// `application/json`.
    pub const JSON: Self = Self(50);
    /// `application/concise-problem-details+cbor` (RFC 9290).
    pub const PROBLEM_DETAILS: Self = Self(257);
    /// `application/missing-blocks+cbor-seq` (RFC 9177).
    pub const MISSING_BLOCKS: Self = Self(272);

    /// Wrap a raw Content-Format ID.
    #[must_use]
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    /// Raw Content-Format ID.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Encode as a uint option value.
    #[must_use]
    pub const fn encode(self) -> EncodedUint {
        EncodedUint::new(self.0 as u32)
    }
}

impl From<u16> for ContentFormat {
    fn from(id: u16) -> Self {
        Self(id)
    }
}

impl From<ContentFormat> for u16 {
    fn from(cf: ContentFormat) -> Self {
        cf.0
    }
}

/// NUM/M/SZX fields of Block1, Block2, Q-Block1, and Q-Block2.
///
/// Q-Block uses the same bitfields (RFC 9177 §4.2). SZX 7 is BERT
/// (`knowledge/rfcs/rfc8323.txt`). This type does not assemble bodies.
/// Enabled body slot capacity is a multiple of [`Self::SIZE_MAX`] (1024).
///
/// See `knowledge/rfcs/rfc7959.txt`, `knowledge/rfcs/rfc9177.txt`, and
/// `knowledge/rfcs/rfc8323.txt`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BlockValue {
    num: u32,
    more: bool,
    szx: u8,
}

impl BlockValue {
    /// Smallest legal SZX (block size 16).
    pub const SZX_MIN: u8 = 0;
    /// Largest classic SZX (block size 1024).
    pub const SZX_MAX: u8 = 6;
    /// BERT SZX (`knowledge/rfcs/rfc8323.txt`). Conceptual size is [`Self::SIZE_MAX`].
    pub const SZX_BERT: u8 = 7;
    /// Largest NUM that fits in a 3-byte Block option value (20 bits).
    pub const NUM_MAX: u32 = 0x000f_ffff;
    /// Smallest legal block size in bytes (SZX 0).
    pub const SIZE_MIN: u16 = 16;
    /// Largest legal block size in bytes (SZX 6).
    ///
    /// Enabled body slots are a multiple of this. This crate does not
    /// reassemble block-wise bodies here.
    pub const SIZE_MAX: u16 = 1024;

    /// Build from NUM, M, and SZX (0..=6, or [`Self::SZX_BERT`]).
    pub const fn new(num: u32, more: bool, szx: u8) -> Result<Self, ValueError> {
        if szx > Self::SZX_BERT {
            return Err(ValueError::IllegalSzx);
        }
        if num > Self::NUM_MAX {
            return Err(ValueError::BlockNumOverflow);
        }
        Ok(Self { num, more, szx })
    }

    /// Build from NUM, M, and a legal block size in bytes (16, 32, …, 1024).
    pub const fn from_size(num: u32, more: bool, size: u16) -> Result<Self, ValueError> {
        match Self::szx_from_size(size) {
            Ok(szx) => Self::new(num, more, szx),
            Err(e) => Err(e),
        }
    }

    /// Block number (NUM).
    #[must_use]
    pub const fn num(self) -> u32 {
        self.num
    }

    /// More flag (M).
    #[must_use]
    pub const fn more(self) -> bool {
        self.more
    }

    /// Size exponent (SZX, 0..=6, or [`Self::SZX_BERT`]).
    #[must_use]
    pub const fn szx(self) -> u8 {
        self.szx
    }

    /// Whether this is a BERT option (SZX 7).
    ///
    /// See `knowledge/rfcs/rfc8323.txt`.
    #[must_use]
    pub const fn is_bert(self) -> bool {
        self.szx == Self::SZX_BERT
    }

    /// NUM/M with SZX 7 (BERT). Conceptual block size is [`Self::SIZE_MAX`].
    pub const fn bert(num: u32, more: bool) -> Result<Self, ValueError> {
        Self::new(num, more, Self::SZX_BERT)
    }

    /// Block size in bytes for this SZX. BERT uses [`Self::SIZE_MAX`].
    #[must_use]
    pub const fn size(self) -> u16 {
        if self.is_bert() {
            Self::SIZE_MAX
        } else {
            16 << self.szx
        }
    }

    /// Packed Block / Q-Block uint. See `knowledge/rfcs/rfc7959.txt`.
    #[must_use]
    pub const fn as_uint(self) -> u32 {
        (self.num << 4) | ((self.more as u32) << 3) | (self.szx as u32)
    }

    /// Encode as a uint option value (0–3 bytes; leading zeros omitted).
    #[must_use]
    pub const fn encode(self) -> EncodedUint {
        EncodedUint::new(self.as_uint())
    }

    /// Decode a Block / Q-Block option value.
    ///
    /// Rejects more than 3 value bytes (RFC 7959 / RFC 9177 length) and NUM
    /// above 20 bits. SZX 7 is BERT. Empty bytes are NUM 0, M unset, SZX 0.
    pub fn decode(bytes: &[u8]) -> Result<Self, ValueError> {
        if bytes.len() > 3 {
            return Err(ValueError::UintOverflow);
        }
        let val = decode_uint(bytes)?;
        Self::from_uint(val)
    }

    /// Unpack a Block / Q-Block uint.
    pub const fn from_uint(val: u32) -> Result<Self, ValueError> {
        if val > 0x00ff_ffff {
            return Err(ValueError::BlockNumOverflow);
        }
        let szx = (val & 7) as u8;
        let more = val & 8 != 0;
        let num = val >> 4;
        Self::new(num, more, szx)
    }

    /// Block size in bytes for `szx`, or [`ValueError::IllegalSzx`].
    ///
    /// BERT (`szx == 7`) is [`Self::SIZE_MAX`].
    pub const fn size_from_szx(szx: u8) -> Result<u16, ValueError> {
        if szx == Self::SZX_BERT {
            return Ok(Self::SIZE_MAX);
        }
        if szx > Self::SZX_MAX {
            return Err(ValueError::IllegalSzx);
        }
        Ok(16 << szx)
    }

    /// SZX for a legal block size in bytes, or [`ValueError::IllegalSzx`].
    pub const fn szx_from_size(size: u16) -> Result<u8, ValueError> {
        match size {
            16 => Ok(0),
            32 => Ok(1),
            64 => Ok(2),
            128 => Ok(3),
            256 => Ok(4),
            512 => Ok(5),
            1024 => Ok(6),
            _ => Err(ValueError::IllegalSzx),
        }
    }
}

/// Options with a given number, in wire order.
#[derive(Clone, Debug)]
pub struct OptionsByNumber<'a> {
    inner: Options<'a>,
    number: OptionNumber,
}

impl<'a> Iterator for OptionsByNumber<'a> {
    type Item = Opt<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.find(|opt| opt.number() == self.number)
    }
}

/// UTF-8 views of string option values with a given number.
#[derive(Clone, Debug)]
pub struct StringOptions<'a> {
    inner: OptionsByNumber<'a>,
}

impl<'a> Iterator for StringOptions<'a> {
    type Item = Result<&'a str, ValueError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(Opt::as_str)
    }
}

/// Opaque values of options with a given number.
#[derive(Clone, Debug)]
pub struct OpaqueOptions<'a> {
    inner: OptionsByNumber<'a>,
}

impl<'a> Iterator for OpaqueOptions<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(Opt::value)
    }
}

/// Block / Q-Block values of options with a given number.
#[derive(Clone, Debug)]
pub struct BlockOptions<'a> {
    inner: OptionsByNumber<'a>,
}

impl<'a> Iterator for BlockOptions<'a> {
    type Item = Result<BlockValue, ValueError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(Opt::as_block)
    }
}

impl<'a> Opt<'a> {
    /// Empty option value.
    #[must_use]
    pub const fn empty(number: OptionNumber) -> Self {
        Self::new(number, &[])
    }

    /// Opaque option value.
    #[must_use]
    pub const fn opaque(number: OptionNumber, value: &'a [u8]) -> Self {
        Self::new(number, value)
    }

    /// String option value (UTF-8 bytes).
    #[must_use]
    pub const fn string(number: OptionNumber, value: &'a str) -> Self {
        Self::new(number, value.as_bytes())
    }

    /// Uint option value. `encoded` must outlive the [`Opt`].
    #[must_use]
    pub const fn uint(number: OptionNumber, encoded: &'a EncodedUint) -> Self {
        Self::new(number, encoded.as_bytes())
    }

    /// If-Match (opaque, empty means any).
    #[must_use]
    pub const fn if_match(etag: &'a [u8]) -> Self {
        Self::opaque(OptionNumber::IF_MATCH, etag)
    }

    /// Uri-Host (string).
    #[must_use]
    pub const fn uri_host(host: &'a str) -> Self {
        Self::string(OptionNumber::URI_HOST, host)
    }

    /// ETag (opaque).
    #[must_use]
    pub const fn etag(tag: &'a [u8]) -> Self {
        Self::opaque(OptionNumber::ETAG, tag)
    }

    /// Request-Tag (opaque, 0..=8). RFC 9175; not in RFC 7252 Table 4.
    ///
    /// See `knowledge/rfcs/rfc9175.txt`.
    #[must_use]
    pub const fn request_tag(tag: &'a [u8]) -> Self {
        Self::opaque(OptionNumber::REQUEST_TAG, tag)
    }

    /// Echo (opaque, 1..=40). RFC 9175; not in RFC 7252 Table 4.
    ///
    /// See `knowledge/rfcs/rfc9175.txt`.
    #[must_use]
    pub const fn echo(value: &'a [u8]) -> Self {
        Self::opaque(OptionNumber::ECHO, value)
    }

    /// If-None-Match (empty).
    #[must_use]
    pub const fn if_none_match() -> Self {
        Self::empty(OptionNumber::IF_NONE_MATCH)
    }

    /// Uri-Port (uint).
    #[must_use]
    pub const fn uri_port(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::URI_PORT, encoded)
    }

    /// Location-Path segment (string).
    #[must_use]
    pub const fn location_path(segment: &'a str) -> Self {
        Self::string(OptionNumber::LOCATION_PATH, segment)
    }

    /// OSCORE option (opaque compressed COSE). RFC 8613; not in RFC 7252 Table 4.
    ///
    /// See `knowledge/rfcs/rfc8613.txt`. An all-zero flag byte is encoded as
    /// an empty value, not `0x00`.
    #[must_use]
    pub const fn oscore(value: &'a [u8]) -> Self {
        Self::opaque(OptionNumber::OSCORE, value)
    }

    /// Uri-Path segment (string).
    #[must_use]
    pub const fn uri_path(segment: &'a str) -> Self {
        Self::string(OptionNumber::URI_PATH, segment)
    }

    /// Content-Format (uint).
    #[must_use]
    pub const fn content_format(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::CONTENT_FORMAT, encoded)
    }

    /// Max-Age (uint).
    #[must_use]
    pub const fn max_age(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::MAX_AGE, encoded)
    }

    /// Uri-Query (string).
    #[must_use]
    pub const fn uri_query(query: &'a str) -> Self {
        Self::string(OptionNumber::URI_QUERY, query)
    }

    /// Accept (uint Content-Format ID).
    #[must_use]
    pub const fn accept(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::ACCEPT, encoded)
    }

    /// Location-Query (string).
    #[must_use]
    pub const fn location_query(query: &'a str) -> Self {
        Self::string(OptionNumber::LOCATION_QUERY, query)
    }

    /// Proxy-Uri (string).
    #[must_use]
    pub const fn proxy_uri(uri: &'a str) -> Self {
        Self::string(OptionNumber::PROXY_URI, uri)
    }

    /// Proxy-Scheme (string).
    #[must_use]
    pub const fn proxy_scheme(scheme: &'a str) -> Self {
        Self::string(OptionNumber::PROXY_SCHEME, scheme)
    }

    /// Size1 (uint).
    #[must_use]
    pub const fn size1(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::SIZE1, encoded)
    }

    /// Hop-Limit (uint). RFC 8768; not in RFC 7252 Table 4.
    ///
    /// See `knowledge/rfcs/rfc8768.txt`.
    #[must_use]
    pub const fn hop_limit(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::HOP_LIMIT, encoded)
    }

    /// No-Response (uint bitmap). RFC 7967; not in RFC 7252 Table 4.
    ///
    /// See `knowledge/rfcs/rfc7967.txt`.
    #[must_use]
    pub const fn no_response(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::NO_RESPONSE, encoded)
    }

    /// Size2 (uint). RFC 7959; not in RFC 7252 Table 4.
    #[must_use]
    pub const fn size2(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::SIZE2, encoded)
    }

    /// Block1 (NUM/M/SZX uint). `encoded` must outlive the [`Opt`].
    ///
    /// See `knowledge/rfcs/rfc7959.txt`.
    #[must_use]
    pub const fn block1(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::BLOCK1, encoded)
    }

    /// Block2 (NUM/M/SZX uint). `encoded` must outlive the [`Opt`].
    ///
    /// See `knowledge/rfcs/rfc7959.txt`.
    #[must_use]
    pub const fn block2(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::BLOCK2, encoded)
    }

    /// Q-Block1 (same NUM/M/SZX as [`BlockValue`]).
    ///
    /// See `knowledge/rfcs/rfc9177.txt`.
    #[must_use]
    pub const fn q_block1(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::Q_BLOCK1, encoded)
    }

    /// Q-Block2 (same NUM/M/SZX as [`BlockValue`]; repeatable).
    ///
    /// See `knowledge/rfcs/rfc9177.txt`.
    #[must_use]
    pub const fn q_block2(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::Q_BLOCK2, encoded)
    }

    /// Observe (uint). `encoded` must outlive the [`Opt`].
    ///
    /// Register is 0, deregister is 1, notifications carry a sequence number.
    /// See `knowledge/rfcs/rfc7641.txt`.
    #[must_use]
    pub const fn observe(encoded: &'a EncodedUint) -> Self {
        Self::uint(OptionNumber::OBSERVE, encoded)
    }

    /// Observe register (GET, value 0). Empty uint encoding.
    #[must_use]
    pub const fn observe_register() -> Self {
        Self::empty(OptionNumber::OBSERVE)
    }

    /// Observe deregister (GET, value 1).
    #[must_use]
    pub const fn observe_deregister() -> Self {
        Self::new(OptionNumber::OBSERVE, &[1])
    }

    /// Whether the value is zero-length (present empty, not missing).
    #[must_use]
    pub const fn is_empty_value(self) -> bool {
        self.value().is_empty()
    }

    /// UTF-8 view of this option value.
    pub fn as_str(self) -> Result<&'a str, ValueError> {
        as_str(self.value())
    }

    /// Decode this option value as a uint that fits in `u32`.
    pub fn as_uint(self) -> Result<u32, ValueError> {
        decode_uint(self.value())
    }

    /// Decode this option value as a uint that fits in `u16`.
    pub fn as_uint16(self) -> Result<u16, ValueError> {
        decode_uint16(self.value())
    }

    /// Decode this option value as Block / Q-Block NUM/M/SZX.
    pub fn as_block(self) -> Result<BlockValue, ValueError> {
        BlockValue::decode(self.value())
    }

    /// Table 4 format for this option number, if it is an RFC 7252 option.
    #[must_use]
    pub const fn value_format(self) -> Option<OptionValueFormat> {
        option_value_format(self.number())
    }

    /// Fail if this is a known RFC 7252 option with the wrong format.
    ///
    /// Unknown numbers succeed. [`crate::message::decode`] does not call this.
    pub fn check_rfc7252_format(self) -> Result<(), ParseError> {
        check_format(self)
    }
}

impl OptionNumber {
    /// Table 4 format for this number, if it is an RFC 7252 option.
    #[must_use]
    pub const fn value_format(self) -> Option<OptionValueFormat> {
        option_value_format(self)
    }
}

/// Table 4 format for `number`, or `None` when the number is not RFC 7252.
#[must_use]
pub const fn option_value_format(number: OptionNumber) -> Option<OptionValueFormat> {
    match table4_spec(number) {
        Some((kind, _, _)) => Some(kind),
        None => None,
    }
}

const fn table4_spec(number: OptionNumber) -> Option<(OptionValueFormat, usize, usize)> {
    match number.get() {
        1 => Some((OptionValueFormat::Opaque, 0, 8)),
        3 => Some((OptionValueFormat::String, 1, 255)),
        4 => Some((OptionValueFormat::Opaque, 1, 8)),
        5 => Some((OptionValueFormat::Empty, 0, 0)),
        7 => Some((OptionValueFormat::Uint, 0, 2)),
        8 => Some((OptionValueFormat::String, 0, 255)),
        11 => Some((OptionValueFormat::String, 0, 255)),
        12 => Some((OptionValueFormat::Uint, 0, 2)),
        14 => Some((OptionValueFormat::Uint, 0, 4)),
        15 => Some((OptionValueFormat::String, 0, 255)),
        17 => Some((OptionValueFormat::Uint, 0, 2)),
        20 => Some((OptionValueFormat::String, 0, 255)),
        35 => Some((OptionValueFormat::String, 1, 1034)),
        39 => Some((OptionValueFormat::String, 1, 255)),
        60 => Some((OptionValueFormat::Uint, 0, 4)),
        _ => None,
    }
}

fn check_format(opt: Opt<'_>) -> Result<(), ParseError> {
    let Some((kind, min, max)) = table4_spec(opt.number()) else {
        return Ok(());
    };
    let len = opt.value().len();
    let in_range = len >= min && len <= max;
    let ok = match kind {
        OptionValueFormat::Empty => len == 0,
        OptionValueFormat::Opaque | OptionValueFormat::Uint => in_range,
        OptionValueFormat::String => in_range && as_str(opt.value()).is_ok(),
    };
    if ok {
        Ok(())
    } else {
        Err(ParseError::BadOptionFormat(opt.number()))
    }
}

impl<'a> ParsedMessage<'a> {
    /// First option with `number`, if any.
    #[must_use]
    pub fn get_option(self, number: OptionNumber) -> Option<Opt<'a>> {
        self.options().find(|opt| opt.number() == number)
    }

    /// All options with `number`, in wire order.
    #[must_use]
    pub fn get_options(self, number: OptionNumber) -> OptionsByNumber<'a> {
        OptionsByNumber {
            inner: self.options(),
            number,
        }
    }

    /// Uri-Host, if present.
    #[must_use]
    pub fn uri_host(self) -> Option<Result<&'a str, ValueError>> {
        self.get_option(OptionNumber::URI_HOST).map(Opt::as_str)
    }

    /// Uri-Port, if present.
    #[must_use]
    pub fn uri_port(self) -> Option<Result<u16, ValueError>> {
        self.get_option(OptionNumber::URI_PORT).map(Opt::as_uint16)
    }

    /// Uri-Path segments in wire order.
    #[must_use]
    pub fn uri_path(self) -> StringOptions<'a> {
        StringOptions {
            inner: self.get_options(OptionNumber::URI_PATH),
        }
    }

    /// Uri-Query values in wire order.
    #[must_use]
    pub fn uri_query(self) -> StringOptions<'a> {
        StringOptions {
            inner: self.get_options(OptionNumber::URI_QUERY),
        }
    }

    /// Location-Path segments in wire order.
    #[must_use]
    pub fn location_path(self) -> StringOptions<'a> {
        StringOptions {
            inner: self.get_options(OptionNumber::LOCATION_PATH),
        }
    }

    /// OSCORE option value, if present. RFC 8613; not in RFC 7252 Table 4.
    ///
    /// See `knowledge/rfcs/rfc8613.txt`. An empty value is a valid
    /// all-zero flag byte (typical OSCORE response).
    #[must_use]
    pub fn oscore(self) -> Option<&'a [u8]> {
        self.get_option(OptionNumber::OSCORE).map(Opt::value)
    }

    /// Location-Query values in wire order.
    #[must_use]
    pub fn location_query(self) -> StringOptions<'a> {
        StringOptions {
            inner: self.get_options(OptionNumber::LOCATION_QUERY),
        }
    }

    /// Proxy-Uri, if present.
    #[must_use]
    pub fn proxy_uri(self) -> Option<Result<&'a str, ValueError>> {
        self.get_option(OptionNumber::PROXY_URI).map(Opt::as_str)
    }

    /// Proxy-Scheme, if present.
    #[must_use]
    pub fn proxy_scheme(self) -> Option<Result<&'a str, ValueError>> {
        self.get_option(OptionNumber::PROXY_SCHEME).map(Opt::as_str)
    }

    /// Content-Format, if present.
    #[must_use]
    pub fn content_format(self) -> Option<Result<ContentFormat, ValueError>> {
        self.get_option(OptionNumber::CONTENT_FORMAT)
            .map(|opt| opt.as_uint16().map(ContentFormat::new))
    }

    /// Accept, if present.
    #[must_use]
    pub fn accept(self) -> Option<Result<ContentFormat, ValueError>> {
        self.get_option(OptionNumber::ACCEPT)
            .map(|opt| opt.as_uint16().map(ContentFormat::new))
    }

    /// Max-Age, if present. Missing is `None`; empty value is `Some(Ok(0))`.
    ///
    /// Does not substitute [`MAX_AGE_DEFAULT`].
    #[must_use]
    pub fn max_age(self) -> Option<Result<u32, ValueError>> {
        self.get_option(OptionNumber::MAX_AGE).map(Opt::as_uint)
    }

    /// Size1, if present.
    #[must_use]
    pub fn size1(self) -> Option<Result<u32, ValueError>> {
        self.get_option(OptionNumber::SIZE1).map(Opt::as_uint)
    }

    /// Size2, if present. RFC 7959; not in RFC 7252 Table 4.
    #[must_use]
    pub fn size2(self) -> Option<Result<u32, ValueError>> {
        self.get_option(OptionNumber::SIZE2).map(Opt::as_uint)
    }

    /// Block1, if present.
    #[must_use]
    pub fn block1(self) -> Option<Result<BlockValue, ValueError>> {
        self.get_option(OptionNumber::BLOCK1).map(Opt::as_block)
    }

    /// Block2, if present.
    #[must_use]
    pub fn block2(self) -> Option<Result<BlockValue, ValueError>> {
        self.get_option(OptionNumber::BLOCK2).map(Opt::as_block)
    }

    /// Q-Block1, if present. Same value format as [`BlockValue`].
    #[must_use]
    pub fn q_block1(self) -> Option<Result<BlockValue, ValueError>> {
        self.get_option(OptionNumber::Q_BLOCK1).map(Opt::as_block)
    }

    /// Q-Block2 values in wire order. Repeatable; same format as [`BlockValue`].
    #[must_use]
    pub fn q_block2(self) -> BlockOptions<'a> {
        BlockOptions {
            inner: self.get_options(OptionNumber::Q_BLOCK2),
        }
    }

    /// Observe, if present.
    ///
    /// On a GET, 0 is register and 1 is deregister. In a response the value
    /// is a notification sequence number. See `knowledge/rfcs/rfc7641.txt`.
    #[must_use]
    pub fn observe(self) -> Option<Result<u32, ValueError>> {
        self.get_option(OptionNumber::OBSERVE)
            .map(|opt| decode_observe(opt.value()))
    }

    /// GET or FETCH with Observe register (value 0). Sequence 0 on a notification is not this.
    #[must_use]
    pub fn is_observe_register(self) -> bool {
        is_observe_method(self.code()) && matches!(self.observe(), Some(Ok(OBSERVE_REGISTER)))
    }

    /// GET or FETCH with Observe deregister (value 1). Sequence 1 on a notification is not this.
    #[must_use]
    pub fn is_observe_deregister(self) -> bool {
        is_observe_method(self.code()) && matches!(self.observe(), Some(Ok(OBSERVE_DEREGISTER)))
    }

    /// Whether If-None-Match is present (empty vs missing).
    #[must_use]
    pub fn if_none_match(self) -> bool {
        self.get_option(OptionNumber::IF_NONE_MATCH).is_some()
    }

    /// If-Match values in wire order (empty slice means any).
    #[must_use]
    pub fn if_match(self) -> OpaqueOptions<'a> {
        OpaqueOptions {
            inner: self.get_options(OptionNumber::IF_MATCH),
        }
    }

    /// Classify If-Match / If-None-Match against the current representation.
    ///
    /// `exists` is whether any representation is stored. `etag` is the
    /// current ETag when known (used only for a non-empty If-Match). The
    /// library does not invent 4.12 policy. See
    /// `knowledge/rfcs/rfc7252.txt` §5.10.8.
    #[must_use]
    pub fn precondition(self, exists: bool, etag: Option<&[u8]>) -> Precondition {
        if self.if_none_match() && exists {
            return Precondition::FailedIfNoneMatch;
        }
        if !self.if_match_holds(exists, etag) {
            return Precondition::FailedIfMatch;
        }
        if self.if_none_match() || self.get_option(OptionNumber::IF_MATCH).is_some() {
            Precondition::Satisfied
        } else {
            Precondition::Unconditional
        }
    }

    fn if_match_holds(self, exists: bool, etag: Option<&[u8]>) -> bool {
        let mut saw = false;
        for v in self.if_match() {
            saw = true;
            if v.is_empty() {
                if exists {
                    return true;
                }
            } else if exists && etag == Some(v) {
                return true;
            }
        }
        !saw
    }

    /// ETag values in wire order.
    #[must_use]
    pub fn etag(self) -> OpaqueOptions<'a> {
        OpaqueOptions {
            inner: self.get_options(OptionNumber::ETAG),
        }
    }

    /// Request-Tag values in wire order. RFC 9175; repeatable.
    ///
    /// See `knowledge/rfcs/rfc9175.txt`.
    #[must_use]
    pub fn request_tag(self) -> OpaqueOptions<'a> {
        OpaqueOptions {
            inner: self.get_options(OptionNumber::REQUEST_TAG),
        }
    }

    /// Echo value, if present. RFC 9175; not repeatable.
    ///
    /// See `knowledge/rfcs/rfc9175.txt`.
    #[must_use]
    pub fn echo(self) -> Option<&'a [u8]> {
        self.get_option(OptionNumber::ECHO).map(Opt::value)
    }

    /// Hop-Limit, if present. RFC 8768; not in RFC 7252 Table 4.
    ///
    /// Missing is `None`. Does not substitute [`HopLimit::DEFAULT`]. See
    /// `knowledge/rfcs/rfc8768.txt`.
    #[must_use]
    pub fn hop_limit(self) -> Option<Result<HopLimit, ValueError>> {
        self.get_option(OptionNumber::HOP_LIMIT)
            .map(|opt| HopLimit::decode(opt.value()))
    }

    /// No-Response, if present. RFC 7967; not in RFC 7252 Table 4.
    ///
    /// Missing is `None`. Does not substitute [`NoResponse::DEFAULT`]. See
    /// `knowledge/rfcs/rfc7967.txt`.
    #[must_use]
    pub fn no_response(self) -> Option<Result<NoResponse, ValueError>> {
        self.get_option(OptionNumber::NO_RESPONSE)
            .map(|opt| NoResponse::decode(opt.value()))
    }

    /// First known RFC 7252 option whose value has the wrong format.
    #[must_use]
    pub fn bad_option_format(self) -> Option<OptionNumber> {
        self.options()
            .find_map(|opt| match opt.check_rfc7252_format() {
                Ok(()) => None,
                Err(_) => Some(opt.number()),
            })
    }

    /// Fail if [`Self::bad_option_format`] finds an option.
    ///
    /// [`crate::message::decode`] does not call this. Distinct from
    /// [`Self::check_rfc7252_options`].
    pub fn check_rfc7252_formats(self) -> Result<(), ParseError> {
        match self.bad_option_format() {
            Some(n) => Err(ParseError::BadOptionFormat(n)),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::{
        BlockValue, ContentFormat, EncodedUint, OBSERVE_DEREGISTER, OBSERVE_REGISTER,
        OBSERVE_SEQUENCE_MASK, OptionValueFormat, as_str, decode_block, decode_observe,
        decode_uint, decode_uint16, encode_block, encode_observe, encode_uint, option_value_format,
    };
    use crate::error::ValueError;
    use crate::message::OptionNumber;

    #[test]
    fn encode_uint_omits_leading_zeros() {
        assert_eq!(encode_uint(0).as_bytes(), &[] as &[u8]);
        assert_eq!(encode_uint(1).as_bytes(), &[1]);
        assert_eq!(encode_uint(255).as_bytes(), &[255]);
        assert_eq!(encode_uint(256).as_bytes(), &[1, 0]);
        assert_eq!(encode_uint(0x0100).as_bytes(), &[1, 0]);
        assert_eq!(encode_uint(0x00ff).as_bytes(), &[0xff]);
        assert_eq!(encode_uint(0x01020304).as_bytes(), &[1, 2, 3, 4]);
        assert!(encode_uint(0).is_empty());
        assert_eq!(encode_uint(1).len(), 1);
    }

    #[test]
    fn decode_uint_accepts_leading_zeros_and_empty() {
        assert_eq!(decode_uint(&[]).expect("empty"), 0);
        assert_eq!(decode_uint(&[1]).expect("1"), 1);
        assert_eq!(decode_uint(&[0, 1]).expect("leading zero"), 1);
        assert_eq!(decode_uint(&[0, 0, 0, 1]).expect("three zeros"), 1);
        assert_eq!(decode_uint(&[0, 0, 0, 0, 1]).expect("fits u32"), 1);
        assert_eq!(decode_uint(&[1, 0]).expect("256"), 256);
        assert_eq!(decode_uint(&[1, 2, 3, 4]).expect("full"), 0x0102_0304);
    }

    #[test]
    fn decode_uint_overflows_when_value_does_not_fit() {
        assert_eq!(decode_uint(&[1, 0, 0, 0, 0]), Err(ValueError::UintOverflow));
        assert_eq!(decode_uint16(&[1, 0, 0]), Err(ValueError::UintOverflow));
        assert_eq!(decode_uint16(&[0, 0, 0xff, 0xff]).expect("u16"), u16::MAX);
    }

    #[test]
    fn as_str_rejects_bad_utf8() {
        assert_eq!(as_str(b"temp").expect("ascii"), "temp");
        assert_eq!(as_str(&[0xff, 0xfe]), Err(ValueError::InvalidUtf8));
        assert_eq!(as_str(&[]).expect("empty string"), "");
    }

    #[test]
    fn content_format_encode_roundtrip() {
        let json = ContentFormat::JSON.encode();
        assert_eq!(json.as_bytes(), &[50]);
        assert_eq!(
            decode_uint16(json.as_bytes()).expect("id"),
            ContentFormat::JSON.get()
        );
        assert_eq!(ContentFormat::TEXT_PLAIN.encode().as_bytes(), &[] as &[u8]);
        assert_eq!(
            EncodedUint::from(ContentFormat::LINK_FORMAT).as_bytes(),
            &[40]
        );
        assert_eq!(ContentFormat::PROBLEM_DETAILS.get(), 257);
        assert_eq!(ContentFormat::PROBLEM_DETAILS.encode().as_bytes(), &[1, 1]);
        assert_eq!(ContentFormat::MISSING_BLOCKS.get(), 272);
        assert_eq!(ContentFormat::MISSING_BLOCKS.encode().as_bytes(), &[1, 16]);
    }

    #[test]
    fn observe_uint_reuses_codec_and_masks_sequence() {
        assert_eq!(encode_observe(OBSERVE_REGISTER).as_bytes(), &[] as &[u8]);
        assert_eq!(encode_observe(OBSERVE_DEREGISTER).as_bytes(), &[1]);
        assert_eq!(encode_observe(12).as_bytes(), &[12]);
        assert_eq!(encode_observe(0x00ff_ffff).as_bytes(), &[0xff, 0xff, 0xff]);
        assert_eq!(
            encode_observe(0x0100_0000).as_bytes(),
            encode_observe(0).as_bytes()
        );
        assert_eq!(encode_observe(0x0100_0001).as_bytes(), &[1]);
        assert_eq!(OBSERVE_SEQUENCE_MASK, 0x00ff_ffff);

        assert_eq!(decode_observe(&[]).expect("register"), 0);
        assert_eq!(decode_observe(&[1]).expect("deregister"), 1);
        assert_eq!(decode_observe(&[0, 1]).expect("leading zero"), 1);
        assert_eq!(
            decode_observe(&[0xff, 0xff, 0xff]).expect("24-bit"),
            0x00ff_ffff
        );
        assert_eq!(decode_observe(&[1, 0, 0, 0]), Err(ValueError::UintOverflow));
        assert_eq!(
            decode_uint(&[1, 0, 0, 0]).expect("uint still 4 bytes"),
            0x0100_0000
        );
    }

    #[test]
    fn table4_formats() {
        assert_eq!(
            option_value_format(OptionNumber::IF_NONE_MATCH),
            Some(OptionValueFormat::Empty)
        );
        assert_eq!(
            option_value_format(OptionNumber::IF_MATCH),
            Some(OptionValueFormat::Opaque)
        );
        assert_eq!(
            option_value_format(OptionNumber::URI_PATH),
            Some(OptionValueFormat::String)
        );
        assert_eq!(
            option_value_format(OptionNumber::CONTENT_FORMAT),
            Some(OptionValueFormat::Uint)
        );
        assert_eq!(option_value_format(OptionNumber::BLOCK2), None);
        assert_eq!(option_value_format(OptionNumber::BLOCK1), None);
        assert_eq!(option_value_format(OptionNumber::SIZE2), None);
        assert_eq!(option_value_format(OptionNumber::Q_BLOCK1), None);
        assert_eq!(option_value_format(OptionNumber::Q_BLOCK2), None);
        assert!(!OptionNumber::BLOCK2.is_rfc7252());
        assert!(!OptionNumber::Q_BLOCK1.is_rfc7252());
        assert!(!OptionNumber::SIZE2.is_rfc7252());
        assert!(!OptionNumber::REQUEST_TAG.is_rfc7252());
        assert!(!OptionNumber::REQUEST_TAG.is_critical());
        assert!(!OptionNumber::REQUEST_TAG.is_unsafe());
        assert!(!OptionNumber::ECHO.is_rfc7252());
        assert!(!OptionNumber::ECHO.is_critical());
        assert!(!OptionNumber::ECHO.is_unsafe());
        assert!(OptionNumber::ECHO.is_no_cache_key());
        assert_eq!(option_value_format(OptionNumber::ECHO), None);
        assert!(!OptionNumber::HOP_LIMIT.is_rfc7252());
        assert!(!OptionNumber::HOP_LIMIT.is_critical());
        assert!(!OptionNumber::NO_RESPONSE.is_rfc7252());
        assert!(!OptionNumber::NO_RESPONSE.is_critical());
        assert!(OptionNumber::NO_RESPONSE.is_unsafe());
        assert!(OptionNumber::URI_PATH.is_known());
        assert!(OptionNumber::OSCORE.is_known());
        assert!(OptionNumber::OSCORE.is_critical());
        assert!(OptionNumber::BLOCK2.is_known());
        assert!(OptionNumber::Q_BLOCK1.is_known());
        assert!(OptionNumber::Q_BLOCK2.is_known());
        assert!(OptionNumber::BLOCK1.is_known());
        assert!(OptionNumber::SIZE2.is_known());
        assert!(OptionNumber::ECHO.is_known());
        assert!(OptionNumber::HOP_LIMIT.is_known());
        assert!(OptionNumber::REQUEST_TAG.is_known());
        assert!(OptionNumber::NO_RESPONSE.is_known());
        assert!(!OptionNumber::new(65001).is_known());
        assert!(!OptionNumber::new(65000).is_known());
        assert_eq!(option_value_format(OptionNumber::HOP_LIMIT), None);
        assert_eq!(option_value_format(OptionNumber::NO_RESPONSE), None);
    }

    #[test]
    fn block_szx_size_and_roundtrip() {
        const SIZES: [u16; 7] = [16, 32, 64, 128, 256, 512, 1024];
        for (szx, &size) in SIZES.iter().enumerate() {
            let szx = szx as u8;
            assert_eq!(BlockValue::size_from_szx(szx).expect("legal szx"), size);
            assert_eq!(BlockValue::szx_from_size(size).expect("legal size"), szx);
            let more = szx % 2 == 1;
            let value = BlockValue::from_size(u32::from(szx), more, size).expect("from_size");
            assert_eq!(value.szx(), szx);
            assert_eq!(value.size(), size);
            assert_eq!(value.more(), more);
            assert_eq!(value.num(), u32::from(szx));
            let encoded = encode_block(value);
            assert_eq!(decode_block(encoded.as_bytes()).expect("roundtrip"), value);
            assert_eq!(EncodedUint::from(value).as_bytes(), encoded.as_bytes());
        }
        assert_eq!(
            BlockValue::size_from_szx(BlockValue::SZX_BERT).expect("bert"),
            BlockValue::SIZE_MAX
        );
        assert_eq!(BlockValue::size_from_szx(8), Err(ValueError::IllegalSzx));
        assert_eq!(BlockValue::szx_from_size(15), Err(ValueError::IllegalSzx));
        assert_eq!(BlockValue::szx_from_size(17), Err(ValueError::IllegalSzx));
        assert_eq!(BlockValue::szx_from_size(2048), Err(ValueError::IllegalSzx));
        assert_eq!(BlockValue::SIZE_MAX, 1024);
    }

    #[test]
    fn block_num_boundaries_and_more_flag() {
        let first = BlockValue::new(0, false, 0).expect("zero");
        assert_eq!(first.encode().as_bytes(), &[] as &[u8]);
        assert_eq!(decode_block(&[]).expect("empty"), first);

        let more = BlockValue::new(0, true, 0).expect("more");
        assert_eq!(more.encode().as_bytes(), &[0x08]);
        assert!(more.more());

        let one_byte_max = BlockValue::new(15, false, 0).expect("1-byte NUM");
        assert_eq!(one_byte_max.encode().as_bytes(), &[0xf0]);

        let two_byte_min = BlockValue::new(16, false, 0).expect("2-byte NUM");
        assert_eq!(two_byte_min.encode().as_bytes(), &[0x01, 0x00]);

        let two_byte_max = BlockValue::new(4095, true, 6).expect("2-byte max");
        assert_eq!(two_byte_max.encode().as_bytes(), &[0xff, 0xfe]);

        let three_byte_min = BlockValue::new(4096, false, 6).expect("3-byte NUM");
        assert_eq!(three_byte_min.encode().as_bytes(), &[0x01, 0x00, 0x06]);

        let num_max = BlockValue::new(BlockValue::NUM_MAX, false, 6).expect("NUM max");
        assert_eq!(num_max.encode().as_bytes(), &[0xff, 0xff, 0xf6]);
        assert_eq!(
            decode_block(num_max.encode().as_bytes()).expect("max roundtrip"),
            num_max
        );

        assert_eq!(
            BlockValue::new(BlockValue::NUM_MAX + 1, false, 0),
            Err(ValueError::BlockNumOverflow)
        );
        assert_eq!(
            BlockValue::from_uint(0x0100_0000),
            Err(ValueError::BlockNumOverflow)
        );
        assert_eq!(decode_block(&[1, 0, 0, 0]), Err(ValueError::UintOverflow));
        let bert = decode_block(&[0x07]).expect("bert szx");
        assert!(bert.is_bert());
        assert_eq!(bert.size(), BlockValue::SIZE_MAX);
        assert_eq!(bert.num(), 0);
        assert!(!bert.more());
        assert_eq!(BlockValue::new(0, false, 8), Err(ValueError::IllegalSzx));
        assert_eq!(
            decode_block(&[0, 0x16]).expect("leading zero"),
            BlockValue::new(1, false, 6).expect("num 1 szx 6")
        );
    }

    #[test]
    fn block_option_numbers_critical_bits() {
        assert!(OptionNumber::BLOCK2.is_critical());
        assert!(OptionNumber::BLOCK2.is_unsafe());
        assert!(OptionNumber::BLOCK1.is_critical());
        assert!(OptionNumber::BLOCK1.is_unsafe());
        assert!(OptionNumber::Q_BLOCK1.is_critical());
        assert!(OptionNumber::Q_BLOCK1.is_unsafe());
        assert!(OptionNumber::Q_BLOCK2.is_critical());
        assert!(OptionNumber::Q_BLOCK2.is_unsafe());
        assert!(!OptionNumber::SIZE2.is_critical());
        assert!(!OptionNumber::SIZE2.is_unsafe());
        assert!(OptionNumber::SIZE2.is_no_cache_key());
        assert_eq!(OptionNumber::Q_BLOCK1.get(), 19);
        assert_eq!(OptionNumber::BLOCK2.get(), 23);
        assert_eq!(OptionNumber::BLOCK1.get(), 27);
        assert_eq!(OptionNumber::SIZE2.get(), 28);
        assert_eq!(OptionNumber::Q_BLOCK2.get(), 31);
    }
}
