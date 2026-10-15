//! RFC 9290 concise problem details (CBOR map).
//!
//! Wire format: `knowledge/rfcs/rfc9290.txt`. This module does not restate it.
//! Default CoAP Content-Format is [`ContentFormat::PROBLEM_DETAILS`] (257).

use crate::message::{Code, ContentFormat};

/// Standard Problem Detail key: title.
const KEY_TITLE: i8 = -1;
/// Standard Problem Detail key: detail.
const KEY_DETAIL: i8 = -2;
/// Standard Problem Detail key: response-code.
const KEY_RESPONSE_CODE: i8 = -4;

const MAJOR_UINT: u8 = 0;
const MAJOR_NINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

/// Failure to encode or decode a concise problem-details CBOR map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProblemError {
    /// Output buffer cannot hold the encoded map.
    BufferTooSmall,
    /// Bytes are not a non-empty CBOR map of problem details.
    Invalid,
}

impl core::fmt::Display for ProblemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall => f.write_str("problem-details encode buffer is too small"),
            Self::Invalid => f.write_str("invalid concise problem-details CBOR"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProblemError {}

/// Explicit RFC 9290 writing direction. Absence differs from explicit Auto:
/// absent direction may inherit presentation context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritingDirection {
    /// Left-to-right presentation.
    LeftToRight,
    /// Right-to-left presentation.
    RightToLeft,
    /// Let the presentation layer determine direction.
    Auto,
}

/// Borrowed plain or language-tagged text (RFC 9290 Appendix A).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProblemText<'a> {
    text: &'a str,
    language: Option<&'a str>,
    direction: Option<WritingDirection>,
}
impl<'a> ProblemText<'a> {
    /// Plain text inheriting language and direction from context.
    #[must_use]
    pub const fn plain(text: &'a str) -> Self {
        Self {
            text,
            language: None,
            direction: None,
        }
    }
    /// Tagged text with optional explicit direction. Validates Appendix A CDDL
    /// language syntax, not registry membership or BCP 47 canonicalization.
    ///
    /// # Errors
    /// [`ProblemError::Invalid`] for a language tag outside that syntax.
    pub fn tagged(
        language: &'a str,
        text: &'a str,
        direction: Option<WritingDirection>,
    ) -> Result<Self, ProblemError> {
        validate_language(language)?;
        Ok(Self {
            text,
            language: Some(language),
            direction,
        })
    }
    /// Human-readable text without its presentation metadata.
    #[must_use]
    pub const fn text(self) -> &'a str {
        self.text
    }
    /// Explicit language, or `None` for plain text.
    #[must_use]
    pub const fn language(self) -> Option<&'a str> {
        self.language
    }
    /// Explicit direction; `None` can inherit surrounding context.
    #[must_use]
    pub const fn direction(self) -> Option<WritingDirection> {
        self.direction
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OptionNumbers<'a> {
    Values(&'a [u64]),
    Encoded(&'a [u8]),
}

/// Borrowed iterator over RFC 9290 unprocessed CoAP option numbers.
/// Preserves order and repetitions; values span the CBOR unsigned range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProblemOptions<'a> {
    source: OptionNumbers<'a>,
    at: usize,
    remaining: usize,
}
impl Iterator for ProblemOptions<'_> {
    type Item = u64;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let number = match self.source {
            OptionNumbers::Values(values) => {
                let number = *values.get(self.at)?;
                self.at += 1;
                number
            }
            OptionNumbers::Encoded(bytes) => read_uint(bytes, &mut self.at).ok()?,
        };
        self.remaining -= 1;
        Some(number)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for ProblemOptions<'_> {}
impl core::iter::FusedIterator for ProblemOptions<'_> {}

/// RFC 9290 concise problem details: `response-code` plus optional title/detail.
///
/// Encodes as a CBOR map with Standard Problem Detail keys. The map is
/// non-empty: [`Self::new`] always includes `response-code` (−4), matching
/// the CoAP code on the message. Title (−1) and detail (−2) are optional
/// text with optional language/direction metadata. Default Content-Format is
/// [`ContentFormat::PROBLEM_DETAILS`]. Decoded maps additionally borrow and
/// preserve their original entries, including fields not exposed by this API.
/// On the App face, build these with
/// [`crate::Response::problem`].
///
/// ```
/// use coaptic::message::ProblemDetails;
/// use coaptic::{Code, ContentFormat};
///
/// let details = ProblemDetails::new(Code::NOT_FOUND).title("Not Found");
/// let mut buf = [0u8; 32];
/// let n = details.encode(&mut buf).expect("fits");
/// let parsed = ProblemDetails::decode(&buf[..n]).expect("cbor");
/// assert_eq!(parsed.response_code(), Some(Code::NOT_FOUND));
/// assert_eq!(parsed.title_text(), Some("Not Found"));
/// assert_eq!(ContentFormat::PROBLEM_DETAILS.get(), 257);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProblemDetails<'a> {
    code: Option<Code>,
    title: Option<ProblemText<'a>>,
    detail: Option<ProblemText<'a>>,
    instance: Option<&'a str>,
    base_uri: Option<&'a str>,
    base_language: Option<&'a str>,
    base_direction: Option<WritingDirection>,
    unprocessed: Option<ProblemOptions<'a>>,
    original: Option<&'a [u8]>,
    edited: u8,
}

impl ProblemDetails<'static> {
    /// Problem details for `code`. Encodes `{ -4: code }` until title/detail
    /// are set.
    #[must_use]
    pub const fn new(code: Code) -> Self {
        Self {
            code: Some(code),
            title: None,
            detail: None,
            instance: None,
            base_uri: None,
            base_language: None,
            base_direction: None,
            unprocessed: None,
            original: None,
            edited: 0,
        }
    }
}

impl<'a> ProblemDetails<'a> {
    /// CoAP Content-Format for this payload (`application/concise-problem-details+cbor`).
    pub const CONTENT_FORMAT: ContentFormat = ContentFormat::PROBLEM_DETAILS;

    /// Set the short title (key −1).
    #[must_use]
    pub const fn title(mut self, title: &'a str) -> Self {
        self.title = Some(ProblemText::plain(title));
        self.edited |= 1;
        self
    }

    /// Set the occurrence-specific detail (key −2).
    #[must_use]
    pub const fn detail(mut self, detail: &'a str) -> Self {
        self.detail = Some(ProblemText::plain(detail));
        self.edited |= 2;
        self
    }

    /// `response-code` (−4), if present.
    #[must_use]
    pub const fn response_code(self) -> Option<Code> {
        self.code
    }

    /// Title (−1), if present.
    #[must_use]
    pub const fn title_text(self) -> Option<&'a str> {
        match self.title {
            Some(value) => Some(value.text),
            None => None,
        }
    }

    /// Detail (−2), if present.
    #[must_use]
    pub const fn detail_text(self) -> Option<&'a str> {
        match self.detail {
            Some(value) => Some(value.text),
            None => None,
        }
    }

    /// Title with its explicit language and direction metadata.
    #[must_use]
    pub const fn title_value(self) -> Option<ProblemText<'a>> {
        self.title
    }
    /// Detail with its explicit language and direction metadata.
    #[must_use]
    pub const fn detail_value(self) -> Option<ProblemText<'a>> {
        self.detail
    }
    /// Set title and its presentation metadata.
    #[must_use]
    pub const fn with_title(mut self, title: ProblemText<'a>) -> Self {
        self.title = Some(title);
        self.edited |= 1;
        self
    }
    /// Set detail and its presentation metadata.
    #[must_use]
    pub const fn with_detail(mut self, detail: ProblemText<'a>) -> Self {
        self.detail = Some(detail);
        self.edited |= 2;
        self
    }
    /// Occurrence URI reference; relative references are not resolved here.
    #[must_use]
    pub const fn instance(self) -> Option<&'a str> {
        self.instance
    }
    /// Explicit base URI for resolving references in this item.
    #[must_use]
    pub const fn base_uri(self) -> Option<&'a str> {
        self.base_uri
    }
    /// Explicit language context for plain text. Callers may have external
    /// context; if neither exists, RFC 9290 specifies English.
    #[must_use]
    pub const fn base_language(self) -> Option<&'a str> {
        self.base_language
    }
    /// Explicit direction context. Without any context the default is
    /// left-to-right for plain text, automatic direction for tag-38 text.
    #[must_use]
    pub const fn base_direction(self) -> Option<WritingDirection> {
        self.base_direction
    }

    /// Set RFC 9290 section 3.1.1 option numbers that could not be processed.
    /// One number encodes as an unsigned integer; two or more encode as an
    /// array. Order and repeated numbers are preserved. This list need not
    /// include every problematic option, or only options sent by the client.
    ///
    /// # Errors
    /// [`ProblemError::Invalid`] for an empty list.
    pub fn with_unprocessed_options(mut self, numbers: &'a [u64]) -> Result<Self, ProblemError> {
        if numbers.is_empty() {
            return Err(ProblemError::Invalid);
        }
        self.unprocessed = Some(ProblemOptions {
            source: OptionNumbers::Values(numbers),
            at: 0,
            remaining: numbers.len(),
        });
        self.edited |= 4;
        Ok(self)
    }

    /// Option numbers the producer could not process, or an empty iterator
    /// when key -8 is absent. No integer narrowing or allocation occurs.
    #[must_use]
    pub fn unprocessed_options(self) -> ProblemOptions<'a> {
        self.unprocessed.unwrap_or(ProblemOptions {
            source: OptionNumbers::Values(&[]),
            at: 0,
            remaining: 0,
        })
    }

    /// Encode the CBOR map into `buf`. New maps use deterministic key order
    /// (title, detail, response-code, unprocessed options). Decoded maps retain all original entries
    /// and their order, including unknown extensions. Unedited maps are copied
    /// byte for byte; typed edits replace only their respective values.
    /// This is lossless forwarding, not canonicalization of received CBOR.
    ///
    /// # Errors
    ///
    /// [`ProblemError::BufferTooSmall`] when `buf` cannot hold the map.
    /// [`ProblemError::Invalid`] when no field is set (empty map).
    pub fn encode(self, buf: &mut [u8]) -> Result<usize, ProblemError> {
        if let Some(original) = self.original {
            return self.encode_retained(original, buf);
        }
        let pairs = usize::from(self.title.is_some())
            + usize::from(self.detail.is_some())
            + usize::from(self.code.is_some())
            + usize::from(self.unprocessed.is_some());
        if pairs == 0 {
            return Err(ProblemError::Invalid);
        }
        let mut at = 0usize;
        put_head(buf, &mut at, MAJOR_MAP, pairs as u64)?;
        if let Some(title) = self.title {
            put_nint(buf, &mut at, KEY_TITLE)?;
            put_problem_text(buf, &mut at, title)?;
        }
        if let Some(detail) = self.detail {
            put_nint(buf, &mut at, KEY_DETAIL)?;
            put_problem_text(buf, &mut at, detail)?;
        }
        if let Some(code) = self.code {
            put_nint(buf, &mut at, KEY_RESPONSE_CODE)?;
            put_uint(buf, &mut at, u64::from(code.as_raw()))?;
        }
        if let Some(options) = self.unprocessed {
            put_nint(buf, &mut at, -8)?;
            put_option_numbers(buf, &mut at, options)?;
        }
        Ok(at)
    }

    fn encode_retained(self, original: &[u8], buf: &mut [u8]) -> Result<usize, ProblemError> {
        if self.edited == 0 {
            let mut at = 0;
            put_slice(buf, &mut at, original)?;
            return Ok(at);
        }
        // Decoding already validated these immutable bytes. Scan without an
        // extension table so retained storage stays independent of entry count.
        let mut read = 0;
        let (_, pairs) = read_head(original, &mut read)?;
        let entries = read;
        let mut found = 0;
        for _ in 0..pairs {
            match read_key(original, &mut read)? {
                Some(0) => found |= 1,
                Some(1) => found |= 2,
                Some(7) => found |= 4,
                _ => {}
            }
            skip_item(original, &mut read)?;
        }
        let added = (self.edited & !found).count_ones();
        let mut at = 0;
        put_head(buf, &mut at, MAJOR_MAP, pairs + u64::from(added))?;
        read = entries;
        for _ in 0..pairs {
            let start = read;
            let key = read_key(original, &mut read)?;
            let value = read;
            skip_item(original, &mut read)?;
            let replacement = match key {
                Some(0) if self.edited & 1 != 0 => self.title,
                Some(1) if self.edited & 2 != 0 => self.detail,
                _ => None,
            };
            if key == Some(7) && self.edited & 4 != 0 {
                put_slice(buf, &mut at, &original[start..value])?;
                put_option_numbers(buf, &mut at, self.unprocessed.ok_or(ProblemError::Invalid)?)?;
            } else if let Some(text) = replacement {
                put_slice(buf, &mut at, &original[start..value])?;
                put_problem_text(buf, &mut at, text)?;
            } else {
                put_slice(buf, &mut at, &original[start..read])?;
            }
        }
        for (bit, key, text) in [(1, KEY_TITLE, self.title), (2, KEY_DETAIL, self.detail)] {
            if self.edited & !found & bit != 0 {
                put_nint(buf, &mut at, key)?;
                put_problem_text(buf, &mut at, text.ok_or(ProblemError::Invalid)?)?;
            }
        }
        if self.edited & !found & 4 != 0 {
            put_nint(buf, &mut at, -8)?;
            put_option_numbers(buf, &mut at, self.unprocessed.ok_or(ProblemError::Invalid)?)?;
        }
        Ok(at)
    }

    /// Decode a concise problem-details CBOR map. Unknown fields are ignored
    /// for typed access but borrowed with the input for lossless re-encoding.
    /// Integer keys cover the full CBOR integer range; URI-reference keys are
    /// UTF-8 text. Custom entries (unsigned integer or text keys) must contain
    /// a nonempty map. A map containing only extensions is valid.
    /// Duplicate standard fields -1 through -8 are refused. Title/detail accept
    /// plain text or tag 38, including optional CBOR tags on its language/text
    /// components. Instance/base URI and language/direction context are exposed.
    /// Language validation follows Appendix A CDDL syntax, not registry
    /// membership. URI syntax and extension-specific semantics are not validated.
    /// Definite nested extension values use constant auxiliary memory and work
    /// bounded by the input length. Malformed UTF-8 text and simple values are
    /// refused even inside an unknown extension. Indefinite CBOR is unsupported.
    ///
    /// # Errors
    ///
    /// [`ProblemError::Invalid`] when the bytes are not a non-empty definite
    /// CBOR map, or a value for a known key has the wrong type.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ProblemError> {
        let mut at = 0usize;
        let (major, n) = read_head(bytes, &mut at)?;
        if major != MAJOR_MAP || n == 0 {
            return Err(ProblemError::Invalid);
        }
        let mut out = Self {
            code: None,
            title: None,
            detail: None,
            instance: None,
            base_uri: None,
            base_language: None,
            base_direction: None,
            unprocessed: None,
            original: None,
            edited: 0,
        };
        for _ in 0..n {
            let key = read_key(bytes, &mut at)?;
            match key {
                Some(0) => {
                    if out.title.is_some() {
                        return Err(ProblemError::Invalid);
                    }
                    out.title = Some(read_problem_text(bytes, &mut at)?);
                }
                Some(1) => {
                    if out.detail.is_some() {
                        return Err(ProblemError::Invalid);
                    }
                    out.detail = Some(read_problem_text(bytes, &mut at)?);
                }
                Some(3) => {
                    if out.code.is_some() {
                        return Err(ProblemError::Invalid);
                    }
                    let raw = read_uint(bytes, &mut at)?;
                    if raw > u64::from(u8::MAX) {
                        return Err(ProblemError::Invalid);
                    }
                    out.code = Some(Code::from_raw(raw as u8));
                }
                Some(2) => {
                    if out.instance.is_some() {
                        return Err(ProblemError::Invalid);
                    }
                    out.instance = Some(read_text(bytes, &mut at)?);
                }
                Some(4) => {
                    if out.base_uri.is_some() {
                        return Err(ProblemError::Invalid);
                    }
                    out.base_uri = Some(read_text(bytes, &mut at)?);
                }
                Some(5) => {
                    if out.base_language.is_some() {
                        return Err(ProblemError::Invalid);
                    }
                    let language = read_text(bytes, &mut at)?;
                    validate_language(language)?;
                    out.base_language = Some(language);
                }
                Some(6) => {
                    if out.base_direction.is_some() {
                        return Err(ProblemError::Invalid);
                    }
                    out.base_direction = Some(read_direction(bytes, &mut at)?);
                }
                Some(7) => {
                    if out.unprocessed.is_some() {
                        return Err(ProblemError::Invalid);
                    }
                    out.unprocessed = Some(read_option_numbers(bytes, &mut at)?);
                }
                None => {
                    let mut probe = at;
                    let (major, entries) = read_head(bytes, &mut probe)?;
                    if major != MAJOR_MAP || entries == 0 {
                        return Err(ProblemError::Invalid);
                    }
                    skip_item(bytes, &mut at)?;
                }
                _ => skip_item(bytes, &mut at)?,
            }
        }
        if at != bytes.len() {
            return Err(ProblemError::Invalid);
        }
        out.original = Some(bytes);
        Ok(out)
    }
}

fn put_option_numbers(
    buf: &mut [u8],
    at: &mut usize,
    options: ProblemOptions<'_>,
) -> Result<(), ProblemError> {
    if options.len() > 1 {
        put_head(buf, at, MAJOR_ARRAY, options.len() as u64)?;
    }
    for number in options {
        put_uint(buf, at, number)?;
    }
    Ok(())
}

fn read_option_numbers<'a>(
    bytes: &'a [u8],
    at: &mut usize,
) -> Result<ProblemOptions<'a>, ProblemError> {
    let start = *at;
    let (major, count) = read_head(bytes, at)?;
    let (start, remaining) = if major == MAJOR_UINT {
        (start, 1)
    } else if major == MAJOR_ARRAY && count >= 2 {
        let start = *at;
        let remaining = usize::try_from(count).map_err(|_| ProblemError::Invalid)?;
        if remaining > bytes.len().saturating_sub(*at) {
            return Err(ProblemError::Invalid);
        }
        for _ in 0..remaining {
            read_uint(bytes, at)?;
        }
        (start, remaining)
    } else {
        return Err(ProblemError::Invalid);
    };
    Ok(ProblemOptions {
        source: OptionNumbers::Encoded(&bytes[start..*at]),
        at: 0,
        remaining,
    })
}

fn put(buf: &mut [u8], at: &mut usize, byte: u8) -> Result<(), ProblemError> {
    if *at >= buf.len() {
        return Err(ProblemError::BufferTooSmall);
    }
    buf[*at] = byte;
    *at += 1;
    Ok(())
}

fn put_slice(buf: &mut [u8], at: &mut usize, bytes: &[u8]) -> Result<(), ProblemError> {
    if buf.len().saturating_sub(*at) < bytes.len() {
        return Err(ProblemError::BufferTooSmall);
    }
    buf[*at..*at + bytes.len()].copy_from_slice(bytes);
    *at += bytes.len();
    Ok(())
}

fn put_head(buf: &mut [u8], at: &mut usize, major: u8, n: u64) -> Result<(), ProblemError> {
    if n <= 23 {
        put(buf, at, (major << 5) | (n as u8))
    } else if n <= 255 {
        put(buf, at, (major << 5) | 24)?;
        put(buf, at, n as u8)
    } else if n <= u64::from(u16::MAX) {
        put(buf, at, (major << 5) | 25)?;
        put(buf, at, (n >> 8) as u8)?;
        put(buf, at, n as u8)
    } else if n <= u64::from(u32::MAX) {
        put(buf, at, (major << 5) | 26)?;
        for shift in [24, 16, 8, 0] {
            put(buf, at, (n >> shift) as u8)?;
        }
        Ok(())
    } else {
        put(buf, at, (major << 5) | 27)?;
        for shift in [56, 48, 40, 32, 24, 16, 8, 0] {
            put(buf, at, (n >> shift) as u8)?;
        }
        Ok(())
    }
}

fn put_uint(buf: &mut [u8], at: &mut usize, n: u64) -> Result<(), ProblemError> {
    put_head(buf, at, MAJOR_UINT, n)
}

fn put_nint(buf: &mut [u8], at: &mut usize, n: i8) -> Result<(), ProblemError> {
    debug_assert!(n < 0);
    put_head(
        buf,
        at,
        MAJOR_NINT,
        u64::from((-1_i16 - i16::from(n)) as u8),
    )
}

fn put_text(buf: &mut [u8], at: &mut usize, text: &str) -> Result<(), ProblemError> {
    put_head(buf, at, MAJOR_TEXT, text.len() as u64)?;
    put_slice(buf, at, text.as_bytes())
}

fn validate_language(language: &str) -> Result<(), ProblemError> {
    let mut subtags = language.split('-');
    let first = subtags.next().ok_or(ProblemError::Invalid)?;
    if first.is_empty() || first.len() > 8 || !first.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(ProblemError::Invalid);
    }
    if subtags.any(|part| {
        part.is_empty() || part.len() > 8 || !part.bytes().all(|b| b.is_ascii_alphanumeric())
    }) {
        return Err(ProblemError::Invalid);
    }
    Ok(())
}
fn put_problem_text(
    buf: &mut [u8],
    at: &mut usize,
    value: ProblemText<'_>,
) -> Result<(), ProblemError> {
    if let Some(language) = value.language {
        put_head(buf, at, MAJOR_TAG, 38)?;
        put_head(
            buf,
            at,
            MAJOR_ARRAY,
            if value.direction.is_some() { 3 } else { 2 },
        )?;
        put_text(buf, at, language)?;
    }
    put_text(buf, at, value.text)?;
    if let Some(direction) = value.direction {
        put(
            buf,
            at,
            match direction {
                WritingDirection::LeftToRight => 0xf4,
                WritingDirection::RightToLeft => 0xf5,
                WritingDirection::Auto => 0xf6,
            },
        )?;
    }
    Ok(())
}
fn read_direction(bytes: &[u8], at: &mut usize) -> Result<WritingDirection, ProblemError> {
    need(bytes, *at, 1)?;
    let direction = match bytes[*at] {
        0xf4 => WritingDirection::LeftToRight,
        0xf5 => WritingDirection::RightToLeft,
        0xf6 => WritingDirection::Auto,
        _ => return Err(ProblemError::Invalid),
    };
    *at += 1;
    Ok(direction)
}
fn read_annotated_text<'a>(bytes: &'a [u8], at: &mut usize) -> Result<&'a str, ProblemError> {
    loop {
        let start = *at;
        let (major, _) = read_head(bytes, at)?;
        if major != MAJOR_TAG {
            *at = start;
            return read_text(bytes, at);
        }
    }
}
fn read_problem_text<'a>(bytes: &'a [u8], at: &mut usize) -> Result<ProblemText<'a>, ProblemError> {
    let start = *at;
    let (major, tag) = read_head(bytes, at)?;
    if major == MAJOR_TEXT {
        *at = start;
        return Ok(ProblemText::plain(read_text(bytes, at)?));
    }
    if major != MAJOR_TAG || tag != 38 {
        return Err(ProblemError::Invalid);
    }
    let (major, count) = read_head(bytes, at)?;
    if major != MAJOR_ARRAY || !(2..=3).contains(&count) {
        return Err(ProblemError::Invalid);
    }
    let language = read_annotated_text(bytes, at)?;
    let text = read_annotated_text(bytes, at)?;
    let direction = if count == 3 {
        Some(read_direction(bytes, at)?)
    } else {
        None
    };
    ProblemText::tagged(language, text, direction)
}

fn need(bytes: &[u8], at: usize, n: usize) -> Result<(), ProblemError> {
    if bytes.len().saturating_sub(at) < n {
        Err(ProblemError::Invalid)
    } else {
        Ok(())
    }
}

fn read_head(bytes: &[u8], at: &mut usize) -> Result<(u8, u64), ProblemError> {
    need(bytes, *at, 1)?;
    let b = bytes[*at];
    *at += 1;
    let major = b >> 5;
    let ai = b & 0x1f;
    let n = match ai {
        0..=23 => u64::from(ai),
        24 => {
            need(bytes, *at, 1)?;
            let n = u64::from(bytes[*at]);
            *at += 1;
            n
        }
        25 => {
            need(bytes, *at, 2)?;
            let n = u64::from(u16::from_be_bytes([bytes[*at], bytes[*at + 1]]));
            *at += 2;
            n
        }
        26 => {
            need(bytes, *at, 4)?;
            let n = u64::from(u32::from_be_bytes([
                bytes[*at],
                bytes[*at + 1],
                bytes[*at + 2],
                bytes[*at + 3],
            ]));
            *at += 4;
            n
        }
        27 => {
            need(bytes, *at, 8)?;
            let n = u64::from_be_bytes([
                bytes[*at],
                bytes[*at + 1],
                bytes[*at + 2],
                bytes[*at + 3],
                bytes[*at + 4],
                bytes[*at + 5],
                bytes[*at + 6],
                bytes[*at + 7],
            ]);
            *at += 8;
            n
        }
        _ => return Err(ProblemError::Invalid),
    };
    Ok((major, n))
}

// Some(n) identifies the standard key -1-n without narrowing to i64.
// None identifies a custom unsigned-integer or URI-reference text key.
fn read_key(bytes: &[u8], at: &mut usize) -> Result<Option<u64>, ProblemError> {
    let start = *at;
    let (major, n) = read_head(bytes, at)?;
    match major {
        MAJOR_NINT => Ok(Some(n)),
        MAJOR_UINT => Ok(None),
        MAJOR_TEXT => {
            *at = start;
            read_text(bytes, at)?;
            Ok(None)
        }
        _ => Err(ProblemError::Invalid),
    }
}

fn read_uint(bytes: &[u8], at: &mut usize) -> Result<u64, ProblemError> {
    let (major, n) = read_head(bytes, at)?;
    if major == MAJOR_UINT {
        Ok(n)
    } else {
        Err(ProblemError::Invalid)
    }
}

fn read_text<'a>(bytes: &'a [u8], at: &mut usize) -> Result<&'a str, ProblemError> {
    let (major, n) = read_head(bytes, at)?;
    if major != MAJOR_TEXT {
        return Err(ProblemError::Invalid);
    }
    let len = usize::try_from(n).map_err(|_| ProblemError::Invalid)?;
    need(bytes, *at, len)?;
    let slice = &bytes[*at..*at + len];
    *at += len;
    core::str::from_utf8(slice).map_err(|_| ProblemError::Invalid)
}

fn skip_item(bytes: &[u8], at: &mut usize) -> Result<(), ProblemError> {
    // Definite CBOR is a preorder stream. Count remaining child items instead
    // of recursing through container/tag depth. Each item consumes at least
    // one input byte; impossible counts fail before iterating over them.
    let mut pending = 1u64;
    while pending != 0 {
        pending -= 1;
        let head_at = *at;
        let (major, n) = read_head(bytes, at)?;
        let children = match major {
            MAJOR_UINT | MAJOR_NINT => 0,
            MAJOR_SIMPLE => {
                if bytes[head_at] == 0xf8 && n < 32 {
                    return Err(ProblemError::Invalid);
                }
                0
            }
            MAJOR_BYTES | MAJOR_TEXT => {
                let len = usize::try_from(n).map_err(|_| ProblemError::Invalid)?;
                need(bytes, *at, len)?;
                if major == MAJOR_TEXT {
                    core::str::from_utf8(&bytes[*at..*at + len])
                        .map_err(|_| ProblemError::Invalid)?;
                }
                *at += len;
                0
            }
            MAJOR_ARRAY => n,
            MAJOR_MAP => n.checked_mul(2).ok_or(ProblemError::Invalid)?,
            MAJOR_TAG => 1,
            _ => return Err(ProblemError::Invalid),
        };
        pending = pending.checked_add(children).ok_or(ProblemError::Invalid)?;
        if pending > bytes.len().saturating_sub(*at) as u64 {
            return Err(ProblemError::Invalid);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{ProblemDetails, ProblemError, ProblemText, WritingDirection};
    use crate::message::Code;

    /// `{ -4: 132 }` — 4.04 Not Found, response-code only (RFC 9290).
    const NOT_FOUND_CODE_ONLY: &[u8] = &[0xa1, 0x23, 0x18, 0x84];

    /// `{ -1: "Not Found", -4: 132 }`.
    const NOT_FOUND_TITLED: &[u8] = &[
        0xa2, 0x20, 0x69, b'N', b'o', b't', b' ', b'F', b'o', b'u', b'n', b'd', 0x23, 0x18, 0x84,
    ];

    /// Figure 3 standard keys only: title, detail, response-code 128 (4.00).
    const FIGURE3_STANDARD: &[u8] = &[
        0xa3, 0x20, 0x72, b't', b'i', b't', b'l', b'e', b' ', b'o', b'f', b' ', b't', b'h', b'e',
        b' ', b'e', b'r', b'r', b'o', b'r', 0x21, 0x78, 0x24, b'd', b'e', b't', b'a', b'i', b'l',
        b'e', b'd', b' ', b'i', b'n', b'f', b'o', b'r', b'm', b'a', b't', b'i', b'o', b'n', b' ',
        b'a', b'b', b'o', b'u', b't', b' ', b't', b'h', b'e', b' ', b'e', b'r', b'r', b'o', b'r',
        0x23, 0x18, 0x80,
    ];

    #[test]
    fn encode_not_found_matches_known_cbor() {
        let mut buf = [0u8; 16];
        let n = ProblemDetails::new(Code::NOT_FOUND)
            .encode(&mut buf)
            .expect("encode");
        assert_eq!(&buf[..n], NOT_FOUND_CODE_ONLY);
        assert_eq!(Code::NOT_FOUND.as_raw(), 132);
    }

    #[test]
    fn encode_titled_not_found_matches_known_cbor() {
        let mut buf = [0u8; 32];
        let n = ProblemDetails::new(Code::NOT_FOUND)
            .title("Not Found")
            .encode(&mut buf)
            .expect("encode");
        assert_eq!(&buf[..n], NOT_FOUND_TITLED);
    }

    #[test]
    fn encode_figure3_standard_keys_matches_known_cbor() {
        let mut buf = [0u8; 80];
        let n = ProblemDetails::new(Code::BAD_REQUEST)
            .title("title of the error")
            .detail("detailed information about the error")
            .encode(&mut buf)
            .expect("encode");
        assert_eq!(&buf[..n], FIGURE3_STANDARD);
        assert_eq!(Code::BAD_REQUEST.as_raw(), 128);
    }

    #[test]
    fn decode_round_trips_fields() {
        let mut buf = [0u8; 80];
        let n = ProblemDetails::new(Code::METHOD_NOT_ALLOWED)
            .title("Method Not Allowed")
            .detail("POST on a GET-only path")
            .encode(&mut buf)
            .expect("encode");
        let parsed = ProblemDetails::decode(&buf[..n]).expect("decode");
        assert_eq!(parsed.response_code(), Some(Code::METHOD_NOT_ALLOWED));
        assert_eq!(parsed.title_text(), Some("Method Not Allowed"));
        assert_eq!(parsed.detail_text(), Some("POST on a GET-only path"));
    }

    #[test]
    fn decode_skips_unknown_key() {
        // `{ -4: 132, -99: 1 }` — unknown standard key ignored.
        let bytes = [0xa2, 0x23, 0x18, 0x84, 0x38, 0x62, 0x01];
        let parsed = ProblemDetails::decode(&bytes).expect("decode");
        assert_eq!(parsed.response_code(), Some(Code::NOT_FOUND));
        assert!(parsed.title_text().is_none());
    }

    #[test]
    fn extension_only_maps_retain_uri_and_full_width_integer_keys() {
        let maps: &[&[u8]] = &[
            // {-9: [1, 2]}; a known title or response-code is not required.
            &[0xa1, 0x28, 0x82, 1, 2],
            // {"urn:x": {0: 1}}.
            &[0xa1, 0x65, b'u', b'r', b'n', b':', b'x', 0xa1, 0, 1],
            // Full CBOR uint and nint domains (including beyond i64).
            &[
                0xa1, 0x1b, 255, 255, 255, 255, 255, 255, 255, 255, 0xa1, 0, 1,
            ],
            &[0xa1, 0x3b, 255, 255, 255, 255, 255, 255, 255, 255, 0],
            &[0xa1, 0x3b, 127, 255, 255, 255, 255, 255, 255, 255, 0],
            // Nonpreferred (but well-formed) integer encoding is retained.
            &[0xa1, 0x38, 8, 0x18, 1],
        ];
        for &wire in maps {
            let parsed = ProblemDetails::decode(wire).unwrap();
            assert_eq!(parsed.response_code(), None);
            assert_eq!(parsed.title_text(), None);
            let mut output = [0u8; 64];
            let n = parsed.encode(&mut output).unwrap();
            assert_eq!(&output[..n], wire);
            for capacity in 0..n {
                assert_eq!(
                    parsed.encode(&mut output[..capacity]),
                    Err(ProblemError::BufferTooSmall)
                );
            }
            for end in 0..wire.len() {
                assert_eq!(
                    ProblemDetails::decode(&wire[..end]),
                    Err(ProblemError::Invalid)
                );
            }
        }
    }

    #[test]
    fn edits_preserve_all_other_entries_and_replace_without_duplicates() {
        // {-9: [1,2], -1: "a", "x": {0: 1}, -4: 132, -2: "d"}.
        let original = [
            0xa5, 0x28, 0x82, 1, 2, 0x20, 0x61, b'a', 0x61, b'x', 0xa1, 0, 1, 0x23, 0x18, 0x84,
            0x21, 0x61, b'd',
        ];
        let parsed = ProblemDetails::decode(&original).unwrap();
        let edited = parsed.title("new").detail("why");
        let expected = [
            0xa5, 0x28, 0x82, 1, 2, 0x20, 0x63, b'n', b'e', b'w', 0x61, b'x', 0xa1, 0, 1, 0x23,
            0x18, 0x84, 0x21, 0x63, b'w', b'h', b'y',
        ];
        let mut output = [0; 64];
        let n = edited.encode(&mut output).unwrap();
        assert_eq!(&output[..n], &expected);
        assert_eq!(
            ProblemDetails::decode(&output[..n]).unwrap().detail_text(),
            Some("why")
        );
        for capacity in 0..n {
            assert_eq!(
                edited.encode(&mut output[..capacity]),
                Err(ProblemError::BufferTooSmall)
            );
        }
        // Repeated builder calls replace one value; they do not add map entries.
        let edited = parsed.title("old").title("new");
        let n = edited.encode(&mut output).unwrap();
        assert_eq!(output[0], 0xa5);
        assert_eq!(
            ProblemDetails::decode(&output[..n]).unwrap().title_text(),
            Some("new")
        );
        let n = parsed.encode(&mut output).unwrap();
        assert_eq!(&output[..n], &original);

        let extensions = [0xa1, 0x28, 0];
        let edited = ProblemDetails::decode(&extensions)
            .unwrap()
            .title("a")
            .detail("b");
        let n = edited.encode(&mut output).unwrap();
        assert_eq!(
            &output[..n],
            &[0xa3, 0x28, 0, 0x20, 0x61, b'a', 0x21, 0x61, b'b']
        );
    }

    #[test]
    fn invalid_extension_shapes_keys_and_duplicate_typed_fields_are_refused() {
        let invalid: &[&[u8]] = &[
            &[0xa1, 0, 0], // Custom value must be a nonempty map.
            &[0xa1, 0, 0xa0],
            &[0xa1, 0x61, b'x', 0x82, 1, 2],
            &[0xa1, 0x61, 255, 0xa1, 0, 1], // Invalid UTF-8 key.
            &[0xa1, 0x40, 0],               // Byte string is not a URI key.
            &[0xa1, 0xf4, 0],
            &[0xa2, 0x20, 0x61, b'a', 0x20, 0x61, b'b'],
            &[0xa2, 0x21, 0x61, b'a', 0x21, 0x61, b'b'],
            &[0xa2, 0x23, 0x18, 0x84, 0x38, 3, 0x18, 0x84],
        ];
        for wire in invalid {
            assert_eq!(
                ProblemDetails::decode(wire),
                Err(ProblemError::Invalid),
                "{wire:x?}"
            );
        }
    }

    #[test]
    fn rfc9290_language_examples_decode_encode_and_retain_metadata() {
        // Literal Appendix A.3 tag-38 values wrapped in {-1: value}.
        let examples: &[(&[u8], &str, &str, Option<WritingDirection>)] = &[
            (
                &[
                    0xa1, 0x20, 0xd8, 0x26, 0x82, 0x62, b'e', b'n', 0x65, b'H', b'e', b'l', b'l',
                    b'o',
                ],
                "en",
                "Hello",
                None,
            ),
            (
                &[
                    0xa1, 0x20, 0xd8, 0x26, 0x82, 0x62, b'f', b'r', 0x67, b'B', b'o', b'n', b'j',
                    b'o', b'u', b'r',
                ],
                "fr",
                "Bonjour",
                None,
            ),
            (
                &[
                    0xa1, 0x20, 0xd8, 0x26, 0x83, 0x62, b'h', b'e', 0x68, 0xd7, 0xa9, 0xd7, 0x9c,
                    0xd7, 0x95, 0xd7, 0x9d, 0xf5,
                ],
                "he",
                "שלום",
                Some(WritingDirection::RightToLeft),
            ),
        ];
        for &(wire, language, text, direction) in examples {
            let parsed = ProblemDetails::decode(wire).unwrap();
            let title = parsed.title_value().unwrap();
            assert_eq!(title.text(), text);
            assert_eq!(title.language(), Some(language));
            assert_eq!(title.direction(), direction);
            assert_eq!(parsed.title_text(), Some(text));
            let mut out = [0; 128];
            let n = parsed.encode(&mut out).unwrap();
            assert_eq!(&out[..n], wire);
            // Re-encode the typed value, not just the retained input bytes.
            let n = parsed
                .with_title(ProblemText::tagged(language, text, direction).unwrap())
                .encode(&mut out)
                .unwrap();
            assert_eq!(&out[..n], wire);
            for capacity in 0..n {
                assert_eq!(
                    parsed.with_title(title).encode(&mut out[..capacity]),
                    Err(ProblemError::BufferTooSmall)
                );
            }
            for end in 0..wire.len() {
                assert_eq!(
                    ProblemDetails::decode(&wire[..end]),
                    Err(ProblemError::Invalid)
                );
            }
        }
    }

    #[test]
    fn context_and_explicit_auto_remain_distinct_across_edits() {
        // {-1: "a", -3: "/1", -5: "coap://h", -6: "fr", -7: true, -9: 0}.
        let wire = [
            0xa6, 0x20, 0x61, b'a', 0x22, 0x62, b'/', b'1', 0x24, 0x68, b'c', b'o', b'a', b'p',
            b':', b'/', b'/', b'h', 0x25, 0x62, b'f', b'r', 0x26, 0xf5, 0x28, 0,
        ];
        let parsed = ProblemDetails::decode(&wire).unwrap();
        assert_eq!(parsed.instance(), Some("/1"));
        assert_eq!(parsed.base_uri(), Some("coap://h"));
        assert_eq!(parsed.base_language(), Some("fr"));
        assert_eq!(parsed.base_direction(), Some(WritingDirection::RightToLeft));
        assert_eq!(parsed.title_value().unwrap(), ProblemText::plain("a"));
        for direction in [
            None,
            Some(WritingDirection::Auto),
            Some(WritingDirection::LeftToRight),
            Some(WritingDirection::RightToLeft),
        ] {
            let title = ProblemText::tagged("EN-us", "hello", direction).unwrap();
            let edited = parsed.with_title(title).with_detail(title);
            let mut out = [0; 128];
            let n = edited.encode(&mut out).unwrap();
            let decoded = ProblemDetails::decode(&out[..n]).unwrap();
            assert_eq!(decoded.title_value(), Some(title));
            assert_eq!(decoded.detail_value(), Some(title));
            assert_eq!(decoded.base_direction(), parsed.base_direction());
            assert_eq!(decoded.base_language(), parsed.base_language());
            assert_eq!(decoded.instance(), parsed.instance());
            assert_eq!(decoded.base_uri(), parsed.base_uri());
            // Original URI/context/unknown entries survive exactly.
            assert!(
                out[..n]
                    .windows(wire.len() - 4)
                    .any(|part| part == &wire[4..])
            );
            let n = decoded.title("plain").encode(&mut [0; 128]).unwrap();
            assert!(n > 0);
        }
        let mut out = [0; 64];
        let n = ProblemDetails::new(Code::BAD_REQUEST)
            .with_title(ProblemText::tagged("en", "x", Some(WritingDirection::Auto)).unwrap())
            .encode(&mut out)
            .unwrap();
        assert_eq!(
            &out[..n],
            &[
                0xa2, 0x20, 0xd8, 0x26, 0x83, 0x62, b'e', b'n', 0x61, b'x', 0xf6, 0x23, 0x18, 0x80
            ]
        );
    }

    #[test]
    fn tagged_components_are_iterative_and_annotations_survive_forwarding() {
        let mut wire = std::vec![0xa1, 0x21, 0xd8, 0x26, 0x82];
        for _ in 0..100_000 {
            wire.extend_from_slice(&[0xd9, 0xea, 0x60]);
        }
        wire.extend_from_slice(&[0x62, b'e', b'n', 0xd9, 0xea, 0x60, 0x61, b'x']);
        let parsed = ProblemDetails::decode(&wire).unwrap();
        assert_eq!(parsed.detail_value().unwrap().language(), Some("en"));
        let mut out = std::vec![0; wire.len()];
        let n = parsed.encode(&mut out).unwrap();
        assert_eq!(&out[..n], wire);
        assert_eq!(
            ProblemDetails::decode(&wire[..wire.len() - 1]),
            Err(ProblemError::Invalid)
        );
    }

    #[test]
    fn malformed_language_direction_context_and_duplicates_are_refused() {
        for language in [
            "",
            "1en",
            "en-",
            "-en",
            "en--US",
            "abcdefghi",
            "en-123456789",
            "en_US",
            "é",
            "en a",
        ] {
            assert_eq!(
                ProblemText::tagged(language, "x", None),
                Err(ProblemError::Invalid)
            );
            let mut wire = std::vec![0xa1, 0x20, 0xd8, 0x26, 0x82];
            wire.push(0x60 + language.len() as u8);
            wire.extend_from_slice(language.as_bytes());
            wire.extend_from_slice(&[0x61, b'x']);
            assert_eq!(ProblemDetails::decode(&wire), Err(ProblemError::Invalid));
        }
        for language in [
            "en",
            "EN-us",
            "zh-Hant-TW",
            "x-private",
            "i-klingon",
            "abcdefgh-12345678",
        ] {
            assert!(ProblemText::tagged(language, "x", None).is_ok());
        }
        let invalid: &[&[u8]] = &[
            &[0xa1, 0x20, 0xd8, 0x25, 0x82, 0x62, b'e', b'n', 0x61, b'x'],
            &[0xa1, 0x20, 0xd8, 0x26, 0x81, 0x62, b'e', b'n'],
            &[
                0xa1, 0x20, 0xd8, 0x26, 0x84, 0x62, b'e', b'n', 0x61, b'x', 0xf4, 0,
            ],
            &[
                0xa1, 0x20, 0xd8, 0x26, 0x83, 0x62, b'e', b'n', 0x61, b'x', 0xf7,
            ],
            &[0xa1, 0x20, 0xd8, 0x26, 0x82, 0x62, b'e', b'n', 0x41, b'x'],
            &[0xa1, 0x20, 0xd8, 0x26, 0x82, 0x62, b'e', b'n', 0x61, 255],
            &[0xa1, 0x22, 0],
            &[0xa1, 0x24, 0],
            &[0xa1, 0x25, 0x60],
            &[0xa1, 0x26, 0],
            &[0xa2, 0x22, 0x60, 0x22, 0x60],
            &[0xa2, 0x24, 0x60, 0x24, 0x60],
            &[0xa2, 0x25, 0x62, b'e', b'n', 0x25, 0x62, b'f', b'r'],
            &[0xa2, 0x26, 0xf6, 0x26, 0xf4],
        ];
        for wire in invalid {
            assert_eq!(
                ProblemDetails::decode(wire),
                Err(ProblemError::Invalid),
                "{wire:x?}"
            );
        }
    }

    #[test]
    fn decode_rejects_empty_or_non_map() {
        assert_eq!(ProblemDetails::decode(&[]), Err(ProblemError::Invalid));
        assert_eq!(ProblemDetails::decode(&[0xa0]), Err(ProblemError::Invalid));
        assert_eq!(ProblemDetails::decode(&[0x01]), Err(ProblemError::Invalid));
    }

    #[test]
    fn encode_empty_is_invalid_and_tiny_buf_fails() {
        let empty = ProblemDetails {
            code: None,
            title: None,
            detail: None,
            instance: None,
            base_uri: None,
            base_language: None,
            base_direction: None,
            unprocessed: None,
            original: None,
            edited: 0,
        };
        let mut buf = [0u8; 16];
        assert_eq!(empty.encode(&mut buf), Err(ProblemError::Invalid));
        assert_eq!(
            ProblemDetails::new(Code::NOT_FOUND).encode(&mut []),
            Err(ProblemError::BufferTooSmall)
        );
    }

    #[test]
    fn long_text_uses_one_byte_length() {
        let title = "Request Entity Incomplete";
        assert_eq!(title.len(), 25);
        let mut buf = [0u8; 48];
        let n = ProblemDetails::new(Code::REQUEST_ENTITY_INCOMPLETE)
            .title(title)
            .encode(&mut buf)
            .expect("encode");
        assert_eq!(buf[0], 0xa2);
        assert_eq!(buf[1], 0x20);
        assert_eq!(&buf[2..4], &[0x78, 25]);
        let parsed = ProblemDetails::decode(&buf[..n]).expect("decode");
        assert_eq!(
            parsed.response_code(),
            Some(Code::REQUEST_ENTITY_INCOMPLETE)
        );
        assert_eq!(parsed.title_text(), Some(title));
        assert_eq!(Code::REQUEST_ENTITY_INCOMPLETE.as_raw(), 136);
    }
    #[test]
    fn deeply_nested_extensions_use_iterative_input_bounded_scanning() {
        let mut bytes = std::vec![0xa2, 0x20, 0x61, b'a', 0x28];
        for _ in 0..100_000 {
            // One-entry map, integer key, one-element array, unknown tag 60000.
            bytes.extend_from_slice(&[0xa1, 0, 0x81, 0xd9, 0xea, 0x60]);
        }
        bytes.push(0);
        let parsed = ProblemDetails::decode(&bytes).unwrap();
        assert_eq!(parsed.title_text(), Some("a"));
        assert_eq!(
            ProblemDetails::decode(&bytes[..bytes.len() - 1]),
            Err(ProblemError::Invalid)
        );
    }

    #[test]
    fn unknown_extensions_refuse_impossible_counts_and_malformed_values() {
        let invalid: &[&[u8]] = &[
            &[0x9b, 255, 255, 255, 255, 255, 255, 255, 255],
            &[0xbb, 255, 255, 255, 255, 255, 255, 255, 255],
            &[0x82, 0],
            &[0xa1, 0],
            &[0xd9, 0xea, 0x60],
            &[0x62, 0xc3, 0x28],
            &[0xf8, 0],
            &[0xf8, 31],
            &[0x9f, 0, 0xff],
        ];
        for value in invalid {
            let mut bytes = std::vec![0xa2, 0x20, 0x61, b'a', 0x28];
            bytes.extend_from_slice(value);
            assert_eq!(
                ProblemDetails::decode(&bytes),
                Err(ProblemError::Invalid),
                "{value:x?}"
            );
        }
        for value in [
            &[0x42, 0xc3, 0x28][..],
            &[0xf8, 32],
            &[0xf8, 255],
            &[0xf9, 0, 0],
            &[0x80],
            &[0xa0],
        ] {
            let mut bytes = std::vec![0xa2, 0x20, 0x61, b'a', 0x28];
            bytes.extend_from_slice(value);
            assert_eq!(
                ProblemDetails::decode(&bytes).unwrap().title_text(),
                Some("a")
            );
        }
    }
    #[test]
    fn unprocessed_option_numbers_match_literal_scalar_and_array_forms() {
        for (wire, expected) in [
            (&[0xa1, 0x27, 0x00][..], &[0][..]),
            (&[0xa1, 0x27, 0x18, 0x3c][..], &[60][..]),
            (&[0xa1, 0x27, 0x82, 0x17, 0x17][..], &[23, 23][..]),
            (
                &[
                    0xa1, 0x27, 0x83, 0x01, 0x19, 0xff, 0xff, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ][..],
                &[1, 65535, u64::MAX][..],
            ),
        ] {
            let parsed = ProblemDetails::decode(wire).unwrap();
            let mut values = parsed.unprocessed_options();
            assert_eq!(values.len(), expected.len());
            for expected in expected {
                assert_eq!(values.next(), Some(*expected));
            }
            assert_eq!(values.len(), 0);
            assert_eq!(values.next(), None);
            assert_eq!(values.next(), None);
            let mut out = [0; 128];
            let n = parsed.encode(&mut out).unwrap();
            assert_eq!(&out[..n], wire);
            let built = ProblemDetails::new(Code::BAD_OPTION)
                .with_unprocessed_options(expected)
                .unwrap();
            let n = built.encode(&mut out).unwrap();
            assert!(
                ProblemDetails::decode(&out[..n])
                    .unwrap()
                    .unprocessed_options()
                    .eq(expected.iter().copied())
            );
            for capacity in 0..n {
                assert_eq!(
                    built.encode(&mut out[..capacity]),
                    Err(ProblemError::BufferTooSmall)
                );
            }
        }
        assert_eq!(
            ProblemDetails::new(Code::BAD_OPTION)
                .unprocessed_options()
                .next(),
            None
        );
        assert_eq!(
            ProblemDetails::new(Code::BAD_OPTION).with_unprocessed_options(&[]),
            Err(ProblemError::Invalid)
        );
    }

    #[test]
    fn unprocessed_options_reject_invalid_shapes_and_duplicate_fields() {
        for wire in [
            &[0xa1, 0x27, 0x80][..],
            &[0xa1, 0x27, 0x81, 0x01][..],
            &[0xa1, 0x27, 0x20][..],
            &[0xa1, 0x27, 0xf4][..],
            &[0xa1, 0x27, 0x61, b'x'][..],
            &[0xa1, 0x27, 0x82, 0x01][..],
            &[0xa1, 0x27, 0x82, 0x01, 0x20][..],
            &[
                0xa1, 0x27, 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ][..],
            &[0xa2, 0x27, 0x01, 0x38, 0x07, 0x02][..],
        ] {
            assert_eq!(
                ProblemDetails::decode(wire),
                Err(ProblemError::Invalid),
                "{wire:?}"
            );
        }
    }

    #[test]
    fn unprocessed_option_edits_preserve_unrelated_wire_entries() {
        let original = [0xa2, 0x01, 0xa1, 0x18, 0x01, 0x18, 0x02, 0x27, 0x18, 0x03];
        let parsed = ProblemDetails::decode(&original).unwrap();
        let mut out = [0; 128];
        let edited = parsed
            .with_unprocessed_options(&[23, 60])
            .unwrap()
            .title("why");
        let n = edited.encode(&mut out).unwrap();
        assert_eq!(
            &out[..n],
            &[
                0xa3, 0x01, 0xa1, 0x18, 0x01, 0x18, 0x02, 0x27, 0x82, 0x17, 0x18, 0x3c, 0x20, 0x63,
                b'w', b'h', b'y'
            ]
        );
        let absent = [0xa1, 0x01, 0xa1, 0x18, 0x01, 0x18, 0x02];
        let added = ProblemDetails::decode(&absent)
            .unwrap()
            .with_unprocessed_options(&[60])
            .unwrap();
        let n = added.encode(&mut out).unwrap();
        assert_eq!(
            &out[..n],
            &[0xa2, 0x01, 0xa1, 0x18, 0x01, 0x18, 0x02, 0x27, 0x18, 0x3c]
        );
    }
}
