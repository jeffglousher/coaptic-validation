//! RFC 9177 missing-blocks CBOR sequence.
//!
//! Wire format: `knowledge/rfcs/rfc9177.txt` §5. This module does not restate it.
//! Default CoAP Content-Format is [`ContentFormat::MISSING_BLOCKS`] (272).

use crate::message::ContentFormat;

const MAJOR_UINT: u8 = 0;

/// Failure to encode or decode an RFC 9177 missing-blocks CBOR sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissingBlocksError {
    /// Output buffer cannot hold the encoded sequence.
    BufferTooSmall,
    /// Bytes are not a non-empty CBOR sequence of unsigned integers, or no
    /// missing block numbers were supplied.
    Invalid,
}

impl core::fmt::Display for MissingBlocksError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall => f.write_str("missing-blocks encode buffer is too small"),
            Self::Invalid => f.write_str("invalid missing-blocks CBOR sequence"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MissingBlocksError {}

/// RFC 9177 `application/missing-blocks+cbor-seq`: unsigned block numbers.
///
/// Encodes as a CBOR Sequence of one or more `uint` values (no array wrapper).
/// Callers MUST supply unique numbers in ascending order; encode skips a value
/// that is not strictly greater than the previous written NUM. Default
/// Content-Format is [`ContentFormat::MISSING_BLOCKS`]. On the App face,
/// [`crate::App::poll`] sends this for Q-Block1 holes via
/// [`crate::Response::missing_blocks`]. Apply-error 4.08 stays
/// [`crate::Response::problem`].
///
/// ```
/// use coaptic::message::MissingBlocks;
/// use coaptic::ContentFormat;
///
/// let mut buf = [0u8; 8];
/// let n = MissingBlocks::encode([1, 9], &mut buf).expect("fits");
/// assert_eq!(&buf[..n], &[0x01, 0x09]);
/// let mut nums = [0u32; 4];
/// let got = MissingBlocks::decode(&buf[..n], &mut nums).expect("cbor-seq");
/// assert_eq!(&nums[..got], &[1, 9]);
/// assert_eq!(ContentFormat::MISSING_BLOCKS.get(), 272);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MissingBlocks;

impl MissingBlocks {
    /// CoAP Content-Format for this payload (`application/missing-blocks+cbor-seq`).
    pub const CONTENT_FORMAT: ContentFormat = ContentFormat::MISSING_BLOCKS;

    /// Encode `nums` as a CBOR sequence of unsigned integers.
    ///
    /// Values that are not strictly greater than the previous written NUM are
    /// skipped (duplicates / out of order). Stops when `buf` cannot hold the
    /// next integer.
    ///
    /// # Errors
    ///
    /// [`MissingBlocksError::Invalid`] when nothing is written.
    /// [`MissingBlocksError::BufferTooSmall`] when the first NUM does not fit.
    pub fn encode(
        nums: impl IntoIterator<Item = u32>,
        buf: &mut [u8],
    ) -> Result<usize, MissingBlocksError> {
        let mut at = 0usize;
        let mut prev = None;
        let mut wrote = false;
        for num in nums {
            if let Some(p) = prev {
                if num <= p {
                    continue;
                }
            }
            match put_uint(buf, &mut at, u64::from(num)) {
                Ok(()) => {
                    prev = Some(num);
                    wrote = true;
                }
                Err(MissingBlocksError::BufferTooSmall) if wrote => break,
                Err(e) => return Err(e),
            }
        }
        if wrote {
            Ok(at)
        } else {
            Err(MissingBlocksError::Invalid)
        }
    }

    /// Decode a CBOR sequence of unsigned integers into `out`.
    ///
    /// # Errors
    ///
    /// [`MissingBlocksError::Invalid`] when `bytes` is empty, is not a sequence
    /// of `uint`s, or is not strictly ascending. Extra `out` slots are unused.
    /// [`MissingBlocksError::BufferTooSmall`] when `out` cannot hold every NUM.
    pub fn decode(bytes: &[u8], out: &mut [u32]) -> Result<usize, MissingBlocksError> {
        if bytes.is_empty() {
            return Err(MissingBlocksError::Invalid);
        }
        let mut at = 0usize;
        let mut n = 0usize;
        let mut prev = None;
        while at < bytes.len() {
            let raw = read_uint(bytes, &mut at)?;
            if raw > u64::from(u32::MAX) {
                return Err(MissingBlocksError::Invalid);
            }
            let num = raw as u32;
            if let Some(p) = prev {
                if num <= p {
                    return Err(MissingBlocksError::Invalid);
                }
            }
            if n >= out.len() {
                return Err(MissingBlocksError::BufferTooSmall);
            }
            out[n] = num;
            n += 1;
            prev = Some(num);
        }
        if n == 0 {
            Err(MissingBlocksError::Invalid)
        } else {
            Ok(n)
        }
    }
}

fn put(buf: &mut [u8], at: &mut usize, byte: u8) -> Result<(), MissingBlocksError> {
    if *at >= buf.len() {
        return Err(MissingBlocksError::BufferTooSmall);
    }
    buf[*at] = byte;
    *at += 1;
    Ok(())
}

fn put_uint(buf: &mut [u8], at: &mut usize, n: u64) -> Result<(), MissingBlocksError> {
    if n <= 23 {
        put(buf, at, n as u8)
    } else if n <= 255 {
        put(buf, at, 24)?;
        put(buf, at, n as u8)
    } else if n <= u64::from(u16::MAX) {
        put(buf, at, 25)?;
        put(buf, at, (n >> 8) as u8)?;
        put(buf, at, n as u8)
    } else if n <= u64::from(u32::MAX) {
        put(buf, at, 26)?;
        for shift in [24, 16, 8, 0] {
            put(buf, at, (n >> shift) as u8)?;
        }
        Ok(())
    } else {
        put(buf, at, 27)?;
        for shift in [56, 48, 40, 32, 24, 16, 8, 0] {
            put(buf, at, (n >> shift) as u8)?;
        }
        Ok(())
    }
}

fn need(bytes: &[u8], at: usize, n: usize) -> Result<(), MissingBlocksError> {
    if bytes.len().saturating_sub(at) < n {
        Err(MissingBlocksError::Invalid)
    } else {
        Ok(())
    }
}

fn read_uint(bytes: &[u8], at: &mut usize) -> Result<u64, MissingBlocksError> {
    need(bytes, *at, 1)?;
    let b = bytes[*at];
    *at += 1;
    let major = b >> 5;
    if major != MAJOR_UINT {
        return Err(MissingBlocksError::Invalid);
    }
    let ai = b & 0x1f;
    match ai {
        0..=23 => Ok(u64::from(ai)),
        24 => {
            need(bytes, *at, 1)?;
            let n = u64::from(bytes[*at]);
            *at += 1;
            Ok(n)
        }
        25 => {
            need(bytes, *at, 2)?;
            let n = u64::from(u16::from_be_bytes([bytes[*at], bytes[*at + 1]]));
            *at += 2;
            Ok(n)
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
            Ok(n)
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
            Ok(n)
        }
        _ => Err(MissingBlocksError::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::{MissingBlocks, MissingBlocksError};

    /// RFC 9277 example NUMs 0, 8, 15 as an unadorned CBOR sequence.
    const RFC9277_EXAMPLE: &[u8] = &[0x00, 0x08, 0x0f];

    #[test]
    fn encode_small_uints_are_bare_bytes() {
        let mut buf = [0u8; 8];
        let n = MissingBlocks::encode([1, 9], &mut buf).expect("encode");
        assert_eq!(&buf[..n], &[0x01, 0x09]);
    }

    #[test]
    fn encode_rfc9277_example_matches_known_cbor_seq() {
        let mut buf = [0u8; 8];
        let n = MissingBlocks::encode([0, 8, 15], &mut buf).expect("encode");
        assert_eq!(&buf[..n], RFC9277_EXAMPLE);
    }

    #[test]
    fn encode_one_byte_additional_info() {
        let mut buf = [0u8; 8];
        let n = MissingBlocks::encode([24, 256], &mut buf).expect("encode");
        assert_eq!(&buf[..n], &[0x18, 24, 0x19, 0x01, 0x00]);
    }

    #[test]
    fn encode_skips_duplicates_and_out_of_order() {
        let mut buf = [0u8; 8];
        let n = MissingBlocks::encode([1, 1, 9, 3], &mut buf).expect("encode");
        assert_eq!(&buf[..n], &[0x01, 0x09]);
    }

    #[test]
    fn decode_round_trips_and_rejects_empty() {
        let mut buf = [0u8; 8];
        let n = MissingBlocks::encode([1], &mut buf).expect("encode");
        let mut nums = [0u32; 2];
        let got = MissingBlocks::decode(&buf[..n], &mut nums).expect("decode");
        assert_eq!(&nums[..got], &[1]);
        assert_eq!(
            MissingBlocks::decode(&[], &mut nums),
            Err(MissingBlocksError::Invalid)
        );
        assert_eq!(
            MissingBlocks::decode(&[0xa1], &mut nums),
            Err(MissingBlocksError::Invalid)
        );
        assert_eq!(
            MissingBlocks::encode(core::iter::empty(), &mut buf),
            Err(MissingBlocksError::Invalid)
        );
    }

    #[test]
    fn decode_rejects_non_ascending() {
        let mut nums = [0u32; 2];
        assert_eq!(
            MissingBlocks::decode(&[0x09, 0x01], &mut nums),
            Err(MissingBlocksError::Invalid)
        );
        assert_eq!(
            MissingBlocks::decode(&[0x01, 0x01], &mut nums),
            Err(MissingBlocksError::Invalid)
        );
    }

    #[test]
    fn encode_first_num_needs_room() {
        assert_eq!(
            MissingBlocks::encode([1], &mut []),
            Err(MissingBlocksError::BufferTooSmall)
        );
        let mut tiny = [0u8; 1];
        let n = MissingBlocks::encode([1, 24], &mut tiny).expect("first fits");
        assert_eq!(&tiny[..n], &[0x01]);
    }
}
