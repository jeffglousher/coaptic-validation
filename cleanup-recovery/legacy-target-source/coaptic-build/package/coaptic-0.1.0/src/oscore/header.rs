//! Compressed OSCORE option (flags, Partial IV, kid context, kid).

use super::{Error, MAX_ID_CONTEXT_LEN, MAX_ID_LEN, MAX_PIV_LEN};

/// Partial IV (Sender Sequence Number, leading zeroes stripped except `0`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PartialIv {
    bytes: [u8; MAX_PIV_LEN],
    len: u8,
}

impl PartialIv {
    /// Encode `seq` as a Partial IV.
    ///
    /// Returns [`Error::PartialIv`] when `seq` needs more than five bytes.
    pub const fn from_seq(seq: u64) -> Result<Self, Error> {
        let be = seq.to_be_bytes();
        let mut start = 0;
        while start < 8 && be[start] == 0 {
            start += 1;
        }
        if start == 8 {
            return Ok(Self {
                bytes: [0, 0, 0, 0, 0],
                len: 1,
            });
        }
        let len = 8 - start;
        if len > MAX_PIV_LEN {
            return Err(Error::PartialIv);
        }
        let mut bytes = [0u8; MAX_PIV_LEN];
        let mut i = 0;
        while i < len {
            bytes[i] = be[start + i];
            i += 1;
        }
        Ok(Self {
            bytes,
            len: len as u8,
        })
    }

    /// Parse a Partial IV from the OSCORE option.
    pub const fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_PIV_LEN {
            return Err(Error::PartialIv);
        }
        let mut out = [0u8; MAX_PIV_LEN];
        let mut i = 0;
        while i < bytes.len() {
            out[i] = bytes[i];
            i += 1;
        }
        Ok(Self {
            bytes: out,
            len: bytes.len() as u8,
        })
    }

    /// Network-order bytes (no leading zeroes except for sequence 0).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Sequence number (big-endian).
    #[must_use]
    pub fn seq(self) -> u64 {
        let mut be = [0u8; 8];
        let n = self.len as usize;
        be[8 - n..].copy_from_slice(&self.bytes[..n]);
        u64::from_be_bytes(be)
    }
}

/// Decompressed OSCORE option fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OscoreHeader<'a> {
    /// Partial IV, if present (required on requests).
    pub piv: Option<PartialIv>,
    /// `kid context` / ID Context, if present.
    pub kid_context: Option<&'a [u8]>,
    /// `kid` / Sender ID, if present (required on requests).
    pub kid: Option<&'a [u8]>,
}

impl<'a> OscoreHeader<'a> {
    /// Parse the OSCORE option value. An empty value is flags = 0.
    pub fn parse(value: &'a [u8]) -> Result<Self, Error> {
        if value.is_empty() {
            return Ok(Self {
                piv: None,
                kid_context: None,
                kid: None,
            });
        }
        let flags = value[0];
        if flags & 0xe0 != 0 {
            return Err(Error::Header);
        }
        let n = usize::from(flags & 0x07);
        if n == 6 || n == 7 {
            return Err(Error::Header);
        }
        let k = flags & 0x08 != 0;
        let h = flags & 0x10 != 0;
        let mut i: usize = 1;
        let piv = if n > 0 {
            let end = i.checked_add(n).ok_or(Error::Header)?;
            let bytes = value.get(i..end).ok_or(Error::Header)?;
            i = end;
            Some(PartialIv::from_bytes(bytes)?)
        } else {
            None
        };
        let kid_context = if h {
            let s = usize::from(*value.get(i).ok_or(Error::Header)?);
            i += 1;
            let end = i.checked_add(s).ok_or(Error::Header)?;
            let bytes = value.get(i..end).ok_or(Error::Header)?;
            i = end;
            Some(bytes)
        } else {
            None
        };
        let kid = if k {
            Some(value.get(i..).ok_or(Error::Header)?)
        } else if i != value.len() {
            return Err(Error::Header);
        } else {
            None
        };
        Ok(Self {
            piv,
            kid_context,
            kid,
        })
    }
}

/// Encode flags + Partial IV + optional kid context + kid.
pub(crate) fn encode_option(
    out: &mut [u8],
    piv: Option<PartialIv>,
    kid_context: Option<&[u8]>,
    kid: Option<&[u8]>,
) -> Result<usize, Error> {
    if let Some(ctx) = kid_context {
        if ctx.len() > MAX_ID_CONTEXT_LEN {
            return Err(Error::Id);
        }
    }
    if let Some(id) = kid {
        if id.len() > MAX_ID_LEN {
            return Err(Error::Id);
        }
    }

    let n = piv.map(|p| p.as_bytes().len()).unwrap_or(0);
    if n > 5 {
        return Err(Error::PartialIv);
    }
    let k = kid.is_some();
    let h = kid_context.is_some();
    if n == 0 && !k && !h {
        return Ok(0);
    }

    let kid_ctx_len = kid_context.map(|c| c.len()).unwrap_or(0);
    let kid_len = kid.map(|c| c.len()).unwrap_or(0);
    let total = 1 + n + usize::from(h) * (1 + kid_ctx_len) + kid_len;
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }

    let mut flags = n as u8;
    if k {
        flags |= 0x08;
    }
    if h {
        flags |= 0x10;
    }
    out[0] = flags;
    let mut i = 1;
    if let Some(piv) = piv {
        let p = piv.as_bytes();
        out[i..i + p.len()].copy_from_slice(p);
        i += p.len();
    }
    if let Some(ctx) = kid_context {
        out[i] = ctx.len() as u8;
        i += 1;
        out[i..i + ctx.len()].copy_from_slice(ctx);
        i += ctx.len();
    }
    if let Some(id) = kid {
        out[i..i + id.len()].copy_from_slice(id);
        i += id.len();
    }
    Ok(i)
}

/// Class E (inner) vs Class U (outer). Unknown options are Class E
/// (`knowledge/rfcs/rfc8613.txt` §4.1).
///
/// RFC 8613 Figure 5 Dual (E+U) options are not one encode rule:
///
/// - Observe (6) is copied to **both** fields (Inner value + Outer
///   proxy/cache). See `knowledge/rfcs/rfc8613.txt` §4.1.3.5.
/// - Block1 (27), Block2 (23), Size1 (60), Size2 (28) are Dual but App
///   uses the **Inner** field only (fragment, then protect;
///   §4.1.3.4.1). They are not copied to Outer — that would look like
///   hop-by-hop fragmentation of the OSCORE datagram (§4.1.3.4.2).
/// - Max-Age (14) is Dual. The **application** value stays Inner
///   (end-to-end freshness, §4.1.3.1). Observe responses additionally
///   get a constructed Outer Max-Age 0 so OSCORE-unaware proxies do
///   not cache 2.05 Content. Incoming Outer Max-Age is discarded
///   (§8.4 step 1).
/// - No-Response (258) is Dual but **MUST** be Inner; Outer SHOULD NOT
///   be present (§4.1.3.6). This slice does not emit the optional
///   Outer 26. The server ignores Outer No-Response (stitch drops Dual).
///
/// ETag (4) is Figure 5 Class E only — not Dual. An Outer ETag is
/// discarded (§8.4).
///
/// Hop-Limit (16) is not in Figure 5 (RFC 8768). It requires proxy
/// processing, so it is Class U / Outer (§4.1: new options are Class E
/// unless they need proxy processing).
///
/// Incoming Outer Block on an OSCORE datagram is not merged into Inner
/// and is not treated as an application body. A truncated ciphertext
/// fails AEAD (silent drop). App does not emit Outer Block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OptionClass {
    Inner,
    Outer,
    Dual,
}

impl OptionClass {
    pub(crate) const fn in_plaintext(self) -> bool {
        matches!(self, Self::Inner | Self::Dual)
    }
}

/// Whether `number` is copied from the original message onto the OSCORE
/// (outer) datagram.
///
/// Dual Observe is copied both ways. Other Duals stay Inner-only on
/// this copy: Block/Size (§4.1.3.4.1), application Max-Age (§4.1.3.1),
/// No-Response (§4.1.3.6). Observe responses inject Outer Max-Age 0
/// separately in `encode_outer` — that is not this copy.
pub(crate) fn encode_as_outer(number: u16) -> bool {
    match classify(number) {
        OptionClass::Outer => true,
        OptionClass::Dual => number == 6,
        OptionClass::Inner => false,
    }
}

pub(crate) fn classify(number: u16) -> OptionClass {
    match number {
        // Figure 5 Class U only, plus Hop-Limit (16, RFC 8768).
        3 | 7 | 9 | 16 | 35 | 39 => OptionClass::Outer,
        // Figure 5 Dual (E+U): Observe, Max-Age, Block2, Block1, Size2,
        // Size1, No-Response. ETag (4) is Class E — it belongs in `_`.
        6 | 14 | 23 | 27 | 28 | 60 | 258 => OptionClass::Dual,
        // Figure 5 Class E and unknown options (§4.1).
        _ => OptionClass::Inner,
    }
}

pub(crate) const fn is_oscore(number: u16) -> bool {
    number == 9
}
