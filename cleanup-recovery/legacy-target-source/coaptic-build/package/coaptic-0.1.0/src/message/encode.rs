//! Serialize a CoAP message into `&mut [u8]`.

use crate::error::EncodeError;

use super::option::Opt;
use super::{Code, MessageId, Token, Type};

/// Maximum option delta or length that fits in a 14-extended field.
const MAX_EXTENDED: u32 = 269 + 65535;

/// Message to encode: header fields plus borrowed options and payload.
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    ty: Type,
    code: Code,
    id: MessageId,
    token: Token,
    options: &'a [Opt<'a>],
    payload: &'a [u8],
}

impl<'a> Message<'a> {
    /// Header-only message (empty token, no options, no payload).
    #[must_use]
    pub const fn new(ty: Type, code: Code, id: MessageId) -> Self {
        Self {
            ty,
            code,
            id,
            token: Token::EMPTY,
            options: &[],
            payload: &[],
        }
    }

    /// Empty ACK (code 0.00, TKL 0, no options or payload) for `id`.
    ///
    /// See `knowledge/rfcs/rfc7252.txt`.
    #[must_use]
    pub const fn empty_ack(id: MessageId) -> Self {
        Self::new(Type::Acknowledgement, Code::EMPTY, id)
    }

    /// Empty RST (code 0.00, TKL 0, no options or payload) for `id`.
    ///
    /// See `knowledge/rfcs/rfc7252.txt`.
    #[must_use]
    pub const fn empty_rst(id: MessageId) -> Self {
        Self::new(Type::Reset, Code::EMPTY, id)
    }

    /// CON skeleton: `code`, `id`, and `token`. No options or payload.
    ///
    /// Does not require [`crate::storage::Engine`]. Pair with [`super::Ids`] to mint `id`.
    #[must_use]
    pub const fn con(code: Code, id: MessageId, token: Token) -> Self {
        Self::new(Type::Confirmable, code, id).with_token(token)
    }

    /// NON skeleton: `code`, `id`, and `token`. No options or payload.
    ///
    /// Does not require [`crate::storage::Engine`]. Pair with [`super::Ids`] to mint `id`.
    #[must_use]
    pub const fn non(code: Code, id: MessageId, token: Token) -> Self {
        Self::new(Type::NonConfirmable, code, id).with_token(token)
    }

    /// Set the token.
    #[must_use]
    pub const fn with_token(mut self, token: Token) -> Self {
        self.token = token;
        self
    }

    /// Set options. Numbers must be non-decreasing.
    #[must_use]
    pub const fn with_options(mut self, options: &'a [Opt<'a>]) -> Self {
        self.options = options;
        self
    }

    /// Set the payload. A payload marker is written only when this is non-empty.
    #[must_use]
    pub const fn with_payload(mut self, payload: &'a [u8]) -> Self {
        self.payload = payload;
        self
    }

    /// Message type.
    #[must_use]
    pub const fn ty(self) -> Type {
        self.ty
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

    /// Token.
    #[must_use]
    pub const fn token(self) -> Token {
        self.token
    }

    /// Options to encode.
    #[must_use]
    pub const fn options(self) -> &'a [Opt<'a>] {
        self.options
    }

    /// Payload to encode.
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }

    /// Serialize into `buf`. Returns the number of bytes written.
    pub fn encode(self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        encode(&self, buf)
    }
}

/// Encode `msg` into `buf`. Does not require [`crate::storage::Engine`].
pub fn encode(msg: &Message<'_>, buf: &mut [u8]) -> Result<usize, EncodeError> {
    if msg.code.is_empty()
        && (!msg.token.is_empty() || !msg.options.is_empty() || !msg.payload.is_empty())
    {
        return Err(EncodeError::EmptyMessageNotEmpty);
    }
    encode_iter(
        buf,
        msg.ty,
        msg.code,
        msg.id,
        msg.token,
        msg.options.iter().copied(),
        msg.payload,
    )
}

pub(crate) fn encode_iter<'a>(
    buf: &mut [u8],
    ty: Type,
    code: Code,
    id: MessageId,
    token: Token,
    options: impl IntoIterator<Item = Opt<'a>>,
    payload: &[u8],
) -> Result<usize, EncodeError> {
    let tkl = token.len();
    let header_end = 4 + tkl;
    if buf.len() < header_end {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[0] = (1 << 6) | (ty.to_bits() << 4) | (tkl as u8);
    buf[1] = code.as_raw();
    let mid = id.get().to_be_bytes();
    buf[2] = mid[0];
    buf[3] = mid[1];
    buf[4..header_end].copy_from_slice(token.as_bytes());

    let mut i = header_end;
    let mut prev = 0u16;
    for opt in options {
        let number = opt.number().get();
        if number < prev {
            return Err(EncodeError::OptionsNotAscending);
        }
        let delta = number - prev;
        i = write_option(buf, i, u32::from(delta), opt.value())?;
        prev = number;
    }

    if !payload.is_empty() {
        if i >= buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        buf[i] = 0xFF;
        i += 1;
        let end = i
            .checked_add(payload.len())
            .ok_or(EncodeError::BufferTooSmall)?;
        if end > buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        buf[i..end].copy_from_slice(payload);
        i = end;
    }

    Ok(i)
}

pub(crate) fn write_option(
    buf: &mut [u8],
    mut i: usize,
    delta: u32,
    value: &[u8],
) -> Result<usize, EncodeError> {
    let len = u32::try_from(value.len()).map_err(|_| EncodeError::OptionValueTooLong)?;
    let (dn, de, dn_n) = ext_nibble(delta)?;
    let (ln, le, ln_n) = ext_nibble(len)?;

    let need = 1usize
        .checked_add(dn_n)
        .and_then(|n| n.checked_add(ln_n))
        .and_then(|n| n.checked_add(value.len()))
        .ok_or(EncodeError::BufferTooSmall)?;
    if i.checked_add(need).is_none_or(|end| end > buf.len()) {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[i] = (dn << 4) | ln;
    i += 1;
    buf[i..i + dn_n].copy_from_slice(&de[..dn_n]);
    i += dn_n;
    buf[i..i + ln_n].copy_from_slice(&le[..ln_n]);
    i += ln_n;
    buf[i..i + value.len()].copy_from_slice(value);
    i += value.len();
    Ok(i)
}

fn ext_nibble(n: u32) -> Result<(u8, [u8; 2], usize), EncodeError> {
    if n < 13 {
        Ok((n as u8, [0, 0], 0))
    } else if n < 269 {
        Ok((13, [(n - 13) as u8, 0], 1))
    } else if n <= MAX_EXTENDED {
        let e = n - 269;
        Ok((14, [(e >> 8) as u8, (e & 0xff) as u8], 2))
    } else {
        Err(EncodeError::OptionValueTooLong)
    }
}
