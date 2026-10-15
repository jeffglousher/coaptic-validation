//! Parse a CoAP datagram (`&[u8]`) into a borrowed view.

use crate::error::ParseError;

use super::option::{OptionNumber, Options, read_option};
use super::{Code, Header, MessageId, Token, Type};

/// Zero-copy view of a decoded CoAP datagram.
///
/// Options and payload borrow `buf` from [`decode`]. No allocator is used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedMessage<'a> {
    header: Header,
    token: Token,
    options: &'a [u8],
    payload: &'a [u8],
}

impl<'a> ParsedMessage<'a> {
    /// Parsed header.
    #[must_use]
    pub const fn header(self) -> Header {
        self.header
    }

    /// Message type.
    #[must_use]
    pub const fn ty(self) -> Type {
        self.header.ty()
    }

    /// Code.
    #[must_use]
    pub const fn code(self) -> Code {
        self.header.code()
    }

    /// Message ID.
    #[must_use]
    pub const fn message_id(self) -> MessageId {
        self.header.message_id()
    }

    /// Token.
    #[must_use]
    pub const fn token(self) -> Token {
        self.token
    }

    /// Payload bytes after the 0xFF marker, or empty if the marker is absent.
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }

    /// Empty message (code 0.00). Successful [`decode`] already rejected extra bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.code().is_empty()
    }

    /// Empty ACK.
    #[must_use]
    pub const fn is_empty_ack(self) -> bool {
        matches!(self.ty(), Type::Acknowledgement) && self.is_empty()
    }

    /// Empty RST.
    #[must_use]
    pub const fn is_empty_rst(self) -> bool {
        matches!(self.ty(), Type::Reset) && self.is_empty()
    }

    /// Empty ACK or empty RST (the types that confirm or reject a pending CON).
    #[must_use]
    pub const fn is_empty_ack_or_rst(self) -> bool {
        self.is_empty_ack() || self.is_empty_rst()
    }

    /// Options in the message, in wire order.
    #[must_use]
    pub const fn options(self) -> Options<'a> {
        Options::new(self.options)
    }

    /// First critical option whose number is not defined in RFC 7252.
    ///
    /// Decode itself accepts any well-formed option as opaque bytes. This
    /// report is for a caller that wants Table 4 checking; it is not a
    /// 4.02 / RST decision. Block / OSCORE / … are reported here even
    /// though [`Self::unknown_critical`] treats them as known.
    #[must_use]
    pub fn unrecognized_critical(self) -> Option<OptionNumber> {
        self.options().find_map(|opt| {
            let n = opt.number();
            (n.is_critical() && !n.is_rfc7252()).then_some(n)
        })
    }

    /// First critical option whose number is not in [`OptionNumber::is_known`].
    ///
    /// [`decode`] does not call this. [`crate::App`] uses it for 4.02
    /// before handlers. Distinct from [`Self::unrecognized_critical`]
    /// (RFC 7252 Table 4 only).
    #[must_use]
    pub fn unknown_critical(self) -> Option<OptionNumber> {
        self.options().find_map(|opt| {
            let n = opt.number();
            (n.is_critical() && !n.is_known()).then_some(n)
        })
    }

    /// Fail if [`Self::unrecognized_critical`] finds an option.
    ///
    /// [`decode`] does not call this. Distinct from
    /// [`Self::check_rfc7252_formats`].
    pub fn check_rfc7252_options(self) -> Result<(), ParseError> {
        match self.unrecognized_critical() {
            Some(n) => Err(ParseError::UnrecognizedCritical(n)),
            None => Ok(()),
        }
    }

    /// Serialize this view into `buf`. Canonical option encoding is used.
    pub fn encode(self, buf: &mut [u8]) -> Result<usize, crate::error::EncodeError> {
        super::encode::encode_iter(
            buf,
            self.ty(),
            self.code(),
            self.message_id(),
            self.token(),
            self.options(),
            self.payload(),
        )
    }
}

/// Parse one CoAP datagram (UDP payload). Does not require [`crate::storage::Engine`].
///
/// Options are accepted as opaque number + value. Optional checks:
/// [`ParsedMessage::check_rfc7252_options`] (Table 4 unrecognized
/// critical), [`ParsedMessage::unknown_critical`] (implemented stack),
/// and [`ParsedMessage::check_rfc7252_formats`] (known option, wrong
/// format).
pub fn decode(buf: &[u8]) -> Result<ParsedMessage<'_>, ParseError> {
    if buf.len() < 4 {
        return Err(ParseError::TruncatedHeader);
    }

    let version = buf[0] >> 6;
    if version != 1 {
        return Err(ParseError::UnsupportedVersion);
    }

    let ty = match (buf[0] >> 4) & 0b11 {
        0 => Type::Confirmable,
        1 => Type::NonConfirmable,
        2 => Type::Acknowledgement,
        _ => Type::Reset,
    };
    let tkl = buf[0] & 0x0f;
    if tkl > 8 {
        return Err(ParseError::BadTokenLength);
    }

    let code = Code::from_raw(buf[1]);
    let id = MessageId::new(u16::from_be_bytes([buf[2], buf[3]]));

    let rest = &buf[4..];
    let tkl_usize = usize::from(tkl);
    if rest.len() < tkl_usize {
        return Err(ParseError::TruncatedToken);
    }
    let (token_bytes, after_token) = rest.split_at(tkl_usize);
    let token = Token::from_checked(token_bytes);

    if code.is_empty() {
        if tkl != 0 || !after_token.is_empty() {
            return Err(ParseError::EmptyMessageNotEmpty);
        }
        return Ok(ParsedMessage {
            header: Header::new(version, ty, tkl, code, id),
            token,
            options: &[],
            payload: &[],
        });
    }

    let (options, payload) = split_options_and_payload(after_token)?;
    Ok(ParsedMessage {
        header: Header::new(version, ty, tkl, code, id),
        token,
        options,
        payload,
    })
}

fn split_options_and_payload(bytes: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let mut i = 0;
    let mut prev = 0u32;
    while i < bytes.len() {
        if bytes[i] == 0xFF {
            if i + 1 == bytes.len() {
                return Err(ParseError::PayloadMarkerWithoutPayload);
            }
            return Ok((&bytes[..i], &bytes[i + 1..]));
        }
        let _ = read_option(bytes, &mut i, &mut prev)?;
    }
    Ok((bytes, &[]))
}
