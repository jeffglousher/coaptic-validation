//! No-Response option value (RFC 7967).
//!
//! Uint bitmap, 0..=1 bytes. Empty / 0 means interested in all responses.
//! The library does not invent send / skip policy. See
//! `knowledge/rfcs/rfc7967.txt`.

use crate::error::ValueError;
use crate::message::Code;

use super::decode::ParsedMessage;
use super::value::EncodedUint;

/// No-Response option value (RFC 7967).
///
/// Bit `(n - 1)` suppresses class `n.xx`. Not a seventh core area. See
/// `knowledge/rfcs/rfc7967.txt`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NoResponse(u8);

impl NoResponse {
    /// Default: interested in all responses (empty / 0).
    pub const DEFAULT: Self = Self(0);
    /// Suppress 2.xx (bit 1).
    pub const SUPPRESS_2: u8 = 2;
    /// Suppress 4.xx (bit 3).
    pub const SUPPRESS_4: u8 = 8;
    /// Suppress 5.xx (bit 4).
    pub const SUPPRESS_5: u8 = 16;
    /// Suppress 2.xx, 4.xx, and 5.xx (`26`).
    pub const SUPPRESS_ALL: u8 = Self::SUPPRESS_2 | Self::SUPPRESS_4 | Self::SUPPRESS_5;

    /// Wrap a bitmap.
    #[must_use]
    pub const fn new(bitmap: u8) -> Self {
        Self(bitmap)
    }

    /// Decode a No-Response option value (0..=1 bytes).
    pub fn decode(bytes: &[u8]) -> Result<Self, ValueError> {
        match bytes {
            [] => Ok(Self::DEFAULT),
            [b] => Ok(Self(*b)),
            _ => Err(ValueError::NoResponseLength),
        }
    }

    /// First No-Response, or `None` when the option is absent or longer than
    /// one byte.
    #[must_use]
    pub fn from_option(bytes: Option<&[u8]>) -> Option<Self> {
        bytes.and_then(|b| Self::decode(b).ok())
    }

    /// No-Response on `parsed`. Absent is [`Self::DEFAULT`].
    pub fn from_message(parsed: &ParsedMessage<'_>) -> Result<Self, ValueError> {
        match parsed.no_response() {
            None => Ok(Self::DEFAULT),
            Some(result) => result,
        }
    }

    /// Raw bitmap.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Whether this bitmap asks to suppress `code`.
    ///
    /// Non-responses are never suppressed. The library does not invent send
    /// policy. See `knowledge/rfcs/rfc7967.txt`.
    #[must_use]
    pub const fn suppresses(self, code: Code) -> bool {
        if !code.is_response() {
            return false;
        }
        let class = code.class();
        if class == 0 || class > 8 {
            return false;
        }
        let bit = 1u8 << (class - 1);
        self.0 & bit != 0
    }

    /// Encode as a uint option value (empty when 0).
    #[must_use]
    pub const fn encode(self) -> EncodedUint {
        EncodedUint::new(self.0 as u32)
    }
}

impl From<NoResponse> for EncodedUint {
    fn from(nr: NoResponse) -> Self {
        nr.encode()
    }
}

#[cfg(test)]
mod unit_tests {
    use super::NoResponse;
    use crate::error::ValueError;
    use crate::message::{Code, Message, MessageId, Opt, Type, decode, encode};

    #[test]
    fn decode_empty_is_default_and_rejects_two_bytes() {
        assert_eq!(NoResponse::decode(&[]).expect("empty"), NoResponse::DEFAULT);
        assert_eq!(NoResponse::decode(&[2]).expect("2").get(), 2);
        assert_eq!(
            NoResponse::decode(&[2, 0]),
            Err(ValueError::NoResponseLength)
        );
        assert_eq!(NoResponse::from_option(None), None);
        assert_eq!(
            NoResponse::from_option(Some(&[])),
            Some(NoResponse::DEFAULT)
        );
        assert_eq!(NoResponse::SUPPRESS_ALL, 26);
        assert!(NoResponse::DEFAULT.encode().is_empty());
    }

    #[test]
    fn suppresses_class_bits() {
        let all = NoResponse::new(NoResponse::SUPPRESS_ALL);
        assert!(all.suppresses(Code::CONTENT));
        assert!(all.suppresses(Code::NOT_FOUND));
        assert!(all.suppresses(Code::INTERNAL_SERVER_ERROR));
        assert!(!all.suppresses(Code::GET));
        assert!(!all.suppresses(Code::FETCH));

        let success_only = NoResponse::new(NoResponse::SUPPRESS_2);
        assert!(success_only.suppresses(Code::CHANGED));
        assert!(!success_only.suppresses(Code::BAD_REQUEST));
        assert!(!success_only.suppresses(Code::BAD_GATEWAY));

        let errors = NoResponse::new(NoResponse::SUPPRESS_4 | NoResponse::SUPPRESS_5);
        assert!(!errors.suppresses(Code::CONTENT));
        assert!(errors.suppresses(Code::CONFLICT));
        assert!(errors.suppresses(Code::HOP_LIMIT_REACHED));
    }

    #[test]
    fn from_message_absent_is_default() {
        let mid = MessageId::new(1);
        let bare = Message::new(Type::NonConfirmable, Code::PUT, mid);
        let mut buf = [0u8; 64];
        let n = encode(&bare, &mut buf).expect("encode");
        let parsed = decode(&buf[..n]).expect("decode");
        assert_eq!(
            NoResponse::from_message(&parsed).expect("ok"),
            NoResponse::DEFAULT
        );
        assert!(parsed.no_response().is_none());

        let encoded = NoResponse::new(NoResponse::SUPPRESS_2).encode();
        let opts = [Opt::no_response(&encoded)];
        let msg = Message::new(Type::NonConfirmable, Code::PUT, mid).with_options(&opts);
        let n = encode(&msg, &mut buf).expect("encode");
        let parsed = decode(&buf[..n]).expect("decode");
        assert_eq!(
            NoResponse::from_message(&parsed).expect("ok").get(),
            NoResponse::SUPPRESS_2
        );
        assert_eq!(
            parsed.no_response(),
            Some(Ok(NoResponse::new(NoResponse::SUPPRESS_2)))
        );
    }
}
