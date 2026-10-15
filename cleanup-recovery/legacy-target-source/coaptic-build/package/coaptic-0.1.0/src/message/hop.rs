//! Hop-Limit option value (RFC 8768).
//!
//! Uint 1..=255. Default initial value is [`HopLimit::DEFAULT`] (16). The
//! library does not invent 4.00 / 5.08 / forwarding policy. See
//! `knowledge/rfcs/rfc8768.txt`.

use crate::error::ValueError;

use super::decode::ParsedMessage;
use super::value::EncodedUint;

/// Hop-Limit option value (RFC 8768).
///
/// Not a seventh core area. See `knowledge/rfcs/rfc8768.txt`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HopLimit(u8);

impl HopLimit {
    /// Default initial Hop-Limit when the caller does not configure one.
    pub const DEFAULT: Self = Self(16);
    /// Smallest legal Hop-Limit.
    pub const MIN: u8 = 1;
    /// Largest legal Hop-Limit (one uint byte).
    pub const MAX: u8 = 255;

    /// Build a legal Hop-Limit (`1..=255`).
    pub const fn new(n: u8) -> Result<Self, ValueError> {
        if n < Self::MIN {
            Err(ValueError::HopLimit)
        } else {
            Ok(Self(n))
        }
    }

    /// Decode a Hop-Limit option value (exactly one byte, `1..=255`).
    pub fn decode(bytes: &[u8]) -> Result<Self, ValueError> {
        match bytes {
            [n] => Self::new(*n),
            _ => Err(ValueError::HopLimit),
        }
    }

    /// First Hop-Limit, or `None` when the option is absent or illegal.
    #[must_use]
    pub fn from_option(bytes: Option<&[u8]>) -> Option<Self> {
        bytes.and_then(|b| Self::decode(b).ok())
    }

    /// Hop-Limit on `parsed`. `Ok(None)` if absent.
    pub fn from_message(parsed: &ParsedMessage<'_>) -> Result<Option<Self>, ValueError> {
        match parsed.hop_limit() {
            None => Ok(None),
            Some(result) => result.map(Some),
        }
    }

    /// Raw Hop-Limit.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// One fewer hop. `None` when decrement would be 0 (exhausted).
    ///
    /// The library does not invent 5.08 policy.
    #[must_use]
    pub const fn decrement(self) -> Option<Self> {
        match Self::new(self.0.saturating_sub(1)) {
            Ok(next) => Some(next),
            Err(_) => None,
        }
    }

    /// Encode as a uint option value (one byte for every legal value).
    #[must_use]
    pub const fn encode(self) -> EncodedUint {
        EncodedUint::new(self.0 as u32)
    }
}

impl From<HopLimit> for EncodedUint {
    fn from(hop: HopLimit) -> Self {
        hop.encode()
    }
}

#[cfg(test)]
mod unit_tests {
    use super::HopLimit;
    use crate::error::ValueError;
    use crate::message::{Code, Message, MessageId, Opt, Type, decode, encode};

    #[test]
    fn new_and_decode_reject_zero_and_wrong_length() {
        assert_eq!(HopLimit::new(0), Err(ValueError::HopLimit));
        assert!(HopLimit::new(1).is_ok());
        assert!(HopLimit::new(255).is_ok());
        assert_eq!(HopLimit::DEFAULT.get(), 16);
        assert_eq!(HopLimit::decode(&[]), Err(ValueError::HopLimit));
        assert_eq!(HopLimit::decode(&[0]), Err(ValueError::HopLimit));
        assert_eq!(HopLimit::decode(&[16, 0]), Err(ValueError::HopLimit));
        assert_eq!(HopLimit::decode(&[16]).expect("16").get(), 16);
        assert_eq!(HopLimit::from_option(None), None);
        assert_eq!(HopLimit::from_option(Some(&[0])), None);
        assert_eq!(HopLimit::from_option(Some(&[16])), Some(HopLimit::DEFAULT));
    }

    #[test]
    fn decrement_exhausts_at_one() {
        let hop = HopLimit::new(2).expect("2");
        let one = hop.decrement().expect("1");
        assert_eq!(one.get(), 1);
        assert_eq!(one.decrement(), None);
        assert_eq!(HopLimit::DEFAULT.encode().as_bytes(), &[16]);
    }

    #[test]
    fn from_message_roundtrip() {
        let mid = MessageId::new(1);
        let bare = Message::new(Type::Confirmable, Code::GET, mid);
        let mut buf = [0u8; 64];
        let n = encode(&bare, &mut buf).expect("encode");
        let parsed = decode(&buf[..n]).expect("decode");
        assert_eq!(HopLimit::from_message(&parsed), Ok(None));
        assert!(parsed.hop_limit().is_none());

        let encoded = HopLimit::DEFAULT.encode();
        let opts = [Opt::hop_limit(&encoded)];
        let msg = Message::new(Type::Confirmable, Code::GET, mid).with_options(&opts);
        let n = encode(&msg, &mut buf).expect("encode");
        let parsed = decode(&buf[..n]).expect("decode");
        assert_eq!(
            HopLimit::from_message(&parsed).expect("ok"),
            Some(HopLimit::DEFAULT)
        );
        assert_eq!(parsed.hop_limit(), Some(Ok(HopLimit::DEFAULT)));
    }
}
