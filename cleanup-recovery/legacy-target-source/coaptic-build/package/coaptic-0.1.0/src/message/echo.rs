//! Echo option value (RFC 9175).
//!
//! Opaque 1..=40 bytes. Clients treat the bytes as opaque. Time-based
//! [`Self::mint`] packs caller `now_ms` plus caller pad; the core does not
//! implement a MAC and does not call an OS RNG. Event-based freshness is
//! equality against a caller-owned value. See `knowledge/rfcs/rfc9175.txt`.

use crate::error::ValueError;

use super::decode::ParsedMessage;

/// Echo option value (opaque, 1..=40 bytes).
///
/// Not a seventh core area. Outstanding-request copies live on
/// [`crate::storage::ExchangeEntry`]. [`crate::App`] applies 4.01 with a
/// caller-issued challenge through [`crate::app::AppBuilder::echo_policy`].
/// See `knowledge/rfcs/rfc9175.txt`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Echo {
    bytes: [u8; Self::MAX_LEN],
    len: u8,
}

impl Echo {
    /// Minimum Echo option value length.
    pub const MIN_LEN: usize = 1;
    /// Maximum Echo option value length.
    pub const MAX_LEN: usize = 40;
    /// Size of the [`Self::mint`] timestamp prefix (`now_ms` as 8-byte BE).
    pub const TIME_PREFIX_LEN: usize = 8;

    /// Present Echo from `bytes` (1..=40).
    pub fn new(bytes: &[u8]) -> Result<Self, ValueError> {
        if bytes.is_empty() || bytes.len() > Self::MAX_LEN {
            return Err(ValueError::EchoLength);
        }
        let mut echo = Self {
            bytes: [0; Self::MAX_LEN],
            len: bytes.len() as u8,
        };
        echo.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(echo)
    }

    /// First Echo value, or `None` when the option is absent or not 1..=40.
    #[must_use]
    pub fn from_option(bytes: Option<&[u8]>) -> Option<Self> {
        bytes.and_then(|b| Self::new(b).ok())
    }

    /// Echo on `parsed`. `Ok(None)` if absent.
    pub fn from_message(parsed: &ParsedMessage<'_>) -> Result<Option<Self>, ValueError> {
        match parsed.echo() {
            None => Ok(None),
            Some(bytes) => Self::new(bytes).map(Some),
        }
    }

    /// Timestamp prefix `now_ms` plus caller `pad`.
    ///
    /// Total length is [`Self::TIME_PREFIX_LEN`] + `pad.len()` and must be
    /// 1..=40. The pad is caller entropy or a caller MAC; this crate does
    /// not compute one. The core does not call an OS RNG.
    pub fn mint(now_ms: u64, pad: &[u8]) -> Result<Self, ValueError> {
        let total = Self::TIME_PREFIX_LEN.saturating_add(pad.len());
        if total > Self::MAX_LEN {
            return Err(ValueError::EchoLength);
        }
        let mut bytes = [0u8; Self::MAX_LEN];
        bytes[..Self::TIME_PREFIX_LEN].copy_from_slice(&now_ms.to_be_bytes());
        bytes[Self::TIME_PREFIX_LEN..total].copy_from_slice(pad);
        Self::new(&bytes[..total])
    }

    /// Value bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Timestamp from a [`Self::mint`] value, if the length is at least 8.
    #[must_use]
    pub fn issued_at(self) -> Option<u64> {
        if (self.len as usize) < Self::TIME_PREFIX_LEN {
            return None;
        }
        let mut prefix = [0u8; Self::TIME_PREFIX_LEN];
        prefix.copy_from_slice(&self.bytes[..Self::TIME_PREFIX_LEN]);
        Some(u64::from_be_bytes(prefix))
    }

    /// Age of a [`Self::mint`] value at caller `now_ms`.
    /// Returns `None` for future timestamps or a clock rollback.
    #[must_use]
    pub fn age_ms(self, now_ms: u64) -> Option<u64> {
        now_ms.checked_sub(self.issued_at()?)
    }

    /// Whether a [`Self::mint`] value still satisfies `(now_ms - t0) < fresh_ms`.
    ///
    /// `false` when the value is not mint-shaped or the age is not below
    /// `fresh_ms`. See `knowledge/rfcs/rfc9175.txt`.
    #[must_use]
    pub fn is_time_fresh(self, now_ms: u64, fresh_ms: u64) -> bool {
        match self.age_ms(now_ms) {
            Some(age) => age < fresh_ms,
            None => false,
        }
    }
}

/// Time-based Echo freshness of one datagram.
///
/// Event-based freshness is equality against a caller-owned [`Echo`].
/// This is only a timestamp classifier, not verification of issuance or a
/// MAC. App uses an explicit [`crate::app::EchoPolicy`] instead.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EchoFreshness {
    /// No Echo option.
    Missing,
    /// Echo is present but not 1..=40 bytes.
    Invalid,
    /// Echo is present and not time-fresh (including non-mint values).
    Stale,
    /// [`Echo::mint`] value with `(now_ms - t0) < fresh_ms`.
    Fresh,
}

impl EchoFreshness {
    /// Whether this is not [`Self::Fresh`] (missing, invalid, or stale).
    ///
    /// This classification alone does not authenticate a challenge.
    #[must_use]
    pub const fn needs_challenge(self) -> bool {
        !matches!(self, Self::Fresh)
    }

    /// Classify the Echo option on `parsed` using caller `now_ms` / `fresh_ms`.
    #[must_use]
    pub fn of(parsed: &ParsedMessage<'_>, now_ms: u64, fresh_ms: u64) -> Self {
        match Echo::from_message(parsed) {
            Ok(None) => Self::Missing,
            Err(_) => Self::Invalid,
            Ok(Some(echo)) if echo.is_time_fresh(now_ms, fresh_ms) => Self::Fresh,
            Ok(Some(_)) => Self::Stale,
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::{Echo, EchoFreshness};
    use crate::error::ValueError;
    use crate::message::{Code, Message, MessageId, Opt, Type, decode, encode};

    #[test]
    fn new_rejects_empty_and_too_long() {
        assert_eq!(Echo::new(&[]), Err(ValueError::EchoLength));
        assert_eq!(Echo::new(&[0; 41]), Err(ValueError::EchoLength));
        assert!(Echo::new(&[0x05]).is_ok());
        assert!(Echo::new(&[0; 40]).is_ok());
        assert_eq!(Echo::from_option(None), None);
        assert_eq!(Echo::from_option(Some(&[])), None);
        assert_eq!(
            Echo::from_option(Some(&[1, 2]))
                .as_ref()
                .map(Echo::as_slice),
            Some(&[1, 2][..])
        );
    }

    #[test]
    fn mint_age_and_time_freshness() {
        let echo = Echo::mint(9, b"pad!").expect("mint");
        assert_eq!(echo.issued_at(), Some(9));
        assert_eq!(echo.age_ms(10), Some(1));
        assert_eq!(echo.age_ms(8), None);
        assert!(!echo.is_time_fresh(8, u64::MAX));
        assert!(
            !Echo::mint(u64::MAX, &[])
                .unwrap()
                .is_time_fresh(0, u64::MAX)
        );
        assert!(echo.is_time_fresh(9, 1));
        assert!(!echo.is_time_fresh(9, 0));
        assert!(echo.is_time_fresh(10, 5));
        assert!(!echo.is_time_fresh(14, 5));
        assert!(!echo.is_time_fresh(15, 5));
        assert_eq!(Echo::mint(1, &[0; 33]), Err(ValueError::EchoLength));

        let short = Echo::new(&[0x05]).expect("event");
        assert_eq!(short.issued_at(), None);
        assert!(!short.is_time_fresh(10, 5));
        assert_eq!(short.as_slice(), &[0x05]);
    }

    #[test]
    fn freshness_of_missing_invalid_stale_fresh() {
        let mid = MessageId::new(1);
        let bare = Message::new(Type::Confirmable, Code::PUT, mid);
        let mut buf = [0u8; 128];
        let n = encode(&bare, &mut buf).expect("encode");
        let parsed = decode(&buf[..n]).expect("decode");
        assert_eq!(Echo::from_message(&parsed), Ok(None));
        assert_eq!(EchoFreshness::of(&parsed, 10, 5), EchoFreshness::Missing);
        assert!(EchoFreshness::Missing.needs_challenge());
        assert!(EchoFreshness::Invalid.needs_challenge());
        assert!(EchoFreshness::Stale.needs_challenge());
        assert!(!EchoFreshness::Fresh.needs_challenge());

        let empty = [Opt::echo(&[])];
        let msg = Message::new(Type::Confirmable, Code::PUT, mid).with_options(&empty);
        let n = encode(&msg, &mut buf).expect("encode");
        let parsed = decode(&buf[..n]).expect("decode");
        assert_eq!(Echo::from_message(&parsed), Err(ValueError::EchoLength));
        assert_eq!(EchoFreshness::of(&parsed, 10, 5), EchoFreshness::Invalid);

        let echo = Echo::mint(9, b"Chulhu!").expect("mint");
        let opts = [Opt::echo(echo.as_slice())];
        let msg = Message::new(Type::Confirmable, Code::PUT, mid).with_options(&opts);
        let n = encode(&msg, &mut buf).expect("encode");
        let parsed = decode(&buf[..n]).expect("decode");
        assert_eq!(EchoFreshness::of(&parsed, 10, 5), EchoFreshness::Fresh);
        assert_eq!(EchoFreshness::of(&parsed, 15, 5), EchoFreshness::Stale);
        assert_eq!(Echo::from_message(&parsed).expect("ok"), Some(echo));
    }
}
