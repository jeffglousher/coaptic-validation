//! If-Match / If-None-Match classification (RFC 7252 §5.10.8).
//!
//! The library does not invent 4.12 policy. See
//! `knowledge/rfcs/rfc7252.txt`.

use super::decode::ParsedMessage;

/// If-Match / If-None-Match outcome against the current representation.
///
/// The library does not invent 4.12 / RST policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Precondition {
    /// Neither If-Match nor If-None-Match is present.
    Unconditional,
    /// Present precondition(s) hold.
    Satisfied,
    /// If-Match does not hold (empty and missing, or no ETag match).
    FailedIfMatch,
    /// If-None-Match is present and the resource exists.
    FailedIfNoneMatch,
}

impl Precondition {
    /// Classify If-Match / If-None-Match on `parsed`.
    ///
    /// `exists` is whether any representation is stored. `etag` is the
    /// current ETag when known (used only for a non-empty If-Match). See
    /// `knowledge/rfcs/rfc7252.txt` §5.10.8.
    #[must_use]
    pub fn of(parsed: &ParsedMessage<'_>, exists: bool, etag: Option<&[u8]>) -> Self {
        parsed.precondition(exists, etag)
    }

    /// Whether this is [`Self::Unconditional`] or [`Self::Satisfied`].
    #[must_use]
    pub const fn holds(self) -> bool {
        matches!(self, Self::Unconditional | Self::Satisfied)
    }
}

#[cfg(test)]
mod unit_tests {
    use super::Precondition;
    use crate::message::{Code, Message, MessageId, Opt, Type, decode, encode};

    fn classify(opts: &[Opt<'_>], exists: bool, etag: Option<&[u8]>) -> Precondition {
        let msg = Message::new(Type::Confirmable, Code::PUT, MessageId::new(1)).with_options(opts);
        let mut buf = [0u8; 128];
        let n = encode(&msg, &mut buf).expect("encode");
        let parsed = decode(&buf[..n]).expect("decode");
        Precondition::of(&parsed, exists, etag)
    }

    #[test]
    fn missing_options_are_unconditional() {
        let p = classify(&[], true, Some(b"abc"));
        assert_eq!(p, Precondition::Unconditional);
        assert!(p.holds());
        assert_eq!(classify(&[], false, None), Precondition::Unconditional);
    }

    #[test]
    fn empty_if_match_is_any_existing() {
        let opts = [Opt::if_match(b"")];
        assert_eq!(classify(&opts, true, Some(b"abc")), Precondition::Satisfied);
        assert_eq!(classify(&opts, true, None), Precondition::Satisfied);
        assert_eq!(classify(&opts, false, None), Precondition::FailedIfMatch);
    }

    #[test]
    fn specific_if_match_compares_etag() {
        let opts = [Opt::if_match(b"abc")];
        assert_eq!(classify(&opts, true, Some(b"abc")), Precondition::Satisfied);
        assert_eq!(
            classify(&opts, true, Some(b"xyz")),
            Precondition::FailedIfMatch
        );
        assert_eq!(classify(&opts, true, None), Precondition::FailedIfMatch);
        assert_eq!(classify(&opts, false, None), Precondition::FailedIfMatch);
    }

    #[test]
    fn if_none_match_fails_when_exists() {
        let opts = [Opt::if_none_match()];
        assert_eq!(
            classify(&opts, true, Some(b"abc")),
            Precondition::FailedIfNoneMatch
        );
        assert_eq!(classify(&opts, false, None), Precondition::Satisfied);
    }

    #[test]
    fn both_options_cannot_hold() {
        let opts = [Opt::if_match(b""), Opt::if_none_match()];
        assert_eq!(
            classify(&opts, true, Some(b"abc")),
            Precondition::FailedIfNoneMatch
        );
        assert_eq!(classify(&opts, false, None), Precondition::FailedIfMatch);
    }
}
