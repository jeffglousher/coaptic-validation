//! Message ID sequence and Token minting.
//!
//! Caller-owned, [`Copy`] where the state is a counter, `no_std`. The core
//! never calls an OS RNG: pass the first [`MessageId`] and any Token entropy
//! (or a [`TokenSource`]). See `knowledge/rfcs/rfc7252.txt`.

use super::{Code, Message, MessageId, Token, Type};

/// Wrapping Message ID sequence.
///
/// Yields the current counter, then wrapping-adds 1. Randomize `start` if
/// you want an unpredictable first ID — this type does not call an OS RNG.
///
/// See `knowledge/rfcs/rfc7252.txt`.
///
/// ```
/// use coaptic::message::{Code, Ids, Token, Type};
///
/// let mut ids = Ids::new(1);
/// let token = Token::mint(2, &[0xaa, 0xbb]).unwrap();
/// let req = ids.con(Code::GET, token);
/// assert_eq!(req.ty(), Type::Confirmable);
/// assert_eq!(req.message_id().get(), 1);
/// assert_eq!(ids.peek().get(), 2);
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Ids {
    next: u16,
}

impl Ids {
    /// Sequence whose first [`Self::next`] is `start`.
    #[must_use]
    pub const fn new(start: u16) -> Self {
        Self { next: start }
    }

    /// Sequence whose first [`Self::next`] is `id`.
    #[must_use]
    pub const fn from_id(id: MessageId) -> Self {
        Self::new(id.get())
    }

    /// Next ID without advancing.
    #[must_use]
    pub const fn peek(self) -> MessageId {
        MessageId::new(self.next)
    }

    /// Yield the next Message ID and wrap the counter.
    #[must_use]
    pub const fn next(&mut self) -> MessageId {
        let id = MessageId::new(self.next);
        self.next = self.next.wrapping_add(1);
        id
    }

    /// CON with the next Message ID and `token`.
    #[must_use]
    pub const fn con(&mut self, code: Code, token: Token) -> Message<'static> {
        Message::con(code, self.next(), token)
    }

    /// NON with the next Message ID and `token`.
    #[must_use]
    pub const fn non(&mut self, code: Code, token: Token) -> Message<'static> {
        Message::non(code, self.next(), token)
    }

    /// CON or NON with the next Message ID and `token`.
    ///
    /// `None` if `ty` is ACK or RST; the counter is not advanced.
    #[must_use]
    pub const fn request(
        &mut self,
        ty: Type,
        code: Code,
        token: Token,
    ) -> Option<Message<'static>> {
        match ty {
            Type::Confirmable | Type::NonConfirmable => {
                Some(Message::new(ty, code, self.next()).with_token(token))
            }
            Type::Acknowledgement | Type::Reset => None,
        }
    }
}

impl From<u16> for Ids {
    fn from(start: u16) -> Self {
        Self::new(start)
    }
}

impl From<MessageId> for Ids {
    fn from(id: MessageId) -> Self {
        Self::from_id(id)
    }
}

/// Caller-supplied Token bytes.
///
/// The core never calls an OS RNG. A source may be a slice, a wrapping
/// counter, or a platform RNG the caller owns.
pub trait TokenSource {
    /// Write `dest.len()` bytes into `dest`.
    ///
    /// Return `false` if this source cannot fill `dest` (short entropy).
    /// `mint_from` only calls this for lengths `1..=8`.
    fn fill(&mut self, dest: &mut [u8]) -> bool;
}

impl TokenSource for [u8] {
    fn fill(&mut self, dest: &mut [u8]) -> bool {
        fill_from_slice(self, dest)
    }
}

impl<const N: usize> TokenSource for [u8; N] {
    fn fill(&mut self, dest: &mut [u8]) -> bool {
        fill_from_slice(self, dest)
    }
}

impl TokenSource for &[u8] {
    fn fill(&mut self, dest: &mut [u8]) -> bool {
        if !fill_from_slice(self, dest) {
            return false;
        }
        *self = &self[dest.len()..];
        true
    }
}

fn fill_from_slice(src: &[u8], dest: &mut [u8]) -> bool {
    if src.len() < dest.len() {
        return false;
    }
    dest.copy_from_slice(&src[..dest.len()]);
    true
}

impl Token {
    /// Copy the first `len` bytes of `entropy` into a token.
    ///
    /// `len == 0` is [`Token::EMPTY`] and ignores `entropy`. `None` if
    /// `len` is greater than [`Token::MAX_LEN`], or if `len > 0` and
    /// `entropy` is shorter than `len`. Deterministic for a fixed
    /// `entropy` prefix. The core does not call an OS RNG.
    #[must_use]
    pub fn mint(len: usize, entropy: &[u8]) -> Option<Self> {
        if len == 0 {
            return Some(Self::EMPTY);
        }
        if len > Self::MAX_LEN || entropy.len() < len {
            return None;
        }
        Some(Self::from_checked(&entropy[..len]))
    }

    /// Mint `len` bytes from `source`.
    ///
    /// `len == 0` is [`Token::EMPTY`] and does not call [`TokenSource::fill`].
    /// `None` if `len` is greater than [`Token::MAX_LEN`] or `source`
    /// returns `false`. The core does not call an OS RNG.
    #[must_use]
    pub fn mint_from<S: TokenSource + ?Sized>(len: usize, source: &mut S) -> Option<Self> {
        if len == 0 {
            return Some(Self::EMPTY);
        }
        if len > Self::MAX_LEN {
            return None;
        }
        let mut buf = [0u8; Token::MAX_LEN];
        let dest = &mut buf[..len];
        if !source.fill(dest) {
            return None;
        }
        Some(Self::from_checked(dest))
    }
}

#[cfg(test)]
mod unit_tests {
    use super::{Ids, TokenSource};
    use crate::message::{Code, MessageId, Token, Type};

    #[test]
    fn ids_wraps_u16() {
        let mut ids = Ids::new(u16::MAX);
        assert_eq!(ids.peek(), MessageId::new(u16::MAX));
        assert_eq!(ids.next(), MessageId::new(u16::MAX));
        assert_eq!(ids.next(), MessageId::new(0));
        assert_eq!(ids.next(), MessageId::new(1));
        assert_eq!(ids.peek(), MessageId::new(2));
    }

    #[test]
    fn ids_from_id_and_default() {
        let mut from_raw = Ids::from(7u16);
        let mut from_id = Ids::from(MessageId::new(7));
        assert_eq!(from_raw.next(), from_id.next());
        assert_eq!(Ids::default().peek(), MessageId::new(0));
        assert_eq!(Ids::from_id(MessageId::new(9)).peek().get(), 9);
    }

    #[test]
    fn token_mint_empty_and_fixed_lengths() {
        assert_eq!(Token::mint(0, &[]).expect("empty"), Token::EMPTY);
        assert_eq!(Token::mint(0, &[0xaa, 0xbb]).expect("ignore"), Token::EMPTY);
        assert!(Token::mint(0, &[]).expect("empty").is_empty());

        let entropy = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        for len in 1..=8 {
            let token = Token::mint(len, &entropy).expect("len");
            assert_eq!(token.len(), len);
            assert_eq!(token.as_bytes(), &entropy[..len]);
            let again = Token::mint(len, &entropy).expect("deterministic");
            assert_eq!(token, again);
        }
    }

    #[test]
    fn token_mint_rejects_too_long_and_short_entropy() {
        assert!(Token::mint(9, &[0; 9]).is_none());
        assert!(Token::mint(9, &[0; 16]).is_none());
        assert!(Token::mint(8, &[0; 7]).is_none());
        assert!(Token::mint(1, &[]).is_none());
        assert_eq!(Token::MAX_LEN, 8);
        assert!(Token::new(&[0; 9]).is_none());
    }

    #[test]
    fn token_mint_from_slice_consumes_and_is_deterministic() {
        let bytes = [0x10u8, 0x20, 0x30, 0x40, 0x50];
        let mut src = bytes.as_slice();
        let a = Token::mint_from(2, &mut src).expect("a");
        let b = Token::mint_from(3, &mut src).expect("b");
        assert_eq!(a.as_bytes(), &[0x10, 0x20]);
        assert_eq!(b.as_bytes(), &[0x30, 0x40, 0x50]);
        assert!(Token::mint_from(1, &mut src).is_none());

        let mut again = bytes.as_slice();
        assert_eq!(Token::mint_from(2, &mut again).expect("again"), a);

        let empty = Token::mint_from(0, &mut again).expect("empty");
        assert_eq!(empty, Token::EMPTY);
        assert_eq!(again, &bytes[2..]);
    }

    struct Counter(u64);

    impl TokenSource for Counter {
        fn fill(&mut self, dest: &mut [u8]) -> bool {
            let n = dest.len();
            if n > Token::MAX_LEN {
                return false;
            }
            let bytes = self.0.to_be_bytes();
            dest.copy_from_slice(&bytes[8 - n..]);
            self.0 = self.0.wrapping_add(1);
            true
        }
    }

    #[test]
    fn token_source_counter_is_deterministic() {
        let mut src = Counter(0x0102_0304_0506_0708);
        let token = Token::mint_from(4, &mut src).expect("4");
        assert_eq!(token.as_bytes(), &[0x05, 0x06, 0x07, 0x08]);
        let next = Token::mint_from(4, &mut src).expect("next");
        assert_eq!(next.as_bytes(), &[0x05, 0x06, 0x07, 0x09]);

        let mut replay = Counter(0x0102_0304_0506_0708);
        assert_eq!(Token::mint_from(4, &mut replay).expect("replay"), token);
        assert!(Token::mint_from(9, &mut replay).is_none());
    }

    #[test]
    fn request_skeleton_con_non_rejects_ack_rst() {
        let mut ids = Ids::new(0x00ab);
        let token = Token::mint(1, &[0x21]).expect("token");

        let con = ids.con(Code::GET, token);
        assert_eq!(con.ty(), Type::Confirmable);
        assert_eq!(con.code(), Code::GET);
        assert_eq!(con.message_id(), MessageId::new(0x00ab));
        assert_eq!(con.token(), token);
        assert!(con.options().is_empty());
        assert!(con.payload().is_empty());

        let non = ids.non(Code::POST, Token::EMPTY);
        assert_eq!(non.ty(), Type::NonConfirmable);
        assert_eq!(non.message_id(), MessageId::new(0x00ac));
        assert!(non.token().is_empty());

        let via = ids
            .request(Type::Confirmable, Code::PUT, token)
            .expect("con");
        assert_eq!(via.message_id(), MessageId::new(0x00ad));
        assert_eq!(via.ty(), Type::Confirmable);

        let before = ids.peek();
        assert!(
            ids.request(Type::Acknowledgement, Code::EMPTY, token)
                .is_none()
        );
        assert!(ids.request(Type::Reset, Code::EMPTY, token).is_none());
        assert_eq!(ids.peek(), before);
    }
}
