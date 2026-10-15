//! Fixed-capacity option list for [`Message::with_options`].

use crate::error::OptionsFull;

use super::option::Opt;

/// Fixed-capacity option list. Inserts stay sorted by option number.
///
/// Push [`Opt`] values (including Table 4 and Block / Q-Block helpers) in any
/// order. Equal
/// numbers keep insertion order so repeatable options such as Uri-Path stay
/// in the order they were pushed.
///
/// `N` is the maximum number of options. There is no allocator on the hot
/// path. A further [`push`](Self::push) when full returns [`OptionsFull`].
///
/// # Lifetimes
///
/// Each [`Opt`] borrows its value bytes from the caller. Those slices must
/// outlive this builder and any [`Message`](crate::message::Message) or
/// [`encode`](crate::message::encode) call that borrows [`as_slice`](Self::as_slice).
///
/// Uint values use [`EncodedUint`](crate::message::EncodedUint) held by the **caller**.
/// Pass [`Opt::uint`], a Table 4 helper such as [`Opt::content_format`], or
/// [`Opt::block2`] after [`crate::message::BlockValue::encode`].
/// The builder does not store `EncodedUint` itself (that would be
/// self-referential).
///
/// ```
/// use coaptic::message::{Message, MessageId, Opt, OptionsBuilder, Type};
/// use coaptic::{Code, ContentFormat};
///
/// let cf = ContentFormat::JSON.encode();
/// let mut opts = OptionsBuilder::<4>::new();
/// opts.push(Opt::content_format(&cf)).expect("room");
/// opts.push(Opt::uri_path("temp")).expect("room");
/// let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
///     .with_options(opts.as_slice());
/// assert_eq!(msg.options()[0].number(), coaptic::message::OptionNumber::URI_PATH);
/// ```
#[derive(Clone, Debug)]
pub struct OptionsBuilder<'a, const N: usize> {
    items: [Opt<'a>; N],
    len: usize,
}

impl<'a, const N: usize> OptionsBuilder<'a, N> {
    const PLACEHOLDER: Opt<'a> = Opt::new(super::OptionNumber::new(0), &[]);

    /// Empty builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            items: [Self::PLACEHOLDER; N],
            len: 0,
        }
    }

    /// Insert `opt` so numbers stay non-decreasing.
    ///
    /// Equal numbers are appended after existing options with that number.
    pub fn push(&mut self, opt: Opt<'a>) -> Result<&mut Self, OptionsFull> {
        if self.len >= N {
            return Err(OptionsFull);
        }
        let mut i = self.len;
        while i > 0 && self.items[i - 1].number() > opt.number() {
            self.items[i] = self.items[i - 1];
            i -= 1;
        }
        self.items[i] = opt;
        self.len += 1;
        Ok(self)
    }

    /// Options in non-decreasing number order, suitable for
    /// [`Message::with_options`](crate::message::Message::with_options).
    #[must_use]
    pub fn as_slice(&self) -> &[Opt<'a>] {
        &self.items[..self.len]
    }

    /// Number of stored options.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no options have been pushed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether [`push`](Self::push) would return [`OptionsFull`].
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len == N
    }

    /// Maximum number of options (`N`).
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Unused slots before the builder is full.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        N - self.len
    }

    /// Drop every stored option. Value slices are not retained.
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl<'a, const N: usize> Default for OptionsBuilder<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, const N: usize> PartialEq for OptionsBuilder<'a, N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<'a, const N: usize> Eq for OptionsBuilder<'a, N> {}

#[cfg(test)]
mod unit_tests {
    use super::OptionsBuilder;
    use crate::error::OptionsFull;
    use crate::message::{Opt, OptionNumber};

    #[test]
    fn insert_sorts_and_keeps_equal_order() {
        let mut opts = OptionsBuilder::<4>::new();
        opts.push(Opt::new(OptionNumber::CONTENT_FORMAT, &[50]))
            .expect("cf");
        opts.push(Opt::uri_path("b")).expect("b");
        opts.push(Opt::uri_host("h")).expect("h");
        opts.push(Opt::uri_path("a")).expect("a");

        let got: [OptionNumber; 4] = [
            opts.as_slice()[0].number(),
            opts.as_slice()[1].number(),
            opts.as_slice()[2].number(),
            opts.as_slice()[3].number(),
        ];
        assert_eq!(
            got,
            [
                OptionNumber::URI_HOST,
                OptionNumber::URI_PATH,
                OptionNumber::URI_PATH,
                OptionNumber::CONTENT_FORMAT,
            ]
        );
        assert_eq!(opts.as_slice()[1].value(), b"b");
        assert_eq!(opts.as_slice()[2].value(), b"a");
    }

    #[test]
    fn full_rejects_further_push() {
        let mut opts = OptionsBuilder::<1>::new();
        assert_eq!(opts.capacity(), 1);
        assert_eq!(opts.remaining(), 1);
        opts.push(Opt::uri_path("x")).expect("first");
        assert!(opts.is_full());
        assert_eq!(opts.remaining(), 0);
        assert_eq!(opts.push(Opt::uri_path("y")).err(), Some(OptionsFull));
        assert_eq!(opts.len(), 1);
        assert_eq!(opts.as_slice()[0].value(), b"x");
    }

    #[test]
    fn zero_capacity_is_always_full() {
        let mut opts = OptionsBuilder::<0>::new();
        assert!(opts.is_empty());
        assert!(opts.is_full());
        assert_eq!(opts.push(Opt::if_none_match()).err(), Some(OptionsFull));
    }

    #[test]
    fn clear_allows_reuse() {
        let mut opts = OptionsBuilder::<2>::new();
        opts.push(Opt::uri_path("x")).expect("push");
        opts.clear();
        assert!(opts.is_empty());
        opts.push(Opt::uri_path("y")).expect("reuse");
        assert_eq!(opts.as_slice()[0].value(), b"y");
    }
}
