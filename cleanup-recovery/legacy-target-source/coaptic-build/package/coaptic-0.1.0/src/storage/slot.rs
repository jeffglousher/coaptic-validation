//! [`SlotId`] and slot addressing errors.

/// Identifier of one slot or table entry in a pool.
///
/// Values are issued by acquire. They are not stable across reuse after release.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SlotId(usize);

impl SlotId {
    pub(crate) const fn from_index(index: usize) -> Self {
        Self(index)
    }

    /// Zero-based index inside the issuing pool or table.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// Failure when releasing or addressing a slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotError {
    /// The identifier is outside the pool or table.
    InvalidSlot,
    /// The slot is already free.
    NotOccupied,
    /// A fill length exceeded the slot byte capacity.
    LengthExceedsSlot,
    /// Application [`crate::storage::Access`] still pins this slot.
    ///
    /// Release is refused until the access is dropped. Rotate does not evict
    /// and is not blocked.
    Pinned,
}

impl core::fmt::Display for SlotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSlot => f.write_str("slot id is outside the pool"),
            Self::NotOccupied => f.write_str("slot is not occupied"),
            Self::LengthExceedsSlot => f.write_str("length exceeds slot bytes"),
            Self::Pinned => f.write_str("slot is pinned by application access"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SlotError {}
