//! Consuming typestate [`EngineBuilder`].

use core::marker::PhantomData;

use super::Engine;
use super::Storage;
use super::capacities::{Capacities, bytes_ok};
use super::memory::MemoryProfile;
use crate::error::BuildError;

#[cfg(feature = "alloc")]
use super::AllocMemory;

/// Typestate: a required builder input is not yet set.
#[derive(Clone, Copy, Debug)]
pub struct Missing;

/// Typestate: a required builder input is set.
#[derive(Clone, Copy, Debug)]
pub struct Present;

#[derive(Clone, Copy, Debug, Default)]
struct Expected {
    rx_datagram: Option<(usize, usize)>,
    tx_datagram: Option<(usize, usize)>,
    dedup: Option<usize>,
    observe: Option<usize>,
    rx_body: Option<(usize, usize)>,
    tx_body: Option<(usize, usize)>,
    bodies_from_profile: bool,
}

/// Consuming typestate builder. `build()` exists only after the required areas
/// are specified (profile or method-by-method) and [`.block_wise`](Self::block_wise)
/// has been called.
///
/// `.block_wise(false)`: Storage must have no body pools.
/// `.block_wise(true)`: Storage must include body pools; body bytes must be a
/// multiple of 1024.
///
/// `build` moves `Storage` in. Size mismatch is a [`BuildError`].
pub struct EngineBuilder<
    Rx = Missing,
    Tx = Missing,
    Dedup = Missing,
    Observe = Missing,
    Block = Missing,
> {
    expected: Expected,
    block_wise: Option<bool>,
    _t: PhantomData<(Rx, Tx, Dedup, Observe, Block)>,
}

impl Default for EngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineBuilder {
    /// Empty builder. Call [`Self::profile`] or the area methods, then
    /// [`Self::block_wise`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            expected: Expected {
                rx_datagram: None,
                tx_datagram: None,
                dedup: None,
                observe: None,
                rx_body: None,
                tx_body: None,
                bodies_from_profile: false,
            },
            block_wise: None,
            _t: PhantomData,
        }
    }
}

impl<Rx, Tx, Dedup, Observe, Block> EngineBuilder<Rx, Tx, Dedup, Observe, Block> {
    fn cast<NRx, NTx, NDedup, NObserve, NBlock>(
        self,
    ) -> EngineBuilder<NRx, NTx, NDedup, NObserve, NBlock> {
        EngineBuilder {
            expected: self.expected,
            block_wise: self.block_wise,
            _t: PhantomData,
        }
    }

    /// Fill every area from `P`, including body sizes used only when block-wise
    /// is later enabled.
    #[must_use]
    pub fn profile<P: MemoryProfile>(
        mut self,
    ) -> EngineBuilder<Present, Present, Present, Present, Block> {
        self.expected.rx_datagram = Some((P::RX_DATAGRAM_SLOTS, P::RX_DATAGRAM_BYTES));
        self.expected.tx_datagram = Some((P::TX_DATAGRAM_SLOTS, P::TX_DATAGRAM_BYTES));
        self.expected.dedup = Some(P::DEDUP_ENTRIES);
        self.expected.observe = Some(P::OBSERVE_ENTRIES);
        self.expected.rx_body = Some((P::RX_BODY_SLOTS, P::RX_BODY_BYTES));
        self.expected.tx_body = Some((P::TX_BODY_SLOTS, P::TX_BODY_BYTES));
        self.expected.bodies_from_profile = true;
        self.cast()
    }

    /// Incoming Datagram Pool count and slot bytes.
    #[must_use]
    pub fn rx_datagram(
        mut self,
        slots: usize,
        bytes: usize,
    ) -> EngineBuilder<Present, Tx, Dedup, Observe, Block> {
        self.expected.rx_datagram = Some((slots, bytes));
        self.cast()
    }

    /// Outgoing Datagram Pool count and slot bytes.
    #[must_use]
    pub fn tx_datagram(
        mut self,
        slots: usize,
        bytes: usize,
    ) -> EngineBuilder<Rx, Present, Dedup, Observe, Block> {
        self.expected.tx_datagram = Some((slots, bytes));
        self.cast()
    }

    /// Dedup table entry count.
    #[must_use]
    pub fn dedup(mut self, entries: usize) -> EngineBuilder<Rx, Tx, Present, Observe, Block> {
        self.expected.dedup = Some(entries);
        self.cast()
    }

    /// Observe interest table entry count.
    #[must_use]
    pub fn observe(mut self, entries: usize) -> EngineBuilder<Rx, Tx, Dedup, Present, Block> {
        self.expected.observe = Some(entries);
        self.cast()
    }

    /// Incoming Body Pool count and complete-body bytes. Meaningful with
    /// `.block_wise(true)`.
    #[must_use]
    pub fn rx_body(mut self, slots: usize, bytes: usize) -> Self {
        self.expected.rx_body = Some((slots, bytes));
        self.expected.bodies_from_profile = false;
        self
    }

    /// Outgoing Body Pool count and complete-body bytes. Meaningful with
    /// `.block_wise(true)`.
    #[must_use]
    pub fn tx_body(mut self, slots: usize, bytes: usize) -> Self {
        self.expected.tx_body = Some((slots, bytes));
        self.expected.bodies_from_profile = false;
        self
    }
}

impl<Rx, Tx, Dedup, Observe> EngineBuilder<Rx, Tx, Dedup, Observe, Missing> {
    /// Set the block-wise switch. `build` exists only after this call (and
    /// after the required areas are specified).
    #[must_use]
    pub fn block_wise(mut self, enabled: bool) -> EngineBuilder<Rx, Tx, Dedup, Observe, Present> {
        self.block_wise = Some(enabled);
        self.cast()
    }
}

impl EngineBuilder<Present, Present, Present, Present, Present> {
    /// Move `storage` in. Validates the block-wise switch and any pinned sizes.
    pub fn build<S: Storage>(self, storage: S) -> Result<Engine<S>, BuildError> {
        let block_wise = self.block_wise.expect("typestate: block_wise was set");
        check(&self.expected, &storage.capacities(), block_wise)?;
        Ok(Engine::from_storage(storage))
    }

    /// Allocate [`AllocMemory`] from runtime [`Capacities`] (one-time heap
    /// growth at init). Same rules as [`Self::build`].
    #[cfg(feature = "alloc")]
    pub fn build_alloc(self, capacities: Capacities) -> Result<Engine<AllocMemory>, BuildError> {
        let block_wise = self.block_wise.expect("typestate: block_wise was set");
        check(&self.expected, &capacities, block_wise)?;
        let storage = AllocMemory::from_capacities(capacities, block_wise)?;
        Ok(Engine::from_storage(storage))
    }
}

fn check(expected: &Expected, storage: &Capacities, block_wise: bool) -> Result<(), BuildError> {
    storage.validate_for_build(block_wise)?;
    check_pair(
        expected.rx_datagram,
        storage.rx_datagram_slots,
        storage.rx_datagram_bytes,
    )?;
    check_pair(
        expected.tx_datagram,
        storage.tx_datagram_slots,
        storage.tx_datagram_bytes,
    )?;
    check_count(expected.dedup, storage.dedup_entries)?;
    check_count(expected.observe, storage.observe_entries)?;

    let user_set_bodies =
        !expected.bodies_from_profile && (expected.rx_body.is_some() || expected.tx_body.is_some());

    if block_wise {
        check_body(
            expected.rx_body,
            storage.rx_body_slots,
            storage.rx_body_bytes,
        )?;
        check_body(
            expected.tx_body,
            storage.tx_body_slots,
            storage.tx_body_bytes,
        )?;
    } else if user_set_bodies {
        return Err(BuildError::UnexpectedBodyPools);
    }
    Ok(())
}

fn check_pair(
    expected: Option<(usize, usize)>,
    slots: usize,
    bytes: usize,
) -> Result<(), BuildError> {
    match expected {
        Some((n, b)) if n != slots || b != bytes => Err(BuildError::SizeMismatch),
        _ => Ok(()),
    }
}

fn check_count(expected: Option<usize>, got: usize) -> Result<(), BuildError> {
    match expected {
        Some(n) if n != got => Err(BuildError::SizeMismatch),
        _ => Ok(()),
    }
}

fn check_body(
    expected: Option<(usize, usize)>,
    slots: Option<usize>,
    bytes: Option<usize>,
) -> Result<(), BuildError> {
    let Some((n, b)) = expected else {
        return Ok(());
    };
    if n == 0 || b == 0 {
        return Err(BuildError::ZeroBodyCapacity);
    }
    if !bytes_ok(b) {
        return Err(BuildError::BodyBytesNotMultipleOf1024);
    }
    if Some(n) != slots || Some(b) != bytes {
        return Err(BuildError::SizeMismatch);
    }
    Ok(())
}
