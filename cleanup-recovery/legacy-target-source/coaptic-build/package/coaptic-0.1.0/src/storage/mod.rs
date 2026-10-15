//! Bounded storage: [`Engine`], [`Memory`], pools, and tables.
//!
//! This is the **advanced path**. [`crate::App`] already runs
//! [`Engine::progress`], routing, Observe, and Block/Q-Block inside
//! [`crate::App::poll`]. Come here for explicit slots, a custom
//! [`DatagramIo`], or [`Access`] / [`AccessMut`].
//!
//! Acquire / release / rotate is written once against [`Storage`].
//! Message parse and encode live in [`crate::message`]. [`Engine`] glues
//! those codecs to occupied datagram slots ([`DatagramSlots`]). Token
//! matching, Observe interest, pending CON, Dedup, and Block/Q-Block
//! sidecars are tables on those slots — not a seventh memory area.
//! Incoming Q-Block `NON_RECEIVE_TIMEOUT` is [`QBlockReceiveWait`]
//! (caller `now_ms`). Engine BERT (SZX 7) codecs exist; App does not
//! expose them (future / backlog).
//!
//! [`Access`] / [`AccessMut`] pin occupied datagram or body bytes against
//! [`SlotPool::release`]. The App happy path does not need them.
//! [`Engine::progress`] is one bounded pass: CON retransmit, one unpinned
//! RX step, one Observe notify, at most one Observe expiry, at most one
//! due Q-Block recover. Empty tables skip those scans. This module does
//! not invent 4.02 / 4.08 / 2.31 / RST policy. [`Metrics`] are wrapping
//! `u32` counters on [`Engine`]; copy with [`Engine::metrics`] /
//! [`crate::App::metrics`].

mod access;
mod block;
mod builder;
mod capacities;
mod endpoint;
mod engine;
mod exchange;
mod io;
mod memory;
mod metrics;
mod occupancy;
mod pending;
mod pool;
pub mod profiles;
mod progress;
mod slot;
mod table;

#[cfg(feature = "alloc")]
mod alloc_memory;

#[cfg(test)]
mod tests;

pub use access::{Access, AccessMut};
#[cfg(feature = "alloc")]
pub use alloc_memory::AllocMemory;
pub use block::{
    BlockKey, BlockProgress, BlockRole, BlockTransfer, BodyTag, OutgoingBlock, QBlockReceiveWait,
    QBlockRecover,
};
pub use builder::{EngineBuilder, Missing, Present};
pub use capacities::Capacities;
pub use endpoint::Endpoint;
pub use engine::Engine;
pub use exchange::{ExchangeEntry, ExchangeKey, ExchangeTable, Exchanges};
pub use io::{DatagramIo, DatagramIoError};
pub use memory::{Memory, MemoryLayout, MemoryProfile, NoBodies, WithBodies};
pub use metrics::Metrics;
pub use pending::{PendingCon, PendingCons, PendingRto, Retransmit};
pub use pool::{BodyPool, DatagramPool, DatagramScratch};
pub use progress::Progress;
pub use slot::{SlotError, SlotId};
pub use table::{
    DedupEntry, DedupKey, DedupTable, ObserveExpiry, ObserveInterest, ObserveKey, ObserveLifetime,
    ObserveNotifyHold, ObserveResource, ObserveTable,
};

/// Acquire, release, and rotate occupancy for one pool or table.
///
/// Logic lives here so [`Engine`] stays generic over [`Storage`].
pub trait SlotPool {
    /// Occupy the next free slot starting at the rotating cursor.
    ///
    /// Returns `None` when every slot is occupied (saturation).
    fn acquire(&mut self) -> Option<SlotId>;

    /// Free `id` so a later acquire can reuse it. Does not move the cursor.
    fn release(&mut self, id: SlotId) -> Result<(), SlotError>;

    /// Advance the rotating cursor by one slot, wrapping at the end.
    fn rotate(&mut self) {
        self.advance(1);
    }

    /// Jump the rotating cursor by `steps` slots, wrapping at the end.
    fn advance(&mut self, steps: usize);

    /// Configured slot or entry count.
    fn slot_count(&self) -> usize;

    /// How many slots are currently occupied.
    ///
    /// O(1): occupancy tracks a live counter on acquire / release.
    fn occupied_count(&self) -> usize;

    /// Whether every slot is free. Default is [`Self::occupied_count`] `== 0`.
    fn is_empty(&self) -> bool {
        self.occupied_count() == 0
    }

    /// Whether `id` names an occupied slot in this pool.
    fn is_occupied(&self, id: SlotId) -> bool;

    /// Whether application access pins `id` against [`Self::release`].
    ///
    /// Default is false. Datagram and body pools override this. Rotate does
    /// not evict and is not blocked by a pin.
    fn is_pinned(&self, id: SlotId) -> bool {
        let _ = id;
        false
    }

    /// Index where the next acquire search starts.
    fn cursor(&self) -> usize;
}

/// Backing store for the six core areas that are present.
///
/// RX and TX datagrams are two [`DatagramPool`] values. Body pools exist
/// only when block-wise is enabled; [`Self::rx_body`] / [`Self::tx_body`] then
/// return `None`.
pub trait Storage {
    /// Configured sizes, including absent body fields when pools are omitted.
    fn capacities(&self) -> Capacities;

    /// Incoming Datagram Pool.
    fn rx_datagram(&mut self) -> &mut dyn SlotPool;

    /// Outgoing Datagram Pool.
    fn tx_datagram(&mut self) -> &mut dyn SlotPool;

    /// Dedup table.
    fn dedup(&mut self) -> &mut dyn SlotPool;

    /// Observe interest table.
    fn observe(&mut self) -> &mut dyn SlotPool;

    /// Incoming Body Pool, if block-wise storage includes body areas.
    fn rx_body(&mut self) -> Option<&mut dyn SlotPool>;

    /// Outgoing Body Pool, if block-wise storage includes body areas.
    fn tx_body(&mut self) -> Option<&mut dyn SlotPool>;
}

/// Filled datagram bytes for occupied RX/TX slots.
///
/// [`Memory`] and [`AllocMemory`] implement this so [`Engine`] can decode
/// and encode without inventing protocol responses.
pub trait DatagramSlots {
    /// Compile-time RX slot bytes for stack scratch (inbound copy, OSCORE
    /// unprotect, Block IO). [`Memory`] uses [`MemoryProfile::RX_DATAGRAM_BYTES`]
    /// so Constrained does not reserve Default 1472.
    ///
    /// [`AllocMemory`] keeps the Default ceiling; a smaller runtime slot
    /// fails loud on oversize copy.
    const RX_DATAGRAM_BYTES: usize = 1472;

    /// Compile-time TX slot bytes for stack scratch (OSCORE protect, Block
    /// encode, Dedup replay copy). [`Memory`] uses
    /// [`MemoryProfile::TX_DATAGRAM_BYTES`].
    const TX_DATAGRAM_BYTES: usize = 1472;

    /// Stack array for one RX datagram copy. [`Memory`] uses
    /// [`DatagramScratch`] sized to [`MemoryProfile::RX_DATAGRAM_BYTES`]
    /// so Constrained does not reserve Default 1472.
    type RxScratch: Default + AsRef<[u8]> + AsMut<[u8]>;

    /// Stack array for one TX datagram copy. [`Memory`] uses
    /// [`DatagramScratch`] sized to [`MemoryProfile::TX_DATAGRAM_BYTES`].
    type TxScratch: Default + AsRef<[u8]> + AsMut<[u8]>;

    /// Filled RX datagram, if `id` is occupied.
    fn rx_payload(&self, id: SlotId) -> Option<&[u8]>;

    /// Filled TX datagram, if `id` is occupied.
    fn tx_payload(&self, id: SlotId) -> Option<&[u8]>;

    /// Writable RX slot buffer (full capacity).
    fn rx_payload_mut(&mut self, id: SlotId) -> Option<&mut [u8]>;

    /// Writable TX slot buffer (full capacity).
    fn tx_payload_mut(&mut self, id: SlotId) -> Option<&mut [u8]>;

    /// Record the filled RX datagram length.
    fn set_rx_len(&mut self, id: SlotId, len: usize) -> Result<(), SlotError>;

    /// Record the filled TX datagram length.
    fn set_tx_len(&mut self, id: SlotId, len: usize) -> Result<(), SlotError>;

    /// Sidecar [`Endpoint`] for an occupied RX slot.
    fn rx_endpoint(&self, id: SlotId) -> Option<Endpoint>;

    /// Sidecar [`Endpoint`] for an occupied TX slot.
    fn tx_endpoint(&self, id: SlotId) -> Option<Endpoint>;

    /// Set RX sidecar [`Endpoint`]. Not written into the byte buffer.
    fn set_rx_endpoint(&mut self, id: SlotId, endpoint: Endpoint) -> Result<(), SlotError>;

    /// Set TX sidecar [`Endpoint`]. Not written into the byte buffer.
    fn set_tx_endpoint(&mut self, id: SlotId, endpoint: Endpoint) -> Result<(), SlotError>;

    /// Pending CON Message ID on an occupied TX slot, if marked.
    fn tx_pending_mid(&self, id: SlotId) -> Option<crate::message::MessageId>;

    /// Mark occupied TX `id` as pending CON with `message_id`.
    fn set_tx_pending(
        &mut self,
        id: SlotId,
        message_id: crate::message::MessageId,
    ) -> Result<(), SlotError>;

    /// Clear the pending-CON mark on TX `id`. The slot stays occupied.
    fn clear_tx_pending(&mut self, id: SlotId) -> Result<(), SlotError>;

    /// Occupied TX slot pending for `message_id` and `endpoint`, if any.
    fn lookup_tx_pending(
        &self,
        message_id: crate::message::MessageId,
        endpoint: Endpoint,
    ) -> Option<SlotId>;

    /// Read access to an occupied RX datagram. Pins `id` until dropped.
    ///
    /// See [`Access`]. The [`crate::App`] happy path does not need this.
    fn access_rx(&mut self, id: SlotId) -> Result<Access<'_>, SlotError>;

    /// Read access to an occupied TX datagram. Pins `id` until dropped.
    fn access_tx(&mut self, id: SlotId) -> Result<Access<'_>, SlotError>;

    /// Write access to an occupied TX datagram buffer. Pins `id` until dropped.
    fn access_tx_mut(&mut self, id: SlotId) -> Result<AccessMut<'_>, SlotError>;
}

/// Typed Dedup Table access.
///
/// Insert, lookup, and remove scan the configured entry count (O(n) in
/// capacity). Capacity is fixed at construction. [`Memory`] and
/// [`AllocMemory`] implement this so [`Engine`] can store [`DedupEntry`]
/// values in the existing table slots. [`crate::App::poll`] uses
/// [`DedupEntry::due_ms`], [`DedupEntry::replay`], and
/// [`DedupEntry::tx_pin`] so a duplicate CON request can be answered
/// without a second handler call.
pub trait DedupSlots {
    /// Insert `entry`, or return the existing slot if the key is present.
    ///
    /// `None` when the table is full and the key is not already stored.
    fn insert_dedup(&mut self, entry: DedupEntry) -> Option<SlotId>;

    /// Occupied slot matching `key`, if any.
    fn lookup_dedup(&self, key: DedupKey) -> Option<SlotId>;

    /// Release the slot matching `key`, if occupied.
    fn remove_dedup(&mut self, key: DedupKey) -> bool;

    /// Occupied payload at `id`.
    fn dedup_entry(&self, id: SlotId) -> Option<DedupEntry>;
}

/// Typed Observe Interest Table access.
///
/// Insert, lookup, remove, and take scan the configured entry count (O(n) in
/// capacity). Capacity is the profile observe-entry count. [`Memory`] and
/// [`AllocMemory`] implement this so [`Engine`] can store
/// [`ObserveInterest`] values in the existing table slots. Pending notify,
/// the 24-bit sequence, optional Max-Age / CON-wait lifetime, and RFC 7641
/// §4.5 / §4.5.1 confirm / NSTART hold stay on the row; bodies are not
/// stored here.
pub trait ObserveSlots {
    /// Insert `interest`, or return the existing slot if the key is present.
    ///
    /// `None` when the table is full and the key is not already stored.
    fn insert_observe(&mut self, interest: ObserveInterest) -> Option<SlotId>;

    /// Occupied slot matching `key`, if any.
    fn lookup_observe(&self, key: ObserveKey) -> Option<SlotId>;

    /// Release the slot matching `key`, if occupied.
    fn remove_observe(&mut self, key: ObserveKey) -> bool;

    /// Remove and return the occupied payload matching `key`, if any.
    fn take_observe(&mut self, key: ObserveKey) -> Option<ObserveInterest>;

    /// Occupied payload at `id`.
    fn observe_interest(&self, id: SlotId) -> Option<ObserveInterest>;

    /// Write payload into an already-occupied Observe slot.
    fn set_observe_interest(
        &mut self,
        id: SlotId,
        interest: ObserveInterest,
    ) -> Result<(), SlotError>;

    /// Mark the interest matching `key` as due for one notification.
    ///
    /// Coalesces until progress surfaces the row. `None` when no row matches.
    fn signal_observe(&mut self, key: ObserveKey) -> Option<SlotId> {
        let id = self.lookup_observe(key)?;
        let mut interest = self.observe_interest(id)?;
        interest.mark_due();
        self.set_observe_interest(id, interest).ok()?;
        Some(id)
    }
}

/// Classic Block and Q-Block access to Incoming / Outgoing Body Pools.
///
/// Present only when block-wise is enabled. [`Memory`] without body pools and
/// `AllocMemory` built with `.block_wise(false)` return `None` /
/// [`crate::error::BlockTransferError::NoBodyPools`]. Incoming Block1 / Block2 /
/// Q-Block1 / Q-Block2 use the Incoming Body Pool; outgoing Block1 / Block2 /
/// Q-Block1 / Q-Block2 use the Outgoing Body Pool.
pub trait BodySlots {
    /// Filled incoming body, if `id` is occupied.
    fn rx_body_payload(&self, id: SlotId) -> Option<&[u8]>;

    /// Filled outgoing body, if `id` is occupied.
    fn tx_body_payload(&self, id: SlotId) -> Option<&[u8]>;

    /// Incoming Block1 / Block2 sidecar, if `id` holds a transfer.
    fn rx_body_transfer(&self, id: SlotId) -> Option<BlockTransfer>;

    /// Write the sidecar into an already-occupied incoming body slot.
    fn set_rx_body_transfer(
        &mut self,
        id: SlotId,
        transfer: BlockTransfer,
    ) -> Result<(), SlotError>;

    /// Outgoing Block1 / Block2 sidecar, if `id` holds a transfer.
    fn tx_body_transfer(&self, id: SlotId) -> Option<BlockTransfer>;

    /// Incoming body slot matching `key`, if any. O(n) in RX body occupancy.
    fn lookup_rx_body(&self, key: BlockKey) -> Option<SlotId>;

    /// Outgoing body slot matching `key`, if any. O(n) in TX body occupancy.
    fn lookup_tx_body(&self, key: BlockKey) -> Option<SlotId>;

    /// Admit a new incoming Block1 body (first block, typically NUM 0).
    fn admit_block1(
        &mut self,
        key: BlockKey,
        block: crate::message::BlockValue,
        payload: &[u8],
        size1: Option<u32>,
    ) -> Result<SlotId, crate::error::BlockTransferError>;

    /// Write the next in-order incoming Block1 range into `id`.
    fn write_block1(
        &mut self,
        id: SlotId,
        block: crate::message::BlockValue,
        payload: &[u8],
    ) -> Result<BlockProgress, crate::error::BlockTransferError>;

    /// Admit or continue incoming Block1 for `key`.
    fn apply_block1(
        &mut self,
        key: BlockKey,
        block: crate::message::BlockValue,
        payload: &[u8],
        size1: Option<u32>,
    ) -> Result<BlockProgress, crate::error::BlockTransferError>;

    /// Admit a new incoming Block2 body (first block, typically NUM 0).
    fn admit_block2(
        &mut self,
        key: BlockKey,
        block: crate::message::BlockValue,
        payload: &[u8],
        size2: Option<u32>,
    ) -> Result<SlotId, crate::error::BlockTransferError>;

    /// Write the next in-order incoming Block2 range into `id`.
    fn write_block2(
        &mut self,
        id: SlotId,
        block: crate::message::BlockValue,
        payload: &[u8],
    ) -> Result<BlockProgress, crate::error::BlockTransferError>;

    /// Admit or continue incoming Block2 for `key`.
    fn apply_block2(
        &mut self,
        key: BlockKey,
        block: crate::message::BlockValue,
        payload: &[u8],
        size2: Option<u32>,
    ) -> Result<BlockProgress, crate::error::BlockTransferError>;

    /// Admit a new incoming Q-Block1 body (first block in window 0).
    fn admit_q_block1(
        &mut self,
        key: BlockKey,
        block: crate::message::BlockValue,
        payload: &[u8],
        size1: Option<u32>,
    ) -> Result<SlotId, crate::error::BlockTransferError>;

    /// Write one incoming Q-Block1 range into `id` (out-of-order in-window).
    fn write_q_block1(
        &mut self,
        id: SlotId,
        block: crate::message::BlockValue,
        payload: &[u8],
    ) -> Result<BlockProgress, crate::error::BlockTransferError>;

    /// Admit or continue incoming Q-Block1 for `key`.
    fn apply_q_block1(
        &mut self,
        key: BlockKey,
        block: crate::message::BlockValue,
        payload: &[u8],
        size1: Option<u32>,
    ) -> Result<BlockProgress, crate::error::BlockTransferError>;

    /// Admit a new incoming Q-Block2 body (first block in window 0).
    fn admit_q_block2(
        &mut self,
        key: BlockKey,
        block: crate::message::BlockValue,
        payload: &[u8],
        size2: Option<u32>,
    ) -> Result<SlotId, crate::error::BlockTransferError>;

    /// Write one incoming Q-Block2 range into `id` (out-of-order in-window).
    fn write_q_block2(
        &mut self,
        id: SlotId,
        block: crate::message::BlockValue,
        payload: &[u8],
    ) -> Result<BlockProgress, crate::error::BlockTransferError>;

    /// Admit or continue incoming Q-Block2 for `key`.
    fn apply_q_block2(
        &mut self,
        key: BlockKey,
        block: crate::message::BlockValue,
        payload: &[u8],
        size2: Option<u32>,
    ) -> Result<BlockProgress, crate::error::BlockTransferError>;

    /// Admit an outgoing Block1 body (complete body copied into a TX slot).
    fn start_block1(
        &mut self,
        key: BlockKey,
        body: &[u8],
        szx: u8,
    ) -> Result<SlotId, crate::error::BlockTransferError>;

    /// Issue the next in-order outgoing Block1 range from `id`.
    fn next_block1(
        &mut self,
        id: SlotId,
    ) -> Result<OutgoingBlock, crate::error::BlockTransferError>;

    /// Issue one outgoing Block1 BERT payload of at most `max_payload` bytes.
    fn next_bert1(
        &mut self,
        id: SlotId,
        max_payload: usize,
    ) -> Result<OutgoingBlock, crate::error::BlockTransferError>;

    /// Admit an outgoing Block2 body (complete body copied into a TX slot).
    fn start_block2(
        &mut self,
        key: BlockKey,
        body: &[u8],
        szx: u8,
    ) -> Result<SlotId, crate::error::BlockTransferError>;

    /// Issue the next in-order outgoing Block2 range from `id`.
    fn next_block2(
        &mut self,
        id: SlotId,
    ) -> Result<OutgoingBlock, crate::error::BlockTransferError>;

    /// Issue one outgoing Block2 BERT payload of at most `max_payload` bytes.
    fn next_bert2(
        &mut self,
        id: SlotId,
        max_payload: usize,
    ) -> Result<OutgoingBlock, crate::error::BlockTransferError>;

    /// Admit an outgoing Q-Block1 body (complete body copied into a TX slot).
    fn start_q_block1(
        &mut self,
        key: BlockKey,
        body: &[u8],
        szx: u8,
    ) -> Result<SlotId, crate::error::BlockTransferError>;

    /// Issue the next unsent outgoing Q-Block1 range in the current window.
    fn next_q_block1(
        &mut self,
        id: SlotId,
    ) -> Result<OutgoingBlock, crate::error::BlockTransferError>;

    /// Advance an outgoing Q-Block1 window using the peer Continue NUM.
    fn ack_q_block1(
        &mut self,
        id: SlotId,
        num: u32,
    ) -> Result<BlockProgress, crate::error::BlockTransferError>;

    /// Admit an outgoing Q-Block2 body (complete body copied into a TX slot).
    fn start_q_block2(
        &mut self,
        key: BlockKey,
        body: &[u8],
        szx: u8,
    ) -> Result<SlotId, crate::error::BlockTransferError>;

    /// Issue the next unsent outgoing Q-Block2 range in the current window.
    fn next_q_block2(
        &mut self,
        id: SlotId,
    ) -> Result<OutgoingBlock, crate::error::BlockTransferError>;

    /// Advance an outgoing Q-Block2 window using the peer Continue NUM.
    fn ack_q_block2(
        &mut self,
        id: SlotId,
        num: u32,
    ) -> Result<BlockProgress, crate::error::BlockTransferError>;

    /// Read access to an occupied incoming body. Pins `id` until dropped.
    ///
    /// See [`Access`]. The [`crate::App`] happy path does not need this.
    fn access_rx_body(&mut self, id: SlotId) -> Result<Access<'_>, SlotError>;

    /// Write access to an occupied outgoing body buffer. Pins `id` until dropped.
    fn access_tx_body_mut(&mut self, id: SlotId) -> Result<AccessMut<'_>, SlotError>;
}
