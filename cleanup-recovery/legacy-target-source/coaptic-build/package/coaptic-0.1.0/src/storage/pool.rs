//! [`DatagramPool`] and [`BodyPool`]: byte buffers, occupancy, rotating cursor.

use super::Access;
use super::AccessMut;
use super::SlotPool;
use super::block::{
    BlockKey, BlockProgress, BlockRole, BlockTransfer, OutgoingBlock, accept_incoming_role,
    block_offset, same_body_identity, start_incoming, store_incoming, write_range,
};
use super::endpoint::Endpoint;
use super::occupancy::Occupancy;
use super::pending::{PendingMark, PendingRto};
use super::slot::{SlotError, SlotId};
use crate::error::{BlockTransferError, SlotMessageError};
use crate::message::{BlockValue, Message, MessageId, ParsedMessage};

/// One datagram of stack scratch. `N` is the profile RX or TX slot size.
///
/// `[u8; N]` has no `Default` for N > 32; this wrapper zeros with a const
/// generic so Constrained (1152) does not reserve Default 1472.
pub struct DatagramScratch<const N: usize>([u8; N]);

impl<const N: usize> DatagramScratch<N> {
    /// Zeroed scratch of `N` bytes.
    #[must_use]
    pub const fn new() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Default for DatagramScratch<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AsRef<[u8]> for DatagramScratch<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for DatagramScratch<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Pool of datagram slots (RX and TX are two pools of this type).
///
/// Each slot holds CoAP message bytes (UDP payload) plus sidecar [`Endpoint`]
/// metadata. On TX slots, an optional pending mark (Message ID + RTO) marks
/// a CON waiting for ACK/RST. Neither sidecar is stored in the byte buffer.
pub struct DatagramPool<const SLOTS: usize, const BYTES: usize> {
    bytes: [[u8; BYTES]; SLOTS],
    lens: [usize; SLOTS],
    endpoints: [Option<Endpoint>; SLOTS],
    pending: [Option<PendingMark>; SLOTS],
    occ: Occupancy<SLOTS>,
}

impl<const SLOTS: usize, const BYTES: usize> DatagramPool<SLOTS, BYTES> {
    /// Empty pool. Cursor starts at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [[0u8; BYTES]; SLOTS],
            lens: [0; SLOTS],
            endpoints: [None; SLOTS],
            pending: [None; SLOTS],
            occ: Occupancy::new(),
        }
    }

    /// Bytes available in each slot.
    #[must_use]
    pub const fn slot_bytes(&self) -> usize {
        BYTES
    }

    /// Filled payload in an occupied slot.
    #[must_use]
    pub fn payload(&self, id: SlotId) -> Option<&[u8]> {
        if !self.occ.is_occupied(id) {
            return None;
        }
        let idx = id.index();
        Some(&self.bytes[idx][..self.lens[idx]])
    }

    /// Writable slot buffer (full capacity). Caller sets the filled length.
    pub fn payload_mut(&mut self, id: SlotId) -> Option<&mut [u8]> {
        if !self.occ.is_occupied(id) {
            return None;
        }
        Some(&mut self.bytes[id.index()])
    }

    /// Decode the occupied slot's filled bytes with [`crate::message::decode`].
    ///
    /// Does not run format or unrecognized-critical checks.
    pub fn decode(&self, id: SlotId) -> Result<ParsedMessage<'_>, SlotMessageError> {
        crate::message::decode(self.payload(id).ok_or(SlotError::NotOccupied)?)
            .map_err(SlotMessageError::Parse)
    }

    /// Encode `msg` into the occupied slot and record the filled length.
    pub fn encode(&mut self, id: SlotId, msg: &Message<'_>) -> Result<usize, SlotMessageError> {
        let n = {
            let buf = self.payload_mut(id).ok_or(SlotError::NotOccupied)?;
            crate::message::encode(msg, buf).map_err(SlotMessageError::Encode)?
        };
        self.set_len(id, n)?;
        Ok(n)
    }

    /// Mark how many bytes in the slot are the current datagram.
    pub fn set_len(&mut self, id: SlotId, len: usize) -> Result<(), SlotError> {
        if !self.occ.is_occupied(id) {
            return Err(if id.index() < SLOTS {
                SlotError::NotOccupied
            } else {
                SlotError::InvalidSlot
            });
        }
        if len > BYTES {
            return Err(SlotError::LengthExceedsSlot);
        }
        self.lens[id.index()] = len;
        Ok(())
    }

    /// Copy `bytes` into an occupied slot, record length, and set sidecar [`Endpoint`].
    pub fn write(
        &mut self,
        id: SlotId,
        bytes: &[u8],
        endpoint: Endpoint,
    ) -> Result<usize, SlotError> {
        {
            let buf = self.payload_mut(id).ok_or(if id.index() < SLOTS {
                SlotError::NotOccupied
            } else {
                SlotError::InvalidSlot
            })?;
            if bytes.len() > buf.len() {
                return Err(SlotError::LengthExceedsSlot);
            }
            buf[..bytes.len()].copy_from_slice(bytes);
        }
        self.set_len(id, bytes.len())?;
        self.set_endpoint(id, endpoint)?;
        Ok(bytes.len())
    }

    /// Sidecar endpoint for an occupied slot. `None` if free or not yet set.
    #[must_use]
    pub fn endpoint(&self, id: SlotId) -> Option<Endpoint> {
        if !self.occ.is_occupied(id) {
            return None;
        }
        self.endpoints[id.index()]
    }

    /// Set sidecar endpoint metadata. Not written into the byte buffer.
    pub fn set_endpoint(&mut self, id: SlotId, endpoint: Endpoint) -> Result<(), SlotError> {
        if !self.occ.is_occupied(id) {
            return Err(if id.index() < SLOTS {
                SlotError::NotOccupied
            } else {
                SlotError::InvalidSlot
            });
        }
        self.endpoints[id.index()] = Some(endpoint);
        Ok(())
    }

    /// Pending CON Message ID for an occupied slot, if marked.
    #[must_use]
    pub fn pending_mid(&self, id: SlotId) -> Option<MessageId> {
        self.pending_mark(id).map(|m| m.message_id)
    }

    /// Pending CON RTO for an occupied slot, if marked.
    #[must_use]
    pub fn pending_rto(&self, id: SlotId) -> Option<PendingRto> {
        self.pending_mark(id).map(|m| m.rto)
    }

    fn pending_mark(&self, id: SlotId) -> Option<PendingMark> {
        if !self.occ.is_occupied(id) {
            return None;
        }
        self.pending.get(id.index()).copied().flatten()
    }

    /// Mark occupied `id` as a pending CON with `message_id`.
    ///
    /// RTO is [`PendingRto::new`]`(0, 0)`. Prefer
    /// [`Self::set_pending`] when the caller has a clock.
    pub fn set_pending_mid(&mut self, id: SlotId, message_id: MessageId) -> Result<(), SlotError> {
        self.set_pending(id, message_id, PendingRto::new(0, 0))
    }

    /// Mark occupied `id` as a pending CON with `message_id` and `rto`.
    pub fn set_pending(
        &mut self,
        id: SlotId,
        message_id: MessageId,
        rto: PendingRto,
    ) -> Result<(), SlotError> {
        if !self.occ.is_occupied(id) {
            return Err(if id.index() < SLOTS {
                SlotError::NotOccupied
            } else {
                SlotError::InvalidSlot
            });
        }
        self.pending[id.index()] = Some(PendingMark::new(message_id, rto));
        Ok(())
    }

    /// Clear the pending-CON mark and RTO. The slot stays occupied.
    pub fn clear_pending_mid(&mut self, id: SlotId) -> Result<(), SlotError> {
        if !self.occ.is_occupied(id) {
            return Err(if id.index() < SLOTS {
                SlotError::NotOccupied
            } else {
                SlotError::InvalidSlot
            });
        }
        self.pending[id.index()] = None;
        Ok(())
    }

    /// Read access to the filled payload. Pins `id` until the guard is dropped.
    pub fn access(&mut self, id: SlotId) -> Result<Access<'_>, SlotError> {
        self.occ.try_pin(id)?;
        let idx = id.index();
        let pin = self.occ.pin_flag_mut(id).ok_or(SlotError::InvalidSlot)?;
        let bytes = &self.bytes[idx][..self.lens[idx]];
        Ok(Access::new(id, bytes, pin))
    }

    /// Write access to the full slot buffer. Pins `id` until the guard is dropped.
    pub fn access_mut(&mut self, id: SlotId) -> Result<AccessMut<'_>, SlotError> {
        self.occ.try_pin(id)?;
        let idx = id.index();
        let pin = self.occ.pin_flag_mut(id).ok_or(SlotError::InvalidSlot)?;
        let bytes = &mut self.bytes[idx];
        let len = &mut self.lens[idx];
        Ok(AccessMut::new(id, bytes, len, pin))
    }

    /// Set the same pin bit [`Self::access`] holds. For tests of release-while-pinned.
    #[cfg(test)]
    pub(crate) fn pin(&mut self, id: SlotId) -> Result<(), SlotError> {
        self.occ.try_pin(id)
    }

    /// Clear a test pin set by [`Self::pin`].
    #[cfg(test)]
    pub(crate) fn unpin(&mut self, id: SlotId) -> Result<(), SlotError> {
        self.occ.unpin(id)
    }

    /// Occupied slot whose pending MID and sidecar endpoint match, if any.
    ///
    /// Scans the configured slot count (O(n)).
    #[must_use]
    pub fn lookup_pending(&self, message_id: MessageId, endpoint: Endpoint) -> Option<SlotId> {
        (0..SLOTS).find_map(|i| {
            let id = SlotId::from_index(i);
            if self.pending_mid(id) == Some(message_id) && self.endpoint(id) == Some(endpoint) {
                Some(id)
            } else {
                None
            }
        })
    }

    fn reset(&mut self, id: SlotId) {
        let idx = id.index();
        self.lens[idx] = 0;
        self.endpoints[idx] = None;
        self.pending[idx] = None;
    }
}

impl<const SLOTS: usize, const BYTES: usize> Default for DatagramPool<SLOTS, BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize, const BYTES: usize> SlotPool for DatagramPool<SLOTS, BYTES> {
    fn acquire(&mut self) -> Option<SlotId> {
        let id = self.occ.acquire()?;
        self.reset(id);
        Some(id)
    }

    fn release(&mut self, id: SlotId) -> Result<(), SlotError> {
        self.occ.release(id)?;
        self.reset(id);
        Ok(())
    }

    fn advance(&mut self, steps: usize) {
        self.occ.advance(steps);
    }

    fn slot_count(&self) -> usize {
        self.occ.slot_count()
    }

    fn occupied_count(&self) -> usize {
        self.occ.occupied_count()
    }

    fn is_occupied(&self, id: SlotId) -> bool {
        self.occ.is_occupied(id)
    }

    fn is_pinned(&self, id: SlotId) -> bool {
        self.occ.is_pinned(id)
    }

    fn cursor(&self) -> usize {
        self.occ.cursor()
    }
}

/// Byte and sidecar access for one datagram pool. Used by [`DatagramSlots`](super::DatagramSlots).
pub(crate) trait DatagramBytes {
    fn payload(&self, id: SlotId) -> Option<&[u8]>;
    fn payload_mut(&mut self, id: SlotId) -> Option<&mut [u8]>;
    fn set_len(&mut self, id: SlotId, len: usize) -> Result<(), SlotError>;
    fn endpoint(&self, id: SlotId) -> Option<Endpoint>;
    fn set_endpoint(&mut self, id: SlotId, endpoint: Endpoint) -> Result<(), SlotError>;
    fn pending_mid(&self, id: SlotId) -> Option<MessageId>;
    fn pending_rto(&self, id: SlotId) -> Option<PendingRto>;
    fn set_pending_mid(&mut self, id: SlotId, message_id: MessageId) -> Result<(), SlotError>;
    fn set_pending(
        &mut self,
        id: SlotId,
        message_id: MessageId,
        rto: PendingRto,
    ) -> Result<(), SlotError>;
    fn clear_pending_mid(&mut self, id: SlotId) -> Result<(), SlotError>;
    fn lookup_pending(&self, message_id: MessageId, endpoint: Endpoint) -> Option<SlotId>;
    fn access(&mut self, id: SlotId) -> Result<Access<'_>, SlotError>;
    fn access_mut(&mut self, id: SlotId) -> Result<AccessMut<'_>, SlotError>;
}

impl<const SLOTS: usize, const BYTES: usize> DatagramBytes for DatagramPool<SLOTS, BYTES> {
    fn payload(&self, id: SlotId) -> Option<&[u8]> {
        DatagramPool::payload(self, id)
    }

    fn payload_mut(&mut self, id: SlotId) -> Option<&mut [u8]> {
        DatagramPool::payload_mut(self, id)
    }

    fn set_len(&mut self, id: SlotId, len: usize) -> Result<(), SlotError> {
        DatagramPool::set_len(self, id, len)
    }

    fn endpoint(&self, id: SlotId) -> Option<Endpoint> {
        DatagramPool::endpoint(self, id)
    }

    fn set_endpoint(&mut self, id: SlotId, endpoint: Endpoint) -> Result<(), SlotError> {
        DatagramPool::set_endpoint(self, id, endpoint)
    }

    fn pending_mid(&self, id: SlotId) -> Option<MessageId> {
        DatagramPool::pending_mid(self, id)
    }

    fn pending_rto(&self, id: SlotId) -> Option<PendingRto> {
        DatagramPool::pending_rto(self, id)
    }

    fn set_pending_mid(&mut self, id: SlotId, message_id: MessageId) -> Result<(), SlotError> {
        DatagramPool::set_pending_mid(self, id, message_id)
    }

    fn set_pending(
        &mut self,
        id: SlotId,
        message_id: MessageId,
        rto: PendingRto,
    ) -> Result<(), SlotError> {
        DatagramPool::set_pending(self, id, message_id, rto)
    }

    fn clear_pending_mid(&mut self, id: SlotId) -> Result<(), SlotError> {
        DatagramPool::clear_pending_mid(self, id)
    }

    fn lookup_pending(&self, message_id: MessageId, endpoint: Endpoint) -> Option<SlotId> {
        DatagramPool::lookup_pending(self, message_id, endpoint)
    }

    fn access(&mut self, id: SlotId) -> Result<Access<'_>, SlotError> {
        DatagramPool::access(self, id)
    }

    fn access_mut(&mut self, id: SlotId) -> Result<AccessMut<'_>, SlotError> {
        DatagramPool::access_mut(self, id)
    }
}

/// Pool of complete-body slots when block-wise is enabled (RX and TX are two pools).
///
/// Independent of datagram slot size. Capacity is in bytes and must be a
/// multiple of 1024 when constructed through the engine builder.
///
/// Each occupied slot may hold a [`BlockTransfer`] sidecar (classic Block or
/// incoming Q-Block).
pub struct BodyPool<const SLOTS: usize, const BYTES: usize> {
    bytes: [[u8; BYTES]; SLOTS],
    lens: [usize; SLOTS],
    transfers: [Option<BlockTransfer>; SLOTS],
    occ: Occupancy<SLOTS>,
}

impl<const SLOTS: usize, const BYTES: usize> BodyPool<SLOTS, BYTES> {
    /// Empty pool. Cursor starts at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [[0u8; BYTES]; SLOTS],
            lens: [0; SLOTS],
            transfers: [None; SLOTS],
            occ: Occupancy::new(),
        }
    }

    /// Complete-body bytes available in each slot.
    #[must_use]
    pub const fn slot_bytes(&self) -> usize {
        BYTES
    }

    /// Filled body bytes in an occupied slot.
    #[must_use]
    pub fn payload(&self, id: SlotId) -> Option<&[u8]> {
        if !self.occ.is_occupied(id) {
            return None;
        }
        let idx = id.index();
        Some(&self.bytes[idx][..self.lens[idx]])
    }

    /// Writable complete-body buffer (full capacity).
    pub fn payload_mut(&mut self, id: SlotId) -> Option<&mut [u8]> {
        if !self.occ.is_occupied(id) {
            return None;
        }
        Some(&mut self.bytes[id.index()])
    }

    /// Mark how many bytes in the slot are the current body.
    pub fn set_len(&mut self, id: SlotId, len: usize) -> Result<(), SlotError> {
        if !self.occ.is_occupied(id) {
            return Err(if id.index() < SLOTS {
                SlotError::NotOccupied
            } else {
                SlotError::InvalidSlot
            });
        }
        if len > BYTES {
            return Err(SlotError::LengthExceedsSlot);
        }
        self.lens[id.index()] = len;
        Ok(())
    }

    /// [`BlockTransfer`] sidecar for an occupied slot.
    #[must_use]
    pub fn transfer(&self, id: SlotId) -> Option<BlockTransfer> {
        if !self.occ.is_occupied(id) {
            return None;
        }
        self.transfers.get(id.index()).copied().flatten()
    }

    /// Replace the sidecar on an occupied slot.
    pub fn set_transfer(&mut self, id: SlotId, transfer: BlockTransfer) -> Result<(), SlotError> {
        if !self.occ.is_occupied(id) {
            return Err(if id.index() < SLOTS {
                SlotError::NotOccupied
            } else {
                SlotError::InvalidSlot
            });
        }
        self.transfers[id.index()] = Some(transfer);
        Ok(())
    }

    /// Read access to the filled body. Pins `id` until the guard is dropped.
    pub fn access(&mut self, id: SlotId) -> Result<Access<'_>, SlotError> {
        self.occ.try_pin(id)?;
        let idx = id.index();
        let pin = self.occ.pin_flag_mut(id).ok_or(SlotError::InvalidSlot)?;
        let bytes = &self.bytes[idx][..self.lens[idx]];
        Ok(Access::new(id, bytes, pin))
    }

    /// Write access to the full body buffer. Pins `id` until the guard is dropped.
    pub fn access_mut(&mut self, id: SlotId) -> Result<AccessMut<'_>, SlotError> {
        self.occ.try_pin(id)?;
        let idx = id.index();
        let pin = self.occ.pin_flag_mut(id).ok_or(SlotError::InvalidSlot)?;
        let bytes = &mut self.bytes[idx];
        let len = &mut self.lens[idx];
        Ok(AccessMut::new(id, bytes, len, pin))
    }

    /// Set the same pin bit [`Self::access`] holds. For tests of release-while-pinned.
    #[cfg(test)]
    pub(crate) fn pin(&mut self, id: SlotId) -> Result<(), SlotError> {
        self.occ.try_pin(id)
    }

    /// Clear a test pin set by [`Self::pin`].
    #[cfg(test)]
    pub(crate) fn unpin(&mut self, id: SlotId) -> Result<(), SlotError> {
        self.occ.unpin(id)
    }

    /// First occupied slot whose sidecar matches `key`, across roles.
    /// Use [`Self::lookup_role`] to distinguish request and response bodies.
    /// O(n) in slot count.
    #[must_use]
    pub fn lookup(&self, key: BlockKey) -> Option<SlotId> {
        (0..SLOTS).find_map(|i| {
            let id = SlotId::from_index(i);
            match self.transfer(id) {
                Some(t) if t.key() == key => Some(id),
                _ => None,
            }
        })
    }

    /// Occupied body with the exact key and transfer role.
    #[must_use]
    pub fn lookup_role(&self, key: BlockKey, role: BlockRole) -> Option<SlotId> {
        (0..SLOTS).find_map(|i| {
            let id = SlotId::from_index(i);
            self.transfer(id)
                .filter(|transfer| transfer.key() == key && transfer.role() == role)
                .map(|_| id)
        })
    }

    /// Occupied slot with the same present Request-Tag / ETag and endpoint.
    #[must_use]
    pub fn lookup_identity(&self, key: BlockKey, role: BlockRole) -> Option<SlotId> {
        if key.identity().is_absent() {
            return None;
        }
        (0..SLOTS).find_map(|i| {
            let id = SlotId::from_index(i);
            match self.transfer(id) {
                Some(t) if same_body_identity(t, key, role) => Some(id),
                _ => None,
            }
        })
    }

    /// Admit an incoming Block / Q-Block body: acquire a slot and write the first block.
    ///
    /// Classic Block starts at NUM 0. Q-Block may start with any NUM in window
    /// 0. Subsequent blocks use [`Self::write_incoming`]. `role` must be incoming.
    pub fn admit_incoming(
        &mut self,
        key: BlockKey,
        role: BlockRole,
        block: BlockValue,
        payload: &[u8],
        expected_len: Option<u32>,
    ) -> Result<SlotId, BlockTransferError> {
        let transfer = start_incoming(key, role, block, payload.len(), BYTES, expected_len)?;
        let id = self.acquire().ok_or(BlockTransferError::Saturated)?;
        let idx = id.index();
        let offset = if role.is_q_block() {
            block_offset(block.num(), usize::from(block.size()))?
        } else {
            0
        };
        let contiguous = role.is_q_block().then_some(transfer.filled());
        if let Err(e) = store_incoming(
            &mut self.bytes[idx],
            &mut self.lens[idx],
            offset,
            payload,
            contiguous,
        ) {
            let _ = self.release(id);
            return Err(e);
        }
        self.transfers[idx] = Some(transfer);
        Ok(id)
    }

    /// Write the next incoming range into `id`.
    ///
    /// Classic Block is in-order. Q-Block allows out-of-order NUMs in the
    /// current window. `role` must match the slot's transfer.
    pub fn write_incoming(
        &mut self,
        id: SlotId,
        role: BlockRole,
        block: BlockValue,
        payload: &[u8],
    ) -> Result<BlockProgress, BlockTransferError> {
        if !self.occ.is_occupied(id) {
            return Err(if id.index() < SLOTS {
                SlotError::NotOccupied.into()
            } else {
                SlotError::InvalidSlot.into()
            });
        }
        let idx = id.index();
        let offset = {
            let transfer = self.transfers[idx]
                .as_mut()
                .ok_or(BlockTransferError::NoTransfer)?;
            if transfer.role() != role {
                return Err(BlockTransferError::IdentityMismatch);
            }
            accept_incoming_role(transfer, block, payload.len(), BYTES)?
        };
        let contiguous = role.is_q_block().then_some(
            self.transfers[idx]
                .ok_or(BlockTransferError::NoTransfer)?
                .filled(),
        );
        store_incoming(
            &mut self.bytes[idx],
            &mut self.lens[idx],
            offset,
            payload,
            contiguous,
        )?;
        let transfer = self.transfers[idx].ok_or(BlockTransferError::NoTransfer)?;
        Ok(BlockProgress::new(
            id,
            transfer.filled(),
            transfer.is_complete(),
        ))
    }

    /// Admit or continue an incoming transfer identified by `key` and `role`.
    ///
    /// A present Request-Tag / ETag also matches an existing slot at the same
    /// endpoint when Tokens differ. Q-Block requires the same `expected_len`
    /// on every call; a change is refused without modifying the transfer.
    /// This range API permits `None` for caller-managed metadata; wire assembly
    /// requires the mandatory size indication on every Q-Block payload.
    pub fn apply_incoming(
        &mut self,
        key: BlockKey,
        role: BlockRole,
        block: BlockValue,
        payload: &[u8],
        expected_len: Option<u32>,
    ) -> Result<BlockProgress, BlockTransferError> {
        if let Some(id) = self
            .lookup_role(key, role)
            .or_else(|| self.lookup_identity(key, role))
        {
            let transfer = self.transfer(id).ok_or(BlockTransferError::NoTransfer)?;
            if role.is_q_block() && transfer.expected_len() != expected_len {
                return Err(BlockTransferError::LengthInconsistent);
            }
            return self.write_incoming(id, role, block, payload);
        }
        let id = self.admit_incoming(key, role, block, payload, expected_len)?;
        let transfer = self.transfer(id).ok_or(BlockTransferError::NoTransfer)?;
        Ok(BlockProgress::new(
            id,
            transfer.filled(),
            transfer.is_complete(),
        ))
    }

    /// Admit an outgoing Block / Q-Block body: acquire a slot and copy the complete body.
    ///
    /// `role` must be outgoing.
    pub fn start_outgoing(
        &mut self,
        key: BlockKey,
        role: BlockRole,
        body: &[u8],
        szx: u8,
    ) -> Result<SlotId, BlockTransferError> {
        let transfer = if role.is_q_block() {
            BlockTransfer::outgoing_q(key, role, body.len(), szx, BYTES)?
        } else {
            BlockTransfer::outgoing(key, role, body.len(), szx, BYTES)?
        };
        let id = self.acquire().ok_or(BlockTransferError::Saturated)?;
        let idx = id.index();
        if let Err(e) = write_range(&mut self.bytes[idx], &mut self.lens[idx], 0, body) {
            let _ = self.release(id);
            return Err(e);
        }
        self.transfers[idx] = Some(transfer);
        Ok(id)
    }

    /// Issue the next outgoing range from `id`.
    ///
    /// Classic Block is in-order. Q-Block issues the next unsent NUM in the
    /// current window. `role` must match the slot's transfer.
    pub fn next_outgoing(
        &mut self,
        id: SlotId,
        role: BlockRole,
    ) -> Result<OutgoingBlock, BlockTransferError> {
        if !self.occ.is_occupied(id) {
            return Err(if id.index() < SLOTS {
                SlotError::NotOccupied.into()
            } else {
                SlotError::InvalidSlot.into()
            });
        }
        let transfer = self.transfers[id.index()]
            .as_mut()
            .ok_or(BlockTransferError::NoTransfer)?;
        if transfer.role() != role {
            return Err(BlockTransferError::IdentityMismatch);
        }
        let (block, offset, len) = if role.is_q_block() {
            transfer.issue_q_outgoing()?
        } else {
            transfer.issue_outgoing()?
        };
        Ok(OutgoingBlock::new(
            id,
            block,
            offset,
            len,
            transfer.is_complete(),
        ))
    }

    /// Issue one BERT payload of at most `max_payload` bytes from `id`.
    pub fn next_bert_outgoing(
        &mut self,
        id: SlotId,
        role: BlockRole,
        max_payload: usize,
    ) -> Result<OutgoingBlock, BlockTransferError> {
        if !self.occ.is_occupied(id) {
            return Err(if id.index() < SLOTS {
                SlotError::NotOccupied.into()
            } else {
                SlotError::InvalidSlot.into()
            });
        }
        let transfer = self.transfers[id.index()]
            .as_mut()
            .ok_or(BlockTransferError::NoTransfer)?;
        if transfer.role() != role {
            return Err(BlockTransferError::IdentityMismatch);
        }
        let (block, offset, len) = transfer.issue_bert_outgoing(max_payload)?;
        Ok(OutgoingBlock::new(
            id,
            block,
            offset,
            len,
            transfer.is_complete(),
        ))
    }

    /// Advance an outgoing Q-Block window after a peer ACK of `num`.
    pub fn ack_outgoing(
        &mut self,
        id: SlotId,
        role: BlockRole,
        num: u32,
    ) -> Result<BlockProgress, BlockTransferError> {
        if !self.occ.is_occupied(id) {
            return Err(if id.index() < SLOTS {
                SlotError::NotOccupied.into()
            } else {
                SlotError::InvalidSlot.into()
            });
        }
        let transfer = self.transfers[id.index()]
            .as_mut()
            .ok_or(BlockTransferError::NoTransfer)?;
        if transfer.role() != role {
            return Err(BlockTransferError::IdentityMismatch);
        }
        let (filled, complete) = transfer.ack_q_window(num)?;
        Ok(BlockProgress::new(id, filled, complete))
    }

    fn reset(&mut self, id: SlotId) {
        let idx = id.index();
        self.lens[idx] = 0;
        self.transfers[idx] = None;
    }
}

impl<const SLOTS: usize, const BYTES: usize> Default for BodyPool<SLOTS, BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize, const BYTES: usize> super::block::BodyOps for BodyPool<SLOTS, BYTES> {
    fn payload(&self, id: SlotId) -> Option<&[u8]> {
        BodyPool::payload(self, id)
    }

    fn transfer(&self, id: SlotId) -> Option<BlockTransfer> {
        BodyPool::transfer(self, id)
    }

    fn set_transfer(&mut self, id: SlotId, transfer: BlockTransfer) -> Result<(), SlotError> {
        BodyPool::set_transfer(self, id, transfer)
    }

    fn lookup(&self, key: BlockKey) -> Option<SlotId> {
        BodyPool::lookup(self, key)
    }

    fn admit_incoming(
        &mut self,
        key: BlockKey,
        role: BlockRole,
        block: BlockValue,
        payload: &[u8],
        expected_len: Option<u32>,
    ) -> Result<SlotId, BlockTransferError> {
        BodyPool::admit_incoming(self, key, role, block, payload, expected_len)
    }

    fn write_incoming(
        &mut self,
        id: SlotId,
        role: BlockRole,
        block: BlockValue,
        payload: &[u8],
    ) -> Result<BlockProgress, BlockTransferError> {
        BodyPool::write_incoming(self, id, role, block, payload)
    }

    fn apply_incoming(
        &mut self,
        key: BlockKey,
        role: BlockRole,
        block: BlockValue,
        payload: &[u8],
        expected_len: Option<u32>,
    ) -> Result<BlockProgress, BlockTransferError> {
        BodyPool::apply_incoming(self, key, role, block, payload, expected_len)
    }

    fn start_outgoing(
        &mut self,
        key: BlockKey,
        role: BlockRole,
        body: &[u8],
        szx: u8,
    ) -> Result<SlotId, BlockTransferError> {
        BodyPool::start_outgoing(self, key, role, body, szx)
    }

    fn next_outgoing(
        &mut self,
        id: SlotId,
        role: BlockRole,
    ) -> Result<OutgoingBlock, BlockTransferError> {
        BodyPool::next_outgoing(self, id, role)
    }

    fn next_bert_outgoing(
        &mut self,
        id: SlotId,
        role: BlockRole,
        max_payload: usize,
    ) -> Result<OutgoingBlock, BlockTransferError> {
        BodyPool::next_bert_outgoing(self, id, role, max_payload)
    }

    fn ack_outgoing(
        &mut self,
        id: SlotId,
        role: BlockRole,
        num: u32,
    ) -> Result<BlockProgress, BlockTransferError> {
        BodyPool::ack_outgoing(self, id, role, num)
    }

    fn access(&mut self, id: SlotId) -> Result<Access<'_>, SlotError> {
        BodyPool::access(self, id)
    }

    fn access_mut(&mut self, id: SlotId) -> Result<AccessMut<'_>, SlotError> {
        BodyPool::access_mut(self, id)
    }
}

impl<const SLOTS: usize, const BYTES: usize> SlotPool for BodyPool<SLOTS, BYTES> {
    fn acquire(&mut self) -> Option<SlotId> {
        let id = self.occ.acquire()?;
        self.reset(id);
        Some(id)
    }

    fn release(&mut self, id: SlotId) -> Result<(), SlotError> {
        self.occ.release(id)?;
        self.reset(id);
        Ok(())
    }

    fn advance(&mut self, steps: usize) {
        self.occ.advance(steps);
    }

    fn slot_count(&self) -> usize {
        self.occ.slot_count()
    }

    fn occupied_count(&self) -> usize {
        self.occ.occupied_count()
    }

    fn is_occupied(&self, id: SlotId) -> bool {
        self.occ.is_occupied(id)
    }

    fn is_pinned(&self, id: SlotId) -> bool {
        self.occ.is_pinned(id)
    }

    fn cursor(&self) -> usize {
        self.occ.cursor()
    }
}
