//! Pending CON sidecar on outgoing datagram slots.
//!
//! Confirm matching is Message ID plus remote [`Endpoint`]. Retransmit
//! bookkeeping ([`PendingRto`]) lives on the same sidecar. This is not the
//! Dedup Table. See `knowledge/rfcs/rfc7252.txt` §4.2 / §4.4 / §4.8.

use super::endpoint::Endpoint;
use super::slot::SlotId;
use crate::message::{MessageId, Transmission};

/// Occupied TX slot waiting for an empty ACK or RST.
///
/// Stored as sidecar on the outgoing datagram slot. Capacity is the TX
/// Datagram Pool. This is not a seventh core memory area.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingCon {
    message_id: MessageId,
    endpoint: Endpoint,
    tx_slot: SlotId,
    rto: PendingRto,
}

impl PendingCon {
    /// Pending CON on `tx_slot` for `message_id` sent to `endpoint`.
    ///
    /// RTO is [`PendingRto::new`]`(0, 0)` (ACK_TIMEOUT at time zero). Use
    /// [`Self::with_rto`] after [`PendingCons::record_pending_con`] with a
    /// real clock.
    #[must_use]
    pub const fn new(message_id: MessageId, endpoint: Endpoint, tx_slot: SlotId) -> Self {
        Self {
            message_id,
            endpoint,
            tx_slot,
            rto: PendingRto::new(0, 0),
        }
    }

    /// Replace retransmit bookkeeping.
    #[must_use]
    pub const fn with_rto(self, rto: PendingRto) -> Self {
        Self {
            message_id: self.message_id,
            endpoint: self.endpoint,
            tx_slot: self.tx_slot,
            rto,
        }
    }

    /// Message ID of the outgoing CON.
    #[must_use]
    pub const fn message_id(self) -> MessageId {
        self.message_id
    }

    /// Remote endpoint the CON was sent to.
    #[must_use]
    pub const fn endpoint(self) -> Endpoint {
        self.endpoint
    }

    /// TX datagram slot that holds the outgoing bytes.
    #[must_use]
    pub const fn tx_slot(self) -> SlotId {
        self.tx_slot
    }

    /// Retransmit / RTO bookkeeping for this pending CON.
    #[must_use]
    pub const fn rto(self) -> PendingRto {
        self.rto
    }
}

/// Retransmit counter and timeout for one pending CON.
///
/// The core does not read an OS clock or draw randomness. [`Self::new`]
/// takes caller `now_ms` and `jitter_ms`; see
/// [`Transmission::initial_timeout_ms`]. See `knowledge/rfcs/rfc7252.txt`
/// §4.2.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingRto {
    attempts: u8,
    next_timeout_ms: u64,
    timeout_ms: u32,
}

impl PendingRto {
    /// Initial RTO: retransmission counter 0, timeout from
    /// [`Transmission::initial_timeout_ms`], due at `now_ms + timeout`.
    #[must_use]
    pub const fn new(now_ms: u64, jitter_ms: u32) -> Self {
        let timeout_ms = Transmission::initial_timeout_ms(jitter_ms);
        Self {
            attempts: 0,
            timeout_ms,
            next_timeout_ms: now_ms.saturating_add(timeout_ms as u64),
        }
    }

    /// Retransmission counter (0 after the first send).
    #[must_use]
    pub const fn attempts(self) -> u8 {
        self.attempts
    }

    /// Absolute millisecond time when this timeout fires (`now_ms` domain).
    #[must_use]
    pub const fn next_timeout_ms(self) -> u64 {
        self.next_timeout_ms
    }

    /// Current timeout duration in milliseconds.
    #[must_use]
    pub const fn timeout_ms(self) -> u32 {
        self.timeout_ms
    }

    /// Whether `now_ms` is at or past [`Self::next_timeout_ms`].
    #[must_use]
    pub const fn is_due(self, now_ms: u64) -> bool {
        now_ms >= self.next_timeout_ms
    }

    /// After a due timeout: doubled timeout and incremented counter, or
    /// `None` when [`Transmission::MAX_RETRANSMIT`] is already reached.
    ///
    /// Next due is `now_ms` plus the doubled timeout (late polls shift the
    /// schedule; the core does not burst catch-up).
    #[must_use]
    pub const fn next_attempt(self, now_ms: u64) -> Option<Self> {
        if self.attempts >= Transmission::MAX_RETRANSMIT {
            return None;
        }
        let timeout_ms = self.timeout_ms.saturating_mul(2);
        Some(Self {
            attempts: self.attempts.saturating_add(1),
            timeout_ms,
            next_timeout_ms: now_ms.saturating_add(timeout_ms as u64),
        })
    }
}

/// One due retransmit or a give-up after [`Transmission::MAX_RETRANSMIT`].
///
/// [`Self::Due`] keeps the TX slot pending (caller resends the bytes already
/// in the slot). [`Self::GiveUp`] clears pending and RTO; the slot stays
/// occupied so the caller can release it. See
/// `knowledge/rfcs/rfc7252.txt` §4.2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Retransmit {
    /// Timeout expired and attempts remain.
    Due(PendingCon),
    /// Retransmission counter reached `MAX_RETRANSMIT` on this timeout.
    GiveUp(PendingCon),
}

/// Typed pending-CON access on the outgoing datagram pool.
///
/// Insert, lookup, take, and poll scan the configured TX slot count (O(n) in
/// capacity). Capacity is the TX Datagram Pool: a slot must already be
/// occupied. [`super::Memory`] and [`super::AllocMemory`] implement this.
pub trait PendingCons {
    /// Mark occupied TX `id` as pending and start RTO.
    ///
    /// `now_ms` is the caller clock (no OS time in the core). `jitter_ms`
    /// is applied by [`Transmission::initial_timeout_ms`]. `None` when `id`
    /// is free or out of range, or when outstanding pending CONs to
    /// `endpoint` already equal [`Transmission::NSTART`]. Idempotent when
    /// the same MID and endpoint are already recorded on `id` (RTO is not
    /// reset).
    fn record_pending_con(
        &mut self,
        id: SlotId,
        endpoint: Endpoint,
        message_id: MessageId,
        now_ms: u64,
        jitter_ms: u32,
    ) -> Option<SlotId>;

    /// Occupied TX slot pending for `message_id` and `endpoint`, if any.
    fn lookup_pending_con(&self, message_id: MessageId, endpoint: Endpoint) -> Option<SlotId>;

    /// Clear pending and RTO for the matching TX slot. The slot stays occupied.
    fn take_pending_con(&mut self, message_id: MessageId, endpoint: Endpoint) -> Option<SlotId>;

    /// Pending CON view at TX `id`, if that slot is marked pending.
    fn pending_con(&self, id: SlotId) -> Option<PendingCon>;

    /// Next pending CON whose timeout is due at `now_ms`, if any.
    ///
    /// Scans occupied pending TX slots in index order (O(n)). On
    /// [`Retransmit::Due`], schedules the next timeout (exponential
    /// backoff). On [`Retransmit::GiveUp`], clears pending. Does not send.
    fn poll_retransmit(&mut self, now_ms: u64) -> Option<Retransmit>;
}

/// MID + RTO stored on one TX slot. Endpoint stays on the existing sidecar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PendingMark {
    pub message_id: MessageId,
    pub rto: PendingRto,
}

impl PendingMark {
    pub(crate) const fn new(message_id: MessageId, rto: PendingRto) -> Self {
        Self { message_id, rto }
    }
}

pub(crate) struct DueSlot {
    pub id: SlotId,
    pub event: Retransmit,
    pub mark: Option<PendingMark>,
}

pub(crate) fn next_due_slot(
    slot_count: usize,
    now_ms: u64,
    mut pending_at: impl FnMut(SlotId) -> Option<PendingCon>,
) -> Option<DueSlot> {
    for i in 0..slot_count {
        let id = SlotId::from_index(i);
        let Some(pending) = pending_at(id) else {
            continue;
        };
        if !pending.rto().is_due(now_ms) {
            continue;
        }
        return Some(match pending.rto().next_attempt(now_ms) {
            Some(rto) => DueSlot {
                id,
                event: Retransmit::Due(pending.with_rto(rto)),
                mark: Some(PendingMark::new(pending.message_id(), rto)),
            },
            None => DueSlot {
                id,
                event: Retransmit::GiveUp(pending),
                mark: None,
            },
        });
    }
    None
}

pub(crate) fn outstanding_pending(
    slot_count: usize,
    endpoint: Endpoint,
    mut pending_at: impl FnMut(SlotId) -> Option<PendingCon>,
) -> usize {
    (0..slot_count)
        .filter(|&i| pending_at(SlotId::from_index(i)).is_some_and(|p| p.endpoint() == endpoint))
        .count()
}

/// Whether a new pending CON may be recorded on `id`.
///
/// `Some(false)` is an idempotent hit (keep existing RTO). `Some(true)`
/// admits a new or replacement mark. `None` is an NSTART reject.
pub(crate) fn record_admission(
    existing: Option<PendingCon>,
    message_id: MessageId,
    endpoint: Endpoint,
    outstanding: usize,
) -> Option<bool> {
    if let Some(pending) = existing {
        if pending.message_id() == message_id && pending.endpoint() == endpoint {
            return Some(false);
        }
        if pending.endpoint() == endpoint {
            return Some(true);
        }
    }
    if outstanding >= usize::from(Transmission::NSTART) {
        return None;
    }
    Some(true)
}
