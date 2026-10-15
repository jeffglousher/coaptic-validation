//! [`Engine`]: acquire / release / rotate against [`Storage`].

use super::Access;
use super::AccessMut;
use super::BodySlots;
use super::Capacities;
use super::DatagramSlots;
use super::DedupEntry;
use super::DedupKey;
use super::DedupSlots;
use super::Endpoint;
use super::ExchangeEntry;
use super::ExchangeKey;
use super::Exchanges;
use super::Metrics;
use super::ObserveExpiry;
use super::ObserveInterest;
use super::ObserveKey;
use super::ObserveLifetime;
use super::ObserveResource;
use super::ObserveSlots;
use super::PendingCon;
use super::PendingCons;
use super::Retransmit;
use super::SlotError;
use super::SlotId;
use super::Storage;
use super::block::{
    BlockKey, BlockProgress, BlockRole, BlockTransfer, BodyTag, OutgoingBlock, QBlockRecover,
    RequestBinding, same_body_identity,
};
use super::pending::outstanding_pending;
use crate::error::{BlockTransferError, SlotMessageError, ValueError};
use crate::message::{
    BlockValue, Code, Echo, EchoFreshness, EncodedUint, Message, MessageId, Opt, OptionsBuilder,
    ParsedMessage, Token, Type, encode_uint,
};

/// Protocol engine over bounded [`Storage`].
///
/// This is the **advanced path**. [`crate::App`] already runs
/// [`Self::progress`], routing, Observe, and Block/Q-Block inside
/// [`crate::App::poll`]. Reach here via [`crate::App::engine_mut`] only
/// when you need explicit slots, [`Access`] / [`AccessMut`], or policy
/// App does not apply. Engine BERT (SZX 7) codecs exist; App does not
/// expose them (future / backlog).
///
/// One [`Self::progress`] pass: CON retransmit, one unpinned RX step, one
/// Observe notify (skips an endpoint at notification NSTART), at most one
/// Observe expiry, at most one due Q-Block recover. The caller owns
/// clock, socket ([`super::DatagramIo`]), and RST / remaining 4.xx
/// policy. [`Self::echo_freshness`] classifies timestamp age only; App uses
/// caller-owned [`crate::app::EchoPolicy`] verification. This type does not invent 4.02 / 4.08 / 2.31 / RST policy.
///
/// Wrapping [`Metrics`] sit on this type. Copy with [`Self::metrics`];
/// [`crate::App::metrics`] is the same snapshot from the happy path.
#[derive(Debug)]
pub struct Engine<S: Storage> {
    storage: S,
    metrics: Metrics,
}

impl<S: Storage> Engine<S> {
    pub(crate) fn from_storage(storage: S) -> Self {
        Self {
            storage,
            metrics: Metrics::ZERO,
        }
    }

    /// Copy of wrapping reactor counters.
    ///
    /// Always-on `u32` fields (64 bytes). A `std` dogfood bin can print
    /// after a run (`format!("{}", engine.metrics())` or `"{snap:?}"`).
    /// [`crate::App::metrics`] forwards here. Reset with
    /// [`Self::reset_metrics`].
    #[must_use]
    pub const fn metrics(&self) -> Metrics {
        self.metrics
    }

    /// Zero all reactor counters.
    pub fn reset_metrics(&mut self) {
        self.metrics = Metrics::ZERO;
    }

    #[inline]
    pub(crate) fn metrics_mut(&mut self) -> &mut Metrics {
        &mut self.metrics
    }

    /// Borrow the backing store.
    #[must_use]
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Borrow the backing store mutably.
    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    /// Configured sizes of the backing store.
    #[must_use]
    pub fn capacities(&self) -> Capacities {
        self.storage.capacities()
    }

    /// Echo option on `parsed`. `Ok(None)` if absent.
    pub fn echo(parsed: &ParsedMessage<'_>) -> Result<Option<Echo>, ValueError> {
        Echo::from_message(parsed)
    }

    /// Time-based freshness of a mint-shaped Echo on `parsed`.
    ///
    /// This does not verify issuance, a MAC, or endpoint/security binding.
    /// Event-based freshness is equality against a caller-owned [`Echo`].
    /// Does not invent 4.01 / RST policy. See `knowledge/rfcs/rfc9175.txt`.
    #[must_use]
    pub fn echo_freshness(parsed: &ParsedMessage<'_>, now_ms: u64, fresh_ms: u64) -> EchoFreshness {
        EchoFreshness::of(parsed, now_ms, fresh_ms)
    }

    /// Whether this engine’s Storage includes body pools.
    #[must_use]
    pub fn has_body_pools(&self) -> bool {
        self.storage.capacities().has_body_pools()
    }

    /// Acquire one RX datagram slot, or `None` if the pool is saturated.
    pub fn acquire_rx(&mut self) -> Option<SlotId> {
        match self.storage.rx_datagram().acquire() {
            Some(id) => Some(id),
            None => {
                Metrics::inc(&mut self.metrics.saturated);
                None
            }
        }
    }

    /// Release an RX datagram slot.
    pub fn release_rx(&mut self, id: SlotId) -> Result<(), SlotError> {
        self.storage.rx_datagram().release(id)
    }

    /// Advance the RX datagram rotating cursor.
    pub fn rotate_rx(&mut self) {
        self.advance_rx(1);
    }

    /// Jump the RX datagram rotating cursor by `steps` slots.
    pub fn advance_rx(&mut self, steps: usize) {
        self.storage.rx_datagram().advance(steps);
    }

    /// Acquire one TX datagram slot, or `None` if the pool is saturated.
    pub fn acquire_tx(&mut self) -> Option<SlotId> {
        match self.storage.tx_datagram().acquire() {
            Some(id) => Some(id),
            None => {
                Metrics::inc(&mut self.metrics.saturated);
                None
            }
        }
    }

    /// Release a TX datagram slot.
    pub fn release_tx(&mut self, id: SlotId) -> Result<(), SlotError> {
        self.storage.tx_datagram().release(id)
    }

    /// Advance the TX datagram rotating cursor.
    pub fn rotate_tx(&mut self) {
        self.storage.tx_datagram().rotate();
    }

    /// Acquire one RX body slot. `None` if body pools are absent or saturated.
    pub fn acquire_rx_body(&mut self) -> Option<SlotId> {
        let id = self.storage.rx_body()?.acquire();
        if id.is_none() {
            Metrics::inc(&mut self.metrics.saturated);
        }
        id
    }

    /// Release an RX body slot.
    pub fn release_rx_body(&mut self, id: SlotId) -> Result<(), SlotError> {
        self.storage
            .rx_body()
            .ok_or(SlotError::InvalidSlot)?
            .release(id)
    }

    /// Advance the RX body rotating cursor. No-op when body pools are absent.
    pub fn rotate_rx_body(&mut self) {
        self.advance_rx_body(1);
    }

    /// Jump the RX body rotating cursor by `steps` slots. No-op when body pools are absent.
    pub fn advance_rx_body(&mut self, steps: usize) {
        if let Some(pool) = self.storage.rx_body() {
            pool.advance(steps);
        }
    }

    /// Acquire one TX body slot. `None` if body pools are absent or saturated.
    pub fn acquire_tx_body(&mut self) -> Option<SlotId> {
        let id = self.storage.tx_body()?.acquire();
        if id.is_none() {
            Metrics::inc(&mut self.metrics.saturated);
        }
        id
    }

    /// Release a TX body slot.
    pub fn release_tx_body(&mut self, id: SlotId) -> Result<(), SlotError> {
        self.storage
            .tx_body()
            .ok_or(SlotError::InvalidSlot)?
            .release(id)
    }

    /// Advance the TX body rotating cursor. No-op when body pools are absent.
    pub fn rotate_tx_body(&mut self) {
        if let Some(pool) = self.storage.tx_body() {
            pool.rotate();
        }
    }

    /// Jump the Observe table rotating cursor by `steps` slots.
    pub(crate) fn advance_observe(&mut self, steps: usize) {
        self.storage.observe().advance(steps);
    }

    /// Occupied RX datagram slots.
    pub fn rx_occupied(&mut self) -> usize {
        self.storage.rx_datagram().occupied_count()
    }

    /// Occupied TX datagram slots.
    pub fn tx_occupied(&mut self) -> usize {
        self.storage.tx_datagram().occupied_count()
    }

    /// RX datagram cursor (next acquire search start).
    pub fn rx_cursor(&mut self) -> usize {
        self.storage.rx_datagram().cursor()
    }

    /// TX datagram cursor (next acquire search start).
    pub fn tx_cursor(&mut self) -> usize {
        self.storage.tx_datagram().cursor()
    }

    /// RX body cursor, if body pools exist.
    pub fn rx_body_cursor(&mut self) -> Option<usize> {
        self.storage.rx_body().map(|pool| pool.cursor())
    }

    /// Whether RX datagram `id` is pinned by a live [`Access`].
    #[must_use]
    pub fn rx_is_pinned(&mut self, id: SlotId) -> bool {
        self.storage.rx_datagram().is_pinned(id)
    }

    /// Whether TX datagram `id` is pinned by a live [`Access`] or [`AccessMut`].
    #[must_use]
    pub fn tx_is_pinned(&mut self, id: SlotId) -> bool {
        self.storage.tx_datagram().is_pinned(id)
    }

    /// Whether RX body `id` is pinned. `false` when body pools are absent.
    #[must_use]
    pub fn rx_body_is_pinned(&mut self, id: SlotId) -> bool {
        self.storage
            .rx_body()
            .map(|pool| pool.is_pinned(id))
            .unwrap_or(false)
    }

    /// Whether TX body `id` is pinned. `false` when body pools are absent.
    #[must_use]
    pub fn tx_body_is_pinned(&mut self, id: SlotId) -> bool {
        self.storage
            .tx_body()
            .map(|pool| pool.is_pinned(id))
            .unwrap_or(false)
    }
}

impl<S: Storage + DatagramSlots> Engine<S> {
    /// Decode the occupied RX datagram with [`crate::message::decode`].
    ///
    /// Does not run [`ParsedMessage::check_rfc7252_options`] or
    /// [`ParsedMessage::check_rfc7252_formats`].
    pub fn decode_rx(&self, id: SlotId) -> Result<ParsedMessage<'_>, SlotMessageError> {
        decode_occupied(self.storage.rx_payload(id))
    }

    /// Decode the occupied TX datagram with [`crate::message::decode`].
    pub fn decode_tx(&self, id: SlotId) -> Result<ParsedMessage<'_>, SlotMessageError> {
        decode_occupied(self.storage.tx_payload(id))
    }

    /// Encode `msg` into an acquired RX slot and [`DatagramSlots::set_rx_len`].
    pub fn encode_rx(&mut self, id: SlotId, msg: &Message<'_>) -> Result<usize, SlotMessageError> {
        let n = encode_occupied(self.storage.rx_payload_mut(id), msg)?;
        self.storage.set_rx_len(id, n)?;
        Ok(n)
    }

    /// Encode `msg` into an acquired TX slot and [`DatagramSlots::set_tx_len`].
    pub fn encode_tx(&mut self, id: SlotId, msg: &Message<'_>) -> Result<usize, SlotMessageError> {
        let n = encode_occupied(self.storage.tx_payload_mut(id), msg)?;
        self.storage.set_tx_len(id, n)?;
        Ok(n)
    }

    /// Copy `bytes` into an acquired RX slot, record length, and set sidecar [`Endpoint`].
    pub fn write_rx(
        &mut self,
        id: SlotId,
        bytes: &[u8],
        endpoint: Endpoint,
    ) -> Result<usize, SlotError> {
        copy_into_slot(self.storage.rx_payload_mut(id), bytes)?;
        self.storage.set_rx_len(id, bytes.len())?;
        self.storage.set_rx_endpoint(id, endpoint)?;
        Ok(bytes.len())
    }

    /// Copy `bytes` into an acquired TX slot, record length, and set sidecar [`Endpoint`].
    pub fn write_tx(
        &mut self,
        id: SlotId,
        bytes: &[u8],
        endpoint: Endpoint,
    ) -> Result<usize, SlotError> {
        copy_into_slot(self.storage.tx_payload_mut(id), bytes)?;
        self.storage.set_tx_len(id, bytes.len())?;
        self.storage.set_tx_endpoint(id, endpoint)?;
        Ok(bytes.len())
    }

    /// Sidecar [`Endpoint`] for an occupied RX slot.
    #[must_use]
    pub fn rx_endpoint(&self, id: SlotId) -> Option<Endpoint> {
        self.storage.rx_endpoint(id)
    }

    /// Sidecar [`Endpoint`] for an occupied TX slot.
    #[must_use]
    pub fn tx_endpoint(&self, id: SlotId) -> Option<Endpoint> {
        self.storage.tx_endpoint(id)
    }

    /// Set RX sidecar [`Endpoint`]. Not written into the byte buffer.
    pub fn set_rx_endpoint(&mut self, id: SlotId, endpoint: Endpoint) -> Result<(), SlotError> {
        self.storage.set_rx_endpoint(id, endpoint)
    }

    /// Set TX sidecar [`Endpoint`]. Not written into the byte buffer.
    pub fn set_tx_endpoint(&mut self, id: SlotId, endpoint: Endpoint) -> Result<(), SlotError> {
        self.storage.set_tx_endpoint(id, endpoint)
    }

    /// Read access to an occupied RX datagram. Pins `id` until dropped.
    ///
    /// Release of `id` returns [`SlotError::Pinned`] while the guard is
    /// live. The [`crate::App`] happy path does not need this; see
    /// [`Access`].
    pub fn access_rx(&mut self, id: SlotId) -> Result<Access<'_>, SlotError> {
        self.storage.access_rx(id)
    }

    /// Read access to an occupied TX datagram. Pins `id` until dropped.
    ///
    /// See [`Access`]. The [`crate::App`] happy path does not need this.
    pub fn access_tx(&mut self, id: SlotId) -> Result<Access<'_>, SlotError> {
        self.storage.access_tx(id)
    }

    /// Write access to an occupied TX datagram buffer. Pins `id` until dropped.
    ///
    /// See [`AccessMut`]. The [`crate::App`] happy path does not need this.
    pub fn access_tx_mut(&mut self, id: SlotId) -> Result<AccessMut<'_>, SlotError> {
        self.storage.access_tx_mut(id)
    }
}

impl<S: Storage + DedupSlots> Engine<S> {
    /// Insert a Dedup Table row, or return the existing slot if the key is present.
    ///
    /// `None` when the table is full and the key is not already stored. Scans
    /// the configured capacity (O(n)).
    pub fn insert_dedup(&mut self, entry: DedupEntry) -> Option<SlotId> {
        self.storage.insert_dedup(entry)
    }

    /// Occupied Dedup Table slot matching `key`, if any. O(n) in capacity.
    #[must_use]
    pub fn lookup_dedup(&self, key: DedupKey) -> Option<SlotId> {
        self.storage.lookup_dedup(key)
    }

    /// Release the Dedup Table slot matching `key`, if occupied. O(n) in capacity.
    pub fn remove_dedup(&mut self, key: DedupKey) -> bool {
        self.storage.remove_dedup(key)
    }

    /// Occupied Dedup Table payload at `id`.
    #[must_use]
    pub fn dedup_entry(&self, id: SlotId) -> Option<DedupEntry> {
        self.storage.dedup_entry(id)
    }
}

impl<S: Storage + PendingCons> Engine<S> {
    /// Record occupied TX `id` as a pending CON (`message_id` + `endpoint`).
    ///
    /// Initializes RTO from [`crate::message::Transmission`] using caller `now_ms`
    /// and `jitter_ms` (no OS clock; `0` jitter is the ACK_TIMEOUT floor).
    /// Sets the TX sidecar endpoint. `None` when the slot is free or out of
    /// range, or when outstanding pending CONs to `endpoint` already equal
    /// [`crate::message::Transmission::NSTART`]. Idempotent for the same MID and
    /// endpoint on `id` (RTO is not reset). Does not use the Dedup Table.
    pub fn record_pending_con(
        &mut self,
        id: SlotId,
        endpoint: Endpoint,
        message_id: MessageId,
        now_ms: u64,
        jitter_ms: u32,
    ) -> Option<SlotId> {
        let recorded = self
            .storage
            .record_pending_con(id, endpoint, message_id, now_ms, jitter_ms);
        if recorded.is_none() {
            let n = self.storage.capacities().tx_datagram_slots;
            let outstanding = outstanding_pending(n, endpoint, |sid| self.storage.pending_con(sid));
            if outstanding >= usize::from(crate::message::Transmission::NSTART) {
                Metrics::inc(&mut self.metrics.nstart_reject);
            }
        }
        recorded
    }

    /// Occupied TX slot pending for `message_id` and `endpoint`, if any. O(n).
    #[must_use]
    pub fn lookup_pending_con(&self, message_id: MessageId, endpoint: Endpoint) -> Option<SlotId> {
        self.storage.lookup_pending_con(message_id, endpoint)
    }

    /// Clear pending and RTO for the matching TX slot. The slot stays occupied.
    ///
    /// The caller releases the returned slot. `None` on miss.
    pub fn take_pending_con(
        &mut self,
        message_id: MessageId,
        endpoint: Endpoint,
    ) -> Option<SlotId> {
        self.storage.take_pending_con(message_id, endpoint)
    }

    /// Pending CON view at TX `id`, if that slot is marked pending.
    #[must_use]
    pub fn pending_con(&self, id: SlotId) -> Option<PendingCon> {
        self.storage.pending_con(id)
    }

    /// If `parsed` is an empty ACK or RST, take the matching pending CON.
    ///
    /// Match is Message ID plus `endpoint`. Clears pending and RTO. Returns
    /// the TX slot id; the caller releases it. `None` when the datagram is
    /// not an empty ACK/RST or no pending CON matches. Does not consult the
    /// Dedup Table.
    pub fn match_empty_ack_rst(
        &mut self,
        parsed: &ParsedMessage<'_>,
        endpoint: Endpoint,
    ) -> Option<SlotId> {
        if !parsed.is_empty_ack_or_rst() {
            return None;
        }
        if parsed.is_empty_ack() {
            Metrics::inc(&mut self.metrics.empty_ack);
        } else {
            Metrics::inc(&mut self.metrics.empty_rst);
        }
        self.storage.take_pending_con(parsed.message_id(), endpoint)
    }

    /// Decode occupied RX `id` and [`Self::match_empty_ack_rst`] using its sidecar endpoint.
    pub fn match_empty_ack_rst_rx(&mut self, id: SlotId) -> Result<Option<SlotId>, SlotMessageError>
    where
        S: DatagramSlots,
    {
        let endpoint = self.storage.rx_endpoint(id).ok_or(SlotError::NotOccupied)?;
        let (message_id, is_empty, is_ack) = {
            let parsed = decode_occupied(self.storage.rx_payload(id))?;
            (
                parsed.message_id(),
                parsed.is_empty_ack_or_rst(),
                parsed.is_empty_ack(),
            )
        };
        if !is_empty {
            return Ok(None);
        }
        if is_ack {
            Metrics::inc(&mut self.metrics.empty_ack);
        } else {
            Metrics::inc(&mut self.metrics.empty_rst);
        }
        Ok(self.storage.take_pending_con(message_id, endpoint))
    }

    /// Next pending CON whose timeout is due at caller `now_ms`, if any.
    ///
    /// Scans pending TX slots in index order (O(n)). Skips the scan when
    /// the TX pool is empty. On [`Retransmit::Due`], doubles the timeout
    /// and increments attempts. On [`Retransmit::GiveUp`], clears pending.
    /// Does not send — [`crate::App::poll`] sends Due and releases GiveUp.
    /// See `knowledge/rfcs/rfc7252.txt` §4.2.
    pub fn poll_retransmit(&mut self, now_ms: u64) -> Option<Retransmit> {
        if self.storage.tx_datagram().is_empty() {
            return None;
        }
        let event = self.storage.poll_retransmit(now_ms);
        match event {
            Some(Retransmit::Due(_)) => Metrics::inc(&mut self.metrics.con_retransmit),
            Some(Retransmit::GiveUp(_)) => Metrics::inc(&mut self.metrics.give_up),
            None => {}
        }
        event
    }
}

impl<S: Storage + Exchanges> Engine<S> {
    /// Insert an outstanding request, or return the existing slot if the key is present.
    ///
    /// `None` when the table is full and the key is not already stored. Scans
    /// the TX-derived capacity (O(n)). Does not use Dedup or pending CON.
    pub fn insert_exchange(&mut self, entry: ExchangeEntry) -> Option<SlotId> {
        self.storage.insert_exchange(entry)
    }

    /// Occupied exchange slot matching `key`, if any. O(n) in capacity.
    #[must_use]
    pub fn lookup_exchange(&self, key: ExchangeKey) -> Option<SlotId> {
        self.storage.lookup_exchange(key)
    }

    /// Remove and return the outstanding request matching `key`, if any.
    ///
    /// The caller releases [`ExchangeEntry::tx_slot`] when it still holds that
    /// TX datagram. `None` on miss.
    pub fn take_exchange(&mut self, key: ExchangeKey) -> Option<ExchangeEntry> {
        self.storage.take_exchange(key)
    }

    /// Occupied exchange payload at `id`.
    #[must_use]
    pub fn exchange_entry(&self, id: SlotId) -> Option<ExchangeEntry> {
        self.storage.exchange_entry(id)
    }

    /// Record an outstanding CON/NON request from occupied TX `id`.
    ///
    /// Sets the TX sidecar endpoint. Captures a well-formed Echo on the
    /// request ([`ExchangeEntry::echo`]). `Ok(None)` when the datagram is
    /// not a CON/NON request, or the table is full. Idempotent for the same
    /// Token and endpoint. Does not mark pending CON and does not use Dedup.
    pub fn record_request(
        &mut self,
        id: SlotId,
        endpoint: Endpoint,
    ) -> Result<Option<ExchangeEntry>, SlotMessageError>
    where
        S: DatagramSlots,
    {
        let (token, message_id, is_request, echo) = {
            let parsed = decode_occupied(self.storage.tx_payload(id))?;
            (
                parsed.token(),
                parsed.message_id(),
                super::exchange::is_con_or_non_request(&parsed),
                Echo::from_option(parsed.echo()),
            )
        };
        if !is_request {
            return Ok(None);
        }
        self.storage.set_tx_endpoint(id, endpoint)?;
        let mut entry = ExchangeEntry::new(token, endpoint, message_id, id);
        if let Some(echo) = echo {
            entry = entry.with_echo(echo);
        }
        let table_id = self.storage.insert_exchange(entry);
        Ok(table_id.and_then(|tid| self.storage.exchange_entry(tid)))
    }

    /// If `parsed` is a response for `endpoint`, take the matching exchange.
    ///
    /// Match is Token plus `endpoint` ([`ExchangeKey`]). A piggybacked ACK
    /// also requires the request Message ID. Empty ACK/RST are not responses.
    /// Returns the entry; a well-formed response Echo is
    /// [`ExchangeEntry::challenge`]. The caller releases the TX slot.
    /// `None` on miss. Does not consult Dedup or pending CON.
    pub fn match_response(
        &mut self,
        parsed: &ParsedMessage<'_>,
        endpoint: Endpoint,
    ) -> Option<ExchangeEntry> {
        self.take_matching_response(
            parsed.token(),
            parsed.ty(),
            parsed.code(),
            parsed.message_id(),
            endpoint,
            Echo::from_option(parsed.echo()),
        )
    }

    /// Decode occupied RX `id` and [`Self::match_response`] using its sidecar endpoint.
    pub fn match_response_rx(
        &mut self,
        id: SlotId,
    ) -> Result<Option<ExchangeEntry>, SlotMessageError>
    where
        S: DatagramSlots,
    {
        let endpoint = self.storage.rx_endpoint(id).ok_or(SlotError::NotOccupied)?;
        let (token, ty, code, message_id, echo) = {
            let parsed = decode_occupied(self.storage.rx_payload(id))?;
            (
                parsed.token(),
                parsed.ty(),
                parsed.code(),
                parsed.message_id(),
                Echo::from_option(parsed.echo()),
            )
        };
        Ok(self.take_matching_response(token, ty, code, message_id, endpoint, echo))
    }

    fn take_matching_response(
        &mut self,
        token: Token,
        ty: crate::message::Type,
        code: crate::message::Code,
        message_id: MessageId,
        endpoint: Endpoint,
        challenge: Option<Echo>,
    ) -> Option<ExchangeEntry> {
        if !code.is_response()
            || !matches!(
                ty,
                crate::message::Type::Confirmable
                    | crate::message::Type::NonConfirmable
                    | crate::message::Type::Acknowledgement
            )
        {
            return None;
        }
        let key = ExchangeKey::new(token, endpoint);
        let id = self.storage.lookup_exchange(key)?;
        let entry = self.storage.exchange_entry(id)?;
        let mid_ok = match ty {
            crate::message::Type::Acknowledgement => message_id == entry.message_id(),
            crate::message::Type::Confirmable | crate::message::Type::NonConfirmable => true,
            crate::message::Type::Reset => false,
        };
        if !mid_ok {
            return None;
        }
        let entry = self.storage.take_exchange(key)?;
        Some(match challenge {
            Some(echo) => entry.with_challenge(echo),
            None => entry,
        })
    }
}

impl<S: Storage + ObserveSlots> Engine<S> {
    /// Insert an Observe interest, or return the existing slot if the key is present.
    ///
    /// `None` when the table is full and the key is not already stored. Scans
    /// the configured capacity (O(n)). Does not use Dedup, pending CON, or
    /// exchange matching.
    pub fn insert_observe(&mut self, interest: ObserveInterest) -> Option<SlotId> {
        match self.storage.insert_observe(interest) {
            Some(id) => {
                Metrics::inc(&mut self.metrics.observe_register);
                Some(id)
            }
            None => {
                Metrics::inc(&mut self.metrics.saturated);
                None
            }
        }
    }

    /// Occupied Observe slot matching `key`, if any. O(n) in capacity.
    #[must_use]
    pub fn lookup_observe(&self, key: ObserveKey) -> Option<SlotId> {
        self.storage.lookup_observe(key)
    }

    /// Release the Observe slot matching `key`, if occupied. O(n) in capacity.
    pub fn remove_observe(&mut self, key: ObserveKey) -> bool {
        let removed = self.storage.remove_observe(key);
        if removed {
            Metrics::inc(&mut self.metrics.observe_cancel);
        }
        removed
    }

    /// Remove and return the Observe interest matching `key`, if any.
    pub fn take_observe(&mut self, key: ObserveKey) -> Option<ObserveInterest> {
        let taken = self.storage.take_observe(key);
        if taken.is_some() {
            Metrics::inc(&mut self.metrics.observe_cancel);
        }
        taken
    }

    /// Occupied Observe payload at `id`.
    #[must_use]
    pub fn observe_interest(&self, id: SlotId) -> Option<ObserveInterest> {
        self.storage.observe_interest(id)
    }

    /// Mark the interest matching `key` as due for one notification.
    ///
    /// Coalesces: a second signal before [`Self::progress`] surfaces the row
    /// still yields one work item. `None` for client-side subscriptions or
    /// when no row matches. Does not
    /// encode a payload, acquire a TX slot, or invent 4.02 / RST policy.
    pub fn signal_observe(&mut self, key: ObserveKey) -> Option<SlotId> {
        if key.is_client() {
            return None;
        }
        self.storage.signal_observe(key)
    }

    /// Set or refresh Max-Age / observer lifetime on the row matching `key`.
    ///
    /// `max_age_secs` is the resource Max-Age. Due is `now_ms + max_age_secs
    /// * 1000` (caller clock; no OS time). `con_mid` `Some` records a CON
    /// notification waiting for ACK ([`ObserveLifetime::Unacked`]); `None`
    /// is freshness ([`ObserveLifetime::MaxAge`]). `None` return when no
    /// row matches. Does not encode, send, or invent 4.02 / RST policy.
    /// See `knowledge/rfcs/rfc7641.txt` and Max-Age in
    /// `knowledge/rfcs/rfc7252.txt`.
    pub fn refresh_observe_max_age(
        &mut self,
        key: ObserveKey,
        now_ms: u64,
        max_age_secs: u32,
        con_mid: Option<MessageId>,
    ) -> Option<SlotId> {
        let id = self.storage.lookup_observe(key)?;
        let interest = self.storage.observe_interest(id)?;
        let lifetime = match con_mid {
            Some(message_id) => ObserveLifetime::unacked(now_ms, max_age_secs, message_id),
            None => ObserveLifetime::max_age(now_ms, max_age_secs),
        };
        self.storage
            .set_observe_interest(id, interest.with_lifetime(Some(lifetime)))
            .ok()?;
        Some(id)
    }

    /// Clear CON-wait and NSTART hold on the interest that recorded `message_id`.
    ///
    /// Used after an empty ACK matches a pending CON notify. Does not drop
    /// the row and does not invent RST policy. `None` when no row matches.
    pub fn ack_observe_con(&mut self, message_id: MessageId, endpoint: Endpoint) -> Option<SlotId> {
        let id = lookup_observe_unacked(&mut self.storage, message_id, endpoint)?;
        let mut interest = self.storage.observe_interest(id)?;
        interest = interest.with_lifetime(None);
        interest.clear_notify_hold();
        self.storage.set_observe_interest(id, interest).ok()?;
        Some(id)
    }

    /// Record a sent notification on the row matching `key` (RFC 7641 §4.5).
    ///
    /// `confirmable` is CON (resets the 24-hour confirm clock; NSTART hold
    /// until [`Self::ack_observe_con`]). Otherwise NON (starts the 24-hour
    /// clock if unset; NSTART hold for
    /// [`crate::message::ObserveTransmission::NON_TIMEOUT_MS`]).
    /// `message_id` is stored on either hold so [`Self::reject_observe_notify`]
    /// can drop the row on empty RST. `None` return when no row matches, or
    /// when the endpoint already has NSTART outstanding notifications and
    /// this row is not the holder. Idempotent when this row already holds
    /// the same CON Message ID. Does not encode, send, or invent 4.02 / RST
    /// policy.
    pub fn record_observe_notify(
        &mut self,
        key: ObserveKey,
        now_ms: u64,
        message_id: MessageId,
        confirmable: bool,
    ) -> Option<SlotId> {
        let id = self.storage.lookup_observe(key)?;
        let mut interest = self.storage.observe_interest(id)?;
        if interest.key().is_client() {
            return None;
        }
        if let Some(existing) = interest.notify_hold() {
            if existing.is_held(now_ms) {
                if confirmable && existing.con_mid() == Some(message_id) {
                    return Some(id);
                }
                return None;
            }
        }
        if endpoint_notify_held(&self.storage, key.endpoint(), now_ms)
            >= usize::from(crate::message::Transmission::NSTART)
            && !interest.is_notify_held(now_ms)
        {
            Metrics::inc(&mut self.metrics.nstart_reject);
            return None;
        }
        interest.record_notify(now_ms, message_id, confirmable);
        self.storage.set_observe_interest(id, interest).ok()?;
        Metrics::inc(&mut self.metrics.observe_notify);
        Some(id)
    }

    /// Drop the interest whose outstanding notification used `message_id`.
    ///
    /// Empty RST has no Token (RFC 7252). Match is Message ID plus
    /// endpoint, covering CON wait and CON/NON notify hold. Used by
    /// [`crate::App::poll`] after RST. Does not send. `None` when no row
    /// matches. See `knowledge/rfcs/rfc7641.txt` §4.5.
    pub fn reject_observe_notify(
        &mut self,
        message_id: MessageId,
        endpoint: Endpoint,
    ) -> Option<ObserveInterest> {
        let id = lookup_observe_unacked(&mut self.storage, message_id, endpoint)?;
        let interest = self.storage.observe_interest(id)?;
        self.take_observe(interest.key())
    }

    /// First interest whose colocated lifetime is due at `now_ms`, if any.
    ///
    /// Rotating and fair. Surfaces at most one row, clears that lifetime
    /// and pending, leaves the row occupied. The caller drops it or stops
    /// notifying. Does not send RST. See `knowledge/rfcs/rfc7641.txt`.
    pub fn poll_observe_lifetime(&mut self, now_ms: u64) -> Option<ObserveExpiry> {
        poll_observe_lifetime(self, now_ms)
    }

    /// If `parsed` is a GET with Observe 0 (register), insert Token + Endpoint.
    ///
    /// Records [`ObserveResource`] from Uri-Path on the same row. Idempotent
    /// for the same Token and endpoint. `None` when the datagram is not a
    /// register GET, or the table is full. Does not invent 4.02 / RST policy.
    pub fn register_observe(
        &mut self,
        parsed: &ParsedMessage<'_>,
        endpoint: Endpoint,
    ) -> Option<SlotId> {
        if !parsed.is_observe_register() {
            return None;
        }
        self.insert_observe(
            ObserveInterest::new(parsed.token(), endpoint)
                .with_resource(observe_resource_from_message(parsed)),
        )
    }

    /// If `parsed` is a GET with Observe 1 (deregister), take Token + Endpoint.
    ///
    /// `None` when the datagram is not a deregister GET, or no row matches.
    pub fn deregister_observe(
        &mut self,
        parsed: &ParsedMessage<'_>,
        endpoint: Endpoint,
    ) -> Option<ObserveInterest> {
        if !parsed.is_observe_deregister() {
            return None;
        }
        self.take_observe(ObserveKey::new(parsed.token(), endpoint))
    }

    /// Decode occupied RX `id` and [`Self::register_observe`] using its sidecar endpoint.
    pub fn register_observe_rx(&mut self, id: SlotId) -> Result<Option<SlotId>, SlotMessageError>
    where
        S: DatagramSlots,
    {
        let endpoint = self.storage.rx_endpoint(id).ok_or(SlotError::NotOccupied)?;
        let (token, is_register, resource) = {
            let parsed = decode_occupied(self.storage.rx_payload(id))?;
            (
                parsed.token(),
                parsed.is_observe_register(),
                observe_resource_from_message(&parsed),
            )
        };
        if !is_register {
            return Ok(None);
        }
        Ok(self.insert_observe(ObserveInterest::new(token, endpoint).with_resource(resource)))
    }

    /// Decode occupied RX `id` and [`Self::deregister_observe`] using its sidecar endpoint.
    pub fn deregister_observe_rx(
        &mut self,
        id: SlotId,
    ) -> Result<Option<ObserveInterest>, SlotMessageError>
    where
        S: DatagramSlots,
    {
        let endpoint = self.storage.rx_endpoint(id).ok_or(SlotError::NotOccupied)?;
        let (token, is_deregister) = {
            let parsed = decode_occupied(self.storage.rx_payload(id))?;
            (parsed.token(), parsed.is_observe_deregister())
        };
        if !is_deregister {
            return Ok(None);
        }
        Ok(self.take_observe(ObserveKey::new(token, endpoint)))
    }

    /// Assign the next 24-bit notification sequence on `id` (same as progress).
    ///
    /// Marks the row due, then [`ObserveInterest::take_due`]. `None` when
    /// the slot is free. Does not encode or send.
    pub fn next_observe_seq(&mut self, id: SlotId) -> Option<u32> {
        let mut interest = self.storage.observe_interest(id)?;
        interest.mark_due();
        let seq = interest.take_due()?;
        self.storage.set_observe_interest(id, interest).ok()?;
        Some(seq)
    }

    /// Undo [`Self::next_observe_seq`] / progress `take_due` after a send miss.
    ///
    /// Re-pends the row and rewinds the 24-bit sequence so a later poll can
    /// send the same seq. No-op if the slot is free or no longer holds
    /// `assigned_seq`.
    pub fn restore_observe_due(&mut self, id: SlotId, assigned_seq: u32) -> bool {
        let Some(mut interest) = self.storage.observe_interest(id) else {
            return false;
        };
        interest.restore_due(assigned_seq);
        self.storage.set_observe_interest(id, interest).is_ok()
    }

    /// Mark every interest whose [`ObserveResource`] equals `resource` as due.
    ///
    /// Coalesces like [`Self::signal_observe`]. Returns how many rows were
    /// marked. [`ObserveResource::NONE`] matches nothing.
    pub fn signal_observe_resource(&mut self, resource: ObserveResource) -> usize {
        if resource.is_none() {
            return 0;
        }
        let n = self.storage.capacities().observe_entries;
        let mut marked = 0usize;
        for i in 0..n {
            let id = SlotId::from_index(i);
            let Some(mut interest) = self.storage.observe_interest(id) else {
                continue;
            };
            if interest.key().is_client() || interest.resource() != resource {
                continue;
            }
            interest.mark_due();
            if self.storage.set_observe_interest(id, interest).is_ok() {
                marked += 1;
            }
        }
        marked
    }

    /// Queue a terminal App notification without losing congestion-control state.
    pub(crate) fn mark_observe_resource_deleted(&mut self, resource: ObserveResource) -> usize {
        if resource.is_none() {
            return 0;
        }
        let mut marked = 0;
        for i in 0..self.storage.capacities().observe_entries {
            let id = SlotId::from_index(i);
            let Some(mut interest) = self.storage.observe_interest(id) else {
                continue;
            };
            if interest.key().is_client() || interest.resource() != resource {
                continue;
            }
            interest.mark_deleted();
            if self.storage.set_observe_interest(id, interest).is_ok() {
                marked += 1;
            }
        }
        marked
    }

    /// Drop every interest whose [`ObserveResource`] equals `resource`.
    ///
    /// Returns how many rows were removed. This is immediate removal with no
    /// notification; App DELETE instead queues terminal delivery.
    /// [`ObserveResource::NONE`] matches nothing.
    pub fn take_observe_resource(&mut self, resource: ObserveResource) -> usize {
        if resource.is_none() {
            return 0;
        }
        let n = self.storage.capacities().observe_entries;
        let mut dropped = 0usize;
        for i in 0..n {
            let id = SlotId::from_index(i);
            let Some(interest) = self.storage.observe_interest(id) else {
                continue;
            };
            if interest.key().is_client() || interest.resource() != resource {
                continue;
            }
            if self.take_observe(interest.key()).is_some() {
                dropped += 1;
            }
        }
        dropped
    }

    /// If a CON notify with `message_id` is still waiting, make it due now.
    ///
    /// Used when [`Retransmit::GiveUp`] matches that CON. Does not drop the
    /// row. `None` when no row matches.
    pub(crate) fn mark_observe_unacked_due(
        &mut self,
        message_id: MessageId,
        endpoint: Endpoint,
        now_ms: u64,
    ) -> Option<SlotId> {
        let id = lookup_observe_unacked(&mut self.storage, message_id, endpoint)?;
        let interest = self.storage.observe_interest(id)?;
        self.storage
            .set_observe_interest(
                id,
                interest.with_lifetime(Some(ObserveLifetime::unacked(now_ms, 0, message_id))),
            )
            .ok()?;
        Some(id)
    }
}

fn observe_resource_from_message(parsed: &ParsedMessage<'_>) -> ObserveResource {
    let mut segs = [""; 8];
    let mut n = 0usize;
    for item in parsed.uri_path() {
        let Ok(seg) = item else {
            return ObserveResource::NONE;
        };
        if n >= segs.len() {
            break;
        }
        segs[n] = seg;
        n += 1;
    }
    ObserveResource::from_path(&segs[..n])
}

pub(crate) fn endpoint_notify_held<S: Storage + ObserveSlots>(
    storage: &S,
    endpoint: Endpoint,
    now_ms: u64,
) -> usize {
    let n = storage.capacities().observe_entries;
    (0..n)
        .filter(|&i| {
            storage
                .observe_interest(SlotId::from_index(i))
                .is_some_and(|row| {
                    !row.key().is_client()
                        && row.endpoint() == endpoint
                        && row.is_notify_held(now_ms)
                })
        })
        .count()
}

fn lookup_observe_unacked<S: Storage + ObserveSlots>(
    storage: &mut S,
    message_id: MessageId,
    endpoint: Endpoint,
) -> Option<SlotId> {
    let n = storage.observe().slot_count();
    for i in 0..n {
        let id = SlotId::from_index(i);
        let Some(interest) = storage.observe_interest(id) else {
            continue;
        };
        if interest.key().is_client() || interest.endpoint() != endpoint {
            continue;
        }
        if interest.lifetime().and_then(ObserveLifetime::con_mid) == Some(message_id)
            || interest
                .notify_hold()
                .is_some_and(|h| h.message_id() == message_id)
        {
            return Some(id);
        }
    }
    None
}

fn poll_observe_lifetime<S: Storage + ObserveSlots>(
    engine: &mut Engine<S>,
    now_ms: u64,
) -> Option<ObserveExpiry> {
    if engine.storage_mut().observe().is_empty() {
        return None;
    }
    let n = engine.storage_mut().observe().slot_count();
    if n == 0 {
        return None;
    }
    let start = engine.storage_mut().observe().cursor();
    let mut found = None;
    for offset in 0..n {
        let id = SlotId::from_index((start + offset) % n);
        let Some(mut interest) = engine.observe_interest(id) else {
            continue;
        };
        let Some(life) = interest.take_expired(now_ms) else {
            continue;
        };
        found = Some((id, offset, interest, life));
        break;
    }
    match found {
        Some((id, offset, interest, life)) => {
            engine
                .storage_mut()
                .set_observe_interest(id, interest)
                .ok()?;
            engine.advance_observe(offset + 1);
            Some(match life {
                ObserveLifetime::MaxAge { .. } => ObserveExpiry::MaxAge(id),
                ObserveLifetime::Unacked { .. } => ObserveExpiry::ClientOff(id),
            })
        }
        None => None,
    }
}

impl<S: Storage + BodySlots> Engine<S> {
    /// Read access to an occupied incoming body. Pins `id` until dropped.
    ///
    /// See [`Access`]. The [`crate::App`] happy path does not need this.
    #[inline]
    pub fn access_rx_body(&mut self, id: SlotId) -> Result<Access<'_>, SlotError> {
        self.storage.access_rx_body(id)
    }

    /// Write access to an occupied outgoing body buffer. Pins `id` until dropped.
    ///
    /// See [`AccessMut`]. The [`crate::App`] happy path does not need this.
    #[inline]
    pub fn access_tx_body_mut(&mut self, id: SlotId) -> Result<AccessMut<'_>, SlotError> {
        self.storage.access_tx_body_mut(id)
    }

    /// Filled incoming body bytes, if `id` is occupied.
    #[inline]
    #[must_use]
    pub fn rx_body_payload(&self, id: SlotId) -> Option<&[u8]> {
        self.storage.rx_body_payload(id)
    }

    /// Filled outgoing body bytes, if `id` is occupied.
    #[inline]
    #[must_use]
    pub fn tx_body_payload(&self, id: SlotId) -> Option<&[u8]> {
        self.storage.tx_body_payload(id)
    }

    /// Incoming Block1 / Block2 sidecar on `id`.
    #[inline]
    #[must_use]
    pub fn rx_body_transfer(&self, id: SlotId) -> Option<BlockTransfer> {
        self.storage.rx_body_transfer(id)
    }

    #[cfg(feature = "oscore")]
    pub(crate) fn remember_qblock1_request(
        &mut self,
        id: SlotId,
        token: crate::message::Token,
        request: crate::oscore::RequestRef,
    ) {
        let Some(mut transfer) = self.storage.rx_body_transfer(id) else {
            return;
        };
        if transfer.role() != BlockRole::IncomingQBlock1 {
            return;
        }
        if transfer
            .oscore_request
            .is_none_or(|(_, old)| request.piv().seq() > old.piv().seq())
        {
            transfer.oscore_request = Some((token, request));
            let _ = self.storage.set_rx_body_transfer(id, transfer);
        }
    }

    /// Arm or clear incoming Q-Block [`super::QBlockReceiveWait`] from caller `now_ms`.
    ///
    /// [`Self::apply_q_block1`] / [`Self::apply_q_block2`] do not take a clock.
    /// App::poll calls this after apply so the wait starts at receive time.
    /// [`Self::progress`] lazy-arms when holes exist and no wait is stored.
    /// `None` when `id` has no incoming transfer.
    pub fn note_q_receive(&mut self, id: SlotId, now_ms: u64) -> Option<BlockTransfer> {
        let mut transfer = self.storage.rx_body_transfer(id)?;
        transfer.note_q_receive(now_ms);
        self.storage.set_rx_body_transfer(id, transfer).ok()?;
        Some(transfer)
    }

    /// Outgoing Block1 / Block2 sidecar on `id`.
    #[inline]
    #[must_use]
    pub fn tx_body_transfer(&self, id: SlotId) -> Option<BlockTransfer> {
        self.storage.tx_body_transfer(id)
    }

    /// First incoming body matching `key` across roles; see [`Self::lookup_rx_body_role`].
    #[inline]
    #[must_use]
    pub fn lookup_rx_body(&self, key: BlockKey) -> Option<SlotId> {
        self.storage.lookup_rx_body(key)
    }

    /// First outgoing body matching `key` across roles; see [`Self::lookup_tx_body_role`].
    #[inline]
    #[must_use]
    pub fn lookup_tx_body(&self, key: BlockKey) -> Option<SlotId> {
        self.storage.lookup_tx_body(key)
    }

    /// Incoming body matching both key and role. Use this when acting as
    /// both client and server: opposite directions may use identical Tokens
    /// and tags at the same endpoint. This scans the configured slot bound.
    #[must_use]
    pub fn lookup_rx_body_role(&self, key: BlockKey, role: BlockRole) -> Option<SlotId> {
        (0..self.capacities().rx_body_slots.unwrap_or(0)).find_map(|index| {
            let id = SlotId::from_index(index);
            self.storage
                .rx_body_transfer(id)
                .filter(|transfer| transfer.key() == key && transfer.role() == role)
                .map(|_| id)
        })
    }

    /// Outgoing body matching both key and role, without selecting a body
    /// owned by the opposite client/server direction.
    #[must_use]
    pub fn lookup_tx_body_role(&self, key: BlockKey, role: BlockRole) -> Option<SlotId> {
        (0..self.capacities().tx_body_slots.unwrap_or(0)).find_map(|index| {
            let id = SlotId::from_index(index);
            self.storage
                .tx_body_transfer(id)
                .filter(|transfer| transfer.key() == key && transfer.role() == role)
                .map(|_| id)
        })
    }

    /// Admit a new incoming Block1 body when the first block arrives.
    ///
    /// Acquires one Incoming Body Slot. Classic Block starts at NUM 0.
    /// `size1` is the Size1 hint when present. See
    /// `knowledge/rfcs/rfc7959.txt`.
    #[inline]
    pub fn admit_block1(
        &mut self,
        key: BlockKey,
        block: BlockValue,
        payload: &[u8],
        size1: Option<u32>,
    ) -> Result<SlotId, BlockTransferError> {
        self.storage.admit_block1(key, block, payload, size1)
    }

    /// Write the next in-order incoming Block1 range into `id`.
    ///
    /// Rejects overlap, gap, SZX mismatch, and actual byte overflow. Size1
    /// is an estimate and does not determine completion. Does not invent 4.08 policy.
    #[inline]
    pub fn write_block1(
        &mut self,
        id: SlotId,
        block: BlockValue,
        payload: &[u8],
    ) -> Result<BlockProgress, BlockTransferError> {
        self.storage.write_block1(id, block, payload)
    }

    /// Admit or continue incoming Block1 for `key`.
    #[inline]
    pub fn apply_block1(
        &mut self,
        key: BlockKey,
        block: BlockValue,
        payload: &[u8],
        size1: Option<u32>,
    ) -> Result<BlockProgress, BlockTransferError> {
        let result = self.storage.apply_block1(key, block, payload, size1);
        self.metrics.tally_block(result.as_ref().map(|_| ()), true);
        result
    }

    /// Decode occupied RX `id` and [`Self::apply_block1`] using Block1 + Token + endpoint.
    ///
    /// Copies the datagram payload into the body slot (datagram RX stays
    /// separate). Request-Tag, when present, is stored on the body sidecar.
    /// Missing Block1 is [`BlockTransferError::MissingBlock`]. Method and
    /// cache-key options are retained exactly, bounded by
    /// [`BlockTransfer::REQUEST_IDENTITY_BYTES`]. A changed operation is refused
    /// before body mutation; integer leading-zero encodings compare equally.
    /// Direct range APIs require the caller to enforce operation matchability.
    pub fn apply_block1_rx(&mut self, id: SlotId) -> Result<BlockProgress, BlockTransferError>
    where
        S: DatagramSlots,
    {
        self.apply_incoming_rx(id, RxBlockOpt::Block1)
    }

    /// Admit a new incoming Block2 body when the first block arrives.
    ///
    /// Acquires one Incoming Body Slot. Classic Block starts at NUM 0.
    /// `size2` is the Size2 hint when present. See
    /// `knowledge/rfcs/rfc7959.txt`.
    #[inline]
    pub fn admit_block2(
        &mut self,
        key: BlockKey,
        block: BlockValue,
        payload: &[u8],
        size2: Option<u32>,
    ) -> Result<SlotId, BlockTransferError> {
        self.storage.admit_block2(key, block, payload, size2)
    }

    /// Write the next in-order incoming Block2 range into `id`.
    ///
    /// Rejects overlap, gap, SZX mismatch, and actual byte overflow. Size2
    /// is an estimate and does not determine completion. Does not invent 4.08 policy.
    #[inline]
    pub fn write_block2(
        &mut self,
        id: SlotId,
        block: BlockValue,
        payload: &[u8],
    ) -> Result<BlockProgress, BlockTransferError> {
        self.storage.write_block2(id, block, payload)
    }

    /// Admit or continue incoming Block2 for `key`.
    #[inline]
    pub fn apply_block2(
        &mut self,
        key: BlockKey,
        block: BlockValue,
        payload: &[u8],
        size2: Option<u32>,
    ) -> Result<BlockProgress, BlockTransferError> {
        let result = self.storage.apply_block2(key, block, payload, size2);
        self.metrics.tally_block(result.as_ref().map(|_| ()), false);
        result
    }

    /// Decode occupied RX `id` and [`Self::apply_block2`] using Block2 + Token + endpoint.
    ///
    /// Copies the datagram payload into the body slot (datagram RX stays
    /// separate). Missing Block2 is [`BlockTransferError::MissingBlock`].
    pub fn apply_block2_rx(&mut self, id: SlotId) -> Result<BlockProgress, BlockTransferError>
    where
        S: DatagramSlots,
    {
        self.apply_incoming_rx(id, RxBlockOpt::Block2)
    }

    /// Admit a new incoming Q-Block1 body when the first window-0 block arrives.
    ///
    /// The first datagram may be any NUM in `0..MAX_PAYLOADS`. `size1` is the
    /// Size1 hint when present. See `knowledge/rfcs/rfc9177.txt`.
    #[inline]
    pub fn admit_q_block1(
        &mut self,
        key: BlockKey,
        block: BlockValue,
        payload: &[u8],
        size1: Option<u32>,
    ) -> Result<SlotId, BlockTransferError> {
        self.storage.admit_q_block1(key, block, payload, size1)
    }

    /// Write one incoming Q-Block1 range into `id`.
    ///
    /// Accepts out-of-order NUMs in the current window. Rejects duplicates
    /// and NUMs outside the window. Does not invent 4.08 policy.
    #[inline]
    pub fn write_q_block1(
        &mut self,
        id: SlotId,
        block: BlockValue,
        payload: &[u8],
    ) -> Result<BlockProgress, BlockTransferError> {
        self.storage.write_q_block1(id, block, payload)
    }

    /// Admit or continue incoming Q-Block1 for `key`.
    #[inline]
    pub fn apply_q_block1(
        &mut self,
        key: BlockKey,
        block: BlockValue,
        payload: &[u8],
        size1: Option<u32>,
    ) -> Result<BlockProgress, BlockTransferError> {
        let result = self.storage.apply_q_block1(key, block, payload, size1);
        self.metrics.tally_block(result.as_ref().map(|_| ()), true);
        result
    }

    /// Decode occupied RX `id` and [`Self::apply_q_block1`] using Q-Block1 + Token + endpoint.
    ///
    /// Identity is Token + Endpoint plus Request-Tag when present (RFC 9175 /
    /// RFC 9177). Missing Q-Block1 is [`BlockTransferError::MissingBlock`].
    ///
    /// Retains the same bounded request matchability context as
    /// [`Self::apply_block1_rx`]; a mismatching continuation cannot mutate it.
    ///
    /// Every payload must carry Size1 and Request-Tag (which may be empty).
    /// Missing identity or missing/changed sizes are rejected before modifying
    /// the body.
    pub fn apply_q_block1_rx(&mut self, id: SlotId) -> Result<BlockProgress, BlockTransferError>
    where
        S: DatagramSlots,
    {
        self.apply_incoming_rx(id, RxBlockOpt::QBlock1)
    }

    /// Admit a new incoming Q-Block2 body when the first window-0 block arrives.
    ///
    /// The first datagram may be any NUM in `0..MAX_PAYLOADS`. `size2` is the
    /// Size2 hint when present. See `knowledge/rfcs/rfc9177.txt`.
    #[inline]
    pub fn admit_q_block2(
        &mut self,
        key: BlockKey,
        block: BlockValue,
        payload: &[u8],
        size2: Option<u32>,
    ) -> Result<SlotId, BlockTransferError> {
        self.storage.admit_q_block2(key, block, payload, size2)
    }

    /// Write one incoming Q-Block2 range into `id`.
    ///
    /// Accepts out-of-order NUMs in the current window. Rejects duplicates
    /// and NUMs outside the window. Does not invent 4.08 policy.
    #[inline]
    pub fn write_q_block2(
        &mut self,
        id: SlotId,
        block: BlockValue,
        payload: &[u8],
    ) -> Result<BlockProgress, BlockTransferError> {
        self.storage.write_q_block2(id, block, payload)
    }

    /// Admit or continue incoming Q-Block2 for `key`.
    #[inline]
    pub fn apply_q_block2(
        &mut self,
        key: BlockKey,
        block: BlockValue,
        payload: &[u8],
        size2: Option<u32>,
    ) -> Result<BlockProgress, BlockTransferError> {
        let result = self.storage.apply_q_block2(key, block, payload, size2);
        self.metrics.tally_block(result.as_ref().map(|_| ()), false);
        result
    }

    /// Decode occupied RX `id` and [`Self::apply_q_block2`] using Q-Block2 + Token + endpoint.
    ///
    /// Uses the first Q-Block2 option. Repeatable recover-request options
    /// are for the outgoing reissue hook, not this assemble path. Missing
    /// Q-Block2 is [`BlockTransferError::MissingBlock`]. Every payload must carry
    /// Size2 and a nonempty ETag; missing identity or missing/changed sizes
    /// are rejected before modifying the body.
    pub fn apply_q_block2_rx(&mut self, id: SlotId) -> Result<BlockProgress, BlockTransferError>
    where
        S: DatagramSlots,
    {
        self.apply_incoming_rx(id, RxBlockOpt::QBlock2)
    }

    /// Copy a complete body into an Outgoing Body Slot and start Block1.
    #[inline]
    pub fn start_block1(
        &mut self,
        key: BlockKey,
        body: &[u8],
        szx: u8,
    ) -> Result<SlotId, BlockTransferError> {
        self.storage.start_block1(key, body, szx)
    }

    /// Issue the next in-order outgoing Block1 range. Bytes stay in the body slot.
    #[inline]
    pub fn next_block1(&mut self, id: SlotId) -> Result<OutgoingBlock, BlockTransferError> {
        self.storage.next_block1(id)
    }

    /// Issue the next Block1 and encode it into occupied TX `tx_id`.
    ///
    /// Token and remote endpoint come from the body-slot sidecar. The caller
    /// supplies type, code, and Message ID. Does not invent 2.31 / 4.08.
    pub fn encode_block1_tx(
        &mut self,
        body_id: SlotId,
        tx_id: SlotId,
        ty: Type,
        code: Code,
        message_id: MessageId,
    ) -> Result<OutgoingBlock, BlockTransferError>
    where
        S: DatagramSlots,
    {
        let issued = self.storage.next_block1(body_id)?;
        self.finish_outgoing_tx(
            issued,
            body_id,
            tx_id,
            (ty, code, message_id),
            OutgoingBlockOpt::Block1,
        )
    }

    /// Issue one outgoing Block1 BERT payload of at most `max_payload` bytes.
    #[inline]
    pub fn next_bert1(
        &mut self,
        id: SlotId,
        max_payload: usize,
    ) -> Result<OutgoingBlock, BlockTransferError> {
        self.storage.next_bert1(id, max_payload)
    }

    /// Issue the next Block1 BERT range and encode it into occupied TX `tx_id`.
    ///
    /// Request-Tag comes from the body sidecar when present. Does not invent
    /// 2.31 / 4.08. See `knowledge/rfcs/rfc8323.txt`.
    pub fn encode_bert1_tx(
        &mut self,
        body_id: SlotId,
        tx_id: SlotId,
        ty: Type,
        code: Code,
        message_id: MessageId,
        max_payload: usize,
    ) -> Result<OutgoingBlock, BlockTransferError>
    where
        S: DatagramSlots,
    {
        let issued = self.storage.next_bert1(body_id, max_payload)?;
        self.finish_outgoing_tx(
            issued,
            body_id,
            tx_id,
            (ty, code, message_id),
            OutgoingBlockOpt::Block1,
        )
    }

    /// Copy a complete body into an Outgoing Body Slot and start Block2.
    #[inline]
    pub fn start_block2(
        &mut self,
        key: BlockKey,
        body: &[u8],
        szx: u8,
    ) -> Result<SlotId, BlockTransferError> {
        self.storage.start_block2(key, body, szx)
    }

    /// Select a classic Block2 response range without advancing a transfer cursor.
    /// Used by App for independently tokened RFC 7959 requests.
    pub(crate) fn requested_block2(
        &self,
        id: SlotId,
        requested: BlockValue,
    ) -> Result<OutgoingBlock, BlockTransferError> {
        let transfer = self
            .storage
            .tx_body_transfer(id)
            .ok_or(BlockTransferError::NoTransfer)?;
        if transfer.role() != BlockRole::OutgoingBlock2 || requested.is_bert() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        let size = usize::from(requested.size());
        let offset = usize::try_from(requested.num())
            .ok()
            .and_then(|n| n.checked_mul(size))
            .ok_or(BlockTransferError::Overflow)?;
        let total = transfer.filled();
        if offset > total || (offset == total && total > 0) {
            return Err(BlockTransferError::Gap);
        }
        let len = (total - offset).min(size);
        let more = offset + len < total;
        let block = BlockValue::new(requested.num(), more, requested.szx())?;
        Ok(OutgoingBlock::new(id, block, offset, len, !more))
    }

    /// Issue the next in-order outgoing Block2 range. Bytes stay in the body slot.
    #[inline]
    pub fn next_block2(&mut self, id: SlotId) -> Result<OutgoingBlock, BlockTransferError> {
        self.storage.next_block2(id)
    }

    /// Issue the next Block2 and encode it into occupied TX `tx_id`.
    ///
    /// Token and remote endpoint come from the body-slot sidecar. The caller
    /// supplies type, code, and Message ID. Does not invent 2.31 / 4.08.
    pub fn encode_block2_tx(
        &mut self,
        body_id: SlotId,
        tx_id: SlotId,
        ty: Type,
        code: Code,
        message_id: MessageId,
    ) -> Result<OutgoingBlock, BlockTransferError>
    where
        S: DatagramSlots,
    {
        let issued = self.storage.next_block2(body_id)?;
        self.finish_outgoing_tx(
            issued,
            body_id,
            tx_id,
            (ty, code, message_id),
            OutgoingBlockOpt::Block2,
        )
    }

    /// [`Self::encode_block2_tx`] plus Observe (RFC 7641) on this block.
    ///
    /// Use on the first block of a block-wise notification. Subsequent
    /// blocks stay on [`Self::encode_block2_tx`]. Does not invent 2.31.
    /// See `knowledge/rfcs/rfc7641.txt` and `knowledge/rfcs/rfc7959.txt`.
    pub fn encode_block2_observe_tx(
        &mut self,
        body_id: SlotId,
        tx_id: SlotId,
        ty: Type,
        code: Code,
        message_id: MessageId,
        observe_seq: u32,
    ) -> Result<OutgoingBlock, BlockTransferError>
    where
        S: DatagramSlots,
    {
        let issued = self.storage.next_block2(body_id)?;
        self.finish_outgoing_tx_observe(
            issued,
            body_id,
            tx_id,
            (ty, code, message_id),
            OutgoingBlockOpt::Block2,
            Some(observe_seq),
        )
    }

    /// Issue one outgoing Block2 BERT payload of at most `max_payload` bytes.
    #[inline]
    pub fn next_bert2(
        &mut self,
        id: SlotId,
        max_payload: usize,
    ) -> Result<OutgoingBlock, BlockTransferError> {
        self.storage.next_bert2(id, max_payload)
    }

    /// Issue the next Block2 BERT range and encode it into occupied TX `tx_id`.
    ///
    /// ETag comes from the body sidecar when present. Does not invent 2.31 /
    /// 4.08. See `knowledge/rfcs/rfc8323.txt`.
    pub fn encode_bert2_tx(
        &mut self,
        body_id: SlotId,
        tx_id: SlotId,
        ty: Type,
        code: Code,
        message_id: MessageId,
        max_payload: usize,
    ) -> Result<OutgoingBlock, BlockTransferError>
    where
        S: DatagramSlots,
    {
        let issued = self.storage.next_bert2(body_id, max_payload)?;
        self.finish_outgoing_tx(
            issued,
            body_id,
            tx_id,
            (ty, code, message_id),
            OutgoingBlockOpt::Block2,
        )
    }

    /// Copy a complete body into an Outgoing Body Slot and start Q-Block1.
    #[inline]
    pub fn start_q_block1(
        &mut self,
        key: BlockKey,
        body: &[u8],
        szx: u8,
    ) -> Result<SlotId, BlockTransferError> {
        self.storage.start_q_block1(key, body, szx)
    }

    /// Issue the next unsent outgoing Q-Block1 range in the current window.
    #[inline]
    pub fn next_q_block1(&mut self, id: SlotId) -> Result<OutgoingBlock, BlockTransferError> {
        self.storage.next_q_block1(id)
    }

    /// Advance an outgoing Q-Block1 window using the peer Continue NUM.
    ///
    /// `num` is the Q-Block1 NUM from the peer (RFC 9177 §4.3: all blocks
    /// through `num` received). Empty ACK is not a window ACK. Does not invent
    /// 2.31 / 4.08 policy.
    #[inline]
    pub fn ack_q_block1(
        &mut self,
        id: SlotId,
        num: u32,
    ) -> Result<BlockProgress, BlockTransferError> {
        self.storage.ack_q_block1(id, num)
    }

    /// Issue the next Q-Block1 and encode it into occupied TX `tx_id`.
    ///
    /// Token and remote endpoint come from the body-slot sidecar. Size1 is
    /// encoded (RFC 9177 §4.6). The sidecar must have a Request-Tag (empty
    /// is valid). Missing identity is refused before advancing the window.
    /// The caller owns uniqueness across bodies and supplies type, code, and Message ID.
    pub fn encode_q_block1_tx(
        &mut self,
        body_id: SlotId,
        tx_id: SlotId,
        ty: Type,
        code: Code,
        message_id: MessageId,
    ) -> Result<OutgoingBlock, BlockTransferError>
    where
        S: DatagramSlots,
    {
        self.require_q_identity(body_id, BlockRole::OutgoingQBlock1)?;
        let issued = self.storage.next_q_block1(body_id)?;
        self.finish_outgoing_tx(
            issued,
            body_id,
            tx_id,
            (ty, code, message_id),
            OutgoingBlockOpt::QBlock1,
        )
    }

    /// Decode occupied RX `id` and [`Self::ack_q_block1`] using Q-Block1 NUM.
    ///
    /// Empty ACK (code 0.00) has no Q-Block1 and is [`BlockTransferError::MissingBlock`].
    /// Token need not match (RFC 9177 §6 may use a new Token per request);
    /// endpoint must match the body slot. Does not inspect the response code.
    pub fn ack_q_block1_rx(
        &mut self,
        body_id: SlotId,
        rx_id: SlotId,
    ) -> Result<BlockProgress, BlockTransferError>
    where
        S: DatagramSlots,
    {
        self.ack_outgoing_rx(body_id, rx_id, RxBlockOpt::QBlock1)
    }

    /// Copy a complete body into an Outgoing Body Slot and start Q-Block2.
    #[inline]
    pub fn start_q_block2(
        &mut self,
        key: BlockKey,
        body: &[u8],
        szx: u8,
    ) -> Result<SlotId, BlockTransferError> {
        self.storage.start_q_block2(key, body, szx)
    }

    /// Issue the next unsent outgoing Q-Block2 range in the current window.
    #[inline]
    pub fn next_q_block2(&mut self, id: SlotId) -> Result<OutgoingBlock, BlockTransferError> {
        self.storage.next_q_block2(id)
    }

    /// Advance an outgoing Q-Block2 window using the peer Continue NUM.
    ///
    /// `num` is the Continue Q-Block2 NUM (RFC 9177 §4.4: `num % MAX_PAYLOADS
    /// == 0` and `num != 0`). Empty ACK is not a window ACK. Does not invent
    /// 2.31 / 4.08 policy.
    #[inline]
    pub fn ack_q_block2(
        &mut self,
        id: SlotId,
        num: u32,
    ) -> Result<BlockProgress, BlockTransferError> {
        self.storage.ack_q_block2(id, num)
    }

    /// Issue the next Q-Block2 and encode it into occupied TX `tx_id`.
    ///
    /// Token and remote endpoint come from the body-slot sidecar. Size2 is
    /// encoded (RFC 9177 §4.6). The sidecar must have a nonempty ETag. Missing
    /// identity is refused before advancing the window; callers own ETag uniqueness.
    /// The caller supplies type, code, and Message ID.
    pub fn encode_q_block2_tx(
        &mut self,
        body_id: SlotId,
        tx_id: SlotId,
        ty: Type,
        code: Code,
        message_id: MessageId,
    ) -> Result<OutgoingBlock, BlockTransferError>
    where
        S: DatagramSlots,
    {
        self.require_q_identity(body_id, BlockRole::OutgoingQBlock2)?;
        let issued = self.storage.next_q_block2(body_id)?;
        self.finish_outgoing_tx(
            issued,
            body_id,
            tx_id,
            (ty, code, message_id),
            OutgoingBlockOpt::QBlock2,
        )
    }

    /// Decode occupied RX `id` and [`Self::ack_q_block2`] using Q-Block2 NUM.
    ///
    /// Empty ACK (code 0.00) has no Q-Block2 and is [`BlockTransferError::MissingBlock`].
    /// A Continue request must have M set. Token need not match; endpoint must
    /// match the body slot. Does not invent 2.31 policy.
    pub fn ack_q_block2_rx(
        &mut self,
        body_id: SlotId,
        rx_id: SlotId,
    ) -> Result<BlockProgress, BlockTransferError>
    where
        S: DatagramSlots,
    {
        self.ack_outgoing_rx(body_id, rx_id, RxBlockOpt::QBlock2)
    }

    /// Reissue one Q-Block1 payload from outgoing body `id`.
    ///
    /// RFC 9177 §4.3: the client retransmits a missing payload using the same
    /// NUM, SZX, and M. Does not change window state. Does not invent 4.08.
    pub fn reissue_q_block1(
        &self,
        id: SlotId,
        num: u32,
    ) -> Result<OutgoingBlock, BlockTransferError> {
        self.reissue_q_outgoing(id, BlockRole::OutgoingQBlock1, num)
    }

    /// Reissue one Q-Block2 payload from outgoing body `id`.
    ///
    /// RFC 9177 §4.4: the server retransmits a missing payload from the
    /// complete body still in the slot. Does not change window state. The
    /// caller walks repeatable Q-Block2 recover options (or a 4.08 NUM list)
    /// and calls this once per NUM. Does not invent 4.08 / 2.31.
    pub fn reissue_q_block2(
        &self,
        id: SlotId,
        num: u32,
    ) -> Result<OutgoingBlock, BlockTransferError> {
        self.reissue_q_outgoing(id, BlockRole::OutgoingQBlock2, num)
    }

    /// Reissue one Q-Block1 payload and encode it into occupied TX `tx_id`.
    ///
    /// Token, Size1, and endpoint come from the body sidecar. Request-Tag is
    /// required in the sidecar. The caller supplies type, code, and
    /// Message ID.
    pub fn encode_q_block1_reissue_tx(
        &mut self,
        body_id: SlotId,
        tx_id: SlotId,
        ty: Type,
        code: Code,
        message_id: MessageId,
        num: u32,
    ) -> Result<OutgoingBlock, BlockTransferError>
    where
        S: DatagramSlots,
    {
        self.require_q_identity(body_id, BlockRole::OutgoingQBlock1)?;
        let issued = self.reissue_q_block1(body_id, num)?;
        self.finish_outgoing_tx(
            issued,
            body_id,
            tx_id,
            (ty, code, message_id),
            OutgoingBlockOpt::QBlock1,
        )
    }

    /// Reissue one Q-Block2 payload and encode it into occupied TX `tx_id`.
    ///
    /// Token, Size2, and endpoint come from the body sidecar. ETag is
    /// required in the sidecar. The caller supplies type, code, and
    /// Message ID.
    pub fn encode_q_block2_reissue_tx(
        &mut self,
        body_id: SlotId,
        tx_id: SlotId,
        ty: Type,
        code: Code,
        message_id: MessageId,
        num: u32,
    ) -> Result<OutgoingBlock, BlockTransferError>
    where
        S: DatagramSlots,
    {
        self.require_q_identity(body_id, BlockRole::OutgoingQBlock2)?;
        let issued = self.reissue_q_block2(body_id, num)?;
        self.finish_outgoing_tx(
            issued,
            body_id,
            tx_id,
            (ty, code, message_id),
            OutgoingBlockOpt::QBlock2,
        )
    }

    /// Encode an incoming Q-Block2 recover request into occupied TX `tx_id`.
    ///
    /// Writes one Q-Block2 option per known hole (ascending NUM, M unset;
    /// RFC 9177 §4.1 / §4.4 repeatable recover). Token and endpoint come from
    /// the incoming body sidecar. The caller supplies type, code, and Message
    /// ID (typically GET / FETCH). Does not include Observe (RFC 9177 §4.5).
    /// Incoming Q-Block1 recover is not encoded here — the caller owns any
    /// 4.08. Does not invent response codes.
    pub fn encode_q_block2_recover_tx(
        &mut self,
        recover: QBlockRecover,
        tx_id: SlotId,
        ty: Type,
        code: Code,
        message_id: MessageId,
    ) -> Result<usize, BlockTransferError>
    where
        S: DatagramSlots,
    {
        if recover.role() != BlockRole::IncomingQBlock2 {
            return Err(BlockTransferError::IdentityMismatch);
        }
        let transfer = self
            .storage
            .rx_body_transfer(recover.id())
            .ok_or(BlockTransferError::NoTransfer)?;
        if transfer.key() != recover.key() {
            return Err(BlockTransferError::IdentityMismatch);
        }
        const N: usize = BlockTransfer::MAX_PAYLOADS as usize;
        let mut encoded = [EncodedUint::new(0); N];
        let mut count = 0usize;
        let mut i = 0u32;
        while i < u32::from(BlockTransfer::MAX_PAYLOADS) {
            if recover.hole_mask() & (1u16 << i) != 0 {
                let num = recover.window_base() + i;
                encoded[count] = BlockValue::new(num, false, recover.szx())?.encode();
                count += 1;
            }
            i += 1;
        }
        if count == 0 {
            return Err(BlockTransferError::Gap);
        }
        let mut opts = OptionsBuilder::<N>::new();
        for item in encoded.iter().take(count) {
            opts.push(Opt::q_block2(item))
                .map_err(|_| BlockTransferError::Overflow)?;
        }
        let msg = Message::new(ty, code, message_id)
            .with_token(transfer.token())
            .with_options(opts.as_slice());
        let n = encode_occupied(self.storage.tx_payload_mut(tx_id), &msg).map_err(|e| match e {
            SlotMessageError::Slot(s) => BlockTransferError::Slot(s),
            SlotMessageError::Parse(p) => BlockTransferError::Parse(p),
            SlotMessageError::Encode(enc) => BlockTransferError::Encode(enc),
        })?;
        self.storage.set_tx_len(tx_id, n)?;
        self.storage.set_tx_endpoint(tx_id, transfer.endpoint())?;
        Ok(n)
    }

    fn reissue_q_outgoing(
        &self,
        id: SlotId,
        role: BlockRole,
        num: u32,
    ) -> Result<OutgoingBlock, BlockTransferError> {
        let transfer = self
            .storage
            .tx_body_transfer(id)
            .ok_or(BlockTransferError::NoTransfer)?;
        if transfer.role() != role {
            return Err(BlockTransferError::IdentityMismatch);
        }
        let (block, offset, len) = transfer.reissue_q_outgoing(num)?;
        Ok(OutgoingBlock::new(
            id,
            block,
            offset,
            len,
            transfer.is_complete(),
        ))
    }

    fn require_q_identity(&self, id: SlotId, role: BlockRole) -> Result<(), BlockTransferError> {
        let transfer = self
            .storage
            .tx_body_transfer(id)
            .ok_or(BlockTransferError::NoTransfer)?;
        if transfer.role() != role {
            return Err(BlockTransferError::IdentityMismatch);
        }
        let identity = transfer.identity();
        if identity.is_absent()
            || (role == BlockRole::OutgoingQBlock2
                && identity.as_slice().is_some_and(|tag| tag.is_empty()))
        {
            return Err(BlockTransferError::MissingIdentity);
        }
        Ok(())
    }

    fn apply_incoming_rx(
        &mut self,
        id: SlotId,
        which: RxBlockOpt,
    ) -> Result<BlockProgress, BlockTransferError>
    where
        S: DatagramSlots,
    {
        let endpoint = self.storage.rx_endpoint(id).ok_or(SlotError::NotOccupied)?;
        // Profile-sized copy so Constrained does not stack Default 1472.
        let mut tmp = S::RxScratch::default();
        let (token, block, expected, identity, binding, n) = {
            let parsed =
                crate::message::decode(self.storage.rx_payload(id).ok_or(SlotError::NotOccupied)?)?;
            let block = match which.read_block(&parsed) {
                Some(Ok(b)) => b,
                Some(Err(e)) => return Err(e.into()),
                None => return Err(BlockTransferError::MissingBlock),
            };
            let expected = if which.uses_size1() {
                match parsed.size1() {
                    Some(Ok(n)) => Some(n),
                    Some(Err(e)) => return Err(e.into()),
                    None => None,
                }
            } else {
                match parsed.size2() {
                    Some(Ok(n)) => Some(n),
                    Some(Err(e)) => return Err(e.into()),
                    None => None,
                }
            };
            if matches!(which, RxBlockOpt::QBlock1 | RxBlockOpt::QBlock2) && expected.is_none() {
                return Err(BlockTransferError::MissingSize);
            }
            let identity = which.read_identity(&parsed)?;
            match which {
                RxBlockOpt::QBlock1 if identity.is_absent() => {
                    return Err(BlockTransferError::MissingIdentity);
                }
                RxBlockOpt::QBlock2 if identity.as_slice().is_none_or(|tag| tag.is_empty()) => {
                    return Err(BlockTransferError::MissingIdentity);
                }
                _ => {}
            }
            let binding = if which.uses_size1() {
                Some(RequestBinding::from_message(&parsed)?)
            } else {
                None
            };
            let payload = parsed.payload();
            if payload.len() > tmp.as_ref().len() {
                return Err(BlockTransferError::PayloadLength);
            }
            tmp.as_mut()[..payload.len()].copy_from_slice(payload);
            (
                parsed.token(),
                block,
                expected,
                identity,
                binding,
                payload.len(),
            )
        };
        let key = BlockKey::new(token, endpoint).with_identity(identity);
        if let Some(binding) = binding {
            let role = if matches!(which, RxBlockOpt::Block1) {
                BlockRole::IncomingBlock1
            } else {
                BlockRole::IncomingQBlock1
            };
            let existing = self.lookup_rx_body_role(key, role).or_else(|| {
                (0..self.capacities().rx_body_slots.unwrap_or(0)).find_map(|i| {
                    let id = SlotId::from_index(i);
                    let transfer = self.storage.rx_body_transfer(id)?;
                    same_body_identity(transfer, key, role).then_some(id)
                })
            });
            if let Some(id) = existing {
                let transfer = self
                    .storage
                    .rx_body_transfer(id)
                    .ok_or(BlockTransferError::NoTransfer)?;
                if transfer.request_binding != Some(binding) {
                    return Err(BlockTransferError::IdentityMismatch);
                }
            }
        }
        let progress = match which {
            RxBlockOpt::Block1 => self.apply_block1(key, block, &tmp.as_ref()[..n], expected),
            RxBlockOpt::Block2 => self.apply_block2(key, block, &tmp.as_ref()[..n], expected),
            RxBlockOpt::QBlock1 => self.apply_q_block1(key, block, &tmp.as_ref()[..n], expected),
            RxBlockOpt::QBlock2 => self.apply_q_block2(key, block, &tmp.as_ref()[..n], expected),
        }?;
        if let Some(binding) = binding {
            let mut transfer = self
                .storage
                .rx_body_transfer(progress.id())
                .ok_or(BlockTransferError::NoTransfer)?;
            transfer.request_binding = Some(binding);
            if let Err(error) = self.storage.set_rx_body_transfer(progress.id(), transfer) {
                let _ = self.release_rx_body(progress.id());
                return Err(error.into());
            }
        }
        Ok(progress)
    }

    fn finish_outgoing_tx(
        &mut self,
        issued: OutgoingBlock,
        body_id: SlotId,
        tx_id: SlotId,
        header: (Type, Code, MessageId),
        which: OutgoingBlockOpt,
    ) -> Result<OutgoingBlock, BlockTransferError>
    where
        S: DatagramSlots,
    {
        self.finish_outgoing_tx_observe(issued, body_id, tx_id, header, which, None)
    }

    fn finish_outgoing_tx_observe(
        &mut self,
        issued: OutgoingBlock,
        body_id: SlotId,
        tx_id: SlotId,
        header: (Type, Code, MessageId),
        which: OutgoingBlockOpt,
        observe_seq: Option<u32>,
    ) -> Result<OutgoingBlock, BlockTransferError>
    where
        S: DatagramSlots,
    {
        let (ty, code, message_id) = header;
        let transfer = self
            .storage
            .tx_body_transfer(body_id)
            .ok_or(BlockTransferError::NoTransfer)?;
        let mut tmp = S::TxScratch::default();
        let payload = self
            .storage
            .tx_body_payload(body_id)
            .ok_or(SlotError::NotOccupied)?;
        let end = issued
            .offset()
            .checked_add(issued.len())
            .ok_or(BlockTransferError::Overflow)?;
        if end > payload.len() || issued.len() > tmp.as_ref().len() {
            return Err(BlockTransferError::Overflow);
        }
        tmp.as_mut()[..issued.len()].copy_from_slice(&payload[issued.offset()..end]);
        let encoded = issued.block().encode();
        let size_n = u32::try_from(transfer.filled()).map_err(|_| BlockTransferError::Overflow)?;
        let size = encode_uint(size_n);
        let identity = transfer.identity();
        let tag = identity.as_slice();
        let observe = observe_seq.map(crate::message::encode_observe);
        let mut opts = OptionsBuilder::<5>::new();
        if let Some(tag) = tag {
            match which {
                OutgoingBlockOpt::Block1 | OutgoingBlockOpt::QBlock1 => {
                    opts.push(Opt::request_tag(tag))
                        .map_err(|_| BlockTransferError::Overflow)?;
                }
                OutgoingBlockOpt::Block2 | OutgoingBlockOpt::QBlock2 => {
                    opts.push(Opt::etag(tag))
                        .map_err(|_| BlockTransferError::Overflow)?;
                }
            }
        }
        if let Some(ref obs) = observe {
            opts.push(Opt::observe(obs))
                .map_err(|_| BlockTransferError::Overflow)?;
        }
        match which {
            OutgoingBlockOpt::Block1 => {
                opts.push(Opt::block1(&encoded))
                    .map_err(|_| BlockTransferError::Overflow)?;
            }
            OutgoingBlockOpt::Block2 => {
                opts.push(Opt::block2(&encoded))
                    .map_err(|_| BlockTransferError::Overflow)?;
            }
            OutgoingBlockOpt::QBlock1 => {
                opts.push(Opt::q_block1(&encoded))
                    .map_err(|_| BlockTransferError::Overflow)?;
                opts.push(Opt::size1(&size))
                    .map_err(|_| BlockTransferError::Overflow)?;
            }
            OutgoingBlockOpt::QBlock2 => {
                opts.push(Opt::size2(&size))
                    .map_err(|_| BlockTransferError::Overflow)?;
                opts.push(Opt::q_block2(&encoded))
                    .map_err(|_| BlockTransferError::Overflow)?;
            }
        }
        let msg = Message::new(ty, code, message_id)
            .with_token(transfer.token())
            .with_options(opts.as_slice())
            .with_payload(&tmp.as_ref()[..issued.len()]);
        let n = encode_occupied(self.storage.tx_payload_mut(tx_id), &msg).map_err(|e| match e {
            SlotMessageError::Slot(s) => BlockTransferError::Slot(s),
            SlotMessageError::Parse(p) => BlockTransferError::Parse(p),
            SlotMessageError::Encode(enc) => BlockTransferError::Encode(enc),
        })?;
        self.storage.set_tx_len(tx_id, n)?;
        self.storage.set_tx_endpoint(tx_id, transfer.endpoint())?;
        Ok(issued)
    }

    fn ack_outgoing_rx(
        &mut self,
        body_id: SlotId,
        rx_id: SlotId,
        which: RxBlockOpt,
    ) -> Result<BlockProgress, BlockTransferError>
    where
        S: DatagramSlots,
    {
        let endpoint = self
            .storage
            .rx_endpoint(rx_id)
            .ok_or(SlotError::NotOccupied)?;
        let num = {
            let parsed = crate::message::decode(
                self.storage
                    .rx_payload(rx_id)
                    .ok_or(SlotError::NotOccupied)?,
            )?;
            if parsed.is_empty() {
                return Err(BlockTransferError::MissingBlock);
            }
            let block = match which.read_block(&parsed) {
                Some(Ok(b)) => b,
                Some(Err(e)) => return Err(e.into()),
                None => return Err(BlockTransferError::MissingBlock),
            };
            if matches!(which, RxBlockOpt::QBlock2) && !block.more() {
                return Err(BlockTransferError::Gap);
            }
            block.num()
        };
        let transfer = self
            .storage
            .tx_body_transfer(body_id)
            .ok_or(BlockTransferError::NoTransfer)?;
        if transfer.endpoint() != endpoint {
            return Err(BlockTransferError::IdentityMismatch);
        }
        match which {
            RxBlockOpt::QBlock1 => self.ack_q_block1(body_id, num),
            RxBlockOpt::QBlock2 => self.ack_q_block2(body_id, num),
            RxBlockOpt::Block1 | RxBlockOpt::Block2 => Err(BlockTransferError::IdentityMismatch),
        }
    }
}

#[derive(Clone, Copy)]
enum OutgoingBlockOpt {
    Block1,
    Block2,
    QBlock1,
    QBlock2,
}

#[derive(Clone, Copy)]
enum RxBlockOpt {
    Block1,
    Block2,
    QBlock1,
    QBlock2,
}

impl RxBlockOpt {
    fn uses_size1(self) -> bool {
        matches!(self, Self::Block1 | Self::QBlock1)
    }

    fn read_block(
        self,
        parsed: &ParsedMessage<'_>,
    ) -> Option<Result<BlockValue, crate::error::ValueError>> {
        match self {
            Self::Block1 => parsed.block1(),
            Self::Block2 => parsed.block2(),
            Self::QBlock1 => parsed.q_block1(),
            Self::QBlock2 => parsed.q_block2().next(),
        }
    }

    fn read_identity(self, parsed: &ParsedMessage<'_>) -> Result<BodyTag, BlockTransferError> {
        let first = match self {
            Self::Block1 | Self::QBlock1 => parsed.request_tag().next(),
            Self::Block2 | Self::QBlock2 => parsed.etag().next(),
        };
        BodyTag::from_first(first).map_err(BlockTransferError::from)
    }
}

#[inline]
fn decode_occupied(bytes: Option<&[u8]>) -> Result<ParsedMessage<'_>, SlotMessageError> {
    crate::message::decode(bytes.ok_or(SlotError::NotOccupied)?).map_err(SlotMessageError::Parse)
}

#[inline]
fn encode_occupied(buf: Option<&mut [u8]>, msg: &Message<'_>) -> Result<usize, SlotMessageError> {
    crate::message::encode(msg, buf.ok_or(SlotError::NotOccupied)?)
        .map_err(SlotMessageError::Encode)
}

fn copy_into_slot(buf: Option<&mut [u8]>, bytes: &[u8]) -> Result<(), SlotError> {
    let buf = buf.ok_or(SlotError::NotOccupied)?;
    if bytes.len() > buf.len() {
        return Err(SlotError::LengthExceedsSlot);
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}
