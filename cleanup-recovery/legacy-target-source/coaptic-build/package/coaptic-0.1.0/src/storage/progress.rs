//! Bounded [`Progress`] from one [`Engine::progress`] invocation.
//!
//! One call is bounded: at most one retransmit, one unpinned RX step, one
//! Observe notify, one Observe lifetime expiry, and one Q-Block recover.
//! Empty RX / TX / Observe / incoming-body tables skip their scans
//! ([`super::SlotPool::is_empty`]).

use super::BodySlots;
use super::DatagramSlots;
use super::Engine;
use super::Metrics;
use super::ObserveExpiry;
use super::ObserveSlots;
use super::PendingCons;
use super::QBlockRecover;
use super::Retransmit;
use super::SlotId;
use super::Storage;
use super::engine::endpoint_notify_held;
use crate::message::Transmission;

/// Outcome of one bounded [`Engine::progress`] pass.
///
/// Idle when [`Self::is_idle`]. Q-Block missing-block recovery is at most
/// one [`QBlockRecover`] from a rotating Incoming Body Pool step. Observe
/// lifetime expiry is at most one [`ObserveExpiry`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Progress {
    retransmit: Option<Retransmit>,
    rx_ready: Option<SlotId>,
    observe_notify: Option<SlotId>,
    observe_expired: Option<ObserveExpiry>,
    qblock_recover: Option<QBlockRecover>,
}

impl Progress {
    /// No retransmit, no RX slot, and no later-domain work.
    #[must_use]
    pub const fn idle() -> Self {
        Self {
            retransmit: None,
            rx_ready: None,
            observe_notify: None,
            observe_expired: None,
            qblock_recover: None,
        }
    }

    /// Whether this pass reported no work.
    #[must_use]
    pub const fn is_idle(self) -> bool {
        self.retransmit.is_none()
            && self.rx_ready.is_none()
            && self.observe_notify.is_none()
            && self.observe_expired.is_none()
            && self.qblock_recover.is_none()
    }

    /// Due CON retransmit or give-up from [`Engine::poll_retransmit`].
    ///
    /// The core does not send. [`crate::App::poll`] sends
    /// [`Retransmit::Due`] and releases [`Retransmit::GiveUp`]. GiveUp
    /// already cleared pending; the TX slot stays occupied so the caller
    /// can release it.
    #[must_use]
    pub const fn retransmit(self) -> Option<Retransmit> {
        self.retransmit
    }

    /// One occupied RX datagram that is not pinned, if any.
    ///
    /// Decode readiness only: the caller may [`Engine::decode_rx`]. This pass
    /// does not release the slot and does not dispatch to the application.
    #[must_use]
    pub const fn rx_ready(self) -> Option<SlotId> {
        self.rx_ready
    }

    /// One Observe interest due for a notification, if any.
    ///
    /// [`Engine::signal_observe`] marks the row pending. This pass surfaces
    /// at most one pending row (rotating, fair) whose remote endpoint is
    /// below notification NSTART, assigns the next 24-bit sequence, and
    /// clears pending. [`Engine::record_observe_notify`] starts the §4.5
    /// hold. The caller encodes a notification into a TX datagram with
    /// existing Observe option helpers and [`super::Access`] (ordinary
    /// datagram or outgoing Block2). This pass does not queue a body in the
    /// Observe table, acquire TX, or invent a resource payload. See
    /// `knowledge/rfcs/rfc7641.txt`.
    #[must_use]
    pub const fn observe_notify(self) -> Option<SlotId> {
        self.observe_notify
    }

    /// One Observe interest whose colocated lifetime is due, if any.
    ///
    /// [`Engine::refresh_observe_max_age`] sets Max-Age or CON-wait.
    /// This pass surfaces at most one due row (rotating, fair), clears that
    /// lifetime and pending, and leaves the row occupied. The caller drops
    /// it or stops notifying. Does not send RST or invent 4.02. A
    /// [`Retransmit::GiveUp`] for a matching CON notify makes that row due
    /// before this poll. See `knowledge/rfcs/rfc7641.txt`.
    #[must_use]
    pub const fn observe_expired(self) -> Option<ObserveExpiry> {
        self.observe_expired
    }

    /// One incoming Q-Block recover opportunity, if any.
    ///
    /// At most one per pass, from a rotating Incoming Body Pool step, and
    /// only when [`super::QBlockReceiveWait`] is due at the caller `now_ms`
    /// (`NON_RECEIVE_TIMEOUT`, doubled after each recover). The caller
    /// encodes a recover request (repeatable Q-Block2) or owns any 4.08
    /// (Q-Block1). This pass does not send, acquire TX, or invent 4.08 /
    /// 2.31 / RST. After [`crate::message::QBlockTransmission::NON_MAX_RETRANSMIT`]
    /// recovers without a filling receive, this pass releases the partial
    /// body and returns `None`. `.block_wise(false)` stays `None`. See
    /// `knowledge/rfcs/rfc9177.txt` §7.2.
    #[must_use]
    pub const fn qblock_recover(self) -> Option<QBlockRecover> {
        self.qblock_recover
    }
}

impl<S: Storage + DatagramSlots + PendingCons + ObserveSlots + BodySlots> Engine<S> {
    /// One bounded progress invocation.
    ///
    /// Caller supplies `now_ms` (no OS clock). Each call:
    ///
    /// 1. [`Self::poll_retransmit`] — at most one due CON (`Due` / `GiveUp`).
    /// 2. One rotating RX step from the pool cursor: first occupied slot
    ///    that is not pinned. The cursor resumes after that slot.
    /// 3. Observe lifetime — at most one due Max-Age / client-OFF row
    ///    ([`Progress::observe_expired`]). A [`Retransmit::GiveUp`] for a
    ///    matching CON notify makes that row due first.
    /// 4. Observe notify — at most one pending interest from the Observe
    ///    table cursor whose endpoint is below notification NSTART
    ///    ([`Progress::observe_notify`]).
    /// 5. Q-Block missing-block recovery — at most one incoming window
    ///    hole whose [`super::QBlockReceiveWait`] is due
    ///    ([`Progress::qblock_recover`]). Unarmed holes are armed from
    ///    `now_ms` and do not fire on this pass.
    ///
    /// Does not allocate, grow storage, or send on the wire
    /// ([`crate::App::poll`] sends a due CON). Does not release
    /// pinned slots (except a Q-Block body exhausted after
    /// `NON_MAX_RETRANSMIT`). Does not invent 4.02 / RST / 2.31 / 4.08 policy.
    /// Empty tables are skipped in O(1) via [`super::SlotPool::occupied_count`]
    /// (CON / Observe / Q-Block scans run only while that area is occupied).
    pub fn progress(&mut self, now_ms: u64) -> Progress {
        self.progress_inner(now_ms, true)
    }

    // App reserves a pending candidate without consuming its signal. Ingress
    // may cancel or replace the relation before App claims that candidate.
    // A newly registered row is never pending, even if it reuses this slot.
    // Q recovery/expiry also waits until ingress can fill its missing blocks.
    pub(crate) fn progress_before_dispatch(&mut self, now_ms: u64) -> Progress {
        self.progress_inner(now_ms, false)
    }

    pub(crate) fn claim_observe_notification(&mut self, id: SlotId, now_ms: u64) -> Option<SlotId> {
        let mut interest = self.observe_interest(id)?;
        if interest.key().is_client()
            || !interest.is_pending()
            || endpoint_notify_held(self.storage(), interest.endpoint(), now_ms)
                >= usize::from(Transmission::NSTART)
        {
            return None;
        }
        interest.take_due()?;
        self.storage_mut().set_observe_interest(id, interest).ok()?;
        Some(id)
    }

    pub(crate) fn next_qblock_recovery(
        &mut self,
        now_ms: u64,
    ) -> (Option<QBlockRecover>, Option<super::ExchangeKey>) {
        let mut expired = None;
        let recover = progress_qblock(self, now_ms, &mut expired);
        (recover, expired)
    }

    fn progress_inner(&mut self, now_ms: u64, immediate_later_work: bool) -> Progress {
        Metrics::inc(&mut self.metrics_mut().progress);
        let rx_busy = !self.storage_mut().rx_datagram().is_empty();
        let tx_busy = !self.storage_mut().tx_datagram().is_empty();
        let observe_busy = !self.storage_mut().observe().is_empty();
        let qblock_busy = self
            .storage_mut()
            .rx_body()
            .is_some_and(|pool| !pool.is_empty());
        if !rx_busy && !tx_busy && !observe_busy && !qblock_busy {
            return Progress::idle();
        }
        let retransmit = if tx_busy {
            self.poll_retransmit(now_ms)
        } else {
            None
        };
        if let Some(Retransmit::GiveUp(pending)) = retransmit {
            let _ = self.mark_observe_unacked_due(pending.message_id(), pending.endpoint(), now_ms);
        }
        let rx_ready = if rx_busy {
            next_unpinned_rx(self)
        } else {
            None
        };
        let observe_expired = if observe_busy {
            self.poll_observe_lifetime(now_ms)
        } else {
            None
        };
        Progress {
            retransmit,
            rx_ready,
            observe_notify: if observe_busy {
                progress_observe(self, now_ms, immediate_later_work)
            } else {
                None
            },
            observe_expired,
            qblock_recover: if qblock_busy && immediate_later_work {
                progress_qblock(self, now_ms, &mut None)
            } else {
                None
            },
        }
    }
}

/// First pending Observe interest starting at the rotating cursor.
///
/// Assigns the next 24-bit sequence and clears pending on the surfaced row.
/// Advances the cursor past that slot so the next call does not restart at
/// slot zero. Does not acquire TX or write a notification body.
fn progress_observe<S: Storage + ObserveSlots>(
    engine: &mut Engine<S>,
    now_ms: u64,
    select_notification: bool,
) -> Option<SlotId> {
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
        if interest.key().is_client() || !interest.is_pending() {
            continue;
        }
        if endpoint_notify_held(engine.storage(), interest.endpoint(), now_ms)
            >= usize::from(Transmission::NSTART)
        {
            continue;
        }
        if !select_notification {
            engine.advance_observe(offset + 1);
            return Some(id);
        }
        if interest.take_due().is_none() {
            continue;
        }
        found = Some((id, offset, interest));
        break;
    }
    match found {
        Some((id, offset, interest)) => {
            engine
                .storage_mut()
                .set_observe_interest(id, interest)
                .ok()?;
            engine.advance_observe(offset + 1);
            Some(id)
        }
        None => None,
    }
}

/// First incoming Q-Block window whose receive wait is due, starting at the
/// body cursor.
///
/// Unarmed holes are armed from `now_ms` ([`super::QBlockReceiveWait::new`])
/// and skipped this pass. A due wait that has already sent
/// [`crate::message::QBlockTransmission::NON_MAX_RETRANSMIT`] recovers
/// releases that partial body (one give-up per pass). Advances the Incoming
/// Body Pool cursor past a fired or given-up slot. Does not acquire TX or
/// encode a recover request. Absent body pools yield `None`.
fn progress_qblock<S: Storage + BodySlots>(
    engine: &mut Engine<S>,
    now_ms: u64,
    client_expired: &mut Option<super::ExchangeKey>,
) -> Option<QBlockRecover> {
    if engine
        .storage_mut()
        .rx_body()
        .is_none_or(|pool| pool.is_empty())
    {
        return None;
    }
    let n = engine.storage_mut().rx_body()?.slot_count();
    if n == 0 {
        return None;
    }
    let start = engine.storage_mut().rx_body()?.cursor();
    let mut found = None;
    let mut give_up = None;
    for offset in 0..n {
        let id = SlotId::from_index((start + offset) % n);
        let Some(mut transfer) = engine.rx_body_transfer(id) else {
            continue;
        };
        let Some((missing_num, hole_mask)) = transfer.q_holes() else {
            continue;
        };
        let Some(wait) = transfer.q_receive() else {
            transfer.note_q_receive(now_ms);
            let _ = engine.storage_mut().set_rx_body_transfer(id, transfer);
            continue;
        };
        if !wait.is_due(now_ms) {
            continue;
        }
        if transfer.note_q_recover(now_ms).is_none() {
            let client = (transfer.role() == super::BlockRole::IncomingQBlock2).then_some(
                super::ExchangeKey::new(transfer.key().token(), transfer.endpoint()),
            );
            give_up = Some((id, offset, client));
            break;
        }
        if engine
            .storage_mut()
            .set_rx_body_transfer(id, transfer)
            .is_err()
        {
            continue;
        }
        found = Some((
            offset,
            QBlockRecover::new(
                id,
                transfer.key(),
                transfer.role(),
                missing_num,
                hole_mask,
                transfer.window_base(),
                transfer.szx(),
            ),
        ));
        break;
    }
    if let Some((id, offset, client)) = give_up {
        *client_expired = client;
        let _ = engine.release_rx_body(id);
        engine.advance_rx_body(offset + 1);
        return None;
    }
    match found {
        Some((offset, recover)) => {
            engine.advance_rx_body(offset + 1);
            Some(recover)
        }
        None => None,
    }
}

/// First occupied, unpinned RX slot starting at the rotating cursor.
///
/// Advances the cursor past the visited slot (or by one when every occupied
/// slot is pinned) so the next call does not restart at slot zero.
fn next_unpinned_rx<S: Storage>(engine: &mut Engine<S>) -> Option<SlotId> {
    if engine.storage_mut().rx_datagram().is_empty() {
        return None;
    }
    let n = engine.storage_mut().rx_datagram().slot_count();
    if n == 0 {
        return None;
    }
    let start = engine.storage_mut().rx_datagram().cursor();
    let mut found = None;
    for offset in 0..n {
        let id = SlotId::from_index((start + offset) % n);
        let pool = engine.storage_mut().rx_datagram();
        if pool.is_occupied(id) && !pool.is_pinned(id) {
            found = Some((id, offset));
            break;
        }
    }
    match found {
        Some((id, offset)) => {
            engine.advance_rx(offset + 1);
            Some(id)
        }
        None => {
            if engine.storage_mut().rx_datagram().occupied_count() > 0 {
                engine.rotate_rx();
            }
            None
        }
    }
}
