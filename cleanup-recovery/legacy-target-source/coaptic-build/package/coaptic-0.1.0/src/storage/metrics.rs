//! Cheap wrapping counters at Engine / reactor hot sites.
//!
//! Always present (`no_std`, no allocator). One [`Metrics`] is 16 × `u32`
//! (64 bytes) on [`crate::storage::Engine`]. Overflow wraps; there is no
//! tracing or OTLP. Copy with [`Engine::metrics`](crate::storage::Engine::metrics)
//! or [`crate::App::metrics`], optionally
//! [`Engine::reset_metrics`](crate::storage::Engine::reset_metrics), then
//! print from a `std` dogfood bin:
//!
//! ```
//! # use coaptic::storage::{EngineBuilder, Memory, profiles};
//! let mut engine = EngineBuilder::new()
//!     .profile::<profiles::Default>()
//!     .block_wise(false)
//!     .build(Memory::<profiles::Default>::new())
//!     .unwrap();
//! let snap = engine.metrics();
//! assert_eq!(snap, coaptic::storage::Metrics::ZERO);
//! engine.reset_metrics();
//! ```

use crate::error::BlockTransferError;

/// Reactor counters copied from [`crate::storage::Engine`].
///
/// Fields are public so a dogfood bin can print or diff a snapshot
/// (`--compare` against `crates/coaptic-plugtest/baselines/`). Values
/// wrap on overflow (`wrapping_add`). Idle polls still increment
/// [`Self::progress`] when [`crate::storage::Engine::progress`] runs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Metrics {
    /// Datagrams stored by [`crate::storage::Engine::recv_from`].
    pub rx_accepted: u32,
    /// RX IO/slot failure, or an occupied datagram dropped as malformed.
    pub rx_error: u32,
    /// Successful [`crate::storage::Engine::send_tx`].
    pub tx_ok: u32,
    /// Failed [`crate::storage::Engine::send_tx`].
    pub tx_fail: u32,
    /// CON retransmit scheduled ([`crate::storage::Retransmit::Due`]).
    pub con_retransmit: u32,
    /// CON give-up ([`crate::storage::Retransmit::GiveUp`]).
    pub give_up: u32,
    /// Observe notification recorded as sent.
    pub observe_notify: u32,
    /// Observe interest inserted (register).
    pub observe_register: u32,
    /// Observe interest removed (deregister, DELETE, or RST drop).
    pub observe_cancel: u32,
    /// Successful incoming Block1 / Q-Block1 assemble step.
    pub block1_assemble: u32,
    /// Successful incoming Block2 / Q-Block2 assemble step.
    pub block2_assemble: u32,
    /// [`crate::storage::Engine::progress`] invocations.
    pub progress: u32,
    /// Pool or table acquire miss (RX/TX/body/Observe insert).
    pub saturated: u32,
    /// NSTART reject (pending CON or notification hold).
    pub nstart_reject: u32,
    /// Empty ACK path ([`crate::storage::Engine::match_empty_ack_rst`]).
    pub empty_ack: u32,
    /// Empty RST path ([`crate::storage::Engine::match_empty_ack_rst`]).
    pub empty_rst: u32,
}

impl Metrics {
    /// All counters zero.
    pub const ZERO: Self = Self {
        rx_accepted: 0,
        rx_error: 0,
        tx_ok: 0,
        tx_fail: 0,
        con_retransmit: 0,
        give_up: 0,
        observe_notify: 0,
        observe_register: 0,
        observe_cancel: 0,
        block1_assemble: 0,
        block2_assemble: 0,
        progress: 0,
        saturated: 0,
        nstart_reject: 0,
        empty_ack: 0,
        empty_rst: 0,
    };

    #[inline]
    pub(crate) fn inc(slot: &mut u32) {
        *slot = slot.wrapping_add(1);
    }

    #[inline]
    pub(crate) fn tally_block(&mut self, result: Result<(), &BlockTransferError>, block1: bool) {
        match result {
            Ok(()) => {
                if block1 {
                    Self::inc(&mut self.block1_assemble);
                } else {
                    Self::inc(&mut self.block2_assemble);
                }
            }
            Err(BlockTransferError::Saturated) => Self::inc(&mut self.saturated),
            Err(_) => {}
        }
    }
}

impl core::fmt::Display for Metrics {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "rx_accepted={} rx_error={} tx_ok={} tx_fail={} con_retransmit={} give_up={} observe_notify={} observe_register={} observe_cancel={} block1_assemble={} block2_assemble={} progress={} saturated={} nstart_reject={} empty_ack={} empty_rst={}",
            self.rx_accepted,
            self.rx_error,
            self.tx_ok,
            self.tx_fail,
            self.con_retransmit,
            self.give_up,
            self.observe_notify,
            self.observe_register,
            self.observe_cancel,
            self.block1_assemble,
            self.block2_assemble,
            self.progress,
            self.saturated,
            self.nstart_reject,
            self.empty_ack,
            self.empty_rst
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Metrics;

    #[test]
    fn zero_copy_and_inc() {
        let mut snap = Metrics::ZERO;
        assert_eq!(snap, Metrics::default());
        Metrics::inc(&mut snap.rx_accepted);
        assert_eq!(snap.rx_accepted, 1);
        let copy = snap;
        assert_eq!(copy.rx_accepted, 1);
        assert_eq!(copy.progress, 0);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn display_lists_counters() {
        extern crate alloc;
        use alloc::string::ToString;

        let snap = Metrics {
            rx_accepted: 2,
            progress: 3,
            ..Metrics::ZERO
        };
        let text = snap.to_string();
        assert!(text.contains("rx_accepted=2"));
        assert!(text.contains("progress=3"));
        assert!(text.contains("empty_rst=0"));
    }
}
