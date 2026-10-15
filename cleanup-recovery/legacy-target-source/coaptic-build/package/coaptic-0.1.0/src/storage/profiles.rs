//! Shipped [`MemoryProfile`] implementations.
//!
//! Slot and table counts below are modest starting numbers.

use super::exchange::ExchangeTable;
use super::memory::MemoryProfile;
use super::pool::{BodyPool, DatagramPool, DatagramScratch};
use super::table::{DedupTable, ObserveTable};

macro_rules! impl_profile {
    (
        $name:ident
        rx_dgram = $rx_n:expr, $rx_b:expr;
        tx_dgram = $tx_n:expr, $tx_b:expr;
        rx_body = $rxb_n:expr, $rxb_b:expr;
        tx_body = $txb_n:expr, $txb_b:expr;
        dedup = $dedup:expr;
        observe = $obs:expr;
    ) => {
        impl MemoryProfile for $name {
            const RX_DATAGRAM_SLOTS: usize = $rx_n;
            const RX_DATAGRAM_BYTES: usize = $rx_b;
            const TX_DATAGRAM_SLOTS: usize = $tx_n;
            const TX_DATAGRAM_BYTES: usize = $tx_b;
            const DEDUP_ENTRIES: usize = $dedup;
            const OBSERVE_ENTRIES: usize = $obs;
            const RX_BODY_SLOTS: usize = $rxb_n;
            const RX_BODY_BYTES: usize = $rxb_b;
            const TX_BODY_SLOTS: usize = $txb_n;
            const TX_BODY_BYTES: usize = $txb_b;

            type RxDatagram = DatagramPool<$rx_n, $rx_b>;
            type TxDatagram = DatagramPool<$tx_n, $tx_b>;
            type RxBody = BodyPool<$rxb_n, $rxb_b>;
            type TxBody = BodyPool<$txb_n, $txb_b>;
            type Dedup = DedupTable<$dedup>;
            type Observe = ObserveTable<$obs>;
            type Exchange = ExchangeTable<$tx_n>;
            type RxScratch = DatagramScratch<$rx_b>;
            type TxScratch = DatagramScratch<$tx_b>;
        }

        const _: () = {
            assert!($rxb_n > 0 && $txb_n > 0);
            assert!($rxb_b > 0 && $txb_b > 0);
            assert!($rxb_b % 1024 == 0 && $txb_b % 1024 == 0);
        };
    };
}

/// Default capacity profile.
///
/// | Area | Count | Bytes |
/// | --- | ---: | ---: |
/// | RX / TX datagram | 4 | **1472** |
/// | RX / TX body (block-wise enabled only) | 2 | **4096** (= 4 × 1024) |
/// | Dedup entries | 8 | compact replay + optional TX pin |
/// | Observe entries | 4 | — |
///
/// 1472 is IPv4 UDP max on Ethernet (`1500 − 20 − 8`). 4096 is four max-size
/// Block/Q-Block blocks.
pub struct Default;

impl_profile! {
    Default
    rx_dgram = 4, 1472;
    tx_dgram = 4, 1472;
    rx_body = 2, 4096;
    tx_body = 2, 4096;
    dedup = 8;
    observe = 4;
}

/// Constrained / unknown-PMTU profile ([RFC 7252] §4.6 **1152**).
///
/// | Area | Count | Bytes |
/// | --- | ---: | ---: |
/// | RX / TX datagram | 2 | **1152** |
/// | RX / TX body (block-wise enabled only) | 1 | 4096 |
/// | Dedup entries | 4 | compact replay + optional TX pin |
/// | Observe entries | 2 | — |
///
/// Body bytes are not locked for this profile; 4096 is used when block-wise is
/// enabled so the same quantum as [`struct@Default`] applies. `.block_wise(false)`
/// still omits body pools entirely.
///
/// [RFC 7252]: https://www.rfc-editor.org/rfc/rfc7252#section-4.6
pub struct Constrained;

impl_profile! {
    Constrained
    rx_dgram = 2, 1152;
    tx_dgram = 2, 1152;
    rx_body = 1, 4096;
    tx_body = 1, 4096;
    dedup = 4;
    observe = 2;
}
