//! [`DatagramIo`]: first-class bind from any datagram transport into Engine slots.
//!
//! This trait moves bytes between the platform boundary and Datagram Slots.
//! The core still does not own a socket, clock, or send policy.

use super::DatagramSlots;
use super::Endpoint;
use super::Engine;
use super::Metrics;
use super::SlotError;
use super::SlotId;
use super::Storage;

/// Caller-owned datagram transport (UDP, test loopback, or a `no_std` radio).
///
/// Implement this on the socket or driver, then
/// [`crate::app::AppBuilder::bind`]. [`Engine::recv_from`] and
/// [`Engine::send_tx`] are the Engine-side bind. The core does not own a
/// socket. `recv` writes into the caller buffer; `Ok(None)` is idle
/// (timeout or would-block).
pub trait DatagramIo {
    /// Transport-specific failure. Not a CoAP code.
    type Error;

    /// Receive one datagram into `buf`.
    ///
    /// `Ok(None)` is idle. `Ok(Some((n, endpoint)))` fills `buf[..n]` and
    /// names the remote peer. `n` must not exceed `buf.len()`. Success must
    /// represent the complete datagram: refuse oversized packets rather than
    /// returning a truncated prefix.
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error>;

    /// Send one complete datagram to `dest`; success must report `bytes.len()`.
    fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error>;
}

/// Failure of [`Engine::recv_from`] / [`Engine::send_tx`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramIoError<E> {
    /// Incoming Datagram Pool is full. The transport datagram is not consumed.
    Saturated,
    /// Slot addressing or fill-length failure.
    Slot(SlotError),
    /// Transport reported a byte count different from the complete datagram.
    SendLength {
        /// Datagram length requested.
        expected: usize,
        /// Byte count reported by the transport.
        actual: usize,
    },
    /// Error from [`DatagramIo::Error`].
    Io(E),
}

impl<E> From<SlotError> for DatagramIoError<E> {
    fn from(e: SlotError) -> Self {
        Self::Slot(e)
    }
}

impl<E> core::fmt::Display for DatagramIoError<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Saturated => f.write_str("incoming datagram pool is saturated"),
            Self::Slot(e) => write!(f, "{e}"),
            Self::SendLength { expected, actual } => write!(
                f,
                "datagram send reported {actual} bytes; expected {expected}"
            ),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for DatagramIoError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Saturated | Self::SendLength { .. } => None,
            Self::Slot(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}

impl<S: Storage + DatagramSlots> Engine<S> {
    /// Recv one datagram from `io` into a newly acquired RX slot.
    ///
    /// `Ok(None)` is an idle poll ([`DatagramIo::recv`] returned `None`); the
    /// slot is released. `Err(Saturated)` leaves the transport unread.
    /// Does not call [`Self::progress`] and does not send.
    pub fn recv_from<T: DatagramIo>(
        &mut self,
        io: &mut T,
    ) -> Result<Option<SlotId>, DatagramIoError<T::Error>> {
        let id = self.acquire_rx().ok_or(DatagramIoError::Saturated)?;
        let outcome = match self.storage_mut().rx_payload_mut(id) {
            Some(buf) => io.recv(buf),
            None => {
                let _ = self.release_rx(id);
                Metrics::inc(&mut self.metrics_mut().rx_error);
                return Err(DatagramIoError::Slot(SlotError::NotOccupied));
            }
        };
        match outcome {
            Ok(Some((n, endpoint))) => {
                if let Err(e) = self.storage_mut().set_rx_len(id, n) {
                    let _ = self.release_rx(id);
                    Metrics::inc(&mut self.metrics_mut().rx_error);
                    return Err(DatagramIoError::Slot(e));
                }
                if let Err(e) = self.storage_mut().set_rx_endpoint(id, endpoint) {
                    let _ = self.release_rx(id);
                    Metrics::inc(&mut self.metrics_mut().rx_error);
                    return Err(DatagramIoError::Slot(e));
                }
                Metrics::inc(&mut self.metrics_mut().rx_accepted);
                Ok(Some(id))
            }
            Ok(None) => {
                let _ = self.release_rx(id);
                Ok(None)
            }
            Err(e) => {
                let _ = self.release_rx(id);
                Metrics::inc(&mut self.metrics_mut().rx_error);
                Err(DatagramIoError::Io(e))
            }
        }
    }

    /// Send occupied TX `id` through `io`. Pins [`Access`](crate::storage::Access) for the call.
    ///
    /// Does not release the slot (pending CON / give-up still apply). Does
    /// not invent RST / 4.xx / No-Response policy.
    pub fn send_tx<T: DatagramIo>(
        &mut self,
        io: &mut T,
        id: SlotId,
    ) -> Result<usize, DatagramIoError<T::Error>> {
        let dest = match self.tx_endpoint(id) {
            Some(dest) => dest,
            None => {
                Metrics::inc(&mut self.metrics_mut().tx_fail);
                return Err(DatagramIoError::Slot(SlotError::NotOccupied));
            }
        };
        let outcome = match self.access_tx(id) {
            Ok(access) => {
                let bytes = access.as_bytes();
                io.send(dest, bytes)
                    .map_err(DatagramIoError::Io)
                    .and_then(|actual| {
                        if actual == bytes.len() {
                            Ok(actual)
                        } else {
                            Err(DatagramIoError::SendLength {
                                expected: bytes.len(),
                                actual,
                            })
                        }
                    })
            }
            Err(e) => Err(DatagramIoError::Slot(e)),
        };
        match outcome {
            Ok(n) => {
                Metrics::inc(&mut self.metrics_mut().tx_ok);
                Ok(n)
            }
            Err(e) => {
                Metrics::inc(&mut self.metrics_mut().tx_fail);
                Err(e)
            }
        }
    }
}

/// Receives into scratch with one extra byte so exact-capacity datagrams are
/// accepted and oversized datagrams cannot become valid-looking prefixes.
/// Uses default-profile-sized stack scratch; larger caller buffers use a
/// fallible temporary allocation of `buf.len() + 1` bytes. Native receive errors
/// (including platform-specific truncation errors) are preserved.
#[cfg(feature = "std")]
impl DatagramIo for std::net::UdpSocket {
    type Error = std::io::Error;

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        const STACK_BYTES: usize =
            <super::profiles::Default as super::MemoryProfile>::RX_DATAGRAM_BYTES + 1;
        let required = buf.len().checked_add(1).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "receive buffer too large")
        })?;
        let mut stack = [0; STACK_BYTES];
        let mut heap = std::vec::Vec::new();
        let scratch = if required <= stack.len() {
            &mut stack[..required]
        } else {
            heap.try_reserve_exact(required)
                .map_err(std::io::Error::other)?;
            heap.resize(required, 0);
            heap.as_mut_slice()
        };
        match self.recv_from(scratch) {
            Ok((n, _)) if n > buf.len() => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "datagram exceeds receive capacity",
            )),
            Ok((n, from)) => {
                buf[..n].copy_from_slice(&scratch[..n]);
                Ok(Some((n, Endpoint::from(from))))
            }
            Err(e) if is_idle_io(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.send_to(bytes, std::net::SocketAddr::from(dest))
    }
}

#[cfg(feature = "std")]
fn is_idle_io(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::DatagramIo;
    use super::DatagramIoError;
    use super::Endpoint;
    use crate::message::{Code, Message, MessageId, Type, encode};
    use crate::storage::EngineBuilder;
    use crate::storage::Memory;
    use crate::storage::profiles;

    #[derive(Default)]
    struct Loopback {
        inbox: Option<(Endpoint, [u8; 64], usize)>,
        last_send: Option<(Endpoint, [u8; 64], usize)>,
    }

    impl DatagramIo for Loopback {
        type Error = &'static str;

        fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
            let Some((ep, bytes, n)) = self.inbox.take() else {
                return Ok(None);
            };
            if n > buf.len() {
                return Err("short buf");
            }
            buf[..n].copy_from_slice(&bytes[..n]);
            Ok(Some((n, ep)))
        }

        fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
            if bytes.len() > 64 {
                return Err("too long");
            }
            let mut slot = [0u8; 64];
            slot[..bytes.len()].copy_from_slice(bytes);
            self.last_send = Some((dest, slot, bytes.len()));
            Ok(bytes.len())
        }
    }

    fn encode_empty_ack() -> ([u8; 64], usize) {
        let msg = Message::empty_ack(MessageId::new(7));
        let mut buf = [0u8; 64];
        let n = encode(&msg, &mut buf).expect("ack");
        (buf, n)
    }

    #[test]
    fn recv_from_stores_endpoint_and_idle_releases() {
        let mut engine = EngineBuilder::new()
            .profile::<profiles::Default>()
            .block_wise(false)
            .build(Memory::<profiles::Default>::new())
            .expect("build");
        let peer = Endpoint::v4([192, 0, 2, 1], 5683);
        let (wire, n) = encode_empty_ack();
        let mut io = Loopback {
            inbox: Some((peer, wire, n)),
            last_send: None,
        };
        let rx = engine.recv_from(&mut io).expect("recv").expect("stored");
        assert_eq!(engine.metrics().rx_accepted, 1);
        assert_eq!(engine.metrics().rx_error, 0);
        assert_eq!(engine.rx_endpoint(rx), Some(peer));
        let parsed = engine.decode_rx(rx).expect("decode");
        assert_eq!(parsed.code(), Code::EMPTY);
        assert_eq!(parsed.ty(), Type::Acknowledgement);
        engine.release_rx(rx).expect("release");

        assert_eq!(engine.recv_from(&mut io).expect("idle"), None);
        assert_eq!(engine.rx_occupied(), 0);
        assert_eq!(engine.metrics().rx_accepted, 1);
    }

    #[test]
    fn send_tx_uses_sidecar_endpoint() {
        let mut engine = EngineBuilder::new()
            .profile::<profiles::Default>()
            .block_wise(false)
            .build(Memory::<profiles::Default>::new())
            .expect("build");
        let dest = Endpoint::v4([192, 0, 2, 9], 5683);
        let (wire, n) = encode_empty_ack();
        let tx = engine.acquire_tx().expect("tx");
        engine.write_tx(tx, &wire[..n], dest).expect("write_tx");
        let mut io = Loopback::default();
        let sent = engine.send_tx(&mut io, tx).expect("send_tx");
        assert_eq!(sent, n);
        assert_eq!(engine.metrics().tx_ok, 1);
        assert_eq!(engine.metrics().tx_fail, 0);
        let (got_ep, got, got_n) = io.last_send.expect("sent");
        assert_eq!(got_ep, dest);
        assert_eq!(&got[..got_n], &wire[..n]);
        engine.release_tx(tx).expect("release");
    }

    #[test]
    fn recv_from_saturated_does_not_consume() {
        let mut engine = EngineBuilder::new()
            .profile::<profiles::Default>()
            .block_wise(false)
            .build(Memory::<profiles::Default>::new())
            .expect("build");
        while engine.acquire_rx().is_some() {}
        engine.reset_metrics();
        let peer = Endpoint::v4([192, 0, 2, 1], 5683);
        let (wire, n) = encode_empty_ack();
        let mut io = Loopback {
            inbox: Some((peer, wire, n)),
            last_send: None,
        };
        assert_eq!(engine.recv_from(&mut io), Err(DatagramIoError::Saturated));
        assert_eq!(engine.metrics().saturated, 1);
        assert!(io.inbox.is_some());
    }

    #[test]
    fn send_length_failure_retains_datagram_for_complete_retry() {
        struct Count(usize);
        impl DatagramIo for Count {
            type Error = &'static str;
            fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
                Ok(None)
            }
            fn send(&mut self, _: Endpoint, _: &[u8]) -> Result<usize, Self::Error> {
                Ok(self.0)
            }
        }
        let mut engine = EngineBuilder::new()
            .profile::<profiles::Default>()
            .block_wise(false)
            .build(Memory::<profiles::Default>::new())
            .unwrap();
        let (wire, n) = encode_empty_ack();
        let tx = engine.acquire_tx().unwrap();
        let dest = Endpoint::v4([192, 0, 2, 9], 5683);
        engine.write_tx(tx, &wire[..n], dest).unwrap();
        for actual in [0, n - 1, n + 1, usize::MAX] {
            assert_eq!(
                engine.send_tx(&mut Count(actual), tx),
                Err(DatagramIoError::SendLength {
                    expected: n,
                    actual
                })
            );
            assert_eq!(engine.access_tx(tx).unwrap().as_bytes(), &wire[..n]);
            assert_eq!(engine.tx_endpoint(tx), Some(dest));
        }
        assert_eq!(engine.metrics().tx_ok, 0);
        assert_eq!(engine.metrics().tx_fail, 4);
        assert_eq!(engine.send_tx(&mut Count(n), tx), Ok(n));
        assert_eq!(engine.metrics().tx_ok, 1);
        engine.release_tx(tx).unwrap();
    }

    #[test]
    fn send_tx_fail_increments_tx_fail() {
        let mut engine = EngineBuilder::new()
            .profile::<profiles::Default>()
            .block_wise(false)
            .build(Memory::<profiles::Default>::new())
            .expect("build");
        let dest = Endpoint::v4([192, 0, 2, 9], 5683);
        let (wire, n) = encode_empty_ack();
        let tx = engine.acquire_tx().expect("tx");
        engine.write_tx(tx, &wire[..n], dest).expect("write_tx");
        struct FailSend;
        impl DatagramIo for FailSend {
            type Error = &'static str;
            fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
                Ok(None)
            }
            fn send(&mut self, _: Endpoint, _: &[u8]) -> Result<usize, Self::Error> {
                Err("nope")
            }
        }
        assert!(engine.send_tx(&mut FailSend, tx).is_err());
        assert_eq!(engine.metrics().tx_ok, 0);
        assert_eq!(engine.metrics().tx_fail, 1);
        engine.release_tx(tx).expect("release");
    }
}

#[cfg(all(test, feature = "std"))]
mod udp_tests {
    use super::*;
    use std::net::UdpSocket;
    use std::time::Duration;

    #[test]
    fn udp_exact_capacity_oversize_and_recovery_ipv4_ipv6() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let sender = UdpSocket::bind(address).unwrap();
            let mut receiver = UdpSocket::bind(address).unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let dest = receiver.local_addr().unwrap();
            // Includes zero capacity, built-in profiles and the heap fallback.
            for capacity in [0, 64, 1472, 2048] {
                let mut output = std::vec![0xA5; capacity];
                for extra in [0, 1, 100] {
                    let payload = std::vec![0x39; capacity + extra];
                    sender.send_to(&payload, dest).unwrap();
                    let got = DatagramIo::recv(&mut receiver, &mut output);
                    if extra == 0 {
                        assert_eq!(
                            got.unwrap(),
                            Some((capacity, sender.local_addr().unwrap().into()))
                        );
                        assert_eq!(output, payload);
                    } else {
                        assert!(
                            got.is_err(),
                            "accepted truncated {address} capacity={capacity} extra={extra}"
                        );
                        // No prefix is exposed, even on Windows native failure.
                        assert!(output.iter().all(|b| *b == 0x39));
                    }
                    sender.send_to(b"", dest).unwrap();
                    assert_eq!(
                        DatagramIo::recv(&mut receiver, &mut output)
                            .unwrap()
                            .unwrap()
                            .0,
                        0
                    );
                }
            }
            receiver.set_nonblocking(true).unwrap();
            assert_eq!(DatagramIo::recv(&mut receiver, &mut [0; 8]).unwrap(), None);
        }
    }
    #[test]
    fn oversized_udp_cannot_occupy_an_engine_slot_and_next_packet_survives() {
        use crate::storage::{EngineBuilder, Memory, profiles};
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let dest = receiver.local_addr().unwrap();
        let mut engine = EngineBuilder::new()
            .profile::<profiles::Default>()
            .block_wise(false)
            .build(Memory::<profiles::Default>::new())
            .unwrap();
        sender.send_to(&[0x41; 3000], dest).unwrap();
        assert!(matches!(
            engine.recv_from(&mut receiver),
            Err(DatagramIoError::Io(_))
        ));
        assert_eq!(engine.rx_occupied(), 0);
        assert_eq!(engine.metrics().rx_accepted, 0);
        assert_eq!(engine.metrics().rx_error, 1);
        let packet = [0x60, 0, 0x12, 0x34];
        sender.send_to(&packet, dest).unwrap();
        let rx = engine.recv_from(&mut receiver).unwrap().unwrap();
        assert_eq!(engine.access_rx(rx).unwrap().as_bytes(), packet);
        engine.release_rx(rx).unwrap();
        assert_eq!(engine.rx_occupied(), 0);
    }
}
