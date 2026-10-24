//! Linux-only synchronous receive control. The kernel borrows the Engine RX
//! destination only during recvfrom(MSG_TRUNC | MSG_DONTWAIT). The call returns
//! the original datagram length, so a truncated prefix is never accepted.
//!
//! There is no submitted operation, retained pointer, extra packet owner, thread,
//! future or Drop-dependent cleanup. Returning (including error) ends all kernel
//! access to the destination. Oversize input may overwrite a prefix; Engine
//! discards the failed RX slot and never parses it. Pool saturation is checked
//! before calling this adapter, so it does not consume a packet on that refusal.
//! Sends use the same immediate Mio send_to as the control. No acceptance is
//! deferred to a future poll and no user-space send queue or retry is introduced.

use super::Endpoint;
use rustix::net::{RecvFlags, recvfrom};
use std::{io, net::SocketAddr};

pub(super) fn receive(
    socket: &mio::net::UdpSocket,
    output: &mut [u8],
) -> io::Result<Option<(usize, Endpoint)>> {
    if output.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let capacity = output.len();
    match recvfrom(socket, output, RecvFlags::TRUNC | RecvFlags::DONTWAIT) {
        Ok((_, len, _)) if len > capacity => Err(io::ErrorKind::InvalidData.into()),
        Ok((_, len, address)) => {
            let address = address.ok_or(io::ErrorKind::InvalidData)?;
            let peer = SocketAddr::try_from(address).map_err(io::Error::from)?;
            Ok(Some((len, Endpoint::from(peer).physical())))
        }
        Err(rustix::io::Errno::AGAIN) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DatagramIo, MioUdp};
    use std::{
        net::UdpSocket,
        time::{Duration, Instant},
    };

    fn sockets(host: &str) -> (MioUdp<0>, UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind(host).unwrap();
        socket.set_nonblocking(true).unwrap();
        let local = socket.local_addr().unwrap();
        let sender = UdpSocket::bind(host).unwrap();
        sender
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        (
            MioUdp {
                socket: mio::net::UdpSocket::from_std(socket),
                scratch: [],
                received: false,
            },
            sender,
            local,
        )
    }

    #[test]
    fn direct_authenticated_complete_operations() {
        use crate::staged_udp::tests::{context, verify_four};
        for protected in [false, true] {
            let (io, _sender, local) = sockets("127.0.0.1:0");
            let app = crate::bind_fixture(io, 64, 1472, protected.then(|| context(true))).unwrap();
            let epoch = Instant::now();
            let until = epoch + Duration::from_secs(1);
            let (app, _) = verify_four(app, local.into(), epoch, until, protected, |app| {
                crate::mio_burst(app, epoch).unwrap();
            });
            assert_eq!(app.metrics().rx_accepted, 4);
        }
    }

    fn burst_recovers<const SCRATCH: usize>() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let local = socket.local_addr().unwrap();
        let io = MioUdp {
            socket: mio::net::UdpSocket::from_std(socket),
            scratch: [0; SCRATCH],
            received: false,
        };
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut app = crate::bind_fixture(io, 64, 1472, None).unwrap();
        sender.send_to(&[0x40; 1473], local).unwrap();
        sender.send_to(&[0x60, 0, 0, 7], local).unwrap();
        assert!(crate::mio_burst(&mut app, Instant::now()).unwrap());
        assert_eq!(app.metrics().rx_error, 1);
        assert_eq!(app.metrics().rx_accepted, 1);
        assert_eq!(app.engine_mut().rx_occupied(), 0);
        sender.send_to(&[0x60, 0, 0, 8], local).unwrap();
        assert!(crate::mio_burst(&mut app, Instant::now()).unwrap());
        assert_eq!(app.metrics().rx_accepted, 2);
    }

    #[test]
    fn direct_and_control_server_bursts_drain_past_oversize_then_recover() {
        burst_recovers::<0>();
        burst_recovers::<2049>();
    }

    #[test]
    fn direct_engine_saturation_and_failed_prefix_release_recover() {
        use coaptic::storage::{DatagramIoError, EngineBuilder, Memory};
        let (mut io, sender, local) = sockets("127.0.0.1:0");
        let mut engine = EngineBuilder::new()
            .profile::<coaptic::profiles::Constrained>()
            .block_wise(false)
            .build(Memory::<coaptic::profiles::Constrained>::new())
            .unwrap();
        let held: [_; 2] = std::array::from_fn(|_| engine.acquire_rx().unwrap());
        sender.send_to(&[0x40, 0, 0, 7], local).unwrap();
        assert!(matches!(
            engine.recv_from(&mut io),
            Err(DatagramIoError::Saturated)
        ));
        assert!(!io.received);
        for slot in held {
            engine.release_rx(slot).unwrap();
        }
        let rx = engine.recv_from(&mut io).unwrap().unwrap();
        assert_eq!(engine.access_rx(rx).unwrap().as_bytes(), &[0x40, 0, 0, 7]);
        engine.release_rx(rx).unwrap();
        assert_eq!(engine.rx_occupied(), 0);
        // An oversized valid-looking prefix never installs a received length.
        sender.send_to(&[0x40; 1153], local).unwrap();
        assert!(matches!(
            engine.recv_from(&mut io),
            Err(DatagramIoError::Io(_))
        ));
        assert_eq!(engine.rx_occupied(), 0);
        sender.send_to(&[0x40, 0, 0, 8], local).unwrap();
        let rx = engine.recv_from(&mut io).unwrap().unwrap();
        assert_eq!(engine.access_rx(rx).unwrap().as_bytes(), &[0x40, 0, 0, 8]);
        engine.release_rx(rx).unwrap();
        assert_eq!(engine.metrics().rx_accepted, 2);
        assert_eq!(engine.metrics().rx_error, 1);
    }

    #[test]
    fn direct_exact_truncation_empty_and_recovery_ipv4_ipv6() {
        for host in ["127.0.0.1:0", "[::1]:0"] {
            for capacity in [64, 1472, 2048] {
                let (mut io, sender, local) = sockets(host);
                let peer = Endpoint::from(sender.local_addr().unwrap());
                let mut output = vec![0xa5; capacity];
                assert!(io.recv(&mut output).unwrap().is_none());
                for size in [0, capacity, capacity + 1, capacity + 100, 3] {
                    let payload = vec![0x39; size];
                    sender.send_to(&payload, local).unwrap();
                    let deadline = Instant::now() + Duration::from_secs(1);
                    let result = loop {
                        match io.recv(&mut output) {
                            Ok(None) => assert!(Instant::now() < deadline, "receive deadline"),
                            result => break result,
                        }
                        std::thread::yield_now();
                    };
                    if size <= capacity {
                        assert_eq!(result.unwrap(), Some((size, peer)));
                        assert_eq!(&output[..size], &payload);
                        assert!(io.received);
                    } else {
                        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                        assert!(!io.received);
                    }
                    assert!(io.recv(&mut output).unwrap().is_none());
                    assert!(!io.received);
                }
                // Invalid destinations refuse before consuming the queued packet.
                sender.send_to(b"keep", local).unwrap();
                assert_eq!(
                    io.recv(&mut []).unwrap_err().kind(),
                    io::ErrorKind::InvalidInput
                );
                assert_eq!(io.recv(&mut output).unwrap(), Some((4, peer)));
                assert_eq!(&output[..4], b"keep");
                assert_eq!(io.send(peer, b"reply").unwrap(), 5);
                let mut reply = [0; 8];
                assert_eq!(sender.recv_from(&mut reply).unwrap(), (5, local));
                assert_eq!(&reply[..5], b"reply");
                // Oversized UDP sends refuse immediately; no queued prefix.
                assert!(io.send(peer, &[0; 65536]).is_err());
                assert_eq!(io.send(peer, b"next").unwrap(), 4);
                assert_eq!(sender.recv_from(&mut reply).unwrap(), (4, local));
                assert_eq!(&reply[..4], b"next");
            }
        }
    }
}
