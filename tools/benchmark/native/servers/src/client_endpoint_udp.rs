//! Private benchmark mapping of genuine local/remote UDP pairs into one App.
//! Logical addresses are opaque pair keys, never wire server addresses. All
//! keys have namespace zero and differ after physical(); the sole context and
//! sender sequence therefore stay in App. No packet queue or socket worker.
use coaptic::storage::{DatagramIo, DatagramTransport, Endpoint};
use std::{
    io,
    net::{SocketAddr, SocketAddrV4, UdpSocket},
};

pub const LANES: usize = 4;
const SCRATCH: usize = 1473;
const SEND_BUDGET: u64 = 60_000;

struct Lane {
    socket: UdpSocket,
    local: SocketAddrV4,
    logical: Endpoint,
    sent: u64,
    received: u64,
}

pub struct EndpointIo {
    lanes: [Option<Lane>; LANES],
    server: SocketAddrV4,
    count: usize,
    cursor: usize,
    scratch: [u8; SCRATCH],
    pub sent: u64,
    pub received: u64,
}

fn pair_key(local: SocketAddrV4, remote: SocketAddrV4) -> Endpoint {
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&[0xfd, 0x63, 0x6f, 0x61]);
    key[4..8].copy_from_slice(&local.ip().octets());
    key[8..12].copy_from_slice(&remote.ip().octets());
    key[12..14].copy_from_slice(&local.port().to_be_bytes());
    key[14..16].copy_from_slice(&remote.port().to_be_bytes());
    Endpoint::v6(key, remote.port())
}

impl EndpointIo {
    pub fn new(server: SocketAddrV4, count: usize) -> io::Result<Self> {
        if !(2..=LANES).contains(&count) || !server.ip().is_loopback() || server.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "independent endpoint bounds 2..4, loopback server",
            ));
        }
        let mut lanes = std::array::from_fn(|_| None);
        for slot in &mut lanes[..count] {
            let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            socket.connect(server)?;
            socket.set_nonblocking(true)?;
            let SocketAddr::V4(local) = socket.local_addr()? else {
                unreachable!()
            };
            *slot = Some(Lane {
                logical: pair_key(local, server),
                socket,
                local,
                sent: 0,
                received: 0,
            });
        }
        Ok(Self {
            lanes,
            server,
            count,
            cursor: 0,
            scratch: [0; SCRATCH],
            sent: 0,
            received: 0,
        })
    }

    pub fn peers(&self) -> [Endpoint; LANES] {
        std::array::from_fn(|i| {
            self.lanes[i]
                .as_ref()
                .unwrap_or(self.lanes[0].as_ref().unwrap())
                .logical
        })
    }

    // Called only outside measurement. Socket handles/metadata and scratch are
    // nested in App inline; kernel buffers/allocator/peak stacks remain unknown.
    pub fn lane_counts(&self) -> ([u64; LANES], [u64; LANES]) {
        (
            std::array::from_fn(|i| self.lanes[i].as_ref().map_or(0, |l| l.sent)),
            std::array::from_fn(|i| self.lanes[i].as_ref().map_or(0, |l| l.received)),
        )
    }

    pub fn report(&self, before: ([u64; LANES], [u64; LANES])) -> String {
        let ports: Vec<_> = self
            .lanes
            .iter()
            .flatten()
            .map(|l| l.local.port())
            .collect();
        let sent: Vec<_> = self.lanes.iter().flatten().map(|l| l.sent).collect();
        let received: Vec<_> = self.lanes.iter().flatten().map(|l| l.received).collect();
        let counts = self.lane_counts();
        let measured_sent: [u64; LANES] = std::array::from_fn(|i| counts.0[i] - before.0[i]);
        let measured_received: [u64; LANES] = std::array::from_fn(|i| counts.1[i] - before.1[i]);
        format!(
            ",\"endpoint_transport\":{{\"schema\":\"coaptic-local-pairs/1\",\"server\":\"{}\",\"local_ports\":{ports:?},\"sent\":{sent:?},\"received\":{received:?},\"measured_sent_datagrams\":{:?},\"measured_received_datagrams\":{:?},\"adapter_inline_bytes\":{},\"socket_count\":{},\"scratch_bytes\":1473,\"receive_attempt_bound\":{},\"packet_queues\":0,\"workers\":0,\"requested_heap_bytes\":0,\"kernel_bytes\":null,\"peak_stack_bytes\":null}}",
            self.server,
            &measured_sent[..self.count],
            &measured_received[..self.count],
            std::mem::size_of::<Self>(),
            self.count,
            self.count
        )
    }
}

impl DatagramTransport for EndpointIo {
    type Error = io::Error;
}
impl DatagramIo for EndpointIo {
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> io::Result<usize> {
        if self.sent >= SEND_BUDGET {
            return Err(io::Error::other(
                "diagnostic fresh-socket outbound datagram budget exhausted",
            ));
        }
        let lane = self
            .lanes
            .iter_mut()
            .flatten()
            .find(|l| l.logical == peer)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown local/remote endpoint pair",
                )
            })?;
        let n = lane.socket.send(bytes)?;
        self.sent += 1;
        lane.sent += 1;
        Ok(n)
    }

    fn recv(&mut self, bytes: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
        // Advance before every syscall, including invalid/empty/error lanes and
        // last->first. Returning a packet never resets the cross-poll cursor.
        for _ in 0..self.count {
            let selected = self.cursor;
            self.cursor = (self.cursor + 1) % self.count;
            let lane = self.lanes[selected].as_mut().unwrap();
            match lane.socket.recv_from(&mut self.scratch) {
                Ok((n, sender)) => {
                    // Connected UDP filters in the kernel, but retain the exact
                    // actual-sender guard before assigning an App peer key.
                    if sender != SocketAddr::V4(self.server) || n > 1472 || n > bytes.len() {
                        continue;
                    }
                    bytes[..n].copy_from_slice(&self.scratch[..n]);
                    lane.received += 1;
                    self.received += 1;
                    return Ok(Some((n, lane.logical)));
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(10040) => {
                }
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
#[path = "client_endpoint_tests.rs"]
mod tests;
