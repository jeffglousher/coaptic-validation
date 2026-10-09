//! Bounded DTLS fixture listener. Each executable compiles against its own
//! webrtc-dtls/util versions. No transport or crypto dependency enters Coaptic.
use async_trait::async_trait;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex as AsyncMutex, mpsc, watch},
};
use webrtc_dtls::{config::Config, conn::DTLSConn};
use webrtc_util::conn::{Conn, Listener};

type Result<T> = webrtc_util::Result<T>;
const MAX_PEERS: usize = 128;
const MAX_HANDSHAKES: usize = 16;
const QUEUE: usize = 32;
const DATAGRAM: usize = 4096;

struct Route {
    id: u64,
    hello: [u8; 32],
    packets: mpsc::Sender<Vec<u8>>,
    closed: watch::Sender<bool>,
}
#[derive(Default)]
struct Peer {
    active: Option<Route>,
    pending: Option<Route>,
}
#[derive(Default)]
struct State {
    peers: HashMap<SocketAddr, Peer>,
    next: u64,
}
type Shared = Arc<Mutex<State>>;
type Accepted = (Arc<dyn Conn + Send + Sync>, SocketAddr);

fn error(message: &str) -> webrtc_util::Error {
    std::io::Error::other(message).into()
}

// Read only the routing discriminator, not cryptographic handshake state.
// RFC 6347 sections 4.2.1, 4.2.2 and 4.2.8. Fragmented initial hellos are
// unsupported by this PSK fixture; the DTLS backend verifies the handshake.
fn client_random(packet: &[u8]) -> Option<[u8; 32]> {
    if packet.len() < 59
        || packet[0] != 22
        || packet[1] != 0xfe
        || ![0xfd, 0xff].contains(&packet[2])
        || packet[3..5] != [0, 0]
    {
        return None;
    }
    let n = usize::from(u16::from_be_bytes([packet[11], packet[12]]));
    let fragment = packet.get(13..13 + n)?;
    let u24 = |s: &[u8]| usize::from(s[0]) << 16 | usize::from(s[1]) << 8 | usize::from(s[2]);
    if fragment.len() < 46
        || fragment[0] != 1
        || fragment[6..9] != [0, 0, 0]
        || u24(&fragment[1..4]) != fragment.len() - 12
        || u24(&fragment[9..12]) != fragment.len() - 12
    {
        return None;
    }
    fragment[14..46].try_into().ok()
}

fn retire(state: &Shared, peer: SocketAddr, id: u64) {
    let mut state = state.lock().expect("DTLS routes");
    if let Some(row) = state.peers.get_mut(&peer) {
        if row.active.as_ref().is_some_and(|r| r.id == id)
            && let Some(r) = row.active.take()
        {
            let _ = r.closed.send(true);
        }
        if row.pending.as_ref().is_some_and(|r| r.id == id)
            && let Some(r) = row.pending.take()
        {
            let _ = r.closed.send(true);
        }
        if row.active.is_none() && row.pending.is_none() {
            state.peers.remove(&peer);
        }
    }
}

struct DatagramConn {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    id: u64,
    state: Weak<Mutex<State>>,
    packets: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    closed: watch::Receiver<bool>,
}
impl Drop for DatagramConn {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            retire(&state, self.peer, self.id);
        }
    }
}
#[async_trait]
impl Conn for DatagramConn {
    async fn connect(&self, addr: SocketAddr) -> Result<()> {
        if addr == self.peer {
            Ok(())
        } else {
            Err(error("cannot change DTLS peer"))
        }
    }
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut closed = self.closed.clone();
        if *closed.borrow() {
            return std::future::pending().await;
        }
        let mut packets = self.packets.lock().await;
        let packet = tokio::select! {
            _ = closed.changed() => return std::future::pending().await,
            packet = tokio::time::timeout(Duration::from_secs(30), packets.recv()) => {
                match packet { Ok(Some(packet)) => packet, _ => {
                    self.close().await?;
                    return std::future::pending().await;
                }}
            }
        };
        if packet.len() > buf.len() {
            return Err(error("DTLS datagram exceeds receive buffer"));
        }
        buf[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Ok((self.recv(buf).await?, self.peer))
    }
    async fn send(&self, buf: &[u8]) -> Result<usize> {
        if *self.closed.borrow() {
            // Retiring an association suppresses its terminal alert: it must not
            // be delivered to the replacement session. The backend's close()
            // requires this completion to stop its reader; other writes fail.
            return if buf.first() == Some(&21) {
                Ok(buf.len())
            } else {
                Err(error("DTLS route closed"))
            };
        }
        Ok(self.socket.send_to(buf, self.peer).await?)
    }
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        if target != self.peer {
            return Err(error("cannot change DTLS peer"));
        }
        self.send(buf).await
    }
    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.peer)
    }
    async fn close(&self) -> Result<()> {
        if let Some(state) = self.state.upgrade() {
            retire(&state, self.peer, self.id);
        }
        Ok(())
    }
    conn_as_any!();
}

pub struct BoundedListener {
    addr: SocketAddr,
    closed: watch::Sender<bool>,
    ready: AsyncMutex<mpsc::Receiver<Accepted>>,
    state: Shared,
    task: tokio::task::JoinHandle<()>,
}
impl BoundedListener {
    pub async fn bind(addr: SocketAddr, config: Config) -> Result<Self> {
        Self::from_socket(Arc::new(UdpSocket::bind(addr).await?), config).await
    }
    async fn from_socket(socket: Arc<UdpSocket>, config: Config) -> Result<Self> {
        let addr = socket.local_addr()?;
        let state: Shared = Arc::default();
        let (ready, receiver) = mpsc::channel(QUEUE);
        let routes = state.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0; DATAGRAM + 1];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(packet) => packet,
                    // A departed UDP client can produce a delayed ICMP error
                    // on the shared socket, especially WSAECONNRESET on Windows.
                    // It must not terminate service for every other endpoint.
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => {
                        eprintln!("DTLS fixture listener stopped: {error}");
                        routes.lock().expect("DTLS routes").peers.clear();
                        break;
                    }
                };
                if n > DATAGRAM {
                    continue;
                }
                let bytes = &buf[..n];
                let hello = client_random(bytes);
                let mut start = None;
                {
                    let mut table = routes.lock().expect("DTLS routes");
                    if let Some(hello) = hello {
                        let known = table.peers.get(&peer).is_some_and(|row| {
                            row.pending.as_ref().is_some_and(|r| r.hello == hello)
                                || row.active.as_ref().is_some_and(|r| r.hello == hello)
                        });
                        let pending = table.peers.values().filter(|r| r.pending.is_some()).count();
                        let occupied = table.peers.get(&peer).is_some_and(|r| r.pending.is_some());
                        if !known
                            && !occupied
                            && pending < MAX_HANDSHAKES
                            && (table.peers.contains_key(&peer) || table.peers.len() < MAX_PEERS)
                        {
                            table.next = table
                                .next
                                .checked_add(1)
                                .expect("fixture generation exhausted");
                            let id = table.next;
                            let (packets, rx) = mpsc::channel(QUEUE);
                            let (closed, stop) = watch::channel(false);
                            table.peers.entry(peer).or_default().pending = Some(Route {
                                id,
                                hello,
                                packets,
                                closed,
                            });
                            start = Some(Arc::new(DatagramConn {
                                socket: socket.clone(),
                                peer,
                                id,
                                state: Arc::downgrade(&routes),
                                packets: AsyncMutex::new(rx),
                                closed: stop,
                            }));
                        }
                    }
                    if let Some(row) = table.peers.get(&peer) {
                        for route in [&row.active, &row.pending].into_iter().flatten() {
                            // New epoch-zero hellos go only to their candidate. Other records
                            // are authenticated independently by the backend for each context.
                            if hello.is_none_or(|random| random == route.hello) {
                                let _ = route.packets.try_send(bytes.to_vec());
                            }
                        }
                    }
                }
                if let Some(raw) = start {
                    let config = config.clone();
                    let routes = routes.clone();
                    let ready = ready.clone();
                    tokio::spawn(async move {
                        let result = tokio::time::timeout(
                            Duration::from_secs(2),
                            DTLSConn::new(raw.clone(), config, false, None),
                        )
                        .await;
                        if let Ok(Ok(connection)) = result {
                            let promoted = {
                                let mut table = routes.lock().expect("DTLS routes");
                                table.peers.get_mut(&peer).is_some_and(|row| {
                                    if !row.pending.as_ref().is_some_and(|r| r.id == raw.id) {
                                        return false;
                                    }
                                    // Verified Finished: retire the old association (RFC 6347 4.2.8).
                                    if let Some(old) = row.active.take() {
                                        let _ = old.closed.send(true);
                                    }
                                    row.active = row.pending.take();
                                    true
                                })
                            };
                            let connection: Arc<dyn Conn + Send + Sync> = Arc::new(connection);
                            let mut stopped = raw.closed.clone();
                            let weak = Arc::downgrade(&connection);
                            tokio::spawn(async move {
                                if !*stopped.borrow() {
                                    let _ = stopped.changed().await;
                                }
                                if let Some(connection) = weak.upgrade() {
                                    let _ = connection.close().await;
                                }
                            });
                            if !promoted || ready.try_send((connection.clone(), peer)).is_err() {
                                let _ = connection.close().await;
                                let _ = raw.close().await;
                            }
                        } else {
                            let _ = raw.close().await;
                        }
                    });
                }
            }
        });
        Ok(Self {
            addr,
            closed: watch::channel(false).0,
            ready: AsyncMutex::new(receiver),
            state,
            task,
        })
    }
}
#[async_trait]
impl Listener for BoundedListener {
    async fn accept(&self) -> Result<Accepted> {
        let mut closed = self.closed.subscribe();
        if *closed.borrow() {
            return Err(error("DTLS listener closed"));
        }
        let mut ready = self.ready.lock().await;
        tokio::select! {
            _ = closed.changed() => Err(error("DTLS listener closed")),
            item = ready.recv() => item.ok_or_else(|| error("DTLS listener closed")),
        }
    }
    async fn close(&self) -> Result<()> {
        self.closed.send_replace(true);
        self.task.abort();
        self.state.lock().expect("DTLS routes").peers.clear();
        self.ready.lock().await.close();
        Ok(())
    }
    async fn addr(&self) -> Result<SocketAddr> {
        Ok(self.addr)
    }
}
impl Drop for BoundedListener {
    fn drop(&mut self) {
        self.closed.send_replace(true);
        self.task.abort();
        self.state.lock().expect("DTLS routes").peers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrtc_dtls::cipher_suite::CipherSuiteId;

    fn config() -> Config {
        Config {
            psk: Some(Arc::new(|_| Ok(b"fixture-secret".to_vec()))),
            psk_identity_hint: Some(b"fixture".to_vec()),
            cipher_suites: vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8],
            ..Default::default()
        }
    }
    fn hello(random: [u8; 32]) -> Vec<u8> {
        let mut body = vec![0xfe, 0xfd];
        body.extend(random);
        body.extend([0, 0, 0, 2, 0xc0, 0xa8, 1, 0]);
        let n = body.len();
        let mut record = vec![
            22,
            0xfe,
            0xfd,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (n + 12) as u8,
            1,
            0,
            0,
            n as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            n as u8,
        ];
        record.extend(body);
        record
    }
    #[test]
    fn routing_parser_rejects_truncated_fragmented_and_nonzero_epoch_hellos() {
        let valid = hello([7; 32]);
        assert_eq!(client_random(&valid), Some([7; 32]));
        for n in 0..valid.len() {
            assert_eq!(client_random(&valid[..n]), None);
        }
        for (at, value) in [(0, 23), (4, 1), (19, 1), (24, 1), (16, 1)] {
            let mut bad = valid.clone();
            bad[at] = value;
            assert_eq!(client_random(&bad), None);
        }
    }
    #[tokio::test]
    async fn close_interrupts_pending_accept() {
        let listener = BoundedListener::bind("127.0.0.1:0".parse().unwrap(), config())
            .await
            .unwrap();
        let (accepted, closed) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(listener.accept(), listener.close())
        })
        .await
        .unwrap();
        assert!(accepted.is_err());
        assert!(closed.is_ok());
    }
    #[tokio::test]
    async fn unauthenticated_replacement_preserves_active_association() {
        let listener = BoundedListener::bind("127.0.0.1:0".parse().unwrap(), config())
            .await
            .unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        socket.connect(listener.addr).await.unwrap();
        let peer = socket.local_addr().unwrap();
        let (client, accepted) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                DTLSConn::new(socket.clone(), config(), true, None),
                listener.accept()
            )
        })
        .await
        .unwrap();
        let client = client.unwrap();
        let (server, _) = accepted.unwrap();
        let original = listener.state.lock().unwrap().peers[&peer]
            .active
            .as_ref()
            .unwrap()
            .id;
        socket.send(&hello([0x77; 32])).await.unwrap();
        client.send(b"still authenticated").await.unwrap();
        let mut buf = [0; 64];
        let n = tokio::time::timeout(Duration::from_secs(1), server.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"still authenticated");
        {
            let table = listener.state.lock().unwrap();
            assert_eq!(table.peers[&peer].active.as_ref().unwrap().id, original);
            assert!(table.peers[&peer].pending.is_some());
        }
        listener.close().await.unwrap();
    }
    #[tokio::test]
    async fn pending_handshakes_are_bounded_and_cleanup_reclaims_capacity() {
        let listener = BoundedListener::bind("127.0.0.1:0".parse().unwrap(), config())
            .await
            .unwrap();
        let mut sockets = Vec::new();
        for i in 0..MAX_HANDSHAKES + 8 {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket
                .send_to(&hello([i as u8; 32]), listener.addr)
                .await
                .unwrap();
            sockets.push(socket);
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if listener.state.lock().unwrap().peers.len() == MAX_HANDSHAKES {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(listener.state.lock().unwrap().peers.len() <= MAX_HANDSHAKES);
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                if listener.state.lock().unwrap().peers.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        sockets[0]
            .send_to(&hello([99; 32]), listener.addr)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if listener.state.lock().unwrap().peers.len() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        listener.close().await.unwrap();
        assert!(listener.state.lock().unwrap().peers.is_empty());
    }
    #[tokio::test]
    async fn departed_udp_peer_does_not_stop_listener() {
        let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let listener = BoundedListener::from_socket(server_socket.clone(), config())
            .await
            .unwrap();
        let departed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = departed.local_addr().unwrap();
        drop(departed);
        // Send to a now-unbound port. Windows may deliver its ICMP refusal on
        // the shared receive socket; it must not stop a subsequent handshake.
        server_socket
            .send_to(b"departed peer", address)
            .await
            .unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        socket.connect(listener.addr).await.unwrap();
        let (client, accepted) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                DTLSConn::new(socket, config(), true, None),
                listener.accept()
            )
        })
        .await
        .unwrap();
        let client = client.unwrap();
        let (server, _) = accepted.unwrap();
        client.send(b"alive").await.unwrap();
        let mut reply = [0; 64];
        let n = tokio::time::timeout(Duration::from_secs(1), server.recv(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply[..n], b"alive");
        listener.close().await.unwrap();
    }
    #[test]
    fn stale_cleanup_cannot_remove_replacement_route() {
        let state: Shared = Arc::default();
        let peer = "127.0.0.1:5683".parse().unwrap();
        let (packets, _rx) = mpsc::channel(1);
        let (closed, stop) = watch::channel(false);
        state.lock().unwrap().peers.insert(
            peer,
            Peer {
                active: Some(Route {
                    id: 2,
                    hello: [2; 32],
                    packets,
                    closed,
                }),
                pending: None,
            },
        );
        retire(&state, peer, 1);
        assert_eq!(
            state.lock().unwrap().peers[&peer]
                .active
                .as_ref()
                .unwrap()
                .id,
            2
        );
        assert!(!*stop.borrow());
        retire(&state, peer, 2);
        assert!(state.lock().unwrap().peers.is_empty());
        assert!(*stop.borrow());
    }
}
