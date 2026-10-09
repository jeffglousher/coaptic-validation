//! Test-only bridge from coap-rs transport traits to the modern DTLS backend.
//! CoAP parsing, matching, retransmission and block assembly remain coap-rs.
use async_trait::async_trait;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    task::{JoinHandle, JoinSet},
};
use webrtc_dtls::{config::Config, conn::DTLSConn};
use webrtc_util::conn::{Conn, Listener};

pub struct Client(pub Arc<DTLSConn>);
impl Client {
    pub async fn connect(peer: SocketAddr, config: Config) -> io::Result<Self> {
        let bind = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(peer).await?;
        let conn = tokio::time::timeout(
            Duration::from_secs(3),
            DTLSConn::new(Arc::new(socket), config, true, None),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DTLS handshake timeout"))?
        .map_err(io::Error::other)?;
        Ok(Self(Arc::new(conn)))
    }
}
#[async_trait]
impl coap::client::ClientTransport for Client {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        self.0
            .recv(buf)
            .await
            .map(|n| (n, self.0.remote_addr()))
            .map_err(io::Error::other)
    }
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.send(buf).await.map_err(io::Error::other)
    }
}

pub struct Server<L>(pub L);
struct Reply {
    conn: Arc<dyn Conn + Send + Sync>,
    peer: SocketAddr,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
#[async_trait]
impl coap::server::Responder for Reply {
    async fn respond(&self, bytes: Vec<u8>) {
        let _ = tokio::time::timeout(Duration::from_secs(2), self.conn.send(&bytes)).await;
    }
    fn address(&self) -> SocketAddr {
        self.peer
    }
}

#[async_trait]
impl<L: Listener + Send + Sync + 'static> coap::server::Listener for Server<L> {
    async fn listen(
        self: Box<Self>,
        sender: coap::server::TransportRequestSender,
    ) -> io::Result<JoinHandle<io::Result<()>>> {
        Ok(tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            let requests = Arc::new(tokio::sync::Semaphore::new(128));
            loop {
                tokio::select! {
                    _ = sender.closed() => break,
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                    accepted = self.0.accept() => {
                        let (conn, peer) = match accepted {
                            Ok(pair) => pair,
                            Err(_) => {
                                // Authentication failure must not stop the listener.
                                tokio::time::sleep(Duration::from_millis(10)).await;
                                continue;
                            }
                        };
                        if tasks.len() >= 128 {
                            let _ = tokio::time::timeout(Duration::from_secs(1), conn.close()).await;
                            continue;
                        }
                        let sender = sender.clone();
                        let requests = Arc::clone(&requests);
                        tasks.spawn(async move {
                            let mut bytes = [0; 1601];
                            loop {
                                let received = tokio::select! {
                                    _ = sender.closed() => break,
                                    received = tokio::time::timeout(Duration::from_secs(30), conn.recv(&mut bytes)) => received,
                                };
                                let n = match received {
                                    Ok(Ok(n @ 1..=1600)) => n,
                                    _ => break,
                                };
                                // A permit follows the responder through coap-rs's
                                // unbounded channel and any retained Observe state.
                                let Ok(permit) = Arc::clone(&requests).try_acquire_owned() else { break; };
                                let reply = Arc::new(Reply { conn: Arc::clone(&conn), peer, _permit: permit });
                                if sender.send((bytes[..n].to_vec(), reply)).is_err() { break; }
                            }
                            let _ = tokio::time::timeout(Duration::from_secs(1), conn.close()).await;
                        });
                    }
                }
            }
            let _ = self.0.close().await;
            while tasks.join_next().await.is_some() {}
            Ok(())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coap::server::Listener as _;
    use tokio::sync::{Mutex, mpsc, watch};

    struct TestConn {
        input: Mutex<mpsc::Receiver<Vec<u8>>>,
        closed: watch::Sender<bool>,
    }
    impl TestConn {
        fn new() -> (Arc<Self>, mpsc::Sender<Vec<u8>>, watch::Receiver<bool>) {
            let (tx, rx) = mpsc::channel(8);
            let (closed, seen) = watch::channel(false);
            (
                Arc::new(Self {
                    input: Mutex::new(rx),
                    closed,
                }),
                tx,
                seen,
            )
        }
    }
    #[async_trait]
    impl Conn for TestConn {
        async fn connect(&self, _: SocketAddr) -> webrtc_util::Result<()> {
            Ok(())
        }
        async fn recv(&self, output: &mut [u8]) -> webrtc_util::Result<usize> {
            let bytes = self
                .input
                .lock()
                .await
                .recv()
                .await
                .ok_or(webrtc_util::Error::ErrBufferClosed)?;
            if bytes.len() > output.len() {
                return Err(webrtc_util::Error::ErrBufferShort);
            }
            output[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
        async fn recv_from(&self, output: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
            Ok((self.recv(output).await?, self.remote_addr().unwrap()))
        }
        async fn send(&self, bytes: &[u8]) -> webrtc_util::Result<usize> {
            Ok(bytes.len())
        }
        async fn send_to(&self, bytes: &[u8], _: SocketAddr) -> webrtc_util::Result<usize> {
            self.send(bytes).await
        }
        fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
            Ok("127.0.0.1:5683".parse().unwrap())
        }
        fn remote_addr(&self) -> Option<SocketAddr> {
            Some("127.0.0.1:5684".parse().unwrap())
        }
        async fn close(&self) -> webrtc_util::Result<()> {
            self.closed.send_replace(true);
            Ok(())
        }
        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
            self
        }
    }
    struct TestListener {
        incoming: Mutex<mpsc::Receiver<Arc<TestConn>>>,
        closed: watch::Sender<bool>,
    }
    #[async_trait]
    impl Listener for TestListener {
        async fn accept(&self) -> webrtc_util::Result<(Arc<dyn Conn + Send + Sync>, SocketAddr)> {
            let conn = self
                .incoming
                .lock()
                .await
                .recv()
                .await
                .ok_or(webrtc_util::Error::ErrClosedListener)?;
            let peer = conn.remote_addr().unwrap();
            Ok((conn, peer))
        }
        async fn close(&self) -> webrtc_util::Result<()> {
            self.closed.send_replace(true);
            Ok(())
        }
        async fn addr(&self) -> webrtc_util::Result<SocketAddr> {
            Ok("127.0.0.1:5683".parse().unwrap())
        }
    }
    async fn wait_closed(seen: &mut watch::Receiver<bool>) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !*seen.borrow_and_update() {
                seen.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn bounded_bridge_refuses_oversize_and_releases_on_shutdown() {
        let (accept, incoming) = mpsc::channel(2);
        let (closed, mut listener_closed) = watch::channel(false);
        let (sender, mut requests) = mpsc::unbounded_channel();
        let task = Box::new(Server(TestListener {
            incoming: Mutex::new(incoming),
            closed,
        }))
        .listen(sender)
        .await
        .unwrap();
        let (conn, packets, mut conn_closed) = TestConn::new();
        accept.send(conn).await.unwrap();
        packets.send(vec![0x39; 1600]).await.unwrap();
        let (bytes, reply) = tokio::time::timeout(Duration::from_secs(2), requests.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes, vec![0x39; 1600]);
        drop(reply);
        packets.send(vec![0x42; 1601]).await.unwrap();
        wait_closed(&mut conn_closed).await;
        assert!(
            requests.try_recv().is_err(),
            "oversized plaintext reached CoAP parser"
        );
        drop(requests);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        wait_closed(&mut listener_closed).await;
    }
    #[tokio::test]
    async fn responder_bound_refuses_then_recovers_after_consumption() {
        let (accept, incoming) = mpsc::channel(2);
        let (closed, _) = watch::channel(false);
        let (sender, mut requests) = mpsc::unbounded_channel();
        let task = Box::new(Server(TestListener {
            incoming: Mutex::new(incoming),
            closed,
        }))
        .listen(sender)
        .await
        .unwrap();
        let (conn, packets, mut conn_closed) = TestConn::new();
        accept.send(conn).await.unwrap();
        let mut held = Vec::new();
        for _ in 0..128 {
            packets.send(vec![1]).await.unwrap();
            held.push(
                tokio::time::timeout(Duration::from_secs(2), requests.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        packets.send(vec![2]).await.unwrap();
        wait_closed(&mut conn_closed).await;
        assert!(requests.try_recv().is_err());
        held.clear();
        let (next, packets, mut next_closed) = TestConn::new();
        accept.send(next).await.unwrap();
        packets.send(vec![3]).await.unwrap();
        let (bytes, reply) = tokio::time::timeout(Duration::from_secs(2), requests.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes, vec![3]);
        drop(reply);
        drop(requests);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        wait_closed(&mut next_closed).await;
    }
}
