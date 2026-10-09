//! Modern DTLS socket adapter owned only by the Coaptic executable.
macro_rules! conn_as_any {
    () => {
        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
            self
        }
    };
}
#[path = "../../../tools/interop/dtls_listener.rs"]
pub(crate) mod listener;
use coaptic::storage::{DatagramIo, Endpoint};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};
use tokio::sync::mpsc as tmpsc;
use webrtc_dtls::{cipher_suite::CipherSuiteId, config::Config, conn::DTLSConn};
use webrtc_util::conn::Conn;
type Routes = Arc<Mutex<HashMap<SocketAddr, tmpsc::Sender<Vec<u8>>>>>;
pub struct DtlsIo {
    incoming: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    routes: Routes,
    worker: Option<tokio::task::JoinHandle<Result<(), String>>>,
}
impl DtlsIo {
    pub fn accepted(conn: Arc<dyn Conn + Send + Sync>, peer: SocketAddr) -> Self {
        let (tx, rx) = mpsc::sync_channel(64);
        let routes: Routes = Arc::default();
        let worker = attach(conn, peer, tx, routes.clone());
        Self {
            incoming: rx,
            routes,
            worker: Some(worker),
        }
    }
    pub async fn close(&mut self) -> Result<(), String> {
        self.routes.lock().expect("routes").clear();
        if let Some(worker) = self.worker.take() {
            tokio::time::timeout(Duration::from_secs(2), worker)
                .await
                .map_err(|_| "DTLS shutdown timeout".to_owned())?
                .map_err(|e| e.to_string())??;
        }
        Ok(())
    }
    pub async fn connect(
        addr: SocketAddr,
        config: Config,
        timeout: Duration,
    ) -> Result<Self, String> {
        let local = if addr.is_ipv6() {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        };
        let socket = tokio::net::UdpSocket::bind(local)
            .await
            .map_err(|e| e.to_string())?;
        socket.connect(addr).await.map_err(|e| e.to_string())?;
        let conn =
            tokio::time::timeout(timeout, DTLSConn::new(Arc::new(socket), config, true, None))
                .await
                .map_err(|_| "DTLS handshake timeout")?
                .map_err(|e| e.to_string())?;
        let (tx, rx) = mpsc::sync_channel(64);
        let routes: Routes = Arc::default();
        let worker = attach(Arc::new(conn), addr, tx, routes.clone());
        Ok(Self {
            incoming: rx,
            routes,
            worker: Some(worker),
        })
    }
}
fn attach(
    conn: Arc<dyn Conn + Send + Sync>,
    peer: SocketAddr,
    tx: mpsc::SyncSender<(SocketAddr, Vec<u8>)>,
    routes: Routes,
) -> tokio::task::JoinHandle<Result<(), String>> {
    let (out, mut rx) = tmpsc::channel::<Vec<u8>>(64);
    {
        let mut map = routes.lock().expect("routes");
        if map.len() >= 128 && !map.contains_key(&peer) {
            return tokio::spawn(async move { conn.close().await.map_err(|e| e.to_string()) });
        }
        map.insert(peer, out.clone());
    }
    let route = out.downgrade();
    drop(out);
    tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            tokio::select! {
                received=tokio::time::timeout(Duration::from_secs(5),conn.recv(&mut buf))=>match received {
                    Ok(Ok(n)) if n>0=> {if tx.try_send((peer,buf[..n].to_vec())).is_err(){break;}}, _=>break
                },
                outgoing=rx.recv()=>match outgoing {Some(bytes)=>{if conn.send(&bytes).await.is_err(){break;}},None=>break}
            }
        }
        {
            let mut map = routes.lock().expect("routes");
            if route.upgrade().is_some_and(|old| {
                map.get(&peer)
                    .is_some_and(|current| current.same_channel(&old))
            }) {
                map.remove(&peer);
            }
        }
        conn.close().await.map_err(|e| e.to_string())
    })
}
impl Drop for DtlsIo {
    fn drop(&mut self) {
        self.routes.lock().expect("routes").clear();
    }
}
impl DatagramIo for DtlsIo {
    type Error = std::io::Error;
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        match self.incoming.try_recv() {
            Ok((peer, bytes)) => {
                if bytes.len() > buf.len() {
                    return Err(std::io::Error::other("oversize DTLS datagram"));
                }
                buf[..bytes.len()].copy_from_slice(&bytes);
                Ok(Some((bytes.len(), peer.into())))
            }
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(_) => Err(std::io::Error::other("DTLS receiver closed")),
        }
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        let addr = std::net::SocketAddr::from(peer);
        self.routes
            .lock()
            .expect("routes")
            .get(&addr)
            .ok_or_else(|| std::io::Error::other("unknown DTLS session"))?
            .try_send(bytes.to_vec())
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(bytes.len())
    }
}
pub fn psk_config(key: &[u8]) -> Config {
    let key = key.to_vec();
    Config {
        psk: Some(Arc::new(move |_| Ok(key.clone()))),
        psk_identity_hint: Some(b"password".to_vec()),
        cipher_suites: vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8],
        ..Default::default()
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    struct ClosingConn {
        closed: AtomicBool,
        fail: bool,
    }
    #[async_trait::async_trait]
    impl Conn for ClosingConn {
        async fn connect(&self, _: SocketAddr) -> webrtc_util::Result<()> {
            Ok(())
        }
        async fn recv(&self, _: &mut [u8]) -> webrtc_util::Result<usize> {
            std::future::pending().await
        }
        async fn recv_from(&self, _: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        async fn send(&self, b: &[u8]) -> webrtc_util::Result<usize> {
            Ok(b.len())
        }
        async fn send_to(&self, b: &[u8], _: SocketAddr) -> webrtc_util::Result<usize> {
            Ok(b.len())
        }
        fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
            Ok("127.0.0.1:5684".parse().unwrap())
        }
        fn remote_addr(&self) -> Option<SocketAddr> {
            Some("127.0.0.1:5685".parse().unwrap())
        }
        async fn close(&self) -> webrtc_util::Result<()> {
            tokio::task::yield_now().await;
            self.closed.store(true, Ordering::SeqCst);
            if self.fail {
                Err(std::io::Error::other("injected close failure").into())
            } else {
                Ok(())
            }
        }
        conn_as_any!();
    }
    #[tokio::test]
    async fn explicit_shutdown_awaits_close_and_propagates_failure() {
        for fail in [false, true] {
            let conn = Arc::new(ClosingConn {
                closed: AtomicBool::new(false),
                fail,
            });
            let mut io = DtlsIo::accepted(conn.clone(), conn.remote_addr().unwrap());
            assert_eq!(io.close().await.is_err(), fail);
            assert!(conn.closed.load(Ordering::SeqCst));
        }
    }
}
