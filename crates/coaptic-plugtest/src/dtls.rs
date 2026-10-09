//! DTLS harness: webrtc-dtls (same stack as coap-rs) as a test-only dependency.
//!
//! The `coaptic` library crate does not terminate DTLS; its default is zero-dep.
//! This module wraps UDP + webrtc-dtls as a sync [`DatagramIo`] so
//! [`crate::coaptic::CoapticPeer`]'s `App::poll` (and the App client) see
//! plaintext CoAP. Mixed role pairs (`coap-rs→coaptic`, `coaptic→coap-rs`,
//! `coaptic→coaptic`) run the real handshake + GET `/secure`.
//!
//! PSK TDs use identity `password` / key `sesame` and
//! `TLS_PSK_WITH_AES_128_CCM_8` (ETSI CoAP#4).
//!
//! `TD_COAP_DTLS_01` records the handshake on the UDP socket (cipher offer,
//! selection, and Finished) plus the decrypted GET. `TD_COAP_DTLS_02`–`03`
//! and the raw-public-key TDs stay skipped: a plaintext `decrypt_error` is
//! not graded, each-flight loss is not injected, and this backend has no
//! RFC 7250 raw public key. X.509 qualification is a different test.

#[path = "../../../tools/interop/coap_dtls.rs"]
mod coap_dtls;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::mpsc as tokio_mpsc;
use webrtc_dtls::cipher_suite::CipherSuiteId;
use webrtc_dtls::config::{ClientAuthType, Config, ExtendedMasterSecretType};
use webrtc_dtls::conn::DTLSConn;
use webrtc_dtls::crypto::Certificate;
use webrtc_util::conn::conn_udp_listener::ListenConfig;
use webrtc_util::conn::{Conn, Listener};

use crate::pcap::{Capture, CapturingIo};
use crate::peer::PeerError;
use crate::runner::{Pair, TdResult};
use crate::site;
use coaptic::message::Code;
use coaptic::storage::{DatagramIo, Endpoint};

/// How long a handshake may take before the runner treats it as failed.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// ETSI PSK identity (ASCII).
pub const PSK_IDENTITY: &[u8] = b"password";
/// ETSI PSK key (ASCII).
pub const PSK_KEY: &[u8] = b"sesame";

/// Sync [`DatagramIo`] over a webrtc-dtls `Conn`.
///
/// A background tokio task pumps decrypted application data onto a channel.
/// [`DatagramIo::recv`] is non-blocking (`Ok(None)` when idle).
/// [`DatagramIo::send`] queues plaintext for the pump to encrypt.
///
/// This adapter lives in the harness crate so the `coaptic` library stays
/// zero-dep. `App::poll` and the App client treat it like any other socket.
pub struct DtlsIo {
    incoming: std_mpsc::Receiver<Vec<u8>>,
    outgoing: tokio_mpsc::UnboundedSender<Vec<u8>>,
    peer: Arc<Mutex<SocketAddr>>,
    local: SocketAddr,
}

impl DtlsIo {
    /// Local UDP address of the wrapped socket.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Listen for one DTLS handshake, then pump decrypted CoAP.
    ///
    /// `accept` runs in the background so the caller can bind [`App`] first.
    /// Handshake datagrams are copied into `capture` before DTLS consumes them.
    pub async fn listen(config: Config, capture: Capture) -> Result<(SocketAddr, Self), PeerError> {
        let mut lc = ListenConfig::default();
        let listener = lc
            .listen("127.0.0.1:0")
            .await
            .map_err(|e| format!("dtls listen: {e}"))?;
        let addr = listener
            .addr()
            .await
            .map_err(|e| format!("dtls addr: {e}"))?;
        let (in_tx, in_rx) = std_mpsc::channel();
        let (out_tx, out_rx) = tokio_mpsc::unbounded_channel();
        let peer = Arc::new(Mutex::new(addr));
        let peer_t = Arc::clone(&peer);
        let capture_t = capture.clone();
        tokio::spawn(async move {
            if let Ok((conn, raddr)) = listener.accept().await {
                *peer_t.lock().expect("dtls peer") = raddr;
                let tapped = Arc::new(TapConn::new(conn, capture_t, addr, raddr));
                if let Ok(dtls) = DTLSConn::new(tapped, config, false, None).await {
                    let dtls: Arc<dyn Conn + Send + Sync> = Arc::new(dtls);
                    pump(dtls, in_tx, out_rx).await;
                }
            }
        });
        Ok((
            addr,
            Self {
                incoming: in_rx,
                outgoing: out_tx,
                peer,
                local: addr,
            },
        ))
    }

    /// Client handshake, then pump decrypted CoAP.
    pub async fn connect(
        dest: SocketAddr,
        config: Config,
        capture: Capture,
    ) -> Result<Self, PeerError> {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("dtls bind: {e}"))?;
        let local = sock.local_addr().map_err(|e| format!("dtls local: {e}"))?;
        sock.connect(dest)
            .await
            .map_err(|e| format!("dtls connect: {e}"))?;
        let tapped = Arc::new(TapConn::new(Arc::new(sock), capture, local, dest));
        let conn =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, DTLSConn::new(tapped, config, true, None))
                .await
                .map_err(|_| PeerError("handshake: timeout".into()))?
                .map_err(|e| PeerError(format!("handshake: {e}")))?;
        let conn: Arc<dyn Conn + Send + Sync> = Arc::new(conn);
        let (in_tx, in_rx) = std_mpsc::channel();
        let (out_tx, out_rx) = tokio_mpsc::unbounded_channel();
        let conn_r = Arc::clone(&conn);
        tokio::spawn(async move {
            pump(conn_r, in_tx, out_rx).await;
        });
        Ok(Self {
            incoming: in_rx,
            outgoing: out_tx,
            peer: Arc::new(Mutex::new(dest)),
            local,
        })
    }
}

/// UDP [`Conn`] that records datagrams before DTLS encrypts or decrypts them.
struct TapConn {
    inner: Arc<dyn Conn + Send + Sync>,
    capture: Capture,
    local: SocketAddr,
    peer: Mutex<SocketAddr>,
}

impl TapConn {
    fn new(
        inner: Arc<dyn Conn + Send + Sync>,
        capture: Capture,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Self {
        Self {
            inner,
            capture,
            local,
            peer: Mutex::new(peer),
        }
    }
}

#[async_trait]
impl Conn for TapConn {
    async fn connect(&self, addr: SocketAddr) -> webrtc_util::Result<()> {
        self.inner.connect(addr).await
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        let n = self.inner.recv(buf).await?;
        let peer = *self.peer.lock().expect("dtls peer");
        self.capture.push(peer, self.local, &buf[..n], false);
        Ok(n)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        let (n, addr) = self.inner.recv_from(buf).await?;
        self.capture.push(addr, self.local, &buf[..n], false);
        Ok((n, addr))
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        let peer = *self.peer.lock().expect("dtls peer");
        self.capture.push(self.local, peer, buf, false);
        self.inner.send(buf).await
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc_util::Result<usize> {
        self.capture.push(self.local, target, buf, false);
        self.inner.send_to(buf, target).await
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(*self.peer.lock().expect("dtls peer"))
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        self.inner.close().await
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

impl DatagramIo for DtlsIo {
    type Error = std::io::Error;

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        match self.incoming.try_recv() {
            Ok(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                let peer = *self.peer.lock().expect("dtls peer");
                Ok(Some((n, Endpoint::from(peer))))
            }
            Err(std_mpsc::TryRecvError::Empty) => Ok(None),
            Err(std_mpsc::TryRecvError::Disconnected) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "dtls closed",
            )),
        }
    }

    fn send(&mut self, _dest: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.outgoing
            .send(bytes.to_vec())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "dtls closed"))?;
        Ok(bytes.len())
    }
}

async fn pump(
    conn: Arc<dyn Conn + Send + Sync>,
    in_tx: std_mpsc::Sender<Vec<u8>>,
    mut out_rx: tokio_mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let mut buf = [0u8; 2048];
    loop {
        tokio::select! {
            incoming = conn.recv(&mut buf) => {
                match incoming {
                    Ok(n) if n > 0 => {
                        if in_tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            outgoing = out_rx.recv() => {
                match outgoing {
                    Some(bytes) => {
                        if conn.send(&bytes).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
    let _ = conn.close().await;
}

/// PSK config for identity `password` / key `sesame` (or `wrong`).
#[must_use]
pub fn psk_config(key: &[u8]) -> Config {
    let key = key.to_vec();
    Config {
        psk: Some(Arc::new(move |_| Ok(key.clone()))),
        psk_identity_hint: Some(PSK_IDENTITY.to_vec()),
        cipher_suites: vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8],
        server_name: "localhost".into(),
        ..Default::default()
    }
}

/// Ephemeral mutually trusted X.509 certificate pair for qualification tests.
pub fn ecdsa_pair() -> Result<(Config, Config), PeerError> {
    let server = Certificate::generate_self_signed(vec!["localhost".into()])
        .map_err(|e| format!("server cert: {e}"))?;
    let client = Certificate::generate_self_signed(vec!["localhost".into()])
        .map_err(|e| format!("client cert: {e}"))?;
    let mut server_roots = rustls::RootCertStore::empty();
    let mut client_roots = rustls::RootCertStore::empty();
    server_roots
        .add(client.certificate[0].clone())
        .map_err(|e| format!("root: {e}"))?;
    client_roots
        .add(server.certificate[0].clone())
        .map_err(|e| format!("root: {e}"))?;
    let server_cfg = Config {
        certificates: vec![server],
        client_auth: ClientAuthType::RequireAndVerifyClientCert,
        client_cas: server_roots,
        cipher_suites: vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8],
        extended_master_secret: ExtendedMasterSecretType::Disable,
        ..Default::default()
    };
    let client_cfg = Config {
        certificates: vec![client],
        roots_cas: client_roots,
        server_name: "localhost".into(),
        cipher_suites: vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8],
        extended_master_secret: ExtendedMasterSecretType::Disable,
        ..Default::default()
    };
    Ok((client_cfg, server_cfg))
}

/// Run one DTLS TD on every role pair (mixed + same-impl).
///
/// `coaptic` terminates DTLS only via [`DtlsIo`] in this crate. The library
/// itself has no DTLS dependency.
pub fn run_dtls_pairs(id: &str, pairs: &[Pair]) -> Vec<TdResult> {
    pairs.iter().map(|pair| run_one(id, *pair)).collect()
}

fn run_one(id: &str, pair: Pair) -> TdResult {
    let _guard = crate::runner::harness_lock();
    if let Some(reason) = crate::catalog::skip_reason(id) {
        return TdResult {
            id: id.to_owned(),
            pair,
            error: Some(format!("SKIP: {reason}")),
            capture: Capture::new(),
        };
    }
    let err = match id {
        "TD_COAP_DTLS_01" => dtls_psk(pair, PSK_KEY, true),
        "TD_COAP_DTLS_02" => dtls_psk(pair, b"wrong", false),
        other => Err(PeerError(format!("unknown DTLS id {other}"))),
    };
    match err {
        Ok(capture) => {
            let grade = crate::grade::Catalog::load().and_then(|c| c.grade(id, &capture));
            TdResult {
                id: id.to_owned(),
                pair,
                error: grade.err(),
                capture,
            }
        }
        Err(e) => TdResult {
            id: id.to_owned(),
            pair,
            error: Some(e.0),
            capture: Capture::new(),
        },
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, PeerError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .map_err(|e| PeerError(e.to_string()))
}

fn dtls_psk(pair: Pair, client_key: &[u8], require_get: bool) -> Result<Capture, PeerError> {
    let capture = Capture::new();
    let outcome = runtime()?.block_on(run_pair(
        pair,
        psk_config(client_key),
        psk_config(PSK_KEY),
        &capture,
    ));
    if require_get {
        outcome?;
    }
    Ok(capture)
}

async fn run_pair(
    pair: Pair,
    client_cfg: Config,
    server_cfg: Config,
    capture: &Capture,
) -> Result<(), PeerError> {
    match (pair.client, pair.server) {
        ("coap-rs", "coaptic") => rs_to_coaptic(client_cfg, server_cfg, capture).await,
        ("coaptic", "coap-rs") => coaptic_to_rs(client_cfg, server_cfg, capture).await,
        ("coaptic", "coaptic") => coaptic_to_coaptic(client_cfg, server_cfg, capture).await,
        (c, s) => Err(PeerError(format!("unsupported DTLS pair {c}→{s}"))),
    }
}

async fn rs_to_coaptic(
    client_cfg: Config,
    server_cfg: Config,
    capture: &Capture,
) -> Result<(), PeerError> {
    let (addr, io) = DtlsIo::listen(server_cfg, capture.clone()).await?;
    let io = CapturingIo::new(io, addr, capture.clone()).decrypted();
    let server = spawn_coaptic_server(io);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let outcome = rs_get_secure(addr, client_cfg).await;
    server.stop();
    outcome
}

async fn coaptic_to_rs(
    client_cfg: Config,
    server_cfg: Config,
    capture: &Capture,
) -> Result<(), PeerError> {
    let addr = start_rs_server(server_cfg).await?;
    let io = DtlsIo::connect(addr, client_cfg, capture.clone()).await?;
    let local = io.local_addr();
    let io = CapturingIo::new(io, local, capture.clone()).decrypted();
    tokio::task::spawn_blocking(move || coaptic_get_secure(io, addr))
        .await
        .map_err(|e| PeerError(format!("join: {e}")))?
}

async fn coaptic_to_coaptic(
    client_cfg: Config,
    server_cfg: Config,
    capture: &Capture,
) -> Result<(), PeerError> {
    let (addr, server_io) = DtlsIo::listen(server_cfg, capture.clone()).await?;
    let server_io = CapturingIo::new(server_io, addr, capture.clone()).decrypted();
    let server = spawn_coaptic_server(server_io);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let outcome = async {
        let io = DtlsIo::connect(addr, client_cfg, capture.clone()).await?;
        let local = io.local_addr();
        let io = CapturingIo::new(io, local, capture.clone()).decrypted();
        tokio::task::spawn_blocking(move || coaptic_get_secure(io, addr))
            .await
            .map_err(|e| PeerError(format!("join: {e}")))?
    }
    .await;
    server.stop();
    outcome
}

struct ServerJoin {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl ServerJoin {
    fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn spawn_coaptic_server<T>(io: T) -> ServerJoin
where
    T: DatagramIo<Error = std::io::Error> + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    let join = thread::Builder::new()
        .name("coaptic-dtls-server".into())
        .spawn(move || serve_until(io, stop_t))
        .expect("spawn coaptic DTLS server");
    ServerJoin {
        stop,
        join: Some(join),
    }
}

fn serve_until<T>(io: T, stop: Arc<AtomicBool>)
where
    T: DatagramIo<Error = std::io::Error>,
{
    let mut app = crate::coaptic::bind_site(io);
    let origin = Instant::now();
    while !stop.load(Ordering::SeqCst) {
        let now = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        if app.poll(now).is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(2));
    }
}

/// Coaptic App client: GET `/secure` over a DTLS-decrypting [`DatagramIo`].
fn coaptic_get_secure<T: DatagramIo<Error = std::io::Error>>(
    io: T,
    dest: SocketAddr,
) -> Result<(), PeerError> {
    let got =
        crate::coaptic::app_exchange(io, dest, &crate::peer::ClientRequest::get(&["secure"]))?;
    if got.code != Code::CONTENT {
        return Err(PeerError(format!("GET /secure {}", got.code)));
    }
    if got.payload != site::SECURE_BODY {
        return Err(PeerError("GET /secure payload".into()));
    }
    Ok(())
}

async fn start_rs_server(cfg: Config) -> Result<SocketAddr, PeerError> {
    use coap::Server;
    use webrtc_dtls::listener::listen;

    let listener = listen("127.0.0.1:0", cfg)
        .await
        .map_err(|e| format!("listen: {e}"))?;
    let addr = listener.addr().await.map_err(|e| format!("addr: {e}"))?;
    let server = Server::from_listeners(vec![Box::new(coap_dtls::Server(listener))]);
    tokio::spawn(async move {
        let _ = server
            .run(
                |mut req: Box<coap_lite::CoapRequest<SocketAddr>>| async move {
                    if let Some(resp) = req.response.as_mut() {
                        resp.message.payload = site::SECURE_BODY.to_vec();
                    }
                    req
                },
            )
            .await;
    });
    tokio::time::sleep(Duration::from_millis(40)).await;
    Ok(addr)
}

async fn rs_get_secure(addr: SocketAddr, cfg: Config) -> Result<(), PeerError> {
    use coap::client::CoAPClient;
    let transport = coap_dtls::Client::connect(addr, cfg)
        .await
        .map_err(|e| PeerError(format!("handshake: {e}")))?;
    let connection = Arc::clone(&transport.0);
    let client = CoAPClient::from_transport(transport);
    let resp = client
        .send(
            coap::request::RequestBuilder::request_path(
                "/secure",
                coap_lite::RequestType::Get,
                None,
                vec![],
                Some(format!("coaps://{addr}/secure")),
            )
            .build(),
        )
        .await
        .map_err(|e| format!("GET /secure: {e}"))?;
    let _ = tokio::time::timeout(Duration::from_secs(1), connection.close()).await;
    if resp.message.header.code
        != coap_lite::MessageClass::Response(coap_lite::ResponseType::Content)
    {
        return Err(PeerError("GET /secure did not return 2.05".into()));
    }
    if resp.message.payload != site::SECURE_BODY {
        return Err(PeerError("GET /secure payload".into()));
    }
    Ok(())
}

/// Feature-gate helper so the runner can mention the adapter.
#[must_use]
pub fn adapter_note() -> &'static str {
    "DTLS: harness webrtc-dtls DatagramIo adapter. coaptic library has no DTLS dep; \
     App::poll / App client see plaintext CoAP over a DTLS-wrapped socket in this crate. \
     Mixed pairs (coap-rs→coaptic, coaptic→coap-rs, coaptic→coaptic) run handshake + GET /secure. \
     TD_COAP_DTLS_01 grades the UDP handshake and decrypted GET. DTLS_02–03 and \
     raw-public-key TDs stay skipped; X.509 tests do not establish RPK support."
}

#[cfg(test)]
mod qualification_tests {
    use super::*;

    #[test]
    fn psk_authentication_preserves_mixed_coap_get() {
        let _guard = crate::runner::harness_lock();
        for pair in crate::runner::default_pairs() {
            let capture = dtls_psk(pair, PSK_KEY, true).unwrap();
            assert!(capture.snapshot().iter().any(|packet| packet.decrypted));
            crate::grade::Catalog::load()
                .unwrap()
                .grade("TD_COAP_DTLS_01", &capture)
                .unwrap();
        }
    }

    #[test]
    fn unqualified_dtls_tds_and_uncaptured_pairs_cannot_pass() {
        for id in crate::catalog::DTLS {
            if crate::catalog::skip_reason(id).is_none() {
                continue;
            }
            for result in run_dtls_pairs(id, &crate::runner::default_pairs()) {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|e| e.starts_with("SKIP:")),
                    "{id}"
                );
                assert!(result.capture.snapshot().is_empty());
            }
        }
        let capture = Capture::new();
        assert!(
            runtime()
                .unwrap()
                .block_on(run_pair(
                    Pair {
                        client: "coap-rs",
                        server: "coap-rs"
                    },
                    psk_config(PSK_KEY),
                    psk_config(PSK_KEY),
                    &capture,
                ))
                .is_err()
        );
        assert!(capture.snapshot().is_empty());
    }

    #[test]
    fn mutual_x509_authentication_preserves_mixed_coap_get() {
        let _guard = crate::runner::harness_lock();
        for pair in crate::runner::default_pairs() {
            let (client, server) = ecdsa_pair().unwrap();
            let capture = Capture::new();
            runtime()
                .unwrap()
                .block_on(run_pair(pair, client, server, &capture))
                .unwrap();
        }
    }

    #[tokio::test]
    async fn x509_rejects_untrusted_server_and_client_with_verifier_evidence() {
        for reject_server in [true, false] {
            let (mut client_cfg, mut server_cfg) = ecdsa_pair().unwrap();
            // Use a valid but unrelated root, so refusal must occur during
            // peer verification rather than invalid local configuration.
            let stranger = Certificate::generate_self_signed(vec!["localhost".into()]).unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(stranger.certificate[0].clone()).unwrap();
            if reject_server {
                client_cfg.roots_cas = roots;
            } else {
                server_cfg.client_cas = roots;
            }
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.connect(server.local_addr().unwrap()).await.unwrap();
            server.connect(client.local_addr().unwrap()).await.unwrap();
            let outcomes = tokio::time::timeout(Duration::from_secs(4), async {
                tokio::join!(
                    DTLSConn::new(Arc::new(client), client_cfg, true, None),
                    DTLSConn::new(Arc::new(server), server_cfg, false, None),
                )
            })
            .await
            .expect("timeout is not certificate-refusal evidence");
            let (verifier, remote) = if reject_server {
                outcomes
            } else {
                (outcomes.1, outcomes.0)
            };
            let error = match verifier {
                Ok(_) => panic!("accepted untrusted certificate"),
                Err(e) => e,
            };
            assert!(
                matches!(error, webrtc_dtls::Error::Other(ref reason) if matches!(reason.as_str(), "invalid peer certificate: UnknownIssuer" | "invalid peer certificate: BadSignature")),
                "wrong refusal: {error:?}"
            );
            assert!(
                remote.is_err(),
                "other endpoint must not complete authentication"
            );
        }
    }
}
