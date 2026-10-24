//! Independent server fixtures; no request-path logging or shared driver code.
//!
//! `coaptic` and `coaptic-reusable` select the bare socket and caller-owned
//! scratch adapters once at startup. Both accept an optional RX capacity of
//! 1472 or 2048 bytes and share the same App configuration and polling loop.
//! TX capacity stays 1472 bytes; reusable scratch reserves 2049 bytes once.
//! Setup allocations precede the external driver's timed request phase.
//!
//! `coaptic-ready` uses Tokio's registered UDP socket, caller-owned scratch,
//! and readiness-driven bounded drain bursts. Idle waits end at the App's next
//! protocol opportunity, including retained work and timers without ingress.
//! These static fixtures have no external application signals to wake them.
//! This is a host scheduling experiment, not a core change.
//! `coaptic-mio` applies the same policy directly through Mio without an async
//! runtime. These variants retain the same protocol processing and pools.
//! `coaptic-async` uses App's native async wait/progress boundary on the same
//! current-thread Tokio runtime and emits one startup inline-storage ledger.
//! `coaptic-blocking` stages bounded synchronous receives before App polling,
//! with soft socket timeouts and a distinct synchronous send congestion policy.
//! `coaptic-staged-ready` stages a nonblocking receive in the same reusable scratch
//! before polling App, preserving ready's immediate try_send_to congestion policy.
//! Explicit coaptic-staged-mio combines staging with direct Mio and immediate send_to.
//! Linux-only coaptic-mio-direct receives into the borrowed Engine RX slot with
//! MSG_TRUNC, retaining Mio's scheduler and immediate send acceptance semantics.
#![forbid(unsafe_code)]
macro_rules! conn_as_any {
    () => {
        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
            self
        }
    };
}
#[path = "../../../../interop/coap_dtls.rs"]
#[allow(
    dead_code,
    reason = "The shared interop module also supplies an unused client transport."
)]
mod coap_dtls;
#[cfg(target_os = "linux")]
mod direct_udp;
#[path = "../../../../interop/dtls_listener.rs"]
mod dtls_listener;
mod staged_mio;
mod staged_ready;
mod staged_udp;
use coap_lite::{CoapOption, MessageClass, MessageType, Packet, ResponseType};
use coaptic::oscore::{DeriveParams, SecurityContext};
use coaptic::storage::{AllocMemory, Capacities, DatagramIo, Endpoint, UdpSocketIo};
use coaptic::{App, ContentFormat, Request, Response, get};
use std::{
    env,
    io::{Read, Write},
    net::UdpSocket,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

static BODY: OnceLock<&'static [u8]> = OnceLock::new();

fn representation(_: Request<'_>) -> Response<'static> {
    Response::content(BODY.get().expect("initialized fixture"))
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"fixture")
}

async fn coap_rs_server(
    address: &str,
    body: &'static [u8],
    config: Option<webrtc_dtls::config::Config>,
) -> Result<(), Box<dyn std::error::Error>> {
    let server = if let Some(config) = config {
        let listener = dtls_listener::BoundedListener::bind(address.parse()?, config).await?;
        coap::Server::from_listeners(vec![Box::new(coap_dtls::Server(listener))])
    } else {
        coap::Server::new_udp(address)?
    };
    let body: Arc<[u8]> = Arc::from(body);
    server
        .run(
            move |mut request: Box<coap_lite::CoapRequest<std::net::SocketAddr>>| {
                let body = Arc::clone(&body);
                async move {
                    if let Some(response) = request.response.as_mut() {
                        response.message.header.code =
                            MessageClass::Response(ResponseType::Content);
                        response.message.payload = body.to_vec();
                        response
                            .message
                            .set_option(CoapOption::ContentFormat, [vec![42]].into());
                        response
                            .message
                            .set_option(CoapOption::ETag, [b"fixture".to_vec()].into());
                    }
                    request
                }
            },
        )
        .await?;
    Ok(())
}

fn dtls_config(path: &str) -> Result<webrtc_dtls::config::Config, Box<dyn std::error::Error>> {
    let mut material = [0; 24];
    let mut file = std::fs::File::open(path)?;
    file.read_exact(&mut material)?;
    if file.read(&mut [0])? != 0 {
        return Err("expected 24-byte ephemeral credentials".into());
    }
    let key = material[..16].to_vec();
    material.fill(0);
    Ok(webrtc_dtls::config::Config {
        psk: Some(Arc::new(move |identity| {
            if identity != b"benchmark" {
                return Err(std::io::Error::other("unexpected DTLS identity").into());
            }
            Ok(key.clone())
        })),
        psk_identity_hint: Some(b"benchmark".to_vec()),
        cipher_suites: vec![webrtc_dtls::cipher_suite::CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8],
        ..Default::default()
    })
}

// The quick-check path keeps the public SmallDevice preset unchanged.
static SMALL_BODY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

fn small_device_server(
    address: &str,
    context: Option<SecurityContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(address)?;
    socket.set_nonblocking(true)?;
    let io = UdpSocketIo::new(socket, [0u8; 1153])?;
    let adapter_bytes = std::mem::size_of_val(&io);
    let builder = App::with_resources(coaptic::resources::SmallDevice::new())
        .randomness(|buffer| getrandom::fill(buffer).is_ok())
        .route("bench", get(representation));
    let security = if context.is_some() {
        "volatile-oscore"
    } else {
        "unprotected"
    };
    let builder = if let Some(context) = context {
        builder.oscore(context)
    } else {
        builder.allow_unprotected()
    };
    let mut app = builder.bind(io)?;
    println!(
        "{{\"profile\":\"SmallDevice\",\"pools\":\"Constrained\",\"storage\":\"fixed\",\"routes\":4,\"populated_routes\":1,\"calls\":1,\"deferred\":0,\"associations\":1,\"security_requests\":4,\"blockwise\":false,\"rx_slots\":2,\"tx_slots\":2,\"datagram_bytes\":1152,\"dedup\":4,\"observe\":2,\"body_bytes\":32,\"udp_scratch_bytes\":1153,\"adapter_bytes\":{},\"app_including_adapter_bytes\":{},\"security\":\"{}\",\"schedule\":\"single-thread spin\"}}",
        adapter_bytes,
        std::mem::size_of_val(&app),
        security
    );
    let started = Instant::now();
    loop {
        match app.poll(started.elapsed().as_millis() as u64) {
            Ok(()) | Err(coaptic::app::Error::Oscore(_)) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn bind_fixture<T: coaptic::storage::DatagramTransport<Error = std::io::Error>>(
    io: T,
    bytes: usize,
    rx_bytes: usize,
    context: Option<SecurityContext>,
) -> Result<App<coaptic::profiles::Default, T, 1, true, AllocMemory>, Box<dyn std::error::Error>> {
    let capacities = Capacities {
        rx_datagram_slots: 4,
        rx_datagram_bytes: rx_bytes,
        tx_datagram_slots: 4,
        tx_datagram_bytes: 1472,
        dedup_entries: 8,
        observe_entries: 4,
        rx_body_slots: Some(1),
        rx_body_bytes: Some(bytes.div_ceil(1024) * 1024),
        tx_body_slots: Some(2),
        tx_body_bytes: Some(bytes.div_ceil(1024) * 1024),
    };
    let builder = App::builder()
        .routes::<1>()
        .block_wise::<true>()
        .randomness(|buffer| getrandom::fill(buffer).is_ok())
        .route("bench", get(representation));
    let builder = if let Some(context) = context {
        builder.oscore(context)
    } else {
        builder.allow_unprotected()
    };
    Ok(builder.bind_alloc(io, capacities)?)
}

struct DtlsIo {
    conn: Arc<dyn webrtc_util::conn::Conn + Send + Sync>,
    peer: Endpoint,
    scratch: [u8; 1473],
}

impl coaptic::storage::DatagramTransport for DtlsIo {
    type Error = std::io::Error;
}

impl coaptic::storage::AsyncDatagramIo for DtlsIo {
    async fn recv(&mut self, output: &mut [u8]) -> std::io::Result<(usize, Endpoint)> {
        let required = output
            .len()
            .checked_add(1)
            .filter(|n| *n <= self.scratch.len())
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        let n = self
            .conn
            .recv(&mut self.scratch[..required])
            .await
            .map_err(std::io::Error::other)?;
        if n > output.len() {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        output[..n].copy_from_slice(&self.scratch[..n]);
        Ok((n, self.peer))
    }
    async fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> std::io::Result<usize> {
        if peer != self.peer {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        self.conn.send(bytes).await.map_err(std::io::Error::other)
    }
}

struct AppTimer(Instant);
impl coaptic::platform::AsyncTimer for AppTimer {
    async fn wait_until(&mut self, deadline_ms: u64) {
        tokio::time::sleep_until((self.0 + Duration::from_millis(deadline_ms)).into()).await;
    }
}

async fn coaptic_dtls_server(
    address: &str,
    bytes: usize,
    config: webrtc_dtls::config::Config,
) -> Result<(), Box<dyn std::error::Error>> {
    use webrtc_util::conn::Listener as _;
    let listener = dtls_listener::BoundedListener::bind(address.parse()?, config).await?;
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let (conn, peer) = accepted?;
                if tasks.len() >= 128 {
                    let _ = tokio::time::timeout(Duration::from_secs(1), conn.close()).await;
                    continue;
                }
                tasks.spawn_local(async move {
                    let io = DtlsIo {conn: Arc::clone(&conn), peer: peer.into(), scratch: [0; 1473]};
                    // One unchanged bounded App per DTLS session; the transport
                    // authenticates records before plaintext reaches the App.
                    let Ok(mut app) = bind_fixture(io, bytes, 1472, None) else { return; };
                    let epoch = Instant::now();
                    let now = || epoch.elapsed().as_millis() as u64;
                    let mut clock = || Ok::<u64, std::io::Error>(now());
                    let mut timer = AppTimer(epoch);
                    loop {
                        if app.wait_async(now(), &mut timer, std::future::pending::<()>()).await.is_err() { break; }
                        if app.progress_async(now(), &mut clock, &mut timer, now() + 1000).await.is_err() { break; }
                    }
                    let _ = tokio::time::timeout(Duration::from_secs(1), conn.close()).await;
                });
            }
        }
    }
}

fn coaptic_server<T: DatagramIo<Error = std::io::Error>>(
    io: T,
    bytes: usize,
    rx_bytes: usize,
    context: Option<SecurityContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut app = bind_fixture(io, bytes, rx_bytes, context)?;
    let started = Instant::now();
    loop {
        match app.poll(started.elapsed().as_millis() as u64) {
            Ok(()) | Err(coaptic::app::Error::Oscore(_)) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

// Opt-in, fixed storage in unit tests only. These are logical call counts, not
// syscall counts: Tokio may return WouldBlock from its cached readiness alone.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TransportCounts {
    app_polls: u32,
    recv_calls: u32,
    recv_empty: u32,
    socket_recv_calls: u32,
    socket_send_calls: u32,
    readable_waits: u32,
    read_timeout_sets: u32,
}

#[cfg(test)]
impl TransportCounts {
    fn inc(value: &mut u32) {
        *value = value.saturating_add(1);
    }
}

struct ReadyUdp {
    socket: tokio::net::UdpSocket,
    scratch: [u8; 2049],
    received: bool,
    #[cfg(test)]
    counts: Option<TransportCounts>,
}

fn receive_guarded(
    buf: &mut [u8],
    scratch: &mut [u8],
    recv: impl FnOnce(&mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)>,
) -> std::io::Result<Option<(usize, Endpoint)>> {
    let scratch = guarded_scratch(buf.len(), scratch)?;
    match recv(scratch) {
        Ok(packet) => finish_receive(buf, scratch, packet).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

fn guarded_scratch(capacity: usize, scratch: &mut [u8]) -> std::io::Result<&mut [u8]> {
    let required = capacity
        .checked_add(1)
        .ok_or(std::io::ErrorKind::InvalidInput)?;
    scratch
        .get_mut(..required)
        .ok_or_else(|| std::io::ErrorKind::InvalidInput.into())
}

fn finish_receive(
    buf: &mut [u8],
    scratch: &[u8],
    (n, peer): (usize, std::net::SocketAddr),
) -> std::io::Result<(usize, Endpoint)> {
    if n > buf.len() {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    buf[..n].copy_from_slice(&scratch[..n]);
    Ok((n, peer.into()))
}

impl coaptic::storage::DatagramTransport for ReadyUdp {
    type Error = std::io::Error;
}
impl DatagramIo for ReadyUdp {
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        #[cfg(test)]
        if let Some(counts) = &mut self.counts {
            TransportCounts::inc(&mut counts.recv_calls);
        }
        self.received = false;
        let result = receive_guarded(buf, &mut self.scratch, |scratch| {
            #[cfg(test)]
            if let Some(counts) = &mut self.counts {
                TransportCounts::inc(&mut counts.socket_recv_calls);
            }
            self.socket.try_recv_from(scratch)
        });
        #[cfg(test)]
        if let Some(counts) = &mut self.counts
            && matches!(result, Ok(None))
        {
            TransportCounts::inc(&mut counts.recv_empty);
        }
        self.received = result.as_ref().is_ok_and(Option::is_some);
        result
    }

    fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        #[cfg(test)]
        if let Some(counts) = &mut self.counts {
            TransportCounts::inc(&mut counts.socket_send_calls);
        }
        self.socket
            .try_send_to(bytes, std::net::SocketAddr::from(dest))
    }
}

impl coaptic::storage::AsyncDatagramIo for ReadyUdp {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, Endpoint)> {
        self.received = false;
        let scratch = guarded_scratch(buf.len(), &mut self.scratch)?;
        let packet = self.socket.recv_from(scratch).await?;
        let result = finish_receive(buf, scratch, packet);
        self.received = result.is_ok();
        result
    }

    async fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> std::io::Result<usize> {
        self.socket
            .send_to(bytes, std::net::SocketAddr::from(dest))
            .await
    }
}

type AsyncUdpApp = App<coaptic::profiles::Default, ReadyUdp, 1, true, AllocMemory>;

async fn async_udp_loop(
    app: &mut AsyncUdpApp,
    epoch: Instant,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = || epoch.elapsed().as_millis() as u64;
    let mut clock = || Ok::<u64, std::io::Error>(now());
    let mut timer = AppTimer(epoch);
    loop {
        for _ in 0..32 {
            // App races local work/deadlines before ingress and retains a winning
            // receive in its RX pool. This static fixture has no local signals.
            app.wait_async(now(), &mut timer, std::future::pending::<()>())
                .await?;
            let now_ms = now();
            // App further limits this send budget to its next protocol deadline.
            match app
                .progress_async(now_ms, &mut clock, &mut timer, now_ms.saturating_add(1000))
                .await
            {
                Ok(()) | Err(coaptic::app::Error::Oscore(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        tokio::task::yield_now().await;
    }
}

async fn async_udp_server(
    address: &str,
    bytes: usize,
    rx_bytes: usize,
    context: Option<SecurityContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    let io = ReadyUdp {
        socket: tokio::net::UdpSocket::bind(address).await?,
        scratch: [0; 2049],
        received: false,
        #[cfg(test)]
        counts: None,
    };
    let adapter_bytes = std::mem::size_of_val(&io);
    let mut app = bind_fixture(io, bytes, rx_bytes, context)?;
    let app_bytes = std::mem::size_of_val(&app);
    let run = async_udp_loop(&mut app, Instant::now());
    // App owns the adapter and scratch; the separate loop future borrows App.
    // Both live in the outer setup future, whose complete layout is not reported.
    println!(
        "{{\"schema\":\"coaptic-native-server-resources/2\",\"server_kind\":\"coaptic-async\",\"udp_scratch_bytes\":2049,\"adapter_inline_bytes\":{adapter_bytes},\"app_including_adapter_bytes\":{app_bytes},\"loop_future_borrowing_app_bytes\":{},\"runtime_heap_bytes\":null,\"runtime_stack_bytes\":null,\"nesting\":\"scratch inside adapter inside App; loop future borrows separate App; both inside outer setup future; do not sum nested owners\",\"limits\":\"inline component sizes only; complete outer setup future, core heap, response body, runtime heap, thread and polling stacks, allocator and kernel costs excluded and unknown\"}}",
        std::mem::size_of_val(&run)
    );
    std::io::stdout().flush()?;
    run.await
}

struct MioUdp<const SCRATCH: usize = 2049> {
    socket: mio::net::UdpSocket,
    scratch: [u8; SCRATCH],
    received: bool,
}

impl<const SCRATCH: usize> coaptic::storage::DatagramTransport for MioUdp<SCRATCH> {
    type Error = std::io::Error;
}
impl<const SCRATCH: usize> DatagramIo for MioUdp<SCRATCH> {
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        self.received = false;
        let result = if SCRATCH == 0 {
            #[cfg(target_os = "linux")]
            {
                direct_udp::receive(&self.socket, buf)
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(std::io::ErrorKind::Unsupported.into())
            }
        } else {
            receive_guarded(buf, &mut self.scratch, |scratch| {
                self.socket.recv_from(scratch)
            })
        };
        self.received = result.as_ref().is_ok_and(Option::is_some);
        result
    }

    fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.socket.send_to(bytes, std::net::SocketAddr::from(dest))
    }
}

fn mio_server<const SCRATCH: usize>(
    address: &str,
    bytes: usize,
    rx_bytes: usize,
    context: Option<SecurityContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(address)?;
    socket.set_nonblocking(true)?;
    let mut io = MioUdp {
        socket: mio::net::UdpSocket::from_std(socket),
        scratch: [0; SCRATCH],
        received: false,
    };
    let mut poll = mio::Poll::new()?;
    poll.registry()
        .register(&mut io.socket, mio::Token(0), mio::Interest::READABLE)?;
    let mut events = mio::Events::with_capacity(8);
    let adapter_bytes = std::mem::size_of_val(&io);
    let mut app = bind_fixture(io, bytes, rx_bytes, context)?;
    println!(
        "{{\"schema\":\"coaptic-native-mio-resources/1\",\"server_kind\":\"{}\",\"udp_scratch_bytes\":{SCRATCH},\"adapter_inline_bytes\":{adapter_bytes},\"app_including_adapter_bytes\":{},\"poll_inline_bytes\":{},\"events_inline_bytes\":{},\"event_capacity\":{},\"worker_threads\":0,\"pending_kernel_operations\":0,\"runtime_heap_bytes\":null,\"runtime_stack_bytes\":null,\"kernel_bytes\":null,\"nesting\":\"scratch inside adapter inside App; poll and event owners separate; no extra packet buffers\",\"limits\":\"inline sizes only; event heap, App heap, body, allocator, peak stack and kernel socket/selector storage require separate accounting\"}}",
        if SCRATCH == 0 {
            "coaptic-mio-direct"
        } else {
            "coaptic-mio"
        },
        std::mem::size_of_val(&app),
        std::mem::size_of_val(&poll),
        std::mem::size_of_val(&events),
        events.capacity(),
    );
    std::io::stdout().flush()?;
    let started = Instant::now();
    loop {
        let idle = mio_burst(&mut app, started)?;
        let now_ms = started.elapsed().as_millis() as u64;
        let timeout = if idle {
            app.next_poll_at(now_ms).map(|due| {
                (started + Duration::from_millis(due)).saturating_duration_since(Instant::now())
            })
        } else {
            Some(Duration::ZERO)
        };
        match poll.poll(&mut events, timeout) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        }
    }
}

fn mio_burst<const SCRATCH: usize>(
    app: &mut App<coaptic::profiles::Default, MioUdp<SCRATCH>, 1, true, AllocMemory>,
    started: Instant,
) -> Result<bool, Box<dyn std::error::Error>> {
    for _ in 0..32 {
        match app.poll(started.elapsed().as_millis() as u64) {
            Ok(()) | Err(coaptic::app::Error::Oscore(_)) => {}
            // A consumed oversized packet is not an empty socket. Keep draining
            // to WouldBlock before an edge-triggered wait; do not parse its prefix.
            Err(coaptic::app::Error::Io(coaptic::storage::DatagramIoError::Io(error)))
                if error.kind() == std::io::ErrorKind::InvalidData =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        if !app.transport().received {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ready_burst(
    app: &mut AsyncUdpApp,
    started: Instant,
) -> Result<bool, Box<dyn std::error::Error>> {
    for _ in 0..32 {
        #[cfg(test)]
        if let Some(counts) = &mut app.transport_mut().counts {
            TransportCounts::inc(&mut counts.app_polls);
        }
        match app.poll(started.elapsed().as_millis() as u64) {
            Ok(()) | Err(coaptic::app::Error::Oscore(_)) => {}
            Err(error) => return Err(error.into()),
        }
        if !app.transport().received {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn ready_wait(
    app: &mut AsyncUdpApp,
    started: Instant,
) -> Result<(), Box<dyn std::error::Error>> {
    let now_ms = started.elapsed().as_millis() as u64;
    #[cfg(test)]
    if let Some(counts) = &mut app.transport_mut().counts {
        TransportCounts::inc(&mut counts.readable_waits);
    }
    match app.next_poll_at(now_ms) {
        Some(due) => {
            let deadline = started + Duration::from_millis(due);
            if let Ok(ready) =
                tokio::time::timeout_at(deadline.into(), app.transport().socket.readable()).await
            {
                ready?;
            }
        }
        None => app.transport().socket.readable().await?,
    }
    Ok(())
}

async fn ready_server(
    address: &str,
    bytes: usize,
    rx_bytes: usize,
    context: Option<SecurityContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    let io = ReadyUdp {
        socket: tokio::net::UdpSocket::bind(address).await?,
        scratch: [0; 2049],
        received: false,
        #[cfg(test)]
        counts: None,
    };
    let mut app = bind_fixture(io, bytes, rx_bytes, context)?;
    let started = Instant::now();
    loop {
        if ready_burst(&mut app, started)? {
            ready_wait(&mut app, started).await?;
        } else {
            tokio::task::yield_now().await;
        }
    }
}

fn codec_server(address: &str, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(address)?;
    let mut bytes = [0u8; 65_535];
    loop {
        let (count, peer) = socket.recv_from(&mut bytes)?;
        let request = match Packet::from_bytes(&bytes[..count]) {
            Ok(packet) => packet,
            Err(_) => continue,
        };
        if request.header.code != MessageClass::Request(coap_lite::RequestType::Get) {
            continue;
        }
        let block = request
            .get_option(CoapOption::Block2)
            .and_then(|values| values.front())
            .map(|v| {
                v.iter()
                    .fold(0usize, |value, byte| value << 8 | usize::from(*byte))
            });
        let number = block.unwrap_or(0) >> 4;
        let size = if let Some(value) = block {
            1usize << ((value & 7).min(6) + 4)
        } else {
            1024
        };
        let offset = number * size;
        if offset >= body.len() {
            continue;
        }
        let end = (offset + size).min(body.len());
        let mut response = Packet::new();
        response
            .header
            .set_type(if request.header.get_type() == MessageType::Confirmable {
                MessageType::Acknowledgement
            } else {
                MessageType::NonConfirmable
            });
        response.header.message_id = request.header.message_id;
        response.header.code = MessageClass::Response(ResponseType::Content);
        response.set_token(request.get_token().to_vec());
        response.payload = body[offset..end].to_vec();
        response.set_option(CoapOption::ContentFormat, [vec![42]].into());
        if block.is_some() || body.len() > 1024 {
            let raw = number << 4
                | usize::from(end < body.len()) << 3
                | (size.trailing_zeros() as usize - 4);
            let value = (raw as u32).to_be_bytes();
            let first = value.iter().position(|byte| *byte != 0).unwrap_or(4);
            response.set_option(CoapOption::Block2, [value[first..].to_vec()].into());
        }
        socket.send_to(&response.to_bytes()?, peer)?;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() == 2 && args[1] == "--security-profile" {
        println!(
            "{{\"security\":\"OSCORE-AES-CCM-16-64-128\",\"replay_window\":{}}}",
            coaptic::oscore::REPLAY_WINDOW
        );
        return Ok(());
    }
    if args
        .get(1)
        .is_some_and(|name| matches!(name.as_str(), "coap-rs-dtls" | "coaptic-dtls"))
    {
        if args.len() != 6 || args[2] != "127.0.0.1" {
            return Err(
                "bench-rust-server coap-rs-dtls|coaptic-dtls 127.0.0.1 PORT BYTES CREDENTIALS"
                    .into(),
            );
        }
        let size: usize = args[4].parse()?;
        if !(1..=1_048_576).contains(&size) {
            return Err("fixture size".into());
        }
        let config = dtls_config(&args[5])?;
        let body: &'static [u8] = Box::leak(
            (0..size)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        BODY.set(body).map_err(|_| "fixture initialization")?;
        let address = format!("{}:{}", args[2], args[3]);
        return if args[1] == "coap-rs-dtls" {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?;
            runtime.block_on(coap_rs_server(&address, body, Some(config)))
        } else {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            tokio::task::LocalSet::new()
                .block_on(&runtime, coaptic_dtls_server(&address, size, config))
        };
    }
    if !(5..=7).contains(&args.len()) {
        return Err(
            "usage: bench-rust-server coaptic-small|coaptic|coaptic-reusable|coaptic-ready|coaptic-staged-ready|coaptic-staged-mio|coaptic-mio|coaptic-mio-direct|coaptic-async|coaptic-blocking|coap-rs|coap-lite-codec HOST PORT BYTES [RX_BYTES [OSCORE_CREDENTIAL_FILE]]".into(),
        );
    }
    let rx_bytes: usize = args
        .get(5)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(if args[1] == "coaptic-small" {
            1152
        } else {
            1472
        });
    if (args[1] == "coaptic-small" && rx_bytes != 1152)
        || (args[1] != "coaptic-small" && ![1472, 2048].contains(&rx_bytes))
    {
        return Err(
            "SmallDevice requires 1152-byte receive capacity; other fixtures require 1472 or 2048"
                .into(),
        );
    }
    if args.len() >= 6
        && !matches!(
            args[1].as_str(),
            "coaptic-small"
                | "coaptic"
                | "coaptic-reusable"
                | "coaptic-ready"
                | "coaptic-staged-ready"
                | "coaptic-staged-mio"
                | "coaptic-mio"
                | "coaptic-mio-direct"
                | "coaptic-async"
                | "coaptic-blocking"
        )
    {
        return Err("receive capacity is supported only by the Coaptic fixtures".into());
    }
    if args.len() == 7
        && !matches!(
            args[1].as_str(),
            "coaptic-small"
                | "coaptic"
                | "coaptic-reusable"
                | "coaptic-ready"
                | "coaptic-staged-ready"
                | "coaptic-staged-mio"
                | "coaptic-mio"
                | "coaptic-mio-direct"
                | "coaptic-async"
                | "coaptic-blocking"
        )
    {
        return Err("OSCORE credentials require the Coaptic socket fixtures".into());
    }
    if args.len() == 7 && args[2] != "127.0.0.1" {
        return Err("ephemeral benchmark credentials are loopback only".into());
    }
    let context = args
        .get(6)
        .map(|path| -> Result<_, Box<dyn std::error::Error>> {
            let mut material = [0; 24];
            let mut file = std::fs::File::open(path)?;
            file.read_exact(&mut material)?;
            if file.read(&mut [0])? != 0 {
                return Err("expected 24-byte ephemeral benchmark credentials".into());
            }
            let result = SecurityContext::derive(DeriveParams {
                master_secret: &material[..16],
                master_salt: &material[16..],
                sender_id: &[1],
                recipient_id: &[],
                id_context: &[],
            });
            material.fill(0);
            Ok(result?)
        })
        .transpose()?;
    let size: usize = args[4].parse()?;
    if !(1..=1_048_576).contains(&size) {
        return Err("fixture size".into());
    }
    if args[1] == "coaptic-small" {
        if size != SMALL_BODY.len() || args[2] != "127.0.0.1" {
            return Err("SmallDevice quick check requires loopback and 32 bytes".into());
        }
        BODY.set(&SMALL_BODY)
            .map_err(|_| "fixture initialization")?;
        return small_device_server(&format!("{}:{}", args[2], args[3]), context);
    }
    let body: &'static [u8] = Box::leak(
        (0..size)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    BODY.set(body).map_err(|_| "fixture initialization")?;
    let address = format!("{}:{}", args[2], args[3]);
    match args[1].as_str() {
        "coaptic" | "coaptic-reusable" => {
            let socket = UdpSocket::bind(&address)?;
            socket.set_nonblocking(true)?;
            if args[1] == "coaptic-reusable" {
                coaptic_server(
                    UdpSocketIo::new(socket, [0u8; 2049])?,
                    size,
                    rx_bytes,
                    context,
                )
            } else {
                coaptic_server(socket, size, rx_bytes, context)
            }
        }
        "coap-lite-codec" => codec_server(&address, body),
        "coaptic-blocking" => staged_udp::serve(&address, size, rx_bytes, context),
        "coaptic-staged-mio" => staged_mio::serve(&address, size, rx_bytes, context),
        "coaptic-mio" => mio_server::<2049>(&address, size, rx_bytes, context),
        #[cfg(target_os = "linux")]
        "coaptic-mio-direct" => mio_server::<0>(&address, size, rx_bytes, context),
        #[cfg(not(target_os = "linux"))]
        "coaptic-mio-direct" => Err("coaptic-mio-direct requires Linux MSG_TRUNC semantics".into()),
        "coaptic-ready" => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(ready_server(&address, size, rx_bytes, context)),
        "coaptic-staged-ready" => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(staged_ready::serve(&address, size, rx_bytes, context)),
        "coaptic-async" => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async_udp_server(&address, size, rx_bytes, context)),
        "coap-rs" => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(coap_rs_server(&address, body, None)),
        _ => Err("unknown implementation".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coaptic::message::{Message, MessageId, Type};

    fn async_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    async fn async_test_io(host: &str) -> ReadyUdp {
        ReadyUdp {
            socket: tokio::net::UdpSocket::bind(host).await.unwrap(),
            scratch: [0; 2049],
            received: false,
            counts: None,
        }
    }

    #[test]
    fn finite_ready_idle_call_counts_and_wait_cancellation() {
        let mut saturated = u32::MAX;
        TransportCounts::inc(&mut saturated);
        assert_eq!(saturated, u32::MAX);
        assert!(std::mem::size_of::<Option<TransportCounts>>() <= 32);
        async_runtime().block_on(async {
            let mut io = async_test_io("127.0.0.1:0").await;
            assert!(io.counts.is_none());
            io.counts = Some(TransportCounts::default());
            let mut app = bind_fixture(io, 64, 1472, None).unwrap();
            let epoch = Instant::now();
            for _ in 0..2 {
                assert!(ready_burst(&mut app, epoch).unwrap());
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(1), ready_wait(&mut app, epoch))
                    .await
                    .is_err()
            );
            let counts = app.transport().counts.unwrap();
            assert_eq!(
                counts,
                TransportCounts {
                    app_polls: 2,
                    recv_calls: 2,
                    recv_empty: 2,
                    socket_recv_calls: 2,
                    readable_waits: 1,
                    ..TransportCounts::default()
                }
            );
            assert_eq!(app.metrics().rx_accepted, 0);
            println!(
                "ready idle, two finite bursts + one cancelled wait, logical calls: {counts:?}"
            );
        });
    }

    #[test]
    fn async_receive_preserves_guard_cancellation_endpoint_and_recovery() {
        use coaptic::storage::AsyncDatagramIo;
        async_runtime().block_on(async {
            for host in ["127.0.0.1:0", "[::1]:0"] {
                for capacity in [64, 1472, 2048] {
                    let mut io = async_test_io(host).await;
                    let local = io.socket.local_addr().unwrap();
                    let sender = tokio::net::UdpSocket::bind(host).await.unwrap();
                    let peer = sender.local_addr().unwrap();
                    let mut buf = vec![0xa5; capacity];
                    assert!(
                        tokio::time::timeout(
                            Duration::from_millis(5),
                            AsyncDatagramIo::recv(&mut io, &mut buf)
                        )
                        .await
                        .is_err()
                    );
                    for size in [capacity, capacity + 1, capacity + 8, 0, 3] {
                        let payload = vec![0x39; size];
                        sender.send_to(&payload, local).await.unwrap();
                        buf.fill(0xa5);
                        let result = tokio::time::timeout(
                            Duration::from_secs(1),
                            AsyncDatagramIo::recv(&mut io, &mut buf),
                        )
                        .await
                        .unwrap();
                        if size <= capacity {
                            assert_eq!(result.unwrap(), (size, peer.into()));
                            assert_eq!(&buf[..size], payload);
                            assert!(io.received);
                        } else {
                            // Windows may refuse at the socket before the guard
                            // can observe the extra byte; either path is an error.
                            assert!(result.is_err());
                            assert!(buf.iter().all(|byte| *byte == 0xa5));
                            assert!(!io.received);
                        }
                    }
                    assert_eq!(
                        AsyncDatagramIo::send(&mut io, peer.into(), b"reply")
                            .await
                            .unwrap(),
                        5
                    );
                    let mut reply = [0; 6];
                    assert_eq!(
                        tokio::time::timeout(Duration::from_secs(1), sender.recv_from(&mut reply))
                            .await
                            .unwrap()
                            .unwrap(),
                        (5, local)
                    );
                    assert_eq!(&reply[..5], b"reply");
                }
            }
        });
    }

    #[test]
    fn async_app_wait_cancels_reservation_prioritizes_local_and_retains_ingress() {
        async_runtime().block_on(async {
            let io = async_test_io("127.0.0.1:0").await;
            let local = io.socket.local_addr().unwrap();
            let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut app = bind_fixture(io, 64, 1472, None).unwrap();
            let epoch = Instant::now();
            let now = || epoch.elapsed().as_millis() as u64;
            let mut timer = AppTimer(epoch);
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(5),
                    app.wait_async(now(), &mut timer, std::future::pending::<()>()),
                )
                .await
                .is_err()
            );
            assert_eq!(app.engine_mut().rx_occupied(), 0);
            // An empty CON is a ping: progress can dispatch it without a handler.
            sender.send_to(&[0x40, 0, 0, 1], local).await.unwrap();
            assert_eq!(
                app.wait_async(now(), &mut timer, std::future::ready(()))
                    .await
                    .unwrap(),
                coaptic::app::AppWake::Local
            );
            assert_eq!(app.engine_mut().rx_occupied(), 0);
            assert_eq!(
                tokio::time::timeout(
                    Duration::from_secs(1),
                    app.wait_async(now(), &mut timer, std::future::pending::<()>())
                )
                .await
                .unwrap()
                .unwrap(),
                coaptic::app::AppWake::Ingress
            );
            assert_eq!(app.engine_mut().rx_occupied(), 1);
            assert_eq!(
                app.wait_async(now(), &mut timer, std::future::pending::<()>())
                    .await
                    .unwrap(),
                coaptic::app::AppWake::Ready
            );
            assert_eq!(app.engine_mut().rx_occupied(), 1);
            let now_ms = now();
            let mut clock = || Ok::<u64, std::io::Error>(now());
            app.progress_async(now_ms, &mut clock, &mut timer, now_ms + 1000)
                .await
                .unwrap();
            assert_eq!(app.engine_mut().rx_occupied(), 0);
            let mut reply = [0; 8];
            let (n, from) =
                tokio::time::timeout(Duration::from_secs(1), sender.recv_from(&mut reply))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(from, local);
            assert_eq!(&reply[..n], &[0x70, 0, 0, 1]);
        });
    }

    #[test]
    fn async_app_timer_progresses_without_ingress_and_preserves_retry_bytes() {
        async_runtime().block_on(async {
            let io = async_test_io("127.0.0.1:0").await;
            let local = io.socket.local_addr().unwrap();
            let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer: Endpoint = receiver.local_addr().unwrap().into();
            let mut app = bind_fixture(io, 64, 1472, None).unwrap();
            let tx = app.engine_mut().acquire_tx().unwrap();
            let mid = MessageId::new(7);
            app.engine_mut()
                .encode_tx(
                    tx,
                    &Message::new(Type::Confirmable, coaptic::Code::GET, mid),
                )
                .unwrap();
            app.engine_mut()
                .record_pending_con(tx, peer, mid, 0, 0)
                .unwrap();
            let due = app.next_timeout().unwrap();
            let epoch = Instant::now() - Duration::from_millis(due - 5);
            let now = || epoch.elapsed().as_millis() as u64;
            let mut timer = AppTimer(epoch);
            let before_wait = now();
            let expected = if before_wait < due {
                coaptic::app::AppWake::Deadline
            } else {
                coaptic::app::AppWake::Ready
            };
            assert_eq!(
                tokio::time::timeout(
                    Duration::from_secs(1),
                    app.wait_async(before_wait, &mut timer, std::future::pending::<()>())
                )
                .await
                .unwrap()
                .unwrap(),
                expected
            );
            assert_eq!(app.engine_mut().rx_occupied(), 0);
            let now_ms = now();
            assert!(now_ms >= due);
            let mut clock = || Ok::<u64, std::io::Error>(now());
            app.progress_async(now_ms, &mut clock, &mut timer, now_ms + 1000)
                .await
                .unwrap();
            let mut packet = [0; 8];
            let (n, from) =
                tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut packet))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(from, local);
            assert_eq!(&packet[..n], &[0x40, 1, 0, 7]);
            assert!(app.next_timeout().unwrap() > now_ms);
            // Due work wins before a continuously readable socket is received.
            let due = app.next_timeout().unwrap();
            receiver.send_to(&[0x40, 0, 0, 2], local).await.unwrap();
            assert_eq!(
                app.wait_async(due, &mut timer, std::future::pending::<()>())
                    .await
                    .unwrap(),
                coaptic::app::AppWake::Ready
            );
            assert_eq!(app.engine_mut().rx_occupied(), 0);
        });
    }

    #[test]
    fn mio_readiness_receive_preserves_exact_oversized_and_recovery_datagrams() {
        for host in ["127.0.0.1:0", "[::1]:0"] {
            for capacity in [64, 1472, 2048] {
                let socket = UdpSocket::bind(host).unwrap();
                socket.set_nonblocking(true).unwrap();
                let local = socket.local_addr().unwrap();
                let sender = UdpSocket::bind(host).unwrap();
                let peer = sender.local_addr().unwrap();
                let mut io = MioUdp {
                    socket: mio::net::UdpSocket::from_std(socket),
                    scratch: [0; 2049],
                    received: false,
                };
                let mut poll = mio::Poll::new().unwrap();
                poll.registry()
                    .register(&mut io.socket, mio::Token(0), mio::Interest::READABLE)
                    .unwrap();
                let mut events = mio::Events::with_capacity(8);
                let mut buf = vec![0; capacity];
                for size in [capacity, capacity + 1, capacity + 8, 3] {
                    let payload = vec![0x39; size];
                    sender.send_to(&payload, local).unwrap();
                    buf.fill(0xa5);
                    let deadline = Instant::now() + Duration::from_secs(1);
                    let result = loop {
                        let timeout = deadline.saturating_duration_since(Instant::now());
                        assert!(!timeout.is_zero(), "receive deadline");
                        poll.poll(&mut events, Some(timeout)).unwrap();
                        match io.recv(&mut buf) {
                            Ok(None) => continue,
                            result => break result,
                        }
                    };
                    if size <= capacity {
                        assert_eq!(result.unwrap(), Some((size, peer.into())));
                        assert_eq!(&buf[..size], payload);
                        assert!(io.received);
                    } else {
                        assert!(result.is_err());
                        assert!(buf.iter().all(|byte| *byte == 0xa5));
                        assert!(!io.received);
                    }
                    assert!(io.recv(&mut buf).unwrap().is_none());
                    assert!(!io.received);
                }
                sender
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                assert_eq!(io.send(peer.into(), b"reply").unwrap(), 5);
                let mut reply = [0; 6];
                assert_eq!(sender.recv_from(&mut reply).unwrap(), (5, local));
                assert_eq!(&reply[..5], b"reply");
            }
        }
    }

    #[test]
    fn readiness_receive_preserves_exact_oversized_and_recovery_datagrams() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                for host in ["127.0.0.1:0", "[::1]:0"] {
                    for capacity in [64, 1472, 2048] {
                        let socket = tokio::net::UdpSocket::bind(host).await.unwrap();
                        let local = socket.local_addr().unwrap();
                        let sender = UdpSocket::bind(host).unwrap();
                        let peer = sender.local_addr().unwrap();
                        let mut io = ReadyUdp {
                            socket,
                            scratch: [0; 2049],
                            received: false,
                            counts: None,
                        };
                        let mut buf = vec![0; capacity];
                        for size in [capacity, capacity + 1, capacity + 8, 3] {
                            let payload = vec![0x39; size];
                            sender.send_to(&payload, local).unwrap();
                            buf.fill(0xa5);
                            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
                            let result = loop {
                                tokio::time::timeout_at(deadline, io.socket.readable())
                                    .await
                                    .unwrap()
                                    .unwrap();
                                match io.recv(&mut buf) {
                                    Ok(None) => continue,
                                    result => break result,
                                }
                            };
                            if size <= capacity {
                                assert_eq!(result.unwrap(), Some((size, peer.into())));
                                assert_eq!(&buf[..size], payload);
                                assert!(io.received);
                            } else {
                                assert!(result.is_err());
                                assert!(buf.iter().all(|byte| *byte == 0xa5));
                                assert!(!io.received);
                            }
                        }
                        sender
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        assert_eq!(io.send(peer.into(), b"reply").unwrap(), 5);
                        let mut reply = [0; 6];
                        assert_eq!(sender.recv_from(&mut reply).unwrap(), (5, local));
                        assert_eq!(&reply[..5], b"reply");
                    }
                }
            });
    }
}
