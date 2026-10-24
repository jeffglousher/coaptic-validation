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
//! Linux-only `coaptic-mio-level` is the SmallDevice32 one-attempt readiness control.
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
use coaptic::app::{AppAssembled, AppStorage};
use coaptic::oscore::{DeriveParams, SecurityContext};
use coaptic::storage::{AllocMemory, Capacities, DatagramIo, Endpoint, MemoryLayout, UdpSocketIo};
use coaptic::{App, ContentFormat, Request, Response, get};
use std::{
    env,
    io::{Read, Write},
    net::UdpSocket,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

static BODY: OnceLock<&'static [u8]> = OnceLock::new();

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ResourceProfile {
    #[default]
    HostControl,
    SmallDevice,
    SmallBlockwise,
    ServiceFixed,
    ServiceAllocated,
}

impl ResourceProfile {
    fn name(self) -> &'static str {
        match self {
            Self::HostControl => "host-control",
            Self::SmallDevice => "small-device",
            Self::SmallBlockwise => "small-blockwise",
            Self::ServiceFixed => "service-fixed",
            Self::ServiceAllocated => "service-allocated",
        }
    }

    fn take_option(args: &mut Vec<String>) -> Result<Self, &'static str> {
        let mut selected = None;
        while let Some(index) = args.iter().position(|arg| arg == "--resource-profile") {
            if selected.is_some() {
                return Err("duplicate resource profile");
            }
            selected = Some(match args.get(index + 1).map(String::as_str) {
                Some("host-control") => Self::HostControl,
                Some("small-device") => Self::SmallDevice,
                Some("small-blockwise") => Self::SmallBlockwise,
                Some("service-fixed") => Self::ServiceFixed,
                Some("service-allocated") => Self::ServiceAllocated,
                _ => return Err("unknown resource profile"),
            });
            args.drain(index..=index + 1);
        }
        Ok(selected.unwrap_or_default())
    }

    fn rx_bytes(self) -> usize {
        match self {
            Self::SmallDevice | Self::SmallBlockwise => 1152,
            _ => 1472,
        }
    }

    fn validate(self, kind: &str, size: usize, rx_bytes: usize) -> Result<(), &'static str> {
        if kind == "coaptic-mio-level" {
            return if self == Self::SmallDevice && size == 32 && rx_bytes == 1152 {
                Ok(())
            } else {
                Err("level control requires SmallDevice32 and exact RX capacity")
            };
        }
        if self == Self::HostControl {
            return Ok(());
        }
        if kind != "coaptic-mio" || rx_bytes != self.rx_bytes() {
            return Err("representative resource profiles require Mio and exact RX capacity");
        }
        let sizes: &[usize] = match self {
            Self::SmallDevice => &[32],
            Self::SmallBlockwise => &[64, 1024, 4096],
            Self::ServiceFixed | Self::ServiceAllocated => &[64, 1024, 16384],
            Self::HostControl => unreachable!(),
        };
        if !sizes.contains(&size) {
            return Err("unsupported resource profile representation");
        }
        Ok(())
    }

    fn allocated(self) -> bool {
        matches!(self, Self::HostControl | Self::ServiceAllocated)
    }
}

// Both fixed and allocated configured builders expose the same bind operations.
// Expand only construction, leaving all polling in the shared generic driver.
macro_rules! bind_resources {
    ($resources:expr, $io:expr, $context:expr) => {{
        let builder = App::with_resources($resources)
            .randomness(|buffer| getrandom::fill(buffer).is_ok())
            .route("bench", get(representation));
        let builder = if let Some(context) = $context {
            builder.oscore(context)
        } else {
            builder.allow_unprotected()
        };
        builder.bind($io)
    }};
}

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
    profile: ResourceProfile,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(address)?;
    socket.set_nonblocking(true)?;
    let mut io = MioUdp {
        socket: mio::net::UdpSocket::from_std(socket),
        scratch: [0; SCRATCH],
        received: false,
    };
    let poll = mio::Poll::new()?;
    poll.registry()
        .register(&mut io.socket, mio::Token(0), mio::Interest::READABLE)?;
    let events = mio::Events::with_capacity(8);
    let security = if context.is_some() {
        "oscore"
    } else {
        "unprotected"
    };
    macro_rules! drive {
        ($app:expr) => {
            drive_mio($app?, poll, events, profile, bytes, security)
        };
    }
    match profile {
        ResourceProfile::HostControl => drive!(bind_fixture(io, bytes, rx_bytes, context)),
        ResourceProfile::SmallDevice => drive!(bind_resources!(
            coaptic::resources::SmallDevice::new(),
            io,
            context
        )),
        ResourceProfile::SmallBlockwise => drive!(bind_resources!(
            coaptic::resources::SmallDevice::new().block_wise::<true>(),
            io,
            context
        )),
        ResourceProfile::ServiceFixed => {
            service_fixed_mio(io, poll, events, bytes, context, security)
        }
        ResourceProfile::ServiceAllocated => {
            let resources = coaptic::resources::Service::new();
            let required = AllocMemory::<coaptic::message::Token>::required_heap_bytes(
                resources.pool_capacities(),
            )?;
            drive!(bind_resources!(resources.allocated(required), io, context))
        }
    }
}

// Keep this large fixed construction out of every other profile's setup frame.
// The App still owns its inline pools and uses the same driver, without boxing.
#[inline(never)]
fn service_fixed_mio<const SCRATCH: usize>(
    io: MioUdp<SCRATCH>,
    poll: mio::Poll,
    events: mio::Events,
    bytes: usize,
    context: Option<SecurityContext>,
    security: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = bind_resources!(coaptic::resources::Service::new(), io, context)?;
    drive_mio(
        app,
        poll,
        events,
        ResourceProfile::ServiceFixed,
        bytes,
        security,
    )
}

fn drive_mio<
    P,
    S,
    const SCRATCH: usize,
    const N: usize,
    const B: bool,
    const D: usize,
    const C: usize,
>(
    mut app: App<P, MioUdp<SCRATCH>, N, B, S, D, C>,
    mut poll: mio::Poll,
    mut events: mio::Events,
    profile: ResourceProfile,
    bytes: usize,
    security: &str,
) -> Result<(), Box<dyn std::error::Error>>
where
    P: MemoryLayout<B> + AppAssembled<B>,
    S: AppStorage<Token = P::Token>,
{
    let adapter_bytes = std::mem::size_of_val(app.transport());
    let capacities = app.engine().capacities();
    let requested_heap = if profile.allocated() {
        AllocMemory::<P::Token>::required_heap_bytes(capacities)?
    } else {
        0
    };
    let representation_heap = if profile == ResourceProfile::SmallDevice {
        0
    } else {
        bytes
    };
    println!(
        "{{\"schema\":\"coaptic-native-mio-resources/1\",\"server_kind\":\"{}\",\"udp_scratch_bytes\":{SCRATCH},\"adapter_inline_bytes\":{adapter_bytes},\"app_including_adapter_bytes\":{},\"poll_inline_bytes\":{},\"events_inline_bytes\":{},\"event_capacity\":{},\"worker_threads\":0,\"pending_kernel_operations\":0,\"runtime_heap_bytes\":null,\"runtime_stack_bytes\":null,\"kernel_bytes\":null,\"allocator_overhead_bytes\":null,\"initialization_stack_bytes\":null,\"events_heap_bytes\":null,\"resource_profile\":\"{}\",\"storage\":\"{}\",\"routes\":{N},\"populated_routes\":1,\"calls\":{C},\"deferred\":{D},\"associations\":1,\"security_requests\":4,\"blockwise\":{B},\"rx_slots\":{},\"tx_slots\":{},\"rx_datagram_bytes\":{},\"tx_datagram_bytes\":{},\"dedup\":{},\"observe\":{},\"rx_body_slots\":{},\"tx_body_slots\":{},\"rx_body_bytes\":{},\"tx_body_bytes\":{},\"representation_bytes\":{bytes},\"representation_heap_bytes\":{representation_heap},\"app_requested_heap_bytes\":{requested_heap},\"security\":\"{security}\",\"nesting\":\"scratch inside adapter inside App; fixed pools inside App; allocated pool payloads and metadata inside requested heap; representation backing, poll and events separate\",\"limits\":\"requested and inline owners only; static representation backing is borrowed; events heap, allocator, initialization and peak stack, runtime and kernel owners unknown; no whole-memory acceptance\"}}",
        if SCRATCH == 0 {
            "coaptic-mio-direct"
        } else {
            "coaptic-mio"
        },
        std::mem::size_of_val(&app),
        std::mem::size_of_val(&poll),
        std::mem::size_of_val(&events),
        events.capacity(),
        profile.name(),
        if profile.allocated() {
            "allocated"
        } else {
            "fixed"
        },
        capacities.rx_datagram_slots,
        capacities.tx_datagram_slots,
        capacities.rx_datagram_bytes,
        capacities.tx_datagram_bytes,
        capacities.dedup_entries,
        capacities.observe_entries,
        capacities.rx_body_slots.unwrap_or(0),
        capacities.tx_body_slots.unwrap_or(0),
        capacities.rx_body_bytes.unwrap_or(0),
        capacities.tx_body_bytes.unwrap_or(0),
    );
    std::io::stdout().flush()?;
    run_readiness(
        &mut app,
        |io| io.received,
        move |_, deadline| {
            let timeout = deadline.map(|due| due.saturating_duration_since(Instant::now()));
            poll.poll(&mut events, timeout)
        },
    )
}

// Both controls share App progress, clocks, burst bounds and error precedence.
fn run_readiness<P, S, T, const N: usize, const B: bool, const D: usize, const C: usize>(
    app: &mut App<P, T, N, B, S, D, C>,
    received: fn(&T) -> bool,
    mut wait: impl FnMut(&mut T, Option<Instant>) -> std::io::Result<()>,
) -> Result<(), Box<dyn std::error::Error>>
where
    P: MemoryLayout<B> + AppAssembled<B>,
    S: AppStorage<Token = P::Token>,
    T: DatagramIo<Error = std::io::Error>,
{
    let started = Instant::now();
    loop {
        readiness_turn(app, started, received, &mut wait)?;
    }
}

// A finite production turn also lets tests exercise App progress and the wait
// boundary together. Borrow the App: fixed Service storage stays with its owner.
fn readiness_turn<P, S, T, const N: usize, const B: bool, const D: usize, const C: usize>(
    app: &mut App<P, T, N, B, S, D, C>,
    started: Instant,
    received: fn(&T) -> bool,
    mut wait: impl FnMut(&mut T, Option<Instant>) -> std::io::Result<()>,
) -> Result<(), Box<dyn std::error::Error>>
where
    P: MemoryLayout<B> + AppAssembled<B>,
    S: AppStorage<Token = P::Token>,
    T: DatagramIo<Error = std::io::Error>,
{
    let idle = read_burst(app, started, received)?;
    let now_ms = started.elapsed().as_millis() as u64;
    let deadline = if idle {
        app.next_poll_at(now_ms)
            .map(|due| started + Duration::from_millis(due))
    } else {
        Some(Instant::now())
    };
    match wait(app.transport_mut(), deadline) {
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(()),
        result => Ok(result?),
    }
}

fn read_burst<P, S, T, const N: usize, const B: bool, const D: usize, const C: usize>(
    app: &mut App<P, T, N, B, S, D, C>,
    started: Instant,
    received: fn(&T) -> bool,
) -> Result<bool, Box<dyn std::error::Error>>
where
    P: MemoryLayout<B> + AppAssembled<B>,
    S: AppStorage<Token = P::Token>,
    T: DatagramIo<Error = std::io::Error>,
{
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
        if !received(app.transport()) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(any(target_os = "linux", test))]
mod level_control {
    use super::*;
    use std::io;

    // None: no receive eligibility; Some(false): readable; Some(true): error
    // readiness. This stores no datagram and leaves ordinary MioUdp unchanged.
    pub(super) struct LevelUdp {
        inner: MioUdp,
        credit: Option<bool>,
    }
    impl LevelUdp {
        fn bind(address: &str) -> io::Result<Self> {
            let socket = UdpSocket::bind(address)?;
            socket.set_nonblocking(true)?;
            Ok(Self {
                inner: MioUdp {
                    socket: mio::net::UdpSocket::from_std(socket),
                    scratch: [0; 2049],
                    received: false,
                },
                credit: None,
            })
        }
        fn receive_with(
            &mut self,
            output: &mut [u8],
            receive: impl FnOnce(&mut MioUdp, &mut [u8]) -> io::Result<Option<(usize, Endpoint)>>,
        ) -> io::Result<Option<(usize, Endpoint)>> {
            self.inner.received = false;
            let Some(error_ready) = self.credit.take() else {
                return Ok(None);
            };
            // Eligibility is spent BEFORE any native attempt/error/oversize.
            let result = receive(&mut self.inner, output);
            if error_ready && matches!(result, Ok(None)) {
                // Refuse unsupported sticky error readiness rather than spinning.
                return Err(io::Error::other(
                    "UDP error readiness without native outcome",
                ));
            }
            result
        }
        fn send_with(
            &mut self,
            peer: Endpoint,
            bytes: &[u8],
            send: impl FnOnce(&mio::net::UdpSocket, &[u8], std::net::SocketAddr) -> io::Result<usize>,
        ) -> io::Result<usize> {
            send(&self.inner.socket, bytes, peer.into())
        }
    }
    impl coaptic::storage::DatagramTransport for LevelUdp {
        type Error = io::Error;
    }
    impl DatagramIo for LevelUdp {
        fn recv(&mut self, output: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
            self.receive_with(output, |inner, output| inner.recv(output))
        }
        fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> io::Result<usize> {
            self.send_with(peer, bytes, |socket, bytes, peer| {
                socket.send_to(bytes, peer)
            })
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use coaptic::message::{Message, MessageId, Type};

        #[test]
        fn credit_is_one_attempt_including_empty_native_error_and_oversize() {
            let mut io = LevelUdp::bind("127.0.0.1:0").unwrap();
            let mut bytes = [0; 1152];
            for kind in [
                io::ErrorKind::Interrupted,
                io::ErrorKind::InvalidData,
                io::ErrorKind::ConnectionReset,
            ] {
                assert!(
                    io.receive_with(&mut bytes, |_, _| panic!("uncredited receive"))
                        .unwrap()
                        .is_none()
                );
                io.credit = Some(false);
                let error = io
                    .receive_with(&mut bytes, |_, _| Err(kind.into()))
                    .unwrap_err();
                assert_eq!(error.kind(), kind);
                assert_eq!(io.credit, None);
            }
            io.credit = Some(false);
            assert!(
                io.receive_with(&mut bytes, |_, _| Ok(None))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(io.credit, None);
            io.credit = Some(true);
            assert!(io.receive_with(&mut bytes, |_, _| Ok(None)).is_err());
            assert_eq!(io.credit, None); // Error readiness cannot create an idle spin.
            io.credit = Some(true);
            assert_eq!(
                io.receive_with(&mut bytes, |_, _| Err(io::Error::from_raw_os_error(123)))
                    .unwrap_err()
                    .raw_os_error(),
                Some(123)
            );
        }
        #[test]
        fn absolute_timeout_matches_mio_ceil_clamp_without_restarting() {
            let now = Instant::now();
            let due = now + Duration::from_micros(1500);
            assert_eq!(timeout(None, now), None);
            assert_eq!(timeout(Some(due), now), Some(Duration::from_millis(2)));
            assert_eq!(
                timeout(Some(due), now + Duration::from_millis(1)),
                Some(Duration::from_millis(1))
            );
            assert_eq!(timeout(Some(due), due), Some(Duration::ZERO));
            assert_eq!(
                timeout(Some(due), due + Duration::from_secs(1)),
                Some(Duration::ZERO)
            );
            assert_eq!(
                timeout(Some(now + Duration::from_secs(i32::MAX as u64)), now),
                Some(Duration::from_millis(i32::MAX as u64))
            );
        }
        #[test]
        fn small_capacity_and_native_send_acceptance_are_unchanged() {
            let mut io = LevelUdp::bind("127.0.0.1:0").unwrap();
            let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            assert_eq!(
                io.send(receiver.local_addr().unwrap().into(), b"reply")
                    .unwrap(),
                5
            );
            assert_eq!(receiver.recv_from(&mut [0; 8]).unwrap().0, 5);
            assert_eq!(io.credit, None); // Sends are immediate and not read-gated.
            let dummy = LevelUdp::bind("127.0.0.1:0").unwrap();
            let mut app =
                bind_resources!(coaptic::resources::SmallDevice::new(), dummy, None).unwrap();
            while app.engine_mut().acquire_rx().is_some() {}
            io.credit = Some(false);
            assert!(matches!(
                app.engine_mut().recv_from(&mut io),
                Err(coaptic::storage::DatagramIoError::Saturated)
            ));
            assert_eq!(io.credit, Some(false)); // No socket attempt on RX refusal.
        }
        #[test]
        fn send_refusal_and_short_send_leave_encoded_tx_and_pending_owner() {
            struct Refuse(LevelUdp, u8);
            impl coaptic::storage::DatagramTransport for Refuse {
                type Error = io::Error;
            }
            impl DatagramIo for Refuse {
                fn recv(&mut self, output: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
                    self.0.recv(output)
                }
                fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> io::Result<usize> {
                    self.0.send_with(peer, bytes, |_, bytes, _| match self.1 {
                        0 => Err(io::ErrorKind::WouldBlock.into()),
                        1 => Ok(bytes.len() - 1),
                        _ => Err(io::Error::from_raw_os_error(123)),
                    })
                }
            }
            let io = LevelUdp::bind("127.0.0.1:0").unwrap();
            let mut app =
                bind_resources!(coaptic::resources::SmallDevice::new(), io, None).unwrap();
            let tx = app.engine_mut().acquire_tx().unwrap();
            let peer = Endpoint::v4([127, 0, 0, 1], 9);
            app.engine_mut()
                .write_tx(tx, &[0x40, 1, 0, 7], peer)
                .unwrap();
            app.engine_mut()
                .record_pending_con(tx, peer, MessageId::new(7), 0, 0)
                .unwrap();
            let before = app.engine_mut().pending_con(tx);
            let mut refused = Refuse(LevelUdp::bind("127.0.0.1:0").unwrap(), 0);
            for mode in 0..3 {
                refused.1 = mode;
                assert!(app.engine_mut().send_tx(&mut refused, tx).is_err());
                assert_eq!(
                    app.engine_mut().access_tx(tx).unwrap().as_bytes(),
                    &[0x40, 1, 0, 7]
                );
                assert!(!app.engine_mut().tx_is_pinned(tx));
                assert_eq!(app.engine_mut().pending_con(tx), before);
            }
        }
        #[test]
        fn maintenance_retransmits_without_any_receive_credit() {
            let io = LevelUdp::bind("127.0.0.1:0").unwrap();
            let mut app =
                bind_resources!(coaptic::resources::SmallDevice::new(), io, None).unwrap();
            let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let peer = receiver.local_addr().unwrap().into();
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
            let epoch = Instant::now() - Duration::from_millis(due);
            assert!(read_burst(&mut app, epoch, |io| io.inner.received).unwrap());
            let mut bytes = [0; 8];
            assert_eq!(receiver.recv_from(&mut bytes).unwrap().0, 4);
            assert_eq!(&bytes[..4], &[0x40, 1, 0, 7]);
            assert!(app.next_timeout().unwrap() > due);
            assert_eq!(app.transport().credit, None);
            assert_eq!(app.engine_mut().rx_occupied(), 0);
        }
        #[test]
        fn production_turn_resamples_after_interrupted_or_spurious_wait() {
            let io = LevelUdp::bind("127.0.0.1:0").unwrap();
            let mut app =
                bind_resources!(coaptic::resources::SmallDevice::new(), io, None).unwrap();
            let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let peer = receiver.local_addr().unwrap().into();
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
            let epoch = Instant::now() - Duration::from_millis(due);
            // Inject the wait outcomes at the production boundary. This does not
            // establish that a real kernel signal interrupted ppoll.
            for interrupted in [true, false] {
                let mut observed = None;
                readiness_turn(
                    &mut app,
                    epoch,
                    |io| io.inner.received,
                    |io, deadline| {
                        observed = deadline;
                        assert_eq!(io.credit, None);
                        if interrupted {
                            Err(io::ErrorKind::Interrupted.into())
                        } else {
                            Ok(())
                        }
                    },
                )
                .unwrap();
                assert_eq!(
                    observed,
                    Some(epoch + Duration::from_millis(app.next_timeout().unwrap()))
                );
            }
            assert_eq!(receiver.recv_from(&mut [0; 8]).unwrap().0, 4);
            assert_eq!(app.metrics().con_retransmit, 1);
            assert!(app.next_timeout().unwrap() > due);
        }
        #[test]
        fn production_turn_rx_saturation_keeps_ingress_unread_but_runs_due_maintenance() {
            let io = LevelUdp::bind("127.0.0.1:0").unwrap();
            let address = io.inner.socket.local_addr().unwrap();
            let mut app =
                bind_resources!(coaptic::resources::SmallDevice::new(), io, None).unwrap();
            let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
            sender
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let peer = sender.local_addr().unwrap().into();
            for _ in 0..2 {
                let rx = app.engine_mut().acquire_rx().unwrap();
                app.engine_mut()
                    .write_rx(rx, &[0x40, 0, 0, 9], peer)
                    .unwrap();
            }
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
            let epoch = Instant::now() - Duration::from_millis(due);
            sender.send_to(&[0x60, 0, 0, 8], address).unwrap();
            app.transport_mut().credit = Some(false);
            let error = readiness_turn(
                &mut app,
                epoch,
                |io| io.inner.received,
                |_, _| panic!("fatal refusal must precede wait"),
            )
            .unwrap_err();
            assert!(matches!(
                error.downcast_ref::<coaptic::app::Error<io::Error>>(),
                Some(coaptic::app::Error::Saturated)
            ));
            assert_eq!(app.transport().credit, Some(false));
            assert_eq!(app.metrics().con_retransmit, 1);
            assert!(app.next_timeout().unwrap() > due);
            assert_eq!(sender.recv_from(&mut [0; 8]).unwrap().0, 4);
            // The native packet remains queued even though retained RX was progressed.
            let mut bytes = [0; 1152];
            assert_eq!(app.transport_mut().recv(&mut bytes).unwrap().unwrap().0, 4);
            assert_eq!(&bytes[..4], &[0x60, 0, 0, 8]);
        }
        #[test]
        fn production_turn_native_error_preserves_due_maintenance_and_send_error_priority() {
            struct Faulty(LevelUdp, bool);
            impl coaptic::storage::DatagramTransport for Faulty {
                type Error = io::Error;
            }
            impl DatagramIo for Faulty {
                fn recv(&mut self, output: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
                    self.0
                        .receive_with(output, |_, _| Err(io::ErrorKind::ConnectionReset.into()))
                }
                fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> io::Result<usize> {
                    if self.1 {
                        self.0
                            .send_with(peer, bytes, |_, _, _| Err(io::ErrorKind::WouldBlock.into()))
                    } else {
                        self.0.send(peer, bytes)
                    }
                }
            }
            for send_error in [false, true] {
                let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
                receiver
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let peer = receiver.local_addr().unwrap().into();
                let io = Faulty(LevelUdp::bind("127.0.0.1:0").unwrap(), send_error);
                let mut app =
                    bind_resources!(coaptic::resources::SmallDevice::new(), io, None).unwrap();
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
                let epoch = Instant::now() - Duration::from_millis(app.next_timeout().unwrap());
                app.transport_mut().0.credit = Some(true);
                let error = readiness_turn(
                    &mut app,
                    epoch,
                    |io| io.0.inner.received,
                    |_, _| panic!("native failure must precede wait"),
                )
                .unwrap_err();
                let expected = if send_error {
                    io::ErrorKind::WouldBlock
                } else {
                    io::ErrorKind::ConnectionReset
                };
                assert!(matches!(
                    error.downcast_ref::<coaptic::app::Error<io::Error>>(),
                    Some(coaptic::app::Error::Io(coaptic::storage::DatagramIoError::Io(error)))
                        if error.kind() == expected
                ));
                assert_eq!(app.transport().0.credit, None);
                assert_eq!(app.metrics().rx_error, 1);
                assert_eq!(app.metrics().tx_fail, u32::from(send_error));
                assert_eq!(
                    app.engine_mut().access_tx(tx).unwrap().as_bytes(),
                    &[0x40, 1, 0, 7]
                );
                assert!(!app.engine_mut().tx_is_pinned(tx));
                if !send_error {
                    assert_eq!(app.metrics().con_retransmit, 1);
                    assert_eq!(receiver.recv_from(&mut [0; 8]).unwrap().0, 4);
                }
            }
        }
        #[cfg(target_os = "linux")]
        #[test]
        fn production_turn_queued_progress_and_fresh_due_work_with_silent_sender() {
            for host in ["127.0.0.1:0", "[::1]:0"] {
                for count in [2u16, 3, 35] {
                    let io = LevelUdp::bind(host).unwrap();
                    let address = io.inner.socket.local_addr().unwrap();
                    let mut app =
                        bind_resources!(coaptic::resources::SmallDevice::new(), io, None).unwrap();
                    let sender = UdpSocket::bind(host).unwrap();
                    sender
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let peer = sender.local_addr().unwrap().into();
                    let tx = app.engine_mut().acquire_tx().unwrap();
                    let mid = MessageId::new(600);
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
                    for n in 0..count {
                        let [a, b] = n.to_be_bytes();
                        sender.send_to(&[0x60, 0, a, b], address).unwrap();
                    }
                    let epoch =
                        Instant::now() - Duration::from_millis(due.checked_sub(50).unwrap());
                    let until = Instant::now() + Duration::from_secs(1);
                    for n in 0..=count {
                        assert!(Instant::now() < until);
                        let mut observed = None;
                        readiness_turn(
                            &mut app,
                            epoch,
                            |io| io.inner.received,
                            |io, deadline| {
                                observed = deadline;
                                if n == 0 {
                                    assert_eq!(deadline, Some(epoch + Duration::from_millis(due)));
                                    // Becomes due while the socket stays readable.
                                    // No new ingress wakes the following turn.
                                    std::thread::sleep(Duration::from_millis(60));
                                }
                                // Bound only the final idle wait, retaining the
                                // actual production deadline for assertions.
                                wait(io, Some(deadline.unwrap().min(until)))
                            },
                        )
                        .unwrap();
                        assert_eq!(app.metrics().rx_accepted, u32::from(n));
                        assert_eq!(
                            observed,
                            Some(epoch + Duration::from_millis(app.next_timeout().unwrap()))
                        );
                        if n != 0 {
                            assert_eq!(app.metrics().con_retransmit, 1);
                        }
                    }
                    assert_eq!(sender.recv_from(&mut [0; 8]).unwrap().0, 4);
                    assert!(app.next_timeout().unwrap() > due);
                }
            }
        }
        #[cfg(target_os = "linux")]
        #[test]
        fn production_turn_oversize_recovery_and_arrival_after_credit_spent() {
            fn reply(_: Request<'_>) -> Response<'static> {
                Response::content(&[0x5a; 32])
            }
            for host in ["127.0.0.1:0", "[::1]:0"] {
                let io = LevelUdp::bind(host).unwrap();
                let address = io.inner.socket.local_addr().unwrap();
                let mut app = App::with_resources(coaptic::resources::SmallDevice::new())
                    .randomness(|b| getrandom::fill(b).is_ok())
                    .route("bench", get(reply))
                    .allow_unprotected()
                    .bind(io)
                    .unwrap();
                let sender = UdpSocket::bind(host).unwrap();
                // A valid NON GET carrying a body fills exactly one RX datagram.
                let mut exact = [0; 1152];
                exact[..11]
                    .copy_from_slice(&[0x50, 1, 0, 1, 0xb5, b'b', b'e', b'n', b'c', b'h', 0xff]);
                sender.send_to(&exact, address).unwrap();
                sender.send_to(&[0x39; 1153], address).unwrap();
                sender.send_to(&[0x39; 4096], address).unwrap();
                sender.send_to(&[0x60, 0, 0, 2], address).unwrap();
                let epoch = Instant::now();
                let until = epoch + Duration::from_secs(1);
                // Initial turn grants the first credit; four turns consume the
                // prequeued packets through the real App and production wait.
                for _ in 0..5 {
                    assert!(Instant::now() < until);
                    readiness_turn(
                        &mut app,
                        epoch,
                        |io| io.inner.received,
                        |io, deadline| wait(io, Some(deadline.map_or(until, |at| at.min(until)))),
                    )
                    .unwrap();
                }
                assert_eq!(app.metrics().rx_accepted, 2);
                assert_eq!(app.metrics().tx_ok, 1);
                assert_eq!(app.transport().credit, None);
                // Arrival after the no-credit maintenance pass but before the
                // next wait must still grant progress without a hidden probe.
                readiness_turn(
                    &mut app,
                    epoch,
                    |io| io.inner.received,
                    |io, _| {
                        sender.send_to(&[0x60, 0, 0, 3], address)?;
                        wait(io, Some(Instant::now() + Duration::from_secs(1)))
                    },
                )
                .unwrap();
                assert_eq!(app.metrics().rx_accepted, 2);
                readiness_turn(
                    &mut app,
                    epoch,
                    |io| io.inner.received,
                    |io, _| wait(io, Some(Instant::now())),
                )
                .unwrap();
                assert_eq!(app.metrics().rx_accepted, 3);
                assert_eq!(app.transport().credit, None);
            }
        }
        #[test]
        fn full_small_responses_are_authenticated_and_complete() {
            use super::super::staged_udp::tests::context;
            fn reply(_: Request<'_>) -> Response<'static> {
                Response::content(&[0x5a; 32])
                    .content_format(ContentFormat::OCTET_STREAM)
                    .etag(b"level")
            }
            for protected in [false, true] {
                let io = LevelUdp::bind("127.0.0.1:0").unwrap();
                let peer = io.inner.socket.local_addr().unwrap().into();
                let builder = App::with_resources(coaptic::resources::SmallDevice::new())
                    .randomness(|b| getrandom::fill(b).is_ok())
                    .route("bench", get(reply));
                let builder = if protected {
                    builder.oscore(context(true))
                } else {
                    builder.allow_unprotected()
                };
                let mut server = builder.bind(io).unwrap();
                let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                socket.set_nonblocking(true).unwrap();
                let builder = App::with_resources(coaptic::resources::SmallDevice::new())
                    .randomness(|b| getrandom::fill(b).is_ok());
                let builder = if protected {
                    builder.oscore(context(false))
                } else {
                    builder.allow_unprotected()
                };
                let mut client = builder
                    .bind(UdpSocketIo::new(socket, [0; 1153]).unwrap())
                    .unwrap();
                let epoch = Instant::now();
                for _ in 0..4 {
                    let call = client
                        .get("bench")
                        .to(peer)
                        .send(epoch.elapsed().as_millis() as u64)
                        .unwrap();
                    let mut completed = false;
                    for _ in 0..64 {
                        assert!(epoch.elapsed() < Duration::from_secs(1));
                        // Portable core/credit proof; the real Linux wait is tested separately.
                        server.transport_mut().credit = Some(false);
                        read_burst(&mut server, epoch, |io| io.inner.received).unwrap();
                        client.poll(epoch.elapsed().as_millis() as u64).unwrap();
                        if let Some(response) = client.take_response(call) {
                            let response = response.unwrap(); // Includes OSCORE authentication.
                            assert_eq!(response.code(), coaptic::Code::CONTENT);
                            assert_eq!(response.format(), Some(ContentFormat::OCTET_STREAM));
                            assert_eq!(response.etag_bytes(), Some(&b"level"[..]));
                            assert!(!response.payload_truncated());
                            assert_eq!(response.payload(), &[0x5a; 32]);
                            completed = true;
                            break;
                        }
                    }
                    assert!(completed);
                }
                assert_eq!(server.metrics().tx_ok, 4);
                if protected {
                    use coaptic::message::{Opt, Token};
                    let mut sender_context = context(false);
                    let options = [Opt::uri_path("bench")];
                    let request =
                        Message::new(Type::Confirmable, coaptic::Code::GET, MessageId::new(999))
                            .with_token(Token::new(&[0x51]).unwrap())
                            .with_options(&options);
                    let mut wire = [0; 1152];
                    let mut n = 0;
                    for _ in 0..5 {
                        n = sender_context.protect_request(&request, &mut wire).unwrap();
                    }
                    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
                    sender
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    wire[n - 1] ^= 1; // Fresh sequence, invalid authentication tag.
                    sender
                        .send_to(&wire[..n], std::net::SocketAddr::from(peer))
                        .unwrap();
                    server.transport_mut().credit = Some(false);
                    read_burst(&mut server, epoch, |io| io.inner.received).unwrap();
                    assert_eq!(server.metrics().tx_ok, 4);
                    wire[n - 1] ^= 1;
                    sender
                        .send_to(&wire[..n], std::net::SocketAddr::from(peer))
                        .unwrap();
                    server.transport_mut().credit = Some(false);
                    read_burst(&mut server, epoch, |io| io.inner.received).unwrap();
                    assert!(sender.recv_from(&mut [0; 1152]).unwrap().0 > 0);
                    assert_eq!(server.metrics().tx_ok, 5); // Tag refusal did not spend replay state.
                    wire[2..4].copy_from_slice(&1000u16.to_be_bytes()); // New MID, same protected sequence.
                    sender
                        .send_to(&wire[..n], std::net::SocketAddr::from(peer))
                        .unwrap();
                    server.transport_mut().credit = Some(false);
                    read_burst(&mut server, epoch, |io| io.inner.received).unwrap();
                    assert_eq!(server.metrics().tx_ok, 5);
                }
                let caps = server.engine().capacities();
                assert_eq!(
                    (
                        caps.rx_datagram_slots,
                        caps.tx_datagram_slots,
                        caps.rx_datagram_bytes
                    ),
                    (2, 2, 1152)
                );
            }
        }
        #[cfg(target_os = "linux")]
        #[test]
        fn level_wait_preserves_queued_packets_and_arrival_after_credit_spent() {
            for host in ["127.0.0.1:0", "[::1]:0"] {
                for count in [2u8, 3, 35] {
                    let mut io = LevelUdp::bind(host).unwrap();
                    let local = io.inner.socket.local_addr().unwrap();
                    let sender = UdpSocket::bind(host).unwrap();
                    for n in 0..count {
                        sender.send_to(&[n], local).unwrap();
                    }
                    let deadline = Instant::now() + Duration::from_secs(1);
                    let mut bytes = [0; 1152];
                    for n in 0..count {
                        wait(&mut io, Some(deadline)).unwrap();
                        assert_eq!(io.recv(&mut bytes).unwrap().unwrap().0, 1);
                        assert_eq!(bytes[0], n);
                        assert!(io.recv(&mut bytes).unwrap().is_none());
                        assert!(Instant::now() < deadline); // Sender is silent throughout drain.
                    }
                    sender.send_to(b"race", local).unwrap();
                    wait(&mut io, Some(deadline)).unwrap();
                    assert_eq!(io.recv(&mut bytes).unwrap().unwrap().0, 4);
                    wait(&mut io, Some(Instant::now())).unwrap();
                    assert_eq!(io.credit, None); // Timeout does not fabricate a credit.
                }
            }
        }
        #[cfg(target_os = "linux")]
        #[test]
        fn oversize_refuses_prefix_and_recovers_queued_valid_datagrams() {
            for host in ["127.0.0.1:0", "[::1]:0"] {
                let mut io = LevelUdp::bind(host).unwrap();
                let local = io.inner.socket.local_addr().unwrap();
                let sender = UdpSocket::bind(host).unwrap();
                for size in [1152, 1153, 4096, 3] {
                    sender.send_to(&vec![0x39; size], local).unwrap();
                }
                let deadline = Instant::now() + Duration::from_secs(1);
                let mut output = [0xa5; 1152];
                for size in [1152, 1153, 4096, 3] {
                    output.fill(0xa5);
                    wait(&mut io, Some(deadline)).unwrap();
                    let result = io.recv(&mut output);
                    if size <= output.len() {
                        assert_eq!(result.unwrap().unwrap().0, size);
                    } else {
                        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                        assert!(output.iter().all(|b| *b == 0xa5));
                    }
                    assert_eq!(io.credit, None);
                    assert!(io.recv(&mut output).unwrap().is_none());
                }
            }
        }
    }
    // Match pinned Mio1.2.4's ceil-ms and i32::MAX clamp. The absolute deadline
    // is resampled on every wait; EINTR never restarts a stale relative timeout.
    fn timeout(deadline: Option<Instant>, now: Instant) -> Option<Duration> {
        deadline.map(|due| {
            let remaining = due.saturating_duration_since(now);
            let ms = remaining
                .checked_add(Duration::from_nanos(999_999))
                .unwrap_or(remaining)
                .as_millis()
                .min(i32::MAX as u128);
            Duration::from_millis(ms as u64)
        })
    }
    #[cfg(target_os = "linux")]
    fn wait(io: &mut LevelUdp, deadline: Option<Instant>) -> io::Result<()> {
        use rustix::event::{PollFd, PollFlags, Timespec};
        io.credit = None;
        let time = timeout(deadline, Instant::now())
            .map(Timespec::try_from)
            .transpose()
            .map_err(io::Error::other)?;
        let mut fd = [PollFd::new(&io.inner.socket, PollFlags::IN)];
        rustix::event::poll(&mut fd, time.as_ref())?;
        let ready = fd[0].revents();
        if ready.contains(PollFlags::NVAL) {
            return Err(rustix::io::Errno::BADF.into());
        }
        if ready.intersects(PollFlags::IN | PollFlags::ERR | PollFlags::HUP) {
            // Native receive failures still flow through App's maintenance and
            // error-priority path. A spurious ordinary readiness may be EAGAIN.
            io.credit = Some(ready.intersects(PollFlags::ERR | PollFlags::HUP));
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub(super) fn serve(
        address: &str,
        context: Option<SecurityContext>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let io = LevelUdp::bind(address)?;
        let security = if context.is_some() {
            "oscore"
        } else {
            "unprotected"
        };
        let mut app = bind_resources!(coaptic::resources::SmallDevice::new(), io, context)?;
        println!(
            "{{\"schema\":\"coaptic-native-level-resources/1\",\"server_kind\":\"coaptic-mio-level\",\"resource_profile\":\"small-device\",\"storage\":\"fixed\",\"security\":\"{security}\",\"udp_scratch_bytes\":2049,\"adapter_inline_bytes\":{},\"app_including_adapter_bytes\":{},\"credit_inline_bytes\":{},\"pollfd_inline_bytes\":{},\"pollfd_count\":1,\"poll_inline_bytes\":0,\"events_inline_bytes\":0,\"event_capacity\":0,\"selector_count\":0,\"retained_datagram_capacity\":0,\"worker_threads\":0,\"pending_kernel_operations\":0,\"routes\":4,\"populated_routes\":1,\"calls\":1,\"deferred\":0,\"associations\":1,\"security_requests\":4,\"blockwise\":false,\"rx_slots\":2,\"tx_slots\":2,\"rx_datagram_bytes\":1152,\"tx_datagram_bytes\":1152,\"dedup\":4,\"observe\":2,\"rx_body_slots\":0,\"tx_body_slots\":0,\"rx_body_bytes\":0,\"tx_body_bytes\":0,\"representation_bytes\":32,\"representation_heap_bytes\":0,\"app_requested_heap_bytes\":0,\"runtime_heap_bytes\":null,\"runtime_stack_bytes\":null,\"kernel_bytes\":null,\"allocator_overhead_bytes\":null,\"initialization_stack_bytes\":null,\"events_heap_bytes\":0,\"nesting\":\"scratch and credit inside adapter inside App; borrowed pollfd temporary separate; representation32B borrowed\",\"limits\":\"inline requested owners only; allocator, peak stack, socket/kernel readiness costs unknown; no whole-memory or CPU claim\"}}",
            std::mem::size_of::<LevelUdp>(),
            std::mem::size_of_val(&app),
            std::mem::size_of::<Option<bool>>(),
            std::mem::size_of::<rustix::event::PollFd<'static>>()
        );
        std::io::stdout().flush()?;
        run_readiness(&mut app, |io| io.inner.received, wait)
    }
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

fn validate_startup_profile(
    args: &[String],
    profile: ResourceProfile,
) -> Result<(), Box<dyn std::error::Error>> {
    // Reject unsupported combinations before credentials, representation or sockets.
    if profile != ResourceProfile::HostControl
        || args.get(1).map(String::as_str) == Some("coaptic-mio-level")
    {
        let kind = args.get(1).ok_or("missing server kind")?;
        let size = args.get(4).ok_or("missing representation bytes")?.parse()?;
        let rx_bytes = args
            .get(5)
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(profile.rx_bytes());
        profile.validate(kind, size, rx_bytes)?;
        if args.get(2).map(String::as_str) != Some("127.0.0.1") {
            return Err("representative fixtures require loopback".into());
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<_> = env::args().collect();
    let profile = ResourceProfile::take_option(&mut args)?;
    validate_startup_profile(&args, profile)?;
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
            profile.rx_bytes()
        });
    if (args[1] == "coaptic-small" && rx_bytes != 1152)
        || (args[1] != "coaptic-small"
            && profile == ResourceProfile::HostControl
            && ![1472, 2048].contains(&rx_bytes))
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
                | "coaptic-mio-level"
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
                | "coaptic-mio-level"
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
    let body: &'static [u8] = if profile == ResourceProfile::SmallDevice {
        &SMALL_BODY
    } else {
        Box::leak(
            (0..size)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    };
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
        "coaptic-mio" => mio_server::<2049>(&address, size, rx_bytes, context, profile),
        #[cfg(target_os = "linux")]
        "coaptic-mio-level" => level_control::serve(&address, context),
        #[cfg(not(target_os = "linux"))]
        "coaptic-mio-level" => Err("coaptic-mio-level requires Linux level readiness".into()),
        #[cfg(target_os = "linux")]
        "coaptic-mio-direct" => mio_server::<0>(&address, size, rx_bytes, context, profile),
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

    #[test]
    fn level_cli_preflight_requires_explicit_small32_before_other_startup_work() {
        for (selected, host, size, rx, accepted) in [
            (None, "127.0.0.1", "32", "1152", false),
            (Some("host-control"), "127.0.0.1", "32", "1152", false),
            (Some("small-device"), "127.0.0.1", "64", "1152", false),
            (Some("small-device"), "127.0.0.1", "32", "1472", false),
            (Some("small-device"), "0.0.0.0", "32", "1152", false),
            (Some("small-device"), "192.0.2.1", "32", "1152", false),
            (Some("small-device"), "127.0.0.1", "32", "1152", true),
        ] {
            let mut args: Vec<String> = [
                "server",
                "coaptic-mio-level",
                host,
                "0",
                size,
                rx,
                "missing-credentials-must-not-be-opened-by-preflight",
            ]
            .into_iter()
            .map(String::from)
            .collect();
            if let Some(profile) = selected {
                args.extend(["--resource-profile".into(), profile.into()]);
            }
            let profile = ResourceProfile::take_option(&mut args).unwrap();
            // This is the same helper main calls before credentials, BODY and bind.
            assert_eq!(validate_startup_profile(&args, profile).is_ok(), accepted);
        }
        let mut args: Vec<String> = [
            "server",
            "coaptic-mio-level",
            "127.0.0.1",
            "0",
            "32",
            "--resource-profile",
            "small-device",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let profile = ResourceProfile::take_option(&mut args).unwrap();
        assert!(validate_startup_profile(&args, profile).is_ok()); // Default RX1152.
        for kind in [
            "coaptic",
            "coaptic-mio",
            "coaptic-mio-direct",
            "coaptic-small",
            "coaptic-async",
            "coaptic-blocking",
            "coap-rs",
            "coap-rs-dtls",
            "--security-profile",
        ] {
            let args = vec!["server".into(), kind.into()];
            assert!(validate_startup_profile(&args, ResourceProfile::HostControl).is_ok());
        }
    }

    #[test]
    fn representative_profiles_refuse_unsupported_selection_before_binding() {
        for (profile, sizes, rx) in [
            (ResourceProfile::SmallDevice, &[32][..], 1152),
            (ResourceProfile::SmallBlockwise, &[64, 1024, 4096][..], 1152),
            (ResourceProfile::ServiceFixed, &[64, 1024, 16384][..], 1472),
            (
                ResourceProfile::ServiceAllocated,
                &[64, 1024, 16384][..],
                1472,
            ),
        ] {
            for &size in sizes {
                assert!(profile.validate("coaptic-mio", size, rx).is_ok());
                for kind in ["coaptic-mio-direct", "coaptic-small", "coaptic-async"] {
                    assert!(profile.validate(kind, size, rx).is_err());
                }
                assert!(profile.validate("coaptic-mio", size, rx + 1).is_err());
            }
            assert!(profile.validate("coaptic-mio", 65536, rx).is_err());
        }
        for value in ["unknown", ""] {
            let mut args = vec!["server".into(), "--resource-profile".into(), value.into()];
            assert!(ResourceProfile::take_option(&mut args).is_err());
        }
        let mut args = vec!["server".into(), "--resource-profile".into()];
        assert!(ResourceProfile::take_option(&mut args).is_err());
        let mut args = vec![
            "server".into(),
            "--resource-profile".into(),
            "small-device".into(),
            "--resource-profile".into(),
            "small-device".into(),
        ];
        assert!(ResourceProfile::take_option(&mut args).is_err());
    }

    #[test]
    fn service_profile_exact_heap_budget_refuses_then_binds_and_drives() {
        let io = || {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            MioUdp {
                socket: mio::net::UdpSocket::from_std(socket),
                scratch: [0; 2049],
                received: false,
            }
        };
        let resources = coaptic::resources::Service::new();
        let capacities = resources.pool_capacities();
        let required =
            AllocMemory::<coaptic::message::Token>::required_heap_bytes(capacities).unwrap();
        let refused = bind_resources!(resources.allocated(required - 1), io(), None);
        assert!(matches!(
            refused,
            Err(coaptic::BuildError::HeapBudgetExceeded { .. })
        ));
        let mut app = bind_resources!(
            coaptic::resources::Service::new().allocated(required),
            io(),
            None
        )
        .unwrap();
        assert_eq!(app.engine().capacities(), capacities);
        assert_eq!(app.client_capacity(), 4);
        assert_eq!(app.security_request_capacity(), 4);
        assert_eq!(app.association_capacity(), 1);
        assert!(read_burst(&mut app, Instant::now(), |io| io.received).unwrap());
        assert_eq!(app.engine_mut().rx_occupied(), 0);
    }

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
            for capacity in [64, 1152, 1472, 2048] {
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
