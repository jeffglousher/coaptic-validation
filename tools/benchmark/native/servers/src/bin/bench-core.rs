//! Socket-free, diagnostics-disabled request-path diagnostic.
//!
//! Identical fixtures can link different Coaptic revisions to isolate core work
//! from OS socket scheduling. Request preparation and complete reply validation
//! are outside each timed poll. Per-call clocks perturb these measurements;
//! they are not production latency or throughput estimates.
use coaptic::app::{AppAssembled, AppStorage};
use coaptic::message::{Message, MessageId, Opt, Token, Type, decode};
use coaptic::storage::{Capacities, DatagramIo, MemoryLayout};
use coaptic::{App, Code, ContentFormat, Endpoint, Request, Response, get};
use std::hint::black_box;
use std::io::{Read, Write};
use std::time::Instant;

#[path = "bench_core/live_c1.rs"]
mod live_c1;

const BODY: [u8; 64] = [0x5a; 64];
const SMALL_BODY: [u8; 32] = [0x5a; 32];
const PEER: Endpoint = Endpoint::v4([127, 0, 0, 1], 30000);

struct CoreIo {
    input: [u8; 1472],
    input_len: Option<usize>,
    output: [u8; 1472],
    output_len: Option<usize>,
}

impl coaptic::storage::DatagramTransport for CoreIo {
    type Error = &'static str;
}
impl DatagramIo for CoreIo {
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        let Some(n) = self.input_len.take() else {
            return Ok(None);
        };
        if n > buf.len() {
            return Err("receive capacity");
        }
        buf[..n].copy_from_slice(&self.input[..n]);
        Ok(Some((n, PEER)))
    }

    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        if peer != PEER || self.output_len.is_some() || bytes.len() > self.output.len() {
            return Err("unexpected response");
        }
        self.output[..bytes.len()].copy_from_slice(bytes);
        self.output_len = Some(bytes.len());
        Ok(bytes.len())
    }
}

fn representation(_: Request<'_>) -> Response<'static> {
    Response::content(&BODY)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"fixture")
}

const USAGE: &str = "usage: bench-core OPERATIONS (1..=60000) [unprotected|oscore [--small-device|--batch-cpu]]; --small-device is wall-only; --batch-cpu requires 50000; or: bench-core OPERATIONS unprotected|oscore --service-fixed|--service-allocated 64|1024|16384 (combined 60000-send bound)";

#[derive(Debug, PartialEq)]
enum ProbeMode {
    Wall,
    SmallDevice,
    BatchCpu,
    LiveC1,
    Service { allocated: bool, payload: usize },
}

#[derive(Debug, PartialEq)]
struct Config<'a> {
    operations: usize,
    security: &'a str,
    mode: ProbeMode,
}

fn parse_args(args: &[String]) -> Result<Config<'_>, Failure> {
    if !(2..=5).contains(&args.len()) {
        return Err(USAGE.into());
    }
    let operations = args[1].parse::<usize>().map_err(|_| USAGE)?;
    // A separate admission path: all historical modes retain their old bounds.
    if args.len() == 4 && args[3] == "--live-c1" {
        if operations != live_c1::OPERATIONS
            || !matches!(args[2].as_str(), "unprotected" | "oscore")
        {
            return Err("live C1 requires: bench-core 1000000 unprotected|oscore --live-c1".into());
        }
        return Ok(Config {
            operations,
            security: &args[2],
            mode: ProbeMode::LiveC1,
        });
    }
    if !(1..=60000).contains(&operations) {
        return Err("operation limit (1..=60000)".into());
    }
    let security = args.get(2).map_or("unprotected", String::as_str);
    if !matches!(security, "unprotected" | "oscore") {
        return Err(USAGE.into());
    }
    let mode = match args.get(3).map(String::as_str) {
        None => ProbeMode::Wall,
        Some("--small-device") if args.len() == 4 => ProbeMode::SmallDevice,
        Some("--batch-cpu") if args.len() == 4 => ProbeMode::BatchCpu,
        Some(flag @ ("--service-fixed" | "--service-allocated")) if args.len() == 5 => {
            let payload = args[4].parse::<usize>().map_err(|_| USAGE)?;
            service_admission(operations, payload)?;
            ProbeMode::Service {
                allocated: flag == "--service-allocated",
                payload,
            }
        }
        _ => return Err(USAGE.into()),
    };
    if mode == ProbeMode::BatchCpu && operations != BATCH_OPS {
        return Err("batch CPU requires exactly 50000 operations".into());
    }
    Ok(Config {
        operations,
        security,
        mode,
    })
}

fn small_representation(_: Request<'_>) -> Response<'static> {
    Response::content(&SMALL_BODY)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"fixture")
}

fn core_io() -> CoreIo {
    CoreIo {
        input: [0; WIRE],
        input_len: None,
        output: [0; WIRE],
        output_len: None,
    }
}

type SmallApp = App<
    coaptic::profiles::Constrained,
    CoreIo,
    4,
    false,
    <coaptic::profiles::Constrained as MemoryLayout<false>>::Store,
    0,
    1,
>;

fn small_app(
    server_context: Option<coaptic::oscore::SecurityContext>,
) -> Result<SmallApp, Failure> {
    let builder = App::with_resources(coaptic::resources::SmallDevice::new())
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .route("bench", get(small_representation));
    let builder = if let Some(context) = server_context {
        builder.oscore(context)
    } else {
        builder.allow_unprotected()
    };
    Ok(builder.bind(core_io())?)
}

fn default_app(
    server_context: Option<coaptic::oscore::SecurityContext>,
) -> Result<CoreApp, Failure> {
    let builder = App::builder()
        .routes::<1>()
        .block_wise::<true>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .route("bench", get(representation));
    let builder = if let Some(context) = server_context {
        builder.oscore(context)
    } else {
        builder.allow_unprotected()
    };
    Ok(builder.bind_alloc(
        core_io(),
        Capacities {
            rx_datagram_slots: 4,
            rx_datagram_bytes: 1472,
            tx_datagram_slots: 4,
            tx_datagram_bytes: 1472,
            dedup_entries: 8,
            observe_entries: 4,
            rx_body_slots: Some(1),
            rx_body_bytes: Some(1024),
            tx_body_slots: Some(2),
            tx_body_bytes: Some(1024),
        },
    )?)
}

fn main() -> Result<(), Failure> {
    let args: Vec<_> = std::env::args().collect();
    let config = parse_args(&args)?;
    let (client_context, server_context) = match config.security {
        "unprotected" => (None, None),
        "oscore" => {
            let mut material = [0; 24];
            getrandom::fill(&mut material)?;
            let derive = |sender_id, recipient_id| {
                coaptic::oscore::SecurityContext::derive(coaptic::oscore::DeriveParams {
                    master_secret: &material[..16],
                    master_salt: &material[16..],
                    sender_id,
                    recipient_id,
                    id_context: &[],
                })
            };
            let pair = (Some(derive(&[], &[1])?), Some(derive(&[1], &[])?));
            material.fill(0);
            pair
        }
        _ => return Err("security selection".into()),
    };
    if let ProbeMode::Service { allocated, payload } = config.mode {
        let mut client = service_client(client_context)?;
        return if allocated {
            service_allocated(server_context, &mut client, &config, payload)
        } else {
            service_fixed(server_context, &mut client, &config, payload)
        };
    }
    // Construct only the selected App; no union reserves a larger profile.
    if config.mode == ProbeMode::SmallDevice {
        wall_run(
            &mut small_app(server_context)?,
            client_context,
            config.operations,
            config.security,
            &SMALL_BODY,
            true,
        )
    } else {
        let mut app = default_app(server_context)?;
        if config.mode == ProbeMode::LiveC1 {
            live_c1::run(&mut app, client_context, config.security)
        } else if config.mode == ProbeMode::BatchCpu {
            batch_run(&mut app, client_context, config.security)
        } else {
            wall_run(
                &mut app,
                client_context,
                config.operations,
                config.security,
                &BODY,
                false,
            )
        }
    }
}

fn verify_reply(
    reply: &coaptic::message::ParsedMessage<'_>,
    mid: MessageId,
    token: Token,
    body: &[u8],
) -> Result<(), Failure> {
    let mut etags = reply.etag();
    if reply.message_id() != mid
        || reply.token() != token
        || reply.ty() != Type::Acknowledgement
        || reply.code() != Code::CONTENT
        || reply.payload() != body
        || reply.block2().is_some()
        || reply.content_format().and_then(Result::ok) != Some(ContentFormat::OCTET_STREAM)
        || etags.next() != Some(&b"fixture"[..])
        || etags.next().is_some()
    {
        return Err("response mismatch".into());
    }
    Ok(())
}

fn wall_run<P, S, const N: usize, const B: bool, const D: usize, const C: usize>(
    app: &mut App<P, CoreIo, N, B, S, D, C>,
    mut client_context: Option<coaptic::oscore::SecurityContext>,
    operations: usize,
    security: &str,
    body: &[u8],
    small_device: bool,
) -> Result<(), Failure>
where
    P: MemoryLayout<B> + AppAssembled<B>,
    S: AppStorage<Token = P::Token>,
{
    let mut latencies = Vec::with_capacity(operations);
    let mut clock_calibration = Vec::with_capacity(4096);
    for sample in 0..4096 {
        let started = Instant::now();
        black_box(sample);
        clock_calibration.push(started.elapsed().as_nanos());
    }
    let mut opened = [0; 1472];
    let clock = Instant::now();
    for operation in 0..operations + 128 {
        let elapsed = wall_step(
            app,
            &mut client_context,
            operation,
            clock,
            &mut opened,
            body,
        )?;
        if operation >= 128 {
            latencies.push(elapsed);
        }
    }
    print!(
        "{{\"operations\":{operations},\"warmup\":128,\"security\":\"{security}\",\"black_box\":true,\"measurement\":\"server App::poll with optimizer barriers; request preparation and complete response verification outside clock; OSCORE responses authenticated; timer calibration separate and never subtracted\",\"latencies_ns\":["
    );
    for (i, elapsed) in latencies.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("{elapsed}");
    }
    print!("],\"clock_calibration_ns\":[");
    for (i, elapsed) in clock_calibration.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("{elapsed}");
    }
    if small_device {
        print!("],");
        small_device_ledger(
            app,
            operations,
            latencies.capacity(),
            clock_calibration.capacity(),
        );
        println!("}}");
    } else {
        println!("]}}");
    }
    Ok(())
}

fn wall_step<P, S, const N: usize, const B: bool, const D: usize, const C: usize>(
    app: &mut App<P, CoreIo, N, B, S, D, C>,
    client_context: &mut Option<coaptic::oscore::SecurityContext>,
    operation: usize,
    clock: Instant,
    opened: &mut [u8; WIRE],
    body: &[u8],
) -> Result<u128, Failure>
where
    P: MemoryLayout<B> + AppAssembled<B>,
    S: AppStorage<Token = P::Token>,
{
    let mid = MessageId::new(operation as u16);
    let token = Token::new(&(operation as u64).to_be_bytes()).ok_or("token")?;
    let options = [Opt::uri_path("bench")];
    let request = Message::con(Code::GET, mid, token).with_options(&options);
    let io = app.transport_mut();
    io.input_len = Some(match client_context.as_mut() {
        Some(context) => context.protect_request(&request, &mut io.input)?,
        None => request.encode(&mut io.input)?,
    });
    let now = clock.elapsed().as_millis() as u64;
    let started = Instant::now();
    let outcome = black_box(black_box(&mut *app).poll(black_box(now)));
    let elapsed = started.elapsed().as_nanos();
    outcome.map_err(|_| "poll failure")?;
    wall_response(
        app.transport_mut(),
        client_context,
        opened,
        mid,
        token,
        body,
    )?;
    Ok(elapsed)
}

fn wall_response(
    io: &mut CoreIo,
    client_context: &mut Option<coaptic::oscore::SecurityContext>,
    opened: &mut [u8; WIRE],
    mid: MessageId,
    token: Token,
    body: &[u8],
) -> Result<(), Failure> {
    let n = io.output_len.take().ok_or("missing response")?;
    if !(1..=io.output.len()).contains(&n) {
        return Err("response length".into());
    }
    let wire = decode(black_box(&io.output[..n]))?;
    let reply = match client_context.as_mut() {
        Some(context) => {
            let binding = context.take(token).ok_or("request binding")?;
            context.unprotect_response(&wire, binding, opened)?
        }
        None => wire,
    };
    verify_reply(&reply, mid, token, body)?;
    Ok(())
}

// This ledger is emitted only by the opt-in wall mode. Nested owners are
// descriptive components of App, never additive whole-memory requirements.
fn small_device_ledger<P, S, const N: usize, const B: bool, const D: usize, const C: usize>(
    app: &App<P, CoreIo, N, B, S, D, C>,
    operations: usize,
    latency_capacity: usize,
    calibration_capacity: usize,
) where
    P: MemoryLayout<B> + AppAssembled<B>,
    S: AppStorage<Token = P::Token>,
{
    let caps = app.engine().capacities();
    print!(
        "\"profile\":\"SmallDevice\",\"pools\":\"Constrained\",\"storage\":\"fixed\",\"payload_bytes\":32,\"concurrency\":1,\"message_type\":\"CON\",\"routes\":{N},\"populated_routes\":1,\"calls\":{C},\"deferred\":{D},\"associations\":1,\"security_requests\":4,\"blockwise\":{B},\"rx_slots\":{},\"rx_datagram_bytes\":{},\"tx_slots\":{},\"tx_datagram_bytes\":{},\"dedup\":{},\"observe\":{},\"rx_body_slots\":0,\"tx_body_slots\":0,\"verified\":{},\"calibration_samples\":4096,",
        caps.rx_datagram_slots,
        caps.rx_datagram_bytes,
        caps.tx_datagram_slots,
        caps.tx_datagram_bytes,
        caps.dedup_entries,
        caps.observe_entries,
        operations + 128
    );
    print!(
        "\"memory\":{{\"app_including_transport_inline_bytes\":{},\"fixed_pool_heap_bytes\":0,\"transport_nested_in_app_inline_bytes\":{},\"transport_input_nested_bytes\":1472,\"transport_output_nested_bytes\":1472,\"separate_latency_requested_bytes\":{},\"separate_calibration_requested_bytes\":{},\"separate_timing_vec_headers_bytes\":{},\"separate_verification_buffer_bytes\":1472,\"separate_optional_client_context_inline_bytes\":{},\"separate_representation_static_bytes\":32,\"remaining\":\"allocator overhead, initialization scratch, generated peak stack and runtime memory unknown; nested owners must not be added twice\"}},\"scope\":\"socket-free wall supporting evidence only; fixture input/output copies remain inside App::poll; not native Mio memory equivalence, server CPU, socket latency, transport share, whole memory or either 50% acceptance\"",
        std::mem::size_of_val(app),
        std::mem::size_of_val(app.transport()),
        latency_capacity * std::mem::size_of::<u128>(),
        calibration_capacity * std::mem::size_of::<u128>(),
        2 * std::mem::size_of::<Vec<u128>>(),
        std::mem::size_of::<Option<coaptic::oscore::SecurityContext>>()
    );
}

// Service-only fixture. Keep CoreIo and all legacy wall/batch layouts unchanged.
const SERVICE_SEND_LIMIT: u32 = 30_000;
const SERVICE_ROUNDS: u32 = 32;
const SERVICE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
static SERVICE_BODY: [u8; 16384] = {
    let mut body = [0; 16384];
    let mut i = 0;
    while i < body.len() {
        body[i] = (i % 251) as u8;
        i += 1;
    }
    body
};

struct ServiceIo {
    io: CoreIo,
    sent: u32,
}
impl coaptic::storage::DatagramTransport for ServiceIo {
    type Error = &'static str;
}
impl DatagramIo for ServiceIo {
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        self.io.recv(buf)
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        if self.sent >= SERVICE_SEND_LIMIT {
            return Err("Service port send limit");
        }
        let n = self.io.send(peer, black_box(bytes))?;
        self.sent += 1;
        Ok(n)
    }
}
fn service_io() -> ServiceIo {
    ServiceIo {
        io: core_io(),
        sent: 0,
    }
}
fn service_admission(operations: usize, payload: usize) -> Result<(), Failure> {
    if !matches!(payload, 64 | 1024 | 16384)
        || operations == 0
        || operations
            .checked_add(128)
            .and_then(|n| n.checked_mul(payload.div_ceil(1024)))
            .is_none_or(|sends| sends > SERVICE_SEND_LIMIT as usize)
    {
        return Err(
            "Service requires payload 64/1024/16384 and (operations+128)*ceil(payload/1024)<=30000"
                .into(),
        );
    }
    Ok(())
}
fn service64(_: Request<'_>) -> Response<'static> {
    service_representation(64)
}
fn service1024(_: Request<'_>) -> Response<'static> {
    service_representation(1024)
}
fn service16384(_: Request<'_>) -> Response<'static> {
    service_representation(16384)
}
fn service_representation(payload: usize) -> Response<'static> {
    Response::content(&SERVICE_BODY[..payload])
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"fixture")
}
// All three handlers borrow the same static owner; no mutable payload selector.
macro_rules! service_builder {
    ($resources:expr, $context:expr, $payload:expr) => {{
        let handler: fn(Request<'_>) -> Response<'static> = match $payload {
            64 => service64,
            1024 => service1024,
            _ => service16384,
        };
        let builder = App::with_resources($resources)
            .randomness(|bytes| getrandom::fill(bytes).is_ok())
            .route("bench", get(handler));
        if let Some(context) = $context {
            builder.oscore(context)
        } else {
            builder.allow_unprotected()
        }
    }};
}
type ServiceClient =
    App<coaptic::profiles::Default, ServiceIo, 1, true, coaptic::storage::AllocMemory>;
type ServiceServer<S> = App<coaptic::profiles::Service, ServiceIo, 32, true, S, 8, 4>;

fn service_client_capacities() -> Capacities {
    Capacities {
        rx_datagram_slots: 4,
        rx_datagram_bytes: WIRE,
        tx_datagram_slots: 4,
        tx_datagram_bytes: WIRE,
        dedup_entries: 8,
        observe_entries: 4,
        rx_body_slots: Some(1),
        rx_body_bytes: Some(16384),
        tx_body_slots: Some(1),
        tx_body_bytes: Some(1024),
    }
}
fn service_client(
    context: Option<coaptic::oscore::SecurityContext>,
) -> Result<ServiceClient, Failure> {
    let builder = App::builder()
        .routes::<1>()
        .block_wise::<true>()
        .full_responses()
        .randomness(|bytes| getrandom::fill(bytes).is_ok());
    let builder = if let Some(context) = context {
        builder.oscore(context)
    } else {
        builder.allow_unprotected()
    };
    let caps = service_client_capacities();
    let heap = coaptic::storage::AllocMemory::<Token>::required_heap_bytes(caps)?;
    Ok(builder.bind_storage(
        service_io(),
        coaptic::storage::AllocMemory::try_new(caps, heap)?,
    )?)
}

// Like the existing Service/Mio entry, isolate large safe fixed initialization.
// No Box::new claim, stack-size override, extra thread or uninitialized storage.
#[inline(never)]
fn service_fixed(
    context: Option<coaptic::oscore::SecurityContext>,
    client: &mut ServiceClient,
    config: &Config<'_>,
    payload: usize,
) -> Result<(), Failure> {
    let mut app =
        service_builder!(coaptic::resources::Service::new(), context, payload).bind(service_io())?;
    service_run(&mut app, client, config, payload, false)
}
#[inline(never)]
fn service_allocated(
    context: Option<coaptic::oscore::SecurityContext>,
    client: &mut ServiceClient,
    config: &Config<'_>,
    payload: usize,
) -> Result<(), Failure> {
    let resources = coaptic::resources::Service::new();
    let heap =
        coaptic::storage::AllocMemory::<Token>::required_heap_bytes(resources.pool_capacities())?;
    let mut app =
        service_builder!(resources.allocated(heap), context, payload).bind(service_io())?;
    service_run(&mut app, client, config, payload, true)
}

fn service_bridge(from: &mut ServiceIo, to: &mut ServiceIo) -> Result<(), Failure> {
    let n = from
        .io
        .output_len
        .ok_or("Service no progress: missing packet")?;
    if !(1..=WIRE).contains(&n) || to.io.input_len.is_some() {
        return Err("Service bridge capacity/occupied input".into());
    }
    to.io.input[..n].copy_from_slice(black_box(&from.io.output[..n]));
    black_box(&to.io.input[..n]);
    to.io.input_len = Some(n);
    from.io.output_len = None;
    Ok(())
}
fn service_wire(io: &ServiceIo) -> Result<coaptic::message::ParsedMessage<'_>, Failure> {
    let n = io
        .io
        .output_len
        .ok_or("Service no progress: missing packet")?;
    if !(1..=WIRE).contains(&n) {
        return Err("Service packet length".into());
    }
    Ok(decode(black_box(&io.io.output[..n]))?)
}
fn service_ack(io: &ServiceIo, mid: MessageId, token: Token) -> Result<(), Failure> {
    let reply = service_wire(io)?;
    if reply.ty() != Type::Acknowledgement || reply.message_id() != mid || reply.token() != token {
        return Err("Service wire ACK/MID/Token mismatch".into());
    }
    Ok(())
}
fn service_deadline(started: Instant) -> Result<(), Failure> {
    if started.elapsed() >= SERVICE_TIMEOUT {
        return Err("Service complete operation deadline".into());
    }
    Ok(())
}
struct ServicePending {
    call: coaptic::Call,
    first_mid: MessageId,
    started: Instant,
    polls: u32,
    wall_sum: u128,
}
fn service_begin(
    client: &mut ServiceClient,
    payload: usize,
    clock: Instant,
) -> Result<ServicePending, Failure> {
    let started = Instant::now();
    let now: u64 = clock.elapsed().as_millis().try_into()?;
    let request = client.get("bench").to(PEER).deadline(now + 3000);
    let request = if payload == 16384 {
        request.block2(coaptic::message::BlockValue::new(0, false, 6)?)
    } else {
        request
    };
    let call = request
        .send(now)
        .map_err(|error| format!("Service client send: {error:?}"))?;
    client
        .poll(clock.elapsed().as_millis().try_into()?)
        .map_err(|_| "Service client poll")?;
    let first_mid = service_wire(client.transport())?.message_id();
    service_deadline(started)?;
    Ok(ServicePending {
        call,
        first_mid,
        started,
        polls: 0,
        wall_sum: 0,
    })
}
fn service_turn<S>(
    server: &mut ServiceServer<S>,
    client: &mut ServiceClient,
    pending: &mut ServicePending,
    clock: Instant,
) -> Result<(), Failure>
where
    S: AppStorage<Token = Token>,
{
    service_deadline(pending.started)?;
    if pending.polls >= SERVICE_ROUNDS {
        return Err("Service round limit".into());
    }
    let request = service_wire(client.transport())?;
    let mid = request.message_id();
    if request.ty() != Type::Confirmable || request.token() != pending.call.token() {
        return Err("Service request header mismatch".into());
    }
    service_bridge(client.transport_mut(), server.transport_mut())?;
    let now: u64 = clock.elapsed().as_millis().try_into()?;
    let started = Instant::now();
    let result = black_box(black_box(&mut *server).poll(black_box(now)));
    let elapsed = started.elapsed().as_nanos();
    pending.wall_sum = pending
        .wall_sum
        .checked_add(elapsed)
        .ok_or("Service wall sum overflow")?;
    pending.polls += 1;
    result.map_err(|_| "Service server poll")?;
    service_ack(server.transport(), mid, pending.call.token())?;
    service_bridge(server.transport_mut(), client.transport_mut())?;
    client
        .poll(clock.elapsed().as_millis().try_into()?)
        .map_err(|_| "Service client poll")?;
    service_deadline(pending.started)
}
fn service_verify(
    reply: &Response<'_>,
    pending: &ServicePending,
    payload: usize,
) -> Result<(), Failure> {
    let mut etags = reply
        .received_options()
        .filter(|opt| opt.number() == coaptic::message::OptionNumber::ETAG);
    if reply.code() != Code::CONTENT
        || reply.format() != Some(ContentFormat::OCTET_STREAM)
        || reply.etag_bytes() != Some(&b"fixture"[..])
        || etags.next().map(|opt| opt.value()) != Some(&b"fixture"[..])
        || etags.next().is_some()
        || reply.ty() != Some(Type::Acknowledgement)
        || reply.token() != Some(pending.call.token())
        || reply.message_id() != Some(pending.first_mid)
        || reply.peer() != Some(PEER)
        || reply.payload_truncated()
        || black_box(reply.payload()) != &SERVICE_BODY[..payload]
        || (payload == 16384 && !reply.has_body())
    {
        return Err("Service complete response mismatch".into());
    }
    // Assembled headers retain the FIRST fragment (including NUM0/M=1).
    // Terminal App collection, full varied body and round count prove completion.
    Ok(())
}
fn service_step<S>(
    server: &mut ServiceServer<S>,
    client: &mut ServiceClient,
    payload: usize,
    clock: Instant,
    output: &mut [u8],
) -> Result<(u128, u32), Failure>
where
    S: AppStorage<Token = Token>,
{
    let mut pending = service_begin(client, payload, clock)?;
    let result = (|| {
        for _ in 0..SERVICE_ROUNDS {
            service_turn(server, client, &mut pending, clock)?;
            if let Some(outcome) = client.take_response_into(pending.call, output)? {
                let reply = outcome.map_err(|_| "Service terminal Call failure")?;
                service_verify(&reply, &pending, payload)?;
                service_deadline(pending.started)?;
                if pending.polls != payload.div_ceil(1024) as u32 {
                    return Err("Service unexpected round count".into());
                }
                if client.transport().io.output_len.is_some() {
                    return Err("Service unexpected extra packet".into());
                }
                return Ok((pending.wall_sum, pending.polls));
            }
        }
        Err("Service incomplete after round limit".into())
    })();
    if result.is_err() {
        client.cancel(pending.call);
        // Cancellation alone does not consume terminal state. Failure stops the
        // run; consume any terminal outcome before dropping the owned Apps.
        let _ = client.take_response(pending.call);
    }
    result
}
fn service_run<S>(
    server: &mut ServiceServer<S>,
    client: &mut ServiceClient,
    config: &Config<'_>,
    payload: usize,
    allocated: bool,
) -> Result<(), Failure>
where
    S: AppStorage<Token = Token>,
{
    let mut samples = Vec::with_capacity(config.operations);
    let mut polls = Vec::with_capacity(config.operations);
    let mut calibration = Vec::with_capacity(4096);
    let mut output = vec![0; 16384];
    for i in 0..4096 {
        let started = Instant::now();
        black_box(i);
        calibration.push(started.elapsed().as_nanos());
    }
    let clock = Instant::now();
    for operation in 0..config.operations + 128 {
        let (wall, count) = service_step(server, client, payload, clock, &mut output)?;
        if operation >= 128 {
            samples.push(wall);
            polls.push(count);
        }
    }
    let heap = if allocated {
        coaptic::storage::AllocMemory::<Token>::required_heap_bytes(server.engine().capacities())?
    } else {
        0
    };
    let client_heap =
        coaptic::storage::AllocMemory::<Token>::required_heap_bytes(client.engine().capacities())?;
    print!(
        "{{\"operations\":{},\"warmup\":128,\"verified\":{},\"security\":\"{}\",\"black_box\":true,\"profile\":\"Service\",\"storage\":\"{}\",\"payload_bytes\":{payload},\"concurrency\":1,\"message_type\":\"CON\",\"calibration_samples\":4096,",
        config.operations,
        config.operations + 128,
        config.security,
        if allocated { "allocated" } else { "fixed" }
    );
    print!(
        "\"server_poll_wall_sum_ns\":{samples:?},\"server_poll_counts\":{polls:?},\"clock_calibration_ns\":{calibration:?},"
    );
    print!(
        "\"server_capacities\":{{\"routes\":32,\"populated_routes\":1,\"calls\":4,\"deferred\":8,\"associations\":1,\"security_requests\":4,\"rx_slots\":32,\"tx_slots\":32,\"datagram_bytes\":1472,\"dedup\":64,\"observe\":32,\"rx_body_slots\":4,\"tx_body_slots\":4,\"body_bytes\":16384,\"blockwise\":true}},"
    );
    print!(
        "\"client_capacities\":{{\"routes\":1,\"populated_routes\":0,\"calls\":4,\"deferred\":0,\"associations\":1,\"security_requests\":4,\"rx_slots\":4,\"tx_slots\":4,\"datagram_bytes\":1472,\"dedup\":8,\"observe\":4,\"rx_body_slots\":1,\"rx_body_bytes\":16384,\"tx_body_slots\":1,\"tx_body_bytes\":1024,\"blockwise\":true}},"
    );
    print!(
        "\"sends\":{{\"client\":{},\"server\":{},\"combined\":{},\"per_port_limit\":30000,\"combined_limit\":60000}},",
        client.transport().sent,
        server.transport().sent,
        client.transport().sent + server.transport().sent
    );
    print!(
        "\"memory\":{{\"server_app_including_transport_inline_bytes\":{},\"server_pool_requested_heap_bytes\":{heap},\"server_pool_payload_nested_bytes\":225280,\"server_transport_nested_bytes\":{},\"client_app_including_transport_inline_bytes\":{},\"client_pool_requested_heap_bytes\":{client_heap},\"client_pool_payload_nested_bytes\":29184,\"client_transport_nested_bytes\":{},\"each_transport_input_nested_bytes\":1472,\"each_transport_output_nested_bytes\":1472,\"packet_buffers_nested_count\":4,",
        std::mem::size_of_val(server),
        std::mem::size_of_val(server.transport()),
        std::mem::size_of_val(client),
        std::mem::size_of_val(client.transport())
    );
    print!(
        "\"separate_static_representation_bytes\":16384,\"separate_verification_requested_bytes\":{},\"separate_timing_requested_bytes\":{},\"separate_poll_counts_requested_bytes\":{},\"separate_calibration_requested_bytes\":{},\"separate_vec_headers_bytes\":{},\"separate_pending_inline_bytes\":{},\"clock_inline_bytes\":{},\"remaining\":\"security/bindings, fixed pools, profile scratch and transport metadata nest in Apps; allocated pool metadata/alignment nest in requested heap; allocator overhead, init temporaries, generated peak stack and runtime unknown; do not add nested owners twice\"}},",
        output.capacity(),
        samples.capacity() * std::mem::size_of::<u128>(),
        polls.capacity() * std::mem::size_of::<u32>(),
        calibration.capacity() * std::mem::size_of::<u128>(),
        std::mem::size_of_val(&output)
            + std::mem::size_of_val(&samples)
            + std::mem::size_of_val(&polls)
            + std::mem::size_of_val(&calibration),
        std::mem::size_of::<ServicePending>(),
        std::mem::size_of::<Instant>()
    );
    println!(
        "\"measurement\":\"sum of every server App::poll wall interval per fully verified operation; server fixture receive/send copies, dispatch, maintenance, body snapshot and crypto inside; bridge, client preparation/polls/protection/authentication/assembly/verification outside; monotonic clock; separate calibration never subtracted\",\"metadata\":\"each wire ACK/MID/Token checked against its request; assembled snapshot retains first fragment MID/header\",\"scope\":\"socket-free C1 wall supporting evidence; not CPU, socket latency, transport share, Mio memory equivalence, peak/whole memory or either 50% acceptance\"}}"
    );
    Ok(())
}

// Diagnostic storage only. App pools, Calls and security bindings stay unchanged.
const BATCH_OPS: usize = 50_000;
const WORK_BATCHES: usize = 1;
const EMPTY_GATES: usize = 16;
const WIRE: usize = 1472;
// Only this fixed 64-byte fixture uses smaller capture rows; App I/O stays WIRE.
const CAPTURE_BYTES: usize = 256;
const FIXTURE_LIMIT: usize = 32 * 1024 * 1024;
type Failure = Box<dyn std::error::Error>;
type CoreApp = App<coaptic::profiles::Default, CoreIo, 1, true, coaptic::storage::AllocMemory>;

struct BatchRow {
    request: [u8; CAPTURE_BYTES],
    response: [u8; CAPTURE_BYTES],
    request_len: usize,
    response_len: usize,
    binding: Option<coaptic::oscore::RequestRef>,
    operation: u16,
}

impl BatchRow {
    fn empty() -> Self {
        Self {
            request: [0; CAPTURE_BYTES],
            response: [0; CAPTURE_BYTES],
            request_len: 0,
            response_len: 0,
            binding: None,
            operation: 0,
        }
    }

    fn token(&self) -> Result<Token, Failure> {
        Token::new(&u64::from(self.operation).to_be_bytes()).ok_or_else(|| "token".into())
    }

    fn prepare(
        &mut self,
        operation: usize,
        context: &mut Option<coaptic::oscore::SecurityContext>,
    ) -> Result<(), Failure> {
        if self.request_len != 0 || self.response_len != 0 || self.binding.is_some() {
            return Err("unconsumed fixture row".into());
        }
        self.operation = operation.try_into()?;
        let token = self.token()?;
        let options = [Opt::uri_path("bench")];
        let request =
            Message::con(Code::GET, MessageId::new(self.operation), token).with_options(&options);
        self.request_len = match context.as_mut() {
            Some(context) => {
                let len = context.protect_request(&request, &mut self.request)?;
                // Public seam: transfer each fresh binding immediately. Never
                // raise REQUESTS, restore bindings or reuse a sender sequence.
                self.binding = Some(context.take(token).ok_or("request binding")?);
                len
            }
            None => request.encode(&mut self.request)?,
        };
        Ok(())
    }

    fn verify(
        &mut self,
        context: &mut Option<coaptic::oscore::SecurityContext>,
        opened: &mut [u8; WIRE],
    ) -> Result<(), Failure> {
        if self.request_len == 0 || !(1..=CAPTURE_BYTES).contains(&self.response_len) {
            return Err("missing/consumed response".into());
        }
        let wire = decode(black_box(&self.response[..self.response_len]))?;
        let reply = match context.as_mut() {
            Some(context) => context.unprotect_response(
                &wire,
                self.binding
                    .take()
                    .ok_or("missing/consumed request binding")?,
                opened,
            )?,
            None => {
                if self.binding.is_some() {
                    return Err("unexpected request binding".into());
                }
                wire
            }
        };
        let mut etags = reply.etag();
        if reply.message_id() != MessageId::new(self.operation)
            || reply.token() != self.token()?
            || reply.ty() != Type::Acknowledgement
            || reply.code() != Code::CONTENT
            || reply.payload() != BODY
            || reply.block2().is_some()
            || reply.content_format().and_then(Result::ok) != Some(ContentFormat::OCTET_STREAM)
            || etags.next() != Some(&b"fixture"[..])
            || etags.next().is_some()
        {
            return Err("response mismatch".into());
        }
        self.request_len = 0;
        self.response_len = 0;
        Ok(())
    }
}

struct BatchFixture {
    rows: Vec<BatchRow>,
    client: Option<coaptic::oscore::SecurityContext>,
    opened: [u8; WIRE],
    clock: Instant,
}

fn batch_layout(app: &CoreApp) -> Result<(usize, usize, usize), Failure> {
    let metadata = std::mem::size_of::<BatchRow>()
        .checked_sub(2 * CAPTURE_BYTES)
        .ok_or("row layout")?;
    // Includes Option<RequestRef>, lengths, global MID and enclosing padding.
    if metadata > 64 {
        return Err("batch row metadata exceeds 64 bytes".into());
    }
    let heap = coaptic::storage::AllocMemory::<Token>::required_heap_bytes(Capacities {
        rx_datagram_slots: 4,
        rx_datagram_bytes: WIRE,
        tx_datagram_slots: 4,
        tx_datagram_bytes: WIRE,
        dedup_entries: 8,
        observe_entries: 4,
        rx_body_slots: Some(1),
        rx_body_bytes: Some(1024),
        tx_body_slots: Some(2),
        tx_body_bytes: Some(1024),
    })?;
    let bytes = std::mem::size_of::<BatchRow>()
        .checked_mul(BATCH_OPS)
        .and_then(|n| n.checked_add(heap))
        .and_then(|n| n.checked_add(std::mem::size_of_val(app)))
        .and_then(|n| n.checked_add(std::mem::size_of::<BatchFixture>()))
        // Conservative allowance for diagnostic gate/prepare call temporaries;
        // neither allocator overhead nor whole-process RSS is claimed here.
        .and_then(|n| n.checked_add(16 * 1024))
        .ok_or("fixture layout overflow")?;
    if bytes >= FIXTURE_LIMIT {
        return Err("batch fixture plus App request/inline budget exceeds 32 MiB".into());
    }
    Ok((bytes, metadata, heap))
}

fn batch_drive(app: &mut CoreApp, rows: &mut [BatchRow], clock: Instant) -> Result<(), Failure> {
    for row in rows {
        let io = app.transport_mut();
        if io.input_len.is_some()
            || io.output_len.is_some()
            || !(1..=CAPTURE_BYTES).contains(&row.request_len)
            || row.response_len != 0
        {
            return Err("unexpected input/extra response".into());
        }
        io.input[..row.request_len].copy_from_slice(black_box(&row.request[..row.request_len]));
        io.input_len = Some(row.request_len);
        // Real monotonic progress, including expiry after a gate stall. There
        // are no per-operation elapsed/calibration clocks in this mode.
        let now_ms = clock.elapsed().as_millis().try_into()?;
        black_box(black_box(&mut *app).poll(black_box(now_ms))).map_err(|_| "poll failure")?;
        let io = app.transport_mut();
        if io.input_len.is_some() {
            return Err("request was not consumed".into());
        }
        let n = io.output_len.take().ok_or("missing response")?;
        if !(1..=CAPTURE_BYTES).contains(&n) {
            return Err("oversize response".into());
        }
        row.response[..n].copy_from_slice(black_box(&io.output[..n]));
        row.response_len = n;
        black_box(&row.response[..n]);
    }
    Ok(())
}

fn batch_gate(input: &mut impl Read, expected: &[u8]) -> Result<(), Failure> {
    let mut control = [0; 7];
    if expected.len() > control.len() {
        return Err("control bound".into());
    }
    input.read_exact(&mut control[..expected.len()])?; // EOF is fatal, including orphaned children.
    if &control[..expected.len()] != expected {
        return Err("control order".into());
    }
    Ok(())
}

fn batch_event(
    output: &mut impl Write,
    event: &str,
    kind: &str,
    block: usize,
    verified: usize,
) -> Result<(), Failure> {
    writeln!(
        output,
        "{{\"event\":\"{event}\",\"kind\":\"{kind}\",\"block\":{block},\"verified\":{verified}}}"
    )?;
    output.flush()?;
    Ok(())
}

#[cfg(windows)]
fn current_windows_thread_id() -> u32 {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentThreadId() -> u32;
    }
    // SAFETY: GetCurrentThreadId takes no arguments and always returns the
    // calling OS thread's ID; it borrows no memory and requires no cleanup.
    unsafe { GetCurrentThreadId() }
}

fn batch_run(
    app: &mut CoreApp,
    client: Option<coaptic::oscore::SecurityContext>,
    security: &str,
) -> Result<(), Failure> {
    let mut input = std::io::stdin().lock();
    // A worker killed between owned spawn and registration cannot release work.
    batch_gate(&mut input, b"start\n")?;
    let (requested_bytes, metadata_bytes, app_heap_bytes) = batch_layout(app)?;
    let mut fixture = BatchFixture {
        rows: Vec::new(),
        client,
        opened: [0; WIRE],
        clock: Instant::now(),
    };
    fixture.rows.try_reserve_exact(BATCH_OPS)?;
    if fixture.rows.capacity() != BATCH_OPS {
        return Err("unexpected fixture capacity expansion".into());
    }
    fixture.rows.resize_with(BATCH_OPS, BatchRow::empty);
    let mut output = std::io::stdout().lock();
    write!(
        output,
        "{{\"event\":\"fixture\",\"security\":\"{security}\",\"requested_bytes\":{requested_bytes},\"row_bytes\":{},\"row_metadata_bytes\":{metadata_bytes},\"request_ref_bytes\":{},\"optional_request_ref_bytes\":{},\"wire_bytes\":25600000,\"capture_datagram_bytes\":256,\"app_datagram_bytes\":1472,\"app_heap_bytes\":{app_heap_bytes},\"app_inline_bytes\":{},\"fixture_inline_bytes\":{},\"scratch_allowance_bytes\":16384,\"rows\":50000,\"limit_bytes\":33554432",
        std::mem::size_of::<BatchRow>(),
        std::mem::size_of::<coaptic::oscore::RequestRef>(),
        std::mem::size_of::<Option<coaptic::oscore::RequestRef>>(),
        std::mem::size_of_val(app),
        std::mem::size_of::<BatchFixture>()
    )?;
    // This synchronous thread also executes every batch_drive below. Report
    // its OS identity once, outside all measured gates; other runtimes may
    // have created auxiliary threads before batch_run starts.
    #[cfg(windows)]
    write!(
        output,
        ",\"workload_thread_id\":{}",
        current_windows_thread_id()
    )?;
    writeln!(output, "}}")?;
    output.flush()?;
    for operation in 0..128 {
        fixture.rows[0].prepare(operation, &mut fixture.client)?;
        batch_drive(app, &mut fixture.rows[..1], fixture.clock)?;
        fixture.rows[0].verify(&mut fixture.client, &mut fixture.opened)?;
    }
    let mut verified = 128;
    for (kind, blocks) in [("empty", EMPTY_GATES), ("work", WORK_BATCHES)] {
        for block in 0..blocks {
            if kind == "work" {
                for (i, row) in fixture.rows.iter_mut().enumerate() {
                    row.prepare(128 + block * BATCH_OPS + i, &mut fixture.client)?;
                }
            }
            batch_event(&mut output, "ready", kind, block, verified)?;
            batch_gate(&mut input, b"run\n")?;
            if kind == "work" {
                batch_drive(app, &mut fixture.rows, fixture.clock)?;
            } else {
                black_box(&mut *app); // No App work in the empty gate control.
            }
            // Parent reads after-CPU while this process blocks before ANY decode.
            batch_event(&mut output, "measured", kind, block, verified)?;
            batch_gate(&mut input, b"verify\n")?;
            if kind == "work" {
                for row in &mut fixture.rows {
                    row.verify(&mut fixture.client, &mut fixture.opened)?;
                }
                verified += BATCH_OPS;
            }
            batch_event(&mut output, "verified", kind, block, verified)?;
        }
    }
    if verified != 50_128 || fixture.rows.capacity() != BATCH_OPS {
        return Err("fixture count/capacity mismatch".into());
    }
    writeln!(
        output,
        "{{\"event\":\"complete\",\"mode\":\"server-app-batch-cpu\",\"security\":\"{security}\",\"operations\":50000,\"warmup\":128,\"verified\":{verified},\"work_batches\":1,\"batch_operations\":50000,\"empty_gates\":16,\"internal_datagrams\":100256,\"udp_datagrams\":0,\"black_box\":true}}"
    )?;
    output.flush()?;
    batch_gate(&mut input, b"exit\n")?;
    Ok(())
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use coaptic::storage::DatagramIo;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    std::thread_local! {
        static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
    }
    struct CountAlloc;
    fn count_alloc() {
        let _ = ALLOCATIONS.try_with(|count| {
            if let Some(n) = count.get() {
                count.set(Some(n + 1));
            }
        });
    }
    // Test-only, thread-local observation; unrelated parallel tests are excluded.
    unsafe impl GlobalAlloc for CountAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            count_alloc();
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            count_alloc();
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            count_alloc();
            unsafe { System.realloc(ptr, layout, size) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }
    #[global_allocator]
    static ALLOCATOR: CountAlloc = CountAlloc;

    struct Counting;
    impl Drop for Counting {
        fn drop(&mut self) {
            ALLOCATIONS.with(|count| count.set(None));
        }
    }

    // Shared by the live sibling; there remains exactly one global allocator.
    pub(super) fn observe_allocations<T>(f: impl FnOnce() -> T) -> (T, usize) {
        ALLOCATIONS.with(|count| count.set(Some(0)));
        let guard = Counting;
        let result = f();
        let count = ALLOCATIONS.with(Cell::get).unwrap();
        drop(guard);
        (result, count)
    }

    pub(super) fn fixture(protected: bool) -> (CoreApp, Option<coaptic::oscore::SecurityContext>) {
        let derive = |sender_id, recipient_id| {
            coaptic::oscore::SecurityContext::derive(coaptic::oscore::DeriveParams {
                master_secret: &[0x37; 16],
                master_salt: &[0x51; 8],
                sender_id,
                recipient_id,
                id_context: &[],
            })
            .unwrap()
        };
        let builder = App::builder()
            .routes::<1>()
            .block_wise::<true>()
            .randomness(|bytes| getrandom::fill(bytes).is_ok())
            .route("bench", get(representation));
        let (builder, client) = if protected {
            (builder.oscore(derive(&[1], &[])), Some(derive(&[], &[1])))
        } else {
            (builder.allow_unprotected(), None)
        };
        let app = builder
            .bind_alloc(
                CoreIo {
                    input: [0; WIRE],
                    input_len: None,
                    output: [0; WIRE],
                    output_len: None,
                },
                Capacities {
                    rx_datagram_slots: 4,
                    rx_datagram_bytes: WIRE,
                    tx_datagram_slots: 4,
                    tx_datagram_bytes: WIRE,
                    dedup_entries: 8,
                    observe_entries: 4,
                    rx_body_slots: Some(1),
                    rx_body_bytes: Some(1024),
                    tx_body_slots: Some(2),
                    tx_body_bytes: Some(1024),
                },
            )
            .unwrap();
        (app, client)
    }

    fn contexts(
        protected: bool,
    ) -> (
        Option<coaptic::oscore::SecurityContext>,
        Option<coaptic::oscore::SecurityContext>,
    ) {
        let derive = |sender_id, recipient_id| {
            coaptic::oscore::SecurityContext::derive(coaptic::oscore::DeriveParams {
                master_secret: &[0x37; 16],
                master_salt: &[0x51; 8],
                sender_id,
                recipient_id,
                id_context: &[],
            })
            .unwrap()
        };
        if protected {
            (Some(derive(&[], &[1])), Some(derive(&[1], &[])))
        } else {
            (None, None)
        }
    }

    #[test]
    fn wall_cli_bounds_and_mixed_flag_refusal() {
        for security in ["unprotected", "oscore"] {
            for (flag, mode) in [
                ("", ProbeMode::Wall),
                ("--small-device", ProbeMode::SmallDevice),
                ("--batch-cpu", ProbeMode::BatchCpu),
            ] {
                let mut args = vec!["bench-core".into(), "50000".into(), security.into()];
                if !flag.is_empty() {
                    args.push(flag.into());
                }
                assert_eq!(parse_args(&args).unwrap().mode, mode);
            }
        }
        for operations in ["1", "60000"] {
            let args = vec!["bench-core".into(), operations.into()];
            assert_eq!(parse_args(&args).unwrap().security, "unprotected");
            assert_eq!(parse_args(&args).unwrap().mode, ProbeMode::Wall);
            let mut small = args;
            small.extend(["oscore".into(), "--small-device".into()]);
            assert_eq!(parse_args(&small).unwrap().mode, ProbeMode::SmallDevice);
        }
        for raw in [
            "",
            "0",
            "60001",
            "-1",
            "x",
            "1 --small-device",
            "1 unknown",
            "1 oscore --unknown",
            "1 oscore --batch-cpu",
            "50000 oscore --small-device --batch-cpu",
            "50000 oscore --batch-cpu --small-device",
            "1 oscore --small-device extra",
        ] {
            let mut args = vec!["bench-core".into()];
            args.extend(raw.split_whitespace().map(str::to_owned));
            assert!(parse_args(&args).is_err(), "{raw}");
        }
        let max = vec!["bench-core".into(), "60000".into()];
        assert!(parse_args(&max).unwrap().operations + 128 < u16::MAX as usize); // No warmup/measured MID reuse.
    }

    fn wall_reuse<P, S, const N: usize, const B: bool, const D: usize, const C: usize>(
        app: &mut App<P, CoreIo, N, B, S, D, C>,
        client: &mut Option<coaptic::oscore::SecurityContext>,
        body: &[u8],
    ) where
        P: MemoryLayout<B> + AppAssembled<B>,
        S: AppStorage<Token = P::Token>,
    {
        let capacities = app.engine().capacities();
        let mut opened = [0; WIRE];
        let clock = Instant::now();
        ALLOCATIONS.with(|count| count.set(Some(0)));
        let guard = Counting;
        for operation in 0..36 {
            wall_step(app, client, operation, clock, &mut opened, body).unwrap();
            assert!(app.transport().input_len.is_none());
            assert!(app.transport().output_len.is_none());
        }
        let allocations = ALLOCATIONS.with(Cell::get).unwrap();
        drop(guard);
        assert_eq!(allocations, 0);
        assert_eq!(app.engine().capacities(), capacities);
        if let Some(client) = client {
            assert_eq!(client.request_capacity(), 4);
            assert_eq!(client.sender_seq(), 36);
        }
    }

    #[test]
    fn wall_exact_presets_both_payloads_verify_without_growth() {
        let preset = coaptic::resources::SmallDevice::new();
        assert_eq!(preset.route_capacity(), 4);
        assert_eq!(preset.client_capacity(), 1);
        assert_eq!(preset.deferred_capacity(), 0);
        assert_eq!(preset.association_capacity(), 1);
        assert_eq!(preset.security_request_capacity(), 4);
        let expected = Capacities {
            rx_datagram_slots: 2,
            rx_datagram_bytes: 1152,
            tx_datagram_slots: 2,
            tx_datagram_bytes: 1152,
            dedup_entries: 4,
            observe_entries: 2,
            rx_body_slots: None,
            rx_body_bytes: None,
            tx_body_slots: None,
            tx_body_bytes: None,
        };
        assert_eq!(preset.pool_capacities(), expected);
        for protected in [false, true] {
            let (mut client, server) = contexts(protected);
            let mut app = small_app(server).unwrap();
            assert_eq!(app.engine().capacities(), expected);
            wall_reuse(&mut app, &mut client, &SMALL_BODY);
            let (mut client, server) = contexts(protected);
            let mut app = default_app(server).unwrap();
            let caps = app.engine().capacities();
            assert_eq!((caps.rx_datagram_slots, caps.tx_datagram_slots), (4, 4));
            assert_eq!(
                (caps.rx_datagram_bytes, caps.tx_datagram_bytes),
                (1472, 1472)
            );
            assert_eq!((caps.dedup_entries, caps.observe_entries), (8, 4));
            assert_eq!((caps.rx_body_slots, caps.tx_body_slots), (Some(1), Some(2)));
            assert_eq!(
                (caps.rx_body_bytes, caps.tx_body_bytes),
                (Some(1024), Some(1024))
            );
            wall_reuse(&mut app, &mut client, &BODY);
        }
    }

    fn wall_faults<P, S, const N: usize, const B: bool, const D: usize, const C: usize>(
        app: &mut App<P, CoreIo, N, B, S, D, C>,
        client: &mut Option<coaptic::oscore::SecurityContext>,
        body: &[u8],
    ) where
        P: MemoryLayout<B> + AppAssembled<B>,
        S: AppStorage<Token = P::Token>,
    {
        let clock = Instant::now();
        for fault in 0..8 {
            let mid = MessageId::new(fault);
            let token = Token::new(&u64::from(fault).to_be_bytes()).unwrap();
            let options = [Opt::uri_path("bench")];
            let request = Message::con(Code::GET, mid, token).with_options(&options);
            let io = app.transport_mut();
            io.input_len = Some(match client.as_mut() {
                Some(context) => context.protect_request(&request, &mut io.input).unwrap(),
                None => request.encode(&mut io.input).unwrap(),
            });
            app.poll(clock.elapsed().as_millis() as u64).unwrap();
            let io = app.transport_mut();
            match fault {
                0 => io.output_len = None,
                1 => io.output_len = Some(1),
                2 => io.output[io.output_len.unwrap() - 1] ^= 1, // Payload or authentication tag.
                3 => io.output[2] ^= 1,                          // MID is outside OSCORE AAD.
                4 => io.output[4] ^= 1,                          // Token.
                5 => io.output_len = Some(WIRE + 1),
                6 => io.output_len = Some(0),
                7 if client.is_some() => {
                    client.as_mut().unwrap().take(token);
                }
                7 => io.output[1] = Code::BAD_REQUEST.as_raw(),
                _ => unreachable!(),
            }
            assert!(
                wall_response(io, client, &mut [0; WIRE], mid, token, body).is_err(),
                "fault {fault}"
            );
            if let Some(client) = client {
                client.take(token);
            }
        }
        wall_step(app, client, 8, clock, &mut [0; WIRE], body).unwrap();
    }

    #[test]
    fn wall_missing_bad_response_and_authentication_refuse_then_recover() {
        for protected in [false, true] {
            let (mut client, server) = contexts(protected);
            wall_faults(&mut small_app(server).unwrap(), &mut client, &SMALL_BODY);
            let (mut client, server) = contexts(protected);
            wall_faults(&mut default_app(server).unwrap(), &mut client, &BODY);
        }
    }

    #[test]
    fn wall_full_metadata_and_complete_payload_are_required() {
        let mid = MessageId::new(17);
        let token = Token::new(b"token").unwrap();
        for body in [&SMALL_BODY[..], &BODY[..]] {
            for fault in 0..10 {
                let etag = Opt::new(coaptic::message::OptionNumber::ETAG, b"fixture");
                let wrong_etag = Opt::new(coaptic::message::OptionNumber::ETAG, b"wrong");
                let format = Opt::new(coaptic::message::OptionNumber::CONTENT_FORMAT, &[42]); // application/octet-stream
                let block = Opt::new(coaptic::message::OptionNumber::BLOCK2, &[0]);
                let mut options = vec![etag, format];
                match fault {
                    1 => {
                        options.remove(0);
                    }
                    2 => options[0] = wrong_etag,
                    3 => options.insert(0, etag),
                    4 => {
                        options.pop();
                    }
                    5 => {
                        options[1] = Opt::new(coaptic::message::OptionNumber::CONTENT_FORMAT, &[0])
                    }
                    6 => options.push(block),
                    _ => {}
                }
                let ty = if fault == 7 {
                    Type::NonConfirmable
                } else {
                    Type::Acknowledgement
                };
                let code = if fault == 8 {
                    Code::BAD_REQUEST
                } else {
                    Code::CONTENT
                };
                let payload = if fault == 9 {
                    &body[..body.len() - 1]
                } else {
                    body
                };
                let mut wire = [0; WIRE];
                let len = Message::new(ty, code, mid)
                    .with_token(token)
                    .with_options(&options)
                    .with_payload(payload)
                    .encode(&mut wire)
                    .unwrap();
                assert_eq!(
                    verify_reply(&decode(&wire[..len]).unwrap(), mid, token, body).is_ok(),
                    fault == 0,
                    "fault {fault}, payload {}",
                    body.len()
                );
            }
        }
    }

    #[test]
    fn batch_external_bindings_exceed_four_without_reset_or_growth() {
        for protected in [false, true] {
            let (mut app, mut context) = fixture(protected);
            let (bytes, metadata, _) = batch_layout(&app).unwrap();
            assert!(bytes < FIXTURE_LIMIT && metadata <= 64);
            let mut rows: Vec<_> = (0..12).map(|_| BatchRow::empty()).collect();
            let capacity = rows.capacity();
            let clock = Instant::now();
            let mut opened = [0; WIRE];
            for batch in 0..3 {
                for (i, row) in rows.iter_mut().enumerate() {
                    row.prepare(batch * rows_len() + i, &mut context).unwrap();
                    if let Some(context) = &context {
                        assert_eq!(context.request_capacity(), 4);
                        assert!(context.lookup(row.token().unwrap()).is_none());
                        assert_eq!(context.sender_seq(), (batch * rows_len() + i + 1) as u64);
                        assert_eq!(
                            row.binding.unwrap().piv().seq(),
                            (batch * rows_len() + i) as u64
                        );
                    }
                }
                batch_drive(&mut app, &mut rows, clock).unwrap();
                for row in &mut rows {
                    row.verify(&mut context, &mut opened).unwrap();
                    assert!(row.binding.is_none());
                    assert!(row.verify(&mut context, &mut opened).is_err());
                }
                assert_eq!(rows.capacity(), capacity);
                if let Some(server) = app.oscore() {
                    assert!(!server.replay_fresh((batch * rows_len()) as u64));
                }
            }
        }
    }

    const fn rows_len() -> usize {
        12
    }

    #[test]
    fn batch_prepare_drive_verify_allocate_nothing_after_startup() {
        for protected in [false, true] {
            let (mut app, mut context) = fixture(protected);
            let mut rows: Vec<_> = (0..12).map(|_| BatchRow::empty()).collect();
            let mut opened = [0; WIRE];
            let clock = Instant::now();
            ALLOCATIONS.with(|count| count.set(Some(0)));
            let guard = Counting;
            for batch in 0..3 {
                for (i, row) in rows.iter_mut().enumerate() {
                    row.prepare(batch * rows_len() + i, &mut context).unwrap();
                }
                batch_drive(&mut app, &mut rows, clock).unwrap();
                for row in &mut rows {
                    row.verify(&mut context, &mut opened).unwrap();
                }
            }
            let allocations = ALLOCATIONS.with(Cell::get).unwrap();
            drop(guard);
            assert_eq!(allocations, 0);
        }
    }

    #[test]
    fn batch_wrong_missing_consumed_bindings_and_bad_responses_fail() {
        for protected in [false, true] {
            for fault in 0..9 {
                let (mut app, mut context) = fixture(protected);
                let mut rows = [BatchRow::empty(), BatchRow::empty()];
                rows[0].prepare(0, &mut context).unwrap();
                rows[1].prepare(1, &mut context).unwrap();
                batch_drive(&mut app, &mut rows, Instant::now()).unwrap();
                let (first, second) = rows.split_at_mut(1);
                let row = &mut second[0];
                match fault {
                    0 => row.response_len = 0,
                    1 => row.response_len = 1,
                    2 => row.response_len = CAPTURE_BYTES + 1,
                    3 => row.response[row.response_len - 1] ^= 1,
                    4 => row.operation += 1,
                    5 => {
                        row.response.copy_from_slice(&first[0].response);
                        row.response_len = first[0].response_len;
                    }
                    6 if protected => row.binding = None,
                    7 if protected => row.binding = first[0].binding.take(),
                    8 => row.response[2] ^= 1, // MID is checked even though it is not OSCORE AAD.
                    _ => continue,
                }
                assert!(
                    row.verify(&mut context, &mut [0; WIRE]).is_err(),
                    "fault {fault}"
                );
            }
        }
    }

    #[test]
    fn batch_refusal_recovery_and_io_guards() {
        let (mut app, mut context) = fixture(false);
        let mut row = BatchRow::empty();
        row.prepare(0, &mut context).unwrap();
        assert!(row.prepare(1, &mut context).is_err());
        let valid_len = row.request_len;
        row.request_len = CAPTURE_BYTES + 1;
        assert!(batch_drive(&mut app, std::slice::from_mut(&mut row), Instant::now()).is_err());
        assert!(app.transport().input_len.is_none());
        row.request_len = valid_len;
        assert!(
            app.transport_mut()
                .send(Endpoint::v4([127, 0, 0, 2], 30000), b"x")
                .is_err()
        );
        assert!(app.transport_mut().send(PEER, &[0; WIRE + 1]).is_err());
        app.transport_mut().output_len = Some(1);
        assert!(batch_drive(&mut app, std::slice::from_mut(&mut row), Instant::now()).is_err());
        app.transport_mut().output_len = None;
        batch_drive(&mut app, std::slice::from_mut(&mut row), Instant::now()).unwrap();
        row.verify(&mut context, &mut [0; WIRE]).unwrap();
        row.prepare(1, &mut context).unwrap(); // Row refusal did not consume a MID or context.
        batch_drive(&mut app, std::slice::from_mut(&mut row), Instant::now()).unwrap();
        row.verify(&mut context, &mut [0; WIRE]).unwrap();
        row.prepare(2, &mut context).unwrap();
        row.request_len = 1; // Real App poll parses malformed input; no response is success.
        assert!(batch_drive(&mut app, std::slice::from_mut(&mut row), Instant::now()).is_err());
    }

    #[test]
    fn batch_server_replay_and_monotonic_progress_survive_batches() {
        let (mut app, mut context) = fixture(true);
        let clock = Instant::now();
        let mut row = BatchRow::empty();
        row.prepare(0, &mut context).unwrap();
        let original = row.request;
        let len = row.request_len;
        batch_drive(&mut app, std::slice::from_mut(&mut row), clock).unwrap();
        row.verify(&mut context, &mut [0; WIRE]).unwrap();
        let checkpoint = app.oscore().unwrap().replay_checkpoint();
        let expiring = coaptic::storage::DedupKey::new(MessageId::new(65000), PEER);
        app.engine_mut()
            .insert_dedup(
                coaptic::storage::DedupEntry::new(MessageId::new(65000), PEER).with_due_ms(1),
            )
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        row.prepare(1, &mut context).unwrap();
        assert!(app.engine_mut().lookup_dedup(expiring).is_some());
        batch_drive(&mut app, std::slice::from_mut(&mut row), clock).unwrap();
        assert!(app.engine_mut().lookup_dedup(expiring).is_none());
        row.verify(&mut context, &mut [0; WIRE]).unwrap();
        checkpoint
            .validate_successor(app.oscore().unwrap().replay_checkpoint())
            .unwrap();
        assert!(clock.elapsed().as_millis() >= 2);
        // Same PIV under a new MID bypasses the dedup hit and must be dropped.
        row.request = original;
        row.request[2..4].copy_from_slice(&2u16.to_be_bytes());
        row.request_len = len;
        assert!(batch_drive(&mut app, std::slice::from_mut(&mut row), clock).is_err());
        assert!(!app.oscore().unwrap().replay_fresh(0));
    }

    #[test]
    fn batch_gate_order_eof_and_fixed_bounds() {
        for raw in [&b""[..], &b"run"[..], &b"no!\n"[..]] {
            let mut input = raw;
            assert!(batch_gate(&mut input, b"run\n").is_err());
        }
        assert!(batch_gate(&mut &b"run\n"[..], b"run\n").is_ok());
        assert!(batch_gate(&mut &b""[..], b"oversize").is_err());
        assert_eq!(2 * BATCH_OPS * CAPTURE_BYTES, 25_600_000);
        assert_eq!(WIRE, 1472);
        assert_eq!(BATCH_OPS * WORK_BATCHES, 50_000);
        let mut context = None;
        let mut row = BatchRow::empty();
        assert!(row.prepare(65_536, &mut context).is_err());
        assert!(row.prepare(65_535, &mut context).is_ok());
        assert_eq!(EMPTY_GATES, 16);
    }
    #[test]
    fn service_cli_exact_modes_and_send_admission() {
        for flag in ["--service-fixed", "--service-allocated"] {
            for (payload, max) in [(64, 29872), (1024, 29872), (16384, 1747)] {
                for security in ["unprotected", "oscore"] {
                    let args: Vec<String> = [
                        "bench-core",
                        &max.to_string(),
                        security,
                        flag,
                        &payload.to_string(),
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect();
                    assert_eq!(
                        parse_args(&args).unwrap().mode,
                        ProbeMode::Service {
                            allocated: flag == "--service-allocated",
                            payload,
                        }
                    );
                }
                assert!(service_admission(max + 1, payload).is_err());
                assert!(service_admission(0, payload).is_err());
            }
        }
        for raw in [
            "1 oscore --service-fixed",
            "1 --service-fixed 16384",
            "1 oscore --service-fixed 32",
            "1 oscore --service-fixed 16385",
            "1 oscore --service-fixed --small-device",
            "1 oscore --small-device 16384",
            "1 oscore --service-fixed 16384 extra",
            "1 oscore --service-fixed --service-allocated 16384",
        ] {
            let mut args = vec!["bench-core".into()];
            args.extend(raw.split_whitespace().map(str::to_owned));
            assert!(parse_args(&args).is_err(), "{raw}");
        }
    }

    fn service_alloc_fixture(
        context: Option<coaptic::oscore::SecurityContext>,
        payload: usize,
    ) -> ServiceServer<coaptic::storage::AllocMemory> {
        let resources = coaptic::resources::Service::new();
        let heap = coaptic::storage::AllocMemory::<Token>::required_heap_bytes(
            resources.pool_capacities(),
        )
        .unwrap();
        service_builder!(resources.allocated(heap), context, payload)
            .bind(service_io())
            .unwrap()
    }

    fn service_reuse<S: AppStorage<Token = Token>>(
        server: &mut ServiceServer<S>,
        protected: bool,
        payload: usize,
    ) {
        let (context, _) = contexts(protected);
        let mut client = service_client(context).unwrap();
        let server_caps = server.engine().capacities();
        let client_caps = client.engine().capacities();
        assert_eq!(
            server_caps,
            coaptic::resources::Service::new().pool_capacities()
        );
        assert_eq!(client_caps, service_client_capacities());
        let mut output = vec![0; 16384];
        let capacity = output.capacity();
        let clock = Instant::now();
        ALLOCATIONS.with(|count| count.set(Some(0)));
        let guard = Counting;
        for _ in 0..4 {
            let (_, polls) =
                service_step(server, &mut client, payload, clock, &mut output).unwrap();
            assert_eq!(polls, payload.div_ceil(1024) as u32);
        }
        let allocations = ALLOCATIONS.with(Cell::get).unwrap();
        drop(guard);
        assert_eq!(allocations, 0);
        assert_eq!(output.capacity(), capacity);
        assert_eq!(server.engine().capacities(), server_caps);
        assert_eq!(client.engine().capacities(), client_caps);
        assert_eq!(client.transport().sent, 4 * payload.div_ceil(1024) as u32);
        assert_eq!(server.transport().sent, client.transport().sent);
        if protected {
            assert_eq!(
                client.oscore().unwrap().sender_seq(),
                u64::from(client.transport().sent)
            );
            assert!(!server.oscore().unwrap().replay_fresh(0));
        }
    }

    // Isolate the fixed construction on the normal test-thread stack, too.
    #[inline(never)]
    fn service_fixed_reuse(protected: bool, payload: usize) {
        let (_, context) = contexts(protected);
        let mut app = service_builder!(coaptic::resources::Service::new(), context, payload)
            .bind(service_io())
            .unwrap();
        service_reuse(&mut app, protected, payload);
    }
    #[test]
    fn service_both_storage_security_all_payloads_full_without_growth() {
        for protected in [false, true] {
            for payload in [64, 1024, 16384] {
                service_fixed_reuse(protected, payload);
                let (_, context) = contexts(protected);
                service_reuse(
                    &mut service_alloc_fixture(context, payload),
                    protected,
                    payload,
                );
            }
        }
    }

    #[test]
    fn service_first_fragment_is_not_completion_and_small_output_retains_reply() {
        for protected in [false, true] {
            let (client_context, server_context) = contexts(protected);
            let mut server = service_alloc_fixture(server_context, 16384);
            let mut client = service_client(client_context).unwrap();
            let clock = Instant::now();
            let mut pending = service_begin(&mut client, 16384, clock).unwrap();
            let mut short = [0xa5; 1024];
            let mut last_mid = pending.first_mid;
            for round in 0..16 {
                last_mid = service_wire(client.transport()).unwrap().message_id();
                service_turn(&mut server, &mut client, &mut pending, clock).unwrap();
                let outcome = client.take_response_into(pending.call, &mut short);
                if round < 15 {
                    assert!(matches!(outcome, Ok(None)));
                } else {
                    assert!(matches!(
                        outcome,
                        Err(coaptic::app::ResponseBufferError::TooSmall {
                            required: 16384,
                            available: 1024
                        })
                    ));
                }
            }
            assert!(short.iter().all(|&byte| byte == 0xa5));
            assert_ne!(last_mid, pending.first_mid);
            assert!(!client.cancel(pending.call)); // Terminal cancellation does not consume.
            let mut output = vec![0; 16384];
            {
                let reply = client
                    .take_response_into(pending.call, &mut output)
                    .unwrap()
                    .unwrap()
                    .unwrap();
                service_verify(&reply, &pending, 16384).unwrap();
                assert_eq!(reply.message_id(), Some(pending.first_mid));
                assert_eq!(reply.body().unwrap(), &SERVICE_BODY);
                let first_block = reply
                    .received_options()
                    .find(|opt| opt.number() == coaptic::message::OptionNumber::BLOCK2)
                    .unwrap();
                let first_block = coaptic::message::decode_block(first_block.value()).unwrap();
                assert_eq!(first_block.num(), 0);
                assert!(first_block.more());
                let wrong = ServicePending {
                    first_mid: last_mid,
                    ..pending
                };
                assert!(service_verify(&reply, &wrong, 16384).is_err());
            }
            assert!(
                client
                    .take_response_into(pending.call, &mut output)
                    .unwrap()
                    .is_none()
            );
            // Subsequent operation reuses consumed Call/body/binding ownership.
            service_step(&mut server, &mut client, 16384, clock, &mut output).unwrap();
        }
    }

    #[test]
    fn service_port_deadline_round_and_wire_guards() {
        let mut source = service_io();
        let mut dest = service_io();
        assert!(service_bridge(&mut source, &mut dest).is_err());
        assert!(source.send(PEER, &[0; WIRE + 1]).is_err());
        assert!(source.send(Endpoint::v4([1, 2, 3, 4], 3), b"x").is_err());
        assert_eq!(source.sent, 0);
        source.sent = SERVICE_SEND_LIMIT - 1;
        source.send(PEER, b"x").unwrap();
        assert_eq!(source.sent, SERVICE_SEND_LIMIT);
        assert!(source.send(PEER, b"x").is_err());
        dest.io.input_len = Some(1);
        assert!(service_bridge(&mut source, &mut dest).is_err());
        assert_eq!(source.io.output_len, Some(1)); // Refusal retains source.
        dest.io.input_len = None;
        service_bridge(&mut source, &mut dest).unwrap();
        assert!(source.io.output_len.is_none());
        assert!(service_deadline(Instant::now() - SERVICE_TIMEOUT).is_err());

        let (mut app, _) = fixture(false);
        // Real wire header validator rejects ACK type, MID and Token independently.
        let mid = MessageId::new(7);
        let token = Token::new(b"t").unwrap();
        for fault in 0..4 {
            let mut port = service_io();
            let msg = Message::new(
                if fault == 1 {
                    Type::NonConfirmable
                } else {
                    Type::Acknowledgement
                },
                Code::CONTENT,
                if fault == 2 { MessageId::new(8) } else { mid },
            )
            .with_token(if fault == 3 {
                Token::new(b"wrong").unwrap()
            } else {
                token
            });
            port.io.output_len = Some(msg.encode(&mut port.io.output).unwrap());
            assert_eq!(service_ack(&port, mid, token).is_ok(), fault == 0);
        }
        // Keep the old transport's occupied-output guard independently exercised.
        app.transport_mut().send(PEER, b"x").unwrap();
        assert!(app.transport_mut().send(PEER, b"y").is_err());
        for exhausted in [false, true] {
            let mut server = service_alloc_fixture(None, 16384);
            let mut client = service_client(None).unwrap();
            let clock = Instant::now();
            let mut pending = service_begin(&mut client, 16384, clock).unwrap();
            if exhausted {
                pending.polls = SERVICE_ROUNDS;
            } else {
                pending.started = Instant::now() - SERVICE_TIMEOUT;
            }
            assert!(service_turn(&mut server, &mut client, &mut pending, clock).is_err());
            assert!(client.cancel(pending.call));
            assert!(matches!(
                client.take_response(pending.call),
                Some(Err(coaptic::app::CallFailure::Cancelled))
            ));
        }
    }

    #[test]
    fn service_bad_metadata_body_auth_and_missing_blocks_refuse_then_cancel() {
        for protected in [false, true] {
            // Changes are made to actual server output, never to a cloned context.
            for fault in 0..8 {
                let (client_context, server_context) = contexts(protected);
                let mut server = service_alloc_fixture(server_context, 16384);
                let mut client = service_client(client_context).unwrap();
                let clock = Instant::now();
                let mut pending = service_begin(&mut client, 16384, clock).unwrap();
                let mut failed = false;
                let mut output = vec![0; 16384];
                for round in 0..16 {
                    let mid = service_wire(client.transport()).unwrap().message_id();
                    service_bridge(client.transport_mut(), server.transport_mut()).unwrap();
                    server.poll(clock.elapsed().as_millis() as u64).unwrap();
                    let io = &mut server.transport_mut().io;
                    let n = io.output_len.unwrap();
                    // Missing middle/final, short wire, changed last body/tag byte,
                    // changed ETag/format, and changed wire MID.
                    if (fault == 0 && round == 7) || (fault == 1 && round == 15) {
                        io.output_len = None;
                    } else if round == 0 {
                        match fault {
                            2 => io.output_len = Some(n - 1),
                            3 => io.output[n - 1] ^= 1,
                            4 | 5 if !protected => {
                                let needle: &[u8] =
                                    if fault == 4 { b"fixture" } else { &[0x81, 42] };
                                let pos = io.output[..n]
                                    .windows(needle.len())
                                    .position(|w| w == needle)
                                    .unwrap();
                                io.output[pos + needle.len() - 1] ^= 1;
                            }
                            4 | 5 => io.output[n - 2] ^= 1,
                            6 => io.output[2] ^= 1,
                            7 => {
                                let start = n - decode(&io.output[..n]).unwrap().payload().len();
                                io.output.swap(start, start + 1);
                            }
                            _ => {}
                        }
                    }
                    if service_ack(server.transport(), mid, pending.call.token()).is_err()
                        || service_bridge(server.transport_mut(), client.transport_mut()).is_err()
                        || client.poll(clock.elapsed().as_millis() as u64).is_err()
                    {
                        failed = true;
                        break;
                    }
                    match client.take_response_into(pending.call, &mut output) {
                        Ok(Some(Ok(reply))) => {
                            pending.polls = round + 1;
                            assert!(service_verify(&reply, &pending, 16384).is_err());
                            failed = true;
                            break;
                        }
                        Ok(Some(Err(_))) | Err(_) => {
                            failed = true;
                            break;
                        }
                        Ok(None) => {
                            if client.transport().io.output_len.is_none() {
                                failed = true;
                                break;
                            }
                        }
                    }
                }
                assert!(failed, "fault {fault}, protected {protected}");
                client.cancel(pending.call);
                let _ = client.take_response(pending.call); // Drain cancelled/terminal ownership.
                assert!(client.take_response(pending.call).is_none());
            }
        }
    }
    #[test]
    fn service_active_cancel_drains_then_fresh_call_reuses_without_nonce_reset() {
        for protected in [false, true] {
            let (cc, sc) = contexts(protected);
            let mut server = service_alloc_fixture(sc, 16384);
            let mut client = service_client(cc).unwrap();
            let clock = Instant::now();
            let pending = service_begin(&mut client, 16384, clock).unwrap();
            let old_mid = pending.first_mid;
            let old_token = pending.call.token();
            assert!(client.cancel(pending.call));
            assert!(matches!(
                client.take_response(pending.call),
                Some(Err(coaptic::app::CallFailure::Cancelled))
            ));
            assert!(client.take_response(pending.call).is_none());
            // This already-sent, undelivered fixture datagram is deliberately
            // discarded after cancellation. Do not reset its send count or nonce.
            client.transport_mut().io.output_len = None;
            let mut output = vec![0; 16384];
            let pending = service_begin(&mut client, 16384, clock).unwrap();
            assert_ne!(pending.first_mid, old_mid);
            assert_ne!(pending.call.token(), old_token);
            assert!(client.cancel(pending.call));
            let _ = client.take_response(pending.call);
            client.transport_mut().io.output_len = None;
            service_step(&mut server, &mut client, 16384, clock, &mut output).unwrap();
            if protected {
                assert_eq!(client.oscore().unwrap().sender_seq(), 18);
                assert!(!server.oscore().unwrap().replay_fresh(2));
            }
            let mut port = service_io();
            port.send(PEER, b"x").unwrap();
            assert!(port.send(PEER, b"y").is_err());
            assert_eq!(port.sent, 1);
        }
    }
}
