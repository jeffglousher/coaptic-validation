//! Complete-operation diagnostic using Coaptic at both ends, not an independent
//! interoperability peer or a replacement for the matched external driver.
//! Loopback only; bounded allocations happen before timing. Spin consumes CPU,
//! while sleep1 deliberately demonstrates a caller-imposed per-poll delay.
//! Optional absolute-deadline pacing never drops operations to catch up. The
//! paced dispatch schedules default to two minutes; explicit --long-window
//! permits at most 1500 seconds with the same complete-operation deadline.
//! A conservative 60,000
//! outbound-datagram budget includes warmup and measurement on this fresh socket;
//! it avoids scheduling a campaign that reaches the core's safe Message ID
//! lifetime refusal. This diagnostic budget is not a product capacity. Every
//! completed latency is retained. CPU-gated campaigns stop before report
//! formatting so an external process can sample CPU first.
#![forbid(unsafe_code)]
#[path = "../client_endpoint_udp.rs"]
mod endpoint_udp;
use coaptic::{
    App, Call, Code, ContentFormat, Response,
    oscore::{DeriveParams, SecurityContext},
    storage::{AllocMemory, Capacities, DatagramIo, Endpoint, UdpSocketIo},
};
use endpoint_udp::EndpointIo;
use std::{
    io::{Read, Write},
    net::UdpSocket,
    time::{Duration, Instant},
};

struct CountIo {
    io: UdpSocketIo<[u8; 1473]>,
    received: u64,
    sent: u64,
}
impl coaptic::storage::DatagramTransport for CountIo {
    type Error = std::io::Error;
}
impl DatagramIo for CountIo {
    fn recv(&mut self, bytes: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        let result = self.io.recv(bytes)?;
        self.received += u64::from(result.is_some());
        Ok(result)
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        if self.sent >= MAX_OUTBOUND_DATAGRAMS as u64 {
            return Err(std::io::Error::other(
                "diagnostic fresh-socket outbound datagram budget exhausted",
            ));
        }
        let n = self.io.send(peer, bytes)?;
        self.sent += 1;
        Ok(n)
    }
}
type Client<T = CountIo> = App<coaptic::profiles::Default, T, 1, true, AllocMemory>;

trait ClientIo: DatagramIo {
    fn lane_counts(&self) -> ([u64; 4], [u64; 4]) {
        ([0; 4], [0; 4])
    }
    fn counts(&self) -> (u64, u64);
    fn peers(&self, server: Endpoint) -> [Endpoint; 4];
    fn endpoint_report(&self, _: ([u64; 4], [u64; 4])) -> String {
        String::new()
    }
}
impl ClientIo for CountIo {
    fn counts(&self) -> (u64, u64) {
        (self.received, self.sent)
    }
    fn peers(&self, server: Endpoint) -> [Endpoint; 4] {
        [server; 4]
    }
}
impl ClientIo for EndpointIo {
    fn counts(&self) -> (u64, u64) {
        (self.received, self.sent)
    }
    fn peers(&self, _: Endpoint) -> [Endpoint; 4] {
        self.peers()
    }
    fn lane_counts(&self) -> ([u64; 4], [u64; 4]) {
        self.lane_counts()
    }
    fn endpoint_report(&self, before: ([u64; 4], [u64; 4])) -> String {
        self.report(before)
    }
}

struct Peers([Endpoint; 4]);
impl From<Endpoint> for Peers {
    fn from(peer: Endpoint) -> Self {
        Self([peer; 4])
    }
}
impl From<[Endpoint; 4]> for Peers {
    fn from(peers: [Endpoint; 4]) -> Self {
        Self(peers)
    }
}

const MAX_OPERATIONS: usize = 60_000;
const MAX_RATE: u32 = 1_000_000;
const MAX_PACED_SECONDS: u64 = 120;
const LONG_PACED_SECONDS: u64 = 1500;
const MAX_OUTBOUND_DATAGRAMS: usize = 60_000;
const MAX_CONCURRENCY: usize = 4;

fn client_capacities(size: usize, concurrency: usize) -> Capacities {
    Capacities {
        rx_datagram_slots: 4,
        rx_datagram_bytes: 1472,
        tx_datagram_slots: 4,
        tx_datagram_bytes: 1472,
        dedup_entries: 8,
        observe_entries: 4,
        rx_body_slots: Some(concurrency),
        rx_body_bytes: Some(size.div_ceil(1024) * 1024),
        tx_body_slots: Some(1),
        // GET has no request body; response length does not size TX storage.
        tx_body_bytes: Some(1024),
    }
}

fn outbound_budget(size: usize, operations: usize, warmup: usize) -> Result<usize, &'static str> {
    let exchanges = operations
        .checked_add(warmup)
        .ok_or("diagnostic outbound budget overflow")?;
    let datagrams = exchanges
        .checked_mul(size.div_ceil(1024))
        .ok_or("diagnostic outbound budget overflow")?;
    if datagrams > MAX_OUTBOUND_DATAGRAMS {
        return Err("diagnostic warmup plus measured outbound datagram budget exceeds 60000");
    }
    Ok(datagrams)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum GateMode {
    #[default]
    None,
    Basic,
    Cpu,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum MessageType {
    #[default]
    Con,
    Non,
}
impl MessageType {
    fn name(self) -> &'static str {
        match self {
            Self::Con => "con",
            Self::Non => "non",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RunOptions {
    gate: GateMode,
    rate: Option<u32>,
    concurrency: usize,
    message_type: MessageType,
    admission_diagnostics: bool,
    independent_endpoints: bool,
    long_window: bool,
}
impl Default for RunOptions {
    fn default() -> Self {
        Self {
            gate: GateMode::None,
            rate: None,
            concurrency: 1,
            message_type: MessageType::Con,
            admission_diagnostics: false,
            independent_endpoints: false,
            long_window: false,
        }
    }
}

fn run_options(args: &mut Vec<String>) -> Result<RunOptions, &'static str> {
    let mut options = RunOptions::default();
    let mut concurrency_seen = false;
    let mut message_type_seen = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--long-window" => {
                if options.long_window {
                    return Err("duplicate long window");
                }
                options.long_window = true;
                args.remove(index);
            }
            "--independent-endpoints" => {
                if options.independent_endpoints {
                    return Err("duplicate independent endpoints");
                }
                options.independent_endpoints = true;
                args.remove(index);
            }
            "--admission-diagnostics" => {
                if options.admission_diagnostics {
                    return Err("duplicate admission diagnostics");
                }
                options.admission_diagnostics = true;
                args.remove(index);
            }
            "--gated" | "--cpu-gated" => {
                if options.gate != GateMode::None {
                    return Err("select only one measurement gate");
                }
                options.gate = if args[index] == "--cpu-gated" {
                    GateMode::Cpu
                } else {
                    GateMode::Basic
                };
                args.remove(index);
            }
            "--rate" => {
                if options.rate.is_some() {
                    return Err("duplicate pacing rate");
                }
                let rate = args
                    .get(index + 1)
                    .ok_or("missing pacing rate")?
                    .parse::<u32>()
                    .map_err(|_| "invalid pacing rate")?;
                if !(1..=MAX_RATE).contains(&rate) {
                    return Err("pacing rate bounds");
                }
                options.rate = Some(rate);
                args.drain(index..=index + 1);
            }
            "--concurrency" => {
                if concurrency_seen {
                    return Err("duplicate concurrency");
                }
                concurrency_seen = true;
                options.concurrency = args
                    .get(index + 1)
                    .ok_or("missing concurrency")?
                    .parse()
                    .map_err(|_| "invalid concurrency")?;
                if !(1..=MAX_CONCURRENCY).contains(&options.concurrency) {
                    return Err("concurrency bounds 1..4");
                }
                args.drain(index..=index + 1);
            }
            "--message-type" => {
                if message_type_seen {
                    return Err("duplicate message type");
                }
                message_type_seen = true;
                options.message_type = match args.get(index + 1).map(String::as_str) {
                    Some("con") => MessageType::Con,
                    Some("non") => MessageType::Non,
                    _ => return Err("explicit message type con|non"),
                };
                args.drain(index..=index + 1);
            }
            _ => index += 1,
        }
    }
    if options.concurrency > 1
        && options.message_type == MessageType::Con
        && !options.independent_endpoints
    {
        return Err(
            "concurrent CON refused: per-endpoint NSTART=1; explicitly select --message-type non",
        );
    }
    if options.independent_endpoints
        && (options.concurrency == 1 || options.message_type != MessageType::Con)
    {
        return Err("independent endpoints require C2..4 CON");
    }
    if options.admission_diagnostics && (options.rate.is_none() || options.concurrency != 1) {
        return Err("admission diagnostics require paced concurrency 1");
    }
    if options.long_window
        && (options.rate.is_none()
            || options.concurrency != 1
            || options.message_type != MessageType::Con
            || options.independent_endpoints
            || options.admission_diagnostics)
    {
        return Err(
            "long window requires paced C1 CON without diagnostics or independent endpoints",
        );
    }
    Ok(options)
}

fn paced_span_limit(options: &RunOptions) -> u64 {
    if options.long_window {
        LONG_PACED_SECONDS
    } else {
        MAX_PACED_SECONDS
    }
}

fn validate_schedule(options: &RunOptions, operations: usize) -> Result<(), &'static str> {
    if !(1..=MAX_OPERATIONS).contains(&operations) {
        return Err("diagnostic operation bounds");
    }
    if options.rate.is_some_and(|rate| {
        scheduled_offset(operations - 1, rate) > Duration::from_secs(paced_span_limit(options))
    }) {
        return Err("paced dispatch schedule exceeds selected limit");
    }
    Ok(())
}

fn scheduled_offset(index: usize, rate: u32) -> Duration {
    // CLI bounds limit this product to 10^15 ns and the admitted schedule to
    // two minutes. Deriving every deadline from the origin avoids sleep drift.
    Duration::from_nanos(index as u64 * 1_000_000_000 / u64::from(rate))
}

fn verify(reply: &Response<'_>, expected: &[u8]) -> Result<(), &'static str> {
    if reply.code() != Code::CONTENT
        || reply.format() != Some(ContentFormat::OCTET_STREAM)
        || reply.etag_bytes() != Some(&b"fixture"[..])
        || reply.payload_truncated()
        || reply.payload() != expected
    {
        return Err("complete representation/status/format/ETag mismatch");
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct PendingCall {
    call: Call,
    started: Instant,
    deadline: Instant,
}

#[derive(Default, Debug)]
struct AdmissionResidual {
    admissions: u64,
    positive: u64,
    crossed_missed: u64,
    total_ns: u128,
    max_ns: u128,
}

impl AdmissionResidual {
    fn record(&mut self, residual: Duration, crossed: bool) {
        self.admissions = self.admissions.saturating_add(1);
        self.positive = self.positive.saturating_add(u64::from(!residual.is_zero()));
        self.crossed_missed = self.crossed_missed.saturating_add(u64::from(crossed));
        let ns = residual.as_nanos();
        self.total_ns = self.total_ns.saturating_add(ns);
        self.max_ns = self.max_ns.max(ns);
    }

    fn json(&self) -> String {
        format!(
            "{{\"admissions\":{},\"positive\":{},\"crossed_missed\":{},\"total_ns\":{},\"max_ns\":{}}}",
            self.admissions, self.positive, self.crossed_missed, self.total_ns, self.max_ns
        )
    }
}

/// Local C1 intervals, not causal shares: C retains all earlier admission debt.
/// Admission uses the existing pre-send attempted/pacing boundary, including a
/// subsequent send refusal. Only fully verified, in-deadline replies advance C.
#[derive(Default, Debug)]
struct AdmissionDiagnostics {
    previous_completion: Option<Instant>,
    idle_sleep_traversed: bool,
    admissions: u64,
    first_admissions: u64,
    first_missed: u64,
    first_lateness_ns: u128,
    prior_forced_missed: u64,
    idle_sleep: AdmissionResidual,
    no_idle_sleep: AdmissionResidual,
}

impl AdmissionDiagnostics {
    fn completed(&mut self, completed: Instant) {
        self.previous_completion = Some(completed);
        self.idle_sleep_traversed = false;
    }

    fn record(&mut self, admission: Instant, scheduled: Instant, period: Duration) {
        self.admissions = self.admissions.saturating_add(1);
        let missed = admission.saturating_duration_since(scheduled) >= period;
        let Some(completed) = self.previous_completion else {
            self.first_admissions = self.first_admissions.saturating_add(1);
            self.first_missed = self.first_missed.saturating_add(u64::from(missed));
            self.first_lateness_ns = self
                .first_lateness_ns
                .saturating_add(admission.saturating_duration_since(scheduled).as_nanos());
            return;
        };
        let forced = completed.saturating_duration_since(scheduled) >= period;
        self.prior_forced_missed = self.prior_forced_missed.saturating_add(u64::from(forced));
        let residual = admission.saturating_duration_since(scheduled.max(completed));
        let bucket = if self.idle_sleep_traversed {
            &mut self.idle_sleep
        } else {
            &mut self.no_idle_sleep
        };
        bucket.record(residual, missed && !forced);
    }

    // Called only after measurement. No per-operation serialization/allocation.
    fn json(&self) -> String {
        format!(
            ",\"admission_diagnostics\":{{\"schema\":\"coaptic-admission-interval/1\",\"storage_bytes\":{},\"option_storage_bytes\":{},\"admissions\":{},\"first_admissions\":{},\"first_missed\":{},\"first_lateness_ns\":{},\"prior_forced_missed\":{},\"idle_sleep\":{},\"no_idle_sleep\":{}}}",
            std::mem::size_of::<Self>(),
            std::mem::size_of::<Option<Self>>(),
            self.admissions,
            self.first_admissions,
            self.first_missed,
            self.first_lateness_ns,
            self.prior_forced_missed,
            self.idle_sleep.json(),
            self.no_idle_sleep.json(),
        )
    }
}

#[derive(Default, Debug)]
struct Window {
    attempted: usize,
    cancelled_inflight: usize,
    failure: Option<&'static str>,
    pacing_late_operations: usize,
    pacing_missed_period_operations: usize,
    pacing_lateness_ns: u128,
    pacing_max_lateness_ns: u128,
    peak_pending: usize,
    overlapping_completions: [usize; MAX_CONCURRENCY],
    verified_completions: [usize; MAX_CONCURRENCY],
    admission_diagnostics: Option<AdmissionDiagnostics>,
}

// One App owns all Calls, security bindings and the sender sequence. No worker
// has a copied context. Only completed, verified replies enter the sample vector.
#[allow(clippy::too_many_arguments)]
fn run_window<T: DatagramIo>(
    client: &mut Client<T>,
    peers: impl Into<Peers>,
    clock: &Instant,
    timeout: Duration,
    sleep: bool,
    output: &mut [u8],
    expected: &[u8],
    options: &RunOptions,
    operations: usize,
    started: Instant,
    timings: &mut Vec<u64>,
) -> Window {
    let peers = peers.into().0;
    let mut window = Window {
        admission_diagnostics: options
            .admission_diagnostics
            .then(AdmissionDiagnostics::default),
        ..Window::default()
    };
    let mut pending: [Option<PendingCall>; MAX_CONCURRENCY] = [None; MAX_CONCURRENCY];
    let mut active = 0;
    while timings.len() < operations && window.failure.is_none() {
        // Poll/collect before refilling, so failures stop further admission.
        // Deadlines cover send, polls, complete assembly and verification.
        if active > 0 {
            if pending
                .iter()
                .flatten()
                .any(|p| Instant::now() >= p.deadline)
            {
                window.failure = Some("complete operation deadline");
                break;
            }
            if client.poll(clock.elapsed().as_millis() as u64).is_err() {
                window.failure = Some("poll");
                break;
            }
            for (lane, slot) in pending.iter_mut().enumerate() {
                let Some(p) = *slot else { continue };
                let outcome = client.take_response_into(p.call, output);
                let reply = match outcome {
                    Ok(None) => continue,
                    Ok(Some(Ok(reply))) => reply,
                    Ok(Some(Err(_))) => {
                        window.failure = Some("call");
                        break;
                    }
                    Err(_) => {
                        window.failure = Some("output");
                        break;
                    }
                };
                if let Err(error) = verify(&reply, expected) {
                    window.failure = Some(error);
                    break;
                }
                let completed = Instant::now();
                if completed >= p.deadline {
                    window.failure = Some("complete operation deadline");
                    break;
                }
                timings.push(completed.duration_since(p.started).as_nanos() as u64);
                if options.independent_endpoints {
                    window.overlapping_completions[lane] += usize::from(active > 1);
                    window.verified_completions[lane] += 1;
                }
                if let Some(diagnostic) = &mut window.admission_diagnostics {
                    diagnostic.completed(completed);
                }
                *slot = None;
                active -= 1;
            }
        }
        if window.failure.is_some() {
            break;
        }
        let mut admitted = false;
        while window.attempted < operations && active < options.concurrency {
            let index = window.attempted;
            let now = Instant::now();
            if pending.iter().flatten().any(|p| now >= p.deadline) {
                window.failure = Some("complete operation deadline");
                break;
            }
            if let Some(rate) = options.rate {
                let scheduled = started + scheduled_offset(index, rate);
                if now < scheduled {
                    break;
                }
                let lateness = now.duration_since(scheduled);
                let ns = lateness.as_nanos();
                window.pacing_late_operations += usize::from(!lateness.is_zero());
                window.pacing_missed_period_operations +=
                    usize::from(lateness >= scheduled_offset(1, rate));
                window.pacing_lateness_ns += ns;
                window.pacing_max_lateness_ns = window.pacing_max_lateness_ns.max(ns);
                if let Some(diagnostic) = &mut window.admission_diagnostics {
                    diagnostic.record(now, scheduled, scheduled_offset(1, rate));
                }
            }
            window.attempted += 1;
            // The pending row is the lane reservation. It is reused only after
            // terminal collection (which releases TX/body/security ownership).
            let lane = pending
                .iter()
                .position(Option::is_none)
                .expect("fixed Call slot");
            let request = client.get("bench").to(peers[lane]);
            let request = if options.message_type == MessageType::Non {
                request.non()
            } else {
                request
            };
            match request.send(clock.elapsed().as_millis() as u64) {
                Ok(call) => {
                    admitted = true;
                    pending[lane] = Some(PendingCall {
                        call,
                        started: now,
                        deadline: now + timeout,
                    });
                    active += 1;
                    window.peak_pending = window.peak_pending.max(active);
                }
                Err(_) => {
                    window.failure = Some("send");
                    break;
                }
            }
        }
        if window.failure.is_some() || timings.len() == operations {
            break;
        }
        if admitted {
            continue;
        }
        if active == 0 {
            // No Call needs service. Pacing can sleep until the absolute next
            // admission; while Calls are live, only the selected poll policy waits.
            if let Some(rate) = options.rate {
                if let Some(diagnostic) = &mut window.admission_diagnostics {
                    // Traversal includes sleep(Duration::ZERO); no extra clock.
                    diagnostic.idle_sleep_traversed = true;
                }
                std::thread::sleep(
                    (started + scheduled_offset(window.attempted, rate))
                        .saturating_duration_since(Instant::now()),
                );
            }
        } else if sleep {
            std::thread::sleep(Duration::from_millis(1));
        } else {
            std::hint::spin_loop();
        }
    }
    if window.failure.is_some() {
        // At most four local cancellations and four collections, without wire
        // traffic or waiting. Already terminal/unverified replies remain failed.
        for p in pending.into_iter().flatten() {
            window.cancelled_inflight += usize::from(client.cancel(p.call));
            // A terminal reply may itself have caused an output-buffer error.
            // Discard through the consuming API so a too-small caller buffer
            // cannot keep its packet/body/security binding held after failure.
            let _ = client.take_response(p.call);
        }
    }
    window
}

fn context(path: &str) -> Result<SecurityContext, Box<dyn std::error::Error>> {
    let mut material = [0; 24];
    let mut file = std::fs::File::open(path)?;
    file.read_exact(&mut material)?;
    if file.read(&mut [0])? != 0 {
        return Err("expected 24-byte ephemeral credentials".into());
    }
    let result = SecurityContext::derive(DeriveParams {
        master_secret: &material[..16],
        master_salt: &material[16..],
        sender_id: &[],
        recipient_id: &[1],
        id_context: &[],
    });
    material.fill(0);
    Ok(result?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<_> = std::env::args().collect();
    let options = run_options(&mut args)?;
    if options.independent_endpoints {
        let count = options.concurrency;
        run_client(&args, options, |port| {
            EndpointIo::new(
                std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port),
                count,
            )
        })
    } else {
        run_client(&args, options, |_| {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            socket.set_nonblocking(true)?;
            Ok(CountIo {
                io: UdpSocketIo::new(socket, [0; 1473])?,
                received: 0,
                sent: 0,
            })
        })
    }
}

fn run_client<T: ClientIo>(
    args: &[String],
    options: RunOptions,
    make_io: impl FnOnce(u16) -> std::io::Result<T>,
) -> Result<(), Box<dyn std::error::Error>> {
    let gated = options.gate != GateMode::None;
    if !(8..=9).contains(&args.len()) {
        return Err("usage: bench-native-client PORT BYTES OPERATIONS WARMUP TIMEOUT_MS spin|sleep1 unprotected|oscore [CREDENTIALS] [--gated|--cpu-gated] [--rate OPS_PER_SEC] [--concurrency 1..4] [--message-type con|non] [--admission-diagnostics] [--independent-endpoints] [--long-window]".into());
    }
    let port: u16 = args[1].parse()?;
    let size: usize = args[2].parse()?;
    let operations: usize = args[3].parse()?;
    let warmup: usize = args[4].parse()?;
    let timeout_ms: u64 = args[5].parse()?;
    if port == 0
        || !(1..=65536).contains(&size)
        || !(1..=MAX_OPERATIONS).contains(&operations)
        || warmup > 1000
        || !(1..=60000).contains(&timeout_ms)
    {
        return Err("diagnostic bounds".into());
    }
    // This is the minimum request count for the fixed 1024-byte Block2 fixture.
    // Retries or smaller negotiated blocks can spend more; CountIo refuses them
    // at the same total bound instead of silently dropping a scheduled Call.
    let minimum_planned_datagrams = outbound_budget(size, operations, warmup)?;
    validate_schedule(&options, operations)?;
    if options.long_window && (timeout_ms != 3000 || args[6] != "spin") {
        return Err(
            "long window requires unchanged 3000ms complete-operation deadline and spin policy"
                .into(),
        );
    }
    let scheduled_span = options
        .rate
        .map(|rate| scheduled_offset(operations - 1, rate));
    let sleep = match args[6].as_str() {
        "spin" => false,
        "sleep1" => true,
        _ => return Err("poll policy".into()),
    };
    let context = match (args[7].as_str(), args.get(8)) {
        ("unprotected", None) => None,
        ("oscore", Some(path)) => Some(context(path)?),
        _ => return Err("explicit security/credential selection".into()),
    };
    let io = make_io(port)?;
    let peers = io.peers(Endpoint::v4([127, 0, 0, 1], port));
    let builder = App::builder()
        .routes::<1>()
        .block_wise::<true>()
        .full_responses()
        .randomness(|b| getrandom::fill(b).is_ok());
    let builder = if let Some(context) = context {
        builder.oscore(context)
    } else {
        builder.allow_unprotected()
    };
    let mut capacities = client_capacities(size, options.concurrency);
    if options.independent_endpoints {
        capacities.rx_datagram_slots = 5;
        capacities.tx_datagram_slots = 5;
    }
    let heap_limit = AllocMemory::<coaptic::message::Token>::required_heap_bytes(capacities)?;
    let storage = AllocMemory::try_new(capacities, heap_limit)?;
    let mut client = builder.bind_storage(io, storage)?;
    let expected: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
    let mut output = vec![0; size];
    let mut timings = Vec::with_capacity(operations.max(warmup));
    let app_inline_bytes = std::mem::size_of_val(&client);
    let verification_heap_bytes = expected.capacity() + output.capacity();
    let timing_heap_bytes = timings.capacity() * std::mem::size_of::<u64>();
    let clock = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let warm_options = RunOptions {
        rate: None,
        admission_diagnostics: false,
        ..options
    };
    let warm = run_window(
        &mut client,
        peers,
        &clock,
        timeout,
        sleep,
        &mut output,
        &expected,
        &warm_options,
        warmup,
        Instant::now(),
        &mut timings,
    );
    if let Some(error) = warm.failure {
        return Err(error.into());
    }
    timings.clear();
    if gated {
        eprintln!("ready");
        gate("run")?;
    }
    let before = client.transport().counts();
    let lane_before = client.transport().lane_counts();
    let started = Instant::now();
    let window = run_window(
        &mut client,
        peers,
        &clock,
        timeout,
        sleep,
        &mut output,
        &expected,
        &options,
        operations,
        started,
        &mut timings,
    );
    let elapsed = started.elapsed().as_nanos();
    let received = client.transport().counts().0 - before.0;
    let sent = client.transport().counts().1 - before.1;
    let total_sent_datagrams = client.transport().counts().1;
    if options.gate == GateMode::Cpu {
        eprintln!("measured");
        gate("report")?;
    }
    let completed = timings.len();
    let attempted = window.attempted;
    let failed = attempted - completed;
    let unattempted = operations - attempted;
    let achieved_rate = completed as f64 * 1_000_000_000.0 / elapsed as f64;
    let rate_json = options
        .rate
        .map_or_else(|| "null".to_owned(), |r| r.to_string());
    let span_json = scheduled_span.map_or_else(|| "null".to_owned(), |s| s.as_nanos().to_string());
    // All possible campaign errors are fixed ASCII strings, not peer input.
    let failure_json = window
        .failure
        .map_or_else(|| "null".to_owned(), |e| format!("{e:?}"));
    let Window {
        pacing_late_operations,
        pacing_missed_period_operations,
        pacing_lateness_ns,
        pacing_max_lateness_ns,
        peak_pending,
        cancelled_inflight,
        ..
    } = window;
    let endpoint_json = client.transport().endpoint_report(lane_before);
    let overlap_json = if options.independent_endpoints {
        format!(
            ",\"overlapping_completions\":{:?},\"client_rx_slots\":5,\"client_tx_slots\":5,\"verified_completions\":{:?},\"window_metadata_bytes\":{},\"lane_counter_snapshot_bytes\":{},\"peer_keys_bytes\":{}",
            &window.overlapping_completions[..options.concurrency],
            &window.verified_completions[..options.concurrency],
            std::mem::size_of::<Window>(),
            std::mem::size_of_val(&lane_before),
            std::mem::size_of_val(&peers)
        )
    } else {
        String::new()
    };
    let concurrency = options.concurrency;
    let message_type = options.message_type.name();
    let pending_call_metadata_bytes = std::mem::size_of::<[Option<PendingCall>; MAX_CONCURRENCY]>();
    let rx_body_slots = capacities.rx_body_slots.unwrap();
    let admission_json = window
        .admission_diagnostics
        .as_ref()
        .map_or_else(String::new, AdmissionDiagnostics::json);
    let long_window = options.long_window;
    let paced_span_limit_seconds = paced_span_limit(&options);
    println!(
        "{{\"long_window\":{long_window},\"paced_span_limit_seconds\":{paced_span_limit_seconds},\"operation_deadline_ms\":{timeout_ms},\"outbound_datagram_limit\":{MAX_OUTBOUND_DATAGRAMS},\"minimum_planned_datagrams\":{minimum_planned_datagrams},\"schema\":\"coaptic-native-complete/1\",\"bytes\":{size},\"requested_operations\":{operations},\"attempted\":{attempted},\"completed\":{completed},\"failed\":{failed},\"unattempted\":{unattempted},\"failure\":{failure_json},\"concurrency\":{concurrency},\"message_type\":\"{message_type}\",\"peak_pending\":{peak_pending},\"cancelled_inflight\":{cancelled_inflight},\"pending_call_metadata_bytes\":{pending_call_metadata_bytes},\"rx_body_slots\":{rx_body_slots},\"total_sent_datagrams\":{total_sent_datagrams},\"warmup\":{warmup},\"elapsed_ns\":{elapsed},\"scheduled_rate_ops_per_second\":{rate_json},\"achieved_ops_per_second\":{achieved_rate},\"scheduled_dispatch_span_ns\":{span_json},\"pacing_late_operations\":{pacing_late_operations},\"pacing_missed_period_operations\":{pacing_missed_period_operations},\"pacing_total_lateness_ns\":{pacing_lateness_ns},\"pacing_max_lateness_ns\":{pacing_max_lateness_ns},\"pacing_dropped_operations\":0,\"pacing_semantics\":\"absolute operation-start deadlines; bounded outstanding Calls; late starts catch up without dropping; elapsed includes pacing; latencies exclude pacing\",\"received_datagrams\":{received},\"sent_datagrams\":{sent},\"latencies_ns\":{timings:?},\"core_heap_limit_bytes\":{heap_limit},\"app_inline_bytes\":{app_inline_bytes},\"verification_heap_bytes\":{verification_heap_bytes},\"timing_heap_bytes\":{timing_heap_bytes},\"udp_scratch_bytes\":1473,\"policy\":\"{}\",\"security\":\"{}\",\"measurement\":\"Coaptic client/server diagnostic; complete authenticated body verification; setup excluded; no durable recovery; heap request excludes allocator overhead; App inline includes UDP scratch\"{admission_json}{endpoint_json}{overlap_json}}}",
        args[6], args[7]
    );
    std::io::stdout().flush()?;
    if gated {
        // Keep process handles live for post-window CPU/RSS sampling. This wait
        // is outside operation and campaign timing, and makes no network calls.
        gate("exit")?;
    }
    if let Some(error) = window.failure {
        return Err(error.into());
    }
    Ok(())
}

fn gate(expected: &str) -> Result<(), Box<dyn std::error::Error>> {
    read_gate(std::io::stdin().lock(), expected)
}

fn read_gate(mut input: impl Read, expected: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0; 8];
    for index in 0..bytes.len() {
        input.read_exact(&mut bytes[index..=index])?;
        if bytes[index] == b'\n' {
            let line = &bytes[..index];
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line == expected.as_bytes() {
                return Ok(());
            }
            return Err("measurement gate".into());
        }
    }
    Err("measurement gate bound".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coaptic::message::{Message, MessageId, Opt, Token, Type, decode, encode};

    const PEER: Endpoint = Endpoint::v4([127, 0, 0, 1], 5683);
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Fault {
        None,
        CorruptBody,
        CorruptLater,
        WrongKey,
        WrongToken,
        Timeout,
        SendRefusal,
    }

    // A tiny response fixture for the production admission/collection loop.
    // It holds the first batch, returns it in reverse order and optionally
    // faults its first delivered reply. Protocol/auth matching stays in App.
    struct Replies {
        queued: Vec<Vec<u8>>,
        sent: Vec<Token>,
        returned: Vec<Token>,
        first_batch: usize,
        fault: Fault,
        server: Option<SecurityContext>,
        wrong_key: Option<SecurityContext>,
    }
    impl coaptic::storage::DatagramTransport for Replies {
        type Error = std::io::Error;
    }
    impl DatagramIo for Replies {
        fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
            let request = decode(bytes).unwrap();
            assert_eq!(request.ty(), Type::NonConfirmable);
            self.sent.push(request.token());
            let number = self.sent.len();
            if self.fault == Fault::SendRefusal && number == self.first_batch {
                return Err(std::io::Error::other("fixture send refusal"));
            }
            let mut scratch = [0; 1472];
            let reference = self
                .server
                .as_mut()
                .map(|ctx| ctx.unprotect_request(&request, &mut scratch).unwrap().1);
            let mut body: [u8; 64] = std::array::from_fn(|i| (i % 251) as u8);
            if (self.fault == Fault::CorruptBody && number == self.first_batch)
                || (self.fault == Fault::CorruptLater && number == 2)
            {
                body[63] ^= 1;
            }
            let format = coaptic::message::encode_uint(42);
            let options = [Opt::etag(b"fixture"), Opt::content_format(&format)];
            let token = if self.fault == Fault::WrongToken {
                Token::new(&[255]).unwrap()
            } else {
                request.token()
            };
            let reply = Message::new(
                Type::NonConfirmable,
                Code::CONTENT,
                MessageId::new(number as u16 + 100),
            )
            .with_token(token)
            .with_options(&options)
            .with_payload(&body);
            let mut wire = [0; 1472];
            let n = if let Some(reference) = reference {
                self.wrong_key
                    .as_ref()
                    .or(self.server.as_ref())
                    .unwrap()
                    .protect_response(&reply, reference, &mut wire)
                    .unwrap()
            } else {
                encode(&reply, &mut wire).unwrap()
            };
            self.queued.push(wire[..n].to_vec());
            Ok(bytes.len())
        }
        fn recv(&mut self, bytes: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
            if self.sent.len() < self.first_batch || self.fault == Fault::Timeout {
                return Ok(None);
            }
            let Some(reply) = self.queued.pop() else {
                return Ok(None);
            };
            if self.returned.is_empty() {
                // Ensure a real interval shared by the first admitted batch.
                std::thread::sleep(Duration::from_millis(2));
            }
            self.returned.push(decode(&reply).unwrap().token());
            bytes[..reply.len()].copy_from_slice(&reply);
            Ok(Some((reply.len(), PEER)))
        }
    }
    fn test_context(server: bool, wrong: bool) -> SecurityContext {
        SecurityContext::derive(DeriveParams {
            master_secret: if wrong { &[9; 16] } else { &[1; 16] },
            master_salt: &[2; 8],
            sender_id: if server { &[1] } else { &[] },
            recipient_id: if server { &[] } else { &[1] },
            id_context: &[],
        })
        .unwrap()
    }
    fn scripted_client(concurrency: usize, protected: bool, fault: Fault) -> Client<Replies> {
        let builder = App::builder()
            .routes::<1>()
            .block_wise::<true>()
            .full_responses()
            .randomness(|b| getrandom::fill(b).is_ok());
        let builder = if protected {
            builder.oscore(test_context(false, false))
        } else {
            builder.allow_unprotected()
        };
        builder
            .bind_alloc(
                Replies {
                    queued: Vec::new(),
                    sent: Vec::new(),
                    returned: Vec::new(),
                    first_batch: concurrency,
                    fault,
                    server: protected.then(|| test_context(true, false)),
                    wrong_key: (fault == Fault::WrongKey).then(|| test_context(true, true)),
                },
                client_capacities(64, concurrency),
            )
            .unwrap()
    }
    fn scripted_window(
        client: &mut Client<Replies>,
        concurrency: usize,
        operations: usize,
    ) -> (Window, Vec<u64>) {
        let clock = Instant::now();
        let mut timings = Vec::with_capacity(operations);
        let mut output = [0; 64];
        let expected: [u8; 64] = std::array::from_fn(|i| (i % 251) as u8);
        let window = run_window(
            client,
            PEER,
            &clock,
            Duration::from_millis(20),
            false,
            &mut output,
            &expected,
            &RunOptions {
                concurrency,
                message_type: MessageType::Non,
                ..RunOptions::default()
            },
            operations,
            clock,
            &mut timings,
        );
        (window, timings)
    }
    #[test]
    fn concurrent_matched_reordered_replies_share_one_context_and_sequence() {
        for protected in [false, true] {
            for concurrency in 1..=3 {
                let mut client = scripted_client(concurrency, protected, Fault::None);
                let (window, timings) = scripted_window(&mut client, concurrency, 8);
                assert_eq!(window.failure, None);
                assert_eq!(window.attempted, 8);
                assert_eq!(timings.len(), 8);
                assert_eq!(window.peak_pending, concurrency);
                let io = client.transport();
                // Refill can interleave newer replies before older ones; the
                // first reply proves that matching is not admission ordered.
                assert_eq!(io.returned[0], io.sent[concurrency - 1]);
                assert_eq!(
                    io.sent
                        .iter()
                        .collect::<std::collections::HashSet<_>>()
                        .len(),
                    8
                );
                if protected {
                    assert_eq!(client.oscore().unwrap().sender_seq(), 8);
                }
                assert_eq!(client.resource_usage().client_requests.occupied, 0);
                assert_eq!(client.resource_usage().client_replies.occupied, 0);
            }
        }
    }
    #[test]
    fn overlapping_latencies_exceed_elapsed_without_inventing_time_or_samples() {
        let mut client = scripted_client(3, true, Fault::None);
        let clock = Instant::now();
        let mut timings = Vec::with_capacity(3);
        let expected: [u8; 64] = std::array::from_fn(|i| (i % 251) as u8);
        let window = run_window(
            &mut client,
            PEER,
            &clock,
            Duration::from_millis(20),
            false,
            &mut [0; 64],
            &expected,
            &RunOptions {
                concurrency: 3,
                message_type: MessageType::Non,
                ..RunOptions::default()
            },
            3,
            clock,
            &mut timings,
        );
        let elapsed = clock.elapsed().as_nanos();
        assert_eq!(window.failure, None);
        assert_eq!(timings.len(), 3);
        let sum: u128 = timings.iter().map(|n| u128::from(*n)).sum();
        assert!(sum > elapsed);
        assert!(sum <= 3 * elapsed);
        assert!(timings.iter().all(|n| u128::from(*n) <= elapsed));
    }
    #[test]
    fn concurrent_faults_never_invent_completions_and_cancel_only_live_calls() {
        for protected in [false, true] {
            for fault in [
                Fault::CorruptBody,
                Fault::WrongToken,
                Fault::Timeout,
                Fault::SendRefusal,
                Fault::WrongKey,
            ] {
                if fault == Fault::WrongKey && !protected {
                    continue;
                }
                let mut client = scripted_client(3, protected, fault);
                let (window, timings) = scripted_window(&mut client, 3, 8);
                assert!(window.failure.is_some());
                assert_eq!(window.attempted, 3);
                assert!(timings.is_empty());
                assert_eq!(8 - window.attempted, 5); // Explicitly unattempted.
                assert_eq!(
                    window.cancelled_inflight,
                    if matches!(fault, Fault::CorruptBody | Fault::SendRefusal) {
                        2
                    } else {
                        3
                    }
                );
                assert_eq!(client.resource_usage().client_requests.occupied, 0);
                assert_eq!(client.resource_usage().client_replies.occupied, 0);
                // The same App recovers without resetting its OSCORE sender.
                client.transport_mut().fault = Fault::None;
                client.transport_mut().wrong_key = None;
                client.transport_mut().queued.clear();
                let sequence = client.oscore().map(SecurityContext::sender_seq);
                let (next, timings) = scripted_window(&mut client, 3, 3);
                assert_eq!(next.failure, None);
                assert_eq!(timings.len(), 3);
                if let Some(sequence) = sequence {
                    assert_eq!(client.oscore().unwrap().sender_seq(), sequence + 3);
                }
            }
        }
    }
    #[test]
    fn capacity_refusal_counts_the_failed_admission_and_reclaims_owned_calls() {
        for protected in [false, true] {
            let mut client = scripted_client(3, protected, Fault::Timeout);
            let other = client.get("bench").non().to(PEER).send(0).unwrap();
            let (window, timings) = scripted_window(&mut client, 3, 8);
            assert_eq!(window.failure, Some("send"));
            assert_eq!(window.attempted, 3);
            assert_eq!(window.cancelled_inflight, 2);
            assert!(timings.is_empty());
            assert_eq!(client.resource_usage().client_requests.occupied, 1);
            assert!(client.cancel(other));
            assert!(client.take_response(other).unwrap().is_err());
            assert_eq!(client.resource_usage().client_requests.occupied, 0);
        }
    }
    #[test]
    fn partial_verified_work_is_retained_when_later_reply_fails() {
        for protected in [false, true] {
            let mut client = scripted_client(3, protected, Fault::CorruptLater);
            let (window, timings) = scripted_window(&mut client, 3, 12);
            assert!(window.failure.is_some());
            assert_eq!(window.attempted, 12);
            assert_eq!(timings.len(), 10);
            assert_eq!(window.attempted - timings.len(), 2);
            assert_eq!(window.cancelled_inflight, 1);
            assert_eq!(client.resource_usage().client_requests.occupied, 0);
        }
    }
    #[test]
    fn output_refusal_reclaims_terminal_reply_and_cancels_other_inflight_calls() {
        let mut client = scripted_client(3, true, Fault::None);
        let clock = Instant::now();
        let mut timings = Vec::with_capacity(8);
        let window = run_window(
            &mut client,
            PEER,
            &clock,
            Duration::from_millis(20),
            false,
            &mut [0; 1],
            &[0; 64],
            &RunOptions {
                concurrency: 3,
                message_type: MessageType::Non,
                ..RunOptions::default()
            },
            8,
            clock,
            &mut timings,
        );
        assert_eq!(window.failure, Some("output"));
        assert_eq!(window.attempted, 3);
        assert_eq!(window.cancelled_inflight, 2);
        assert!(timings.is_empty());
        assert_eq!(client.resource_usage().client_requests.occupied, 0);
        assert_eq!(client.resource_usage().client_replies.occupied, 0);
    }
    #[test]
    fn concurrency_is_explicit_bounded_and_con_refuses_before_any_io() {
        assert_eq!(
            run_options(&mut args(&["client"])),
            Ok(RunOptions::default())
        );
        for concurrency in 1..=4 {
            let value = concurrency.to_string();
            let options = run_options(&mut args(&[
                "client",
                "--concurrency",
                &value,
                "--message-type",
                "non",
            ]))
            .unwrap();
            assert_eq!(options.concurrency, concurrency);
            assert_eq!(options.message_type, MessageType::Non);
        }
        for values in [
            vec!["client", "--concurrency", "2"],
            vec!["client", "--concurrency", "5", "--message-type", "non"],
            vec!["client", "--concurrency", "0"],
            vec!["client", "--concurrency", "1", "--concurrency", "1"],
            vec!["client", "--message-type", "con", "--message-type", "non"],
            vec!["client", "--message-type", "NON"],
        ] {
            assert!(run_options(&mut args(&values)).is_err());
        }
        assert_eq!(client_capacities(65536, 1).rx_body_slots, Some(1));
        assert_eq!(client_capacities(65536, 4).rx_body_slots, Some(4));
    }
    #[test]
    fn c4_burst_preserves_existing_rx_headroom_refusal_and_accounts_all_admissions() {
        for protected in [false, true] {
            let mut client = scripted_client(4, protected, Fault::None);
            let (window, timings) = scripted_window(&mut client, 4, 8);
            assert_eq!(window.failure, Some("send"));
            assert_eq!(window.peak_pending, 3);
            assert_eq!(window.attempted, 4);
            assert_eq!(window.cancelled_inflight, 3);
            assert!(timings.is_empty());
            assert_eq!(client.transport().sent.len(), 3);
            assert_eq!(client.resource_usage().client_requests.occupied, 0);
            assert_eq!(client.resource_usage().client_replies.occupied, 0);
        }
    }
    #[test]
    fn independent_endpoint_selector_requires_explicit_con_counts_and_preserves_legacy_caps() {
        for count in 2..=4 {
            let value = count.to_string();
            let selected = run_options(&mut args(&[
                "client",
                "--concurrency",
                &value,
                "--independent-endpoints",
            ]))
            .unwrap();
            assert!(selected.independent_endpoints);
            assert_eq!(selected.message_type, MessageType::Con);
        }
        for values in [
            vec!["client", "--independent-endpoints"],
            vec![
                "client",
                "--concurrency",
                "2",
                "--message-type",
                "non",
                "--independent-endpoints",
            ],
            vec![
                "client",
                "--concurrency",
                "2",
                "--independent-endpoints",
                "--independent-endpoints",
            ],
        ] {
            assert!(run_options(&mut args(&values)).is_err());
        }
        assert_eq!(client_capacities(64, 1).rx_datagram_slots, 4);
        assert_eq!(client_capacities(64, 1).tx_datagram_slots, 4);
    }

    #[test]
    fn outbound_admission_counts_warmup_blocks_and_checked_arithmetic() {
        assert_eq!(outbound_budget(64, 59_872, 128), Ok(60_000));
        assert!(outbound_budget(64, 59_873, 128).is_err());
        assert_eq!(outbound_budget(1024, 60_000, 0), Ok(60_000));
        assert_eq!(outbound_budget(1025, 30_000, 0), Ok(60_000));
        assert!(outbound_budget(1025, 30_001, 0).is_err());
        assert_eq!(outbound_budget(65536, 809, 128), Ok(59_968));
        assert!(outbound_budget(65536, 810, 128).is_err());
        assert!(outbound_budget(64, usize::MAX, 1).is_err());
        assert!(outbound_budget(usize::MAX, usize::MAX, 0).is_err());
    }
    #[test]
    fn outbound_runtime_budget_refuses_before_the_next_socket_send() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let peer = Endpoint::v4([127, 0, 0, 1], receiver.local_addr().unwrap().port());
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut io = CountIo {
            io: UdpSocketIo::new(socket, [0; 1473]).unwrap(),
            received: 0,
            sent: MAX_OUTBOUND_DATAGRAMS as u64 - 1,
        };
        assert_eq!(io.send(peer, b"last").unwrap(), 4);
        let mut bytes = [0; 4];
        assert_eq!(receiver.recv_from(&mut bytes).unwrap().0, 4);
        assert_eq!(&bytes, b"last");
        let error = io.send(peer, b"over").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(error.to_string().contains("diagnostic fresh-socket"));
        assert_eq!(io.sent, MAX_OUTBOUND_DATAGRAMS as u64);
        receiver.set_nonblocking(true).unwrap();
        assert_eq!(
            receiver.recv_from(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }
    #[test]
    fn long_window_is_explicit_bounded_and_keeps_operation_send_limits() {
        let normal = RunOptions {
            rate: Some(1),
            ..RunOptions::default()
        };
        assert_eq!(paced_span_limit(&normal), 120);
        assert!(validate_schedule(&normal, 121).is_ok());
        assert!(validate_schedule(&normal, 122).is_err());
        let long = RunOptions {
            long_window: true,
            ..normal
        };
        assert_eq!(paced_span_limit(&long), 1500);
        assert!(validate_schedule(&long, 1501).is_ok());
        assert!(validate_schedule(&long, 1502).is_err());
        assert!(validate_schedule(&long, 0).is_err());
        assert!(validate_schedule(&long, 60_001).is_err());
        for (size, operations) in [(32, 59_980), (4096, 14_980), (16384, 3730)] {
            assert_eq!(outbound_budget(size, operations, 20), Ok(60_000));
            assert!(outbound_budget(size, operations + 1, 20).is_err());
        }
        for mut invalid in [
            args(&["client", "--long-window"]),
            args(&["client", "--long-window", "--rate", "10", "--long-window"]),
            args(&[
                "client",
                "--long-window",
                "--rate",
                "10",
                "--message-type",
                "non",
            ]),
            args(&[
                "client",
                "--long-window",
                "--rate",
                "10",
                "--concurrency",
                "2",
                "--independent-endpoints",
            ]),
            args(&[
                "client",
                "--long-window",
                "--rate",
                "10",
                "--admission-diagnostics",
            ]),
        ] {
            assert!(run_options(&mut invalid).is_err());
        }
        let mut input = args(&["client", "--long-window", "--rate", "10"]);
        assert!(run_options(&mut input).unwrap().long_window);
        assert_eq!(input, args(&["client"]));
    }

    #[test]
    fn long_window_cannot_extend_complete_operation_deadline_or_allocate_before_refusal() {
        for (operations, timeout, policy) in [
            ("2", "3001", "spin"),
            ("2", "3000", "sleep1"),
            ("60001", "3000", "spin"),
        ] {
            let input = args(&[
                "client",
                "12345",
                "32",
                operations,
                "20",
                timeout,
                policy,
                "unprotected",
            ]);
            let options = RunOptions {
                rate: Some(100),
                long_window: true,
                ..RunOptions::default()
            };
            assert!(
                run_client::<CountIo>(&input, options, |_| panic!(
                    "must refuse before socket/pools"
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn warmup_and_control_sends_share_the_existing_counter() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = Endpoint::v4([127, 0, 0, 1], receiver.local_addr().unwrap().port());
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut io = CountIo {
            io: UdpSocketIo::new(socket, [0; 1473]).unwrap(),
            received: 0,
            sent: MAX_OUTBOUND_DATAGRAMS as u64 - 2,
        };
        io.send(peer, b"warmup").unwrap();
        // An empty CoAP ACK consumes the same counter as an operation request.
        io.send(peer, &[0x60, 0, 0, 1]).unwrap();
        assert_eq!(io.sent, MAX_OUTBOUND_DATAGRAMS as u64);
        assert!(io.send(peer, b"measurement").is_err());
        assert_eq!(io.sent, MAX_OUTBOUND_DATAGRAMS as u64);
    }
    #[test]
    fn pacing_and_gate_options_preserve_positionals_and_refuse_ambiguity() {
        let mut input = args(&[
            "client",
            "12345",
            "64",
            "10000",
            "128",
            "3000",
            "spin",
            "oscore",
            "credentials.bin",
            "--rate",
            "2000",
            "--cpu-gated",
        ]);
        assert_eq!(
            run_options(&mut input),
            Ok(RunOptions {
                gate: GateMode::Cpu,
                rate: Some(2000),
                ..RunOptions::default()
            })
        );
        assert_eq!(
            input,
            args(&[
                "client",
                "12345",
                "64",
                "10000",
                "128",
                "3000",
                "spin",
                "oscore",
                "credentials.bin",
            ])
        );
        let mut legacy = args(&["client", "12345", "--gated"]);
        assert_eq!(run_options(&mut legacy).unwrap().gate, GateMode::Basic);
        assert_eq!(legacy, args(&["client", "12345"]));
        for mut invalid in [
            args(&["client", "--rate"]),
            args(&["client", "--rate", "0"]),
            args(&["client", "--rate", "1000001"]),
            args(&["client", "--rate", "invalid"]),
            args(&["client", "--rate", "1", "--rate", "2"]),
            args(&["client", "--gated", "--cpu-gated"]),
        ] {
            assert!(run_options(&mut invalid).is_err());
        }
    }
    #[test]
    fn pacing_uses_the_origin_without_accumulating_fractional_period_drift() {
        assert_eq!(scheduled_offset(0, 2000), Duration::ZERO);
        assert_eq!(
            scheduled_offset(9999, 2000),
            Duration::from_micros(4_999_500)
        );
        assert_eq!(scheduled_offset(3, 3), Duration::from_secs(1));
        assert_eq!(
            scheduled_offset(1_000_000, 1),
            Duration::from_secs(1_000_000)
        );
        assert_eq!(
            scheduled_offset(1_000_000, 1_000_000),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn admission_diagnostics_require_explicit_paced_c1_and_reject_duplicates() {
        assert!(
            !run_options(&mut args(&["client"]))
                .unwrap()
                .admission_diagnostics
        );
        let selected = run_options(&mut args(&[
            "client",
            "--admission-diagnostics",
            "--rate",
            "4000",
        ]))
        .unwrap();
        assert!(selected.admission_diagnostics);
        for values in [
            vec!["client", "--admission-diagnostics"],
            vec![
                "client",
                "--admission-diagnostics",
                "--rate",
                "4000",
                "--concurrency",
                "2",
                "--message-type",
                "non",
            ],
            vec![
                "client",
                "--rate",
                "4000",
                "--admission-diagnostics",
                "--admission-diagnostics",
            ],
        ] {
            assert!(run_options(&mut args(&values)).is_err());
        }
    }

    #[test]
    fn admission_first_and_new_window_have_no_previous_completion_or_warmup() {
        let origin = Instant::now();
        let period = Duration::from_nanos(10);
        let mut diagnostic = AdmissionDiagnostics::default();
        diagnostic.record(origin + period, origin, period);
        assert_eq!(diagnostic.first_admissions, 1);
        assert_eq!(diagnostic.first_missed, 1); // A-D == P.
        assert_eq!(diagnostic.first_lateness_ns, 10);
        assert_eq!(diagnostic.no_idle_sleep.admissions, 0);
        diagnostic.completed(origin + period);
        let mut reset = AdmissionDiagnostics::default(); // Every run_window starts fresh.
        assert_eq!(reset.admissions, 0);
        assert!(reset.previous_completion.is_none());
        assert!(!reset.idle_sleep_traversed);
        reset.record(origin, origin, period);
        assert_eq!(reset.first_admissions, 1);
        assert_eq!(reset.first_missed, 0);
        assert_eq!(reset.first_lateness_ns, 0);
        assert!(!RunOptions::default().admission_diagnostics);
    }

    #[test]
    fn admission_prior_completion_carries_debt_and_equal_period_is_forced() {
        let origin = Instant::now();
        let period = Duration::from_nanos(10);
        let mut diagnostic = AdmissionDiagnostics::default();
        // C includes earlier admission delay, even with a short preceding RTT.
        diagnostic.completed(origin + Duration::from_nanos(35));
        diagnostic.record(origin + Duration::from_nanos(37), origin + period, period);
        diagnostic.completed(origin + Duration::from_nanos(38));
        diagnostic.record(
            origin + Duration::from_nanos(38),
            origin + Duration::from_nanos(28),
            period,
        );
        assert_eq!(diagnostic.prior_forced_missed, 2); // Second C-D == P.
        assert_eq!(diagnostic.no_idle_sleep.crossed_missed, 0);
        assert_eq!(diagnostic.no_idle_sleep.admissions, 2);
        assert_eq!(diagnostic.no_idle_sleep.positive, 1);
        assert_eq!(diagnostic.no_idle_sleep.total_ns, 2);
        assert_eq!(diagnostic.no_idle_sleep.max_ns, 2);
    }

    #[test]
    fn admission_residual_crossings_include_no_sleep_and_zero_duration_sleep() {
        let origin = Instant::now();
        let period = Duration::from_nanos(10);
        let mut diagnostic = AdmissionDiagnostics::default();
        for traversed in [false, true] {
            diagnostic.completed(origin + Duration::from_nanos(4));
            diagnostic.idle_sleep_traversed = traversed;
            diagnostic.record(origin + Duration::from_nanos(20), origin + period, period);
        }
        // A checked the deadline early but the existing sleep clock may find
        // zero duration. Traversal is still true; elapsed sleep is not measured.
        diagnostic.completed(origin);
        diagnostic.idle_sleep_traversed = true;
        diagnostic.record(origin + period, origin + period, period);
        assert_eq!(diagnostic.prior_forced_missed, 0);
        assert_eq!(diagnostic.no_idle_sleep.crossed_missed, 1);
        assert_eq!(diagnostic.idle_sleep.crossed_missed, 1);
        assert_eq!(diagnostic.idle_sleep.admissions, 2);
        assert_eq!(diagnostic.idle_sleep.positive, 1);
        assert_eq!(diagnostic.idle_sleep.total_ns, 10);
        diagnostic.completed(origin + period);
        assert!(!diagnostic.idle_sleep_traversed);
        diagnostic.record(origin + period, origin + period, period);
        assert_eq!(diagnostic.no_idle_sleep.admissions, 2);
    }

    #[test]
    fn admission_counters_saturate_and_report_member_is_bounded() {
        let origin = Instant::now();
        let mut bucket = AdmissionResidual {
            admissions: u64::MAX,
            positive: u64::MAX,
            crossed_missed: u64::MAX,
            total_ns: u128::MAX,
            max_ns: u128::MAX,
        };
        bucket.record(Duration::from_nanos(1), true);
        assert_eq!(bucket.admissions, u64::MAX);
        assert_eq!(bucket.positive, u64::MAX);
        assert_eq!(bucket.crossed_missed, u64::MAX);
        assert_eq!(bucket.total_ns, u128::MAX);
        assert_eq!(bucket.max_ns, u128::MAX);
        let mut diagnostic = AdmissionDiagnostics {
            admissions: u64::MAX,
            first_admissions: u64::MAX,
            first_missed: u64::MAX,
            first_lateness_ns: u128::MAX,
            prior_forced_missed: u64::MAX,
            idle_sleep: bucket,
            no_idle_sleep: AdmissionResidual::default(),
            ..AdmissionDiagnostics::default()
        };
        diagnostic.record(
            origin + Duration::from_nanos(1),
            origin,
            Duration::from_nanos(1),
        );
        assert_eq!(diagnostic.admissions, u64::MAX);
        assert_eq!(diagnostic.first_admissions, u64::MAX);
        assert_eq!(diagnostic.first_missed, u64::MAX);
        assert_eq!(diagnostic.first_lateness_ns, u128::MAX);
        diagnostic.completed(origin + Duration::from_nanos(1));
        diagnostic.record(
            origin + Duration::from_nanos(1),
            origin,
            Duration::from_nanos(1),
        );
        assert_eq!(diagnostic.prior_forced_missed, u64::MAX);
        diagnostic.no_idle_sleep = AdmissionResidual {
            admissions: u64::MAX,
            positive: u64::MAX,
            crossed_missed: u64::MAX,
            total_ns: u128::MAX,
            max_ns: u128::MAX,
        };
        assert!(diagnostic.json().len() <= 2048);
        eprintln!(
            "admission diagnostic compiled storage: {} bytes, Option {} bytes",
            std::mem::size_of::<AdmissionDiagnostics>(),
            std::mem::size_of::<Option<AdmissionDiagnostics>>()
        );
    }
    #[test]
    fn control_gate_is_bounded_and_refuses_wrong_or_incomplete_input() {
        assert!(read_gate(&b"run\n"[..], "run").is_ok());
        assert!(read_gate(&b"exit\n"[..], "exit").is_ok());
        assert!(read_gate(&b"run\r\n"[..], "run").is_ok());
        assert!(read_gate(&b"exit\r\n"[..], "exit").is_ok());
        assert!(read_gate(&b"report\n"[..], "report").is_ok());
        assert!(read_gate(&b"report\r\n"[..], "report").is_ok());
        for bytes in [
            &b"wrong\n"[..],
            &b"run"[..],
            &b"runxxxxxxxxxx\n"[..],
            &b""[..],
        ] {
            assert!(read_gate(bytes, "run").is_err());
        }
    }
    #[test]
    fn verification_refuses_corruption_truncation_and_metadata_then_recovers() {
        let valid = Response::content(b"body")
            .content_format(ContentFormat::OCTET_STREAM)
            .etag(b"fixture");
        assert!(verify(&valid, b"body").is_ok());
        for invalid in [
            valid.payload_borrowed(b"bodx"),
            valid.payload_borrowed(b"bod"),
            valid.content_format(ContentFormat::TEXT_PLAIN),
            valid.etag(b"changed"),
            Response::not_found()
                .content_format(ContentFormat::OCTET_STREAM)
                .etag(b"fixture"),
        ] {
            assert!(verify(&invalid, b"body").is_err());
        }
        assert!(verify(&valid, b"body").is_ok());
    }
}
