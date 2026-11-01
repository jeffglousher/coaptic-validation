//! Two extended-option polls and an untimed recovery in one continuous App.
use coaptic::message::{Message, MessageId, Opt, OptionNumber, ParsedMessage, Token, Type, decode};
use coaptic::oscore::{DeriveParams, RequestRef, SecurityContext};
use coaptic::storage::{Capacities, DatagramIo, MemoryLayout, Metrics};
use coaptic::{App, Code, ContentFormat, Endpoint, Request, Response, get};
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::mem::{size_of, size_of_val};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Instant;

const WIRE: usize = 1472;
const PEER: Endpoint = Endpoint::v4([127, 0, 0, 1], 30000);
const SMALL: [u8; 32] = [0x5a; 32];
const BODY: [u8; 64] = *b"0123456789abcdefABCDEFGHIJKLMNOPqrstuvwxyz#$%^&*ZYXWVUTSRQPONMLK";
const fn pattern<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    let mut i = 0;
    while i < N {
        bytes[i] = ((i * 17 + 3) % 251) as u8;
        i += 1;
    }
    bytes
}
static VALUE13: [u8; 13] = pattern();
static VALUE269: [u8; 269] = pattern();
static HANDLERS: AtomicUsize = AtomicUsize::new(0);
static LOCK: Mutex<()> = Mutex::new(());

fn inspect_request(request: Request<'_>) {
    assert_eq!(request.code(), Code::GET);
    assert_eq!(request.ty(), Type::Confirmable);
    assert_eq!(request.payload(), b"");
    let token: [u8; 8] = request.token().as_bytes().try_into().unwrap();
    let phase = u64::from_be_bytes(token) % 16;
    let mut options = request.options();
    let path = options.next().unwrap();
    assert_eq!(path.number(), OptionNumber::URI_PATH);
    assert_eq!(path.value(), b"bench");
    match phase {
        1 | 2 => {
            let option = options.next().unwrap();
            let (number, value): (u16, &[u8]) = if phase == 1 {
                (42, &VALUE13)
            } else {
                (280, &VALUE269)
            };
            assert_eq!(option.number(), OptionNumber::new(number));
            assert_eq!(option.value(), value);
        }
        3 => {}
        _ => panic!("unselected phase"),
    }
    assert!(options.next().is_none());
}

fn small_response(_: Request<'_>) -> Response<'static> {
    HANDLERS.fetch_add(1, Ordering::SeqCst);
    Response::content(&SMALL)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"fixture")
}
fn large_response(_: Request<'_>) -> Response<'static> {
    HANDLERS.fetch_add(1, Ordering::SeqCst);
    Response::content(&BODY)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"notify64")
}
fn small_qualification(request: Request<'_>) -> Response<'static> {
    inspect_request(request);
    small_response(request)
}
fn large_qualification(request: Request<'_>) -> Response<'static> {
    inspect_request(request);
    large_response(request)
}

struct CoreIo {
    input: [u8; WIRE],
    input_len: Option<usize>,
    output: [u8; WIRE],
    output_len: Option<usize>,
    received: u64,
    sent: u64,
}
impl coaptic::storage::DatagramTransport for CoreIo {
    type Error = &'static str;
}
impl DatagramIo for CoreIo {
    fn recv(&mut self, destination: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        let Some(n) = self.input_len.take() else {
            return Ok(None);
        };
        if n > destination.len() {
            return Err("receive capacity");
        }
        destination[..n].copy_from_slice(&self.input[..n]);
        Ok(Some((n, PEER)))
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        if peer != PEER || self.output_len.is_some() || bytes.len() > WIRE {
            return Err("unexpected output");
        }
        self.output[..bytes.len()].copy_from_slice(bytes);
        self.output_len = Some(bytes.len());
        Ok(bytes.len())
    }
}
fn io() -> CoreIo {
    CoreIo {
        input: [0; WIRE],
        input_len: None,
        output: [0; WIRE],
        output_len: None,
        received: 0,
        sent: 0,
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
type LargeApp = App<coaptic::profiles::Default, CoreIo, 1, true, coaptic::storage::AllocMemory>;
fn small(context: Option<SecurityContext>, qualification: bool) -> SmallApp {
    let resources = coaptic::resources::SmallDevice::new();
    assert_eq!(
        (
            resources.route_capacity(),
            resources.client_capacity(),
            resources.deferred_capacity(),
            resources.association_capacity(),
            resources.security_request_capacity()
        ),
        (4, 1, 0, 1, 4)
    );
    let handler: fn(Request<'_>) -> Response<'static> = if qualification {
        small_qualification
    } else {
        small_response
    };
    let builder = App::with_resources(resources)
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .route("bench", get(handler));
    let builder = if let Some(context) = context {
        builder.oscore(context)
    } else {
        builder.allow_unprotected()
    };
    builder.bind(io()).unwrap()
}
fn capacities() -> Capacities {
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
    }
}
fn large(context: Option<SecurityContext>, qualification: bool) -> LargeApp {
    let handler: fn(Request<'_>) -> Response<'static> = if qualification {
        large_qualification
    } else {
        large_response
    };
    let builder = App::builder()
        .full_responses()
        .routes::<1>()
        .block_wise::<true>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .route("bench", get(handler));
    let builder = if let Some(context) = context {
        builder.oscore(context)
    } else {
        builder.allow_unprotected()
    };
    builder.bind_alloc(io(), capacities()).unwrap()
}
fn pair(protected: bool) -> (Option<SecurityContext>, Option<SecurityContext>) {
    let mut seed = [0; 24];
    getrandom::fill(&mut seed).unwrap();
    let derive = |sender_id, recipient_id| {
        SecurityContext::derive(DeriveParams {
            master_secret: &seed[..16],
            master_salt: &seed[16..],
            sender_id,
            recipient_id,
            id_context: &[],
        })
        .unwrap()
    };
    let contexts = if protected {
        (Some(derive(&[1], &[])), Some(derive(&[], &[1])))
    } else {
        (None, None)
    };
    seed.fill(0);
    black_box(&mut seed); // Best effort; no erasure guarantee.
    contexts
}

trait Clock {
    fn poll<T>(&mut self, label: usize, cycle: usize, operation: impl FnOnce() -> T) -> T;
}
struct NoClock;
impl Clock for NoClock {
    fn poll<T>(&mut self, _: usize, _: usize, operation: impl FnOnce() -> T) -> T {
        operation()
    }
}
struct RealClock {
    latencies: [[u128; 1000]; 2],
    calibration: [u128; 4096],
}
impl RealClock {
    fn new() -> Self {
        let mut clock = Self {
            latencies: [[0; 1000]; 2],
            calibration: [0; 4096],
        };
        for sample in &mut clock.calibration {
            let started = Instant::now();
            black_box(());
            *sample = started.elapsed().as_nanos();
        }
        clock
    }
}
impl Clock for RealClock {
    fn poll<T>(&mut self, label: usize, cycle: usize, operation: impl FnOnce() -> T) -> T {
        black_box(());
        let started = Instant::now();
        let result = operation();
        black_box(());
        let elapsed = started.elapsed().as_nanos();
        assert!(elapsed <= 30_000_000_000);
        if cycle >= 128 {
            self.latencies[label][cycle - 128] = elapsed;
        }
        result
    }
}
struct Aux {
    peer: Option<SecurityContext>,
    wire: [u8; WIRE],
    opened: [u8; WIRE],
    peer_fresh: u64,
    bindings: usize,
    max_piv: usize,
}
impl Aux {
    fn new(peer: Option<SecurityContext>) -> Self {
        Self {
            peer,
            wire: [0; WIRE],
            opened: [0; WIRE],
            peer_fresh: 0,
            bindings: 0,
            max_piv: 0,
        }
    }
    fn input(&mut self, io: &mut CoreIo, request: &Message<'_>, phase: usize) {
        assert!(io.input_len.is_none() && io.output_len.is_none());
        assert_eq!(self.bindings, 0);
        let n = request.encode(&mut self.wire).unwrap();
        assert!(n < 320);
        // The token is exactly eight bytes; Uri-Path uses one regular header.
        assert_eq!(&self.wire[12..18], b"\xb5bench");
        match phase {
            1 => assert_eq!(&self.wire[18..21], &[0xdd, 18, 0]),
            2 => assert_eq!(&self.wire[18..23], &[0xee, 0, 0, 0, 0]),
            3 => assert_eq!(n, 18),
            _ => panic!("unselected phase"),
        }
        let decoded = decode(&self.wire[..n]).unwrap();
        assert_eq!(decoded.token(), request.token());
        assert_eq!(decoded.code(), Code::GET);
        let mut options = decoded.options();
        assert_eq!(options.next().unwrap(), Opt::uri_path("bench"));
        if phase < 3 {
            let expected = if phase == 1 {
                Opt::new(OptionNumber::new(42), &VALUE13)
            } else {
                Opt::new(OptionNumber::new(280), &VALUE269)
            };
            assert_eq!(options.next(), Some(expected));
        }
        assert!(options.next().is_none());
        let n = if let Some(peer) = self.peer.as_mut() {
            assert!(peer.lookup(request.token()).is_none());
            let before = peer.sender_seq();
            let n = peer.protect_request(request, &mut io.input).unwrap();
            assert_eq!(peer.sender_seq(), before + 1);
            let parsed = decode(&io.input[..n]).unwrap();
            assert!(parsed.get_option(OptionNumber::new(42)).is_none());
            assert!(parsed.get_option(OptionNumber::new(280)).is_none());
            let header = coaptic::oscore::OscoreHeader::parse(parsed.oscore().unwrap()).unwrap();
            let piv = header.piv.unwrap();
            assert_eq!(piv.seq(), self.peer_fresh);
            assert!(piv.as_bytes().len() <= 2);
            self.max_piv = self.max_piv.max(piv.as_bytes().len());
            self.peer_fresh += 1;
            assert!(self.peer_fresh <= 3384);
            self.bindings = 1;
            n
        } else {
            io.input[..n].copy_from_slice(&self.wire[..n]);
            n
        };
        assert!(n < 320);
        io.input_len = Some(n);
    }
    fn output(&mut self, io: &mut CoreIo, mid: MessageId, token: Token, large: bool) {
        assert!(io.input_len.is_none());
        let n = io.output_len.take().unwrap();
        io.sent += 1;
        self.wire[..n].copy_from_slice(&io.output[..n]);
        let wire = decode(&self.wire[..n]).unwrap();
        assert_eq!(wire.ty(), Type::Acknowledgement);
        assert_eq!(wire.message_id(), mid);
        assert_eq!(wire.token(), token);
        assert_eq!(wire.oscore().is_some(), self.peer.is_some());
        let response = if let Some(peer) = self.peer.as_mut() {
            assert_eq!(self.bindings, 1);
            let header = coaptic::oscore::OscoreHeader::parse(wire.oscore().unwrap()).unwrap();
            assert!(
                header.piv.is_none(),
                "ordinary response uses request nonce binding"
            );
            let binding = peer.take(token).unwrap();
            assert!(peer.lookup(token).is_none());
            self.bindings = 0;
            peer.unprotect_response(&wire, binding, &mut self.opened)
                .unwrap()
        } else {
            wire
        };
        verify(&response, mid, token, large);
        assert_eq!(self.bindings, 0);
    }
}
impl Drop for Aux {
    fn drop(&mut self) {
        self.wire.fill(0);
        self.opened.fill(0);
        black_box(&mut self.opened);
    }
}
fn verify(response: &ParsedMessage<'_>, mid: MessageId, token: Token, large: bool) {
    assert_eq!(response.ty(), Type::Acknowledgement);
    assert_eq!(response.message_id(), mid);
    assert_eq!(response.token(), token);
    assert_eq!(response.code(), Code::CONTENT);
    assert_eq!(
        response.payload(),
        if large { &BODY[..] } else { &SMALL[..] }
    );
    assert_eq!(
        response.content_format(),
        Some(Ok(ContentFormat::OCTET_STREAM))
    );
    let mut tags = response.etag();
    assert_eq!(
        tags.next(),
        Some(if large {
            &b"notify64"[..]
        } else {
            &b"fixture"[..]
        })
    );
    assert!(tags.next().is_none());
    assert!(response.block2().is_none());
    assert!(response.observe().is_none());
}

struct Report {
    app_inline: usize,
    app_heap: usize,
    aux_inline: usize,
    peer_nested: usize,
    datagrams: u64,
    handlers: usize,
    peer_fresh: u64,
    max_piv: usize,
}
macro_rules! driver {
    ($module:ident, $app:ty, $factory:ident, $large:literal) => {
        mod $module {
            use super::*;
            type A = $app;
            fn empty(app: &mut A, expiry: bool) {
                assert!(
                    app.transport().input_len.is_none() && app.transport().output_len.is_none()
                );
                let usage = app.storage_usage();
                assert_eq!(
                    (
                        usage.rx_datagram.occupied,
                        usage.tx_datagram.occupied,
                        usage.observe.occupied
                    ),
                    (0, 0, 0)
                );
                if let Some(pool) = usage.rx_body {
                    assert_eq!(pool.occupied, 0);
                }
                if let Some(pool) = usage.tx_body {
                    assert_eq!(pool.occupied, 0);
                }
                if expiry {
                    assert_eq!(usage.dedup.occupied, 0);
                    assert!(app.next_timeout().is_none());
                }
            }
            pub fn execute<C: Clock>(
                protected: bool,
                timing: bool,
                clock: &mut C,
                cycles: usize,
            ) -> Report {
                let (server, peer) = pair(protected);
                let mut app = $factory(server, !timing);
                let mut aux = Aux::new(peer);
                let caps = app.engine().capacities();
                assert_eq!(
                    (
                        caps.rx_datagram_slots,
                        caps.tx_datagram_slots,
                        caps.rx_datagram_bytes,
                        caps.tx_datagram_bytes,
                        caps.dedup_entries,
                        caps.observe_entries
                    ),
                    if $large {
                        (4, 4, 1472, 1472, 8, 4)
                    } else {
                        (2, 2, 1152, 1152, 4, 2)
                    }
                );
                assert_eq!(
                    (
                        caps.rx_body_slots,
                        caps.tx_body_slots,
                        caps.rx_body_bytes,
                        caps.tx_body_bytes
                    ),
                    if $large {
                        (Some(1), Some(2), Some(1024), Some(1024))
                    } else {
                        (None, None, None, None)
                    }
                );
                assert_eq!(app.oscore().is_some(), protected);
                assert_eq!(app.oscore().map(|c| c.sender_seq()).unwrap_or(0), 0);
                for cycle in 0..cycles {
                    empty(&mut app, false);
                    app.poll(248000 * cycle as u64).unwrap();
                    empty(&mut app, true);
                    let before = app.metrics();
                    let inputs = app.transport().received;
                    let outputs = app.transport().sent;
                    let handlers = HANDLERS.load(Ordering::SeqCst);
                    for phase in 1..=3 {
                        let operation = cycle * 16 + phase;
                        assert!(operation <= 18035);
                        let mid = MessageId::new(operation as u16);
                        let token = Token::new(&(operation as u64).to_be_bytes()).unwrap();
                        let path = Opt::uri_path("bench");
                        let options = [
                            path,
                            if phase == 1 {
                                Opt::new(OptionNumber::new(42), &VALUE13)
                            } else {
                                Opt::new(OptionNumber::new(280), &VALUE269)
                            },
                        ];
                        let request = Message::con(Code::GET, mid, token)
                            .with_options(if phase < 3 { &options } else { &options[..1] });
                        aux.input(app.transport_mut(), &request, phase);
                        let now = 248000 * cycle as u64 + phase as u64;
                        let result = if phase < 3 {
                            clock.poll(phase - 1, cycle, || black_box(app.poll(black_box(now))))
                        } else {
                            app.poll(now)
                        };
                        result.unwrap();
                        assert!(app.transport().input_len.is_none());
                        app.transport_mut().received += 1;
                        aux.output(app.transport_mut(), mid, token, $large);
                        empty(&mut app, false);
                    }
                    let after = app.metrics();
                    assert_eq!(
                        (
                            after.rx_accepted - before.rx_accepted,
                            after.tx_ok - before.tx_ok
                        ),
                        (3, 3)
                    );
                    assert!(after.progress > before.progress);
                    let mut other = after;
                    other.rx_accepted = 0;
                    other.tx_ok = 0;
                    other.progress = 0;
                    assert_eq!(other, Metrics::ZERO);
                    assert_eq!(
                        (
                            app.transport().received - inputs,
                            app.transport().sent - outputs
                        ),
                        (3, 3)
                    );
                    assert_eq!(HANDLERS.load(Ordering::SeqCst) - handlers, 3);
                    assert_eq!(app.storage_usage().dedup.occupied, 3);
                    for phase in 1..=3 {
                        let mid = MessageId::new((cycle * 16 + phase) as u16);
                        let row = app
                            .engine_mut()
                            .lookup_dedup(coaptic::storage::DedupKey::new(mid, PEER))
                            .unwrap();
                        assert!(
                            app.engine_mut()
                                .dedup_entry(row)
                                .unwrap()
                                .tx_pin()
                                .is_none()
                        );
                    }
                    assert_eq!(aux.bindings, 0);
                    assert_eq!(app.oscore().map(|c| c.sender_seq()).unwrap_or(0), 0);
                    assert_eq!(
                        aux.peer.as_ref().map(|c| c.sender_seq()).unwrap_or(0),
                        aux.peer_fresh
                    );
                    assert_eq!(
                        aux.peer_fresh,
                        if protected { 3 * (cycle + 1) as u64 } else { 0 }
                    );
                }
                app.poll(279744000).unwrap();
                empty(&mut app, true);
                assert_eq!(
                    (app.transport().received, app.transport().sent),
                    (3 * cycles as u64, 3 * cycles as u64)
                );
                Report {
                    app_inline: size_of_val(&app),
                    app_heap: if $large {
                        coaptic::storage::AllocMemory::<Token>::required_heap_bytes(caps).unwrap()
                    } else {
                        0
                    },
                    aux_inline: size_of_val(&aux),
                    peer_nested: size_of_val(&aux.peer),
                    datagrams: app.transport().received + app.transport().sent,
                    handlers: HANDLERS.load(Ordering::SeqCst),
                    peer_fresh: aux.peer_fresh,
                    max_piv: aux.max_piv,
                }
            }
        }
    };
}
driver!(fixed, SmallApp, small, false);
driver!(allocated, LargeApp, large, true);

pub fn run(large: bool, protected: bool, timing: bool) {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    HANDLERS.store(0, Ordering::SeqCst);
    let case = if large {
        "long_default"
    } else {
        "long_small_device"
    };
    if timing {
        let mut clock = RealClock::new();
        let report = if large {
            allocated::execute(protected, true, &mut clock, 1128)
        } else {
            fixed::execute(protected, true, &mut clock, 1128)
        };
        emit(case, large, protected, &clock, report);
    } else {
        if large {
            allocated::execute(protected, false, &mut NoClock, 16);
        } else {
            fixed::execute(protected, false, &mut NoClock, 16);
        }
        let stdout = std::io::stdout();
        let mut writer = BufWriter::with_capacity(8192, stdout.lock());
        writeln!(writer,"\nCOAPTIC_STAGE_B_QUALIFICATION {{\"schema\":\"coaptic-admission-stage-b-qualification/1\",\"contract_sha256\":\"{}\",\"case\":\"{case}\",\"security\":\"{}\",\"cycles\":16,\"passed\":true,\"measurement\":\"NOT RUN\"}}",super::HASH,if protected {"oscore"} else {"unprotected"}).unwrap();
        writer.flush().unwrap();
    }
}
fn array(writer: &mut impl Write, values: &[u128]) {
    write!(writer, "[").unwrap();
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            write!(writer, ",").unwrap();
        }
        write!(writer, "{value}").unwrap();
    }
    write!(writer, "]").unwrap();
}
fn emit(case: &str, large: bool, protected: bool, clock: &RealClock, report: Report) {
    for values in &clock.latencies {
        assert!(values.iter().sum::<u128>() > 0);
    }
    // Source-owner sum, including immutable wire patterns. App already contains
    // CoreIo, so its transport arrays are not counted here again. Compiler moves,
    // initialization and peak stack are not established by these object sizes.
    let fixture_inline = report.aux_inline
        + size_of::<RealClock>()
        + size_of::<Report>()
        + size_of::<BufWriter<std::io::StdoutLock<'_>>>()
        + size_of::<Option<RequestRef>>()
        + size_of::<[Opt<'_>; 2]>()
        + size_of::<Opt<'_>>()
        + size_of::<coaptic::message::Options<'_>>() * 2
        + size_of::<coaptic::message::OpaqueOptions<'_>>()
        + size_of::<Request<'_>>()
        + size_of::<coaptic::oscore::OscoreHeader<'_>>() * 2
        + size_of::<Message<'_>>()
        + size_of::<ParsedMessage<'_>>() * 3
        + size_of::<Metrics>() * 3
        + size_of::<coaptic::storage::StorageUsage>()
        + size_of::<Capacities>()
        + size_of::<[u8; 24]>()
        + size_of::<DeriveParams<'_>>()
        + size_of::<[u8; 8]>()
        + size_of::<[u8; 13]>()
        + size_of::<[u8; 269]>()
        + size_of::<[u8; 32]>()
        + size_of::<[u8; 64]>()
        + size_of::<usize>() * 16
        + size_of::<u64>() * 8;
    let fixture_heap = 8192;
    let total = fixture_inline + fixture_heap;
    assert!(total <= 262144);
    let stdout = std::io::stdout();
    let mut writer = BufWriter::with_capacity(8192, stdout.lock());
    write!(writer,"\nCOAPTIC_STAGE_B_RESULT {{\"schema\":\"coaptic-admission-stage-b-native/1\",\"contract_sha256\":\"{}\",\"contract\":{},\"case\":\"{case}\",\"security\":\"{}\",\"profile\":\"{}\",\"operations\":1000,\"warmup\":128,\"calibration_samples\":4096,\"verified_cycles\":1128,\"latencies_ns\":{{",super::HASH,super::CONTRACT.trim(),if protected {"oscore"} else {"unprotected"},if large {"Default"} else {"SmallDevice"}).unwrap();
    for (index, label) in ["delta13_len13", "delta14_len269"].iter().enumerate() {
        if index > 0 {
            write!(writer, ",").unwrap();
        }
        write!(writer, "\"{label}\":").unwrap();
        array(&mut writer, &clock.latencies[index]);
    }
    write!(writer, "}},\"calibration_ns\":").unwrap();
    array(&mut writer, &clock.calibration);
    write!(writer,",\"internal_datagrams\":{},\"udp_datagrams\":0,\"handler_calls\":{},\"clock_ms\":[0,279744000],\"metrics\":{{\"admission_rx_refused\":0,\"admission_tx_refused\":0,\"admission_refusal_sent\":0,\"admission_refusal_unsent\":0,\"observe_register\":0,\"observe_cancel\":0,\"observe_notify\":0}},\"sender_sequences\":",report.datagrams,report.handlers).unwrap();
    if protected {
        assert_eq!(report.peer_fresh, 3384);
        assert_eq!(report.max_piv, 2);
        write!(writer,"{{\"app\":[0,0],\"peer\":[0,{}],\"fresh_app\":0,\"fresh_peer\":{},\"max_piv_bytes\":2}}",report.peer_fresh,report.peer_fresh).unwrap();
    } else {
        write!(writer, "null").unwrap();
    }
    // No outbound Call is created in these cells. The shared settlement key
    // calls_collected_once is the zero-Call case, not a Call-collection proof.
    write!(writer,",\"memory\":{{\"app_inline_bytes\":{},\"app_pool_requested_heap_bytes\":{},\"fixture_inline_bytes\":{fixture_inline},\"fixture_requested_heap_bytes\":{fixture_heap},\"fixture_total_requested_bytes\":{total},\"peer_context_nested_bytes\":{},\"latency_bytes\":32000,\"calibration_bytes\":65536,\"token_ledger_bytes\":0,\"serializer_buffer_bytes\":8192,\"remaining\":\"allocator/runtime/initialization/peak-stack costs unknown\"}},\"settled\":{{\"calls_collected_once\":true,\"peer_bindings_consumed\":true,\"rx_empty\":true,\"tx_empty\":true,\"observe_empty\":true,\"bodies_empty\":true,\"pending_empty\":true,\"io_empty\":true,\"dedup_expired\":true}}}}",report.app_inline,report.app_heap,report.peer_nested).unwrap();
    writeln!(writer).unwrap();
    writer.flush().unwrap();
}
