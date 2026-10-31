//! Continuous protocol fixture. No inherited qualification from the old module.
use coaptic::message::{BlockValue, Message, MessageId, Opt, Token, Type, decode};
use coaptic::oscore::{DeriveParams, RequestRef, SecurityContext};
use coaptic::storage::{Capacities, DatagramIo, MemoryLayout, Metrics, SlotId, Storage};
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
static HANDLERS: AtomicUsize = AtomicUsize::new(0);
static LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Case {
    Rx,
    Tx,
    Observe,
    Notification,
    Ordinary,
    Negative,
}
impl Case {
    fn id(self) -> &'static str {
        match self {
            Self::Rx => "rx",
            Self::Tx => "tx",
            Self::Observe => "observe_cancel",
            Self::Notification => "notification_block2",
            Self::Ordinary => "ordinary_block2",
            Self::Negative => "ordinary_three_rx_owners_refuse",
        }
    }
    fn large(self) -> bool {
        matches!(self, Self::Notification | Self::Ordinary | Self::Negative)
    }
    fn labels(self) -> &'static [&'static str] {
        if self.large() {
            &["num1", "num2", "num3"]
        } else {
            &["poll"]
        }
    }
    fn metrics(self) -> [u32; 7] {
        match self {
            Self::Rx | Self::Negative => [1, 0, 1, 0, 0, 0, 0],
            Self::Tx => [0, 1, 1, 0, 0, 0, 0],
            Self::Observe => [0, 1, 1, 0, 1, 1, 0],
            Self::Notification => [0, 0, 0, 0, 1, 1, 1],
            Self::Ordinary => [0; 7],
        }
    }
    fn counts(self) -> (u64, usize) {
        match self {
            Self::Rx => (6, 1),
            Self::Tx => (4, 1),
            Self::Observe => (6, 2),
            Self::Notification => (19, 3),
            Self::Ordinary => (14, 5),
            Self::Negative => (10, 1),
        }
    }
}
fn selected(m: Metrics) -> [u32; 7] {
    [
        m.admission_rx_refused,
        m.admission_tx_refused,
        m.admission_refusal_sent,
        m.admission_refusal_unsent,
        m.observe_register,
        m.observe_cancel,
        m.observe_notify,
    ]
}
fn representation(req: Request<'_>) -> Response<'static> {
    HANDLERS.fetch_add(1, Ordering::SeqCst);
    let r = if LARGE.load(Ordering::SeqCst) > 0 {
        body_response()
    } else {
        Response::content(&SMALL)
            .content_format(ContentFormat::OCTET_STREAM)
            .etag(b"fixture")
    };
    // Registration and cancellation use the same observable resource. Ordinary
    // requests do not acquire a relation merely because the resource supports it.
    let _ = req;
    if OBSERVABLE.load(Ordering::SeqCst) > 0 {
        r.observe(0)
    } else {
        r
    }
}
static LARGE: AtomicUsize = AtomicUsize::new(0);
static OBSERVABLE: AtomicUsize = AtomicUsize::new(0);
fn body_response() -> Response<'static> {
    Response::content(&BODY)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"notify64")
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
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        let Some(n) = self.input_len.take() else {
            return Ok(None);
        };
        if n > buf.len() {
            return Err("receive capacity");
        };
        buf[..n].copy_from_slice(&self.input[..n]);
        Ok(Some((n, PEER)))
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        if peer != PEER || self.output_len.is_some() || bytes.len() > WIRE {
            return Err("unexpected output");
        };
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
fn small(context: Option<SecurityContext>) -> SmallApp {
    let r = coaptic::resources::SmallDevice::new();
    assert_eq!(
        (
            r.route_capacity(),
            r.client_capacity(),
            r.deferred_capacity(),
            r.association_capacity(),
            r.security_request_capacity()
        ),
        (4, 1, 0, 1, 4)
    );
    let b = App::with_resources(r)
        .randomness(|b| getrandom::fill(b).is_ok())
        .route("bench", get(representation));
    let b = if let Some(c) = context {
        b.oscore(c)
    } else {
        b.allow_unprotected()
    };
    b.bind(io()).unwrap()
}
fn large(context: Option<SecurityContext>) -> LargeApp {
    let b = App::builder()
        .full_responses()
        .routes::<1>()
        .block_wise::<true>()
        .randomness(|b| getrandom::fill(b).is_ok())
        .route("bench", get(representation));
    let b = if let Some(c) = context {
        b.oscore(c)
    } else {
        b.allow_unprotected()
    };
    b.bind_alloc(
        io(),
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
    )
    .unwrap()
}
fn pair(protected: bool) -> (Option<SecurityContext>, Option<SecurityContext>) {
    // Entropy is acquired exactly once per process fixture, never during cycles.
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
    let pair = if protected {
        (Some(derive(&[1], &[])), Some(derive(&[], &[1])))
    } else {
        (None, None)
    };
    seed.fill(0);
    black_box(&mut seed); // Best effort only; no erasure guarantee.
    pair
}

trait Clock {
    fn poll<T>(&mut self, label: usize, cycle: usize, f: impl FnOnce() -> T) -> T;
}
struct NoClock;
impl Clock for NoClock {
    fn poll<T>(&mut self, _: usize, _: usize, f: impl FnOnce() -> T) -> T {
        f()
    }
}
struct RealClock {
    latencies: [[u128; 1000]; 3],
    calibration: [u128; 4096],
}
impl RealClock {
    fn new() -> Self {
        let mut c = Self {
            latencies: [[0; 1000]; 3],
            calibration: [0; 4096],
        };
        for x in &mut c.calibration {
            let t = Instant::now();
            black_box(());
            *x = t.elapsed().as_nanos();
        }
        c
    }
}
impl Clock for RealClock {
    fn poll<T>(&mut self, label: usize, cycle: usize, f: impl FnOnce() -> T) -> T {
        black_box(());
        let t = Instant::now();
        let result = f();
        black_box(());
        let n = t.elapsed().as_nanos();
        assert!(n <= 30_000_000_000);
        if cycle >= 128 {
            self.latencies[label][cycle - 128] = n;
        }
        result
    }
}
// All explicit auxiliary owners are inline here. App transport arrays live in
// App and are counted there, not again. The context is nested exactly once.
struct Aux {
    peer: Option<SecurityContext>,
    opened: [u8; WIRE],
    wire: [u8; WIRE],
    postponed: [u8; 128],
    postponed_len: usize,
    ledger: [[u8; 8]; 3384],
    ledger_len: usize,
    fresh: [u64; 2],
    max_piv: usize,
    bindings: usize,
    snapshots: [[u8; 128]; 3],
    lengths: [usize; 3],
    held: [Option<SlotId>; 3],
    body_ids: [Option<SlotId>; 2],
}
impl Aux {
    fn new(peer: Option<SecurityContext>) -> Self {
        Self {
            peer,
            opened: [0; WIRE],
            wire: [0; WIRE],
            postponed: [0; 128],
            postponed_len: 0,
            ledger: [[0; 8]; 3384],
            ledger_len: 0,
            fresh: [0; 2],
            max_piv: 0,
            bindings: 0,
            snapshots: [[0; 128]; 3],
            lengths: [0; 3],
            held: [None; 3],
            body_ids: [None; 2],
        }
    }
    fn token(&mut self, token: Token) {
        let b: [u8; 8] = token.as_bytes().try_into().unwrap();
        assert!(u64::from_be_bytes(b) >= 18048, "reserved token collision");
        assert!(
            !self.ledger[..self.ledger_len].contains(&b),
            "process token collision"
        );
        assert!(self.ledger_len < 3384);
        self.ledger[self.ledger_len] = b;
        self.ledger_len += 1;
    }
    fn piv(&mut self, dir: usize, bytes: &[u8]) {
        let m = decode(bytes).unwrap();
        if let Some(h) = m.oscore() {
            let h = coaptic::oscore::OscoreHeader::parse(h).unwrap();
            if let Some(p) = h.piv {
                assert!(p.as_bytes().len() <= 2);
                assert_eq!(p.seq(), self.fresh[dir]);
                self.fresh[dir] += 1;
                assert!(self.fresh[dir] <= 11280);
                self.max_piv = self.max_piv.max(p.as_bytes().len());
            }
        }
    }
    fn input(&mut self, io: &mut CoreIo, request: &Message<'_>) {
        assert!(io.input_len.is_none());
        let n = if let Some(p) = self.peer.as_mut() {
            p.protect_request(request, &mut io.input).unwrap()
        } else {
            request.encode(&mut io.input).unwrap()
        };
        self.piv(1, &io.input[..n]);
        io.input_len = Some(n);
    }
    fn output(
        &mut self,
        io: &mut CoreIo,
        token: Token,
        notification: Option<RequestRef>,
    ) -> coaptic::message::ParsedMessage<'_> {
        let n = io.output_len.take().unwrap();
        io.sent += 1;
        self.wire[..n].copy_from_slice(&io.output[..n]);
        // Inspect before borrowing scratch for the returned opened message.
        let mut packet = [0; WIRE];
        packet[..n].copy_from_slice(&self.wire[..n]);
        self.piv(0, &packet[..n]);
        let wire = decode(&self.wire[..n]).unwrap();
        assert_eq!(wire.oscore().is_some(), self.peer.is_some());
        assert_eq!(wire.token(), token);
        match self.peer.as_mut() {
            Some(p) => {
                let binding = notification.unwrap_or_else(|| {
                    self.bindings -= 1;
                    p.take(token).unwrap()
                });
                p.unprotect_response(&wire, binding, &mut self.opened)
                    .unwrap()
            }
            None => wire,
        }
    }
}
impl Drop for Aux {
    fn drop(&mut self) {
        self.opened.fill(0);
        self.wire.fill(0);
        self.postponed.fill(0);
        self.snapshots.fill([0; 128]);
        black_box(&mut self.opened);
    }
}
fn mid(cycle: usize, phase: usize) -> MessageId {
    assert!(phase <= 15);
    let n = cycle * 16 + phase;
    assert!(n <= 18047);
    MessageId::new(n as u16)
}
fn token(cycle: usize, phase: usize) -> Token {
    assert!(phase <= 15);
    Token::new(&((cycle * 16 + phase) as u64).to_be_bytes()).unwrap()
}
fn time(cycle: usize, phase: usize) -> u64 {
    assert!(phase <= 15);
    248000 * cycle as u64 + phase as u64
}
fn verify(
    reply: &coaptic::message::ParsedMessage<'_>,
    m: MessageId,
    t: Token,
    code: Code,
    body: &[u8],
) {
    assert_eq!(reply.ty(), Type::Acknowledgement);
    assert_eq!(reply.message_id(), m);
    assert_eq!(reply.token(), t);
    assert_eq!(reply.code(), code);
    assert_eq!(reply.payload(), body);
    if code == Code::CONTENT {
        assert_eq!(
            reply.content_format(),
            Some(Ok(ContentFormat::OCTET_STREAM))
        );
    }
}

// Generate monomorphic public-App drivers for the two supported layouts. This
// keeps all cycle logic identical without exposing or reconstructing core types.
macro_rules! driver {
    ($module:ident,$app:ty,$factory:ident,$large:literal) => {
        mod $module {
            use super::*;
            type A = $app;
            fn seq(app: &A) -> u64 {
                app.association_at(0)
                    .map(|a| app.association_context(a).unwrap().sender_seq())
                    .unwrap_or(0)
            }
            fn empty(app: &mut A, expiry: bool) {
                assert!(
                    app.transport().input_len.is_none() && app.transport().output_len.is_none()
                );
                let e = app.engine_mut();
                assert_eq!(e.rx_occupied(), 0);
                assert_eq!(e.tx_occupied(), 0);
                assert_eq!(e.storage_mut().observe().occupied_count(), 0);
                if let Some(p) = e.storage_mut().rx_body() {
                    assert_eq!(p.occupied_count(), 0)
                }
                if let Some(p) = e.storage_mut().tx_body() {
                    assert_eq!(p.occupied_count(), 0)
                }
                if expiry {
                    assert_eq!(e.storage_mut().dedup().occupied_count(), 0)
                }
            }
            fn request(
                app: &mut A,
                aux: &mut Aux,
                cycle: usize,
                phase: usize,
                t: Token,
                opts: &[Opt<'_>],
            ) {
                let r = Message::con(Code::GET, mid(cycle, phase), t).with_options(opts);
                aux.input(app.transport_mut(), &r);
                if aux.peer.is_some() {
                    aux.bindings += 1;
                }
            }
            // Observe the one-slot transport after progress. Bookkeeping and
            // Result checks stay outside the selected complete-App poll clock.
            fn progress<C: Clock>(
                app: &mut A,
                clock: &mut C,
                selected: Option<usize>,
                cycle: usize,
                now: u64,
            ) {
                let had_input = app.transport().input_len.is_some();
                let result = if let Some(label) = selected {
                    clock.poll(label, cycle, || app.poll(black_box(now)))
                } else {
                    app.poll(now)
                };
                result.unwrap();
                let io = app.transport_mut();
                assert!(io.input_len.is_none());
                io.received += u64::from(had_input);
            }
            fn exchange<C: Clock>(
                app: &mut A,
                aux: &mut Aux,
                clock: &mut C,
                cycle: usize,
                phase: usize,
                t: Token,
                opts: &[Opt<'_>],
                selected: Option<usize>,
                code: Code,
                body: &[u8],
            ) {
                request(app, aux, cycle, phase, t, opts);
                let now = time(cycle, phase);
                progress(app, clock, selected, cycle, now);
                assert!(app.transport().input_len.is_none());
                let reply = aux.output(app.transport_mut(), t, None);
                verify(&reply, mid(cycle, phase), t, code, body);
            }
            fn inventory(app: &mut A) -> [Option<SlotId>; 4] {
                let p = app.engine_mut().storage_mut().rx_datagram();
                let mut ids = [None; 4];
                let cursor = p.cursor();
                for i in 0..if $large { 4 } else { 2 } {
                    ids[i] = Some(p.acquire().unwrap());
                }
                for id in ids.into_iter().flatten() {
                    p.release(id).unwrap();
                }
                assert_eq!(p.cursor(), cursor);
                ids
            }
            fn capture(
                app: &mut A,
                aux: &mut Aux,
                ids: [Option<SlotId>; 4],
                i: usize,
                m: MessageId,
                t: Token,
            ) {
                let mut found = None;
                for id in ids.into_iter().flatten() {
                    if app.engine_mut().storage_mut().rx_datagram().is_occupied(id)
                        && !aux.held.contains(&Some(id))
                    {
                        assert!(found.is_none());
                        found = Some(id);
                    }
                }
                let id = found.unwrap();
                aux.held[i] = Some(id);
                assert!(!app.engine_mut().rx_is_pinned(id));
                assert_eq!(app.engine_mut().rx_endpoint(id), Some(PEER));
                let r = app.engine_mut().decode_rx(id).unwrap();
                assert_eq!(r.message_id(), m);
                assert_eq!(r.token(), t);
                assert_eq!(r.code(), Code::CONTENT);
                assert_eq!(r.payload(), b"retained-response");
                let b = app.engine_mut().access_rx(id).unwrap();
                assert!(b.len() <= aux.snapshots[i].len());
                aux.lengths[i] = b.len();
                aux.snapshots[i][..b.len()].copy_from_slice(&b);
            }
            fn retained(app: &mut A, aux: &Aux, count: usize) {
                assert_eq!(app.engine_mut().rx_occupied(), count);
                for i in 0..count {
                    let id = aux.held[i].unwrap();
                    assert!(app.engine_mut().storage_mut().rx_datagram().is_occupied(id));
                    assert!(!app.engine_mut().rx_is_pinned(id));
                    assert_eq!(app.engine_mut().rx_endpoint(id), Some(PEER));
                    let b = app.engine_mut().access_rx(id).unwrap();
                    assert_eq!(&*b, &aux.snapshots[i][..aux.lengths[i]]);
                }
            }
            fn call(
                app: &mut A,
                aux: &mut Aux,
                cycle: usize,
                i: usize,
                postpone: bool,
            ) -> (coaptic::app::Call, MessageId, Token) {
                let phase = 1 + 2 * i;
                let outgoing = app.get("retained").to(PEER);
                let c = if postpone {
                    outgoing.non().send(time(cycle, phase))
                } else {
                    outgoing.send(time(cycle, phase))
                }
                .unwrap();
                let n = app.transport_mut().output_len.take().unwrap();
                app.transport_mut().sent += 1;
                let mut wire = [0; WIRE];
                wire[..n].copy_from_slice(&app.transport().output[..n]);
                aux.piv(0, &wire[..n]);
                let wire = decode(&wire[..n]).unwrap();
                let (r, binding) = if let Some(p) = aux.peer.as_mut() {
                    let (r, b) = p.unprotect_request(&wire, &mut aux.opened).unwrap();
                    (r, Some(b))
                } else {
                    (wire, None)
                };
                let t = r.token();
                let m = if postpone {
                    mid(cycle, 8)
                } else {
                    r.message_id()
                };
                assert_eq!(r.code(), Code::GET);
                let format = ContentFormat::OCTET_STREAM.encode();
                let opts = [Opt::etag(b"call"), Opt::content_format(&format)];
                let response = Message::new(
                    if postpone {
                        Type::NonConfirmable
                    } else {
                        Type::Acknowledgement
                    },
                    Code::CONTENT,
                    m,
                )
                .with_token(t)
                .with_options(&opts)
                .with_payload(b"retained-response");
                let io = app.transport_mut();
                let n = if let Some(p) = aux.peer.as_mut() {
                    p.protect_response(&response, binding.unwrap(), &mut io.input)
                        .unwrap()
                } else {
                    response.encode(&mut io.input).unwrap()
                };
                aux.token(t);
                aux.piv(1, &io.input[..n]);
                if postpone {
                    assert!(n <= 128);
                    aux.postponed[..n].copy_from_slice(&io.input[..n]);
                    aux.postponed_len = n;
                } else {
                    io.input_len = Some(n);
                    progress(app, &mut NoClock, None, cycle, time(cycle, phase + 1));
                    assert!(app.transport().output_len.is_none());
                }
                (c, m, t)
            }
            fn collect(
                app: &mut A,
                aux: &mut Aux,
                calls: &[(coaptic::app::Call, MessageId, Token)],
            ) {
                let mut buf = [0; 32];
                for (i, (c, m, t)) in calls.iter().copied().enumerate() {
                    let r = app
                        .take_response_into(c, &mut buf)
                        .unwrap()
                        .unwrap()
                        .unwrap();
                    assert_eq!(r.message_id(), Some(m));
                    assert_eq!(r.token(), Some(t));
                    assert_eq!(r.code(), Code::CONTENT);
                    assert_eq!(r.payload(), b"retained-response");
                    assert!(app.take_response_into(c, &mut buf).unwrap().is_none());
                    assert!(
                        !app.engine_mut()
                            .storage_mut()
                            .rx_datagram()
                            .is_occupied(aux.held[i].unwrap())
                    );
                    aux.held[i] = None;
                }
                assert_eq!(app.engine_mut().rx_occupied(), 0);
            }
            fn sentinel(app: &mut A, cycle: usize) -> SlotId {
                let id = app.engine_mut().acquire_tx().unwrap();
                let m = Message::new(Type::NonConfirmable, Code::CONTENT, mid(cycle, 0))
                    .with_token(token(cycle, 0))
                    .with_payload(b"fixture-owned-tx");
                app.engine_mut().encode_tx(id, &m).unwrap();
                app.engine_mut().set_tx_endpoint(id, PEER).unwrap();
                assert!(!app.engine_mut().tx_is_pinned(id));
                assert!(app.engine_mut().pending_con(id).is_none());
                id
            }
            fn release_sentinel(app: &mut A, id: SlotId, cycle: usize) {
                assert_eq!(app.engine_mut().tx_occupied(), 1);
                assert!(!app.engine_mut().tx_is_pinned(id));
                assert!(app.engine_mut().pending_con(id).is_none());
                assert_eq!(app.engine_mut().tx_endpoint(id), Some(PEER));
                let r = app.engine_mut().decode_tx(id).unwrap();
                assert_eq!(r.ty(), Type::NonConfirmable);
                assert_eq!(r.code(), Code::CONTENT);
                assert_eq!(r.message_id(), mid(cycle, 0));
                assert_eq!(r.token(), token(cycle, 0));
                assert_eq!(r.payload(), b"fixture-owned-tx");
                app.engine_mut().release_tx(id).unwrap();
                assert!(!app.engine_mut().storage_mut().tx_datagram().is_occupied(id));
            }
            fn simple<C: Clock>(
                app: &mut A,
                aux: &mut Aux,
                clock: &mut C,
                case: Case,
                cycle: usize,
                ids: [Option<SlotId>; 4],
            ) {
                let opts = [Opt::uri_path("bench")];
                let t = token(cycle, 1);
                if case == Case::Rx {
                    let c = call(app, aux, cycle, 0, false);
                    capture(app, aux, ids, 0, c.1, c.2);
                    exchange(
                        app,
                        aux,
                        clock,
                        cycle,
                        3,
                        t,
                        &opts,
                        Some(0),
                        Code::SERVICE_UNAVAILABLE,
                        &[],
                    );
                    retained(app, aux, 1);
                    collect(app, aux, &[c]);
                    exchange(
                        app,
                        aux,
                        clock,
                        cycle,
                        4,
                        token(cycle, 4),
                        &opts,
                        None,
                        Code::CONTENT,
                        &SMALL,
                    );
                } else {
                    if case == Case::Observe {
                        let reg = [Opt::observe_register(), Opt::uri_path("bench")];
                        exchange(
                            app,
                            aux,
                            clock,
                            cycle,
                            1,
                            t,
                            &reg,
                            None,
                            Code::CONTENT,
                            &SMALL,
                        );
                        assert!(
                            app.engine_mut()
                                .lookup_observe(coaptic::storage::ObserveKey::new(t, PEER))
                                .is_some()
                        );
                    }
                    let id = sentinel(app, cycle);
                    let cancel = [Opt::observe_deregister(), Opt::uri_path("bench")];
                    exchange(
                        app,
                        aux,
                        clock,
                        cycle,
                        2,
                        t,
                        if case == Case::Observe {
                            &cancel
                        } else {
                            &opts
                        },
                        Some(0),
                        Code::SERVICE_UNAVAILABLE,
                        &[],
                    );
                    assert_eq!(app.engine_mut().storage_mut().observe().occupied_count(), 0);
                    release_sentinel(app, id, cycle);
                    exchange(
                        app,
                        aux,
                        clock,
                        cycle,
                        3,
                        token(cycle, 3),
                        &opts,
                        None,
                        Code::CONTENT,
                        &SMALL,
                    );
                }
            }
            fn block<C: Clock>(
                app: &mut A,
                aux: &mut Aux,
                clock: &mut C,
                case: Case,
                cycle: usize,
                ids: [Option<SlotId>; 4],
            ) {
                let notification = case == Case::Notification;
                let negative = case == Case::Negative;
                let count = if notification || negative { 3 } else { 2 };
                let mut calls = [None; 3];
                for i in 0..count {
                    let c = call(app, aux, cycle, i, notification && i == 2);
                    calls[i] = Some(c);
                    if !(notification && i == 2) {
                        capture(app, aux, ids, i, c.1, c.2);
                        retained(app, aux, i + 1);
                    }
                }
                let t = token(cycle, 6);
                let b = BlockValue::new(0, false, 0).unwrap().encode();
                let reg = [
                    Opt::observe_register(),
                    Opt::uri_path("bench"),
                    Opt::block2(&b),
                ];
                let ordinary = [Opt::uri_path("bench"), Opt::block2(&b)];
                if negative {
                    exchange(
                        app,
                        aux,
                        clock,
                        cycle,
                        7,
                        t,
                        &ordinary,
                        None,
                        Code::SERVICE_UNAVAILABLE,
                        &[],
                    );
                    retained(app, aux, 3);
                    assert_eq!(HANDLERS.load(Ordering::SeqCst), cycle);
                    let known = [calls[0].unwrap(), calls[1].unwrap(), calls[2].unwrap()];
                    collect(app, aux, &known);
                    exchange(
                        app,
                        aux,
                        clock,
                        cycle,
                        8,
                        token(cycle, 8),
                        &[Opt::uri_path("bench")],
                        None,
                        Code::CONTENT,
                        &BODY,
                    );
                    return;
                }
                request(
                    app,
                    aux,
                    cycle,
                    6,
                    t,
                    if notification { &reg } else { &ordinary },
                );
                progress(app, &mut NoClock, None, cycle, time(cycle, 6));
                let observing = if let Some(p) = aux.peer.as_mut() {
                    aux.bindings -= 1;
                    Some(p.take(t).unwrap())
                } else {
                    None
                };
                let r = aux.output(app.transport_mut(), t, observing);
                verify(&r, mid(cycle, 6), t, Code::CONTENT, &BODY[..16]);
                let block = r.block2().unwrap().unwrap();
                assert_eq!((block.num(), block.szx(), block.more()), (0, 0, true));
                assert_eq!(r.observe(), if notification { Some(Ok(0)) } else { None });
                assert_eq!(HANDLERS.load(Ordering::SeqCst), cycle * case.counts().1 + 1);
                let mut assembled = [0; 64];
                let mut owned = None;
                let mut snapshot = None;
                if notification {
                    assert_eq!(
                        app.notify(time(cycle, 7), &["bench"], body_response())
                            .unwrap(),
                        1
                    );
                    let r = aux.output(app.transport_mut(), t, observing);
                    assert_eq!(r.ty(), Type::NonConfirmable);
                    assert_eq!(r.code(), Code::CONTENT);
                    assert_eq!(r.payload(), &BODY[..16]);
                    assert!(r.observe().unwrap().is_ok());
                    let b = r.block2().unwrap().unwrap();
                    assert_eq!((b.num(), b.szx(), b.more()), (0, 0, true));
                    assembled[..16].copy_from_slice(r.payload());
                    let key = coaptic::storage::BlockKey::new(t, PEER)
                        .with_identity(coaptic::storage::BodyTag::new(b"notify64").unwrap());
                    let id = app.engine_mut().lookup_tx_body(key).unwrap();
                    assert!(aux.body_ids.contains(&Some(id)));
                    owned = Some(id);
                    let transfer = app.engine_mut().tx_body_transfer(id).unwrap();
                    assert_eq!(transfer.key(), key);
                    assert_eq!(transfer.role(), coaptic::storage::BlockRole::OutgoingBlock2);
                    assert_eq!(transfer.filled(), 64);
                    snapshot = Some(transfer);
                    let io = app.transport_mut();
                    io.input[..aux.postponed_len]
                        .copy_from_slice(&aux.postponed[..aux.postponed_len]);
                    io.input_len = Some(aux.postponed_len);
                    progress(app, &mut NoClock, None, cycle, time(cycle, 8));
                    let c = calls[2].unwrap();
                    capture(app, aux, ids, 2, c.1, c.2);
                    retained(app, aux, 3);
                    assert_eq!(app.engine_mut().tx_body_transfer(owned.unwrap()), snapshot);
                } else {
                    assembled[..16].copy_from_slice(&BODY[..16]);
                    assert_eq!(
                        app.engine_mut()
                            .storage_mut()
                            .tx_body()
                            .unwrap()
                            .occupied_count(),
                        0
                    );
                }
                for num in 1..=3 {
                    let b = BlockValue::new(num, false, 0).unwrap().encode();
                    let opts = [Opt::uri_path("bench"), Opt::block2(&b)];
                    let phase = 8 + num as usize;
                    request(app, aux, cycle, phase, t, &opts);
                    let now = time(cycle, phase);
                    progress(app, clock, Some(num as usize - 1), cycle, now);
                    let r = aux.output(app.transport_mut(), t, None);
                    let start = num as usize * 16;
                    verify(
                        &r,
                        mid(cycle, phase),
                        t,
                        Code::CONTENT,
                        &BODY[start..start + 16],
                    );
                    let b = r.block2().unwrap().unwrap();
                    assert_eq!((b.num(), b.szx(), b.more()), (num, 0, num < 3));
                    assert!(r.observe().is_none());
                    assert_eq!(r.etag().next(), Some(&b"notify64"[..]));
                    assembled[start..start + 16].copy_from_slice(r.payload());
                    retained(app, aux, count);
                    assert_eq!(
                        HANDLERS.load(Ordering::SeqCst),
                        cycle * case.counts().1 + if notification { 1 } else { 1 + num as usize }
                    );
                    let occupied = app
                        .engine_mut()
                        .storage_mut()
                        .tx_body()
                        .unwrap()
                        .occupied_count();
                    if notification && num < 3 {
                        let id = owned.unwrap();
                        assert_eq!(occupied, 1);
                        assert!(!app.engine_mut().tx_body_is_pinned(id));
                        assert_eq!(app.engine_mut().tx_body_payload(id), Some(&BODY[..]));
                        assert_eq!(app.engine_mut().tx_body_transfer(id), snapshot);
                    } else {
                        assert_eq!(occupied, 0);
                        if let Some(id) = owned {
                            assert!(app.engine_mut().tx_body_transfer(id).is_none());
                        }
                    }
                }
                assert_eq!(assembled, BODY);
                if notification {
                    let known = [calls[0].unwrap(), calls[1].unwrap(), calls[2].unwrap()];
                    collect(app, aux, &known);
                    let cancel = [Opt::observe_deregister(), Opt::uri_path("bench")];
                    exchange(
                        app,
                        aux,
                        clock,
                        cycle,
                        12,
                        t,
                        &cancel,
                        None,
                        Code::CONTENT,
                        &BODY,
                    );
                    assert!(
                        app.engine_mut()
                            .lookup_observe(coaptic::storage::ObserveKey::new(t, PEER))
                            .is_none()
                    );
                } else {
                    let known = [calls[0].unwrap(), calls[1].unwrap()];
                    collect(app, aux, &known);
                }
                exchange(
                    app,
                    aux,
                    clock,
                    cycle,
                    13,
                    token(cycle, 13),
                    &[Opt::uri_path("bench")],
                    None,
                    Code::CONTENT,
                    &BODY,
                );
            }
            pub fn execute<C: Clock>(
                case: Case,
                protected: bool,
                clock: &mut C,
                cycles: usize,
            ) -> Report {
                let (server, peer) = pair(protected);
                let mut app = $factory(server);
                let mut aux = Aux::new(peer);
                let ids = inventory(&mut app);
                if $large {
                    let pool = app.engine_mut().storage_mut().tx_body().unwrap();
                    let cursor = pool.cursor();
                    for i in 0..2 {
                        aux.body_ids[i] = Some(pool.acquire().unwrap());
                    }
                    for id in aux.body_ids.into_iter().flatten() {
                        pool.release(id).unwrap();
                    }
                    assert_eq!(pool.occupied_count(), 0);
                    assert_eq!(pool.cursor(), cursor);
                }
                let caps = app.engine_mut().capacities();
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
                assert_eq!(seq(&app), 0);
                assert_eq!(aux.peer.as_ref().map(|p| p.sender_seq()).unwrap_or(0), 0);
                for cycle in 0..cycles {
                    empty(&mut app, false);
                    progress(&mut app, &mut NoClock, None, cycle, time(cycle, 0));
                    empty(&mut app, true);
                    let before = app.metrics();
                    let inputs = app.transport().received;
                    let outputs = app.transport().sent;
                    let handlers = HANDLERS.load(Ordering::SeqCst);
                    if $large {
                        block(&mut app, &mut aux, clock, case, cycle, ids)
                    } else {
                        simple(&mut app, &mut aux, clock, case, cycle, ids)
                    }
                    let after = app.metrics();
                    let expected = case.metrics();
                    for i in 0..7 {
                        assert_eq!(selected(after)[i] - selected(before)[i], expected[i]);
                    }
                    let (datagrams, h) = case.counts();
                    assert_eq!(
                        app.transport().received - inputs + app.transport().sent - outputs,
                        datagrams
                    );
                    assert_eq!(HANDLERS.load(Ordering::SeqCst) - handlers, h);
                    // Accepted packets and successful Engine sends must account for every IO
                    // event. Idle progress and due dedup expiry are expected; no eviction is
                    // used to supply admission credit, verified by each owner's snapshot.
                    assert_eq!(
                        u64::from(after.rx_accepted - before.rx_accepted),
                        app.transport().received - inputs
                    );
                    assert_eq!(
                        u64::from(after.tx_ok - before.tx_ok),
                        app.transport().sent - outputs
                    );
                    assert_eq!(
                        (
                            after.token_capacity_refused,
                            after.hard_rx_exhausted,
                            after.hard_tx_exhausted,
                            after.rx_error,
                            after.tx_fail,
                            after.con_retransmit,
                            after.give_up,
                            after.saturated,
                            after.nstart_reject,
                            after.empty_ack,
                            after.empty_rst
                        ),
                        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                    );
                    assert_eq!((after.block1_assemble, after.block2_assemble), (0, 0));
                    assert!(after.progress > before.progress);
                    // Every incoming request has one inline replay row. Exact
                    // key census detects eviction/replacement as well as extra
                    // cache work; no row may pin a TX packet to hide pressure.
                    let phases: &[usize] = match case {
                        Case::Rx => &[3, 4],
                        Case::Tx => &[2, 3],
                        Case::Observe => &[1, 2, 3],
                        Case::Notification => &[6, 9, 10, 11, 12, 13],
                        Case::Ordinary => &[6, 9, 10, 11, 13],
                        Case::Negative => &[7, 8],
                    };
                    assert_eq!(
                        app.engine_mut().storage_mut().dedup().occupied_count(),
                        phases.len()
                    );
                    for phase in phases {
                        let row = app
                            .engine_mut()
                            .lookup_dedup(coaptic::storage::DedupKey::new(mid(cycle, *phase), PEER))
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
                    assert_eq!(seq(&app), aux.fresh[0]);
                    assert_eq!(
                        aux.peer.as_ref().map(|p| p.sender_seq()).unwrap_or(0),
                        aux.fresh[1]
                    );
                    empty(&mut app, false);
                }
                progress(&mut app, &mut NoClock, None, cycles, 279744000);
                empty(&mut app, true);
                let heap = if $large {
                    coaptic::storage::AllocMemory::<Token>::required_heap_bytes(caps).unwrap()
                } else {
                    0
                };
                Report {
                    app_inline: size_of_val(&app),
                    app_heap: heap,
                    aux_inline: size_of_val(&aux),
                    peer_nested: size_of_val(&aux.peer),
                    metrics: selected(app.metrics()),
                    datagrams: app.transport().received + app.transport().sent,
                    handlers: HANDLERS.load(Ordering::SeqCst),
                    sequences: aux.fresh,
                    max_piv: aux.max_piv,
                }
            }
        }
    };
}
driver!(fixed, SmallApp, small, false);
driver!(allocated, LargeApp, large, true);

struct Report {
    app_inline: usize,
    app_heap: usize,
    aux_inline: usize,
    peer_nested: usize,
    metrics: [u32; 7],
    datagrams: u64,
    handlers: usize,
    sequences: [u64; 2],
    max_piv: usize,
}
fn execute<C: Clock>(case: Case, protected: bool, clock: &mut C, cycles: usize) -> Report {
    if case.large() {
        allocated::execute(case, protected, clock, cycles)
    } else {
        fixed::execute(case, protected, clock, cycles)
    }
}
pub fn run(case: Case, protected: bool, timing: bool) {
    // Poison recovery is confined to independent test fixtures: reset these three
    // handler-only globals, and allocate a fresh App/context pair in execute.
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    HANDLERS.store(0, Ordering::SeqCst);
    LARGE.store(usize::from(case.large()), Ordering::SeqCst);
    OBSERVABLE.store(
        usize::from(matches!(case, Case::Observe | Case::Notification)),
        Ordering::SeqCst,
    );
    if timing {
        assert!(case != Case::Negative);
        let mut clock = RealClock::new();
        let r = execute(case, protected, &mut clock, 1128);
        emit(case, protected, &clock, r);
    } else {
        let _r = execute(case, protected, &mut NoClock, 16);
        let stdout = std::io::stdout();
        let mut w = BufWriter::with_capacity(8192, stdout.lock());
        writeln!(w,"\nCOAPTIC_STAGE_B_QUALIFICATION {{\"schema\":\"coaptic-admission-stage-b-qualification/1\",\"contract_sha256\":\"{}\",\"case\":\"{}\",\"security\":\"{}\",\"cycles\":16,\"passed\":true,\"measurement\":\"NOT RUN\"}}",super::HASH,case.id(),if protected{"oscore"}else{"unprotected"}).unwrap();
        w.flush().unwrap();
    }
}
fn array(w: &mut impl Write, a: &[u128]) {
    write!(w, "[").unwrap();
    for (i, n) in a.iter().enumerate() {
        if i > 0 {
            write!(w, ",").unwrap();
        }
        write!(w, "{n}").unwrap();
    }
    write!(w, "]").unwrap();
}
fn emit(case: Case, protected: bool, clock: &RealClock, r: Report) {
    let labels = case.labels();
    for values in &clock.latencies[..labels.len()] {
        assert!(values.iter().sum::<u128>() > 0);
    }
    // Sum declared auxiliary owners; nested arrays/context are already in Aux
    // and RealClock. Local protocol descriptors/scratch are counted separately.
    // Compiler-created moves, initialization and peak stack remain unknown.
    let fixture_inline = r.aux_inline
        + size_of::<RealClock>()
        + size_of::<Report>()
        + size_of::<BufWriter<std::io::StdoutLock<'_>>>()
        + size_of::<[u8; WIRE]>() * 2
        + size_of::<[u8; 64]>()
        + size_of::<[u8; 32]>()
        + size_of::<[Option<(coaptic::app::Call, MessageId, Token)>; 3]>()
        + size_of::<[(coaptic::app::Call, MessageId, Token); 3]>()
        + size_of::<[Option<SlotId>; 4]>()
        + size_of::<Option<coaptic::storage::BlockTransfer>>()
        + size_of::<Option<RequestRef>>()
        + size_of::<[Opt<'_>; 3]>() * 3
        + size_of::<Message<'_>>() * 2
        + size_of::<coaptic::message::ParsedMessage<'_>>() * 3
        + size_of::<Metrics>() * 2
        + size_of::<Capacities>()
        // Scalar loop indices, lengths, IO snapshots and report/writer counters.
        + size_of::<usize>() * 16
        + size_of::<u64>() * 8;
    let fixture_heap = 8192;
    let total = fixture_inline + fixture_heap;
    assert!(total <= 262144);
    let stdout = std::io::stdout();
    let mut w = BufWriter::with_capacity(8192, stdout.lock());
    write!(w,"\nCOAPTIC_STAGE_B_RESULT {{\"schema\":\"coaptic-admission-stage-b-native/1\",\"contract_sha256\":\"{}\",\"contract\":{},\"case\":\"{}\",\"security\":\"{}\",\"profile\":\"{}\",\"operations\":1000,\"warmup\":128,\"calibration_samples\":4096,\"verified_cycles\":1128,\"latencies_ns\":{{",super::HASH,super::CONTRACT.trim(),case.id(),if protected{"oscore"}else{"unprotected"},if case.large(){"Default"}else{"SmallDevice"}).unwrap();
    for (i, label) in labels.iter().enumerate() {
        if i > 0 {
            write!(w, ",").unwrap();
        }
        write!(w, "\"{label}\":").unwrap();
        array(&mut w, &clock.latencies[i]);
    }
    write!(w, "}},\"calibration_ns\":").unwrap();
    array(&mut w, &clock.calibration);
    write!(w,",\"internal_datagrams\":{},\"udp_datagrams\":0,\"handler_calls\":{},\"clock_ms\":[0,279744000],\"metrics\":{{",r.datagrams,r.handlers).unwrap();
    for (i, k) in [
        "admission_rx_refused",
        "admission_tx_refused",
        "admission_refusal_sent",
        "admission_refusal_unsent",
        "observe_register",
        "observe_cancel",
        "observe_notify",
    ]
    .iter()
    .enumerate()
    {
        if i > 0 {
            write!(w, ",").unwrap();
        }
        write!(w, "\"{k}\":{}", r.metrics[i]).unwrap();
    }
    write!(w, "}},\"sender_sequences\":").unwrap();
    if protected {
        assert_eq!(r.max_piv, 2);
        write!(w,"{{\"app\":[0,{}],\"peer\":[0,{}],\"fresh_app\":{},\"fresh_peer\":{},\"max_piv_bytes\":2}}",r.sequences[0],r.sequences[1],r.sequences[0],r.sequences[1]).unwrap();
    } else {
        write!(w, "null").unwrap();
    }
    write!(w,",\"memory\":{{\"app_inline_bytes\":{},\"app_pool_requested_heap_bytes\":{},\"fixture_inline_bytes\":{fixture_inline},\"fixture_requested_heap_bytes\":{fixture_heap},\"fixture_total_requested_bytes\":{total},\"peer_context_nested_bytes\":{},\"latency_bytes\":48000,\"calibration_bytes\":65536,\"token_ledger_bytes\":27072,\"serializer_buffer_bytes\":8192,\"remaining\":\"allocator/runtime/initialization/peak-stack costs unknown\"}},\"settled\":{{\"calls_collected_once\":true,\"peer_bindings_consumed\":true,\"rx_empty\":true,\"tx_empty\":true,\"observe_empty\":true,\"bodies_empty\":true,\"pending_empty\":true,\"io_empty\":true,\"dedup_expired\":true}}}}",r.app_inline,r.app_heap,r.peer_nested).unwrap();
    writeln!(w).unwrap();
    w.flush().unwrap();
}
