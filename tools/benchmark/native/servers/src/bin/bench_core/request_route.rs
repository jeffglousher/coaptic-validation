//! Finite, socket-free full-App route trace. The method is frozen before data.
use super::*;
use coaptic::message::{OptionNumber, ParsedMessage};
use coaptic::oscore::SecurityContext;
use std::cell::Cell;
use std::mem::{align_of_val, size_of, size_of_val};

const METHOD: &str = "ab04a97d50ff7ed244614ef409f0abb2209cea0cae4c15b80e5d1fc49aa4aa98";
const CAP_0: &str = r#"{"associations":1,"block_wise":false,"calls":1,"dedup":4,"deferred":0,"observe":2,"routes":4,"rx":{"bytes":1152,"slots":2},"rx_body":{"bytes":0,"slots":0},"security_requests":4,"tx":{"bytes":1152,"slots":2},"tx_body":{"bytes":0,"slots":0}}"#;
const CAP_1: &str = r#"{"associations":1,"block_wise":false,"calls":1,"dedup":4,"deferred":0,"observe":2,"routes":4,"rx":{"bytes":1152,"slots":2},"rx_body":{"bytes":0,"slots":0},"security_requests":4,"tx":{"bytes":1152,"slots":2},"tx_body":{"bytes":0,"slots":0}}"#;
const CAP_2: &str = r#"{"associations":1,"block_wise":true,"calls":4,"dedup":8,"deferred":0,"observe":4,"routes":8,"rx":{"bytes":1472,"slots":4},"rx_body":{"bytes":1024,"slots":1},"security_requests":4,"tx":{"bytes":1472,"slots":4},"tx_body":{"bytes":1024,"slots":2}}"#;
const CAP_3: &str = r#"{"associations":1,"block_wise":true,"calls":4,"dedup":8,"deferred":0,"observe":4,"routes":32,"rx":{"bytes":1472,"slots":4},"rx_body":{"bytes":1024,"slots":1},"security_requests":4,"tx":{"bytes":1472,"slots":4},"tx_body":{"bytes":1024,"slots":2}}"#;
const CAP_4: &str = r#"{"associations":1,"block_wise":true,"calls":4,"dedup":8,"deferred":0,"observe":4,"routes":32,"rx":{"bytes":1472,"slots":4},"rx_body":{"bytes":1024,"slots":1},"security_requests":4,"tx":{"bytes":1472,"slots":4},"tx_body":{"bytes":1024,"slots":2}}"#;
const OPS: usize = 8000;
const WARM: usize = 128;
const CAL: usize = 4096;
const OWNER_CAP: usize = 262144;
const OUTPUT_CAP: usize = 2097152;
// RFC9290 map: title(-1), response-code(-4); independent frozen literals.
const NOT_FOUND: &[u8] = b"\xa2\x20\x69Not Found\x23\x18\x84";
const NOT_ALLOWED: &[u8] = b"\xa2\x20\x71Method Not Allowed\x23\x18\x85";
const PATHS: [&str; 34] = [
    "r00",
    "r01",
    "r02",
    "r03",
    "r04",
    "r05",
    "r06",
    "r07",
    "r08",
    "r09",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "common/prefix/p16",
    "common/prefix/p17",
    "common/prefix/p18",
    "common/prefix/p19",
    "common/prefix/p20",
    "common/prefix/p21",
    "common/prefix/p22",
    "common/prefix/p23",
    "common/prefix/p24",
    "common/prefix/p25",
    "common/prefix/p26",
    "common/prefix/p27",
    "common/prefix/p28",
    "common/prefix/p29",
    "common/prefix/p30",
    "r31",
    "new/a",
    "new/b",
];
// Each thread owns one trace, including parallel unit tests. Refuse counter overflow.
thread_local! { static CALLS: Cell<u32> = const { Cell::new(0) }; }
fn calls() -> u32 {
    CALLS.get()
}
fn reset_calls() {
    CALLS.set(0);
}
const fn bodies<const L: usize>() -> [[u8; L]; 34] {
    let mut result = [[0x5a; L]; 34];
    let mut tag = 0;
    while tag < 34 {
        result[tag][L - 1] = tag as u8;
        tag += 1;
    }
    result
}
static SMALL_BODIES: [[u8; 32]; 34] = bodies();
static DEFAULT_BODIES: [[u8; 64]; 34] = bodies();
struct Identity<const TAG: u8, const LEN: usize>;
impl<const TAG: u8, const LEN: usize> Identity<TAG, LEN> {
    fn serve(_: Request<'_>) -> Response<'static> {
        CALLS.set(calls().checked_add(1).expect("finite handler count"));
        let body: &'static [u8] = if LEN == 32 {
            &SMALL_BODIES[TAG as usize]
        } else {
            &DEFAULT_BODIES[TAG as usize]
        };
        Response::content(body)
            .content_format(ContentFormat::OCTET_STREAM)
            .etag(b"fixture")
    }
}
fn handler<const L: usize>(tag: usize) -> fn(Request<'_>) -> Response<'static> {
    macro_rules! select { ($($n:literal),*) => { match tag { $($n => Identity::<$n,L>::serve,)* _ => unreachable!("bounded tag") } }; }
    select!(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33
    )
}
#[derive(Clone, Copy)]
struct Group {
    id: &'static str,
    routes: usize,
    registered: usize,
    body: usize,
    cases: usize,
    expected: u32,
}
const GROUPS: [Group; 5] = [
    Group {
        id: "small_one",
        routes: 4,
        registered: 1,
        body: 32,
        cases: 1,
        expected: 8128,
    },
    Group {
        id: "small_full",
        routes: 4,
        registered: 4,
        body: 32,
        cases: 4,
        expected: 6096,
    },
    Group {
        id: "default8_full",
        routes: 8,
        registered: 8,
        body: 64,
        cases: 4,
        expected: 6096,
    },
    Group {
        id: "default32_full",
        routes: 32,
        registered: 32,
        body: 64,
        cases: 8,
        expected: 5080,
    },
    Group {
        id: "default32_sparse",
        routes: 32,
        registered: 4,
        body: 64,
        cases: 4,
        expected: 6096,
    },
];
#[derive(Clone, Copy)]
struct Case {
    id: &'static str,
    path: &'static str,
    tag: Option<u8>,
    put: bool,
}
fn case(g: Group, operation: usize) -> Case {
    let i = operation % g.cases;
    let (id, tag, path, put) = if g.id == "default32_sparse" {
        match i {
            0 => ("first", Some(0), PATHS[0], false),
            1 => ("last", Some(31), PATHS[31], false),
            2 => ("reused", Some(33), PATHS[33], false),
            _ => ("miss", None, "r99", false),
        }
    } else {
        match i {
            0 => ("first", Some(0), PATHS[0], false),
            1 => {
                let tag = g.routes / 2;
                ("middle", Some(tag as u8), PATHS[tag], false)
            }
            2 => {
                let tag = if g.routes == 4 { 3 } else { g.routes - 1 };
                ("last", Some(tag as u8), PATHS[tag], false)
            }
            3 => ("miss", None, "r99", false),
            4 => ("shared_prefix_hit", Some(30), PATHS[30], false),
            5 => ("shared_prefix_miss", None, "common/prefix/p99", false),
            6 => ("method_405", None, "r31", true),
            _ => {
                let tag = if (operation / 8) % 10 == 9 { 31 } else { 0 };
                ("common", Some(tag), PATHS[tag as usize], false)
            }
        }
    };
    Case { id, path, tag, put }
}
fn contexts(
    protected: bool,
) -> Result<(Option<SecurityContext>, Option<SecurityContext>), Failure> {
    if !protected {
        return Ok((None, None));
    }
    let mut material = [0; 24];
    getrandom::fill(&mut material)?;
    let result = (|| {
        let derive = |sender_id, recipient_id| {
            SecurityContext::derive(coaptic::oscore::DeriveParams {
                master_secret: &material[..16],
                master_salt: &material[16..],
                sender_id,
                recipient_id,
                id_context: &[],
            })
        };
        Ok((Some(derive(&[], &[1])?), Some(derive(&[1], &[])?)))
    })();
    material.fill(0);
    black_box(&mut material);
    result
}
macro_rules! register {
    ($builder:ident,$g:expr,$len:literal) => {{
        let g = $g;
        let full = if g.id == "default32_sparse" {
            32
        } else {
            g.registered
        };
        for (tag, path) in PATHS[..full].iter().enumerate() {
            $builder.try_route(*path, get(handler::<$len>(tag)))?;
        }
        if g.id == "default32_sparse" {
            for path in &PATHS[1..31] {
                if !$builder.remove_route(*path)? {
                    return Err("missing removal".into());
                }
            }
            for tag in [32, 33] {
                $builder.try_route(PATHS[tag], get(handler::<$len>(tag)))?;
            }
        }
    }};
}
fn small(g: Group, server: Option<SecurityContext>) -> Result<SmallApp, Failure> {
    let mut b = App::with_resources(coaptic::resources::SmallDevice::new())
        .randomness(|bytes| getrandom::fill(bytes).is_ok());
    register!(b, g, 32);
    let b = if let Some(c) = server {
        b.oscore(c)
    } else {
        b.allow_unprotected()
    };
    Ok(b.bind(core_io())?)
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
type DefaultApp<const N: usize> =
    App<coaptic::profiles::Default, CoreIo, N, true, coaptic::storage::AllocMemory>;
fn default<const N: usize>(
    g: Group,
    server: Option<SecurityContext>,
) -> Result<DefaultApp<N>, Failure> {
    let mut b = App::builder()
        .routes::<N>()
        .block_wise::<true>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok());
    register!(b, g, 64);
    let b = if let Some(c) = server {
        b.oscore(c)
    } else {
        b.allow_unprotected()
    };
    Ok(b.bind_alloc(core_io(), capacities())?)
}
fn prepare(
    io: &mut CoreIo,
    client: &mut Option<SecurityContext>,
    operation: usize,
    c: Case,
) -> Result<(MessageId, Token), Failure> {
    if io.input_len.is_some() || io.output_len.is_some() {
        return Err("extra pending IO".into());
    }
    if operation >= OPS + WARM {
        return Err("operation bound".into());
    }
    let mid = MessageId::new(operation as u16);
    let token = Token::new(&(operation as u64).to_be_bytes()).ok_or("token")?;
    if client.as_ref().is_some_and(|x| x.lookup(token).is_some()) {
        return Err("old binding".into());
    }
    let mut options = [Opt::uri_path(""); 3];
    let mut n = 0;
    for segment in c.path.split('/') {
        *options.get_mut(n).ok_or("path bound")? = Opt::uri_path(segment);
        n += 1;
    }
    let msg = Message::con(if c.put { Code::PUT } else { Code::GET }, mid, token)
        .with_options(&options[..n]);
    io.input_len = Some(if let Some(context) = client.as_mut() {
        context.protect_request(&msg, &mut io.input)?
    } else {
        msg.encode(&mut io.input)?
    });
    Ok((mid, token))
}
fn verify(
    reply: &ParsedMessage<'_>,
    mid: MessageId,
    token: Token,
    c: Case,
    body: usize,
) -> Result<(), Failure> {
    if reply.ty() != Type::Acknowledgement || reply.message_id() != mid || reply.token() != token {
        return Err("response envelope".into());
    }
    let mut options = reply.options();
    if let Some(tag) = c.tag {
        if reply.code() != Code::CONTENT
            || reply.payload().len() != body
            || reply.payload().last() != Some(&tag)
            || reply.payload()[..body - 1].iter().any(|&b| b != 0x5a)
            || options.next() != Some(Opt::new(OptionNumber::ETAG, b"fixture"))
            || options.next() != Some(Opt::new(OptionNumber::CONTENT_FORMAT, &[42]))
        {
            return Err("hit metadata/body".into());
        }
    } else {
        let (code, payload) = if c.put {
            (Code::METHOD_NOT_ALLOWED, NOT_ALLOWED)
        } else {
            (Code::NOT_FOUND, NOT_FOUND)
        };
        if reply.code() != code
            || reply.payload() != payload
            || options.next() != Some(Opt::new(OptionNumber::CONTENT_FORMAT, &[1, 1]))
        {
            return Err("problem metadata/body".into());
        }
    }
    if options.next().is_some() {
        return Err("extra response option".into());
    }
    Ok(())
}
fn response(
    io: &mut CoreIo,
    client: &mut Option<SecurityContext>,
    opened: &mut [u8; WIRE],
    mid: MessageId,
    token: Token,
    c: Case,
    body: usize,
) -> Result<(), Failure> {
    if io.input_len.is_some() {
        return Err("input not consumed".into());
    }
    let n = io.output_len.take().ok_or("missing response")?;
    if !(1..=WIRE).contains(&n) {
        return Err("output bound".into());
    }
    let wire = decode(&io.output[..n])?;
    let protected = client.is_some();
    let reply = if let Some(context) = client.as_mut() {
        let binding = context.take(token).ok_or("missing binding")?;
        context.unprotect_response(&wire, binding, opened)?
    } else {
        wire
    };
    // Check outer metadata only after authenticating the protected response.
    if protected {
        let mut options = wire.options();
        if wire.ty() != Type::Acknowledgement
            || wire.message_id() != mid
            || wire.token() != token
            || wire.code() != Code::CHANGED
            || options
                .next()
                .is_none_or(|o| o.number() != OptionNumber::OSCORE)
            || options.next().is_some()
        {
            return Err("protected outer metadata".into());
        }
    }
    verify(&reply, mid, token, c, body)?;
    if client.as_ref().is_some_and(|x| x.lookup(token).is_some()) {
        return Err("binding leak".into());
    }
    Ok(())
}
fn count(before: u32, after: u32, hit: bool) -> Result<(), Failure> {
    if after.checked_sub(before) != Some(u32::from(hit)) {
        return Err("handler count".into());
    }
    Ok(())
}
fn state(
    u: coaptic::app::AppUsage,
    g: Group,
    protected: bool,
    complete: bool,
) -> Result<(), Failure> {
    let s = u.storage;
    let small = g.body == 32;
    let expected_calls = if small { 1 } else { 4 };
    if u.client_requests.capacity != expected_calls
        || u.client_replies.capacity != expected_calls
        || u.deferred.capacity != 0
        || s.rx_datagram.capacity != if small { 2 } else { 4 }
        || s.tx_datagram.capacity != if small { 2 } else { 4 }
        || s.dedup.capacity != if small { 4 } else { 8 }
        || s.observe.capacity != if small { 2 } else { 4 }
        || (small && (s.rx_body.is_some() || s.tx_body.is_some()))
        || (!small
            && (s.rx_body.is_none_or(|x| x.capacity != 1)
                || s.tx_body.is_none_or(|x| x.capacity != 2)))
    {
        return Err("capacity configuration".into());
    }
    if u.routes.occupied != g.registered
        || u.routes.capacity != g.routes
        || u.client_requests.occupied != 0
        || u.client_replies.occupied != 0
        || u.completed_replies != 0
        || u.client_cooldowns != 0
        || u.deferred.occupied != 0
        || u.revoked_associations != 0
        || u.security
            .is_none_or(|x| x.occupied != usize::from(protected) || x.capacity != 1)
        || s.rx_datagram.occupied != 0
        || s.tx_datagram.occupied != 0
        || s.observe.occupied != 0
        || s.rx_body.is_some_and(|x| x.occupied != 0)
        || s.tx_body.is_some_and(|x| x.occupied != 0)
        || (complete && s.dedup.occupied != s.dedup.capacity)
    {
        return Err("state leak/configuration".into());
    }
    Ok(())
}
struct Step {
    elapsed: Option<u128>,
    request_piv: Option<usize>,
    response_piv: bool,
}
fn piv(wire: &ParsedMessage<'_>) -> Result<Option<(u64, usize)>, Failure> {
    wire.get_option(OptionNumber::OSCORE)
        .map(|o| {
            coaptic::oscore::OscoreHeader::parse(o.value())
                .map(|h| h.piv.map(|p| (p.seq(), p.as_bytes().len())))
        })
        .transpose()
        .map(|p| p.flatten())
        .map_err(Into::into)
}
fn step<P, S, const N: usize, const B: bool, const D: usize, const C: usize>(
    app: &mut App<P, CoreIo, N, B, S, D, C>,
    client: &mut Option<SecurityContext>,
    operation: usize,
    g: Group,
    opened: &mut [u8; WIRE],
    timed: bool,
) -> Result<Step, Failure>
where
    P: MemoryLayout<B> + AppAssembled<B>,
    S: AppStorage<Token = Token>,
    P: coaptic::storage::MemoryProfile<Token = Token>,
{
    let c = case(g, operation);
    let (mid, token) = prepare(app.transport_mut(), client, operation, c)?;
    let request_piv = piv(&decode(
        &app.transport().input[..app.transport().input_len.ok_or("missing prepared input")?],
    )?)?;
    if client.is_some() && request_piv.map(|p| p.0) != Some(operation as u64) {
        return Err("request PIV sequence".into());
    }
    let checkpoint = app.oscore().map(|c| c.replay_checkpoint());
    let before = calls();
    let elapsed = if timed {
        let start = Instant::now();
        let outcome = black_box(black_box(&mut *app).poll(black_box(1)));
        let ns = start.elapsed().as_nanos();
        outcome.map_err(|_| "poll failure")?;
        Some(ns)
    } else {
        black_box(black_box(&mut *app).poll(black_box(1))).map_err(|_| "poll failure")?;
        None
    };
    count(before, calls(), c.tag.is_some())?;
    let response_piv = {
        let io = app.transport();
        let n = io.output_len.ok_or("missing response")?;
        if n > WIRE {
            return Err("output bound".into());
        }
        piv(&decode(&io.output[..n])?)?
    };
    response(app.transport_mut(), client, opened, mid, token, c, g.body)?;
    state(
        app.resource_usage(),
        g,
        client.is_some(),
        operation >= WARM - 1,
    )?;
    if let Some(previous) = checkpoint {
        previous.validate_successor(app.oscore().ok_or("lost context")?.replay_checkpoint())?;
    }
    Ok(Step {
        elapsed,
        request_piv: request_piv.map(|p| p.1),
        response_piv: response_piv.is_some(),
    })
}
// Streaming writer bounds the entire JSON without an array clone or output String.
struct Bounded<W: Write> {
    inner: W,
    bytes: usize,
}
impl<W: Write> Write for Bounded<W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if b.len() > OUTPUT_CAP - self.bytes {
            return Err(std::io::Error::other("output cap"));
        }
        let n = self.inner.write(b)?;
        self.bytes += n;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
fn optional(w: &mut impl Write, n: Option<u64>) -> Result<(), Failure> {
    if let Some(n) = n {
        write!(w, "{n}")?;
    } else {
        write!(w, "null")?;
    }
    Ok(())
}
fn array(w: &mut impl Write, a: &[u128]) -> Result<(), Failure> {
    write!(w, "[")?;
    for (i, n) in a.iter().enumerate() {
        if i != 0 {
            write!(w, ",")?;
        }
        write!(w, "{n}")?;
    }
    write!(w, "]")?;
    Ok(())
}
fn drive<P, S, const N: usize, const B: bool, const D: usize, const C: usize>(
    mut app: App<P, CoreIo, N, B, S, D, C>,
    mut client: Option<SecurityContext>,
    g: Group,
    measure: bool,
) -> Result<(), Failure>
where
    P: MemoryLayout<B> + AppAssembled<B> + coaptic::storage::MemoryProfile<Token = Token>,
    S: AppStorage<Token = Token>,
{
    reset_calls();
    state(app.resource_usage(), g, client.is_some(), false)?;
    let mut latencies = Vec::<u128>::with_capacity(if measure { OPS } else { 0 });
    let mut calibration = Vec::<u128>::with_capacity(if measure { CAL } else { 0 });
    let latency_backing = latencies.capacity() * size_of::<u128>();
    let calibration_backing = calibration.capacity() * size_of::<u128>();
    let array_headers = 2 * size_of::<Vec<u128>>();
    let client_context = size_of_val(&client) + size_of::<coaptic::oscore::RequestRef>();
    // Pinned A/B protect.rs declares INNER=1280, OptionsBuilder<16>,
    // a 30-byte encoded OSCORE option, nonce13 and Aad backing32+usize.
    // Count these source-declared client crypto scratch owners once per call
    // path, separately from App/server scratch; backend/compiler frames unknown.
    let auth_common = 1280
        + size_of::<coaptic::message::OptionsBuilder<'_, 16>>()
        + 32
        + size_of::<usize>()
        + coaptic::oscore::NONCE_LEN;
    let request_auth = if client.is_some() {
        auth_common + 30 + size_of::<Message<'_>>()
    } else {
        0
    };
    let verification_auth = if client.is_some() {
        auth_common + size_of::<Message<'_>>()
    } else {
        0
    };
    let request_scratch = 3 * size_of::<Opt<'_>>()
        + size_of::<Message<'_>>()
        + size_of::<MessageId>()
        + size_of::<Token>()
        + request_auth;
    let verification_scratch = WIRE + 2 * size_of::<ParsedMessage<'_>>() + verification_auth;
    // The three case arrays, histogram and scalar census/counter owners below.
    // Counter metadata is counted once even though copied values are printed.
    let metadata = 3 * size_of::<[u32; 8]>()
        + size_of::<[u32; 6]>()
        + 6 * size_of::<u32>()
        + size_of::<Cell<u32>>();
    let serialization_scratch = size_of::<Bounded<std::io::StdoutLock<'static>>>()
        + size_of::<std::fmt::Arguments<'static>>();
    let entropy_scratch = 24;
    let static_data = size_of_val(&SMALL_BODIES)
        + size_of_val(&DEFAULT_BODIES)
        + size_of_val(&PATHS)
        + size_of_val(&GROUPS)
        + PATHS.iter().map(|p| p.len()).sum::<usize>()
        + GROUPS.iter().map(|g| g.id.len()).sum::<usize>()
        + METHOD.len()
        + NOT_FOUND.len()
        + NOT_ALLOWED.len()
        + CAP_0.len()
        + CAP_1.len()
        + CAP_2.len()
        + CAP_3.len()
        + CAP_4.len();
    // Further explicit non-App bookkeeping owners: current group/case/step,
    // capacities and AppUsage snapshots, four sequence endpoints, the ledger
    // scalar fields themselves. No server context or nested transport is added.
    // Construction/protection library temporaries, generated stack/futures,
    // allocator/runtime and physical static placement remain unknown.
    let other_explicit = size_of::<Group>()
        + size_of::<Case>()
        + size_of::<Step>()
        + size_of::<Capacities>()
        + size_of::<coaptic::app::AppUsage>()
        + 4 * size_of::<Option<u64>>()
        + 18 * size_of::<usize>();
    let owners = latency_backing
        + calibration_backing
        + array_headers
        + client_context
        + request_scratch
        + verification_scratch
        + metadata
        + serialization_scratch
        + entropy_scratch
        + static_data
        + other_explicit;
    if (measure && (latency_backing != 128000 || calibration_backing != 65536))
        || owners > OWNER_CAP
    {
        return Err("fixture owner cap/backing".into());
    }
    let caps = app.engine().capacities();
    let small = g.body == 32;
    if caps.rx_datagram_bytes != if small { 1152 } else { 1472 }
        || caps.tx_datagram_bytes != if small { 1152 } else { 1472 }
        || (!small && (caps.rx_body_bytes != Some(1024) || caps.tx_body_bytes != Some(1024)))
    {
        return Err("pool byte configuration".into());
    }
    let pool_heap = if B {
        coaptic::storage::AllocMemory::<Token>::required_heap_bytes(capacities())?
    } else {
        0
    };
    let app_inline = size_of_val(&app);
    let app_align = align_of_val(&app);
    let site_inline = size_of_val(app.site());
    let client_start = client.as_ref().map(SecurityContext::sender_seq);
    let server_start = app.oscore().map(SecurityContext::sender_seq);
    let mut per_case = [0u32; 8];
    let mut handlers = [0u32; 8];
    let mut measured = [0u32; 8];
    let mut opened = [0; WIRE];
    let mut histogram = [0u32; 6];
    let mut completed = 0u32;
    let mut response_pivs = 0u32;
    let mut common_first = 0u32;
    let mut common_last = 0u32;
    for operation in 0..OPS + WARM {
        let c = case(g, operation);
        let i = operation % g.cases;
        let before = calls();
        let result = step(
            &mut app,
            &mut client,
            operation,
            g,
            &mut opened,
            measure && operation >= WARM,
        )?;
        per_case[i] += 1;
        handlers[i] += calls().checked_sub(before).ok_or("counter rollback")?;
        if let Some(width) = result.request_piv {
            *histogram.get_mut(width).ok_or("PIV width")? += 1;
        }
        completed += 1;
        response_pivs += u32::from(result.response_piv);
        if operation >= WARM && c.id == "common" {
            if c.tag == Some(0) {
                common_first += 1;
            } else {
                common_last += 1;
            }
        }
        if operation >= WARM {
            measured[i] += 1;
        }
        if let Some(ns) = result.elapsed {
            latencies.push(ns);
        }
    }
    if g.id == "default32_full" && (common_first, common_last) != (900, 100) {
        return Err("common measured census".into());
    }
    if calls() != g.expected {
        return Err("total handler count".into());
    }
    for i in 0..g.cases {
        let expected = (OPS + WARM) / g.cases;
        let hits = if case(g, i).tag.is_some() {
            expected
        } else {
            0
        };
        if per_case[i] != expected as u32
            || handlers[i] != hits as u32
            || measured[i] != (OPS / g.cases) as u32
        {
            return Err("case census".into());
        }
    }
    let client_end = client.as_ref().map(SecurityContext::sender_seq);
    let server_end = app.oscore().map(SecurityContext::sender_seq);
    if completed != 8128
        || (client.is_some()
            && (histogram.iter().sum::<u32>() != 8128 || histogram[3..].iter().any(|&n| n != 0)))
    {
        return Err("protocol census".into());
    }
    if server_end
        .zip(server_start)
        .is_some_and(|(end, start)| end.checked_sub(start) != Some(u64::from(response_pivs)))
    {
        return Err("server PIV delta".into());
    }
    if client_end
        .zip(client_start)
        .is_some_and(|(end, start)| end - start != (OPS + WARM) as u64)
    {
        return Err("client sequence delta".into());
    }
    if let Some(context) = app.oscore() {
        if context.replay_fresh((OPS + WARM - 1) as u64) {
            return Err("replay state".into());
        }
    }
    if measure {
        for sample in 0..CAL {
            let start = Instant::now();
            black_box(sample);
            calibration.push(start.elapsed().as_nanos());
        }
    }
    // Worst-case decimal u128 intervals plus bounded scalar/header output.
    if (latencies.len() + calibration.len()) * 40 + 16384 > OUTPUT_CAP {
        return Err("output preflight cap".into());
    }
    let mut w = Bounded {
        inner: std::io::stdout().lock(),
        bytes: 0,
    };
    let security = if client.is_some() {
        "oscore"
    } else {
        "unprotected"
    };
    let phase = if measure { "measure" } else { "qualify" };
    let purpose = if measure {
        "request-route-benefit"
    } else {
        "request-route-qualification"
    };
    let schema = if measure {
        "coaptic-request-route-wall/1"
    } else {
        "coaptic-request-route-qualification/1"
    };
    let group = g.id;
    let payload_bytes = g.body;
    let registered_routes = g.registered;
    let route_capacity = g.routes;
    let profile = match g.id {
        "small_one" | "small_full" => "SmallDevice/Constrained",
        "default8_full" => "Default pools/routes8",
        _ => "Default pools/routes32",
    };
    let cap = match g.id {
        "small_one" => CAP_0,
        "small_full" => CAP_1,
        "default8_full" => CAP_2,
        "default32_full" => CAP_3,
        _ => CAP_4,
    };
    let total_handlers = calls();
    let measured_polls = latencies.len();
    let calibration_samples = calibration.len();
    let pointer_bytes = size_of::<usize>();
    let internal_datagrams = completed * 2;
    let authenticated = if client.is_some() { completed } else { 0 };
    write!(
        w,
        r#"{{"schema":"{schema}","contract":"request-route-permutation","purpose":"{purpose}","phase":"{phase}","method_sha256":"{METHOD}","group":"{group}","security":"{security}","operations":8000,"warmup":128,"verified":{completed},"handler_calls":{total_handlers},"measured_polls":{measured_polls},"calibration_samples":{calibration_samples},"payload_bytes":{payload_bytes},"profile":"{profile}","registered_routes":{registered_routes},"route_capacity":{route_capacity},"terminal":"complete","trace_id":"round-robin/1""#
    )?;
    write!(w, ",\"capacities\":{cap},\"case_counts\":[")?;
    for i in 0..g.cases {
        if i > 0 {
            write!(w, ",")?;
        }
        let id = case(g, i).id;
        let warmup_verified = per_case[i] - measured[i];
        let work_verified = measured[i];
        let handler_calls = handlers[i];
        write!(
            w,
            r#"{{"id":"{id}","warmup_verified":{warmup_verified},"work_verified":{work_verified},"handler_calls":{handler_calls}}}"#
        )?;
    }
    write!(w, "],\"layout\":")?;
    write!(
        w,
        r#"{{"app_inline_bytes":{app_inline},"app_align_bytes":{app_align},"site_inline_bytes":{site_inline},"pool_heap_requested_bytes":{pool_heap},"pointer_bytes":{pointer_bytes},"fixture_additional_bytes":{owners},"fixture_owners":{{"latency_backing":{latency_backing},"calibration_backing":{calibration_backing},"array_headers":{array_headers},"client_context":{client_context},"request_scratch":{request_scratch},"verification_scratch":{verification_scratch},"metadata":{metadata},"serialization_scratch":{serialization_scratch},"entropy_scratch":{entropy_scratch},"static_data":{static_data},"other_explicit":{other_explicit}}}}}"#
    )?;
    write!(w, ",\"protocol\":")?;
    write!(
        w,
        r#"{{"prepared":{completed},"polled":{completed},"responded":{completed},"verified":{completed},"input_datagrams":{completed},"output_datagrams":{completed},"internal_datagrams":{internal_datagrams},"udp_datagrams":0,"now_ms":1,"first_mid":0,"last_mid":8127,"token_bytes":8,"max_outstanding":1,"input_empty":true,"output_empty":true,"authenticated_responses":{authenticated},"bindings_consumed":{authenticated}"#
    )?;
    write!(w, ",\"client_sender_seq_start\":")?;
    optional(&mut w, client_start)?;
    write!(w, ",\"client_sender_seq_end\":")?;
    optional(&mut w, client_end)?;
    write!(w, ",\"request_piv_bytes_histogram\":")?;
    if client.is_some() {
        write!(
            w,
            "[{}, {}, {}, {}, {}, {}]",
            histogram[0], histogram[1], histogram[2], histogram[3], histogram[4], histogram[5]
        )?;
    } else {
        write!(w, "null")?;
    }
    write!(w, "}}")?;
    if measure {
        write!(w, ",\"latency_ns\":")?;
        array(&mut w, &latencies)?;
        write!(w, ",\"calibration_ns\":")?;
        array(&mut w, &calibration)?;
    }
    writeln!(w, "}}")?;
    w.flush()?;
    Ok(())
}
pub(super) fn run(args: &[String]) -> Result<(), Failure> {
    if args.len() != 5
        || args[1] != "--request-route"
        || !matches!(args[2].as_str(), "qualify" | "measure")
        || !matches!(args[4].as_str(), "unprotected" | "oscore")
    {
        return Err("bench-core --request-route qualify|measure GROUP unprotected|oscore".into());
    }
    let g = *GROUPS
        .iter()
        .find(|g| g.id == args[3])
        .ok_or("group allowlist")?;
    let (client, server) = contexts(args[4] == "oscore")?;
    let measure = args[2] == "measure";
    if g.body == 32 {
        drive(small(g, server)?, client, g, measure)
    } else if g.routes == 8 {
        drive(default::<8>(g, server)?, client, g, measure)
    } else {
        drive(default::<32>(g, server)?, client, g, measure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(protected: bool) -> (SmallApp, Option<SecurityContext>, Group) {
        reset_calls();
        let g = GROUPS[1];
        let (client, server) = contexts(protected).unwrap();
        (small(g, server).unwrap(), client, g)
    }
    fn exchange(
        app: &mut SmallApp,
        client: &mut Option<SecurityContext>,
        op: usize,
        g: Group,
    ) -> (MessageId, Token, Case) {
        let c = case(g, op);
        let (mid, token) = prepare(app.transport_mut(), client, op, c).unwrap();
        app.poll(1).unwrap();
        (mid, token, c)
    }
    fn check(
        app: &mut SmallApp,
        client: &mut Option<SecurityContext>,
        mid: MessageId,
        token: Token,
        c: Case,
    ) -> Result<(), Failure> {
        response(
            app.transport_mut(),
            client,
            &mut [0; WIRE],
            mid,
            token,
            c,
            32,
        )
    }
    #[test]
    fn metadata_and_body_refuse() {
        for protected in [false, true] {
            for fault in 0..10 {
                let (mut app, mut client, g) = fixture(protected);
                let (mid, token, c) = exchange(&mut app, &mut client, 0, g);
                // Authenticate genuine protocol output first, then mutate the inner
                // message: OSCORE corruption alone would not test semantic checks.
                let io = app.transport_mut();
                let n = io.output_len.take().unwrap();
                let wire = decode(&io.output[..n]).unwrap();
                let mut opened = [0; WIRE];
                let reply = if let Some(ctx) = client.as_mut() {
                    let r = ctx.take(token).unwrap();
                    ctx.unprotect_response(&wire, r, &mut opened).unwrap()
                } else {
                    wire
                };
                verify(&reply, mid, token, c, 32).unwrap();
                let mut body = [0x5a; 32];
                body[31] = 0;
                let wrong_cf = [43];
                let mut opts = [
                    Opt::new(OptionNumber::ETAG, b"fixture"),
                    Opt::new(OptionNumber::CONTENT_FORMAT, &[42]),
                    Opt::new(OptionNumber::MAX_AGE, &[1]),
                ];
                if fault == 3 {
                    opts[0] = Opt::new(OptionNumber::ETAG, b"wrong");
                }
                if fault == 4 {
                    opts[1] = Opt::new(OptionNumber::CONTENT_FORMAT, &wrong_cf);
                }
                if fault == 5 {
                    body[31] = 3;
                }
                if fault == 6 {
                    body[0] = 0;
                }
                let msg = Message::new(
                    if fault == 0 {
                        Type::NonConfirmable
                    } else {
                        Type::Acknowledgement
                    },
                    if fault == 1 {
                        Code::CHANGED
                    } else {
                        Code::CONTENT
                    },
                    if fault == 2 { MessageId::new(99) } else { mid },
                )
                .with_token(if fault == 8 {
                    Token::new(b"wrong").unwrap()
                } else {
                    token
                })
                .with_options(&opts[..if fault == 7 { 3 } else { 2 }])
                .with_payload(if fault == 9 { &body[..31] } else { &body });
                let mut buf = [0; WIRE];
                let n = msg.encode(&mut buf).unwrap();
                assert!(verify(&decode(&buf[..n]).unwrap(), mid, token, c, 32).is_err());
            }
            // Genuine miss and method errors must pass the independent literals.
            let (mut app, mut client, g) = fixture(protected);
            let (mid, token, c) = exchange(&mut app, &mut client, 3, g);
            check(&mut app, &mut client, mid, token, c).unwrap();
            let c = Case {
                id: "method_405",
                path: "r03",
                tag: None,
                put: true,
            };
            let (mid, token) = prepare(app.transport_mut(), &mut client, 4, c).unwrap();
            app.poll(1).unwrap();
            check(&mut app, &mut client, mid, token, c).unwrap();
        }
    }
    #[test]
    fn authentication_and_replay_refuse() {
        let (mut app, mut client, g) = fixture(true);
        let (mid, token, c) = exchange(&mut app, &mut client, 0, g);
        let n = app.transport().output_len.unwrap();
        app.transport_mut().output[n - 1] ^= 1;
        assert!(check(&mut app, &mut client, mid, token, c).is_err());
        for protected in [false, true] {
            let (mut app, mut client, g) = fixture(protected);
            let c = case(g, 0);
            let (mid, token) = prepare(app.transport_mut(), &mut client, 0, c).unwrap();
            let n = app.transport().input_len.unwrap();
            let mut replay = [0; WIRE];
            replay[..n].copy_from_slice(&app.transport().input[..n]);
            app.poll(1).unwrap();
            check(&mut app, &mut client, mid, token, c).unwrap();
            let before = calls();
            // Exact duplicate CON legitimately replays a cached response. It must
            // never execute the handler again, nor recreate a consumed client binding.
            let io = app.transport_mut();
            io.input[..n].copy_from_slice(&replay[..n]);
            io.input_len = Some(n);
            app.poll(1).unwrap();
            assert_eq!(calls(), before);
            if protected {
                assert!(!app.oscore().unwrap().replay_fresh(0));
            }
            if protected {
                assert!(check(&mut app, &mut client, mid, token, c).is_err());
            } else {
                check(&mut app, &mut client, mid, token, c).unwrap();
            }
        }
        // An unauthenticated fresh protected request must not invoke a handler.
        let (mut app, mut client, g) = fixture(true);
        prepare(app.transport_mut(), &mut client, 0, case(g, 0)).unwrap();
        let n = app.transport().input_len.unwrap();
        app.transport_mut().input[n - 1] ^= 1;
        let _ = app.poll(1);
        assert_eq!(calls(), 0);
        assert!(app.oscore().unwrap().replay_fresh(0));
    }
    #[test]
    fn missing_and_extra_io_refuse() {
        for protected in [false, true] {
            let (mut app, mut client, g) = fixture(protected);
            let (mid, token, c) = exchange(&mut app, &mut client, 0, g);
            app.transport_mut().output_len = None;
            assert!(check(&mut app, &mut client, mid, token, c).is_err());
            let (mut app, mut client, g) = fixture(protected);
            let (mid, token, c) = exchange(&mut app, &mut client, 0, g);
            app.transport_mut().input_len = Some(1);
            assert!(check(&mut app, &mut client, mid, token, c).is_err());
            assert!(prepare(app.transport_mut(), &mut client, 1, case(g, 1)).is_err());
            app.transport_mut().input_len = None;
            // The actual transport refuses a second send rather than overwriting.
            assert!(app.transport_mut().send(PEER, b"extra").is_err());
            assert!(prepare(app.transport_mut(), &mut client, 1, case(g, 1)).is_err());
        }
    }
    #[test]
    fn count_and_state_refuse() {
        for protected in [false, true] {
            let (mut app, mut client, g) = fixture(protected);
            let before = calls();
            let (mid, token, c) = exchange(&mut app, &mut client, 0, g);
            check(&mut app, &mut client, mid, token, c).unwrap();
            count(before, calls(), true).unwrap();
            assert!(count(before, calls(), false).is_err());
            assert!(count(calls() + 1, calls(), true).is_err());
            state(app.resource_usage(), g, protected, false).unwrap();
            assert!(state(app.resource_usage(), g, !protected, false).is_err());
            let mut wrong = g;
            wrong.registered -= 1;
            assert!(state(app.resource_usage(), wrong, protected, false).is_err());
            assert!(state(app.resource_usage(), g, protected, true).is_err());
            // Run the real continuous trace and verify bounded-state recovery.
            for op in 1..WARM + OPS {
                step(&mut app, &mut client, op, g, &mut [0; WIRE], false).unwrap();
            }
            assert_eq!(calls(), g.expected);
            state(app.resource_usage(), g, protected, true).unwrap();
        }
    }
}
