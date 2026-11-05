//! Independent incoming-App fixture. Source freeze is not execution permission.
//! Logical idle gaps describe fresh transfers after idle, not wall throughput.
//! Qualification never records latency. Encrypted download inner headers are
//! checked through authenticated App state; they are not opened a second time.
use super::*;
use coaptic::message::{BlockValue, OptionNumber, ParsedMessage};
use coaptic::storage::{BlockRole, SlotId};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const METHOD_SHA: &str = "7e1c6be071e61fb0e9176e0d5ed2e0f4c6cf6fd02bc2a8afe5815a7ee61fb02c";
const CELLS: [&str; 8] = [
    "fixed_upload_unprotected",
    "fixed_upload_oscore",
    "allocated_download_unprotected",
    "allocated_download_oscore",
    "fixed_guard_unprotected",
    "fixed_guard_oscore",
    "allocated_guard_unprotected",
    "allocated_guard_oscore",
];
const WARM: usize = 8;
const MEASURED: usize = 64;
const TRANSFERS: usize = WARM + MEASURED;
const OUTPUT_LIMIT: usize = 1 << 20; // Combined stdout/stderr, including failure reserve.
const FAILURE_RESERVE: usize = 4096;
static LOCK: Mutex<()> = Mutex::new(());
static HANDLERS: AtomicUsize = AtomicUsize::new(0);
static BAD_HANDLERS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Qualify,
    Measure,
}
fn mode(args: &[String]) -> Result<Mode, Failure> {
    if args.len() != 3 || args[1] != "--incoming-rx" {
        return Err("incoming-rx requires exactly --incoming-rx qualify|measure".into());
    }
    match args[2].as_str() {
        "qualify" => Ok(Mode::Qualify),
        "measure" => Ok(Mode::Measure),
        _ => Err("incoming-rx requires exactly --incoming-rx qualify|measure".into()),
    }
}

// Output is assembled within one fixed capacity and written once. Errors have
// static bounded messages. The CLI consumes errors here so main cannot print an
// unbounded boxed diagnostic after the combined-output budget has been spent.
struct Json {
    bytes: Vec<u8>,
}
impl Json {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(OUTPUT_LIMIT - FAILURE_RESERVE),
        }
    }
}
impl Write for Json {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > OUTPUT_LIMIT - FAILURE_RESERVE)
        {
            return Err(std::io::Error::other("incoming-rx output capacity"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
struct Sample {
    ns: [u128; 16],
    count: usize,
    sum: u128,
}
impl Sample {
    fn add(&mut self, ns: Option<u128>) -> Result<(), Failure> {
        if self.count == self.ns.len() {
            return Err("receiving poll capacity".into());
        }
        if let Some(ns) = ns {
            let sum = self.sum.checked_add(ns).ok_or("receiving sum overflow")?;
            self.ns[self.count] = ns;
            self.sum = sum;
        }
        self.count = self
            .count
            .checked_add(1)
            .ok_or("receiving count overflow")?;
        Ok(())
    }
    fn validate(&self, expected: usize, timed: bool) -> Result<(), Failure> {
        let sum = self.ns[..self.count.min(16)]
            .iter()
            .try_fold(0u128, |a, b| a.checked_add(*b));
        if self.count != expected || sum != Some(self.sum) || (!timed && self.sum != 0) {
            return Err("poll/transfer conservation".into());
        }
        Ok(())
    }
}
fn tick<E>(
    sample: &mut Sample,
    timed: bool,
    poll: impl FnOnce() -> Result<(), E>,
) -> Result<(), Failure> {
    if timed {
        let start = Instant::now();
        let result = black_box(poll());
        let ns = start.elapsed().as_nanos();
        sample.add(Some(ns))?;
        result.map_err(|_| "receiving App poll".into())
    } else {
        let result = poll();
        sample.add(None)?;
        result.map_err(|_| "receiving App poll".into())
    }
}
fn deadline(start: Instant, seconds: u64) -> Result<(), Failure> {
    if start.elapsed().as_secs() >= seconds {
        return Err("incoming-rx absolute process deadline".into());
    }
    Ok(())
}
fn pair(
    protected: bool,
) -> Result<
    (
        Option<coaptic::oscore::SecurityContext>,
        Option<coaptic::oscore::SecurityContext>,
    ),
    Failure,
> {
    if !protected {
        return Ok((None, None));
    }
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
    let result = (derive(&[], &[1]), derive(&[1], &[]));
    material.fill(0);
    Ok((Some(result.0?), Some(result.1?)))
}

struct Audit {
    partial: Sample,
    partial_timed: bool,
    requests: u64,
    responses: u64,
    receiving: u64,
    handlers: u64,
    bytes_in: u64,
    bytes_out: u64,
    collections: u64,
    releases: u64,
    pivs: u64,
    crossed_256: bool,
    last_piv: Option<u64>,
    last_mid: Option<u16>,
    tokens: [u64; TRANSFERS],
    token_count: usize,
    digest: u64,
}
impl Default for Audit {
    fn default() -> Self {
        Self {
            partial: Sample::default(),
            partial_timed: false,
            requests: 0,
            responses: 0,
            receiving: 0,
            handlers: 0,
            bytes_in: 0,
            bytes_out: 0,
            collections: 0,
            releases: 0,
            pivs: 0,
            crossed_256: false,
            last_piv: None,
            last_mid: None,
            tokens: [0; TRANSFERS],
            token_count: 0,
            digest: 0,
        }
    }
}
impl Audit {
    fn hash(&mut self, bytes: &[u8]) {
        // Public protocol audit only. Not a cryptographic or source identity hash.
        for b in bytes {
            self.digest = (self.digest ^ u64::from(*b)).wrapping_mul(1099511628211);
        }
    }
    fn request(
        &mut self,
        wire: &ParsedMessage<'_>,
        protected: bool,
        fresh: bool,
    ) -> Result<(), Failure> {
        if wire.ty() != Type::Confirmable {
            return Err("request CON".into());
        }
        let mid = wire.message_id().get();
        if let Some(last) = self.last_mid {
            if mid != last.wrapping_add(1) {
                return Err("request MID progression".into());
            }
        }
        self.last_mid = Some(mid);
        self.hash(&mid.to_be_bytes());
        if fresh {
            let mut bytes = [0; 8];
            let token = wire.token();
            let value = token.as_bytes();
            if value.len() > 8 || value.is_empty() {
                return Err("request token width".into());
            }
            bytes[8 - value.len()..].copy_from_slice(value);
            let value = u64::from_be_bytes(bytes);
            if self.tokens[..self.token_count].contains(&value) || self.token_count == TRANSFERS {
                return Err("request token reuse/capacity".into());
            }
            self.tokens[self.token_count] = value;
            self.token_count += 1;
            self.hash(&bytes);
        }
        if protected {
            let opt = wire
                .get_option(OptionNumber::OSCORE)
                .ok_or("missing OSCORE")?;
            let piv = coaptic::oscore::OscoreHeader::parse(opt.value())?
                .piv
                .ok_or("missing request PIV")?;
            let seq = piv.seq();
            if seq != self.pivs || self.last_piv.is_some_and(|p| seq != p + 1) {
                return Err("request PIV progression".into());
            }
            if seq == 256 {
                if self.last_piv != Some(255) || piv.as_bytes().len() != 2 {
                    return Err("PIV width crossing".into());
                }
                self.crossed_256 = true;
            }
            self.last_piv = Some(seq);
            self.hash(piv.as_bytes());
            self.pivs += 1;
        } else if wire.get_option(OptionNumber::OSCORE).is_some() {
            return Err("unexpected OSCORE".into());
        }
        self.requests += 1;
        Ok(())
    }
}

// Only the qualification peer override differs from CoreIo. No old transport,
// App layout, timer or Service helper is changed.
struct UploadIo {
    io: CoreIo,
    peer: Endpoint,
    sends: u64,
    receives: u64,
}
impl coaptic::storage::DatagramTransport for UploadIo {
    type Error = &'static str;
}
impl DatagramIo for UploadIo {
    fn recv(&mut self, out: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        let result = self.io.recv(out)?;
        if let Some((n, _)) = result {
            self.receives += 1;
            return Ok(Some((n, self.peer)));
        }
        Ok(None)
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        if peer != self.peer {
            return Err("upload endpoint");
        }
        let n = self.io.send(PEER, bytes)?;
        self.sends += 1;
        Ok(n)
    }
}
type UploadApp = App<
    coaptic::profiles::Constrained,
    UploadIo,
    4,
    true,
    <coaptic::profiles::Constrained as MemoryLayout<true>>::Store,
    0,
    1,
>;
fn upload_handler(req: Request<'_>) -> Response<'static> {
    HANDLERS.fetch_add(1, Ordering::SeqCst);
    let bytes = if req.has_body() {
        req.body()
    } else {
        Some(req.payload())
    };
    let expected = if req.has_body() { 4096 } else { 64 };
    if bytes != Some(&SERVICE_BODY[..expected])
        || req.content_format().and_then(Result::ok) != Some(ContentFormat::OCTET_STREAM)
    {
        BAD_HANDLERS.fetch_add(1, Ordering::SeqCst);
        return Response::new(Code::BAD_REQUEST);
    }
    Response::content(&BODY)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"fixture")
}
fn upload_app(context: Option<coaptic::oscore::SecurityContext>) -> Result<UploadApp, Failure> {
    let builder = App::with_resources(coaptic::resources::SmallDevice::new().block_wise::<true>())
        .randomness(|b| getrandom::fill(b).is_ok())
        .route("bench", coaptic::put(upload_handler));
    let builder = if let Some(c) = context {
        builder.oscore(c)
    } else {
        builder.allow_unprotected()
    };
    let app = builder.bind(UploadIo {
        io: core_io(),
        peer: PEER,
        sends: 0,
        receives: 0,
    })?;
    let expected = Capacities {
        rx_datagram_slots: 2,
        rx_datagram_bytes: 1152,
        tx_datagram_slots: 2,
        tx_datagram_bytes: 1152,
        dedup_entries: 4,
        observe_entries: 2,
        rx_body_slots: Some(1),
        rx_body_bytes: Some(4096),
        tx_body_slots: Some(1),
        tx_body_bytes: Some(4096),
    };
    if app.engine().capacities() != expected {
        return Err("fixed actual capacities differ from method".into());
    }
    Ok(app)
}
fn body_id(app: &mut UploadApp) -> Result<SlotId, Failure> {
    let id = app
        .engine_mut()
        .acquire_rx_body()
        .ok_or("body inventory acquire")?;
    if app.engine_mut().acquire_rx_body().is_some() {
        return Err("body inventory capacity".into());
    }
    app.engine_mut().release_rx_body(id)?;
    Ok(id)
}
fn prepare_upload(
    app: &mut UploadApp,
    context: &mut Option<coaptic::oscore::SecurityContext>,
    q: usize,
    j: usize,
    guard: bool,
) -> Result<(MessageId, Token), Failure> {
    let mid = MessageId::new(if guard { q } else { 4 * q + j } as u16);
    let token = Token::new(&(q as u64 + 1).to_be_bytes()).ok_or("upload token")?;
    let cf = ContentFormat::OCTET_STREAM.encode();
    let block = BlockValue::new(j as u32, j != 3, 6)?.encode();
    let size = coaptic::message::encode_uint(4096);
    let options = [
        Opt::uri_path("bench"),
        Opt::content_format(&cf),
        Opt::block1(&block),
        Opt::size1(&size),
    ];
    let request = Message::con(Code::PUT, mid, token)
        .with_options(if guard { &options[..2] } else { &options })
        .with_payload(if guard {
            &SERVICE_BODY[..64]
        } else {
            &SERVICE_BODY[j * 1024..(j + 1) * 1024]
        });
    let io = &mut app.transport_mut().io;
    if io.input_len.is_some() || io.output_len.is_some() {
        return Err("upload occupied transport".into());
    }
    io.input_len = Some(if let Some(c) = context {
        c.protect_request(&request, &mut io.input)?
    } else {
        request.encode(&mut io.input)?
    });
    Ok((mid, token))
}
#[allow(clippy::too_many_arguments)]
fn upload_reply(
    app: &mut UploadApp,
    context: &mut Option<coaptic::oscore::SecurityContext>,
    mid: MessageId,
    token: Token,
    j: usize,
    guard: bool,
    audit: &mut Audit,
) -> Result<(), Failure> {
    let io = &mut app.transport_mut().io;
    let n = io.output_len.take().ok_or("missing upload response")?;
    audit.bytes_out += n as u64;
    let wire = decode(&io.output[..n])?;
    if wire.message_id() != mid || wire.token() != token || wire.ty() != Type::Acknowledgement {
        return Err("upload outer header".into());
    }
    let mut opened = [0; WIRE];
    let reply = if let Some(c) = context {
        let binding = c.take(token).ok_or("upload response binding")?;
        c.unprotect_response(&wire, binding, &mut opened)?
    } else {
        wire
    };
    if guard || j == 3 {
        verify_reply(&reply, mid, token, &BODY)?;
    } else if reply.code() != Code::CONTINUE || !reply.payload().is_empty() {
        return Err("upload continuation".into());
    }
    if !guard {
        let b = reply.block1().transpose()?.ok_or("upload Block1 missing")?;
        if b.num() != j as u32 || b.szx() != 6 || b.more() != (j != 3) {
            return Err("upload Block1 metadata".into());
        }
    } else if reply.block1().is_some() {
        return Err("upload guard unexpected block".into());
    }
    audit.responses += 1;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn upload_transfer(
    app: &mut UploadApp,
    context: &mut Option<coaptic::oscore::SecurityContext>,
    id: SlotId,
    q: usize,
    guard: bool,
    timed: bool,
    audit: &mut Audit,
) -> Result<Sample, Failure> {
    let mut sample = Sample::default();
    audit.partial = sample;
    audit.partial_timed = timed;
    let h = HANDLERS.load(Ordering::SeqCst);
    let receives = app.transport().receives;
    let sends = app.transport().sends;
    let polls = if guard { 1 } else { 4 };
    for j in 0..polls {
        let (mid, token) = prepare_upload(app, context, q, j, guard)?;
        let io = &app.transport().io;
        let n = io.input_len.ok_or("upload input")?;
        audit.request(&decode(&io.input[..n])?, context.is_some(), j == 0)?;
        audit.bytes_in += n as u64;
        let now = 1 + 300000 * q as u64 + 3 * j as u64;
        let outcome = tick(&mut sample, timed, || {
            // Raw peer preparation is phase 0; receiving server is phase 1.
            // Raw response opening/checking is phase 2 and invokes no App poll.
            black_box(&mut *app).poll(black_box(now + 1))
        });
        audit.partial = sample;
        audit.receiving += 1;
        outcome?;
        upload_reply(app, context, mid, token, j, guard, audit)?;
        if !guard && j < 3 {
            let t = app
                .engine()
                .rx_body_transfer(id)
                .ok_or("upload body owner missing")?;
            if t.role() != BlockRole::IncomingBlock1
                || t.token() != token
                || t.endpoint() != PEER
                || t.num() != j as u32
                || t.filled() != (j + 1) * 1024
                || t.is_complete()
                || app.engine().rx_body_payload(id) != Some(&SERVICE_BODY[..(j + 1) * 1024])
            {
                return Err("upload body progress".into());
            }
        }
    }
    if HANDLERS.load(Ordering::SeqCst) != h + 1
        || BAD_HANDLERS.load(Ordering::SeqCst) != 0
        || app.transport().receives != receives + polls as u64
        || app.transport().sends != sends + polls as u64
        || app.engine().rx_body_transfer(id).is_some()
        || app.storage_usage().rx_body.is_none_or(|p| p.occupied != 0)
        || app.transport().io.input_len.is_some()
        || app.transport().io.output_len.is_some()
    {
        return Err("upload completion/owner/count".into());
    }
    audit.handlers += 1;
    audit.releases += 1;
    sample.validate(polls, timed)?;
    Ok(sample)
}

fn download_handler(req: Request<'_>) -> Response<'static> {
    HANDLERS.fetch_add(1, Ordering::SeqCst);
    service16384(req)
}
fn download_guard_handler(req: Request<'_>) -> Response<'static> {
    HANDLERS.fetch_add(1, Ordering::SeqCst);
    service64(req)
}
type Partner = ServiceServer<<coaptic::profiles::Service as MemoryLayout<true>>::Store>;
// Keep fixed storage in this frame; returning the App duplicates large caller
// temporaries. Match the existing Service driver without enlarging its stack.
#[inline(never)]
fn with_partner<R>(
    context: Option<coaptic::oscore::SecurityContext>,
    guard: bool,
    use_partner: impl FnOnce(&mut Partner) -> Result<R, Failure>,
) -> Result<R, Failure> {
    let handler: fn(Request<'_>) -> Response<'static> = if guard {
        download_guard_handler
    } else {
        download_handler
    };
    let b = App::with_resources(coaptic::resources::Service::new())
        .randomness(|b| getrandom::fill(b).is_ok())
        .route("bench", get(handler));
    let b = if let Some(c) = context {
        b.oscore(c)
    } else {
        b.allow_unprotected()
    };
    // Borrow the App inside its Result: `?` would move this large fixed value
    // into a second local while the builder return slot is still in the frame.
    let mut bound = b.bind(service_io());
    let app = bound.as_mut().map_err(|error| *error)?;
    let caps = app.engine().capacities();
    let expected = Capacities {
        rx_datagram_slots: 32,
        rx_datagram_bytes: 1472,
        tx_datagram_slots: 32,
        tx_datagram_bytes: 1472,
        dedup_entries: 64,
        observe_entries: 32,
        rx_body_slots: Some(4),
        rx_body_bytes: Some(16384),
        tx_body_slots: Some(4),
        tx_body_bytes: Some(16384),
    };
    if caps != expected {
        return Err("partner actual capacities differ from method".into());
    }
    use_partner(app)
}
fn download_id(client: &mut ServiceClient) -> Result<SlotId, Failure> {
    if client.engine().capacities() != service_client_capacities() {
        return Err("allocated actual capacities differ from method".into());
    }
    let id = client
        .engine_mut()
        .acquire_rx_body()
        .ok_or("download inventory")?;
    if client.engine_mut().acquire_rx_body().is_some() {
        return Err("download body capacity".into());
    }
    client.engine_mut().release_rx_body(id)?;
    Ok(id)
}
fn begin(client: &mut ServiceClient, q: usize, guard: bool) -> Result<coaptic::Call, Failure> {
    let base = 1 + 300000 * q as u64;
    let r = client.get("bench").to(PEER).deadline(base + 3000);
    let r = if guard {
        r
    } else {
        r.block2(BlockValue::new(0, false, 6)?)
    };
    r.send(base).map_err(|_| "download send".into())
}
#[allow(clippy::too_many_arguments)]
fn download_turn(
    client: &mut ServiceClient,
    server: &mut Partner,
    call: coaptic::Call,
    q: usize,
    j: usize,
    guard: bool,
    timed: bool,
    sample: &mut Sample,
    audit: &mut Audit,
) -> Result<(), Failure> {
    let request = service_wire(client.transport())?;
    let mid = request.message_id();
    if request.token() != call.token() {
        return Err("download request token".into());
    }
    audit.request(&request, client.oscore().is_some(), j == 0)?;
    let n = client
        .transport()
        .io
        .output_len
        .ok_or("download request missing")?;
    audit.bytes_out += n as u64;
    service_bridge(client.transport_mut(), server.transport_mut())?;
    let now = 1 + 300000 * q as u64 + 3 * j as u64;
    server.poll(now + 1).map_err(|_| "download partner poll")?;
    service_ack(server.transport(), mid, call.token())?;
    let wire = service_wire(server.transport())?;
    if client.oscore().is_none() {
        verify_download_fragment(&wire, j, guard)?;
    } else if wire.get_option(OptionNumber::OSCORE).is_none() {
        return Err("download missing protection".into());
    }
    audit.bytes_in += server
        .transport()
        .io
        .output_len
        .ok_or("download response missing")? as u64;
    service_bridge(server.transport_mut(), client.transport_mut())?;
    let outcome = tick(sample, timed, || {
        black_box(&mut *client).poll(black_box(now + 2))
    });
    audit.partial = *sample;
    audit.partial_timed = timed;
    audit.receiving += 1;
    outcome?;
    audit.responses += 1;
    Ok(())
}
fn verify_download_fragment(
    reply: &ParsedMessage<'_>,
    j: usize,
    guard: bool,
) -> Result<(), Failure> {
    let bytes = if guard {
        &SERVICE_BODY[..64]
    } else {
        &SERVICE_BODY[j * 1024..(j + 1) * 1024]
    };
    let mut etags = reply.etag();
    if reply.code() != Code::CONTENT
        || reply.content_format().transpose()? != Some(ContentFormat::OCTET_STREAM)
        || etags.next() != Some(&b"fixture"[..])
        || etags.next().is_some()
        || reply.payload() != bytes
    {
        return Err("download wire metadata/body".into());
    }
    if guard {
        if reply.block2().is_some() {
            return Err("guard Block2".into());
        }
    } else {
        let b = reply
            .block2()
            .transpose()?
            .ok_or("download Block2 missing")?;
        if b.num() != j as u32 || b.more() != (j != 15) || b.szx() != 6 {
            return Err("download block range".into());
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn download_transfer(
    client: &mut ServiceClient,
    server: &mut Partner,
    id: SlotId,
    q: usize,
    guard: bool,
    timed: bool,
    audit: &mut Audit,
    output: &mut [u8; 16384],
) -> Result<Sample, Failure> {
    audit.partial = Sample::default();
    audit.partial_timed = timed;
    let call = begin(client, q, guard)?;
    let first = service_wire(client.transport())?.message_id();
    let mut sample = Sample::default();
    let h = HANDLERS.load(Ordering::SeqCst);
    let cs = client.transport().sent;
    let ss = server.transport().sent;
    let polls = if guard { 1 } else { 16 };
    for j in 0..polls {
        download_turn(client, server, call, q, j, guard, timed, &mut sample, audit)?;
        if !guard {
            let t = client
                .engine()
                .rx_body_transfer(id)
                .ok_or("download body owner")?;
            if t.role() != BlockRole::IncomingBlock2
                || t.token() != call.token()
                || t.endpoint() != PEER
                || t.num() != j as u32
                || t.filled() != (j + 1) * 1024
                || t.is_complete() != (j == 15)
                || client.engine().rx_body_payload(id) != Some(&SERVICE_BODY[..(j + 1) * 1024])
            {
                return Err("authenticated download body progress".into());
            }
        }
        if j + 1 < polls && client.transport().io.output_len.is_none() {
            return Err("missing download continuation".into());
        }
    }
    let pending = ServicePending {
        call,
        first_mid: first,
        started: Instant::now(),
        polls: polls as u32,
        wall_sum: 0,
    };
    {
        let reply = client
            .take_response_into(call, output)?
            .ok_or("missing terminal response")?
            .map_err(|_| "download Call failure")?;
        service_verify(&reply, &pending, if guard { 64 } else { 16384 })?;
        if !guard {
            let option = reply
                .received_options()
                .find(|o| o.number() == OptionNumber::BLOCK2)
                .ok_or("first Block2 metadata")?;
            let b = coaptic::message::decode_block(option.value())?;
            if b.num() != 0 || b.szx() != 6 || !b.more() || reply.body() != Some(&SERVICE_BODY[..])
            {
                return Err("first metadata/final body".into());
            }
        }
    }
    audit.collections += 1;
    if client.take_response(call).is_some()
        || client
            .storage_usage()
            .rx_body
            .is_none_or(|p| p.occupied != 0)
        || client.engine().rx_body_transfer(id).is_some()
        || client.transport().io.output_len.is_some()
        || client.transport().io.input_len.is_some()
        || server.transport().io.output_len.is_some()
        || client.transport().sent - cs != polls as u32 - 1
        || server.transport().sent - ss != polls as u32
        || HANDLERS.load(Ordering::SeqCst) != h + polls
    {
        return Err("download collection/owner/packet/handler counts".into());
    }
    audit.handlers += polls as u64;
    audit.releases += 1;
    sample.validate(polls, timed)?;
    Ok(sample)
}

struct Cell {
    samples: [Sample; MEASURED],
    audit: Audit,
    app_bytes: usize,
    heap: usize,
    partner_bytes: usize,
    raw_context_bytes: usize,
}
#[inline(never)]
fn cell(index: usize, mode: Mode, start: Instant, result: &mut Cell) -> Result<(), Failure> {
    HANDLERS.store(0, Ordering::SeqCst);
    BAD_HANDLERS.store(0, Ordering::SeqCst);
    let protected = index % 2 == 1;
    let guard = index >= 4;
    let upload = index % 4 < 2;
    let (cc, sc) = pair(protected)?;
    if upload {
        let mut context = cc;
        let mut app = upload_app(sc)?;
        let id = body_id(&mut app)?;
        result.app_bytes = std::mem::size_of_val(&app);
        result.raw_context_bytes = std::mem::size_of_val(&context);
        for q in 0..TRANSFERS {
            deadline(start, if mode == Mode::Measure { 14 } else { 20 })?;
            let s = upload_transfer(
                &mut app,
                &mut context,
                id,
                q,
                guard,
                mode == Mode::Measure && q >= WARM,
                &mut result.audit,
            )?;
            if q >= WARM && mode == Mode::Measure {
                result.samples[q - WARM] = s;
            }
        }
        if context
            .as_ref()
            .is_some_and(|c| c.sender_seq() != result.audit.requests)
        {
            return Err("upload sender sequence census".into());
        }
    } else {
        let mut client = service_client(cc)?;
        with_partner(sc, guard, |server| {
            let id = download_id(&mut client)?;
            result.app_bytes = std::mem::size_of_val(&client);
            result.partner_bytes = std::mem::size_of_val(server);
            result.heap = coaptic::storage::AllocMemory::<Token>::required_heap_bytes(
                service_client_capacities(),
            )?;
            let mut output = [0; 16384];
            for q in 0..TRANSFERS {
                deadline(start, if mode == Mode::Measure { 14 } else { 20 })?;
                let s = download_transfer(
                    &mut client,
                    server,
                    id,
                    q,
                    guard,
                    mode == Mode::Measure && q >= WARM,
                    &mut result.audit,
                    &mut output,
                )?;
                if q >= WARM && mode == Mode::Measure {
                    result.samples[q - WARM] = s;
                }
            }
            if client
                .oscore()
                .is_some_and(|c| c.sender_seq() != result.audit.requests)
            {
                return Err("download sender sequence census".into());
            }
            Ok(())
        })?;
    }
    let polls = if guard {
        1
    } else if upload {
        4
    } else {
        16
    };
    if result.audit.requests != (TRANSFERS * polls) as u64
        || result.audit.responses != result.audit.requests
        || result.audit.receiving != result.audit.requests
        || result.audit.token_count != TRANSFERS
        || result.audit.releases != TRANSFERS as u64
        || (protected && !guard && !result.audit.crossed_256)
    {
        return Err("cell observed census".into());
    }
    Ok(())
}

struct FailureReport {
    bytes: [u8; FAILURE_RESERVE],
    len: usize,
}
impl std::fmt::Write for FailureReport {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let mut n = text.len().min(self.bytes.len() - self.len);
        while !text.is_char_boundary(n) {
            n -= 1;
        }
        self.bytes[self.len..self.len + n].copy_from_slice(&text.as_bytes()[..n]);
        self.len += n;
        if n == text.len() {
            Ok(())
        } else {
            Err(std::fmt::Error)
        }
    }
}
fn failure_report(error: impl std::fmt::Display) -> FailureReport {
    let mut report = FailureReport {
        bytes: [0; FAILURE_RESERVE],
        len: 0,
    };
    let _ = std::fmt::write(
        &mut report,
        format_args!("incoming-rx validation failed: {error}\n"),
    );
    report
}

#[inline(never)]
pub(super) fn dispatch(args: &[String]) -> Result<(), Failure> {
    let mode = match mode(args) {
        Ok(m) => m,
        Err(_) => {
            eprintln!("incoming-rx: invalid closed CLI");
            std::process::exit(2)
        }
    };
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut json = Json::new();
    if let Err(error) = run(mode, &mut json) {
        // The bounded prefix is evidence only, never a success document.
        let _ = std::io::stdout().write_all(&json.bytes);
        let report = failure_report(&error);
        let _ = std::io::stderr().write_all(&report.bytes[..report.len]);
        std::process::exit(1);
    }
    if std::io::stdout().write_all(&json.bytes).is_err() {
        eprintln!("incoming-rx output write failed");
        std::process::exit(1);
    }
    Ok(())
}

fn run(mode: Mode, out: &mut Json) -> Result<(), Failure> {
    let start = Instant::now();
    let schema = if mode == Mode::Measure {
        "coaptic-incoming-rx/1"
    } else {
        "coaptic-incoming-rx-qualification/1"
    };
    let output_capacity = out.bytes.capacity();
    // transfers, requests, responses, receiving polls, handlers, collections,
    // body releases, measured receiving polls. Values come from validated cells.
    let mut census = [0u64; 8];
    write!(
        out,
        "{{\"schema\":\"{schema}\",\"method_sha256\":\"{METHOD_SHA}\",\"method_state\":\"source-frozen-before-execution\",\"measurement\":\"complete receiving App::poll only; input/output copies and final upload handler whole-body comparison inside; partner/preparation/bridge/verification/collection outside; synthetic fresh-transfer-after-idle logical time; no throughput or Q speed claim\",\"memory\":{{\"bounded_json_requested_heap_bytes\":{},\"json_vec_inline_bytes\":{},\"calibration_retention\":\"JSON values; one scalar scratch, no subtraction\",\"calibration_scalar_bytes\":{},\"audit_inline_nested_in_cell_bytes\":{},\"raw_master_material_temporary_bytes\":24,\"qualification_extra_wire_scratch_peak_bytes\":{},\"failure_report_temporary_bytes\":{},\"unknown\":\"allocator, initialization and generated stack/runtime costs\"}},\"cells\":[",
        output_capacity,
        std::mem::size_of::<Vec<u8>>(),
        std::mem::size_of::<u128>(),
        std::mem::size_of::<Audit>(),
        if mode == Mode::Qualify { 2 * WIRE } else { 0 },
        std::mem::size_of::<FailureReport>()
    )?;
    for (i, name) in CELLS.iter().enumerate() {
        let mut c = Cell {
            samples: [Sample::default(); MEASURED],
            audit: Audit::default(),
            app_bytes: 0,
            heap: 0,
            partner_bytes: 0,
            raw_context_bytes: 0,
        };
        if let Err(error) = cell(i, mode, start, &mut c) {
            let completed = c.audit.releases;
            write!(
                out,
                "],\"failure\":{{\"id\":\"{name}\",\"completed_transfers\":{completed},\"observed_requests\":{},\"observed_receiving_polls\":{},\"observed_responses\":{}",
                c.audit.requests, c.audit.receiving, c.audit.responses
            )?;
            if mode == Mode::Measure {
                write!(out, ",\"completed_transfer_prefix_ns\":[")?;
                let kept = (completed as usize).saturating_sub(WARM).min(MEASURED);
                for (n, s) in c.samples[..kept].iter().enumerate() {
                    if n > 0 {
                        write!(out, ",")?;
                    }
                    write!(out, "{{\"sum\":{},\"polls\":[", s.sum)?;
                    for (j, t) in s.ns[..s.count].iter().enumerate() {
                        if j > 0 {
                            write!(out, ",")?;
                        }
                        write!(out, "{t}")?;
                    }
                    write!(out, "]}}")?;
                }
                write!(out, "]")?;
                if c.audit.partial_timed {
                    write!(out, ",\"failed_transfer_receiving_poll_prefix_ns\":[")?;
                    for (j, n) in c.audit.partial.ns[..c.audit.partial.count]
                        .iter()
                        .enumerate()
                    {
                        if j > 0 {
                            write!(out, ",")?;
                        }
                        write!(out, "{n}")?;
                    }
                    write!(out, "]")?;
                }
            }
            write!(out, "}}")?;
            return Err(error);
        }
        if i != 0 {
            write!(out, ",")?;
        }
        let a = &c.audit;
        let measured_polls = c
            .samples
            .iter()
            .try_fold(0u64, |n, s| n.checked_add(s.count as u64))
            .ok_or("process measured poll overflow")?;
        let row = [
            a.releases,
            a.requests,
            a.responses,
            a.receiving,
            a.handlers,
            a.collections,
            if i >= 4 { 0 } else { a.releases },
            measured_polls,
        ];
        for (total, value) in census.iter_mut().zip(row) {
            *total = total.checked_add(value).ok_or("process census overflow")?;
        }
        write!(
            out,
            "{{\"positive_trace_id\":\"positive72.{name}\",\"warm_transfers\":{WARM},\"measured_transfers\":{},\"timing_state\":\"{}\",",
            if mode == Mode::Measure { MEASURED } else { 0 },
            if mode == Mode::Measure {
                "RECORDED"
            } else {
                "NOTRUN"
            }
        )?;
        write!(
            out,
            "\"id\":\"{name}\",\"transfers\":{},\"requests\":{},\"responses\":{},\"receiving_polls\":{},\"handler_calls\":{},\"collections\":{},\"released_body_owners\":{},\"bytes_in\":{},\"bytes_out\":{},\"fresh_tokens\":{},\"request_pivs\":{},\"piv_255_to_256\":{},\"public_audit_fnv64\":{},",
            TRANSFERS,
            a.requests,
            a.responses,
            a.receiving,
            a.handlers,
            a.collections,
            if i >= 4 { 0 } else { a.releases },
            a.bytes_in,
            a.bytes_out,
            a.token_count,
            a.pivs,
            a.crossed_256,
            a.digest
        )?;
        let protected = i % 2 == 1;
        write!(
            out,
            "\"crypto\":{{\"request_seals\":{},\"app_authenticated_receiving_polls\":{},\"raw_peer_response_opens\":{},\"response_seals\":{}}},",
            if protected { a.requests } else { 0 },
            if protected { a.receiving } else { 0 },
            if protected && i % 4 < 2 {
                a.responses
            } else {
                0
            },
            if protected { a.responses } else { 0 }
        )?;
        write!(
            out,
            "\"memory\":{{\"app_including_transport_inline_bytes\":{},\"app_required_pool_heap_bytes\":{},\"fixed_partner_app_inline_bytes\":{},\"partner_required_pool_heap_bytes\":0,\"raw_peer_optional_context_inline_bytes\":{},\"service_body_static_shared_bytes\":16384,\"download_collection_bytes\":{},\"upload_open_scratch_bytes\":{},\"cell_result_inline_bytes\":{},\"nested_transport_is_in_app\":true,\"remaining\":\"allocator/runtime/generated-stack/initialization unknown\"}},",
            c.app_bytes,
            c.heap,
            c.partner_bytes,
            c.raw_context_bytes,
            if i % 4 >= 2 { 16384 } else { 0 },
            if i % 4 < 2 { WIRE } else { 0 },
            std::mem::size_of::<Cell>()
        )?;
        write!(
            out,
            "\"config\":{{\"routes\":{},\"populated_routes\":{},\"calls\":{},\"deferred\":0,\"associations\":1,\"bindings\":4,\"rx_slots\":{},\"tx_slots\":{},\"datagram_bytes\":{},\"dedup\":{},\"observe\":{},\"rx_body_slots\":1,\"rx_body_bytes\":{},\"tx_body_slots\":1,\"tx_body_bytes\":{}}}",
            if i % 4 < 2 { 4 } else { 1 },
            if i % 4 < 2 { 1 } else { 0 },
            if i % 4 < 2 { 1 } else { 4 },
            if i % 4 < 2 { 2 } else { 4 },
            if i % 4 < 2 { 2 } else { 4 },
            if i % 4 < 2 { 1152 } else { 1472 },
            if i % 4 < 2 { 4 } else { 8 },
            if i % 4 < 2 { 2 } else { 4 },
            if i % 4 < 2 { 4096 } else { 16384 },
            if i % 4 < 2 { 4096 } else { 1024 }
        )?;
        if i % 4 >= 2 {
            write!(
                out,
                ",\"partner_config\":{{\"routes\":32,\"populated_routes\":1,\"calls\":4,\"deferred\":8,\"associations\":1,\"bindings\":4,\"rx_slots\":32,\"tx_slots\":32,\"datagram_bytes\":1472,\"dedup\":64,\"observe\":32,\"rx_body_slots\":4,\"tx_body_slots\":4,\"rx_body_bytes\":16384,\"tx_body_bytes\":16384}}"
            )?;
        }
        if mode == Mode::Measure {
            write!(out, ",\"transfers_ns\":[")?;
            for (j, s) in c.samples.iter().enumerate() {
                if j > 0 {
                    write!(out, ",")?;
                }
                write!(out, "{{\"sum\":{},\"polls\":[", s.sum)?;
                for (k, n) in s.ns[..s.count].iter().enumerate() {
                    if k > 0 {
                        write!(out, ",")?;
                    }
                    write!(out, "{n}")?;
                }
                write!(out, "]}}")?;
            }
            write!(out, "]")?;
        }
        write!(out, "}}")?;
    }
    write!(out, "]")?;
    let expected_measured = if mode == Mode::Measure { 2816 } else { 0 };
    if census != [576, 3168, 3168, 3168, 2736, 288, 288, expected_measured] {
        return Err("process positive census mismatch".into());
    }
    let datagrams = census[1]
        .checked_add(census[2])
        .ok_or("process datagram sum overflow")?;
    write!(
        out,
        ",\"positive_census\":{{\"transfers\":{},\"requests\":{},\"responses\":{},\"receiving_polls\":{},\"handler_calls\":{},\"collections\":{},\"released_body_owners\":{},\"measured_receiving_polls\":{},\"datagram_sends\":{datagrams}}}",
        census[0], census[1], census[2], census[3], census[4], census[5], census[6], census[7]
    )?;
    if mode == Mode::Measure {
        write!(out, ",\"calibration_samples\":4096,\"calibration_ns\":[")?;
        for n in 0..4096 {
            let t = Instant::now();
            black_box(n);
            let ns = t.elapsed().as_nanos();
            if n > 0 {
                write!(out, ",")?;
            }
            write!(out, "{ns}")?;
        }
        write!(out, "]")?;
    } else {
        write!(out, ",\"calibration_state\":\"NOTRUN\"")?;
        qualification(out, start)?;
    }
    deadline(start, if mode == Mode::Measure { 14 } else { 20 })?;
    writeln!(out, ",\"status\":\"PASS\"}}")?;
    Ok(())
}

// These tables are the qualification manifest. Each row names a concrete
// oracle/stage, rather than treating a malformed packet as generic success.
const ORACLE_TRACES: [&str; 9] = [
    "oracle.code",
    "oracle.format",
    "oracle.etag",
    "oracle.body",
    "oracle.block_num",
    "oracle.block_more",
    "oracle.block_szx",
    "oracle.missing_block",
    "oracle.extra_etag",
];
fn oracle_trace(fault: usize) -> Result<(), Failure> {
    let cf = if fault == 1 {
        ContentFormat::TEXT_PLAIN
    } else {
        ContentFormat::OCTET_STREAM
    }
    .encode();
    let block = BlockValue::new(
        if fault == 4 { 1 } else { 0 },
        fault != 5,
        if fault == 6 { 5 } else { 6 },
    )?
    .encode();
    let tag = if fault == 2 {
        &b"wrong!!"[..]
    } else {
        &b"fixture"[..]
    };
    let options = [
        Opt::etag(tag),
        Opt::etag(b"extra"),
        Opt::content_format(&cf),
        Opt::block2(&block),
    ];
    let options = if fault == 8 {
        &options[..]
    } else {
        &options[2..]
    };
    // Normal metadata in a separate bounded builder avoids an artificial
    // duplicate option in all faults except the duplicate-ETag row.
    let normal = [
        Opt::etag(tag),
        Opt::content_format(&cf),
        Opt::block2(&block),
    ];
    let options = if fault == 8 {
        options
    } else if fault == 7 {
        &normal[..2]
    } else {
        &normal[..]
    };
    let mut body = [0; 1024];
    body.copy_from_slice(&SERVICE_BODY[..1024]);
    if fault == 3 {
        body[700] ^= 1;
    }
    let code = if fault == 0 {
        Code::CHANGED
    } else {
        Code::CONTENT
    };
    let token = Token::new(b"oracle").ok_or("oracle token")?;
    let message = Message::new(Type::Acknowledgement, code, MessageId::new(7))
        .with_token(token)
        .with_options(options)
        .with_payload(&body);
    let mut bytes = [0; WIRE];
    let n = message.encode(&mut bytes)?;
    if verify_download_fragment(&decode(&bytes[..n])?, 0, false).is_ok() {
        return Err("negative metadata/body oracle accepted".into());
    }
    Ok(())
}

fn auth_trace() -> Result<(), Failure> {
    let (cc, sc) = pair(true)?;
    let mut client = cc.ok_or("auth client")?;
    let mut server = sc.ok_or("auth server")?;
    let t1 = Token::new(b"auth-one").ok_or("auth token")?;
    let t2 = Token::new(b"auth-two").ok_or("auth token")?;
    let options = [Opt::uri_path("bench")];
    let mut wire = [0; WIRE];
    let mut opened = [0; WIRE];
    let request = Message::con(Code::GET, MessageId::new(1), t1).with_options(&options);
    let n = client.protect_request(&request, &mut wire)?;
    wire[n - 1] ^= 1;
    if server
        .unprotect_request(&decode(&wire[..n])?, &mut opened)
        .is_ok()
        || !server.replay_fresh(0)
    {
        return Err("tamper accepted/consumed replay state".into());
    }
    wire[n - 1] ^= 1;
    let (_, binding) = server.unprotect_request(&decode(&wire[..n])?, &mut opened)?;
    if server
        .unprotect_request(&decode(&wire[..n])?, &mut opened)
        .is_ok()
        || server.replay_fresh(0)
    {
        return Err("replayed request accepted".into());
    }
    let request2 = Message::con(Code::GET, MessageId::new(2), t2).with_options(&options);
    client.protect_request(&request2, &mut wire)?;
    let wrong = client.take(t2).ok_or("wrong binding missing")?;
    let response = Message::new(Type::Acknowledgement, Code::CONTENT, MessageId::new(1))
        .with_token(t1)
        .with_payload(&BODY);
    let n = server.protect_response(&response, binding, &mut wire)?;
    if client
        .unprotect_response(&decode(&wire[..n])?, wrong, &mut opened)
        .is_ok()
    {
        return Err("wrong request binding accepted".into());
    }
    let binding = client.take(t1).ok_or("correct binding missing")?;
    let reply = client.unprotect_response(&decode(&wire[..n])?, binding, &mut opened)?;
    if reply.payload() != BODY {
        return Err("auth recovery body".into());
    }
    Ok(())
}

// First fragment is retained in the genuine single body owner. A competing
// token cannot replace it when the body area is full. Finish that owner, then
// complete another transfer on the same App/context without resetting security.
struct Trace {
    client_sends: u64,
    server_sends: u64,
    receiving: u64,
    housekeeping: u64,
    handlers: usize,
    collections: u64,
}
impl Trace {
    fn emit(&self, out: &mut Json, id: &str) -> Result<(), Failure> {
        let (client, server, receiving, housekeeping, handlers, collections) = trace_contract(id)?;
        if (
            self.client_sends,
            self.server_sends,
            self.receiving,
            self.housekeeping,
            self.handlers,
            self.collections,
        ) != (
            client,
            server,
            receiving,
            housekeeping,
            handlers,
            collections,
        ) {
            return Err("qualification trace contract census".into());
        }
        let sends = self
            .client_sends
            .checked_add(self.server_sends)
            .ok_or("trace send sum overflow")?;
        write!(
            out,
            ",{{\"id\":\"{id}\",\"client_sends\":{},\"server_sends\":{},\"datagram_sends\":{},\"receiving_polls\":{},\"housekeeping_polls\":{},\"handler_calls\":{},\"collections\":{},\"final\":\"owners_released_fresh_recovery\"}}",
            self.client_sends,
            self.server_sends,
            sends,
            self.receiving,
            self.housekeeping,
            self.handlers,
            self.collections
        )?;
        Ok(())
    }
}

// Exact preregistration counts, checked against observed transport and poll
// counters before each trace is emitted. Deadline polls have no received packet.
fn trace_contract(id: &str) -> Result<(u64, u64, u64, u64, usize, u64), Failure> {
    if id.starts_with("upload.capacity_preserve_finish_recover.") {
        return Ok((9, 9, 9, 0, 2, 0));
    }
    if id.starts_with("download.capacity_preserve_collect_recover.") {
        return Ok((33, 33, 33, 0, 33, 3));
    }
    if id.starts_with("download.cancel.") {
        return Ok((18, 17, 17, 0, 17, 2));
    }
    if id.starts_with("download.expire.") {
        return Ok((18, 17, 17, 1, 17, 2));
    }
    if id == "download.reject_body_or_tag.unprotected" {
        return Ok((18, 17, 17, 1, 17, 2));
    }
    if id.starts_with("download.reject_missing.") {
        return Ok((17, 17, 16, 1, 17, 2));
    }
    if id.starts_with("download.reject_wrong_token.") || id == "download.reject_body_or_tag.oscore"
    {
        return Ok((17, 17, 17, 1, 17, 2));
    }
    if id == "upload.wrong_peer_preserves_partial_then_cancel_recover.oscore" {
        return Ok((6, 6, 6, 0, 1, 0));
    }
    if id == "upload.app_tamper_replay_preserves_partial_finish_recover.oscore" {
        return Ok((10, 8, 10, 0, 2, 0));
    }
    Err("unknown qualification trace contract".into())
}

fn upload_capacity_trace(protected: bool) -> Result<Trace, Failure> {
    HANDLERS.store(0, Ordering::SeqCst);
    BAD_HANDLERS.store(0, Ordering::SeqCst);
    let (mut context, sc) = pair(protected)?;
    let mut app = upload_app(sc)?;
    let id = body_id(&mut app)?;
    let mut audit = Audit::default();
    let (mid, token) = prepare_upload(&mut app, &mut context, 0, 0, false)?;
    app.poll(1).map_err(|_| "capacity first poll")?;
    upload_reply(&mut app, &mut context, mid, token, 0, false, &mut audit)?;
    let before = app
        .engine()
        .rx_body_transfer(id)
        .ok_or("capacity owner missing")?;
    let (mid, token) = prepare_upload(&mut app, &mut context, 1, 0, false)?;
    // A new Token on the same resource/peer is an allowed untagged restart.
    // A distinct peer needs its own body slot and must preserve this owner.
    app.transport_mut().peer = Endpoint::v4([127, 0, 0, 2], 30000);
    app.poll(2).map_err(|_| "capacity refusal poll")?;
    let io = &mut app.transport_mut().io;
    let n = io.output_len.take().ok_or("capacity refusal missing")?;
    let wire = decode(&io.output[..n])?;
    let mut opened = [0; WIRE];
    let reply = if let Some(c) = context.as_mut() {
        let b = c.take(token).ok_or("capacity binding")?;
        c.unprotect_response(&wire, b, &mut opened)?
    } else {
        wire
    };
    if reply.message_id() != mid
        || reply.token() != token
        || reply.code() != Code::REQUEST_ENTITY_INCOMPLETE
        || HANDLERS.load(Ordering::SeqCst) != 0
        || app.engine().rx_body_transfer(id) != Some(before)
        || app.engine().rx_body_payload(id) != Some(&SERVICE_BODY[..1024])
    {
        return Err("capacity refusal changed existing owner".into());
    }
    app.transport_mut().peer = PEER;
    for j in 1..4 {
        let (mid, token) = prepare_upload(&mut app, &mut context, 0, j, false)?;
        app.poll(3 + j as u64)
            .map_err(|_| "capacity owner finish")?;
        upload_reply(&mut app, &mut context, mid, token, j, false, &mut audit)?;
    }
    let mut recovery = Audit::default();
    if protected {
        recovery.pivs = 5;
        recovery.last_piv = Some(4);
    }
    upload_transfer(&mut app, &mut context, id, 2, false, false, &mut recovery)?;
    if app.transport().receives != 9
        || app.transport().sends != 9
        || HANDLERS.load(Ordering::SeqCst) != 2
        || BAD_HANDLERS.load(Ordering::SeqCst) != 0
    {
        return Err("capacity trace census".into());
    }
    Ok(Trace {
        client_sends: app.transport().receives,
        server_sends: app.transport().sends,
        receiving: app.transport().receives,
        housekeeping: 0,
        handlers: HANDLERS.load(Ordering::SeqCst),
        collections: 0,
    })
}

fn download_cancel_trace(protected: bool, expire: bool) -> Result<Trace, Failure> {
    HANDLERS.store(0, Ordering::SeqCst);
    BAD_HANDLERS.store(0, Ordering::SeqCst);
    let (cc, sc) = pair(protected)?;
    let mut client = service_client(cc)?;
    with_partner(sc, false, |server| {
        let id = download_id(&mut client)?;
        let call = begin(&mut client, 0, false)?;
        let mut sample = Sample::default();
        let mut audit = Audit::default();
        download_turn(
            &mut client,
            server,
            call,
            0,
            0,
            false,
            false,
            &mut sample,
            &mut audit,
        )?;
        if client.engine().rx_body_payload(id) != Some(&SERVICE_BODY[..1024]) {
            return Err("cancel trace partial body".into());
        }
        // The already emitted second request is deliberately undelivered. Its send
        // and PIV remain counted. This is cancellation of a partial real transfer.
        if client.transport_mut().io.output_len.take().is_none() {
            return Err("cancel pending followup".into());
        }
        if expire {
            client.poll(3001).map_err(|_| "expiry poll")?;
        } else if !client.cancel(call) {
            return Err("partial cancel refusal".into());
        }
        let terminal = client
            .take_response(call)
            .ok_or("cancel terminal missing")?;
        let expected = if expire {
            coaptic::app::CallFailure::DeadlineExceeded
        } else {
            coaptic::app::CallFailure::Cancelled
        };
        if terminal.err() != Some(expected)
            || client.take_response(call).is_some()
            || client.engine().rx_body_transfer(id).is_some()
            || client
                .storage_usage()
                .rx_body
                .is_none_or(|p| p.occupied != 0)
        {
            return Err("partial cancellation/expiry ownership".into());
        }
        // A fresh q=1 call follows the idle interval, on the same contexts. Account
        // for the undelivered request in the continuous nonce and MID progression.
        let mut recovery = Audit::default();
        if protected {
            recovery.pivs = 2;
            recovery.last_piv = Some(1);
        }
        let mut output = [0; 16384];
        download_transfer(
            &mut client,
            server,
            id,
            1,
            false,
            false,
            &mut recovery,
            &mut output,
        )?;
        if client.transport().sent != 18
            || server.transport().sent != 17
            || HANDLERS.load(Ordering::SeqCst) != 17
        {
            return Err("partial recovery census".into());
        }
        Ok(Trace {
            client_sends: client.transport().sent as u64,
            server_sends: server.transport().sent as u64,
            receiving: sample.count as u64 + recovery.receiving,
            housekeeping: u64::from(expire),
            handlers: HANDLERS.load(Ordering::SeqCst),
            collections: 1 + recovery.collections,
        })
    })
}

// Authenticated response corruption must leave the App's body absent. Outer
// Token mismatches are rejected by App lookup before inner processing. A missing
// response is bounded by the same absolute Call deadline, never a relative reset.
fn require_expired_call<T>(
    outcome: Option<Result<T, coaptic::CallFailure>>,
) -> Result<(), Failure> {
    if matches!(outcome, Some(Err(coaptic::CallFailure::DeadlineExceeded))) {
        Ok(())
    } else {
        Err("rejection terminal reason is not deadline expiry".into())
    }
}

fn download_rejection_trace(protected: bool, fault: usize) -> Result<Trace, Failure> {
    HANDLERS.store(0, Ordering::SeqCst);
    let (cc, sc) = pair(protected)?;
    let mut client = service_client(cc)?;
    with_partner(sc, false, |server| {
        let id = download_id(&mut client)?;
        let call = begin(&mut client, 0, false)?;
        service_bridge(client.transport_mut(), server.transport_mut())?;
        server.poll(2).map_err(|_| "rejection partner poll")?;
        let io = &mut server.transport_mut().io;
        let n = io.output_len.ok_or("rejection response")?;
        match fault {
            0 => {
                io.output[n - 1] ^= 1;
            }
            1 => {
                if io.output[0] & 15 == 0 {
                    return Err("rejection token absent".into());
                }
                io.output[4] ^= 1;
            }
            2 => {
                io.output_len = None;
            }
            _ => return Err("unknown rejection trace".into()),
        }
        let mut receives = 0;
        if fault != 2 {
            service_bridge(server.transport_mut(), client.transport_mut())?;
            let _ = client.poll(3);
            receives += 1;
            // Plain body corruption is detected by the independent full-byte oracle,
            // not by CoAP authentication. Do not claim protocol rejection for it.
            if !protected && fault == 0 {
                if client.engine().rx_body_payload(id) == Some(&SERVICE_BODY[..1024]) {
                    return Err("corrupt body oracle accepted".into());
                }
            } else if client.engine().rx_body_transfer(id).is_some() {
                return Err("rejected response acquired body owner".into());
            }
        }
        // Do not forward any followup emitted by a corrupted unprotected body.
        client.transport_mut().io.output_len = None;
        if client.take_response(call).is_some() {
            return Err("rejection completed before deadline".into());
        }
        client.poll(3001).map_err(|_| "rejection expiry")?;
        require_expired_call(client.take_response(call))?;
        if client.take_response(call).is_some() {
            return Err("rejection terminal collected twice".into());
        }
        if client.engine().rx_body_transfer(id).is_some() {
            return Err("rejection leaked body".into());
        }
        let mut recovery = Audit::default();
        if protected {
            recovery.pivs = client.oscore().ok_or("rejection context")?.sender_seq();
            recovery.last_piv = recovery.pivs.checked_sub(1);
        }
        let mut output = [0; 16384];
        download_transfer(
            &mut client,
            server,
            id,
            1,
            false,
            false,
            &mut recovery,
            &mut output,
        )?;
        if HANDLERS.load(Ordering::SeqCst) != 17
            || server.transport().sent != 17
            || receives != usize::from(fault != 2)
        {
            return Err("rejection recovery census".into());
        }
        Ok(Trace {
            client_sends: client.transport().sent as u64,
            server_sends: server.transport().sent as u64,
            receiving: receives as u64 + recovery.receiving,
            housekeeping: 1,
            handlers: HANDLERS.load(Ordering::SeqCst),
            collections: 1 + recovery.collections,
        })
    })
}

fn upload_peer_trace() -> Result<Trace, Failure> {
    HANDLERS.store(0, Ordering::SeqCst);
    BAD_HANDLERS.store(0, Ordering::SeqCst);
    let (mut cc, sc) = pair(true)?;
    let mut app = upload_app(sc)?;
    let id = body_id(&mut app)?;
    let (mid, token) = prepare_upload(&mut app, &mut cc, 0, 0, false)?;
    app.poll(1).map_err(|_| "peer first poll")?;
    let mut a = Audit::default();
    upload_reply(&mut app, &mut cc, mid, token, 0, false, &mut a)?;
    let before = app
        .engine()
        .rx_body_transfer(id)
        .ok_or("peer existing owner")?;
    let (wrong_mid, wrong_token) = prepare_upload(&mut app, &mut cc, 0, 1, false)?;
    app.transport_mut().peer = Endpoint::v4([127, 0, 0, 2], 30000);
    app.poll(2).map_err(|_| "wrong peer refusal poll")?;
    if app.engine().rx_body_transfer(id) != Some(before)
        || app.engine().rx_body_payload(id) != Some(&SERVICE_BODY[..1024])
        || HANDLERS.load(Ordering::SeqCst) != 0
    {
        return Err("wrong peer changed existing body".into());
    }
    let io = &mut app.transport_mut().io;
    let n = io.output_len.take().ok_or("wrong peer refusal response")?;
    let wire = decode(&io.output[..n])?;
    let context = cc.as_mut().ok_or("peer context missing")?;
    let binding = context
        .take(wrong_token)
        .ok_or("peer refusal binding missing")?;
    let mut opened = [0; WIRE];
    let refusal = context.unprotect_response(&wire, binding, &mut opened)?;
    if refusal.message_id() != wrong_mid
        || refusal.token() != wrong_token
        || refusal.code() != Code::REQUEST_ENTITY_INCOMPLETE
    {
        return Err("wrong peer refusal metadata/authentication".into());
    }
    app.transport_mut().peer = PEER;
    // Public explicit cancellation of the partial incoming owner, then recovery.
    app.engine_mut().release_rx_body(id)?;
    let mut recovery = Audit {
        pivs: 2,
        last_piv: Some(1),
        ..Audit::default()
    };
    upload_transfer(&mut app, &mut cc, id, 1, false, false, &mut recovery)?;
    if HANDLERS.load(Ordering::SeqCst) != 1 {
        return Err("peer recovery handler".into());
    }
    Ok(Trace {
        client_sends: app.transport().receives,
        server_sends: app.transport().sends,
        receiving: app.transport().receives,
        housekeeping: 0,
        handlers: HANDLERS.load(Ordering::SeqCst),
        collections: 0,
    })
}

fn upload_auth_trace() -> Result<Trace, Failure> {
    HANDLERS.store(0, Ordering::SeqCst);
    BAD_HANDLERS.store(0, Ordering::SeqCst);
    let (mut cc, sc) = pair(true)?;
    let mut app = upload_app(sc)?;
    let id = body_id(&mut app)?;
    let (mid, token) = prepare_upload(&mut app, &mut cc, 0, 0, false)?;
    let mut replay = [0; WIRE];
    let replay_len = app.transport().io.input_len.ok_or("auth input")?;
    replay[..replay_len].copy_from_slice(&app.transport().io.input[..replay_len]);
    app.poll(1).map_err(|_| "auth first poll")?;
    let mut audit = Audit::default();
    upload_reply(&mut app, &mut cc, mid, token, 0, false, &mut audit)?;
    let before = app.engine().rx_body_transfer(id).ok_or("auth partial")?;
    let (mid, token) = prepare_upload(&mut app, &mut cc, 0, 1, false)?;
    let n = app.transport().io.input_len.ok_or("auth second input")?;
    let mut valid = [0; WIRE];
    valid[..n].copy_from_slice(&app.transport().io.input[..n]);
    app.transport_mut().io.input[n - 1] ^= 1;
    let _ = app.poll(2);
    if app.engine().rx_body_transfer(id) != Some(before)
        || app.engine().rx_body_payload(id) != Some(&SERVICE_BODY[..1024])
        || !app.oscore().ok_or("auth App context")?.replay_fresh(1)
        || app.transport().io.output_len.is_some()
    {
        return Err("App tamper changed body/replay/output".into());
    }
    app.transport_mut().io.input[..n].copy_from_slice(&valid[..n]);
    app.transport_mut().io.input_len = Some(n);
    app.poll(3).map_err(|_| "auth valid second poll")?;
    upload_reply(&mut app, &mut cc, mid, token, 1, false, &mut audit)?;
    let before = app
        .engine()
        .rx_body_transfer(id)
        .ok_or("auth second partial")?;
    // Expire dedup so this is OSCORE replay refusal, not cached ACK replay.
    app.transport_mut().io.input[..replay_len].copy_from_slice(&replay[..replay_len]);
    app.transport_mut().io.input_len = Some(replay_len);
    let _ = app.poll(300001);
    if app.engine().rx_body_transfer(id) != Some(before)
        || app.engine().rx_body_payload(id) != Some(&SERVICE_BODY[..2048])
        || app.oscore().ok_or("replay App context")?.replay_fresh(0)
        || app.transport().io.output_len.is_some()
    {
        return Err("App replay changed body/output".into());
    }
    for j in 2..4 {
        let (mid, token) = prepare_upload(&mut app, &mut cc, 0, j, false)?;
        app.poll(300002 + j as u64).map_err(|_| "auth finish")?;
        upload_reply(&mut app, &mut cc, mid, token, j, false, &mut audit)?;
    }
    let mut recovery = Audit {
        pivs: 4,
        last_piv: Some(3),
        ..Audit::default()
    };
    upload_transfer(&mut app, &mut cc, id, 2, false, false, &mut recovery)?;
    if app.transport().receives != 10
        || app.transport().sends != 8
        || HANDLERS.load(Ordering::SeqCst) != 2
    {
        return Err("App authentication trace census".into());
    }
    Ok(Trace {
        client_sends: app.transport().receives,
        server_sends: app.transport().sends,
        receiving: app.transport().receives,
        housekeeping: 0,
        handlers: HANDLERS.load(Ordering::SeqCst),
        collections: 0,
    })
}

fn download_capacity_trace(protected: bool) -> Result<Trace, Failure> {
    HANDLERS.store(0, Ordering::SeqCst);
    let (cc, sc) = pair(protected)?;
    let mut client = service_client(cc)?;
    with_partner(sc, false, |server| {
        let id = download_id(&mut client)?;
        let first = begin(&mut client, 0, false)?;
        let first_mid = service_wire(client.transport())?.message_id();
        let mut sample = Sample::default();
        let mut audit = Audit::default();
        for j in 0..16 {
            download_turn(
                &mut client,
                server,
                first,
                0,
                j,
                false,
                false,
                &mut sample,
                &mut audit,
            )?;
        }
        let before = client
            .engine()
            .rx_body_transfer(id)
            .ok_or("retained capacity owner")?;
        if !before.is_complete() || client.engine().rx_body_payload(id) != Some(&SERVICE_BODY[..]) {
            return Err("capacity retained complete bytes".into());
        }
        // Completed, uncollected real Call owns this body. A different real Call
        // must fail explicit body admission without replacing the retained owner.
        let second = begin(&mut client, 1, false)?;
        let mut refusal = Sample::default();
        download_turn(
            &mut client,
            server,
            second,
            1,
            0,
            false,
            false,
            &mut refusal,
            &mut audit,
        )?;
        if !matches!(
            client.take_response(second),
            Some(Err(coaptic::app::CallFailure::BlockTransfer(
                coaptic::error::BlockTransferError::Saturated
            )))
        ) || client.take_response(second).is_some()
            || client.engine().rx_body_transfer(id) != Some(before)
            || client.engine().rx_body_payload(id) != Some(&SERVICE_BODY[..])
        {
            return Err("allocated capacity refusal changed retained owner".into());
        }
        let mut output = [0; 16384];
        let pending = ServicePending {
            call: first,
            first_mid,
            started: Instant::now(),
            polls: 16,
            wall_sum: 0,
        };
        {
            let reply = client
                .take_response_into(first, &mut output)?
                .ok_or("capacity retained collection")?
                .map_err(|_| "capacity retained Call failure")?;
            service_verify(&reply, &pending, 16384)?;
        }
        if client.take_response(first).is_some() || client.engine().rx_body_transfer(id).is_some() {
            return Err("capacity original collection once".into());
        }
        let mut recovery = Audit::default();
        if protected {
            recovery.pivs = 17;
            recovery.last_piv = Some(16);
        }
        download_transfer(
            &mut client,
            server,
            id,
            2,
            false,
            false,
            &mut recovery,
            &mut output,
        )?;
        if client.transport().sent != 33
            || server.transport().sent != 33
            || HANDLERS.load(Ordering::SeqCst) != 33
        {
            return Err("allocated capacity census".into());
        }
        Ok(Trace {
            client_sends: client.transport().sent as u64,
            server_sends: server.transport().sent as u64,
            receiving: sample.count as u64 + refusal.count as u64 + recovery.receiving,
            housekeeping: 0,
            handlers: HANDLERS.load(Ordering::SeqCst),
            collections: 2 + recovery.collections,
        })
    })
}

fn qualification(out: &mut Json, start: Instant) -> Result<(), Failure> {
    write!(out, ",\"traces\":[")?;
    for (fault, id) in ORACLE_TRACES.iter().enumerate() {
        deadline(start, 20)?;
        oracle_trace(fault)?;
        if fault > 0 {
            write!(out, ",")?;
        }
        write!(
            out,
            "{{\"id\":\"{id}\",\"datagram_sends\":0,\"receiving_polls\":0,\"handler_calls\":0,\"final\":\"oracle_refused\"}}"
        )?;
    }
    let mut queued = service_io();
    queued.send(PEER, b"one")?;
    let mut occupied = service_io();
    occupied.io.input_len = Some(1);
    if service_bridge(&mut queued, &mut occupied).is_ok()
        || queued.io.output_len != Some(3)
        || queued.send(PEER, b"extra").is_ok()
        || queued.sent != 1
    {
        return Err("extra packet/occupied bridge oracle accepted".into());
    }
    write!(
        out,
        ",{{\"id\":\"transport.extra_packet_and_occupied_bridge\",\"datagram_sends\":{},\"receiving_polls\":0,\"handler_calls\":0,\"final\":\"first_packet_preserved_extra_refused\"}}",
        queued.sent
    )?;
    auth_trace()?;
    write!(
        out,
        ",{{\"id\":\"crypto.tamper_replay_wrong_binding_then_authenticate\",\"datagram_sends\":0,\"receiving_polls\":0,\"handler_calls\":0,\"request_seals\":2,\"request_open_attempts\":3,\"response_seals\":1,\"response_open_attempts\":2,\"final\":\"correct_binding_authenticated\"}}"
    )?;
    for protected in [false, true] {
        let security = if protected { "oscore" } else { "unprotected" };
        deadline(start, 20)?;
        upload_capacity_trace(protected)?.emit(
            out,
            &format!("upload.capacity_preserve_finish_recover.{security}"),
        )?;
        deadline(start, 20)?;
        download_capacity_trace(protected)?.emit(
            out,
            &format!("download.capacity_preserve_collect_recover.{security}"),
        )?;
        for expire in [false, true] {
            deadline(start, 20)?;
            download_cancel_trace(protected, expire)?.emit(
                out,
                &format!(
                    "download.{}.{security}",
                    if expire { "expire" } else { "cancel" }
                ),
            )?;
        }
        for (fault, name) in ["body_or_tag", "wrong_token", "missing"].iter().enumerate() {
            deadline(start, 20)?;
            download_rejection_trace(protected, fault)?
                .emit(out, &format!("download.reject_{name}.{security}"))?;
        }
    }
    deadline(start, 20)?;
    upload_peer_trace()?.emit(
        out,
        "upload.wrong_peer_preserves_partial_then_cancel_recover.oscore",
    )?;
    deadline(start, 20)?;
    upload_auth_trace()?.emit(
        out,
        "upload.app_tamper_replay_preserves_partial_finish_recover.oscore",
    )?;
    write!(out, "]")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_cli_rejects_overrides_and_legacy_spelling() {
        for word in ["qualify", "measure"] {
            let args = ["bench-core", "--incoming-rx", word].map(str::to_owned);
            assert!(mode(&args).is_ok());
            for extra in ["64", "--oscore", "--warm=0", ""] {
                let mut args = args.to_vec();
                args.push(extra.into());
                assert!(mode(&args).is_err());
            }
        }
        for args in [
            vec!["bench-core", "--incoming-rx"],
            vec!["bench-core", "--incoming-rx", "Measure"],
            vec!["bench-core", "72", "--incoming-rx"],
        ] {
            assert!(mode(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err());
        }
    }
    #[test]
    fn independent_wire_metadata_and_body_mismatches_are_refused() {
        for fault in 0..ORACLE_TRACES.len() {
            oracle_trace(fault).unwrap();
        }
        let cf = ContentFormat::OCTET_STREAM.encode();
        let block = BlockValue::new(0, true, 6).unwrap().encode();
        let opts = [
            Opt::etag(b"fixture"),
            Opt::content_format(&cf),
            Opt::block2(&block),
        ];
        let message = Message::new(Type::Acknowledgement, Code::CONTENT, MessageId::new(1))
            .with_options(&opts)
            .with_payload(&SERVICE_BODY[..1024]);
        let mut bytes = [0; WIRE];
        let n = message.encode(&mut bytes).unwrap();
        verify_download_fragment(&decode(&bytes[..n]).unwrap(), 0, false).unwrap();
    }
    #[test]
    fn receiving_counts_sums_and_overflow_conserve_complete_transfers() {
        let mut s = Sample::default();
        for n in [3, 5, 7, 11] {
            s.add(Some(n)).unwrap();
        }
        s.validate(4, true).unwrap();
        assert_eq!(s.sum, 26);
        assert!(s.validate(16, true).is_err());
        s.ns[2] += 1;
        assert!(s.validate(4, true).is_err());
        let mut s = Sample {
            sum: u128::MAX,
            ..Sample::default()
        };
        assert!(s.add(Some(1)).is_err());
        assert_eq!(s.count, 0);
        assert_eq!(s.sum, u128::MAX);
        let mut s = Sample::default();
        for _ in 0..16 {
            s.add(None).unwrap();
        }
        assert!(s.add(None).is_err());
        s.validate(16, false).unwrap();
        let report = failure_report("original transfer error");
        assert_eq!(
            std::str::from_utf8(&report.bytes[..report.len]).unwrap(),
            "incoming-rx validation failed: original transfer error\n"
        );
        let report = failure_report("?".repeat(FAILURE_RESERVE));
        assert!(report.len <= FAILURE_RESERVE);
        assert!(std::str::from_utf8(&report.bytes[..report.len]).is_ok());
        assert!(report.bytes[..report.len].starts_with(b"incoming-rx validation failed: "));
        require_expired_call::<()>(Some(Err(coaptic::CallFailure::DeadlineExceeded))).unwrap();
        for wrong in [
            None,
            Some(Ok(())),
            Some(Err(coaptic::CallFailure::Cancelled)),
        ] {
            assert!(require_expired_call(wrong).is_err());
        }
    }
    #[test]
    fn genuine_oscore_tamper_replay_and_wrong_request_binding_refuse() {
        auth_trace().unwrap();
    }
}
