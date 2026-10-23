//! Socket-free, diagnostics-disabled request-path diagnostic.
//!
//! Identical fixtures can link different Coaptic revisions to isolate core work
//! from OS socket scheduling. Request preparation and complete reply validation
//! are outside each timed poll. Per-call clocks perturb these measurements;
//! they are not production latency or throughput estimates.
use coaptic::message::{Message, MessageId, Opt, Token, Type, decode};
use coaptic::storage::{Capacities, DatagramIo};
use coaptic::{App, Code, ContentFormat, Endpoint, Request, Response, get};
use std::hint::black_box;
use std::io::{Read, Write};
use std::time::Instant;

const BODY: [u8; 64] = [0x5a; 64];
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let batch_cpu = args.len() == 4 && args[3] == "--batch-cpu";
    if !(2..=3).contains(&args.len()) && !batch_cpu {
        return Err("usage: bench-core OPERATIONS (1..=60000) [unprotected|oscore]".into());
    }
    let operations: usize = args[1].parse()?;
    if !(1..=60000).contains(&operations) {
        return Err("operation limit".into());
    }
    if batch_cpu && operations != 50_000 {
        return Err("batch CPU requires exactly 50000 operations".into());
    }
    let security = args.get(2).map_or("unprotected", String::as_str);
    let (client_context, server_context) = match security {
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
    let mut client_context = client_context;
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
    let mut app = builder.bind_alloc(
        CoreIo {
            input: [0; 1472],
            input_len: None,
            output: [0; 1472],
            output_len: None,
        },
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
    )?;
    if batch_cpu {
        return batch_run(&mut app, client_context, security);
    }
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
        let outcome = black_box(black_box(&mut app).poll(black_box(now)));
        let elapsed = started.elapsed().as_nanos();
        outcome.map_err(|_| "poll failure")?;
        let io = app.transport_mut();
        let n = io.output_len.take().ok_or("missing response")?;
        let wire = decode(black_box(&io.output[..n]))?;
        let reply = match client_context.as_mut() {
            Some(context) => {
                let binding = context.take(token).ok_or("request binding")?;
                context.unprotect_response(&wire, binding, &mut opened)?
            }
            None => wire,
        };
        let mut etags = reply.etag();
        if reply.message_id() != mid
            || reply.token() != token
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
    println!("]}}");
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
    writeln!(
        output,
        "{{\"event\":\"fixture\",\"security\":\"{security}\",\"requested_bytes\":{requested_bytes},\"row_bytes\":{},\"row_metadata_bytes\":{metadata_bytes},\"request_ref_bytes\":{},\"optional_request_ref_bytes\":{},\"wire_bytes\":25600000,\"capture_datagram_bytes\":256,\"app_datagram_bytes\":1472,\"app_heap_bytes\":{app_heap_bytes},\"app_inline_bytes\":{},\"fixture_inline_bytes\":{},\"scratch_allowance_bytes\":16384,\"rows\":50000,\"limit_bytes\":33554432}}",
        std::mem::size_of::<BatchRow>(),
        std::mem::size_of::<coaptic::oscore::RequestRef>(),
        std::mem::size_of::<Option<coaptic::oscore::RequestRef>>(),
        std::mem::size_of_val(app),
        std::mem::size_of::<BatchFixture>()
    )?;
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

    fn fixture(protected: bool) -> (CoreApp, Option<coaptic::oscore::SecurityContext>) {
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
}
