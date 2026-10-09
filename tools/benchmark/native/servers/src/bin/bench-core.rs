//! Socket-free, feature-disabled request-path diagnostic.
//!
//! Identical fixtures can link different Coaptic revisions to isolate core work
//! from OS socket scheduling. Request preparation and complete reply validation
//! are outside each timed poll. Per-call clocks perturb these measurements;
//! they are not production latency or throughput estimates.
use coaptic::message::{Message, MessageId, Opt, Token, Type, decode};
use coaptic::storage::{Capacities, DatagramIo};
use coaptic::{App, Code, ContentFormat, Endpoint, Request, Response, get};
use std::time::Instant;

const BODY: [u8; 64] = [0x5a; 64];
const PEER: Endpoint = Endpoint::v4([127, 0, 0, 1], 30000);

struct CoreIo {
    input: [u8; 64],
    input_len: Option<usize>,
    output: [u8; 1472],
    output_len: Option<usize>,
}

impl DatagramIo for CoreIo {
    type Error = &'static str;

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
    if args.len() != 2 {
        return Err("usage: bench-core OPERATIONS (1..=60000)".into());
    }
    let operations: usize = args[1].parse()?;
    if !(1..=60000).contains(&operations) {
        return Err("operation limit".into());
    }
    let mut app = App::builder()
        .allow_plaintext()
        .routes::<1>()
        .block_wise::<true>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .route("bench", get(representation))
        .bind_alloc(
            CoreIo {
                input: [0; 64],
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
    let mut latencies = Vec::with_capacity(operations);
    let clock = Instant::now();
    for operation in 0..operations + 128 {
        let mid = MessageId::new(operation as u16);
        let token = Token::new(&(operation as u64).to_be_bytes()).ok_or("token")?;
        let options = [Opt::uri_path("bench")];
        let request = Message::con(Code::GET, mid, token).with_options(&options);
        let io = app.transport_mut();
        io.input_len = Some(request.encode(&mut io.input)?);
        let now = clock.elapsed().as_millis() as u64;
        let started = Instant::now();
        let outcome = app.poll(now);
        let elapsed = started.elapsed().as_nanos();
        outcome.map_err(|_| "poll failure")?;
        let io = app.transport_mut();
        let n = io.output_len.take().ok_or("missing response")?;
        let reply = decode(&io.output[..n])?;
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
    print!("{{\"operations\":{operations},\"warmup\":128,\"latencies_ns\":[");
    for (i, elapsed) in latencies.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("{elapsed}");
    }
    println!("]}}");
    Ok(())
}
