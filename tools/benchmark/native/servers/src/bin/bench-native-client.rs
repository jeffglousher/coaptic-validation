//! Complete-operation diagnostic using Coaptic at both ends, not an independent
//! interoperability peer or a replacement for the matched external driver.
//! Loopback only; bounded allocations happen before timing. Spin consumes CPU,
//! while sleep1 deliberately demonstrates a caller-imposed per-poll delay.
//! Optional absolute-deadline pacing never drops operations to catch up. The
//! paced dispatch schedules are limited to two minutes. A conservative 60,000
//! outbound-datagram budget includes warmup and measurement on this fresh socket;
//! it avoids scheduling a campaign that reaches the core's safe Message ID
//! lifetime refusal. This diagnostic budget is not a product capacity. Every
//! completed latency is retained. CPU-gated campaigns stop before report
//! formatting so an external process can sample CPU first.
#![forbid(unsafe_code)]
use coaptic::{
    App, Code, ContentFormat, Response,
    oscore::{DeriveParams, SecurityContext},
    storage::{AllocMemory, Capacities, DatagramIo, Endpoint, UdpSocketIo},
};
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
type Client = App<coaptic::profiles::Default, CountIo, 1, true, AllocMemory>;

const MAX_OPERATIONS: usize = 60_000;
const MAX_RATE: u32 = 1_000_000;
const MAX_PACED_SECONDS: u64 = 120;
const MAX_OUTBOUND_DATAGRAMS: usize = 60_000;

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

#[derive(Debug, Default, PartialEq, Eq)]
struct RunOptions {
    gate: GateMode,
    rate: Option<u32>,
}

fn run_options(args: &mut Vec<String>) -> Result<RunOptions, &'static str> {
    let mut options = RunOptions::default();
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
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
            _ => index += 1,
        }
    }
    Ok(options)
}

fn scheduled_offset(index: usize, rate: u32) -> Duration {
    // CLI bounds limit this product to 10^15 ns and the admitted schedule to
    // two minutes. Deriving every deadline from the origin avoids sleep drift.
    Duration::from_nanos(index as u64 * 1_000_000_000 / u64::from(rate))
}

fn wait_until(deadline: Instant) -> Duration {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return now.duration_since(deadline);
        }
        std::thread::sleep(deadline.duration_since(now));
    }
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

fn exchange(
    client: &mut Client,
    peer: Endpoint,
    clock: &Instant,
    timeout: Duration,
    sleep: bool,
    output: &mut [u8],
    expected: &[u8],
) -> Result<u64, &'static str> {
    let started = Instant::now();
    let deadline = started + timeout;
    let call = client
        .get("bench")
        .to(peer)
        .send(clock.elapsed().as_millis() as u64)
        .map_err(|_| "send")?;
    loop {
        if Instant::now() >= deadline {
            // The campaign fails rather than admitting another overlapping call.
            return Err("complete operation deadline");
        }
        client
            .poll(clock.elapsed().as_millis() as u64)
            .map_err(|_| "poll")?;
        if let Some(reply) = client
            .take_response_into(call, output)
            .map_err(|_| "output")?
        {
            verify(&reply.map_err(|_| "call")?, expected)?;
            return Ok(started.elapsed().as_nanos() as u64);
        }
        if sleep {
            std::thread::sleep(Duration::from_millis(1));
        } else {
            std::hint::spin_loop();
        }
    }
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
    let gated = options.gate != GateMode::None;
    if !(8..=9).contains(&args.len()) {
        return Err("usage: bench-native-client PORT BYTES OPERATIONS WARMUP TIMEOUT_MS spin|sleep1 unprotected|oscore [CREDENTIALS] [--gated|--cpu-gated] [--rate OPS_PER_SEC]".into());
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
    outbound_budget(size, operations, warmup)?;
    let scheduled_span = options
        .rate
        .map(|rate| scheduled_offset(operations - 1, rate));
    if scheduled_span.is_some_and(|span| span > Duration::from_secs(MAX_PACED_SECONDS)) {
        return Err("paced dispatch schedule exceeds two minutes".into());
    }
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
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_nonblocking(true)?;
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
    let capacity = size.div_ceil(1024) * 1024;
    let capacities = Capacities {
        rx_datagram_slots: 4,
        rx_datagram_bytes: 1472,
        tx_datagram_slots: 4,
        tx_datagram_bytes: 1472,
        dedup_entries: 8,
        observe_entries: 4,
        rx_body_slots: Some(1),
        rx_body_bytes: Some(capacity),
        tx_body_slots: Some(1),
        // GET has no request body; response length does not size TX storage.
        tx_body_bytes: Some(1024),
    };
    let heap_limit = AllocMemory::<coaptic::message::Token>::required_heap_bytes(capacities)?;
    let storage = AllocMemory::try_new(capacities, heap_limit)?;
    let mut client = builder.bind_storage(
        CountIo {
            io: UdpSocketIo::new(socket, [0; 1473])?,
            received: 0,
            sent: 0,
        },
        storage,
    )?;
    let expected: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
    let mut output = vec![0; size];
    let mut timings = Vec::with_capacity(operations);
    let app_inline_bytes = std::mem::size_of_val(&client);
    let verification_heap_bytes = expected.capacity() + output.capacity();
    let timing_heap_bytes = timings.capacity() * std::mem::size_of::<u64>();
    let clock = Instant::now();
    let peer = Endpoint::v4([127, 0, 0, 1], port);
    let timeout = Duration::from_millis(timeout_ms);
    for _ in 0..warmup {
        exchange(
            &mut client,
            peer,
            &clock,
            timeout,
            sleep,
            &mut output,
            &expected,
        )?;
    }
    if gated {
        eprintln!("ready");
        gate("run")?;
    }
    let before = (client.transport().received, client.transport().sent);
    let started = Instant::now();
    let mut pacing_late_operations = 0usize;
    let mut pacing_missed_period_operations = 0usize;
    let mut pacing_lateness_ns = 0u128;
    let mut pacing_max_lateness_ns = 0u128;
    let mut failure = None;
    for index in 0..operations {
        if let Some(rate) = options.rate {
            let lateness = wait_until(started + scheduled_offset(index, rate));
            let ns = lateness.as_nanos();
            pacing_late_operations += usize::from(!lateness.is_zero());
            pacing_missed_period_operations += usize::from(lateness >= scheduled_offset(1, rate));
            pacing_lateness_ns += ns;
            pacing_max_lateness_ns = pacing_max_lateness_ns.max(ns);
        }
        match exchange(
            &mut client,
            peer,
            &clock,
            timeout,
            sleep,
            &mut output,
            &expected,
        ) {
            Ok(latency) => timings.push(latency),
            Err(error) => {
                // Never start a second Call after an unresolved failed one.
                // Preserve completed samples and account for the failed attempt
                // and the explicitly unattempted remainder of the campaign.
                failure = Some(error);
                break;
            }
        }
    }
    let elapsed = started.elapsed().as_nanos();
    let received = client.transport().received - before.0;
    let sent = client.transport().sent - before.1;
    if options.gate == GateMode::Cpu {
        eprintln!("measured");
        gate("report")?;
    }
    let completed = timings.len();
    let failed = usize::from(failure.is_some());
    let attempted = completed + failed;
    let unattempted = operations - attempted;
    let achieved_rate = completed as f64 * 1_000_000_000.0 / elapsed as f64;
    let rate_json = options
        .rate
        .map_or_else(|| "null".to_owned(), |r| r.to_string());
    let span_json = scheduled_span.map_or_else(|| "null".to_owned(), |s| s.as_nanos().to_string());
    // All possible campaign errors are fixed ASCII strings, not peer input.
    let failure_json = failure.map_or_else(|| "null".to_owned(), |e| format!("{e:?}"));
    println!(
        "{{\"schema\":\"coaptic-native-complete/1\",\"bytes\":{size},\"requested_operations\":{operations},\"attempted\":{attempted},\"completed\":{completed},\"failed\":{failed},\"unattempted\":{unattempted},\"failure\":{failure_json},\"warmup\":{warmup},\"elapsed_ns\":{elapsed},\"scheduled_rate_ops_per_second\":{rate_json},\"achieved_ops_per_second\":{achieved_rate},\"scheduled_dispatch_span_ns\":{span_json},\"pacing_late_operations\":{pacing_late_operations},\"pacing_missed_period_operations\":{pacing_missed_period_operations},\"pacing_total_lateness_ns\":{pacing_lateness_ns},\"pacing_max_lateness_ns\":{pacing_max_lateness_ns},\"pacing_dropped_operations\":0,\"pacing_semantics\":\"absolute operation-start deadlines; one outstanding Call; late starts catch up without dropping; elapsed includes pacing; latencies exclude pacing\",\"received_datagrams\":{received},\"sent_datagrams\":{sent},\"latencies_ns\":{timings:?},\"core_heap_limit_bytes\":{heap_limit},\"app_inline_bytes\":{app_inline_bytes},\"verification_heap_bytes\":{verification_heap_bytes},\"timing_heap_bytes\":{timing_heap_bytes},\"udp_scratch_bytes\":1473,\"policy\":\"{}\",\"security\":\"{}\",\"measurement\":\"Coaptic client/server diagnostic; complete authenticated body verification; setup excluded; no durable recovery; heap request excludes allocator overhead; App inline includes UDP scratch\"}}",
        args[6], args[7]
    );
    std::io::stdout().flush()?;
    if gated {
        // Keep process handles live for post-window CPU/RSS sampling. This wait
        // is outside operation and campaign timing, and makes no network calls.
        gate("exit")?;
    }
    if let Some(error) = failure {
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
