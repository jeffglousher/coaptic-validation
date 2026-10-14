//! Complete-operation diagnostic using Coaptic at both ends, not an independent
//! interoperability peer or a replacement for the matched external driver.
//! Loopback only; bounded allocations happen before timing. Spin consumes CPU,
//! while sleep1 deliberately demonstrates a caller-imposed per-poll delay.
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
impl DatagramIo for CountIo {
    type Error = std::io::Error;
    fn recv(&mut self, bytes: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        let result = self.io.recv(bytes)?;
        self.received += u64::from(result.is_some());
        Ok(result)
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        let n = self.io.send(peer, bytes)?;
        self.sent += 1;
        Ok(n)
    }
}
type Client = App<coaptic::profiles::Default, CountIo, 1, true, AllocMemory>;

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
    let gated = args.last().is_some_and(|v| v == "--gated");
    if gated {
        args.pop();
    }
    if !(8..=9).contains(&args.len()) {
        return Err("usage: bench-native-client PORT BYTES OPERATIONS WARMUP TIMEOUT_MS spin|sleep1 plaintext|oscore [CREDENTIALS] [--gated]".into());
    }
    let port: u16 = args[1].parse()?;
    let size: usize = args[2].parse()?;
    let operations: usize = args[3].parse()?;
    let warmup: usize = args[4].parse()?;
    let timeout_ms: u64 = args[5].parse()?;
    if port == 0
        || !(1..=65536).contains(&size)
        || !(1..=20000).contains(&operations)
        || warmup > 1000
        || !(1..=60000).contains(&timeout_ms)
    {
        return Err("diagnostic bounds".into());
    }
    let sleep = match args[6].as_str() {
        "spin" => false,
        "sleep1" => true,
        _ => return Err("poll policy".into()),
    };
    let context = match (args[7].as_str(), args.get(8)) {
        ("plaintext", None) => None,
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
        builder.allow_plaintext()
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
        tx_body_bytes: Some(capacity),
    };
    let heap_limit = AllocMemory::required_heap_bytes(capacities)?;
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
    for _ in 0..operations {
        timings.push(exchange(
            &mut client,
            peer,
            &clock,
            timeout,
            sleep,
            &mut output,
            &expected,
        )?);
    }
    let elapsed = started.elapsed().as_nanos();
    let received = client.transport().received - before.0;
    let sent = client.transport().sent - before.1;
    println!(
        "{{\"schema\":\"coaptic-native-complete/1\",\"bytes\":{size},\"completed\":{operations},\"warmup\":{warmup},\"elapsed_ns\":{elapsed},\"received_datagrams\":{received},\"sent_datagrams\":{sent},\"latencies_ns\":{timings:?},\"core_heap_limit_bytes\":{heap_limit},\"app_inline_bytes\":{app_inline_bytes},\"verification_heap_bytes\":{verification_heap_bytes},\"timing_heap_bytes\":{timing_heap_bytes},\"udp_scratch_bytes\":1473,\"policy\":\"{}\",\"security\":\"{}\",\"measurement\":\"Coaptic client/server diagnostic; complete authenticated body verification; setup excluded; no durable recovery; heap request excludes allocator overhead; App inline includes UDP scratch\"}}",
        args[6], args[7]
    );
    std::io::stdout().flush()?;
    if gated {
        // Keep process handles live for post-window CPU/RSS sampling. This wait
        // is outside operation and campaign timing, and makes no network calls.
        gate("exit")?;
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
    fn control_gate_is_bounded_and_refuses_wrong_or_incomplete_input() {
        assert!(read_gate(&b"run\n"[..], "run").is_ok());
        assert!(read_gate(&b"exit\n"[..], "exit").is_ok());
        assert!(read_gate(&b"run\r\n"[..], "run").is_ok());
        assert!(read_gate(&b"exit\r\n"[..], "exit").is_ok());
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
