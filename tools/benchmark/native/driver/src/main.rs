//! External socket driver. Complete verified representations define completion.
//!
//! Fixtures declare application/octet-stream; replies must carry exactly one
//! matching Content-Format in addition to complete, byte-exact body validation.
#![forbid(unsafe_code)]

use std::{
    env,
    net::UdpSocket,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

struct Config {
    endpoint: String,
    bytes: usize,
    concurrency: usize,
    operations: usize,
    warmup: usize,
    timeout_ms: u64,
    confirmable: bool,
}

struct Block {
    number: u32,
    more: bool,
    size: usize,
}

struct Reply<'a> {
    body: &'a [u8],
    block: Option<Block>,
    etag: Option<&'a [u8]>,
}

struct Endpoint {
    socket: UdpSocket,
    next_mid: u32,
    retired: Vec<UdpSocket>,
}

impl Endpoint {
    fn new(config: &Config) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(&config.endpoint)?;
        Ok(Self {
            socket,
            next_mid: 0,
            retired: Vec::new(),
        })
    }

    fn reserve(&mut self, config: &Config) -> Result<(), &'static str> {
        let worst_case = config.bytes.div_ceil(16) as u32;
        if self.next_mid + worst_case > 65_536 {
            let fresh = Self::new(config).map_err(|_| "driver endpoint rotation")?;
            self.retired
                .push(std::mem::replace(&mut self.socket, fresh.socket));
            self.next_mid = 0;
        }
        Ok(())
    }
}

fn reserved_endpoint_count(config: &Config) -> usize {
    let representations_per_endpoint = 65_536 / config.bytes.div_ceil(16);
    (0..config.concurrency)
        .map(|worker| {
            let count = config.operations / config.concurrency
                + usize::from(worker < config.operations % config.concurrency);
            (count + config.warmup)
                .div_ceil(representations_per_endpoint)
                .max(1)
        })
        .sum()
}

fn extended(bytes: &[u8], cursor: &mut usize, nibble: u8) -> Result<u16, &'static str> {
    let result = match nibble {
        0..=12 => u16::from(nibble),
        13 => {
            let result = 13 + u16::from(*bytes.get(*cursor).ok_or("short option")?);
            *cursor += 1;
            result
        }
        14 => {
            let slice = bytes.get(*cursor..*cursor + 2).ok_or("short option")?;
            *cursor += 2;
            269u16
                .checked_add(u16::from_be_bytes([slice[0], slice[1]]))
                .ok_or("option overflow")?
        }
        _ => return Err("reserved option"),
    };
    Ok(result)
}

fn response<'a>(wire: &'a [u8], token: &[u8; 8]) -> Result<Reply<'a>, &'static str> {
    if wire.len() < 12
        || wire[0] >> 6 != 1
        || wire[0] & 15 != 8
        || wire[0] >> 4 & 3 == 3
        || wire[1] != 69
        || wire[4..12] != token[..]
    {
        return Err("response identity/status");
    }
    let mut cursor = 12;
    let mut number = 0u16;
    let mut block = None;
    let mut etag = None;
    let mut content_format = false;
    while cursor < wire.len() && wire[cursor] != 255 {
        let header = wire[cursor];
        cursor += 1;
        number = number
            .checked_add(extended(wire, &mut cursor, header >> 4)?)
            .ok_or("option overflow")?;
        let length = usize::from(extended(wire, &mut cursor, header & 15)?);
        let value = wire.get(cursor..cursor + length).ok_or("short option")?;
        cursor += length;
        match number {
            4 => {
                if etag.is_some() || value.is_empty() || value.len() > 8 {
                    return Err("invalid etag");
                }
                etag = Some(value);
            }
            23 => {
                if block.is_some() || value.len() > 3 {
                    return Err("invalid Block2");
                }
                let raw = value
                    .iter()
                    .fold(0u32, |n, byte| (n << 8) | u32::from(*byte));
                if raw & 7 == 7 {
                    return Err("BERT on UDP");
                }
                block = Some(Block {
                    number: raw >> 4,
                    more: raw & 8 != 0,
                    size: 1 << ((raw & 7) + 4),
                });
            }
            12 => {
                if content_format || value.len() > 2 {
                    return Err("invalid fixture Content-Format");
                }
                let format = value
                    .iter()
                    .fold(0u16, |n, byte| (n << 8) | u16::from(*byte));
                if format != 42 {
                    return Err("wrong fixture Content-Format");
                }
                content_format = true;
            }
            14 | 28 => {}
            critical if critical & 1 != 0 => return Err("unsupported critical response option"),
            _ => {}
        }
    }
    let body = if cursor < wire.len() {
        &wire[cursor + 1..]
    } else {
        &[]
    };
    if !content_format {
        return Err("missing fixture Content-Format");
    }
    if body.is_empty() {
        return Err("empty fixture representation");
    }
    Ok(Reply { body, block, etag })
}

fn request(mid: u16, token: &[u8; 8], block: Option<u32>, confirmable: bool) -> Vec<u8> {
    let [hi, lo] = mid.to_be_bytes();
    let mut bytes = vec![if confirmable { 0x48 } else { 0x58 }, 1, hi, lo];
    bytes.extend_from_slice(token);
    bytes.extend_from_slice(b"\xb5bench");
    if let Some(block) = block {
        let raw = block.to_be_bytes();
        let first = raw.iter().position(|byte| *byte != 0).unwrap_or(4);
        bytes.push(0xc0 | (4 - first) as u8);
        bytes.extend_from_slice(&raw[first..]);
    }
    bytes
}

fn exchange(
    endpoint: &mut Endpoint,
    config: &Config,
    worker: usize,
    sequence: u64,
) -> Result<u64, &'static str> {
    endpoint.reserve(config)?;
    let socket = &endpoint.socket;
    let token = ((worker as u64) << 48 | sequence).to_be_bytes();
    let start = Instant::now();
    let deadline = start + Duration::from_millis(config.timeout_ms);
    let mut offset = 0usize;
    let mut block_request = if config.bytes > 1024 { Some(6) } else { None };
    let mut expected_etag: Option<Vec<u8>> = None;
    let mut etag_seen = false;
    let mut wire = [0u8; 65_535];
    loop {
        let current_mid = u16::try_from(endpoint.next_mid).map_err(|_| "driver MID exhaustion")?;
        endpoint.next_mid += 1;
        let outgoing = request(current_mid, &token, block_request, config.confirmable);
        socket.send(&outgoing).map_err(|_| "send")?;
        let reply = loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or("deadline")?;
            socket
                .set_read_timeout(Some(remaining))
                .map_err(|_| "timeout setup")?;
            let length = socket.recv(&mut wire).map_err(|_| "receive/deadline")?;
            if length == 4
                && wire[0] == 0x60
                && wire[1] == 0
                && wire[2..4] == current_mid.to_be_bytes()
            {
                continue;
            }
            if length < 12 || wire[4..12] != token {
                continue;
            }
            if wire[0] >> 6 != 1 {
                return Err("version");
            }
            let ty = wire[0] >> 4 & 3;
            if ty == 3 || (ty == 2 && !config.confirmable) {
                return Err("invalid response type");
            }
            if ty == 2 && wire[2..4] != current_mid.to_be_bytes() {
                continue;
            }
            if ty == 0 {
                socket
                    .send(&[0x60, 0, wire[2], wire[3]])
                    .map_err(|_| "ACK send")?;
            }
            break response(&wire[..length], &token)?;
        };
        let current_etag = reply.etag.map(<[u8]>::to_vec);
        if etag_seen && current_etag != expected_etag {
            return Err("changed representation etag");
        }
        expected_etag = current_etag;
        etag_seen = true;
        if offset + reply.body.len() > config.bytes
            || reply
                .body
                .iter()
                .enumerate()
                .any(|(i, byte)| *byte != ((offset + i) % 251) as u8)
        {
            return Err("representation mismatch");
        }
        let more = match reply.block {
            Some(block) => {
                if block.number as usize * block.size != offset
                    || reply.body.len() > block.size
                    || (block.more && reply.body.len() != block.size)
                {
                    return Err("Block2 range");
                }
                offset += reply.body.len();
                if offset % block.size != 0 && block.more {
                    return Err("Block2 alignment");
                }
                block_request =
                    Some(((offset / block.size) as u32) << 4 | (block.size.trailing_zeros() - 4));
                block.more
            }
            None => {
                offset += reply.body.len();
                false
            }
        };
        if !more {
            if offset != config.bytes {
                return Err("incomplete representation");
            }
            return Ok(start.elapsed().as_nanos() as u64);
        }
        if offset >= config.bytes {
            return Err("Block2 M contradicts total bytes");
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 9 {
        return Err(
            "usage: bench-load HOST PORT BYTES CONCURRENCY OPERATIONS WARMUP TIMEOUT_MS con|non"
                .into(),
        );
    }
    let config = Arc::new(Config {
        endpoint: format!("{}:{}", args[1], args[2]),
        bytes: args[3].parse()?,
        concurrency: args[4].parse()?,
        operations: args[5].parse()?,
        warmup: args[6].parse()?,
        timeout_ms: args[7].parse()?,
        confirmable: match args[8].as_str() {
            "con" => true,
            "non" => false,
            _ => return Err("invalid mode".into()),
        },
    });
    if !(1..=128).contains(&config.concurrency)
        || !(1..=200_000).contains(&config.operations)
        || !(1..=1_048_576).contains(&config.bytes)
        || config.warmup > 10_000
        || !(1..=60_000).contains(&config.timeout_ms)
    {
        return Err("bounds".into());
    }
    let reserved_endpoints = reserved_endpoint_count(&config);
    if reserved_endpoints > 1024 {
        return Err("driver endpoint reservation exceeds 1024; split into smaller sessions".into());
    }
    let mut sockets = Vec::new();
    for _ in 0..config.concurrency {
        sockets.push(Endpoint::new(&config)?);
    }
    let barrier = Arc::new(Barrier::new(config.concurrency + 1));
    let mut workers = Vec::new();
    for (worker, mut endpoint) in sockets.into_iter().enumerate() {
        let config = Arc::clone(&config);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            let mut sequence = 1u64;
            let mut warmup_failed = 0;
            for _ in 0..config.warmup {
                if exchange(&mut endpoint, &config, worker, sequence).is_err() {
                    warmup_failed += 1;
                }
                sequence += 1;
            }
            let count = config.operations / config.concurrency
                + usize::from(worker < config.operations % config.concurrency);
            let mut timings = Vec::with_capacity(count);
            let mut failures = 0usize;
            let mut driver_failures = 0usize;
            barrier.wait();
            barrier.wait();
            for _ in 0..count {
                match exchange(&mut endpoint, &config, worker, sequence) {
                    Ok(elapsed) => timings.push(elapsed),
                    Err(error) => {
                        failures += 1;
                        if error.starts_with("driver ") {
                            driver_failures += 1;
                        }
                    }
                }
                sequence += 1;
            }
            (timings, failures, warmup_failed, driver_failures, endpoint)
        }));
    }
    barrier.wait();
    let started = Instant::now();
    barrier.wait();
    let mut timings = Vec::new();
    let mut failures = 0;
    let mut warmup_failures = 0;
    let mut driver_failures = 0;
    let mut retained_endpoints = Vec::new();
    for worker in workers {
        let (latencies, failed, warmup_failed, driver_failed, endpoint) =
            worker.join().map_err(|_| "worker panic")?;
        timings.extend(latencies);
        failures += failed;
        warmup_failures += warmup_failed;
        driver_failures += driver_failed;
        retained_endpoints.push(endpoint);
    }
    let elapsed = started.elapsed().as_nanos();
    let rotations: usize = retained_endpoints
        .iter()
        .map(|endpoint| endpoint.retired.len())
        .sum();
    let latencies = timings
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "{{\"schema\":\"coaptic-load/1\",\"protocol\":\"coap\",\"security\":\"plaintext\",\"mode\":\"{}\",\"concurrency\":{},\"warmup\":{},\"attempted\":{},\"completed\":{},\"failed\":{},\"warmup_failed\":{},\"driver_failures\":{},\"endpoint_rotations\":{},\"verified_bytes\":{},\"elapsed_ns\":{},\"latencies_ns\":[{}],\"clock\":\"std::time::Instant\",\"measurement\":\"closed-loop; complete byte validation included; endpoint rotation in wall time\"}}",
        args[8],
        config.concurrency,
        config.warmup,
        config.operations,
        timings.len(),
        failures,
        warmup_failures,
        driver_failures,
        rotations,
        timings.len() * config.bytes,
        elapsed,
        latencies
    );
    if failures > 0 || warmup_failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_request_and_hostile_response() {
        let token = [1; 8];
        assert_eq!(
            &request(0x1234, &token, Some(6), true)[12..],
            b"\xb5bench\xc1\x06"
        );
        let mut wire = vec![0x68, 69, 0x12, 0x34];
        wire.extend_from_slice(&token);
        wire.extend_from_slice(&[0xc1, 42, 255, 0, 1, 2]);
        assert_eq!(response(&wire, &token).unwrap().body, &[0, 1, 2]);
        wire[0] = 0x78;
        assert!(response(&wire, &token).is_err());
        wire[0] = 0x68;
        let mut block_wire = wire[..12].to_vec();
        block_wire.extend_from_slice(&[0xc1, 42, 0xb1, 6, 255, 0, 1, 2]);
        let reply = response(&block_wire, &token).unwrap();
        let block = reply.block.unwrap();
        assert_eq!(block.number, 0);
        assert_eq!(block.size, 1024);
        assert!(!block.more);
        assert_eq!(reply.body, &[0, 1, 2]);
        wire[1] = 128;
        assert!(response(&wire, &token).is_err());
    }

    #[test]
    fn fixture_format_missing_wrong_duplicate_or_overwide_is_rejected() {
        let token = [1; 8];
        let mut header = vec![0x68, 69, 0x12, 0x34];
        header.extend_from_slice(&token);
        for options in [
            vec![],
            vec![0xc1, 0],
            vec![0xc1, 42, 0x01, 42],
            vec![0xc3, 0, 0, 42],
        ] {
            let mut wire = header.clone();
            wire.extend_from_slice(&options);
            wire.extend_from_slice(&[255, 0, 1, 2]);
            assert!(response(&wire, &token).is_err(), "{options:?}");
        }
    }

    #[test]
    fn mid_reservation_rotates_without_reusing_live_ports() {
        let config = Config {
            endpoint: "127.0.0.1:9".into(),
            bytes: 65536,
            concurrency: 1,
            operations: 2,
            warmup: 0,
            timeout_ms: 1,
            confirmable: true,
        };
        let mut endpoint = Endpoint::new(&config).unwrap();
        let original = endpoint.socket.local_addr().unwrap();
        endpoint.next_mid = 65536 - 4096;
        endpoint.reserve(&config).unwrap();
        assert_eq!(endpoint.socket.local_addr().unwrap(), original);
        endpoint.next_mid += 1;
        endpoint.reserve(&config).unwrap();
        assert_ne!(endpoint.socket.local_addr().unwrap(), original);
        assert_eq!(endpoint.retired[0].local_addr().unwrap(), original);
        assert_eq!(endpoint.next_mid, 0);
    }

    #[test]
    fn reservation_accounts_for_unusable_mid_tails_and_worker_rounding() {
        let mut config = Config {
            endpoint: "127.0.0.1:9".into(),
            bytes: 640_000,
            concurrency: 1,
            operations: 1500,
            warmup: 0,
            timeout_ms: 1,
            confirmable: true,
        };
        assert_eq!(reserved_endpoint_count(&config), 1500);
        config.bytes = 65536;
        config.concurrency = 4;
        config.operations = 64;
        config.warmup = 1;
        assert_eq!(reserved_endpoint_count(&config), 8);
        config.operations = 1;
        config.warmup = 0;
        assert_eq!(reserved_endpoint_count(&config), 4);
    }
}
