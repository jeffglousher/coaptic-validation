//! Same constrained fixed-storage service with explicit security and address scope. Read/commit
//! and UDP intervals are nested in ready-poll intervals, as on the device.
//! This diagnostic spin-polls; it is not a recommended host scheduling policy.
use super::*;
use coaptic_esphome_probe::security_state::{Error, RECORD_BYTES, Store};
use std::cell::{Cell, RefCell};
use std::net::Ipv4Addr;

pub(super) fn validate_placeholders(credentials: &str, state: &str) -> Result<()> {
    if credentials == "-" && state == "-" {
        Ok(())
    } else {
        Err("unprotected timing requires - credentials and - state")
    }
}

fn validate_scope(address: SocketAddr, remote: Option<Ipv4Addr>) -> Result<()> {
    match (address, remote) {
        (SocketAddr::V4(local), None) if local.ip().is_loopback() && local.port() != 0 => Ok(()),
        (SocketAddr::V4(local), Some(remote))
            if local.ip().is_private()
                && remote.is_private()
                && local.ip() != &remote
                && local.port() != 0 =>
        {
            Ok(())
        }
        _ => Err("timing server requires loopback or explicit private local/remote scope"),
    }
}

fn allowed(peer: Endpoint, remote: Option<Ipv4Addr>) -> bool {
    remote.is_none_or(|remote| peer.as_ipv4().is_some_and(|(ip, _)| ip == remote.octets()))
}

const LIMIT: usize = 512;
type Event = [u64; 5];
struct Trace {
    rows: Vec<Event>,
    overflow: bool,
    rx: u64,
}
impl Trace {
    fn push(&mut self, row: Event) {
        if self.rows.len() == LIMIT {
            self.overflow = true;
        } else {
            self.rows.push(row);
        }
    }
}
struct Io<'a> {
    socket: UdpSocketIo<[u8; 1153]>,
    clock: &'a Instant,
    trace: &'a RefCell<Trace>,
    remote: Option<Ipv4Addr>,
    refused_sources: &'a Cell<u64>,
}
impl coaptic::storage::DatagramTransport for Io<'_> {
    type Error = std::io::Error;
}
impl DatagramIo for Io<'_> {
    fn recv(&mut self, bytes: &mut [u8]) -> std::io::Result<Option<(usize, Endpoint)>> {
        let start = self.clock.elapsed().as_nanos() as u64;
        let result = self.socket.recv(bytes);
        if let Ok(Some((n, peer))) = result {
            if !allowed(peer, self.remote) {
                self.refused_sources.set(self.refused_sources.get() + 1);
                return Ok(None);
            }
            let duration = self.clock.elapsed().as_nanos() as u64 - start;
            let mid = bytes
                .get(2..4)
                .map_or(65536, |b| u64::from(u16::from_be_bytes([b[0], b[1]])));
            let mut trace = self.trace.borrow_mut();
            trace.rx += 1;
            trace.push([1, start, duration, n as u64, mid]);
        }
        result
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> std::io::Result<usize> {
        if !allowed(peer, self.remote) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "timing peer scope",
            ));
        }
        let start = self.clock.elapsed().as_nanos() as u64;
        let result = self.socket.send(peer, bytes);
        let duration = self.clock.elapsed().as_nanos() as u64 - start;
        let mid = bytes
            .get(2..4)
            .map_or(65536, |b| u64::from(u16::from_be_bytes([b[0], b[1]])));
        self.trace
            .borrow_mut()
            .push([2, start, duration, bytes.len() as u64, mid]);
        result
    }
}
struct Durable<'a> {
    store: FileStore,
    clock: &'a Instant,
    trace: &'a RefCell<Trace>,
}
impl Store for Durable<'_> {
    fn read(&mut self) -> std::result::Result<Option<[u8; RECORD_BYTES]>, Error> {
        let start = self.clock.elapsed().as_nanos() as u64;
        let result = self.store.read();
        self.trace.borrow_mut().push([
            3,
            start,
            self.clock.elapsed().as_nanos() as u64 - start,
            RECORD_BYTES as u64,
            65536,
        ]);
        result
    }
    fn commit(&mut self, bytes: &[u8; RECORD_BYTES]) -> std::result::Result<(), Error> {
        let start = self.clock.elapsed().as_nanos() as u64;
        let result = self.store.commit(bytes);
        self.trace.borrow_mut().push([
            4,
            start,
            self.clock.elapsed().as_nanos() as u64 - start,
            RECORD_BYTES as u64,
            65536,
        ]);
        result
    }
}
pub(super) fn run(
    c: &Credentials,
    state: &Path,
    address: SocketAddr,
    run_id: &str,
    report: &Path,
    remote: Option<Ipv4Addr>,
) -> Result<()> {
    run_selected(Some((c, state)), address, run_id, report, remote)
}

pub(super) fn run_unprotected(
    address: SocketAddr,
    run_id: &str,
    report: &Path,
    remote: Option<Ipv4Addr>,
) -> Result<()> {
    run_selected(None, address, run_id, report, remote)
}

fn run_selected(
    protection: Option<(&Credentials, &Path)>,
    address: SocketAddr,
    run_id: &str,
    report: &Path,
    remote: Option<Ipv4Addr>,
) -> Result<()> {
    validate_scope(address, remote)?;
    if run_id.len() != 32 || !run_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("timing server identity");
    }
    let report = File::create_new(report).map_err(|_| "timing server report exists/unavailable")?;
    let socket = UdpSocket::bind(address).map_err(|_| "timing server socket")?;
    socket
        .set_nonblocking(true)
        .map_err(|_| "timing server socket mode")?;
    run_bound(protection, socket, run_id, report, remote)
}

// The single bound-socket path owns the trace and stop policy in both modes.
// Tests can bind their socket before starting a client, without a readiness
// probe or exposing any additional listener in the executable.
fn run_bound(
    protection: Option<(&Credentials, &Path)>,
    socket: UdpSocket,
    run_id: &str,
    mut report: File,
    remote: Option<Ipv4Addr>,
) -> Result<()> {
    let started = Instant::now();
    let trace = RefCell::new(Trace {
        rows: Vec::with_capacity(LIMIT),
        overflow: false,
        rx: 0,
    });
    let refused_sources = Cell::new(0);
    let io = Io {
        socket: UdpSocketIo::new(socket, [0; 1153]).map_err(|_| "timing server scratch")?,
        clock: &started,
        trace: &trace,
        remote,
        refused_sources: &refused_sources,
    };
    let id: &[u8; 32] = run_id
        .as_bytes()
        .try_into()
        .map_err(|_| "timing server identity")?;
    let previous_rx = Cell::new(0);
    let poll_start = Cell::new(0u64);
    let last_rx = Cell::new(0u64);
    let clock = || {
        let now = started.elapsed().as_nanos() as u64;
        let received = trace.borrow().rx;
        if received != previous_rx.get() {
            trace
                .borrow_mut()
                .push([6, poll_start.get(), now - poll_start.get(), 0, 65536]);
            previous_rx.set(received);
            last_rx.set(now);
        }
        poll_start.set(now);
        if now >= 30_000_000_000 || (received >= 32 && now - last_rx.get() >= 2_000_000_000) {
            None
        } else {
            Some(now / 1_000_000)
        }
    };
    let random = |bytes: &mut [u8]| getrandom::fill(bytes).is_ok();
    let result = if let Some((credentials, state)) = protection {
        let store = Durable {
            store: FileStore::open(state, false)?,
            clock: &started,
            trace: &trace,
        };
        coaptic_esphome_probe::network::run_protected(io, random, clock, id, credentials, store)
    } else {
        coaptic_esphome_probe::network::run(io, random, clock, id)
    };
    let trace = trace.borrow();
    let passed = result.is_ok() && !trace.overflow && trace.rx >= 32;
    let (security, storage) = if protection.is_some() {
        ("durable-oscore", "authenticated durable host file")
    } else {
        ("unprotected", "no credential or security-state file")
    };
    writeln!(report, "{{\"passed\":{passed},\"case\":\"timing_host_server\",\"run_id\":\"{run_id}\",\"security\":\"{security}\",\"refused_sources\":{},\"event_bound\":{LIMIT},\"trace_heap_bytes\":{},\"received\":{},\"overflow\":{},\"events\":{:?},\"method\":\"same constrained service; fixed core storage; {storage}; spin-poll diagnostic; nested intervals; no throughput or CPU efficiency claim\"}}", refused_sources.get(), trace.rows.capacity() * std::mem::size_of::<Event>(), trace.rx, trace.overflow, trace.rows).map_err(|_| "timing server report")?;
    report.sync_all().map_err(|_| "timing server report sync")?;
    if passed {
        Ok(())
    } else {
        Err("timing server refused/incomplete")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unprotected_selection_requires_both_literal_placeholders() {
        assert_eq!(validate_placeholders("-", "-"), Ok(()));
        for (credentials, state) in [
            ("credentials", "-"),
            ("-", "state"),
            ("", ""),
            ("credentials", "state"),
        ] {
            assert!(validate_placeholders(credentials, state).is_err());
        }
    }

    #[test]
    fn unprotected_service_completes_the_matched_udp_campaign_without_state_events() {
        use coaptic_esphome_probe::read_campaign::{Observation, run_unprotected};

        const ID: &str = "0123456789abcdef0123456789abcdef";
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let peer = socket.local_addr().unwrap();
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "coaptic-unprotected-server-{}-{:016x}.json",
            std::process::id(),
            u64::from_ne_bytes(nonce)
        ));
        let report = File::create_new(&path).unwrap();
        let server = std::thread::spawn(move || run_bound(None, socket, ID, report, None));
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_nonblocking(true).unwrap();
        let io = UdpSocketIo::new(client, [0; 1153]).unwrap();
        let started = Instant::now();
        let mut prepared = false;
        let mut completed = 0;
        let result = run_unprotected(
            io,
            |bytes| getrandom::fill(bytes).is_ok(),
            || Some(started.elapsed().as_nanos() as u64),
            || std::thread::sleep(Duration::from_millis(1)),
            peer.into(),
            ID.as_bytes().try_into().unwrap(),
            |observation| match observation {
                Observation::Preparation { recovery_ns: 0, .. } if !prepared => {
                    prepared = true;
                    Ok(())
                }
                Observation::Operation(operation) if prepared => {
                    let (path, bytes) =
                        [("identity", 32), ("test", 7), ("large", 2000)][completed % 3];
                    if operation.iteration != (completed / 3) as u32
                        || operation.path != path
                        || operation.bytes != bytes
                    {
                        return Err("unexpected matched operation");
                    }
                    completed += 1;
                    Ok(())
                }
                _ => Err("unprotected preparation/reservation"),
            },
        );
        let server_result = server.join().unwrap();
        let report = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(server_result, Ok(()));
        assert!(prepared);
        assert_eq!(completed, 24);
        assert!(report.contains("\"security\":\"unprotected\""));
        assert!(report.contains("\"passed\":true"));
        assert!(report.contains("\"received\":32,"));
        assert!(!report.contains("[3,"));
        assert!(!report.contains("[4,"));
    }

    #[test]
    fn excluded_udp_source_never_reaches_protocol_or_receives_a_reply() {
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let trace = RefCell::new(Trace {
            rows: Vec::with_capacity(LIMIT),
            overflow: false,
            rx: 0,
        });
        let refused = Cell::new(0);
        let clock = Instant::now();
        let mut io = Io {
            socket: UdpSocketIo::new(listener, [0; 1153]).unwrap(),
            clock: &clock,
            trace: &trace,
            remote: Some(Ipv4Addr::LOCALHOST),
            refused_sources: &refused,
        };
        let foreign = UdpSocket::bind("127.0.0.2:0").unwrap();
        foreign.send_to(&[0x40, 1, 0x12, 0x34], address).unwrap();
        let mut bytes = [0; 1152];
        while refused.get() == 0 {
            assert!(clock.elapsed() < Duration::from_secs(2));
            assert!(io.recv(&mut bytes).unwrap().is_none());
            std::thread::yield_now();
        }
        assert_eq!(trace.borrow().rx, 0);
        assert!(trace.borrow().rows.is_empty());
        assert_eq!(
            io.send(foreign.local_addr().unwrap().into(), b"forbidden")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let valid = UdpSocket::bind("127.0.0.1:0").unwrap();
        valid.send_to(&[0x40, 1, 0x56, 0x78], address).unwrap();
        loop {
            assert!(clock.elapsed() < Duration::from_secs(2));
            if let Some((size, peer)) = io.recv(&mut bytes).unwrap() {
                assert_eq!(size, 4);
                assert_eq!(peer, valid.local_addr().unwrap().into());
                assert_eq!(trace.borrow().rx, 1);
                break;
            }
            std::thread::yield_now();
        }
    }
    #[test]
    fn network_scope_refuses_wildcards_public_addresses_and_other_peers() {
        let remote = Ipv4Addr::new(192, 168, 1, 144);
        assert!(validate_scope("127.0.0.1:5683".parse().unwrap(), None).is_ok());
        assert!(validate_scope("192.168.1.134:5683".parse().unwrap(), Some(remote)).is_ok());
        for address in [
            "0.0.0.0:5683",
            "192.168.1.134:0",
            "8.8.8.8:5683",
            "[::1]:5683",
        ] {
            assert!(validate_scope(address.parse().unwrap(), Some(remote)).is_err());
        }
        assert!(validate_scope("192.168.1.134:5683".parse().unwrap(), None).is_err());
        assert!(validate_scope("127.0.0.1:0".parse().unwrap(), None).is_err());
        assert!(validate_scope("192.168.1.144:5683".parse().unwrap(), Some(remote)).is_err());
        assert!(
            validate_scope(
                "192.168.1.134:5683".parse().unwrap(),
                Some(Ipv4Addr::new(8, 8, 8, 8))
            )
            .is_err()
        );
        assert!(allowed(Endpoint::v4(remote.octets(), 12345), Some(remote)));
        assert!(!allowed(
            Endpoint::v4([192, 168, 1, 145], 12345),
            Some(remote)
        ));
    }
    #[test]
    fn server_trace_limit_refuses_overflow_without_extending_storage() {
        let mut trace = Trace {
            rows: Vec::with_capacity(LIMIT),
            overflow: false,
            rx: 0,
        };
        for _ in 0..LIMIT {
            trace.push([1; 5]);
        }
        assert!(!trace.overflow);
        trace.push([1; 5]);
        assert!(trace.overflow);
        assert_eq!(trace.rows.len(), LIMIT);
        assert_eq!(trace.rows.capacity(), LIMIT);
    }
}
