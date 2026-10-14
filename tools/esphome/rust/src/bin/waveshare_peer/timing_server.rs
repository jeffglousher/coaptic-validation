//! Same constrained protected fixed-storage service on loopback. Read/commit
//! and UDP intervals are nested in ready-poll intervals, as on the device.
//! This diagnostic spin-polls; it is not a recommended host scheduling policy.
use super::*;
use coaptic_esphome_probe::security_state::{Error, RECORD_BYTES, Store};
use std::cell::{Cell, RefCell};

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
}
impl DatagramIo for Io<'_> {
    type Error = std::io::Error;
    fn recv(&mut self, bytes: &mut [u8]) -> std::io::Result<Option<(usize, Endpoint)>> {
        let start = self.clock.elapsed().as_nanos() as u64;
        let result = self.socket.recv(bytes);
        if let Ok(Some((n, _))) = result {
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
) -> Result<()> {
    if !address.ip().is_loopback() {
        return Err("timing server is loopback only");
    }
    let mut report =
        File::create_new(report).map_err(|_| "timing server report exists/unavailable")?;
    let started = Instant::now();
    let trace = RefCell::new(Trace {
        rows: Vec::with_capacity(LIMIT),
        overflow: false,
        rx: 0,
    });
    let socket = UdpSocket::bind(address).map_err(|_| "timing server socket")?;
    socket
        .set_nonblocking(true)
        .map_err(|_| "timing server socket mode")?;
    let io = Io {
        socket: UdpSocketIo::new(socket, [0; 1153]).map_err(|_| "timing server scratch")?,
        clock: &started,
        trace: &trace,
    };
    let store = Durable {
        store: FileStore::open(state, false)?,
        clock: &started,
        trace: &trace,
    };
    let id: &[u8; 32] = run_id
        .as_bytes()
        .try_into()
        .map_err(|_| "timing server identity")?;
    let previous_rx = Cell::new(0);
    let poll_start = Cell::new(0u64);
    let last_rx = Cell::new(0u64);
    let result = coaptic_esphome_probe::network::run_protected(
        io,
        |b| getrandom::fill(b).is_ok(),
        || {
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
        },
        id,
        c,
        store,
    );
    let trace = trace.borrow();
    let passed = result.is_ok() && !trace.overflow && trace.rx >= 32;
    writeln!(report, "{{\"passed\":{passed},\"case\":\"timing_loopback_server\",\"event_bound\":{LIMIT},\"trace_heap_bytes\":{},\"received\":{},\"overflow\":{},\"events\":{:?},\"method\":\"same protected constrained service; fixed core storage; authenticated durable host file; spin-poll diagnostic; nested intervals; no throughput or CPU efficiency claim\"}}", trace.rows.capacity() * std::mem::size_of::<Event>(), trace.rx, trace.overflow, trace.rows).map_err(|_| "timing server report")?;
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
