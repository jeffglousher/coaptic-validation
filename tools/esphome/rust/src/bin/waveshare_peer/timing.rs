//! Finite protected LAN diagnostic. Trace clocks perturb execution; this is not
//! a throughput benchmark. Credentials and durable sequence state are reused
//! exclusively, never copied/reset. No packet contents are recorded.
use super::*;
use coaptic_esphome_probe::security_state::{Error, RECORD_BYTES, Store};
use std::cell::RefCell;

const EVENTS: usize = 128;
// [kind, relative start ns, duration ns, wire bytes, MID]. Kinds: receive=1,
// send=2, state read=3, state commit=4. Receive idle calls are aggregated only.
type Event = [u64; 5];
#[derive(Default)]
struct Ledger {
    events: Vec<Event>,
    overflow: bool,
    recv_ns: u64,
    send_ns: u64,
    read_ns: u64,
    commit_ns: u64,
    recv_calls: u64,
    reads: u64,
    commits: u64,
}
impl Ledger {
    fn record(&mut self, event: Event) {
        if self.events.len() == EVENTS {
            self.overflow = true;
        } else {
            self.events.push(event);
        }
    }
    fn reset(&mut self) {
        self.events.clear();
        *self = Self {
            events: std::mem::take(&mut self.events),
            ..Self::default()
        };
    }
}
struct TimedIo<'a> {
    io: UdpSocketIo<[u8; 1153]>,
    clock: &'a Instant,
    ledger: &'a RefCell<Ledger>,
}
impl DatagramIo for TimedIo<'_> {
    type Error = std::io::Error;
    fn recv(&mut self, bytes: &mut [u8]) -> std::io::Result<Option<(usize, Endpoint)>> {
        let start = self.clock.elapsed().as_nanos() as u64;
        let result = self.io.recv(bytes);
        let elapsed = self.clock.elapsed().as_nanos() as u64 - start;
        let mut ledger = self.ledger.borrow_mut();
        ledger.recv_ns += elapsed;
        ledger.recv_calls += 1;
        if let Ok(Some((n, _))) = result {
            ledger.record([1, start, elapsed, n as u64, mid(&bytes[..n])]);
        }
        result
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> std::io::Result<usize> {
        let start = self.clock.elapsed().as_nanos() as u64;
        let result = self.io.send(peer, bytes);
        let elapsed = self.clock.elapsed().as_nanos() as u64 - start;
        let mut ledger = self.ledger.borrow_mut();
        ledger.send_ns += elapsed;
        ledger.record([2, start, elapsed, bytes.len() as u64, mid(bytes)]);
        result
    }
}
fn mid(bytes: &[u8]) -> u64 {
    bytes
        .get(2..4)
        .map_or(65536, |b| u64::from(u16::from_be_bytes([b[0], b[1]])))
}

/// Execute the no_std/no-allocation initiator algorithm on the host, with the
/// same nested transport/state trace used by the original host diagnostic.
pub(super) fn campaign(
    c: &Credentials,
    state_path: &Path,
    peer: SocketAddr,
    run_id: &str,
    report_path: &Path,
) -> Result<()> {
    use coaptic_esphome_probe::read_campaign::{self, Observation};
    let mut report =
        File::create_new(report_path).map_err(|_| "timing report exists/unavailable")?;
    let clock = Instant::now();
    let ledger = RefCell::new(Ledger {
        events: Vec::with_capacity(EVENTS),
        ..Ledger::default()
    });
    let mut completed = 0;
    let result = (|| {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|_| "timing socket")?;
        socket
            .set_nonblocking(true)
            .map_err(|_| "timing socket mode")?;
        let io = TimedIo {
            io: UdpSocketIo::new(socket, [0; 1153]).map_err(|_| "timing scratch")?,
            clock: &clock,
            ledger: &ledger,
        };
        let store = TimedStore {
            store: FileStore::open(state_path, false)?,
            clock: &clock,
            ledger: &ledger,
        };
        read_campaign::run(
            io,
            |b| getrandom::fill(b).is_ok(),
            || u64::try_from(clock.elapsed().as_nanos()).ok(),
            || std::thread::sleep(Duration::from_millis(1)),
            c,
            store,
            peer.into(),
            run_id
                .as_bytes()
                .try_into()
                .map_err(|_| "timing identity")?,
            |observation| {
                let mut l = ledger.borrow_mut();
                if l.overflow {
                    return Err("timing trace bound");
                }
                match observation {
                    Observation::Preparation { recovery_ns, app_bytes } =>
                        writeln!(report, "{{\"case\":\"preparation\",\"security_recovery_ns\":{recovery_ns},\"app_inline_bytes\":{app_bytes},\"output_bytes\":4096,\"trace_heap_bytes\":{}}}", l.events.capacity() * std::mem::size_of::<Event>()),
                    Observation::Reservation { elapsed_ns } =>
                        writeln!(report, "{{\"case\":\"sender_refill\",\"duration_ns\":{elapsed_ns}}}"),
                    Observation::Operation(op) => {
                        completed += 1;
                        writeln!(report, "{{\"passed\":true,\"case\":\"complete_operation\",\"iteration\":{},\"path\":\"{}\",\"bytes\":{},\"start_ns\":{},\"elapsed_ns\":{},\"prepare_ns\":{},\"poll_ns\":{},\"checkpoint_ns\":{},\"take_ns\":{},\"verify_ns\":{},\"sleep_ns\":{},\"polls\":{},\"recv_ns\":{},\"send_ns\":{},\"state_read_ns\":{},\"state_commit_ns\":{},\"recv_calls\":{},\"state_reads\":{},\"state_commits\":{},\"events\":{:?}}}",
                            op.iteration, op.path, op.bytes, op.start_ns, op.elapsed_ns, op.prepare_ns, op.poll_ns, op.checkpoint_ns, op.take_ns, op.verify_ns, op.wait_ns, op.polls, l.recv_ns, l.send_ns, l.read_ns, l.commit_ns, l.recv_calls, l.reads, l.commits, l.events)
                    },
                }.map_err(|_| "timing report")?;
                l.reset();
                Ok(())
            },
        )
    })();
    let passed = result.is_ok();
    writeln!(report, "{{\"passed\":{passed},\"case\":\"timing_campaign\",\"completed\":{},\"run_id\":\"{run_id}\",\"event_bound\":{EVENTS},\"method\":\"portable fixed-storage protected initiator; bounded host trace; authenticated durable client state; 1ms requested wait included; partial failures retained\"}}", completed).map_err(|_| "timing report")?;
    report.sync_all().map_err(|_| "timing report sync")?;
    result
}
struct TimedStore<'a> {
    store: FileStore,
    clock: &'a Instant,
    ledger: &'a RefCell<Ledger>,
}
impl Store for TimedStore<'_> {
    fn read(&mut self) -> std::result::Result<Option<[u8; RECORD_BYTES]>, Error> {
        let start = self.clock.elapsed().as_nanos() as u64;
        let result = self.store.read();
        let elapsed = self.clock.elapsed().as_nanos() as u64 - start;
        let mut ledger = self.ledger.borrow_mut();
        ledger.read_ns += elapsed;
        ledger.reads += 1;
        ledger.record([3, start, elapsed, RECORD_BYTES as u64, 65536]);
        result
    }
    fn commit(&mut self, bytes: &[u8; RECORD_BYTES]) -> std::result::Result<(), Error> {
        let start = self.clock.elapsed().as_nanos() as u64;
        let result = self.store.commit(bytes);
        let elapsed = self.clock.elapsed().as_nanos() as u64 - start;
        let mut ledger = self.ledger.borrow_mut();
        ledger.commit_ns += elapsed;
        ledger.commits += 1;
        ledger.record([4, start, elapsed, RECORD_BYTES as u64, 65536]);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trace_bounds_refuse_overflow_and_reset_preserves_capacity() {
        let mut ledger = Ledger {
            events: Vec::with_capacity(EVENTS),
            ..Ledger::default()
        };
        for _ in 0..EVENTS {
            ledger.record([1, 2, 3, 4, 5]);
        }
        assert!(!ledger.overflow);
        ledger.record([1, 2, 3, 4, 5]);
        assert!(ledger.overflow);
        assert_eq!(ledger.events.len(), EVENTS);
        ledger.reset();
        assert!(!ledger.overflow);
        assert_eq!(ledger.events.capacity(), EVENTS);
        ledger.record([1, 2, 3, 4, 5]);
        assert_eq!(ledger.events.len(), 1);
    }
    #[test]
    fn packet_metadata_is_bounded_without_recording_body() {
        assert_eq!(mid(&[]), 65536);
        assert_eq!(mid(&[0x44, 1, 0xab, 0xcd, 0xff]), 0xabcd);
    }
}
