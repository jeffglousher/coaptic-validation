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
fn verify(reply: &coaptic::Response<'_>, expected: &[u8]) -> Result<()> {
    if reply.code() != Code::CONTENT || reply.payload_truncated() || reply.payload() != expected {
        return Err("timing representation/identity");
    }
    Ok(())
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

pub(super) fn campaign(
    c: &Credentials,
    state_path: &Path,
    peer: SocketAddr,
    run_id: &str,
    report_path: &Path,
) -> Result<()> {
    let mut report =
        File::create_new(report_path).map_err(|_| "timing report exists/unavailable")?;
    let result = measure(c, state_path, peer, run_id, &mut report);
    if result.is_err() {
        let _ = writeln!(
            report,
            "{{\"passed\":false,\"case\":\"timing_campaign\",\"reason\":\"refused; partial observations retained\"}}"
        );
        let _ = report.sync_all();
    }
    result
}
fn measure(
    c: &Credentials,
    state_path: &Path,
    peer: SocketAddr,
    run_id: &str,
    report: &mut File,
) -> Result<()> {
    let clock = Instant::now();
    let ledger = RefCell::new(Ledger {
        events: Vec::with_capacity(EVENTS),
        ..Ledger::default()
    });
    let store = TimedStore {
        store: FileStore::open(state_path, false)?,
        clock: &clock,
        ledger: &ledger,
    };
    let (mut state, context) = State::recover(store, c).map_err(|_| "timing state recovery")?;
    let recovery_ns = clock.elapsed().as_nanos() as u64;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|_| "timing socket")?;
    socket
        .set_nonblocking(true)
        .map_err(|_| "timing socket mode")?;
    let io = TimedIo {
        io: UdpSocketIo::new(socket, [0; 1153]).map_err(|_| "timing scratch")?,
        clock: &clock,
        ledger: &ledger,
    };
    let mut app = App::profile::<profiles::Constrained>()
        .block_wise::<true>()
        .full_responses()
        .randomness(|b| getrandom::fill(b).is_ok())
        .oscore(context)
        .bind(io)
        .map_err(|_| "timing bind")?;
    let mut output = [0; 4096];
    writeln!(report, "{{\"case\":\"preparation\",\"security_recovery_ns\":{recovery_ns},\"app_inline_bytes\":{},\"trace_heap_bytes\":{},\"output_bytes\":4096,\"method\":\"fixed Coaptic storage; host trace heap bounded and reserved before operation timing; recovery/reservation includes durable host state\"}}", std::mem::size_of_val(&app), ledger.borrow().events.capacity() * std::mem::size_of::<Event>()).map_err(|_| "timing report")?;
    for iteration in 0..8 {
        for (path, expected) in [
            ("identity", run_id.as_bytes()),
            ("test", &b"coaptic"[..]),
            ("large", &[0x5a; 2000][..]),
        ] {
            let remaining = app
                .oscore()
                .ok_or("timing context")?
                .sender_reservation_end()
                .ok_or("timing sender bound")?
                .saturating_sub(app.oscore().unwrap().sender_seq());
            // Explicit reservation cost is outside this read operation and remains
            // separately reported. Never omit the durable reservation itself.
            if remaining < 8 {
                let start = clock.elapsed().as_nanos() as u64;
                state
                    .refill(app.oscore_mut().ok_or("timing context")?)
                    .map_err(|_| "timing refill")?;
                writeln!(
                    report,
                    "{{\"case\":\"sender_refill\",\"duration_ns\":{}}}",
                    clock.elapsed().as_nanos() as u64 - start
                )
                .map_err(|_| "timing report")?;
            }
            ledger.borrow_mut().reset();
            let start = clock.elapsed().as_nanos() as u64;
            let call = app
                .get(path)
                .to(peer.into())
                .send(clock.elapsed().as_millis() as u64)
                .map_err(|_| "timing request")?;
            let prepared = clock.elapsed().as_nanos() as u64 - start;
            let mut poll_ns = 0;
            let mut checkpoint_ns = 0;
            let mut take_ns = 0;
            let mut sleep_ns = 0;
            let mut polls = 0;
            loop {
                if clock.elapsed().as_nanos() as u64 - start >= 5_000_000_000 {
                    return Err("timing deadline");
                }
                let phase = Instant::now();
                app.poll(clock.elapsed().as_millis() as u64)
                    .map_err(|_| "timing poll")?;
                poll_ns += phase.elapsed().as_nanos() as u64;
                polls += 1;
                let phase = Instant::now();
                state
                    .checkpoint(app.oscore().ok_or("timing context")?.replay_checkpoint())
                    .map_err(|_| "timing checkpoint")?;
                checkpoint_ns += phase.elapsed().as_nanos() as u64;
                let phase = Instant::now();
                let reply = app
                    .take_response_into(call, &mut output)
                    .map_err(|_| "timing output")?;
                take_ns += phase.elapsed().as_nanos() as u64;
                if let Some(reply) = reply {
                    let phase = Instant::now();
                    let reply = reply.map_err(|_| "timing response")?;
                    verify(&reply, expected)?;
                    let verify_ns = phase.elapsed().as_nanos() as u64;
                    let elapsed = clock.elapsed().as_nanos() as u64 - start;
                    let l = ledger.borrow();
                    if l.overflow {
                        return Err("timing trace bound");
                    }
                    writeln!(report, "{{\"passed\":true,\"case\":\"complete_operation\",\"iteration\":{iteration},\"path\":\"{path}\",\"bytes\":{},\"start_ns\":{start},\"elapsed_ns\":{elapsed},\"prepare_ns\":{prepared},\"poll_ns\":{poll_ns},\"checkpoint_ns\":{checkpoint_ns},\"take_ns\":{take_ns},\"verify_ns\":{verify_ns},\"sleep_ns\":{sleep_ns},\"polls\":{polls},\"recv_ns\":{},\"send_ns\":{},\"state_read_ns\":{},\"state_commit_ns\":{},\"recv_calls\":{},\"state_reads\":{},\"state_commits\":{},\"events\":{:?}}}", expected.len(), l.recv_ns, l.send_ns, l.read_ns, l.commit_ns, l.recv_calls, l.reads, l.commits, l.events).map_err(|_| "timing report")?;
                    break;
                }
                let phase = Instant::now();
                std::thread::sleep(Duration::from_millis(1));
                sleep_ns += phase.elapsed().as_nanos() as u64;
            }
        }
    }
    writeln!(report, "{{\"passed\":true,\"case\":\"timing_campaign\",\"completed\":24,\"run_id\":\"{run_id}\",\"event_bound\":{EVENTS},\"method\":\"instrumented protected fixed-storage host; durable client checkpoint and 1ms requested sleep included; poll includes transport/crypto; state read/commit nested in checkpoint; independent clocks; no one-way network claim\"}}").map_err(|_| "timing report")?;
    report.sync_all().map_err(|_| "timing report sync")?;
    Ok(())
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
    #[test]
    fn complete_representation_refuses_wrong_code_corruption_and_short_body_then_recovers() {
        let valid = coaptic::Response::content(b"coaptic");
        assert!(verify(&valid, b"coaptic").is_ok());
        assert!(verify(&valid.payload_borrowed(b"coaptix"), b"coaptic").is_err());
        assert!(verify(&valid.payload_borrowed(b"coap"), b"coaptic").is_err());
        assert!(verify(&coaptic::Response::not_found(), b"coaptic").is_err());
        assert!(verify(&valid, b"coaptic").is_ok());
    }
}
