//! Finite explicitly selected LAN diagnostic. Trace clocks perturb execution; this is not
//! a throughput benchmark. Credentials and durable sequence state are reused
//! exclusively, never copied/reset. No packet contents are recorded.
use super::*;
#[cfg(feature = "async-network")]
use coaptic::storage::AsyncDatagramIo;
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
#[cfg(not(feature = "async-network"))]
struct TimedIo<'a> {
    io: UdpSocketIo<[u8; 1153]>,
    clock: &'a Instant,
    ledger: &'a RefCell<Ledger>,
}
#[cfg(not(feature = "async-network"))]
impl coaptic::storage::DatagramTransport for TimedIo<'_> {
    type Error = std::io::Error;
}
#[cfg(not(feature = "async-network"))]
impl DatagramIo for TimedIo<'_> {
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

#[cfg(feature = "async-network")]
struct AsyncIo<'a> {
    io: coaptic_async_host::Udp<[u8; 1153]>,
    clock: &'a Instant,
    ledger: &'a RefCell<Ledger>,
}
#[cfg(feature = "async-network")]
impl coaptic::storage::DatagramTransport for AsyncIo<'_> {
    type Error = std::io::Error;
}
#[cfg(feature = "async-network")]
impl AsyncDatagramIo for AsyncIo<'_> {
    async fn recv(&mut self, bytes: &mut [u8]) -> std::io::Result<(usize, Endpoint)> {
        let start = self.clock.elapsed().as_nanos() as u64;
        let result = self.io.recv(bytes).await;
        let elapsed = self.clock.elapsed().as_nanos() as u64 - start;
        let mut ledger = self.ledger.borrow_mut();
        ledger.recv_ns += elapsed;
        ledger.recv_calls += 1;
        if let Ok((n, _)) = result {
            ledger.record([1, start, elapsed, n as u64, mid(&bytes[..n])]);
        }
        result
    }
    async fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> std::io::Result<usize> {
        let start = self.clock.elapsed().as_nanos() as u64;
        let result = self.io.send(peer, bytes).await;
        let elapsed = self.clock.elapsed().as_nanos() as u64 - start;
        let mut ledger = self.ledger.borrow_mut();
        ledger.send_ns += elapsed;
        ledger.record([2, start, elapsed, bytes.len() as u64, mid(bytes)]);
        result
    }
}

// Use the trace/campaign epoch for both absolute protocol and local deadlines.
// A separately initialized reactor clock would shift those deadlines.
#[cfg(feature = "async-network")]
struct Timer<'a>(&'a Instant);
#[cfg(feature = "async-network")]
impl coaptic::platform::AsyncTimer for Timer<'_> {
    async fn wait_until(&mut self, deadline_ms: u64) {
        if let Some(deadline) = self.0.checked_add(Duration::from_millis(deadline_ms)) {
            async_io::Timer::at(deadline).await;
        } else {
            core::future::pending::<()>().await;
        }
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
    campaign_selected(Some((c, state_path)), peer, run_id, report_path)
}

pub(super) fn campaign_unprotected(
    peer: SocketAddr,
    run_id: &str,
    report_path: &Path,
) -> Result<()> {
    campaign_selected(None, peer, run_id, report_path)
}

fn campaign_selected(
    protection: Option<(&Credentials, &Path)>,
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
        #[cfg(not(feature = "async-network"))]
        let io = TimedIo {
            io: UdpSocketIo::new(socket, [0; 1153]).map_err(|_| "timing scratch")?,
            clock: &clock,
            ledger: &ledger,
        };
        #[cfg(feature = "async-network")]
        let io = AsyncIo {
            io: coaptic_async_host::Udp::new(socket, [0; 1153])
                .map_err(|_| "timing async scratch/reactor")?,
            clock: &clock,
            ledger: &ledger,
        };
        let observe = |observation| {
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
        };
        let random = |b: &mut [u8]| getrandom::fill(b).is_ok();
        let now = || u64::try_from(clock.elapsed().as_nanos()).ok();
        #[cfg(not(feature = "async-network"))]
        let wait = || std::thread::sleep(Duration::from_millis(1));
        #[cfg(feature = "async-network")]
        let (mut protocol_timer, mut local_timer) = (Timer(&clock), Timer(&clock));
        let identity = run_id
            .as_bytes()
            .try_into()
            .map_err(|_| "timing identity")?;
        if let Some((c, state_path)) = protection {
            let store = TimedStore {
                store: FileStore::open(state_path, false)?,
                clock: &clock,
                ledger: &ledger,
            };
            #[cfg(not(feature = "async-network"))]
            {
                read_campaign::run(
                    io,
                    random,
                    now,
                    wait,
                    c,
                    store,
                    peer.into(),
                    identity,
                    observe,
                )
            }
            #[cfg(feature = "async-network")]
            {
                async_io::block_on(read_campaign::run_async(
                    io,
                    random,
                    now,
                    (&mut protocol_timer, &mut local_timer),
                    c,
                    store,
                    peer.into(),
                    identity,
                    observe,
                ))
            }
        } else {
            #[cfg(not(feature = "async-network"))]
            {
                read_campaign::run_unprotected(
                    io,
                    random,
                    now,
                    wait,
                    peer.into(),
                    identity,
                    observe,
                )
            }
            #[cfg(feature = "async-network")]
            {
                async_io::block_on(read_campaign::run_unprotected_async(
                    io,
                    random,
                    now,
                    (&mut protocol_timer, &mut local_timer),
                    peer.into(),
                    identity,
                    observe,
                ))
            }
        }
    })();
    let passed = result.is_ok();
    let io_mode = if cfg!(feature = "async-network") {
        "async"
    } else {
        "sync"
    };
    let (security, method) = if protection.is_some() {
        (
            "durable-oscore",
            if cfg!(feature = "async-network") {
                "portable fixed-storage native async protected initiator; bounded host trace; authenticated durable client state; readiness/absolute timers included; completed transport awaits traced; partial failures retained"
            } else {
                "portable fixed-storage protected initiator; bounded host trace; authenticated durable client state; 1ms requested wait included; partial failures retained"
            },
        )
    } else {
        (
            "unprotected",
            if cfg!(feature = "async-network") {
                "portable fixed-storage native async unprotected initiator; bounded host trace; no security state; readiness/absolute timers included; completed transport awaits traced; partial failures retained"
            } else {
                "portable fixed-storage unprotected initiator; bounded host trace; no security state; 1ms requested wait included; partial failures retained"
            },
        )
    };
    writeln!(report, "{{\"passed\":{passed},\"case\":\"timing_campaign\",\"completed\":{},\"run_id\":\"{run_id}\",\"event_bound\":{EVENTS},\"security\":\"{security}\",\"io_mode\":\"{io_mode}\",\"method\":\"{method}\"}}", completed).map_err(|_| "timing report")?;
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

    #[test]
    fn selected_initiator_completes_real_udp_reads_and_reports_its_mode() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        const ID: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
        fn identity(_: coaptic::Request<'_>) -> coaptic::Response<'static> {
            coaptic::Response::content(ID)
        }
        fn test(_: coaptic::Request<'_>) -> coaptic::Response<'static> {
            coaptic::Response::content(b"coaptic")
        }
        fn large(_: coaptic::Request<'_>) -> coaptic::Response<'static> {
            coaptic::Response::content(&[0x5a; 2000])
        }

        // Bind before the client starts. This independent App fixture avoids
        // sharing the service's process-wide identity owner with other tests.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let peer = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || -> Result<()> {
            let io = UdpSocketIo::new(socket, [0; 1153]).map_err(|_| "test server scratch")?;
            let mut app = App::profile::<profiles::Constrained>()
                .block_wise::<true>()
                .randomness(|bytes| getrandom::fill(bytes).is_ok())
                .allow_unprotected()
                .route("identity", coaptic::get(identity))
                .route("test", coaptic::get(test))
                .route("large", coaptic::get(large))
                .bind(io)
                .map_err(|_| "test server bind")?;
            let clock = Instant::now();
            while !server_stop.load(Ordering::Relaxed) && clock.elapsed() < Duration::from_secs(10)
            {
                app.poll(clock.elapsed().as_millis() as u64)
                    .map_err(|_| "test server poll")?;
                std::thread::yield_now();
            }
            Ok(())
        });
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let report_path = std::env::temp_dir().join(format!(
            "coaptic-timing-initiator-{}-{:016x}.json",
            std::process::id(),
            u64::from_ne_bytes(nonce),
        ));
        let result = campaign_unprotected(peer, std::str::from_utf8(ID).unwrap(), &report_path);
        stop.store(true, Ordering::Relaxed);
        let server_result = server.join().unwrap();
        let report = std::fs::read_to_string(&report_path).unwrap();
        std::fs::remove_file(&report_path).unwrap();
        assert_eq!(server_result, Ok(()));
        assert_eq!(result, Ok(()));
        let operations: Vec<_> = report
            .lines()
            .filter(|line| line.contains("\"case\":\"complete_operation\""))
            .collect();
        assert_eq!(operations.len(), 24);
        for (index, line) in operations.iter().enumerate() {
            let (path, bytes) = [("identity", 32), ("test", 7), ("large", 2000)][index % 3];
            assert!(line.contains("\"passed\":true"));
            assert!(line.contains(&format!("\"iteration\":{}", index / 3)));
            assert!(line.contains(&format!("\"path\":\"{path}\"")));
            assert!(line.contains(&format!("\"bytes\":{bytes},")));
            assert!(line.contains("\"state_reads\":0,\"state_commits\":0,"));
        }
        let mode = if cfg!(feature = "async-network") {
            "async"
        } else {
            "sync"
        };
        let summary = report.lines().last().unwrap();
        assert!(summary.contains("\"passed\":true"));
        assert!(summary.contains("\"completed\":24,"));
        assert!(summary.contains("\"security\":\"unprotected\""));
        assert!(summary.contains(&format!("\"io_mode\":\"{mode}\"")));
    }
}
