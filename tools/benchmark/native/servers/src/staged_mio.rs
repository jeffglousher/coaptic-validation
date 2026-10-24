//! Explicit synchronous Mio readiness with one staged receive in the sole scratch.
//!
//! Stage adds one datagram beyond the four Engine RX slots. Only an actual
//! WouldBlock leaves it empty; zero bytes and all other receive errors belong to
//! ordinary App polling. Guard N+1 at ingress and preserve occupied stages on
//! destination/RX refusal. Sends have immediate refusal/short-send semantics:
//! no timeout, writable wait, retry, task or per-operation allocation is added.
//!
//! Fresh App::next_poll_at eligibility precedes probing and follows every poll
//! wake. Empty probes skip App maintenance. Edge-triggered readiness is advisory:
//! successful reads/events never establish emptiness; read to actual WouldBlock.
//! There is no persistent timer cache or manual readiness clearing. Every 32
//! total turns (including empty/spurious wakes) yields the OS thread. This is a
//! synchronous control checkpoint, not async cancellation or a send deadline.
//! Production has no horizon; finite tests alone have a 64-turn cap. Pending
//! stages survive stop/error. Static fixture only: external signals, pin release
//! and policy changes require independent wakes. Inline sizes exclude runtime
//! allocations and whole-system RAM; no CPU gain is claimed.

#[cfg(test)]
use super::TransportCounts;
use super::{AllocMemory, App, DatagramIo, Endpoint, SecurityContext, bind_fixture};
use coaptic::storage::{DatagramIoError, DatagramTransport};
use std::{
    io, mem,
    net::SocketAddr,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Empty,
    Oversized,
    // Scoped to one driver poll; a failed progress send invalidates its marker.
    RejectOversized,
    RejectedOversized,
    Packet {
        len: u16,
        peer: Endpoint,
    },
    Error {
        raw: Option<i32>,
        kind: io::ErrorKind,
    },
}

struct StagedMio {
    socket: mio::net::UdpSocket,
    scratch: [u8; 2049],
    stage: Stage,
    #[cfg(test)]
    counts: TransportCounts,
}

type StagedApp = App<coaptic::profiles::Default, StagedMio, 1, true, AllocMemory>;
type AppError = coaptic::app::Error<io::Error>;

fn app_io(error: io::Error) -> AppError {
    AppError::Io(DatagramIoError::Io(error))
}

impl StagedMio {
    fn bind(address: &str) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(address)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: mio::net::UdpSocket::from_std(socket),
            scratch: [0; 2049],
            stage: Stage::Empty,
            #[cfg(test)]
            counts: TransportCounts::default(),
        })
    }

    // Native-error seam; production calls this only with an actual receive result.
    fn stage_result(&mut self, result: io::Result<(usize, SocketAddr)>) {
        assert_eq!(self.stage, Stage::Empty);
        self.stage = match result {
            Ok((len, peer)) if len <= self.scratch.len() => Stage::Packet {
                len: u16::try_from(len).expect("bounded scratch"),
                peer: Endpoint::from(peer).physical(),
            },
            Ok(_) => Stage::Oversized,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Stage::Empty,
            Err(error) => Stage::Error {
                raw: error.raw_os_error(),
                kind: error.kind(),
            },
        };
    }

    fn probe(&mut self, capacity: usize) -> io::Result<()> {
        if self.stage != Stage::Empty {
            return Ok(());
        }
        let scratch = super::guarded_scratch(capacity, &mut self.scratch)?;
        let result = self.socket.recv_from(scratch);
        // No suspension between consuming the socket and owning its result.
        self.stage_result(result);
        if matches!(self.stage, Stage::Packet { len, .. } if usize::from(len) > capacity) {
            self.stage = Stage::Oversized;
        }
        Ok(())
    }

    fn send_with(
        &mut self,
        peer: Endpoint,
        bytes: &[u8],
        send: impl FnOnce(&mio::net::UdpSocket, &[u8], SocketAddr) -> io::Result<usize>,
    ) -> io::Result<usize> {
        #[cfg(test)]
        TransportCounts::inc(&mut self.counts.socket_send_calls);
        let result = send(&self.socket, bytes, peer.into());
        if result.is_err() && self.stage == Stage::RejectedOversized {
            self.stage = Stage::Empty;
        }
        result
    }

    fn begin_poll(&mut self) -> Stage {
        let previous = self.stage;
        if previous == Stage::Oversized {
            self.stage = Stage::RejectOversized;
        }
        previous
    }

    fn finish_poll(
        &mut self,
        previous: Stage,
        result: Result<(), AppError>,
    ) -> Result<(), AppError> {
        let rejected = self.stage == Stage::RejectedOversized;
        if self.stage == Stage::RejectOversized {
            self.stage = previous;
        } else if rejected {
            self.stage = Stage::Empty;
        }
        match result {
            Err(AppError::Io(DatagramIoError::Io(error)))
                if rejected && error.kind() == io::ErrorKind::InvalidData =>
            {
                Ok(())
            }
            result => result,
        }
    }
}

impl DatagramTransport for StagedMio {
    type Error = io::Error;
}

impl DatagramIo for StagedMio {
    fn recv(&mut self, output: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
        #[cfg(test)]
        TransportCounts::inc(&mut self.counts.recv_calls);
        super::guarded_scratch(output.len(), &mut self.scratch)?;
        if matches!(self.stage, Stage::Packet { len, .. } if usize::from(len) > output.len()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Invalid destinations retain legitimate packets. Oversize probe errors
        // are consumed normally even if the destination later has more room.
        match mem::replace(&mut self.stage, Stage::Empty) {
            Stage::Oversized | Stage::RejectedOversized => Err(io::ErrorKind::InvalidData.into()),
            Stage::RejectOversized => {
                self.stage = Stage::RejectedOversized;
                Err(io::ErrorKind::InvalidData.into())
            }
            Stage::Empty => {
                #[cfg(test)]
                TransportCounts::inc(&mut self.counts.recv_empty);
                Ok(None)
            }
            Stage::Packet { len, peer } => {
                super::finish_receive(output, &self.scratch, (usize::from(len), peer.into()))
                    .map(Some)
            }
            Stage::Error { raw, kind } => {
                Err(raw.map_or_else(|| kind.into(), io::Error::from_raw_os_error))
            }
        }
    }

    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> io::Result<usize> {
        self.send_with(peer, bytes, |socket, bytes, peer| {
            socket.send_to(bytes, peer)
        })
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct Counts {
    turns: u32,
    probes: u32,
    empty: u32,
    waits: u32,
    checkpoints: u32,
}

struct Driver {
    poll: mio::Poll,
    events: mio::Events,
    epoch: Instant,
    until: Option<Instant>,
    turns_since_checkpoint: u8,
    #[cfg(test)]
    counts: Counts,
}

#[derive(Debug, PartialEq, Eq)]
enum Turn {
    Stop,
    Idle,
    Polled(u64),
}

impl Driver {
    fn register(io: &mut StagedMio, epoch: Instant, until: Option<Instant>) -> io::Result<Self> {
        let poll = mio::Poll::new()?;
        poll.registry()
            .register(&mut io.socket, mio::Token(0), mio::Interest::READABLE)?;
        Ok(Self {
            poll,
            events: mio::Events::with_capacity(8),
            epoch,
            until,
            turns_since_checkpoint: 0,
            #[cfg(test)]
            counts: Counts::default(),
        })
    }

    fn new(app: &mut StagedApp, epoch: Instant, until: Option<Instant>) -> io::Result<Self> {
        let capacity = app.engine_mut().capacities().rx_datagram_bytes;
        super::guarded_scratch(capacity, &mut app.transport_mut().scratch)?;
        Self::register(app.transport_mut(), epoch, until)
    }

    fn sample(&self, time: Instant, previous: Instant) -> Result<Option<u64>, AppError> {
        if time < previous {
            return Err(app_io(io::ErrorKind::InvalidInput.into()));
        }
        let elapsed = time
            .checked_duration_since(self.epoch)
            .ok_or_else(|| app_io(io::ErrorKind::InvalidInput.into()))?;
        let millis = u64::try_from(elapsed.as_millis())
            .map_err(|_| app_io(io::ErrorKind::InvalidInput.into()))?;
        Ok(self
            .until
            .is_none_or(|until| time < until)
            .then_some(millis))
    }

    fn work_ready(app: &mut StagedApp, now: u64, local: bool) -> bool {
        app.transport().stage != Stage::Empty
            || local
            || app.next_poll_at(now).is_some_and(|due| due <= now)
    }

    fn poll_app(
        &self,
        app: &mut StagedApp,
        time: Instant,
        previous: Instant,
    ) -> Result<Turn, AppError> {
        let Some(now) = self.sample(time, previous)? else {
            return Ok(Turn::Stop);
        };
        #[cfg(test)]
        TransportCounts::inc(&mut app.transport_mut().counts.app_polls);
        let previous = app.transport_mut().begin_poll();
        let result = app.poll(now);
        match app.transport_mut().finish_poll(previous, result) {
            Ok(()) | Err(AppError::Oscore(_)) => Ok(Turn::Polled(now)),
            Err(error) => Err(error),
        }
    }

    fn wait(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        let timeout = deadline.map(|due| due.saturating_duration_since(Instant::now()));
        match self.poll.poll(&mut self.events, timeout) {
            // Interrupted/spurious readiness only ends this wait. The next turn
            // resamples eligibility and performs a real read before waiting again.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(()),
            result => result,
        }
    }

    fn turn(&mut self, app: &mut StagedApp) -> Result<Turn, AppError> {
        self.turn_with(
            app,
            |_| false,
            Instant::now,
            |driver, deadline| driver.wait(deadline),
        )
    }

    // Synchronous clock/local/wait seams prove ordering without readiness fakery.
    fn turn_with(
        &mut self,
        app: &mut StagedApp,
        mut local: impl FnMut(&mut StagedApp) -> bool,
        mut clock: impl FnMut() -> Instant,
        mut wait: impl FnMut(&mut Self, Option<Instant>) -> io::Result<()>,
    ) -> Result<Turn, AppError> {
        #[cfg(test)]
        if self.until.is_some() && self.counts.turns >= 64 {
            return Ok(Turn::Stop);
        }
        self.turns_since_checkpoint += 1;
        #[cfg(test)]
        TransportCounts::inc(&mut self.counts.turns);
        let result = (|| {
            let before = clock();
            let Some(now) = self.sample(before, self.epoch)? else {
                return Ok(Turn::Stop);
            };
            let local_ready = local(app);
            if Self::work_ready(app, now, local_ready) {
                return self.poll_app(app, clock(), before);
            }
            let capacity = app.engine_mut().capacities().rx_datagram_bytes;
            #[cfg(test)]
            TransportCounts::inc(&mut self.counts.probes);
            app.transport_mut().probe(capacity).map_err(app_io)?;
            if app.transport().stage != Stage::Empty {
                return self.poll_app(app, clock(), before);
            }
            #[cfg(test)]
            TransportCounts::inc(&mut self.counts.empty);
            let after = clock();
            let Some(now) = self.sample(after, before)? else {
                return Ok(Turn::Stop);
            };
            let local_ready = local(app);
            if app.transport().stage != Stage::Empty || local_ready {
                return self.poll_app(app, clock(), after);
            }
            // Reuse only this adjacent same-App, same-time result; no mutation
            // separates the eligibility decision from its wait bound.
            let opportunity = app.next_poll_at(now);
            if opportunity.is_some_and(|due| due <= now) {
                return self.poll_app(app, clock(), after);
            }
            let due = opportunity
                .map(|due| {
                    self.epoch
                        .checked_add(Duration::from_millis(due))
                        .ok_or_else(|| app_io(io::ErrorKind::InvalidInput.into()))
                })
                .transpose()?;
            let deadline = match (due, self.until) {
                (Some(due), Some(until)) => Some(due.min(until)),
                (due, until) => due.or(until),
            };
            #[cfg(test)]
            TransportCounts::inc(&mut self.counts.waits);
            wait(self, deadline).map_err(app_io)?;
            let woke = clock();
            let Some(now) = self.sample(woke, after)? else {
                return Ok(Turn::Stop);
            };
            let local_ready = local(app);
            if Self::work_ready(app, now, local_ready) {
                self.poll_app(app, clock(), woke)
            } else {
                Ok(Turn::Idle)
            }
        })();
        if self.turns_since_checkpoint == 32 {
            self.turns_since_checkpoint = 0;
            #[cfg(test)]
            TransportCounts::inc(&mut self.counts.checkpoints);
            std::thread::yield_now();
        }
        result
    }
}

fn write_resources(output: &mut impl io::Write) -> io::Result<()> {
    assert!((1..=64).contains(&mem::size_of::<Stage>()));
    writeln!(
        output,
        "{{\"schema\":\"coaptic-native-server-resources/2\",\"server_kind\":\"coaptic-staged-mio\",\"udp_scratch_bytes\":2049,\"staged_datagram_capacity\":1,\"stage_metadata_bytes\":{},\"driver_inline_bytes\":{},\"adapter_inline_bytes\":{},\"app_including_adapter_bytes\":{},\"runtime_heap_bytes\":null,\"runtime_stack_bytes\":null,\"send_policy\":\"immediate_send_to\",\"nesting\":\"scratch and Stage inside adapter inside App; separate Driver owns Poll and Events; do not sum nested owners\",\"limits\":\"inline component sizes only; one extra staged datagram beyond four Engine RX; main and polling stacks, core pools and body heap, Events allocation, poller and socket allocations, allocator and kernel costs excluded and unknown; actual runtime allocations and whole RAM unknown; no CPU claim\"}}",
        mem::size_of::<Stage>(),
        mem::size_of::<Driver>(),
        mem::size_of::<StagedMio>(),
        mem::size_of::<StagedApp>()
    )?;
    output.flush()
}

pub(super) fn serve(
    address: &str,
    bytes: usize,
    rx_bytes: usize,
    context: Option<SecurityContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    let io = StagedMio::bind(address)?;
    let mut app = bind_fixture(io, bytes, rx_bytes, context)?;
    let mut driver = Driver::new(&mut app, Instant::now(), None)?;
    write_resources(&mut io::stdout().lock())?;
    loop {
        match driver.turn(&mut app)? {
            Turn::Stop => return Ok(()),
            Turn::Idle | Turn::Polled(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::staged_udp::tests::{context, oversized_packet, verify_four};
    use super::*;

    fn fixture() -> StagedApp {
        bind_fixture(StagedMio::bind("127.0.0.1:0").unwrap(), 64, 1472, None).unwrap()
    }

    fn finite(epoch: Instant) -> Instant {
        epoch.checked_add(Duration::from_secs(1)).unwrap()
    }

    #[test]
    fn oversized_driver_turn_recovers_complete_operations() {
        for protected in [false, true] {
            let epoch = Instant::now();
            let until = finite(epoch);
            let io = StagedMio::bind("127.0.0.1:0").unwrap();
            let local = io.socket.local_addr().unwrap();
            let mut app = bind_fixture(io, 64, 1472, protected.then(|| context(true))).unwrap();
            let mut driver = Driver::new(&mut app, epoch, Some(until)).unwrap();
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            sender.send_to(&oversized_packet(), local).unwrap();
            assert!(matches!(driver.turn(&mut app).unwrap(), Turn::Polled(_)));
            assert_eq!(app.transport().stage, Stage::Empty);
            assert_eq!(app.engine_mut().rx_occupied(), 0);
            assert_eq!(
                (
                    app.metrics().rx_accepted,
                    app.metrics().tx_ok,
                    app.metrics().rx_error
                ),
                (0, 0, 1)
            );
            let (app, _) = verify_four(app, local.into(), epoch, until, protected, |app| {
                assert_ne!(driver.turn(app).unwrap(), Turn::Stop);
            });
            assert_eq!(app.transport().stage, Stage::Empty);
            assert_eq!(app.metrics().rx_error, 1);
        }
    }

    #[test]
    fn driver_turn_preserves_native_receive_errors() {
        for kind in [io::ErrorKind::InvalidData, io::ErrorKind::ConnectionReset] {
            let mut app = fixture();
            app.transport_mut().stage_result(Err(kind.into()));
            let epoch = Instant::now();
            let mut driver = Driver::new(&mut app, epoch, Some(finite(epoch))).unwrap();
            assert!(
                matches!(driver.turn(&mut app), Err(AppError::Io(DatagramIoError::Io(error))) if error.kind() == kind)
            );
            assert_eq!(app.transport().stage, Stage::Empty);
            assert_eq!(app.engine_mut().rx_occupied(), 0);
            assert_eq!(app.metrics().rx_error, 1);
        }
    }

    #[test]
    fn driver_turn_progress_send_failure_preserves_ingress_provenance() {
        let bad_peer: Endpoint = "[::1]:9".parse::<SocketAddr>().unwrap().into();
        for saturated in [false, true] {
            let mut app = fixture();
            let expected = app
                .transport()
                .socket
                .send_to(b"no", SocketAddr::from(bad_peer))
                .unwrap_err();
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            sender
                .send_to(
                    &oversized_packet(),
                    app.transport().socket.local_addr().unwrap(),
                )
                .unwrap();
            let due = pending(&mut app, bad_peer);
            let epoch = Instant::now() - Duration::from_millis(due);
            let mut driver = Driver::new(&mut app, epoch, Some(finite(Instant::now()))).unwrap();
            stage(app.transport_mut(), &mut driver, 1472);
            assert_eq!(app.transport().stage, Stage::Oversized);
            let held: Option<[_; 4]> = saturated.then(|| {
                std::array::from_fn(|_| {
                    let slot = app.engine_mut().acquire_rx().unwrap();
                    app.engine_mut()
                        .write_rx(slot, &[0x40, 0, 0, 9], bad_peer)
                        .unwrap();
                    slot
                })
            });
            let Err(AppError::Io(DatagramIoError::Io(error))) = driver.turn(&mut app) else {
                panic!("due progress send failure must propagate");
            };
            assert_eq!(error.kind(), expected.kind());
            assert_eq!(error.raw_os_error(), expected.raw_os_error());
            assert_eq!(
                app.transport().stage,
                if saturated {
                    Stage::Oversized
                } else {
                    Stage::Empty
                }
            );
            assert_eq!(app.metrics().rx_error, u32::from(!saturated));
            assert_eq!(app.metrics().tx_fail, 1);
            if let Some(held) = held {
                for slot in held {
                    app.engine_mut().release_rx(slot).unwrap();
                }
            }
            assert_eq!(app.engine_mut().rx_occupied(), 0);
        }
    }

    #[test]
    fn oversize_marker_preserves_saturation_and_send_errors() {
        let mut app = fixture();
        let epoch = Instant::now();
        let mut driver = Driver::new(&mut app, epoch, Some(finite(epoch))).unwrap();
        app.transport_mut().stage = Stage::Oversized;
        let peer = Endpoint::v4([127, 0, 0, 1], 9);
        let held: [_; 4] = std::array::from_fn(|_| {
            let slot = app.engine_mut().acquire_rx().unwrap();
            app.engine_mut()
                .write_rx(slot, &[0x40, 0, 0, 9], peer)
                .unwrap();
            slot
        });
        assert!(matches!(driver.turn(&mut app), Err(AppError::Saturated)));
        assert_eq!(app.transport().stage, Stage::Oversized);
        for slot in held {
            if app.engine_mut().access_rx(slot).is_ok() {
                app.engine_mut().release_rx(slot).unwrap();
            }
        }
        driver.turn(&mut app).unwrap();
        assert_eq!(app.transport().stage, Stage::Empty);
        for consumed in [false, true] {
            for kind in [io::ErrorKind::InvalidData, io::ErrorKind::ConnectionReset] {
                let io = app.transport_mut();
                io.stage = Stage::Oversized;
                let previous = io.begin_poll();
                if consumed {
                    assert_eq!(
                        io.recv(&mut [0; 1472]).unwrap_err().kind(),
                        io::ErrorKind::InvalidData
                    );
                }
                let error = io
                    .send_with(peer, b"retained", |_, _, _| Err(kind.into()))
                    .unwrap_err();
                assert!(
                    matches!(io.finish_poll(previous, Err(app_io(error))), Err(AppError::Io(DatagramIoError::Io(error))) if error.kind() == kind)
                );
                assert_eq!(io.stage, if consumed { Stage::Empty } else { previous });
                io.stage = Stage::Empty;
            }
        }
    }

    fn stage(io: &mut StagedMio, driver: &mut Driver, capacity: usize) {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(100))
            .unwrap();
        loop {
            io.probe(capacity).unwrap();
            if io.stage != Stage::Empty {
                return;
            }
            assert!(Instant::now() < deadline, "finite native receive");
            driver.wait(Some(deadline)).unwrap();
        }
    }

    fn pending(app: &mut StagedApp, peer: Endpoint) -> u64 {
        use coaptic::message::{Message, MessageId, Type};
        let slot = app.engine_mut().acquire_tx().unwrap();
        let mid = MessageId::new(9);
        app.engine_mut()
            .encode_tx(
                slot,
                &Message::new(Type::Confirmable, coaptic::Code::GET, mid),
            )
            .unwrap();
        app.engine_mut()
            .record_pending_con(slot, peer, mid, 0, 0)
            .unwrap();
        app.next_timeout().unwrap()
    }

    #[test]
    fn finite_authenticated_four() {
        for protected in [false, true] {
            let epoch = Instant::now();
            let until = finite(epoch);
            let io = StagedMio::bind("127.0.0.1:0").unwrap();
            let peer = io.socket.local_addr().unwrap().into();
            let mut app = bind_fixture(io, 64, 1472, protected.then(|| context(true))).unwrap();
            let mut driver = Driver::new(&mut app, epoch, Some(until)).unwrap();
            let (app, result) = verify_four(app, peer, epoch, until, protected, |app| {
                assert_ne!(driver.turn(app).unwrap(), Turn::Stop);
            });
            let c = app.transport().counts;
            assert_eq!(
                (c.app_polls, c.recv_calls, c.recv_empty, c.socket_send_calls),
                (4, 4, 0, 4)
            );
            assert_eq!(
                (c.socket_recv_calls, c.readable_waits, c.read_timeout_sets),
                (0, 0, 0)
            );
            assert!(driver.counts.probes >= 4 && driver.counts.turns <= 64);
            assert_eq!(driver.counts.empty, driver.counts.waits);
            assert_eq!(driver.counts.probes - driver.counts.empty, 4);
            println!(
                "staged-mio protected={protected} verified=4 warmup=0 rx_tx_progress_client_turns={result:?} app_polls={} stage_consumes={} external_probes={} external_empty={} waits={} turns={} checkpoints={}; test counters compile out, ordinary sizes in startup ledger",
                c.app_polls,
                c.recv_calls,
                driver.counts.probes,
                driver.counts.empty,
                driver.counts.waits,
                driver.counts.turns,
                driver.counts.checkpoints
            );
        }
    }

    #[test]
    fn actual_udp_boundaries_short_output_occupied_stage_and_recovery() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let sender = match std::net::UdpSocket::bind(address) {
                Ok(socket) => socket,
                Err(_) if address.starts_with('[') => continue,
                Err(error) => panic!("IPv4 required: {error}"),
            };
            let peer: Endpoint = sender.local_addr().unwrap().into();
            for capacity in [64, 1472, 2048] {
                let mut io = StagedMio::bind(address).unwrap();
                let local = io.socket.local_addr().unwrap();
                let epoch = Instant::now();
                let mut driver = Driver::register(&mut io, epoch, Some(finite(epoch))).unwrap();
                let payload = [0x39; 2056];
                let mut output = [0xa5; 2049];
                for size in [capacity, capacity + 1, capacity + 8, 0, 3] {
                    sender.send_to(&payload[..size], local).unwrap();
                    stage(&mut io, &mut driver, capacity);
                    let staged = io.stage;
                    sender.send_to(b"next", local).unwrap();
                    let scratch = io.scratch; // Test witness only.
                    io.probe(capacity).unwrap();
                    assert_eq!(io.stage, staged);
                    assert_eq!(io.scratch, scratch);
                    output.fill(0xa5);
                    assert_eq!(
                        io.recv(&mut output).unwrap_err().kind(),
                        io::ErrorKind::InvalidInput
                    );
                    assert_eq!(io.stage, staged);
                    if size <= capacity {
                        if size > 0 {
                            assert_eq!(
                                io.recv(&mut output[..size - 1]).unwrap_err().kind(),
                                io::ErrorKind::InvalidInput
                            );
                            assert_eq!(io.stage, staged);
                            assert_eq!(io.scratch, scratch);
                        }
                        assert_eq!(
                            io.recv(&mut output[..capacity]).unwrap(),
                            Some((size, peer))
                        );
                        assert_eq!(&output[..size], &payload[..size]);
                    } else {
                        // Even a larger destination cannot admit the N+1 prefix.
                        assert!(io.recv(&mut output[..(capacity + 64).min(2048)]).is_err());
                        assert!(output.iter().all(|byte| *byte == 0xa5));
                    }
                    assert_eq!(io.stage, Stage::Empty);
                    stage(&mut io, &mut driver, capacity);
                    assert_eq!(io.recv(&mut output[..capacity]).unwrap(), Some((4, peer)));
                    assert_eq!(&output[..4], b"next");
                }
                io.probe(capacity).unwrap();
                assert_eq!(io.stage, Stage::Empty); // Actual WouldBlock.
                for kind in [
                    io::ErrorKind::TimedOut,
                    io::ErrorKind::Interrupted,
                    io::ErrorKind::ConnectionReset,
                ] {
                    io.stage_result(Err(kind.into()));
                    assert_eq!(io.recv(&mut output[..capacity]).unwrap_err().kind(), kind);
                    sender.send_to(b"valid", local).unwrap();
                    stage(&mut io, &mut driver, capacity);
                    assert_eq!(io.recv(&mut output[..capacity]).unwrap(), Some((5, peer)));
                }
                io.stage_result(Err(io::Error::from_raw_os_error(12345)));
                assert_eq!(
                    io.recv(&mut output[..capacity]).unwrap_err().raw_os_error(),
                    Some(12345)
                );
            }
        }
        assert!(bind_fixture(StagedMio::bind("127.0.0.1:0").unwrap(), 64, 2049, None).is_err());
    }

    #[test]
    fn rx_saturation_pin_and_pending_stage_recover() {
        let mut app = fixture();
        let peer = Endpoint::v4([127, 0, 0, 1], 9);
        app.transport_mut().scratch[..4].copy_from_slice(&[0x40, 0, 0, 7]);
        app.transport_mut().stage_result(Ok((4, peer.into())));
        let mut engine = coaptic::storage::EngineBuilder::new()
            .profile::<coaptic::profiles::Default>()
            .block_wise(false)
            .build(coaptic::storage::Memory::<coaptic::profiles::Default>::new())
            .unwrap();
        let held: [_; 4] = std::array::from_fn(|_| engine.acquire_rx().unwrap());
        engine.write_rx(held[0], b"pinned", peer).unwrap();
        {
            let access = engine.access_rx(held[0]).unwrap();
            assert!(access.is_pinned());
            app.transport_mut().probe(1472).unwrap();
            assert_eq!(access.as_bytes(), b"pinned");
        }
        assert!(!engine.rx_is_pinned(held[0]));
        let expected = app.transport().stage;
        let epoch = Instant::now();
        let mut driver = Driver::new(&mut app, epoch, Some(finite(epoch))).unwrap();
        assert!(matches!(
            engine.recv_from(app.transport_mut()),
            Err(DatagramIoError::Saturated)
        ));
        assert_eq!(app.transport().stage, expected);
        assert_eq!(app.transport().counts.recv_calls, 0);
        for slot in held {
            engine.release_rx(slot).unwrap();
        }
        driver.turn(&mut app).unwrap();
        assert_eq!(app.transport().stage, Stage::Empty);
        assert_eq!(app.metrics().rx_accepted, 1);

        let mut app = fixture();
        app.transport_mut().scratch[..4].copy_from_slice(&[0x40, 0, 0, 8]);
        app.transport_mut().stage_result(Ok((4, peer.into())));
        let held: [_; 4] = std::array::from_fn(|_| {
            let slot = app.engine_mut().acquire_rx().unwrap();
            app.engine_mut()
                .write_rx(slot, &[0x40, 0, 0, 9], peer)
                .unwrap();
            slot
        });
        let epoch = Instant::now();
        let mut driver = Driver::new(&mut app, epoch, Some(finite(epoch))).unwrap();
        let refused = driver.turn(&mut app);
        assert!(matches!(refused, Err(AppError::Saturated)), "{refused:?}");
        assert_ne!(app.transport().stage, Stage::Empty);
        assert_eq!(driver.counts.probes, 0);
        for slot in held {
            if app.engine_mut().access_rx(slot).is_ok() {
                app.engine_mut().release_rx(slot).unwrap();
            }
        }
        driver.turn(&mut app).unwrap();
        assert_eq!(app.transport().stage, Stage::Empty);
    }

    #[test]
    fn fresh_due_local_retained_work_precedes_ingress() {
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = sender.local_addr().unwrap().into();
        let mut app = fixture();
        let address = app.transport().socket.local_addr().unwrap();
        let due = pending(&mut app, peer);
        let epoch = Instant::now();
        let mut driver = Driver::new(
            &mut app,
            epoch,
            Some(
                epoch
                    .checked_add(Duration::from_millis(due + 1000))
                    .unwrap(),
            ),
        )
        .unwrap();
        let mut times = [
            epoch,
            epoch,
            epoch + Duration::from_millis(due),
            epoch + Duration::from_millis(due + 1),
        ]
        .into_iter();
        assert_eq!(
            driver
                .turn_with(
                    &mut app,
                    |_| false,
                    || times.next().unwrap(),
                    |_, deadline| {
                        assert_eq!(deadline, Some(epoch + Duration::from_millis(due)));
                        sender.send_to(&[0x40, 0, 0, 1], address).unwrap();
                        Ok(())
                    }
                )
                .unwrap(),
            Turn::Polled(due + 1)
        );
        assert_eq!(app.metrics().con_retransmit, 1);
        assert_eq!(app.metrics().rx_accepted, 0);
        assert_eq!((driver.counts.probes, driver.counts.empty), (1, 1));
        driver
            .turn_with(
                &mut app,
                |_| true,
                || epoch + Duration::from_millis(due + 2),
                |_, _| panic!("local must not wait"),
            )
            .unwrap();
        let slot = app.engine_mut().acquire_rx().unwrap();
        app.engine_mut()
            .write_rx(slot, &[0x40, 0, 0, 2], peer)
            .unwrap();
        driver
            .turn_with(
                &mut app,
                |_| false,
                || epoch + Duration::from_millis(due + 3),
                |_, _| panic!("retained must not wait"),
            )
            .unwrap();
        assert_eq!(driver.counts.probes, 1);
        assert_eq!(app.metrics().rx_accepted, 0);
        driver
            .turn_with(
                &mut app,
                |_| false,
                || epoch + Duration::from_millis(due + 4),
                |_, _| panic!("queued packet"),
            )
            .unwrap();
        assert_eq!(app.metrics().rx_accepted, 1);

        let mut app = fixture();
        let due = pending(&mut app, peer);
        let mut driver = Driver::new(&mut app, epoch, None).unwrap();
        let mut times = [
            epoch,
            epoch + Duration::from_millis(due),
            epoch + Duration::from_millis(due + 1),
        ]
        .into_iter();
        assert_eq!(
            driver
                .turn_with(
                    &mut app,
                    |_| false,
                    || times.next().unwrap(),
                    |_, _| panic!("became due during probe")
                )
                .unwrap(),
            Turn::Polled(due + 1)
        );
        assert_eq!(app.metrics().con_retransmit, 1);
        let mut times = [
            epoch + Duration::from_millis(6),
            epoch + Duration::from_millis(5),
        ]
        .into_iter();
        assert!(
            driver
                .turn_with(&mut app, |_| true, || times.next().unwrap(), |_, _| Ok(()))
                .is_err()
        );
    }

    #[test]
    fn staged_errors_still_advance_maintenance_and_send_error_wins() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = receiver.local_addr().unwrap().into();
        let mut app = fixture();
        let call = app.get("unused").deadline(10).to(peer).send(0).unwrap();
        app.transport_mut()
            .stage_result(Err(io::ErrorKind::TimedOut.into()));
        let epoch = Instant::now();
        let mut driver = Driver::new(&mut app, epoch, Some(finite(epoch))).unwrap();
        let mut times = [epoch, epoch + Duration::from_millis(17)].into_iter();
        assert!(
            matches!(driver.turn_with(&mut app, |_| false, || times.next().unwrap(), |_, _| Ok(())), Err(AppError::Io(DatagramIoError::Io(error))) if error.kind() == io::ErrorKind::TimedOut)
        );
        assert!(matches!(
            app.take_response(call),
            Some(Err(coaptic::CallFailure::DeadlineExceeded))
        ));
        assert_eq!(app.transport().stage, Stage::Empty);
        let due = pending(&mut app, peer);
        driver.until = Some(epoch.checked_add(Duration::from_millis(due + 100)).unwrap());
        app.transport_mut()
            .stage_result(Err(io::ErrorKind::ConnectionReset.into()));
        assert!(
            matches!(driver.turn_with(&mut app, |_| false, || epoch + Duration::from_millis(due), |_, _| Ok(())), Err(AppError::Io(DatagramIoError::Io(error))) if error.kind() == io::ErrorKind::ConnectionReset)
        );
        assert_eq!(app.metrics().con_retransmit, 1);

        struct Refuse(StagedMio);
        impl DatagramTransport for Refuse {
            type Error = io::Error;
        }
        impl DatagramIo for Refuse {
            fn recv(&mut self, bytes: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
                self.0.recv(bytes)
            }
            fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> io::Result<usize> {
                self.0
                    .send_with(peer, bytes, |_, _, _| Err(io::ErrorKind::WouldBlock.into()))
            }
        }
        let mut app = bind_fixture(
            Refuse(StagedMio::bind("127.0.0.1:0").unwrap()),
            64,
            1472,
            None,
        )
        .unwrap();
        use coaptic::message::{Message, MessageId, Type};
        let tx = app.engine_mut().acquire_tx().unwrap();
        let mid = MessageId::new(9);
        app.engine_mut()
            .encode_tx(
                tx,
                &Message::new(Type::Confirmable, coaptic::Code::GET, mid),
            )
            .unwrap();
        app.engine_mut()
            .record_pending_con(tx, peer, mid, 0, 0)
            .unwrap();
        let due = app.next_timeout().unwrap();
        app.transport_mut()
            .0
            .stage_result(Err(io::ErrorKind::ConnectionReset.into()));
        assert!(
            matches!(app.poll(due), Err(AppError::Io(DatagramIoError::Io(error))) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(app.transport().0.stage, Stage::Empty);
        assert_eq!((app.metrics().rx_error, app.metrics().tx_fail), (1, 1));
    }

    #[test]
    fn immediate_refusal_short_send_preserve_exact_tx_and_staged_rx() {
        use coaptic::{
            Code,
            message::{Message, MessageId, Opt, Token, Type},
        };
        struct Refuse(StagedMio, bool);
        impl DatagramTransport for Refuse {
            type Error = io::Error;
        }
        impl DatagramIo for Refuse {
            fn recv(&mut self, bytes: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
                self.0.recv(bytes)
            }
            fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> io::Result<usize> {
                let short = self.1;
                self.0.send_with(peer, bytes, |_, bytes, _| {
                    if short {
                        Ok(bytes.len() - 1)
                    } else {
                        Err(io::ErrorKind::WouldBlock.into())
                    }
                })
            }
        }
        let peer = Endpoint::v4([127, 0, 0, 1], 9);
        for protected in [false, true] {
            let options = [Opt::uri_path("bench")];
            let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(11))
                .with_token(Token::new(&[1]).unwrap())
                .with_options(&options);
            let mut wire = [0; 1472];
            let n = if protected {
                context(false).protect_request(&request, &mut wire).unwrap()
            } else {
                coaptic::message::encode(&request, &mut wire).unwrap()
            };
            let mut app = fixture();
            let tx = app.engine_mut().acquire_tx().unwrap();
            app.engine_mut().write_tx(tx, &wire[..n], peer).unwrap();
            app.engine_mut()
                .record_pending_con(tx, peer, MessageId::new(11), 0, 0)
                .unwrap();
            let before = app.engine_mut().pending_con(tx);
            let mut io = Refuse(StagedMio::bind("127.0.0.1:0").unwrap(), false);
            io.0.scratch[..3].copy_from_slice(b"rx!");
            io.0.stage_result(Ok((3, peer.into())));
            let stage = io.0.stage;
            for short in [false, true] {
                io.1 = short;
                let error = app.engine_mut().send_tx(&mut io, tx).unwrap_err();
                if short {
                    assert!(matches!(error, DatagramIoError::SendLength { .. }));
                } else {
                    assert!(
                        matches!(error, DatagramIoError::Io(error) if error.kind() == io::ErrorKind::WouldBlock)
                    );
                }
                assert_eq!(
                    app.engine_mut().access_tx(tx).unwrap().as_bytes(),
                    &wire[..n]
                );
                assert_eq!(app.engine_mut().pending_con(tx), before);
                assert!(!app.engine_mut().tx_is_pinned(tx));
                assert_eq!(io.0.stage, stage);
            }
            let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            assert_eq!(
                io.0.send(receiver.local_addr().unwrap().into(), &wire[..n])
                    .unwrap(),
                n
            );
            let mut output = [0; 1472];
            let (received, _) = receiver.recv_from(&mut output).unwrap();
            assert_eq!(&output[..received], &wire[..n]);
            assert_eq!(&io.0.scratch[..3], b"rx!");
            assert_eq!(io.0.stage, stage);
            assert_eq!(io.0.counts.socket_send_calls, 3);
            assert_eq!(app.metrics().tx_fail, 2);
        }
    }

    #[test]
    fn stop_preserves_ingress_and_empty_turns_checkpoint_with_no_production_caps() {
        let mut app = fixture();
        let epoch = Instant::now();
        let until = finite(epoch);
        let mut driver = Driver::new(&mut app, epoch, Some(until)).unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(
                &[0x40, 0, 0, 7],
                app.transport().socket.local_addr().unwrap(),
            )
            .unwrap();
        stage(app.transport_mut(), &mut driver, 1472);
        let expected = app.transport().stage;
        assert_eq!(
            driver
                .turn_with(&mut app, |_| false, || until, |_, _| panic!("expired"))
                .unwrap(),
            Turn::Stop
        );
        assert_eq!(app.transport().stage, expected);
        let mut output = [0; 1472];
        assert_eq!(app.transport_mut().recv(&mut output).unwrap().unwrap().0, 4);

        // Use a fresh App/driver pair for the ordinary None lifetime regression.
        let mut app = fixture();
        let mut driver = Driver::new(&mut app, epoch, None).unwrap();
        for turn in 1..=96 {
            assert_eq!(
                driver
                    .turn_with(
                        &mut app,
                        |_| false,
                        Instant::now,
                        |_, deadline| {
                            assert_eq!(deadline, None);
                            if turn == 1 {
                                std::thread::sleep(Duration::from_millis(1050));
                            }
                            Ok(())
                        }
                    )
                    .unwrap(),
                Turn::Idle
            );
            assert_eq!(driver.counts.checkpoints, turn / 32);
            assert_eq!(u32::from(driver.turns_since_checkpoint), turn % 32);
        }
        assert!(
            epoch.elapsed() > Duration::from_secs(1) && epoch.elapsed() < Duration::from_secs(3)
        );
        assert_eq!(
            (
                driver.counts.turns,
                driver.counts.probes,
                driver.counts.empty,
                driver.counts.waits,
                driver.counts.checkpoints
            ),
            (96, 96, 96, 96, 3)
        );
        assert_eq!(app.transport().counts.app_polls, 0);
        // Finite Some alone enforces the test turn budget, even with a fixed clock.
        let mut app = fixture();
        let mut finite_driver = Driver::new(&mut app, epoch, Some(finite(Instant::now()))).unwrap();
        for _ in 0..64 {
            assert_eq!(
                finite_driver
                    .turn_with(&mut app, |_| false, || epoch, |_, _| Ok(()))
                    .unwrap(),
                Turn::Idle
            );
        }
        assert_eq!(
            finite_driver
                .turn_with(&mut app, |_| false, || epoch, |_, _| Ok(()))
                .unwrap(),
            Turn::Stop
        );
        assert_eq!(finite_driver.counts.checkpoints, 2);
    }

    #[test]
    fn startup_ledger_is_single_bounded_flushed_line_without_future_or_timeout() {
        if cfg!(all(target_os = "windows", target_pointer_width = "64")) {
            assert_eq!(mem::size_of::<Stage>(), 32);
        }
        #[derive(Default)]
        struct Output {
            bytes: Vec<u8>,
            flushes: u8,
        }
        impl io::Write for Output {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                assert!(self.bytes.len() + bytes.len() <= 4096);
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                Ok(())
            }
        }
        let mut output = Output::default();
        write_resources(&mut output).unwrap();
        assert_eq!(output.flushes, 1);
        assert!(output.bytes.ends_with(b"}\n"));
        assert_eq!(
            output.bytes.iter().filter(|byte| **byte == b'\n').count(),
            1
        );
        let line = String::from_utf8(output.bytes).unwrap();
        assert!(line.starts_with("{\"schema\":\"coaptic-native-server-resources/2\",\"server_kind\":\"coaptic-staged-mio\","));
        for (name, expected) in [
            ("udp_scratch_bytes", 2049),
            ("staged_datagram_capacity", 1),
            ("stage_metadata_bytes", mem::size_of::<Stage>()),
            ("driver_inline_bytes", mem::size_of::<Driver>()),
            ("adapter_inline_bytes", mem::size_of::<StagedMio>()),
            ("app_including_adapter_bytes", mem::size_of::<StagedApp>()),
        ] {
            assert!(line.contains(&format!("\"{name}\":{expected},")));
        }
        assert!(line.contains("\"runtime_heap_bytes\":null,\"runtime_stack_bytes\":null,"));
        assert!(line.contains("\"send_policy\":\"immediate_send_to\","));
        assert!(!line.contains("future") && !line.contains("timeout"));
        println!("test-build only: {line}");
    }
}
