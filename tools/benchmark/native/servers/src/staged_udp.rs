//! Explicit synchronous host control with finite tests and optional server life.
//!
//! Receive waits happen before App samples its poll timestamp. Socket timeouts
//! are soft OS bounds; synchronous sends keep App's entry-time commit semantics
//! and are a different congestion policy from immediate WouldBlock.

#[cfg(test)]
use super::TransportCounts;
use super::{AllocMemory, App, DatagramIo, Endpoint, SecurityContext, UdpSocket, bind_fixture};
use coaptic::storage::{DatagramIoError, DatagramTransport};
use std::{
    io, mem,
    net::SocketAddr,
    time::{Duration, Instant},
};

const SCRATCH_BYTES: usize = 2049;
const MAX_WAIT: Duration = Duration::from_millis(5);
const SEND_WAIT: Duration = Duration::from_millis(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Empty,
    Oversized,
    // These two tags exist only within one driver poll. A failed progress send
    // clears RejectedOversized so it cannot be mistaken for the receive error.
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

struct State {
    stage: Stage,
    // Microseconds fit the fixed 5ms ceiling; zero means not yet configured.
    read_timeout_us: u32,
    until: Option<Instant>,
}

struct StagedUdp {
    socket: UdpSocket,
    scratch: [u8; SCRATCH_BYTES],
    state: State,
    #[cfg(test)]
    counts: Option<TransportCounts>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wait {
    Ready,
    Receive,
    CloseDeadline,
}

type StagedApp = App<coaptic::profiles::Default, StagedUdp, 1, true, AllocMemory>;
type AppError = coaptic::app::Error<io::Error>;

fn app_io(error: io::Error) -> AppError {
    AppError::Io(DatagramIoError::Io(error))
}

impl StagedUdp {
    fn new(socket: UdpSocket, until: Option<Instant>) -> io::Result<Self> {
        socket.set_nonblocking(false)?;
        socket.set_write_timeout(Some(SEND_WAIT))?;
        let mut io = Self {
            #[cfg(test)]
            counts: None,
            socket,
            scratch: [0; SCRATCH_BYTES],
            state: State {
                stage: Stage::Empty,
                read_timeout_us: 0,
                until,
            },
        };
        io.read_timeout_with(MAX_WAIT, |socket, timeout| {
            socket.set_read_timeout(Some(timeout))
        })?;
        Ok(io)
    }

    // The setter seam checks cache behavior without adding counters to transport.
    fn read_timeout_with(
        &mut self,
        allowance: Duration,
        set: impl FnOnce(&UdpSocket, Duration) -> io::Result<()>,
    ) -> io::Result<bool> {
        let micros = allowance.min(MAX_WAIT).as_micros();
        if micros == 0 {
            return Ok(false);
        }
        let micros = u32::try_from(micros).map_err(|_| io::ErrorKind::InvalidInput)?;
        if self.state.read_timeout_us == 0 || self.state.read_timeout_us > micros {
            #[cfg(test)]
            if let Some(counts) = &mut self.counts {
                TransportCounts::inc(&mut counts.read_timeout_sets);
            }
            set(&self.socket, Duration::from_micros(u64::from(micros)))?;
            self.state.read_timeout_us = micros;
        }
        Ok(true)
    }

    fn stage_result(&mut self, result: io::Result<(usize, SocketAddr)>) {
        debug_assert_eq!(self.state.stage, Stage::Empty);
        self.state.stage = match result {
            Ok((len, peer)) => match u16::try_from(len) {
                Ok(len) if usize::from(len) <= self.scratch.len() => Stage::Packet {
                    len,
                    peer: peer.into(),
                },
                _ => Stage::Oversized,
            },
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Stage::Empty
            }
            Err(error) => Stage::Error {
                raw: error.raw_os_error(),
                kind: error.kind(),
            },
        };
    }

    fn wait_until(&mut self, deadline: Option<Instant>, max_wait: Duration) -> io::Result<Wait> {
        if self.state.stage != Stage::Empty {
            return Ok(Wait::Ready);
        }
        let deadline = match (deadline, self.state.until) {
            (Some(deadline), Some(until)) => Some(deadline.min(until)),
            (deadline, until) => deadline.or(until),
        };
        let allowance = deadline.map_or(max_wait, |deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .min(max_wait)
        });
        if allowance.is_zero() {
            return Ok(Wait::Ready);
        }
        if !self.read_timeout_with(allowance, |socket, timeout| {
            socket.set_read_timeout(Some(timeout))
        })? {
            std::thread::sleep(allowance);
            return Ok(Wait::CloseDeadline);
        }
        // Recheck after configuration. An almost-due deadline must not start an
        // overlong cached receive. This fallback may delay ingress until the due
        // opportunity and is deliberately visible in the returned receipt.
        let remaining = deadline.map_or(max_wait, |deadline| {
            deadline.saturating_duration_since(Instant::now())
        });
        if Duration::from_micros(u64::from(self.state.read_timeout_us)) > remaining {
            std::thread::sleep(remaining.min(max_wait));
            return Ok(Wait::CloseDeadline);
        }
        #[cfg(test)]
        if let Some(counts) = &mut self.counts {
            TransportCounts::inc(&mut counts.socket_recv_calls);
        }
        let result = self.socket.recv_from(&mut self.scratch);
        self.stage_result(result);
        Ok(Wait::Receive)
    }

    fn send_with(
        &mut self,
        peer: Endpoint,
        bytes: &[u8],
        send: impl FnOnce(&UdpSocket, &[u8], SocketAddr) -> io::Result<usize>,
    ) -> io::Result<usize> {
        let result = self.try_send_with(peer, bytes, send);
        if result.is_err() && self.state.stage == Stage::RejectedOversized {
            self.state.stage = Stage::Empty;
        }
        result
    }

    fn try_send_with(
        &mut self,
        peer: Endpoint,
        bytes: &[u8],
        send: impl FnOnce(&UdpSocket, &[u8], SocketAddr) -> io::Result<usize>,
    ) -> io::Result<usize> {
        if self
            .state
            .until
            .is_some_and(|until| until.saturating_duration_since(Instant::now()) < SEND_WAIT)
        {
            return Err(io::ErrorKind::TimedOut.into());
        }
        #[cfg(test)]
        if let Some(counts) = &mut self.counts {
            TransportCounts::inc(&mut counts.socket_send_calls);
        }
        send(&self.socket, bytes, peer.into())
    }

    fn begin_poll(&mut self, capacity: usize) -> Stage {
        let previous = self.state.stage;
        if previous == Stage::Oversized
            || matches!(previous, Stage::Packet { len, .. } if usize::from(len) > capacity)
        {
            self.state.stage = Stage::RejectOversized;
        }
        previous
    }

    fn finish_poll(
        &mut self,
        previous: Stage,
        result: Result<(), AppError>,
    ) -> Result<(), AppError> {
        let rejected = self.state.stage == Stage::RejectedOversized;
        if self.state.stage == Stage::RejectOversized {
            // Failure before receive (including RX saturation) retains ingress.
            self.state.stage = previous;
        } else if rejected {
            self.state.stage = Stage::Empty;
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

impl DatagramTransport for StagedUdp {
    type Error = io::Error;
}

impl DatagramIo for StagedUdp {
    fn recv(&mut self, bytes: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
        #[cfg(test)]
        if let Some(counts) = &mut self.counts {
            TransportCounts::inc(&mut counts.recv_calls);
        }
        // The extra scratch byte must distinguish every accepted packet from a
        // truncated oversized one. Keep the stage available on capacity refusal.
        if bytes.len() >= self.scratch.len() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Engine calls this only after acquiring RX. An admission failure never
        // reaches this take and therefore cannot overwrite the staged owner.
        match mem::replace(&mut self.state.stage, Stage::Empty) {
            Stage::Oversized | Stage::RejectedOversized => Err(io::ErrorKind::InvalidData.into()),
            Stage::RejectOversized => {
                self.state.stage = Stage::RejectedOversized;
                Err(io::ErrorKind::InvalidData.into())
            }
            Stage::Empty => {
                #[cfg(test)]
                if let Some(counts) = &mut self.counts {
                    TransportCounts::inc(&mut counts.recv_empty);
                }
                Ok(None)
            }
            Stage::Packet { len, peer } => {
                let len = usize::from(len);
                if len > bytes.len() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                bytes[..len].copy_from_slice(&self.scratch[..len]);
                Ok(Some((len, peer)))
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

#[derive(Debug)]
struct Step {
    #[cfg(test)]
    poll_ms: u64,
    #[cfg(test)]
    wait: Wait,
}

fn step(app: &mut StagedApp, epoch: Instant, local: bool) -> Result<Option<Step>, AppError> {
    step_with_clock(app, epoch, local, Instant::now)
}

// A clock seam proves that App sees the post-wait time, not the pre-wait sample.
fn step_with_clock(
    app: &mut StagedApp,
    epoch: Instant,
    local: bool,
    mut clock: impl FnMut() -> Instant,
) -> Result<Option<Step>, AppError> {
    let before = clock();
    let until = app.transport().state.until;
    if until.is_some_and(|until| before >= until) {
        return Ok(None);
    }
    let elapsed = before
        .checked_duration_since(epoch)
        .ok_or_else(|| app_io(io::ErrorKind::InvalidInput.into()))?;
    let now = u64::try_from(elapsed.as_millis())
        .map_err(|_| app_io(io::ErrorKind::InvalidInput.into()))?;
    let due = app.next_poll_at(now);
    let _wait =
        if !local && app.transport().state.stage == Stage::Empty && due.is_none_or(|due| due > now)
        {
            let deadline = due
                .map(|due| {
                    epoch
                        .checked_add(Duration::from_millis(due))
                        .ok_or_else(|| app_io(io::ErrorKind::InvalidInput.into()))
                })
                .transpose()?;
            app.transport_mut()
                .wait_until(deadline, MAX_WAIT)
                .map_err(app_io)?
        } else {
            Wait::Ready
        };
    let after = clock();
    if after < before {
        return Err(app_io(io::ErrorKind::InvalidInput.into()));
    }
    // Leave the stage owned if the finite budget expires. send() independently
    // checks room for its fixed configured timeout before each socket call.
    if until.is_some_and(|until| after >= until) {
        return Ok(None);
    }
    let poll_ms = u64::try_from(after.duration_since(epoch).as_millis())
        .map_err(|_| app_io(io::ErrorKind::InvalidInput.into()))?;
    #[cfg(test)]
    if let Some(counts) = &mut app.transport_mut().counts {
        TransportCounts::inc(&mut counts.app_polls);
    }
    let capacity = app.engine().capacities().rx_datagram_bytes;
    let previous = app.transport_mut().begin_poll(capacity);
    let result = app.poll(poll_ms);
    app.transport_mut().finish_poll(previous, result)?;
    Ok(Some(Step {
        #[cfg(test)]
        poll_ms,
        #[cfg(test)]
        wait: _wait,
    }))
}

fn write_resources(output: &mut impl io::Write) -> io::Result<()> {
    assert!((1..=64).contains(&mem::size_of::<State>()));
    writeln!(
        output,
        "{{\"schema\":\"coaptic-native-blocking-resources/1\",\"server_kind\":\"coaptic-blocking\",\"udp_scratch_bytes\":2049,\"staged_datagram_capacity\":1,\"stage_cache_metadata_bytes\":{},\"adapter_inline_bytes\":{},\"app_including_adapter_bytes\":{},\"read_timeout_max_us\":5000,\"send_timeout_us\":1000,\"timeouts_soft\":true,\"runtime_heap_bytes\":null,\"runtime_stack_bytes\":null,\"nesting\":\"metadata and one staged packet in scratch inside adapter inside App; stage separate from Engine RX pool; do not sum nested owners\",\"limits\":\"inline sizes only; caller/main frame, heap pools/body, allocator and kernel costs excluded and unknown; socket timeouts are soft bounds; synchronous sends commit at App poll entry time\"}}",
        mem::size_of::<State>(),
        mem::size_of::<StagedUdp>(),
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
    let io = StagedUdp::new(UdpSocket::bind(address)?, None)?;
    let mut app = bind_fixture(io, bytes, rx_bytes, context)?;
    write_resources(&mut io::stdout().lock())?;
    let epoch = Instant::now();
    loop {
        match step(&mut app, epoch, false) {
            Ok(_) | Err(coaptic::app::Error::Oscore(_)) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(crate) fn oversized_packet() -> [u8; 1473] {
        let mut packet = [0x39; 1473];
        // CON GET /bench with a payload: even its truncated prefix decodes.
        packet[..11].copy_from_slice(&[0x40, 1, 0, 123, 0xb5, b'b', b'e', b'n', b'c', b'h', 0xff]);
        assert!(coaptic::message::decode(&packet[..1472]).is_ok());
        packet
    }

    #[test]
    fn oversized_driver_turn_recovers_complete_operations() {
        for protected in [false, true] {
            let epoch = Instant::now();
            let until = epoch + Duration::from_secs(1);
            let io = StagedUdp::new(UdpSocket::bind("127.0.0.1:0").unwrap(), Some(until)).unwrap();
            let local = io.socket.local_addr().unwrap();
            let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
            sender.send_to(&oversized_packet(), local).unwrap();
            let mut app = bind_fixture(io, 64, 1472, protected.then(|| context(true))).unwrap();
            assert_eq!(
                step(&mut app, epoch, false).unwrap().unwrap().wait,
                Wait::Receive
            );
            assert_eq!(app.transport().state.stage, Stage::Empty);
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
                assert!(step(app, epoch, false).unwrap().is_some());
            });
            assert_eq!(app.transport().state.stage, Stage::Empty);
            assert_eq!(app.metrics().rx_error, 1);
        }
    }

    #[test]
    fn driver_turn_preserves_native_receive_errors() {
        for kind in [io::ErrorKind::InvalidData, io::ErrorKind::ConnectionReset] {
            let mut app = fixture(transport());
            app.transport_mut().stage_result(Err(kind.into()));
            assert!(
                matches!(step(&mut app, Instant::now(), false), Err(AppError::Io(DatagramIoError::Io(error))) if error.kind() == kind)
            );
            assert_eq!(app.transport().state.stage, Stage::Empty);
            assert_eq!(app.engine_mut().rx_occupied(), 0);
            assert_eq!(app.metrics().rx_error, 1);
        }
    }

    #[test]
    fn driver_turn_progress_send_failure_preserves_ingress_provenance() {
        let bad_peer: Endpoint = "[::1]:9".parse::<SocketAddr>().unwrap().into();
        for saturated in [false, true] {
            let mut app = fixture(transport());
            // An IPv4 socket cannot send to an IPv6 destination. Keep the actual
            // platform's error rather than inventing a portable errno mapping.
            let expected = app
                .transport()
                .socket
                .send_to(b"no", SocketAddr::from(bad_peer))
                .unwrap_err();
            let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
            sender
                .send_to(
                    &oversized_packet(),
                    app.transport().socket.local_addr().unwrap(),
                )
                .unwrap();
            app.transport_mut().wait_until(None, MAX_WAIT).unwrap();
            let staged = app.transport().state.stage;
            let due = pending(&mut app, bad_peer);
            let held: Option<[_; 4]> = saturated.then(|| {
                std::array::from_fn(|_| {
                    let slot = app.engine_mut().acquire_rx().unwrap();
                    app.engine_mut()
                        .write_rx(slot, &[0x40, 0, 0, 9], bad_peer)
                        .unwrap();
                    slot
                })
            });
            let epoch = Instant::now() - Duration::from_millis(due);
            let Err(AppError::Io(DatagramIoError::Io(error))) = step(&mut app, epoch, false) else {
                panic!("due progress send failure must propagate");
            };
            assert_eq!(error.kind(), expected.kind());
            assert_eq!(error.raw_os_error(), expected.raw_os_error());
            assert_eq!(
                app.transport().state.stage,
                if saturated { staged } else { Stage::Empty }
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
        let mut app = fixture(transport());
        let peer = Endpoint::v4([127, 0, 0, 1], 9);
        app.transport_mut().stage_result(Ok((1473, peer.into())));
        let previous = app.transport().state.stage;
        let held: [_; 4] = std::array::from_fn(|_| {
            let slot = app.engine_mut().acquire_rx().unwrap();
            app.engine_mut()
                .write_rx(slot, &[0x40, 0, 0, 9], peer)
                .unwrap();
            slot
        });
        assert!(matches!(
            step(&mut app, Instant::now(), false),
            Err(AppError::Saturated)
        ));
        assert_eq!(app.transport().state.stage, previous);
        for slot in held {
            if app.engine_mut().access_rx(slot).is_ok() {
                app.engine_mut().release_rx(slot).unwrap();
            }
        }
        assert!(step(&mut app, Instant::now(), false).unwrap().is_some());
        assert_eq!(app.transport().state.stage, Stage::Empty);
        // poll_engine may return a progress send error before its saved recv error.
        // Exercise the production send seam in both pre/post-receive states.
        for consumed in [false, true] {
            for kind in [io::ErrorKind::InvalidData, io::ErrorKind::ConnectionReset] {
                let io = app.transport_mut();
                io.stage_result(Ok((1473, peer.into())));
                let previous = io.begin_poll(1472);
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
                assert_eq!(
                    io.state.stage,
                    if consumed { Stage::Empty } else { previous }
                );
                io.state.stage = Stage::Empty;
            }
        }
    }

    fn transport() -> StagedUdp {
        StagedUdp::new(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            Some(Instant::now() + Duration::from_secs(1)),
        )
        .unwrap()
    }

    fn fixture(io: StagedUdp) -> StagedApp {
        bind_fixture(io, 64, 1472, None).unwrap()
    }

    #[test]
    fn unbounded_lifetime_receives_without_an_invented_deadline() {
        let io = StagedUdp::new(UdpSocket::bind("127.0.0.1:0").unwrap(), None).unwrap();
        assert_eq!(io.state.until, None);
        assert_eq!(io.socket.read_timeout().unwrap(), Some(MAX_WAIT));
        assert_eq!(io.socket.write_timeout().unwrap(), Some(SEND_WAIT));
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.set_write_timeout(Some(SEND_WAIT)).unwrap();
        sender
            .send_to(&[0x40, 0, 0, 1], io.socket.local_addr().unwrap())
            .unwrap();
        let mut app = fixture(io);
        let epoch = Instant::now();
        let future = epoch + Duration::from_secs(2);
        let receipt = step_with_clock(&mut app, epoch, false, || future)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.wait, Wait::Receive);
        assert_eq!(receipt.poll_ms, 2000);
        assert_eq!(app.metrics().rx_accepted, 1);
        assert_eq!(app.transport().state.stage, Stage::Empty);
    }

    #[test]
    fn startup_ledger_is_one_bounded_flushed_line() {
        if cfg!(all(target_os = "windows", target_pointer_width = "64")) {
            assert_eq!(mem::size_of::<Stage>(), 32);
            assert_eq!(mem::size_of::<State>(), 56);
        }
        #[derive(Default)]
        struct Output {
            bytes: Vec<u8>,
            flushes: usize,
        }
        impl io::Write for Output {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                assert!(self.bytes.len() + bytes.len() < 4096);
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
        assert_eq!(
            output.bytes.iter().filter(|byte| **byte == b'\n').count(),
            1
        );
        assert!(output.bytes.ends_with(b"}\n"));
        let line = String::from_utf8(output.bytes).unwrap();
        assert!(line.starts_with("{\"schema\":\"coaptic-native-blocking-resources/1\",\"server_kind\":\"coaptic-blocking\","));
        for (name, size) in [
            ("udp_scratch_bytes", 2049),
            ("staged_datagram_capacity", 1),
            ("stage_cache_metadata_bytes", mem::size_of::<State>()),
            ("adapter_inline_bytes", mem::size_of::<StagedUdp>()),
            ("app_including_adapter_bytes", mem::size_of::<StagedApp>()),
            ("read_timeout_max_us", 5000),
            ("send_timeout_us", 1000),
        ] {
            assert!(line.contains(&format!("\"{name}\":{size},")));
        }
        assert!(line.contains(
            "\"timeouts_soft\":true,\"runtime_heap_bytes\":null,\"runtime_stack_bytes\":null,"
        ));
        assert!(!line.contains("future"));
    }

    #[test]
    fn timeout_cache_close_deadline_and_finite_budget() {
        use std::cell::Cell;
        let mut io = transport();
        let calls = Cell::new(0);
        for _ in 0..8 {
            assert!(
                io.read_timeout_with(MAX_WAIT, |_, _| {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .unwrap()
            );
        }
        assert_eq!(calls.get(), 0);
        assert!(
            io.read_timeout_with(Duration::from_millis(2), |_, duration| {
                calls.set(calls.get() + 1);
                assert_eq!(duration, Duration::from_millis(2));
                Ok(())
            })
            .unwrap()
        );
        assert_eq!(calls.get(), 1);
        assert!(
            !io.read_timeout_with(Duration::ZERO, |_, _| panic!("zero timeout setter"))
                .unwrap()
        );
        assert_eq!(
            io.wait_until(Some(Instant::now()), MAX_WAIT).unwrap(),
            Wait::Ready
        );
        assert_eq!(
            io.wait_until(io.state.until, Duration::ZERO).unwrap(),
            Wait::Ready
        );
        assert_eq!(
            io.wait_until(io.state.until, Duration::from_nanos(1))
                .unwrap(),
            Wait::CloseDeadline
        );
        io.state.until = Some(Instant::now());
        assert_eq!(
            io.send(Endpoint::v4([127, 0, 0, 1], 9), b"no")
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        let mut app = fixture(io);
        assert!(step(&mut app, Instant::now(), false).unwrap().is_none());
        assert_eq!(app.metrics().progress, 0);
    }

    #[test]
    fn staged_guard_refuses_oversize_and_recovers_without_overwrite() {
        for capacity in [64, 1472, 2048] {
            let mut io = transport();
            let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
            sender.set_write_timeout(Some(SEND_WAIT)).unwrap();
            let peer: Endpoint = sender.local_addr().unwrap().into();
            let local = io.socket.local_addr().unwrap();
            let mut output = [0xa5; 2049];
            let payload = [0x39; 2056];
            for size in [capacity, capacity + 1, capacity + 8, 3] {
                sender.send_to(&payload[..size], local).unwrap();
                assert_eq!(
                    io.wait_until(io.state.until, MAX_WAIT).unwrap(),
                    Wait::Receive
                );
                let staged = io.state.stage;
                assert_ne!(staged, Stage::Empty);
                assert_eq!(
                    io.wait_until(io.state.until, MAX_WAIT).unwrap(),
                    Wait::Ready
                );
                assert_eq!(io.state.stage, staged);
                output.fill(0xa5);
                assert_eq!(
                    io.recv(&mut output).unwrap_err().kind(),
                    io::ErrorKind::InvalidInput
                );
                assert_eq!(io.state.stage, staged);
                assert!(output.iter().all(|byte| *byte == 0xa5));
                let result = io.recv(&mut output[..capacity]);
                if size <= capacity {
                    assert_eq!(result.unwrap(), Some((size, peer)));
                    assert_eq!(&output[..size], &payload[..size]);
                } else {
                    assert!(result.is_err()); // Windows may reject oversize at the socket.
                    assert!(output.iter().all(|byte| *byte == 0xa5));
                }
                assert_eq!(io.state.stage, Stage::Empty);
            }
        }
    }

    #[test]
    fn rx_saturation_preserves_stage_and_slot_ownership() {
        let mut io = transport();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(&[0x40, 0, 0, 7], io.socket.local_addr().unwrap())
            .unwrap();
        io.wait_until(io.state.until, MAX_WAIT).unwrap();
        let expected = io.state.stage;
        let mut engine = coaptic::storage::EngineBuilder::new()
            .profile::<coaptic::profiles::Default>()
            .block_wise(false)
            .build(coaptic::storage::Memory::<coaptic::profiles::Default>::new())
            .unwrap();
        let held: [_; 4] = std::array::from_fn(|_| engine.acquire_rx().unwrap());
        assert!(matches!(
            engine.recv_from(&mut io),
            Err(DatagramIoError::Saturated)
        ));
        assert_eq!(io.state.stage, expected);
        for slot in held {
            engine.release_rx(slot).unwrap();
        }
        let rx = engine.recv_from(&mut io).unwrap().unwrap();
        assert_eq!(io.state.stage, Stage::Empty);
        assert_eq!(engine.access_rx(rx).unwrap().as_bytes(), &[0x40, 0, 0, 7]);
        engine.release_rx(rx).unwrap();
        assert_eq!(engine.metrics().rx_accepted, 1);
        assert_eq!(engine.rx_occupied(), 0);
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
    fn retained_local_and_due_work_precede_socket_receive() {
        let io = transport();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let peer: Endpoint = sender.local_addr().unwrap().into();
        let local = io.socket.local_addr().unwrap();
        let mut app = fixture(io);
        sender.send_to(&[0x40, 0, 0, 1], local).unwrap();
        let epoch = Instant::now();
        assert_eq!(
            step(&mut app, epoch, true).unwrap().unwrap().wait,
            Wait::Ready
        );
        assert_eq!(app.metrics().rx_accepted, 0);
        let slot = app.engine_mut().acquire_rx().unwrap();
        app.engine_mut()
            .write_rx(slot, &[0x40, 0, 0, 2], peer)
            .unwrap();
        assert_eq!(
            step(&mut app, epoch, false).unwrap().unwrap().wait,
            Wait::Ready
        );
        assert_eq!(app.metrics().rx_accepted, 0);
        let due = pending(&mut app, peer);
        let epoch = Instant::now() - Duration::from_millis(due);
        assert_eq!(
            step(&mut app, epoch, false).unwrap().unwrap().wait,
            Wait::Ready
        );
        assert_eq!(app.metrics().rx_accepted, 0);
        assert_eq!(app.metrics().con_retransmit, 1);
        step(&mut app, epoch, false).unwrap().unwrap();
        assert_eq!(app.metrics().rx_accepted, 1);
    }

    #[test]
    fn post_wait_clock_and_receive_error_advance_deadlines() {
        let mut app = fixture(transport());
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let epoch = Instant::now();
        let call = app
            .get("unused")
            .deadline(10)
            .to(peer.local_addr().unwrap().into())
            .send(0)
            .unwrap();
        let mut times = [epoch, epoch + Duration::from_millis(17)].into_iter();
        let receipt = step_with_clock(&mut app, epoch, false, || times.next().unwrap())
            .unwrap()
            .unwrap();
        assert_ne!(receipt.wait, Wait::Ready);
        assert_eq!(receipt.poll_ms, 17);
        assert!(matches!(
            app.take_response(call),
            Some(Err(coaptic::CallFailure::DeadlineExceeded))
        ));

        let due = pending(&mut app, peer.local_addr().unwrap().into());
        app.transport_mut()
            .stage_result(Err(io::ErrorKind::ConnectionReset.into()));
        let epoch = Instant::now() - Duration::from_millis(due);
        assert!(
            matches!(step(&mut app, epoch, false), Err(AppError::Io(DatagramIoError::Io(error))) if error.kind() == io::ErrorKind::ConnectionReset)
        );
        assert_eq!(app.metrics().con_retransmit, 1);
        assert!(app.next_timeout().unwrap() > due);

        let mut backwards = [epoch + Duration::from_millis(due), epoch].into_iter();
        assert!(step_with_clock(&mut app, epoch, true, || backwards.next().unwrap()).is_err());
    }

    #[test]
    fn send_refusal_and_short_send_preserve_encoded_tx_and_pins() {
        use coaptic::{
            Code,
            message::{Message, MessageId, Opt, Token, Type},
        };
        struct Refuse(StagedUdp, bool);
        impl DatagramTransport for Refuse {
            type Error = io::Error;
        }
        impl DatagramIo for Refuse {
            fn recv(&mut self, bytes: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
                self.0.recv(bytes)
            }
            fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> io::Result<usize> {
                self.0.send_with(peer, bytes, |_, bytes, _| {
                    if self.1 {
                        Ok(bytes.len() - 1)
                    } else {
                        Err(io::ErrorKind::WouldBlock.into())
                    }
                })
            }
        }
        for protected in [false, true] {
            let token = Token::new(&[1]).unwrap();
            let options = [Opt::uri_path("bench")];
            let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(11))
                .with_token(token)
                .with_options(&options);
            let mut wire = [0; 1472];
            let n = if protected {
                context(false).protect_request(&request, &mut wire).unwrap()
            } else {
                coaptic::message::encode(&request, &mut wire).unwrap()
            };
            let mut app = fixture(transport());
            let peer = Endpoint::v4([127, 0, 0, 1], 9);
            let tx = app.engine_mut().acquire_tx().unwrap();
            app.engine_mut().write_tx(tx, &wire[..n], peer).unwrap();
            app.engine_mut()
                .record_pending_con(tx, peer, MessageId::new(11), 0, 0)
                .unwrap();
            let before = app.engine_mut().pending_con(tx);
            let mut refused = Refuse(transport(), false);
            for short in [false, true] {
                refused.1 = short;
                assert!(app.engine_mut().send_tx(&mut refused, tx).is_err());
                assert_eq!(
                    app.engine_mut().access_tx(tx).unwrap().as_bytes(),
                    &wire[..n]
                );
                assert!(!app.engine_mut().tx_is_pinned(tx));
                assert_eq!(app.engine_mut().pending_con(tx), before);
            }
            assert_eq!(app.metrics().tx_fail, 2);
        }
    }

    pub(crate) fn context(server: bool) -> SecurityContext {
        SecurityContext::derive(coaptic::oscore::DeriveParams {
            master_secret: &[1; 16],
            master_salt: &[2; 8],
            sender_id: if server { &[1] } else { &[] },
            recipient_id: if server { &[] } else { &[1] },
            id_context: &[],
        })
        .unwrap()
    }

    struct ClientIo {
        io: coaptic::storage::UdpSocketIo<[u8; 1473]>,
        protected: bool,
        iv: [u8; 13],
        nonces: [[u8; 13]; 4],
        requests: [Option<coaptic::message::Token>; 4],
        replies: [Option<coaptic::message::Token>; 4],
        sent: usize,
        received: usize,
    }
    impl DatagramTransport for ClientIo {
        type Error = io::Error;
    }
    impl DatagramIo for ClientIo {
        fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> io::Result<usize> {
            use coaptic::{
                message::{OptionNumber, Type},
                oscore::OscoreHeader,
            };
            let packet = coaptic::message::decode(bytes).unwrap();
            assert_eq!(packet.ty(), Type::Confirmable);
            assert!(self.sent < 4);
            if self.protected {
                let option = packet
                    .options()
                    .find(|o| o.number() == OptionNumber::OSCORE)
                    .unwrap();
                let header = OscoreHeader::parse(option.value()).unwrap();
                assert_eq!(header.kid, Some(&[][..]));
                let piv = header.piv.unwrap();
                assert_eq!(piv.seq(), self.sent as u64);
                // This fixture has the empty sender ID. RFC8613 section5.2 then
                // leaves only the padded wire PIV to XOR with its fixed Common IV.
                let mut nonce = self.iv;
                let offset = nonce.len() - piv.as_bytes().len();
                for (byte, piv) in nonce[offset..].iter_mut().zip(piv.as_bytes()) {
                    *byte ^= piv;
                }
                assert!(!self.nonces[..self.sent].contains(&nonce));
                self.nonces[self.sent] = nonce;
            }
            let n = self.io.send(peer, bytes)?;
            assert_eq!(n, bytes.len());
            self.requests[self.sent] = Some(packet.token());
            self.sent += 1;
            Ok(n)
        }
        fn recv(&mut self, bytes: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
            let result = self.io.recv(bytes)?;
            if let Some((n, _)) = result {
                use coaptic::message::OptionNumber;
                let packet = coaptic::message::decode(&bytes[..n]).unwrap();
                let option = packet
                    .options()
                    .find(|o| o.number() == OptionNumber::OSCORE);
                assert_eq!(option.is_some(), self.protected);
                if let Some(option) = option {
                    // A single piggybacked response uses its request nonce, with
                    // the distinct server sender key; do not demand a fresh PIV.
                    assert!(
                        coaptic::oscore::OscoreHeader::parse(option.value())
                            .unwrap()
                            .piv
                            .is_none()
                    );
                }
                assert!(self.received < 4);
                self.replies[self.received] = Some(packet.token());
                self.received += 1;
            }
            Ok(result)
        }
    }

    // Reuse the same authenticated four-operation client proof for both drivers.
    // The caller supplies the real driver step, not a second benchmark runner.
    pub(crate) fn verify_four<T: DatagramIo<Error = io::Error>>(
        mut server: App<coaptic::profiles::Default, T, 1, true, AllocMemory>,
        peer: Endpoint,
        epoch: Instant,
        until: Instant,
        protected: bool,
        mut drive: impl FnMut(&mut App<coaptic::profiles::Default, T, 1, true, AllocMemory>),
    ) -> (
        App<coaptic::profiles::Default, T, 1, true, AllocMemory>,
        [u32; 4],
    ) {
        use coaptic::{Code, ContentFormat};
        let before = server.metrics();
        const PAYLOAD: [u8; 64] = {
            let mut bytes = [0; 64];
            let mut i = 0;
            while i < bytes.len() {
                bytes[i] = i as u8;
                i += 1;
            }
            bytes
        };
        assert_eq!(*super::super::BODY.get_or_init(|| &PAYLOAD), &PAYLOAD);
        assert!(mem::size_of::<State>() <= 64);
        let client_context = context(false);
        assert_ne!(client_context.sender_key(), context(true).sender_key());
        let iv = *client_context.common_iv();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let io = ClientIo {
            io: coaptic::storage::UdpSocketIo::new(socket, [0; 1473]).unwrap(),
            protected,
            iv,
            nonces: [[0; 13]; 4],
            requests: [None; 4],
            replies: [None; 4],
            sent: 0,
            received: 0,
        };
        let mut client = bind_fixture(io, 64, 1472, protected.then_some(client_context)).unwrap();
        let mut turns = 0u8;
        for index in 0..4 {
            assert!(Instant::now() < until);
            let call = client
                .get("bench")
                .to(peer)
                .send(epoch.elapsed().as_millis() as u64)
                .unwrap();
            loop {
                assert!(turns < 64 && Instant::now() < until, "finite proof budget");
                turns += 1;
                drive(&mut server);
                client.poll(epoch.elapsed().as_millis() as u64).unwrap();
                if let Some(response) = client.take_response(call) {
                    let response = response.unwrap(); // includes OSCORE opening/authentication.
                    assert_eq!(response.code(), Code::CONTENT);
                    assert_eq!(response.format(), Some(ContentFormat::OCTET_STREAM));
                    assert_eq!(response.etag_bytes(), Some(&b"fixture"[..]));
                    assert!(!response.payload_truncated());
                    assert_eq!(response.payload(), &PAYLOAD);
                    assert_eq!(client.transport().requests[index], Some(call.token()));
                    assert_eq!(client.transport().replies[index], Some(call.token()));
                    break;
                }
            }
        }
        assert!(Instant::now() < until);
        assert_eq!(client.transport().sent, 4);
        assert_eq!(client.transport().received, 4);
        let metrics = server.metrics();
        assert_eq!(
            (
                metrics.rx_accepted,
                metrics.tx_ok,
                metrics.rx_error,
                metrics.tx_fail
            ),
            (
                before.rx_accepted + 4,
                before.tx_ok + 4,
                before.rx_error,
                before.tx_fail
            )
        );
        assert_eq!(server.engine_mut().rx_occupied(), 0);
        (
            server,
            [
                metrics.rx_accepted,
                metrics.tx_ok,
                metrics.progress,
                u32::from(turns),
            ],
        )
    }

    #[test]
    fn finite_ready_udp_call_counts() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for protected in [false, true] {
            let epoch = Instant::now();
            let until = epoch + Duration::from_secs(1);
            let io = runtime.block_on(async {
                super::super::ReadyUdp {
                    socket: tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                    scratch: [0; SCRATCH_BYTES],
                    received: false,
                    counts: Some(TransportCounts::default()),
                }
            });
            let peer = io.socket.local_addr().unwrap().into();
            let server = bind_fixture(io, 64, 1472, protected.then(|| context(true))).unwrap();
            let mut idle = false;
            let (server, result) = verify_four(server, peer, epoch, until, protected, |server| {
                runtime.block_on(async {
                    if idle {
                        tokio::time::timeout_at(
                            until.into(),
                            super::super::ready_wait(server, epoch),
                        )
                        .await
                        .expect("finite readiness budget")
                        .unwrap();
                    }
                    idle = super::super::ready_burst(server, epoch).unwrap();
                    if !idle {
                        tokio::task::yield_now().await;
                    }
                });
            });
            let counts = server.transport().counts.unwrap();
            assert_eq!(counts.socket_send_calls, 4);
            assert_eq!(counts.recv_calls, counts.socket_recv_calls);
            assert_eq!(counts.recv_calls, counts.app_polls);
            assert_eq!(counts.recv_calls - counts.recv_empty, 4);
            assert!(counts.app_polls <= 64 * 32);
            assert!(counts.readable_waits <= result[3]);
            assert_eq!(counts.read_timeout_sets, 0);
            print_counts("ready", protected, result, counts);
        }
    }

    fn print_counts(driver: &str, protected: bool, result: [u32; 4], counts: TransportCounts) {
        assert!(mem::size_of::<Option<TransportCounts>>() <= 32);
        let receipt = format!(
            "{{\"schema\":\"native-transport-calls/1\",\"driver\":\"{driver}\",\"protected\":{protected},\"verified\":4,\"warmup\":0,\"rx_tx_progress_turns\":{result:?},\"app_polls\":{},\"recv_calls\":{},\"recv_empty\":{},\"socket_recv_calls\":{},\"socket_send_calls\":{},\"readable_waits\":{},\"read_timeout_sets\":{},\"counter_option_bytes\":{},\"limits\":\"test-only opt-in saturating u32; setup excluded; 64 turns, 32 polls/ready burst, 1s checked wall budget with soft OS timeouts; logical calls, not syscalls/wakeups/time/cause/gain; Tokio cached readiness may skip recv syscall\"}}",
            counts.app_polls,
            counts.recv_calls,
            counts.recv_empty,
            counts.socket_recv_calls,
            counts.socket_send_calls,
            counts.readable_waits,
            counts.read_timeout_sets,
            mem::size_of::<Option<TransportCounts>>()
        );
        assert!(receipt.len() <= 2048);
        println!("{receipt}");
    }

    #[test]
    fn finite_staged_idle_call_counts() {
        let mut io = transport();
        io.counts = Some(TransportCounts::default());
        let mut app = fixture(io);
        let epoch = Instant::now();
        for _ in 0..2 {
            assert_eq!(
                step(&mut app, epoch, false).unwrap().unwrap().wait,
                Wait::Receive
            );
        }
        let counts = app.transport().counts.unwrap();
        assert_eq!(
            counts,
            TransportCounts {
                app_polls: 2,
                recv_calls: 2,
                recv_empty: 2,
                socket_recv_calls: 2,
                ..TransportCounts::default()
            }
        );
        assert_eq!(app.metrics().rx_accepted, 0);
        println!("staged idle, two finite turns, setup excluded, logical calls: {counts:?}");
    }

    #[test]
    fn finite_verified_udp_proof_and_storage_receipt() {
        let mut results = [[0u32; 4]; 2];
        for (mode, protected) in [false, true].into_iter().enumerate() {
            let epoch = Instant::now();
            let until = epoch + Duration::from_secs(1);
            let mut io =
                StagedUdp::new(UdpSocket::bind("127.0.0.1:0").unwrap(), Some(until)).unwrap();
            assert!(io.counts.is_none());
            io.counts = Some(TransportCounts::default()); // Excludes socket setup.
            let peer = io.socket.local_addr().unwrap().into();
            let server = bind_fixture(io, 64, 1472, protected.then(|| context(true))).unwrap();
            let (server, result) = verify_four(server, peer, epoch, until, protected, |server| {
                step(server, epoch, false)
                    .unwrap()
                    .expect("finite server stopped");
            });
            let counts = server.transport().counts.unwrap();
            assert_eq!(counts.socket_send_calls, 4);
            assert_eq!(counts.app_polls, result[3]);
            assert!(counts.app_polls <= 64);
            assert_eq!(counts.recv_calls, counts.app_polls);
            assert_eq!(counts.recv_calls - counts.recv_empty, 4);
            assert!(counts.socket_recv_calls <= counts.app_polls);
            assert_eq!(counts.readable_waits, 0);
            print_counts("staged", protected, result, counts);
            results[mode] = result;
        }
        let receipt = format!(
            "{{\"schema\":\"staged-udp-finite-proof/1\",\"verified_per_mode\":4,\"warmup\":0,\"unprotected\":{:?},\"oscore\":{:?},\"stage_bytes\":{},\"stage_cache_budget_bytes\":{},\"adapter_including_scratch_state_bytes\":{},\"app_including_adapter_bytes\":{},\"scratch_bytes\":2049,\"send_timeout_us\":1000,\"limits\":\"Test-build layout includes the counter option; nested owners do not sum; soft socket timeouts, sync entry-time commits; no CPU/peak-stack/whole-RAM claim\"}}",
            results[0],
            results[1],
            mem::size_of::<Stage>(),
            mem::size_of::<State>(),
            mem::size_of::<StagedUdp>(),
            mem::size_of::<StagedApp>()
        );
        assert!(receipt.len() <= 2048);
        println!("{receipt}");
    }
}
