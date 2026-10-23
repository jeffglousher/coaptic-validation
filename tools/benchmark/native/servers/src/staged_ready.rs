//! Finite TEST-ONLY nonblocking receive staging; there is no server selector.
//!
//! ReadyUdp owns the sole socket and 2049-byte scratch. Stage owns one extra
//! datagram beyond Engine RX, even though its payload reuses that scratch.
//! Never probe an occupied stage or call inner ReadyUdp.recv: either overwrites
//! live ingress. Destination validation precedes taking the stage; RX refusal
//! therefore preserves it. Only an actual Tokio WouldBlock means no staged item;
//! zero bytes is a packet and every other receive error belongs to ordinary App
//! polling, including its maintenance and competing send-error precedence.
//!
//! Probe exactly configured N+1 bytes (N <= 2048), persist before any await,
//! and poll with fresh time. Local/due work precedes probing and is rechecked
//! after readiness: timeout_at polls readability before its timer. Readiness,
//! successful receive and ReadyUdp.received never prove the queue empty. No
//! fabricated WouldBlock, manual readiness clearing, nested drain or retry.
//! Send delegates unchanged to synchronous ReadyUdp.send/try_send_to: immediate
//! refusal and short sends, no writable wait, retry or socket timeout.
//!
//! Every work turn, including an empty probe/immediate wait, counts toward a
//! yield after 32 turns and a finite 64-turn/checked one-second proof budget.
//! Cancellation of the borrowed driver cannot consume during readiness waits;
//! any received item already belongs to the adapter. Saturation is surfaced,
//! never a successful busy loop. This static fixture has no external signals;
//! new signals, pin releases and policy changes still require separate wakes
//! under App::next_poll_at's contract. Sizes here describe nested test objects,
//! not production RAM, whole-system memory or peak stack. No CPU gain is claimed.

use super::{AllocMemory, App, DatagramIo, Endpoint, ReadyUdp, TransportCounts, bind_fixture};
use coaptic::storage::{DatagramIoError, DatagramTransport};
use std::{
    io, mem,
    net::SocketAddr,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Empty,
    Packet {
        len: u16,
        peer: Endpoint,
    },
    Error {
        raw: Option<i32>,
        kind: io::ErrorKind,
    },
}

struct StagedReady {
    inner: ReadyUdp,
    stage: Stage,
}

type StagedApp = App<coaptic::profiles::Default, StagedReady, 1, true, AllocMemory>;
type AppError = coaptic::app::Error<io::Error>;

fn app_io(error: io::Error) -> AppError {
    AppError::Io(DatagramIoError::Io(error))
}

impl StagedReady {
    // This seam also exercises native error preservation without OS fault injection.
    fn stage_result(&mut self, result: io::Result<(usize, SocketAddr)>) {
        assert_eq!(self.stage, Stage::Empty);
        self.stage = match result {
            Ok((len, peer)) if len <= self.inner.scratch.len() => Stage::Packet {
                len: u16::try_from(len).expect("bounded scratch"),
                peer: Endpoint::from(peer).physical(),
            },
            Ok(_) => Stage::Error {
                raw: None,
                kind: io::ErrorKind::InvalidData,
            },
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
        let scratch = super::guarded_scratch(capacity, &mut self.inner.scratch)?;
        let result = self.inner.socket.try_recv_from(scratch);
        // Classify against the probed N, even if a later caller supplies more room.
        let result = result.and_then(|packet| {
            if packet.0 > capacity {
                Err(io::ErrorKind::InvalidData.into())
            } else {
                Ok(packet)
            }
        });
        // There is no suspension between consuming the socket and owning its result.
        self.stage_result(result);
        Ok(())
    }
}

impl DatagramTransport for StagedReady {
    type Error = io::Error;
}

impl DatagramIo for StagedReady {
    fn recv(&mut self, output: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
        if let Some(counts) = &mut self.inner.counts {
            TransportCounts::inc(&mut counts.recv_calls);
        }
        super::guarded_scratch(output.len(), &mut self.inner.scratch)?;
        if matches!(self.stage, Stage::Packet { len, .. } if usize::from(len) > output.len()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Invalid destinations retain legitimate packets. Oversize probe errors
        // are consumed normally, so the next valid datagram can recover.
        let result = match mem::replace(&mut self.stage, Stage::Empty) {
            Stage::Empty => {
                if let Some(counts) = &mut self.inner.counts {
                    TransportCounts::inc(&mut counts.recv_empty);
                }
                Ok(None)
            }
            Stage::Packet { len, peer } => {
                super::finish_receive(output, &self.inner.scratch, (usize::from(len), peer.into()))
                    .map(Some)
            }
            Stage::Error { raw, kind } => {
                Err(raw.map_or_else(|| kind.into(), io::Error::from_raw_os_error))
            }
        };
        self.inner.received = result.as_ref().is_ok_and(Option::is_some);
        result
    }

    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> io::Result<usize> {
        DatagramIo::send(&mut self.inner, peer, bytes)
    }
}

#[derive(Debug, Default)]
struct Counts {
    turns: u32,
    probes: u32,
    empty: u32,
    waits: u32,
    yields: u32,
}

struct Driver {
    epoch: Instant,
    until: Instant,
    counts: Counts,
}

#[derive(Debug, PartialEq, Eq)]
enum Turn {
    Stop,
    Idle,
    Polled(u64),
}

impl Driver {
    fn new(app: &mut StagedApp, epoch: Instant, until: Instant) -> io::Result<Self> {
        let capacity = app.engine_mut().capacities().rx_datagram_bytes;
        super::guarded_scratch(capacity, &mut app.transport_mut().inner.scratch)?;
        Ok(Self {
            epoch,
            until,
            counts: Counts::default(),
        })
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
        Ok((time < self.until).then_some(millis))
    }

    fn work_ready(app: &mut StagedApp, now: u64, local: bool) -> bool {
        app.transport().stage != Stage::Empty
            || local
            || app.next_poll_at(now).is_some_and(|due| due <= now)
    }

    fn poll(
        &self,
        app: &mut StagedApp,
        time: Instant,
        previous: Instant,
    ) -> Result<Turn, AppError> {
        let Some(now) = self.sample(time, previous)? else {
            return Ok(Turn::Stop);
        };
        if let Some(counts) = &mut app.transport_mut().inner.counts {
            TransportCounts::inc(&mut counts.app_polls);
        }
        match app.poll(now) {
            Ok(()) | Err(AppError::Oscore(_)) => Ok(Turn::Polled(now)),
            Err(error) => Err(error),
        }
    }

    async fn turn(&mut self, app: &mut StagedApp) -> Result<Turn, AppError> {
        self.turn_with(
            app,
            |_| false,
            Instant::now,
            async |socket, deadline| match tokio::time::timeout_at(
                deadline.into(),
                socket.readable(),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Ok(()),
            },
        )
        .await
    }

    // Small clock/local/wait seams exercise races without altering Tokio readiness.
    async fn turn_with(
        &mut self,
        app: &mut StagedApp,
        mut local: impl FnMut(&mut StagedApp) -> bool,
        mut clock: impl FnMut() -> Instant,
        mut wait: impl AsyncFnMut(&tokio::net::UdpSocket, Instant) -> io::Result<()>,
    ) -> Result<Turn, AppError> {
        if self.counts.turns >= 64 {
            return Ok(Turn::Stop);
        }
        self.counts.turns += 1;
        let result = async {
            let before = clock();
            let Some(now) = self.sample(before, self.epoch)? else {
                return Ok(Turn::Stop);
            };
            let local_ready = local(app);
            let ready = Self::work_ready(app, now, local_ready);
            if ready {
                return self.poll(app, clock(), before);
            }
            let capacity = app.engine_mut().capacities().rx_datagram_bytes;
            self.counts.probes += 1;
            app.transport_mut().probe(capacity).map_err(app_io)?;
            if app.transport().stage != Stage::Empty {
                return self.poll(app, clock(), before);
            }
            self.counts.empty += 1;
            let after = clock();
            let Some(now) = self.sample(after, before)? else {
                return Ok(Turn::Stop);
            };
            let local_ready = local(app);
            let ready = Self::work_ready(app, now, local_ready);
            if ready {
                return self.poll(app, clock(), after);
            }
            let deadline = app
                .next_poll_at(now)
                .map(|due| {
                    self.epoch
                        .checked_add(Duration::from_millis(due))
                        .ok_or_else(|| app_io(io::ErrorKind::InvalidInput.into()))
                })
                .transpose()?
                .map_or(self.until, |due| due.min(self.until));
            self.counts.waits += 1;
            wait(&app.transport().inner.socket, deadline)
                .await
                .map_err(app_io)?;
            let woke = clock();
            let Some(now) = self.sample(woke, after)? else {
                return Ok(Turn::Stop);
            };
            let local_ready = local(app);
            let ready = Self::work_ready(app, now, local_ready);
            if ready {
                self.poll(app, clock(), woke)
            } else {
                Ok(Turn::Idle)
            }
        }
        .await;
        if self.counts.turns.is_multiple_of(32) {
            self.counts.yields += 1;
            tokio::task::yield_now().await;
        }
        result
    }
}

async fn transport() -> StagedReady {
    StagedReady {
        inner: ReadyUdp {
            socket: tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            scratch: [0; 2049],
            received: false,
            counts: Some(TransportCounts::default()),
        },
        stage: Stage::Empty,
    }
}

fn fixture(io: StagedReady) -> StagedApp {
    bind_fixture(io, 64, 1472, None).unwrap()
}

async fn readable(io: &StagedReady) {
    tokio::time::timeout(Duration::from_millis(100), io.inner.socket.readable())
        .await
        .expect("finite readiness")
        .unwrap();
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
    use super::staged_udp::tests::{context, verify_four};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for protected in [false, true] {
        let epoch = Instant::now();
        let until = epoch + Duration::from_secs(1);
        let io = runtime.block_on(transport());
        let peer = io.inner.socket.local_addr().unwrap().into();
        let mut app = bind_fixture(io, 64, 1472, protected.then(|| context(true))).unwrap();
        let mut driver = Driver::new(&mut app, epoch, until).unwrap();
        let future = driver.turn(&mut app);
        let future_bytes = mem::size_of_val(&future);
        drop(future);
        let (app, result) = verify_four(app, peer, epoch, until, protected, |app| {
            assert_ne!(runtime.block_on(driver.turn(app)).unwrap(), Turn::Stop);
        });
        let counts = app.transport().inner.counts.unwrap();
        assert_eq!(
            (
                counts.app_polls,
                counts.recv_calls,
                counts.recv_empty,
                counts.socket_send_calls
            ),
            (4, 4, 0, 4)
        );
        assert_eq!(
            (
                counts.socket_recv_calls,
                counts.readable_waits,
                counts.read_timeout_sets
            ),
            (0, 0, 0)
        );
        assert!(driver.counts.probes >= 4 && driver.counts.turns <= 64);
        assert!(mem::size_of::<Stage>() <= 64);
        let added = mem::size_of::<StagedReady>() - mem::size_of::<ReadyUdp>();
        assert!(added <= 64);
        println!(
            "staged-ready protected={protected} verified=4 warmup=0 rx_tx_progress_client_turns={result:?} app_polls={} adapter_recv={} adapter_empty={} sends={} external_probes={} external_empty={} readable_waits={} work_turns={} yields={} stage_bytes={} added_adapter_bytes={added} adapter_bytes={} app_including_adapter_bytes={} borrowed_turn_future_bytes={future_bytes} driver_bytes={} driver_counter_bytes={} inner_counter_option_bytes={} staged_datagrams_beyond_engine_rx=1 send_waits=0; scratch inside ReadyUdp inside adapter inside App; future borrows App/Driver; driver includes its counters; inline test layouts only, not outer future/heap/runtime/stack/kernel/CPU",
            counts.app_polls,
            counts.recv_calls,
            counts.recv_empty,
            counts.socket_send_calls,
            driver.counts.probes,
            driver.counts.empty,
            driver.counts.waits,
            driver.counts.turns,
            driver.counts.yields,
            mem::size_of::<Stage>(),
            mem::size_of::<StagedReady>(),
            mem::size_of::<StagedApp>(),
            mem::size_of::<Driver>(),
            mem::size_of::<Counts>(),
            mem::size_of::<Option<TransportCounts>>()
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn guarded_packets_occupied_scratch_and_error_recovery() {
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer: Endpoint = sender.local_addr().unwrap().into();
    let payload = [0x39; 2056];
    let mut output = [0xa5; 2049];
    for capacity in [64, 1472, 2048] {
        let mut io = transport().await;
        let local = io.inner.socket.local_addr().unwrap();
        for size in [capacity, capacity + 1, capacity + 8, 0, 3] {
            sender.send_to(&payload[..size], local).unwrap();
            readable(&io).await;
            io.probe(capacity).unwrap();
            assert_ne!(io.stage, Stage::Empty);
            let staged = io.stage;
            sender.send_to(b"next", local).unwrap();
            let scratch = io.inner.scratch; // Test witness only, never adapter storage.
            io.probe(capacity).unwrap();
            assert_eq!(io.stage, staged);
            assert_eq!(io.inner.scratch, scratch);
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
                    assert_eq!(io.inner.scratch, scratch);
                }
                assert_eq!(
                    io.recv(&mut output[..capacity]).unwrap(),
                    Some((size, peer))
                );
                assert_eq!(&output[..size], &payload[..size]);
            } else {
                // A larger destination cannot turn the N+1 prefix into success.
                let larger = (capacity + 64).min(2048);
                assert!(io.recv(&mut output[..larger]).is_err());
                assert!(output.iter().all(|byte| *byte == 0xa5));
            }
            assert_eq!(io.stage, Stage::Empty);
            readable(&io).await;
            io.probe(capacity).unwrap();
            assert_eq!(io.recv(&mut output[..capacity]).unwrap(), Some((4, peer)));
            assert_eq!(&output[..4], b"next");
        }
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionReset,
        ] {
            io.stage_result(Err(kind.into()));
            assert_eq!(io.recv(&mut output[..capacity]).unwrap_err().kind(), kind);
            sender.send_to(b"valid", local).unwrap();
            readable(&io).await;
            io.probe(capacity).unwrap();
            assert_eq!(io.recv(&mut output[..capacity]).unwrap(), Some((5, peer)));
        }
        let raw = io::Error::from_raw_os_error(12345);
        io.stage_result(Err(raw));
        assert_eq!(
            io.recv(&mut output[..capacity]).unwrap_err().raw_os_error(),
            Some(12345)
        );
        io.stage_result(Err(io::ErrorKind::WouldBlock.into()));
        assert_eq!(io.stage, Stage::Empty);
    }
    // App already rejects this configuration; the driver independently validates
    // its supported guard before entering any turn.
    assert!(bind_fixture(transport().await, 64, 2049, None).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn rx_refusal_pins_release_and_stage_ownership() {
    let mut io = transport().await;
    io.inner.scratch[..4].copy_from_slice(&[0x40, 0, 0, 7]);
    let peer = Endpoint::v4([127, 0, 0, 1], 9);
    io.stage_result(Ok((4, peer.into())));
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
        io.probe(1472).unwrap();
        assert_eq!(access.as_bytes(), b"pinned");
    }
    assert!(!engine.rx_is_pinned(held[0]));
    let stage = io.stage;
    assert!(matches!(
        engine.recv_from(&mut io),
        Err(DatagramIoError::Saturated)
    ));
    assert_eq!(io.stage, stage);
    assert_eq!(io.inner.counts.unwrap().recv_calls, 0);
    for slot in held {
        engine.release_rx(slot).unwrap();
    }
    let rx = engine.recv_from(&mut io).unwrap().unwrap();
    assert_eq!(engine.access_rx(rx).unwrap().as_bytes(), &[0x40, 0, 0, 7]);
    assert_eq!(io.stage, Stage::Empty);
    engine.release_rx(rx).unwrap();

    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer: Endpoint = sender.local_addr().unwrap().into();
    io.inner.scratch[..4].copy_from_slice(&[0x40, 0, 0, 8]);
    io.stage_result(Ok((4, peer.into())));
    let mut app = fixture(io);
    // Setup only: an immediate send refusal would correctly outrank saturation.
    tokio::time::timeout(
        Duration::from_millis(100),
        app.transport().inner.socket.writable(),
    )
    .await
    .unwrap()
    .unwrap();
    let held: [_; 4] = std::array::from_fn(|_| {
        let slot = app.engine_mut().acquire_rx().unwrap();
        app.engine_mut()
            .write_rx(slot, &[0x40, 0, 0, 9], peer)
            .unwrap();
        slot
    });
    let epoch = Instant::now();
    let mut driver = Driver::new(&mut app, epoch, epoch + Duration::from_secs(1)).unwrap();
    let refused = driver.turn(&mut app).await;
    assert!(matches!(&refused, Err(AppError::Saturated)), "{refused:?}");
    assert_ne!(app.transport().stage, Stage::Empty);
    assert_eq!(driver.counts.probes, 0);
    for slot in held {
        if app.engine_mut().access_rx(slot).is_ok() {
            app.engine_mut().release_rx(slot).unwrap();
        }
    }
    driver.turn(&mut app).await.unwrap();
    assert_eq!(app.transport().stage, Stage::Empty);
}

#[tokio::test(flavor = "current_thread")]
async fn due_local_and_post_wait_time_precede_receive() {
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut app = fixture(transport().await);
    let local = app.transport().inner.socket.local_addr().unwrap();
    let peer = sender.local_addr().unwrap().into();
    let due = pending(&mut app, peer);
    let epoch = Instant::now();
    let mut driver =
        Driver::new(&mut app, epoch, epoch + Duration::from_millis(due + 1000)).unwrap();
    let mut times = [
        epoch,
        epoch,
        epoch + Duration::from_millis(due),
        epoch + Duration::from_millis(due + 1),
    ]
    .into_iter();
    let result = driver
        .turn_with(
            &mut app,
            |_| false,
            || times.next().unwrap(),
            async |socket, _| {
                sender.send_to(&[0x40, 0, 0, 1], local).unwrap();
                tokio::time::timeout(Duration::from_millis(100), socket.readable())
                    .await
                    .unwrap()
            },
        )
        .await
        .unwrap();
    assert_eq!(result, Turn::Polled(due + 1));
    assert_eq!(app.metrics().con_retransmit, 1);
    assert_eq!(app.metrics().rx_accepted, 0);
    assert_eq!((driver.counts.probes, driver.counts.empty), (1, 1));
    // Still-readable socket also loses to explicit local and retained RX work.
    driver
        .turn_with(
            &mut app,
            |_| true,
            || epoch + Duration::from_millis(due + 2),
            async |_, _| panic!("local work must not wait"),
        )
        .await
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
            async |_, _| panic!("retained work must not wait"),
        )
        .await
        .unwrap();
    assert_eq!(driver.counts.probes, 1);
    assert_eq!(app.metrics().rx_accepted, 0);
    driver
        .turn_with(
            &mut app,
            |_| false,
            || epoch + Duration::from_millis(due + 4),
            async |_, _| panic!("registered packet"),
        )
        .await
        .unwrap();
    assert_eq!(app.metrics().rx_accepted, 1);

    let mut app = fixture(transport().await);
    let mut driver = Driver::new(&mut app, epoch, epoch + Duration::from_secs(1)).unwrap();
    let signaled = std::cell::Cell::new(false);
    let mut times = [
        epoch,
        epoch,
        epoch + Duration::from_millis(17),
        epoch + Duration::from_millis(18),
    ]
    .into_iter();
    assert_eq!(
        driver
            .turn_with(
                &mut app,
                |_| signaled.get(),
                || times.next().unwrap(),
                async |_, _| {
                    signaled.set(true);
                    Ok(())
                }
            )
            .await
            .unwrap(),
        Turn::Polled(18)
    );
    assert_eq!(app.transport().inner.counts.unwrap().app_polls, 1);
    let mut backwards = [
        epoch + Duration::from_millis(6),
        epoch + Duration::from_millis(5),
    ]
    .into_iter();
    assert!(
        driver
            .turn_with(
                &mut app,
                |_| true,
                || backwards.next().unwrap(),
                async |_, _| Ok(())
            )
            .await
            .is_err()
    );
    assert_eq!(app.transport().inner.counts.unwrap().app_polls, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn staged_error_progress_deadline_and_send_error_precedence() {
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = sender.local_addr().unwrap().into();
    let mut app = fixture(transport().await);
    // Prime setup readiness before creating the outbound Call; the driver and
    // adapter still perform no send waits or retries.
    tokio::time::timeout(
        Duration::from_millis(100),
        app.transport().inner.socket.writable(),
    )
    .await
    .unwrap()
    .unwrap();
    let call = app.get("unused").deadline(10).to(peer).send(0).unwrap();
    app.transport_mut()
        .stage_result(Err(io::ErrorKind::TimedOut.into()));
    let epoch = Instant::now();
    let mut driver = Driver::new(&mut app, epoch, epoch + Duration::from_secs(1)).unwrap();
    let mut times = [epoch, epoch + Duration::from_millis(17)].into_iter();
    assert!(
        matches!(driver.turn_with(&mut app, |_| false, || times.next().unwrap(), async |_, _| Ok(())).await,
        Err(AppError::Io(DatagramIoError::Io(error))) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert!(matches!(
        app.take_response(call),
        Some(Err(coaptic::CallFailure::DeadlineExceeded))
    ));
    assert_eq!(app.transport().stage, Stage::Empty);
    let due = pending(&mut app, peer);
    app.transport_mut()
        .stage_result(Err(io::ErrorKind::ConnectionReset.into()));
    let mut driver =
        Driver::new(&mut app, epoch, epoch + Duration::from_millis(due + 100)).unwrap();
    assert!(
        matches!(driver.turn_with(&mut app, |_| false, || epoch + Duration::from_millis(due), async |_, _| Ok(())).await,
        Err(AppError::Io(DatagramIoError::Io(error))) if error.kind() == io::ErrorKind::ConnectionReset)
    );
    assert_eq!(app.metrics().con_retransmit, 1);
    assert_eq!(app.transport().stage, Stage::Empty);

    struct Refuse(StagedReady);
    impl DatagramTransport for Refuse {
        type Error = io::Error;
    }
    impl DatagramIo for Refuse {
        fn recv(&mut self, output: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
            self.0.recv(output)
        }
        fn send(&mut self, _: Endpoint, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
    let mut app = bind_fixture(Refuse(transport().await), 64, 1472, None).unwrap();
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
    assert_eq!(app.transport().0.stage, Stage::Empty); // Consumed RX error is never reinserted.
    assert_eq!(app.metrics().rx_error, 1);
    assert_eq!(app.metrics().tx_fail, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn retained_exact_tx_after_refusal_or_short_send() {
    use coaptic::{
        Code,
        message::{Message, MessageId, Opt, Token, Type},
    };
    struct Refuse(StagedReady, bool);
    impl DatagramTransport for Refuse {
        type Error = io::Error;
    }
    impl DatagramIo for Refuse {
        fn recv(&mut self, bytes: &mut [u8]) -> io::Result<Option<(usize, Endpoint)>> {
            self.0.recv(bytes)
        }
        fn send(&mut self, _: Endpoint, bytes: &[u8]) -> io::Result<usize> {
            if self.1 {
                Ok(bytes.len() - 1)
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
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
            super::staged_udp::tests::context(false)
                .protect_request(&request, &mut wire)
                .unwrap()
        } else {
            coaptic::message::encode(&request, &mut wire).unwrap()
        };
        let mut app = fixture(transport().await);
        let tx = app.engine_mut().acquire_tx().unwrap();
        app.engine_mut().write_tx(tx, &wire[..n], peer).unwrap();
        app.engine_mut()
            .record_pending_con(tx, peer, MessageId::new(11), 0, 0)
            .unwrap();
        let before = app.engine_mut().pending_con(tx);
        let mut io = Refuse(transport().await, false);
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
        }
        assert_eq!(app.metrics().tx_fail, 2);
        // Actual send delegation leaves occupied receive scratch untouched.
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        io.0.inner.scratch[..3].copy_from_slice(b"rx!");
        io.0.stage_result(Ok((3, peer.into())));
        tokio::time::timeout(Duration::from_millis(100), io.0.inner.socket.writable())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            io.0.send(receiver.local_addr().unwrap().into(), &wire[..n])
                .unwrap(),
            n
        );
        assert_eq!(&io.0.inner.scratch[..3], b"rx!");
        assert_ne!(io.0.stage, Stage::Empty);
        assert_eq!(io.0.inner.counts.unwrap().socket_send_calls, 1);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_and_expired_budget_preserve_ingress() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let mut app = fixture(transport().await);
    let epoch = Instant::now();
    let mut driver = Driver::new(&mut app, epoch, epoch + Duration::from_secs(1)).unwrap();
    {
        let mut waiting = std::pin::pin!(driver.turn(&mut app));
        assert!(matches!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
    }
    assert_eq!(app.transport().stage, Stage::Empty);
    assert_eq!(app.transport().inner.counts.unwrap().app_polls, 0);
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(
            &[0x40, 0, 0, 7],
            app.transport().inner.socket.local_addr().unwrap(),
        )
        .unwrap();
    readable(app.transport()).await;
    let mut times = [epoch, epoch + Duration::from_secs(1)].into_iter();
    assert_eq!(
        driver
            .turn_with(
                &mut app,
                |_| false,
                || times.next().unwrap(),
                async |_, _| Ok(())
            )
            .await
            .unwrap(),
        Turn::Stop
    );
    let stage = app.transport().stage;
    assert_ne!(stage, Stage::Empty); // Received before finite stop, retained without poll.
    drop(driver.turn(&mut app));
    assert_eq!(app.transport().stage, stage);
    assert_eq!(app.transport().inner.counts.unwrap().recv_calls, 0);
    let mut output = [0; 1472];
    assert_eq!(app.transport_mut().recv(&mut output).unwrap().unwrap().0, 4);
}

#[tokio::test(flavor = "current_thread")]
async fn transport_only_false_readiness_yields_at_32_total_turns() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let mut app = fixture(transport().await);
    let epoch = Instant::now();
    let mut driver = Driver::new(&mut app, epoch, epoch + Duration::from_secs(1)).unwrap();
    {
        let mut run = std::pin::pin!(async {
            for _ in 0..64 {
                assert_eq!(
                    driver
                        .turn_with(&mut app, |_| false, || epoch, async |_, _| Ok(()))
                        .await
                        .unwrap(),
                    Turn::Idle
                );
            }
        });
        assert!(matches!(
            run.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
    }
    assert_eq!(
        (
            driver.counts.turns,
            driver.counts.probes,
            driver.counts.empty,
            driver.counts.waits,
            driver.counts.yields
        ),
        (32, 32, 32, 32, 1)
    );
    assert_eq!(app.transport().inner.counts.unwrap().app_polls, 0);
    for _ in 0..32 {
        driver
            .turn_with(&mut app, |_| false, || epoch, async |_, _| Ok(()))
            .await
            .unwrap();
    }
    assert_eq!(driver.turn(&mut app).await.unwrap(), Turn::Stop);
    assert_eq!((driver.counts.turns, driver.counts.yields), (64, 2));
}
