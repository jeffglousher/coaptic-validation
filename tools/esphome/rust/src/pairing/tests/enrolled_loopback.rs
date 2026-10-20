use super::*;
use coaptic::provisioning::{
    EnrollmentPolicy, OperationId, ReceiptStore, TelemetryOperation, TrustAnchor,
};
use coaptic::storage::{DatagramTransport, UdpSocketIo};
use coaptic_receipts::{Authority, Journal, Policy};
use std::{cell::Cell, net::UdpSocket};

#[cfg(feature = "async-network")]
mod async_read_only {
    use super::*;
    use coaptic::{platform::AsyncTimer, storage::AsyncDatagramIo};
    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    struct Socket(UdpSocket);
    impl DatagramTransport for Socket {
        type Error = std::io::Error;
    }
    impl AsyncDatagramIo for Socket {
        async fn recv(&mut self, out: &mut [u8]) -> Result<(usize, Endpoint), Self::Error> {
            core::future::poll_fn(|_| match self.0.recv_from(out) {
                Ok((n, peer)) => Poll::Ready(Ok((n, peer.into()))),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            })
            .await
        }
        async fn send(&mut self, to: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
            let (ip, port) = to.as_ipv4().unwrap();
            self.0
                .send_to(bytes, std::net::SocketAddrV4::new(ip.into(), port))
        }
    }
    struct Timer(Rc<Cell<u64>>);
    impl AsyncTimer for Timer {
        async fn wait_until(&mut self, deadline: u64) {
            core::future::poll_fn(|_| {
                if self.0.get() >= deadline {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await
        }
    }
    struct NoConsole;
    impl ConsoleWait for NoConsole {
        async fn wait(&mut self) -> Result<(), Error> {
            core::future::pending().await
        }
    }
    struct StatusConsole(Rc<Cell<bool>>);
    impl Console for StatusConsole {
        fn read(&mut self, _: &mut [u8]) -> Result<usize, Error> {
            Ok(0)
        }
        fn write(&mut self, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        fn restart(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn event(&mut self, event: u32) {
            if event == 5 {
                self.0.set(true);
            }
        }
    }

    #[test]
    fn enrolled_async_read_only_denies_echo_while_observing_and_reading() {
        let device_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let host_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        device_socket.set_nonblocking(true).unwrap();
        host_socket.set_nonblocking(true).unwrap();
        let device_endpoint = Endpoint::from(device_socket.local_addr().unwrap());
        let host_endpoint = Endpoint::from(host_socket.local_addr().unwrap());
        let store = Rc::new(RefCell::new(Memory::default()));
        let mut shared = Shared(store.clone());
        let mut device = Device::initialize(&mut shared, 17, random).unwrap();
        let host = (1..=255)
            .find_map(|byte| {
                Identity::from_private_key([byte; 32], 18)
                    .ok()
                    .filter(|host| {
                        host.peer().principal().fingerprint()
                            > device.identity.peer().principal().fingerprint()
                    })
            })
            .unwrap();
        let challenge = device.pairing.begin(&device.identity, 0, random).unwrap();
        device
            .pairing
            .pair(
                &challenge,
                EnrollmentPolicy::new(host.peer(), [7; 32], permissions(false)).unwrap(),
                1,
                |old, next| {
                    prepare_pending(&mut shared, &device.private, &device.identity, old, next)?;
                    let mut bytes = [0; STORE_BYTES];
                    let len =
                        encode_store(&device.private, 17, next, Some(host_endpoint), &mut bytes)?;
                    shared.commit(&device.stored[..device.stored_len], &bytes[..len])
                },
            )
            .unwrap();
        let mut pairing =
            LocalPairing::restore(&host, PairingRecord::unpaired(&host, [9; 32]).unwrap()).unwrap();
        let challenge = pairing.begin(&host, 0, random).unwrap();
        pairing
            .pair(
                &challenge,
                EnrollmentPolicy::new(device.identity.peer(), [7; 32], permissions(false)).unwrap(),
                1,
                |_, _| Ok::<_, ()>(()),
            )
            .unwrap();
        let mut host_connection =
            ManagedConnection::<_, profiles::Constrained>::from_local_pairing(
                &host,
                &pairing,
                device_endpoint,
                UdpSocketIo::new(host_socket, [0; 1473]).unwrap(),
                random,
                0,
            )
            .unwrap();
        host_connection.observable_manual("identity").unwrap();
        host_connection.connect(0).unwrap();
        let now = Rc::new(Cell::new(0));
        let mut protocol = Timer(now.clone());
        let mut local = Timer(now.clone());
        let stopped = Rc::new(Cell::new(false));
        let mut future = core::pin::pin!(run_async(
            Socket(device_socket),
            random,
            || Some(now.get()),
            Shared(store),
            StatusConsole(stopped.clone()),
            (&mut protocol, &mut local),
            NoConsole
        ));
        let mut context = Context::from_waker(Waker::noop());
        let mut call = None;
        let mut due = 0;
        let mut refused = 0;
        let mut denied = false;
        let mut output = [0; 128];
        for tick in 0..3000 {
            let time = tick * 10;
            now.set(time);
            host_connection
                .poll_with(time, |_, request, _| {
                    assert_eq!(request.path(), ["identity"]);
                    let reply =
                        Response::content_copy(host.peer().principal().fingerprint()).max_age(10);
                    if request.is_observe_register() {
                        reply.observe(0)
                    } else {
                        reply
                    }
                })
                .or_else(|error| match error {
                    ManagedError::Recovery(_) => Ok(()),
                    error => Err(error),
                })
                .unwrap();
            if host_connection.is_connected() && call.is_none() && time >= due {
                match host_connection.request(
                    Method::Post,
                    "echo",
                    b"must refuse",
                    Some(ContentFormat::CBOR),
                    time,
                ) {
                    Ok(next) => call = Some(next),
                    Err(ManagedError::Application(coaptic::app::Error::Backoff { until_ms })) => {
                        due = until_ms
                    }
                    Err(error) => panic!("probe admission: {error:?}"),
                }
            }
            if let Some(current) = call
                && let Some(reply) = host_connection
                    .take_response_into(current, &mut output, time)
                    .unwrap()
            {
                let reply = reply.unwrap();
                call = None;
                if reply.code() == Code::FORBIDDEN {
                    assert!(reply.payload().is_empty());
                    denied = true;
                    break;
                }
                assert_eq!(reply.code(), Code::SERVICE_UNAVAILABLE);
                refused += 1;
                due = time + u64::from(reply.max_age_secs().unwrap_or(60)) * 1000;
            }
            if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
                panic!("async device stopped: {result:?}")
            }
        }
        assert!(
            denied,
            "read-only service never dispatched denial; stopped={}, temporary refusals={refused}, host metrics={:?}",
            stopped.get(),
            host_connection.diagnostic_snapshot(now.get())
        );
        assert!(!stopped.get());
    }
}

#[test]
fn enrolled_pending_owner_has_an_independent_memory_ceiling() {
    type Io = UdpSocketIo<[u8; 1473]>;
    type Baseline = ManagedConnection<'static, Io, profiles::Constrained>;
    type Enrolled = ManagedConnection<'static, Io, EnrolledDevice>;
    assert!(core::mem::size_of::<Enrolled>() <= 64 * 1024);
    assert!(core::mem::size_of::<coaptic::App<EnrolledDevice>>() <= 48 * 1024);
    std::eprintln!(
        "Enrolled whole owners: baseline_managed={} enrolled_managed={} app={} delta={} alignment={}",
        core::mem::size_of::<Baseline>(),
        core::mem::size_of::<Enrolled>(),
        core::mem::size_of::<coaptic::App<EnrolledDevice>>(),
        core::mem::size_of::<Enrolled>() - core::mem::size_of::<Baseline>(),
        core::mem::align_of::<Enrolled>(),
    );
    assert!(core::mem::size_of::<Device>() <= 1344);
    std::eprintln!(
        "Pairing owner bytes: record={} state={} device={} pending={}",
        core::mem::size_of::<PairingRecord>(),
        core::mem::size_of::<LocalPairing>(),
        core::mem::size_of::<Device>(),
        core::mem::size_of::<crate::pending_telemetry::Pending<'_, PendingStore<'_, Memory>>>()
    );
    // One retained record plus its custody reference/metadata, never another
    // application payload array. Persistent bytes and transmission prefix are
    // separately bounded; target stack peaks still require the final firmware.
    assert!(
        core::mem::size_of::<crate::pending_telemetry::Pending<'_, PendingStore<'_, Memory>>>()
            <= 1280
    );
    assert_eq!(crate::pending_telemetry::RECORD_BYTES, 1214);
}

#[test]
fn enrolled_two_response_credits_keep_headroom_and_refuse_third_call() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let endpoint = Endpoint::from(peer.local_addr().unwrap());
    let mut app = coaptic::App::profile::<EnrolledDevice>()
        .block_wise::<false>()
        .full_responses()
        .allow_unprotected()
        .randomness(random)
        .bind(UdpSocketIo::new(socket, [0; 1473]).unwrap())
        .unwrap();
    let observation = app
        .get("identity")
        .to(endpoint)
        .observe()
        .non()
        .send(0)
        .unwrap();
    let ordinary = app.get("probe").to(endpoint).non().send(1).unwrap();
    assert!(matches!(
        app.get("third").to(endpoint).non().send(2),
        Err(coaptic::app::Error::Saturated)
    ));
    assert_eq!(app.engine().metrics().admission_rx_refused, 1);
    assert!(app.cancel(ordinary));
    assert!(app.get("replacement").to(endpoint).non().send(3).is_ok());
    assert!(app.cancel(observation));
}

struct DropReply {
    inner: UdpSocketIo<[u8; 1473]>,
    drop_next: Rc<Cell<bool>>,
}
impl DatagramTransport for DropReply {
    type Error = std::io::Error;
}
impl DatagramIo for DropReply {
    fn recv(&mut self, bytes: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        self.inner.recv(bytes)
    }
    fn send(&mut self, to: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        if self.drop_next.replace(false) {
            Ok(bytes.len())
        } else {
            self.inner.send(to, bytes)
        }
    }
}
struct QuietConsole(Rc<Cell<bool>>, Rc<Cell<usize>>);
impl Console for QuietConsole {
    fn read(&mut self, _: &mut [u8]) -> Result<usize, Error> {
        Ok(0)
    }
    fn write(&mut self, _: &[u8]) -> Result<(), Error> {
        Ok(())
    }
    fn restart(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn event(&mut self, event: u32) {
        if event == 4 {
            self.0.set(true);
        }
    }
    fn diagnostics(&mut self, snapshot: &coaptic::app::diagnostics::Snapshot) {
        assert!(snapshot.at_ms > 0);
        assert!(snapshot.usage.storage.tx_datagram.capacity > 0);
        self.1.set(self.1.get() + 1);
    }
}

struct DrainConsole {
    inner: QuietConsole,
    command: std::io::Cursor<Vec<u8>>,
    decoder: CommissioningDecoder,
    held: Rc<Cell<bool>>,
}
impl Console for DrainConsole {
    fn read(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        std::io::Read::read(&mut self.command, out).map_err(|_| Error::Console)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        for byte in bytes {
            if let Some(payload) = self.decoder.feed(*byte) {
                assert!(matches!(
                    CommissioningReply::decode(payload).unwrap(),
                    CommissioningReply::Quiesced
                ));
                assert!(
                    self.inner.0.get(),
                    "quiescence must follow durable receipt completion"
                );
                self.held.set(true);
            }
        }
        Ok(())
    }
    fn restart(&mut self) -> Result<(), Error> {
        self.inner.restart()
    }
    fn event(&mut self, event: u32) {
        self.inner.event(event);
    }
    fn diagnostics(&mut self, snapshot: &coaptic::app::diagnostics::Snapshot) {
        self.inner.diagnostics(snapshot);
    }
}

#[test]
fn enrolled_udp_restart_recovers_one_effect_after_lost_receipt() {
    let device_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let host_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    device_socket.set_nonblocking(true).unwrap();
    host_socket.set_nonblocking(true).unwrap();
    let device_endpoint = Endpoint::from(device_socket.local_addr().unwrap());
    let host_endpoint = Endpoint::from(host_socket.local_addr().unwrap());
    let store = Rc::new(RefCell::new(Memory::default()));
    let mut shared = Shared(store.clone());
    let mut device = Device::initialize(&mut shared, 17, random).unwrap();
    let host = Identity::from_private_key([2; 32], 18).unwrap();
    let challenge = device.pairing.begin(&device.identity, 0, random).unwrap();
    let policy = EnrollmentPolicy::new(host.peer(), [7; 32], permissions(true)).unwrap();
    device
        .pairing
        .pair(&challenge, policy, 1, |old, next| {
            prepare_pending(&mut shared, &device.private, &device.identity, old, next)?;
            let mut bytes = [0; STORE_BYTES];
            let len = encode_store(&device.private, 17, next, Some(host_endpoint), &mut bytes)?;
            shared.commit(&device.stored[..device.stored_len], &bytes[..len])
        })
        .unwrap();
    let mut host_pairing =
        LocalPairing::restore(&host, PairingRecord::unpaired(&host, [9; 32]).unwrap()).unwrap();
    let challenge = host_pairing.begin(&host, 0, random).unwrap();
    host_pairing
        .pair(
            &challenge,
            EnrollmentPolicy::new(device.identity.peer(), [7; 32], permissions(true)).unwrap(),
            1,
            |_, _| Ok::<_, ()>(()),
        )
        .unwrap();
    let record = host_pairing.checkpoint();
    let anchor =
        TrustAnchor::from_parts(*record.store(), record.revision(), record.commitment()).unwrap();
    let authority = Authority::new(Policy {
        anchor,
        principal: device.identity.peer().principal(),
        resource: telemetry_resource(),
        enabled: true,
    });
    let path = std::env::temp_dir().join(format!(
        "coaptic-enrolled-receipts-{}-{}",
        std::process::id(),
        host_socket.local_addr().unwrap().port()
    ));
    let mut journal = Journal::create(&path, authority.clone(), 2).unwrap();
    for phase in 0..2 {
        let diagnostic_samples = Rc::new(Cell::new(0));
        let drop_next = Rc::new(Cell::new(false));
        let mut connection = ManagedConnection::<_, profiles::Constrained>::from_local_pairing(
            &host,
            &host_pairing,
            device_endpoint,
            DropReply {
                inner: UdpSocketIo::new(host_socket.try_clone().unwrap(), [0; 1473]).unwrap(),
                drop_next: drop_next.clone(),
            },
            random,
            0,
        )
        .unwrap();
        connection.observable_manual("identity").unwrap();
        if host.peer().principal().fingerprint() > device.identity.peer().principal().fingerprint()
        {
            connection.connect(0).unwrap();
        }
        let completed = Rc::new(Cell::new(false));
        let held = Rc::new(Cell::new(false));
        let mut held_at = None;
        let mut command = [0; 16];
        let mut payload = [0; 8];
        let payload_len = CommissioningRequest::Quiesce.encode(&mut payload).unwrap();
        let command_len =
            CommissioningDecoder::frame(&payload[..payload_len], &mut command).unwrap();
        let console = DrainConsole {
            inner: QuietConsole(completed.clone(), diagnostic_samples.clone()),
            command: std::io::Cursor::new(if phase == 1 {
                command[..command_len].to_vec()
            } else {
                Vec::new()
            }),
            decoder: CommissioningDecoder::new(),
            held: held.clone(),
        };
        let mut now = 0;
        let mut committed = false;
        let mut observed = false;
        let mut io = Some(UdpSocketIo::new(device_socket.try_clone().unwrap(), [0; 1473]).unwrap());
        let result = run(
            || io.take().unwrap(),
            random,
            || {
                now += 1;
                connection
                    .poll_with(now, |principal, request, _| {
                        if request.path() == ["identity"] {
                            let response =
                                Response::content_copy(host.peer().principal().fingerprint());
                            return if request.is_observe_register() {
                                observed = true;
                                response.observe(0)
                            } else {
                                response
                            };
                        }
                        assert_eq!(request.path(), ["telemetry"]);
                        assert_eq!(request.content_format(), Some(Ok(ContentFormat::CBOR)));
                        let payload = request.payload();
                        let operation = TelemetryOperation::new(
                            OperationId::new(payload[..16].try_into().unwrap()),
                            telemetry_resource(),
                            Some(60),
                            &payload[16..],
                        )
                        .unwrap();
                        let receipt = journal.commit(&anchor, principal, &operation).unwrap();
                        committed = true;
                        if phase == 0 {
                            drop_next.set(true);
                        }
                        Response::new(Code::CHANGED).payload_copy(&receipt.encode())
                    })
                    .unwrap();
                if held.get() && held_at.is_none() {
                    held_at = Some(now);
                }
                if (phase == 0 && committed)
                    || held_at.is_some_and(|at| now >= at + 6_000)
                    || now > 20_000
                {
                    None
                } else {
                    Some(now)
                }
            },
            Shared(store.clone()),
            console,
        );
        assert_eq!(result, Ok(()));
        assert!(diagnostic_samples.get() > 0);
        assert!(
            observed,
            "host must accept the persistent Observe before telemetry"
        );
        assert!(now <= 20_000, "enrolled service did not complete");
        assert_eq!(journal.effects().unwrap(), 1);
        let recovered = Device::recover(&mut Shared(store.clone()))
            .unwrap()
            .unwrap();
        let mut backend = Shared(store.clone());
        let pending = recover_pending(&recovered, &mut backend, true)
            .unwrap()
            .unwrap();
        if phase == 0 {
            assert!(!completed.get());
            assert!(pending.pending().unwrap().is_some());
            assert!(pending.completion().unwrap().is_none());
        } else {
            assert!(completed.get());
            assert!(held.get());
            assert!(now >= held_at.unwrap() + 6_000);
            assert!(pending.pending().unwrap().is_none());
            assert_eq!(pending.completion().unwrap().unwrap().sequence(), 1);
        }
        drop(journal);
        journal = Journal::open(&path, authority.clone()).unwrap();
    }
    drop(journal);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn enrolled_live_device_accepts_fresh_host_after_authenticated_silence() {
    let device_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let host_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    device_socket.set_nonblocking(true).unwrap();
    host_socket.set_nonblocking(true).unwrap();
    let device_endpoint = Endpoint::from(device_socket.local_addr().unwrap());
    let host_endpoint = Endpoint::from(host_socket.local_addr().unwrap());
    let store = Rc::new(RefCell::new(Memory::default()));
    let mut shared = Shared(store.clone());
    let mut device = Device::initialize(&mut shared, 17, random).unwrap();
    let host = (1..=255)
        .find_map(|byte| {
            Identity::from_private_key([byte; 32], 18)
                .ok()
                .filter(|identity| {
                    identity.peer().principal().fingerprint()
                        > device.identity.peer().principal().fingerprint()
                })
        })
        .expect("host initiator identity");
    let challenge = device.pairing.begin(&device.identity, 0, random).unwrap();
    device
        .pairing
        .pair(
            &challenge,
            EnrollmentPolicy::new(host.peer(), [7; 32], echo_permissions()).unwrap(),
            1,
            |_, next| {
                let mut bytes = [0; STORE_BYTES];
                let len = encode_store(&device.private, 17, next, Some(host_endpoint), &mut bytes)?;
                shared.commit(&device.stored[..device.stored_len], &bytes[..len])
            },
        )
        .unwrap();
    let mut host_pairing =
        LocalPairing::restore(&host, PairingRecord::unpaired(&host, [9; 32]).unwrap()).unwrap();
    let challenge = host_pairing.begin(&host, 0, random).unwrap();
    host_pairing
        .pair(
            &challenge,
            EnrollmentPolicy::new(device.identity.peer(), [7; 32], echo_permissions()).unwrap(),
            1,
            |_, _| Ok::<_, ()>(()),
        )
        .unwrap();
    let make_host = |now| {
        let mut connection = ManagedConnection::<_, profiles::Constrained>::from_local_pairing(
            &host,
            &host_pairing,
            device_endpoint,
            UdpSocketIo::new(host_socket.try_clone().unwrap(), [0; 1473]).unwrap(),
            random,
            now,
        )
        .unwrap();
        connection.observable_manual("identity").unwrap();
        connection.connect(now).unwrap();
        connection
    };
    let mut connection = Some(make_host(0));
    let mut phase = 0;
    let mut restart_at = 0;
    let mut retry_at = 30_000;
    let mut observed = [false; 2];
    let mut now = 0;
    let mut io = Some(UdpSocketIo::new(device_socket, [0; 1473]).unwrap());
    let result = run(
        || io.take().unwrap(),
        random,
        || {
            now += 10;
            if phase == 1 && connection.is_none() && now >= restart_at {
                connection = Some(make_host(now));
                retry_at = now + 30_000;
            }
            let mut echoed = false;
            if let Some(connection) = connection.as_mut() {
                connection
                    .poll_with(now, |_, request, _| {
                        if request.path() == ["identity"] {
                            let response =
                                Response::content_copy(host.peer().principal().fingerprint())
                                    .max_age(10);
                            if request.is_observe_register() {
                                observed[phase] = true;
                                response.observe(0)
                            } else {
                                response
                            }
                        } else {
                            assert_eq!(request.path(), ["echo"]);
                            echoed = true;
                            Response::content_copy(request.payload())
                        }
                    })
                    .or_else(|error| match error {
                        ManagedError::Recovery(_) => Ok(()),
                        error => Err(error),
                    })
                    .unwrap();
                if now >= retry_at {
                    match connection.connect(now) {
                        Ok(()) => retry_at = now + 30_000,
                        Err(ManagedError::Busy | ManagedError::Capacity) => retry_at = now + 1000,
                        Err(ManagedError::Recovery(_)) => retry_at = now + 5000,
                        Err(error) => panic!("fresh host: {error:?}"),
                    }
                }
            }
            if echoed && phase == 0 {
                assert!(observed[0]);
                // Lose the host after sending a valid reply; the live device retains
                // its App, observation and MID history throughout host replacement.
                connection = None;
                phase = 1;
                restart_at = now + 10_000;
            } else if echoed && phase == 1 && observed[1] {
                phase = 2;
                return None;
            }
            (now < 120_000).then_some(now)
        },
        Shared(store.clone()),
        QuietConsole(Rc::new(Cell::new(false)), Rc::new(Cell::new(0))),
    );
    assert_eq!(result, Ok(()));
    assert_eq!(
        phase, 2,
        "live device must admit fresh host and resume Observe plus echo"
    );
    assert!(observed.into_iter().all(|value| value));
    let restored = Device::recover(&mut Shared(store)).unwrap().unwrap();
    assert_eq!(
        restored.pairing.checkpoint().commitment(),
        device.pairing.checkpoint().commitment()
    );
}

#[test]
fn enrolled_liveness_quiesces_without_discarding_generation() {
    assert!(core::mem::size_of::<SessionLiveness>() <= 32);
    let mut state = SessionLiveness::new(0);
    assert!(!state.expired(90_000));
    state.generation(Some(1), 10);
    assert!(!state.expired(30_009));
    assert!(state.expired(30_010));
    state.quiet = true;
    state.generation(Some(1), 40_000);
    assert!(state.quiet);
    state.generation(None, 40_001);
    assert!(state.quiet);
    state.generation(Some(2), 40_002);
    assert!(!state.quiet);
    assert!(!state.expired(40_003));
    state.quiet = true;
    state.authenticated(50_000);
    assert!(!state.quiet);
}
