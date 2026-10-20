//! Finite native-async UDP integration with startup-sized Service heap pools.
//!
//! Run with `--features cloud --bin peer-coaptic-cloud -- --unprotected` or
//! `--protected`. This adapter deliberately has no synchronous DatagramIo impl.
//! App progress waits for socket readiness or a protocol deadline, without a
//! polling sleep or a task spawned for each Call.
//!
//! Allocation observations cover App-future construction/polls and explicit
//! synchronous App operations on the current runtime thread. Runtime creation,
//! socket registration and executor work between those polls are outside that
//! zero-allocation assertion. Separate startup/steady/Drop snapshots retain
//! requested Rust heap and OS process counters, with overlapping scope explicit.
//! There is no unmeasured request warmup. This is not a throughput benchmark or
//! durable OSCORE restart qualification.

use coaptic::app::AsyncCallError;
use coaptic::platform::AsyncTimer;
use coaptic::resources::{Allocated, Resources};
use coaptic::storage::{AllocMemory, AsyncDatagramIo, DatagramTransport};
use coaptic::{App, Call, CallFailure, Code, Endpoint, Error, Response, get, profiles};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::convert::Infallible;
use std::future::{Future, pending, poll_fn};
use std::net::SocketAddr;
use std::pin::pin;
use std::process::ExitCode;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time::Instant;

#[path = "cloud/memory.rs"]
mod memory;

const SCRATCH_BYTES: usize = 1473;
const BODY: [u8; 2000] = [0x5a; 2000];
const TINY: &[u8] = b"complete";
const RUN_LIMIT: Duration = Duration::from_secs(5);
const FIXTURE_STACK_BYTES: usize = 4 * 1024 * 1024;
const PRESSURE_TX_SLOTS: usize = 31;
const CHURN_DATAGRAMS: usize = 16;

#[derive(Clone, Copy, Default)]
struct AllocationRequests {
    alloc: usize,
    realloc: usize,
}

#[derive(Clone, Copy, Default)]
struct Observations {
    scopes: usize,
    future_polls: usize,
    pending_polls: usize,
    alloc: usize,
    realloc: usize,
}

thread_local! {
    static ACTIVE: Cell<Option<AllocationRequests>> = const { Cell::new(None) };
}

fn allocation_request(reallocation: bool) {
    let _ = ACTIVE.try_with(|active| {
        if let Some(mut counts) = active.get() {
            if reallocation {
                counts.realloc += 1;
            } else {
                counts.alloc += 1;
            }
            active.set(Some(counts));
        }
    });
}

struct TrackingAllocator;

// Const thread-local counters do not allocate or synchronize with other threads.
// Allocation behavior is unchanged: every request delegates directly to System.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocation_request(false);
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            memory::allocated(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocation_request(false);
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            memory::allocated(layout.size());
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocation_request(true);
        let resized = unsafe { System.realloc(pointer, layout, size) };
        if !resized.is_null() {
            memory::reallocated(layout.size(), size);
        }
        resized
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        memory::deallocated(layout.size());
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn observed<R>(totals: &Cell<Observations>, work: impl FnOnce() -> R) -> R {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            ACTIVE.with(|active| active.set(None));
        }
    }

    ACTIVE.with(|active| {
        assert!(active.get().is_none(), "nested allocation observation");
        active.set(Some(AllocationRequests::default()));
    });
    let guard = Guard;
    let result = work();
    let counts = ACTIVE.with(|active| active.get().unwrap());
    drop(guard);
    let mut sum = totals.get();
    sum.scopes += 1;
    sum.alloc += counts.alloc;
    sum.realloc += counts.realloc;
    totals.set(sum);
    result
}

async fn observed_async<F: Future>(
    totals: &Cell<Observations>,
    construct: impl FnOnce() -> F,
) -> F::Output {
    // send_async performs eager admission before returning its future. Observe
    // construction as well as polling so that work is included in the count.
    let mut operation = pin!(observed(totals, construct));
    poll_fn(|cx| {
        let poll = observed(totals, || operation.as_mut().poll(cx));
        let mut sum = totals.get();
        sum.future_polls += 1;
        sum.pending_polls += usize::from(poll.is_pending());
        totals.set(sum);
        poll
    })
    .await
}

struct TokioUdp {
    socket: UdpSocket,
    scratch: [u8; SCRATCH_BYTES],
    send_attempts: usize,
    received: usize,
}

impl DatagramTransport for TokioUdp {
    type Error = std::io::Error;
}

impl AsyncDatagramIo for TokioUdp {
    async fn recv(&mut self, output: &mut [u8]) -> std::io::Result<(usize, Endpoint)> {
        let required = output
            .len()
            .checked_add(1)
            .filter(|required| *required <= self.scratch.len())
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        // A spare byte detects oversized datagrams on platforms that truncate
        // silently. Preserve native errors on platforms reporting truncation.
        // Pending receive only borrows this adapter's retained scratch.
        let (length, peer) = self.socket.recv_from(&mut self.scratch[..required]).await?;
        if length > output.len() {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        output[..length].copy_from_slice(&self.scratch[..length]);
        self.received += 1;
        Ok((length, peer.into()))
    }

    async fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> std::io::Result<usize> {
        self.send_attempts += 1;
        self.socket.send_to(bytes, SocketAddr::from(dest)).await
    }
}

struct Timer {
    epoch: Instant,
}

impl AsyncTimer for Timer {
    async fn wait_until(&mut self, deadline_ms: u64) {
        tokio::time::sleep_until(self.epoch + Duration::from_millis(deadline_ms)).await;
    }
}

type Configuration = Resources<profiles::Service, 2, true, 0, 4, Allocated, 4>;
type Service = App<profiles::Service, TokioUdp, 2, true, AllocMemory, 0, 4, 4>;

fn configuration(limit: usize) -> Configuration {
    coaptic::resources::Service::new()
        .routes::<2>()
        .deferred::<0>()
        .client_calls::<4>()
        .security_requests::<4>()
        .allocated(limit)
}

fn bind(socket: UdpSocket, required: usize, secret: Option<&[u8; 32]>, server: bool) -> Service {
    let builder = App::with_resources(configuration(required))
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .route("body", get(|_| Response::content(&BODY)))
        .route("tiny", get(|_| Response::content(TINY)));
    let builder = if let Some(secret) = secret {
        builder.oscore(
            coaptic::oscore::SecurityContext::derive(coaptic::oscore::DeriveParams {
                master_secret: secret,
                master_salt: &[],
                sender_id: if server { &[2] } else { &[1] },
                recipient_id: if server { &[1] } else { &[2] },
                id_context: &[],
            })
            .unwrap(),
        )
    } else {
        builder.allow_unprotected()
    };
    builder
        .bind(TokioUdp {
            socket,
            scratch: [0; SCRATCH_BYTES],
            send_attempts: 0,
            received: 0,
        })
        .unwrap()
}

fn now(epoch: Instant) -> u64 {
    u64::try_from(epoch.elapsed().as_millis()).unwrap()
}

fn clock(epoch: Instant) -> impl FnMut() -> Result<u64, Infallible> {
    move || Ok(now(epoch))
}

async fn serve(
    server: &mut Service,
    epoch: Instant,
    finished: &Notify,
    totals: &Cell<Observations>,
    pressure_release: &Notify,
    held_tx: &mut [Option<coaptic::storage::SlotId>; PRESSURE_TX_SLOTS],
) {
    let mut timer = Timer { epoch };
    let mut clock = clock(epoch);
    loop {
        tokio::select! {
            biased;
            () = finished.notified() => return,
            () = pressure_release.notified() => {
                observed(totals, || {
                    for slot in held_tx.iter_mut().filter_map(Option::take) {
                        server.engine_mut().release_tx(slot).unwrap();
                    }
                });
            }
            result = observed_async(totals, || server.wait_async(now(epoch), &mut timer, pending())) => {
                result.expect("server native async readiness");
            }
        }
        observed_async(totals, || {
            server.progress_async(now(epoch), &mut clock, &mut timer, now(epoch) + 1000)
        })
        .await
        .expect("server native async progress");
    }
}

async fn expected_response(
    client: &mut Service,
    call: Call,
    epoch: Instant,
    totals: &Cell<Observations>,
    expected_code: Code,
    expected_body: &[u8],
) {
    let mut timer = Timer { epoch };
    let mut clock = clock(epoch);
    let mut output = [0; BODY.len()];
    loop {
        observed_async(totals, || {
            client.progress_async(now(epoch), &mut clock, &mut timer, now(epoch) + 1000)
        })
        .await
        .expect("client native async progress");
        let ready = observed(totals, || {
            client
                .take_response_into(call, &mut output)
                .unwrap()
                .map(|result| {
                    let result = result.unwrap();
                    assert_eq!(result.code(), expected_code);
                    assert_eq!(result.payload(), expected_body);
                    if expected_code == Code::SERVICE_UNAVAILABLE {
                        assert_eq!(result.max_age_secs(), Some(1));
                    }
                })
        });
        if ready.is_some() {
            return;
        }
        observed_async(totals, || {
            client.wait_async(now(epoch), &mut timer, pending())
        })
        .await
        .expect("client native async readiness");
    }
}

async fn response(client: &mut Service, call: Call, epoch: Instant, totals: &Cell<Observations>) {
    expected_response(client, call, epoch, totals, Code::CONTENT, &BODY).await;
}

async fn server_pressure(
    client: &mut Service,
    peer: Endpoint,
    epoch: Instant,
    totals: &Cell<Observations>,
    pressure_release: &Notify,
    chatter: &UdpSocket,
) {
    let mut timer = Timer { epoch };
    let refused = observed_async(totals, || {
        client
            .get("tiny")
            .non()
            .to(peer)
            .send_async(now(epoch), clock(epoch), &mut timer)
    })
    .await
    .expect("valid request reaches the pressured server");
    expected_response(
        client,
        refused,
        epoch,
        totals,
        Code::SERVICE_UNAVAILABLE,
        &[],
    )
    .await;
    let sends = client.transport().send_attempts;
    let retry = observed_async(totals, || {
        client
            .get("tiny")
            .non()
            .to(peer)
            .send_async(now(epoch), clock(epoch), &mut timer)
    })
    .await;
    let until_ms = match retry {
        Err(AsyncCallError::Request(Error::Backoff { until_ms })) => until_ms,
        other => panic!("server Max-Age must retain its bounded cooldown: {other:?}"),
    };
    assert_eq!(client.transport().send_attempts, sends);
    pressure_release.notify_one();
    // The failed tiny request retains its one-second cooldown. A different
    // resource can progress without bypassing that request's backoff contract.
    // This is finite malformed-ingress churn, not a sustained flood claim.
    for _ in 0..CHURN_DATAGRAMS {
        assert_eq!(
            chatter
                .send_to(&[0xff], SocketAddr::from(peer))
                .await
                .unwrap(),
            1
        );
    }
    let recovered = observed_async(totals, || {
        client
            .get("body")
            .non()
            .to(peer)
            .send_async(now(epoch), clock(epoch), &mut timer)
    })
    .await
    .expect("valid work can be admitted after pressure clears");
    response(client, recovered, epoch, totals).await;
    // Honor the actual protocol cooldown before reusing all four Call rows.
    // This is one deadline wait, not a periodic progress-polling sleep.
    timer.wait_until(until_ms).await;
    let mut deadline_clock = clock(epoch);
    observed_async(totals, || {
        client.progress_async(
            now(epoch),
            &mut deadline_clock,
            &mut timer,
            now(epoch) + 1000,
        )
    })
    .await
    .expect("drive the due cooldown deadline before sending fresh work");
    let recovered_tiny = observed_async(totals, || {
        client
            .get("tiny")
            .non()
            .to(peer)
            .send_async(now(epoch), clock(epoch), &mut timer)
    })
    .await
    .expect("same refused resource recovers after Max-Age");
    expected_response(client, recovered_tiny, epoch, totals, Code::CONTENT, TINY).await;
}

async fn client_work(
    client: &mut Service,
    peer: Endpoint,
    epoch: Instant,
    totals: &Cell<Observations>,
) {
    let mut timer = Timer { epoch };
    for _ in 0..3 {
        let mut calls = [None; 4];
        for call in &mut calls {
            *call = Some(
                observed_async(totals, || {
                    client.get("body").non().to(peer).send_async(
                        now(epoch),
                        clock(epoch),
                        &mut timer,
                    )
                })
                .await
                .expect("admit one of four native async NON Calls"),
            );
        }
        let calls = calls.map(Option::unwrap);
        let sends = client.transport().send_attempts;
        let refusal = observed_async(totals, || {
            client
                .get("body")
                .non()
                .to(peer)
                .send_async(now(epoch), clock(epoch), &mut timer)
        })
        .await;
        assert!(matches!(
            refusal,
            Err(AsyncCallError::Request(
                Error::Saturated | Error::Oscore(coaptic::oscore::Error::Saturated)
            ))
        ));
        assert_eq!(client.transport().send_attempts, sends);

        response(client, calls[0], epoch, totals).await;
        let recovered = observed_async(totals, || {
            client
                .get("body")
                .non()
                .to(peer)
                .send_async(now(epoch), clock(epoch), &mut timer)
        })
        .await
        .expect("consuming one body releases Call credit");
        for call in &calls[1..] {
            response(client, *call, epoch, totals).await;
        }
        response(client, recovered, epoch, totals).await;
        observed(totals, || {
            assert_eq!(client.storage_usage().rx_body.unwrap().occupied, 0);
            assert_eq!(client.storage_usage().tx_body.unwrap().occupied, 0);
        });
    }

    let cancelled = observed_async(totals, || {
        client
            .get("tiny")
            .non()
            .to(peer)
            .send_async(now(epoch), clock(epoch), &mut timer)
    })
    .await
    .unwrap();
    observed(totals, || {
        assert!(client.cancel(cancelled));
        assert!(matches!(
            client.take_response(cancelled),
            Some(Err(CallFailure::Cancelled))
        ));
    });
    let recovered = observed_async(totals, || {
        client
            .get("body")
            .non()
            .to(peer)
            .send_async(now(epoch), clock(epoch), &mut timer)
    })
    .await
    .unwrap();
    response(client, recovered, epoch, totals).await;
    observed(totals, || {
        assert!(client.take_response(cancelled).is_none());
    });
}

async fn exercise(
    protected: bool,
    process_start: memory::Snapshot,
    runtime_ready: memory::Snapshot,
    future_bytes: &Cell<usize>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = Endpoint::from(socket.local_addr().unwrap());
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let chatter = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).unwrap();
    let security = protected.then_some(&secret);
    let required = configuration(usize::MAX).required_heap_bytes().unwrap();
    let before_bind = memory::Snapshot::capture();
    let mut server = bind(socket, required, security, true);
    let mut client = bind(client_socket, required, security, false);
    secret.fill(0);
    let after_bind = memory::Snapshot::capture();
    assert_eq!(
        after_bind.requested_live() - before_bind.requested_live(),
        required * 2
    );
    let capacities = configuration(required).pool_capacities();
    let totals = Cell::new(Observations::default());
    let finished = Notify::new();
    let pressure_release = Notify::new();
    // Explicit fault injection occupies existing storage to test wire refusal;
    // these are not extra buffers or a different capacity configuration.
    let mut held_tx = observed(&totals, || {
        std::array::from_fn(|_| Some(server.engine_mut().acquire_tx().unwrap()))
    });
    assert_eq!(
        server.storage_usage().tx_datagram.occupied,
        PRESSURE_TX_SLOTS
    );
    let epoch = Instant::now();
    tokio::time::timeout(RUN_LIMIT, async {
        tokio::join!(
            serve(
                &mut server,
                epoch,
                &finished,
                &totals,
                &pressure_release,
                &mut held_tx
            ),
            async {
                server_pressure(
                    &mut client,
                    peer,
                    epoch,
                    &totals,
                    &pressure_release,
                    &chatter,
                )
                .await;
                client_work(&mut client, peer, epoch, &totals).await;
                finished.notify_one();
            }
        );
    })
    .await
    .expect("finite native async cloud run deadline");
    observed(&totals, || {
        assert_eq!(client.engine().capacities(), capacities);
        assert_eq!(server.engine().capacities(), capacities);
        assert_eq!(client.storage_usage().rx_datagram.occupied, 0);
        assert_eq!(client.storage_usage().rx_body.unwrap().occupied, 0);
        // Shutdown cancels the outstanding receive and releases its RX owner.
        assert_eq!(server.storage_usage().rx_datagram.occupied, 0);
        assert_eq!(server.storage_usage().tx_body.unwrap().occupied, 0);
        assert_eq!(server.storage_usage().tx_datagram.occupied, 0);
        assert!(held_tx.iter().all(Option::is_none));
        assert_eq!(server.metrics().admission_tx_refused, 1);
        assert_eq!(server.metrics().admission_refusal_sent, 1);
        assert_eq!(server.metrics().admission_refusal_unsent, 0);
        assert_eq!(server.metrics().hard_tx_exhausted, 0);
        assert_eq!(server.metrics().rx_error, CHURN_DATAGRAMS as u32);
    });
    let counts = totals.get();
    assert_eq!(counts.alloc, 0, "observed App/adapter allocation requests");
    assert_eq!(
        counts.realloc, 0,
        "observed App/adapter reallocation requests"
    );
    assert!(
        counts.pending_polls > 0,
        "native futures actually suspended"
    );
    let after_traffic = memory::Snapshot::capture();
    let client_received = client.transport().received;
    let server_received = server.transport().received;
    drop(client);
    drop(server);
    drop(chatter);
    let after_drop = memory::Snapshot::capture();
    assert!(after_traffic.requested_live() - after_drop.requested_live() >= required * 2);
    let server_pressure = serde_json::json!({
        "wire_refusals": 1,
        "wire_refusal_code": "5.03",
        "wire_refusal_max_age_seconds": 1,
        "held_tx_slots": PRESSURE_TX_SLOTS,
        "finite_malformed_churn_datagrams": CHURN_DATAGRAMS,
        "recovery_complete_bytes": BODY.len(),
        "refused_resource_recovered_after_max_age": true,
        "local_max_age_backoff_refusals": 1,
        "additional_complete_tiny_responses": 1,
    });
    let memory = serde_json::json!({
        "exercise_future_bytes_nested_in_stack": future_bytes.get(),
        "snapshots": [
            process_start.json("main-before-arguments-and-worker"),
            runtime_ready.json("worker-runtime-ready"),
            before_bind.json("sockets-registered-before-app-bind"),
            after_bind.json("two-apps-bound-before-traffic"),
            after_traffic.json("finite-traffic-complete-before-drop"),
            after_drop.json("apps-and-sockets-dropped-runtime-still-live"),
        ],
    });
    println!(
        "{}",
        serde_json::json!({
            "success": true,
            "mode": if protected { "oscore-ephemeral" } else { "unprotected" },
            "execution": "tokio-current-thread-native-async",
            "profile": "Service",
            "rx_slots": capacities.rx_datagram_slots,
            "tx_slots": capacities.tx_datagram_slots,
            "datagram_bytes": capacities.rx_datagram_bytes,
            "rx_body_slots": capacities.rx_body_slots,
            "tx_body_slots": capacities.tx_body_slots,
            "body_bytes": capacities.rx_body_bytes,
            "routes": 2,
            "deferred": 0,
            "calls": 4,
            "security_request_bindings": 4,
            "associations": 1,
            "requested_heap_bytes_per_app": required,
            "inline_app_bytes_including_adapter": std::mem::size_of::<Service>(),
            "inline_adapter_bytes": std::mem::size_of::<TokioUdp>(),
            "adapter_scratch_bytes": SCRATCH_BYTES,
            "complete_responses": 17,
            "bytes_per_response": BODY.len(),
            "local_admission_refusals": 3,
            "server_pressure": server_pressure,
            "cancellation_recovery": true,
            "app_future_polls": counts.future_polls,
            "pending_app_future_polls": counts.pending_polls,
            "measured_scopes": counts.scopes,
            "allocation_requests": counts.alloc,
            "reallocation_requests": counts.realloc,
            "client_received_datagrams": client_received,
            "server_received_datagrams": server_received,
            "request_warmups": 0,
            "fixture_thread_stack_bytes": FIXTURE_STACK_BYTES,
            "memory": memory,
            "memory_scope": "Rust requested live/layout peak covers global allocator across process lifetime, including runtime/fixture; excludes allocator metadata and direct native allocation. OS process counters include overlapping heap/stack/runtime/code domains and are never added to component sizes. App owners and exercise future are nested in reserved fixture stack. No individual stack high-water or kernel socket-buffer allocation measurement; process lifetime peaks cover this finite run, not deployment maxima. JSON output is constructed after snapshots.",
            "allocation_scope": "same-thread App future construction and polls plus explicit synchronous App operations; executor work between polls, startup and pending-future Drop excluded",
        })
    );
}

fn main() -> ExitCode {
    let process_start = memory::Snapshot::capture();
    let mut arguments = std::env::args_os().skip(1);
    let protected = match (arguments.next(), arguments.next()) {
        (Some(flag), None) if flag == "--protected" => true,
        (Some(flag), None) if flag == "--unprotected" => false,
        _ => {
            eprintln!("usage: peer-coaptic-cloud --unprotected | --protected");
            return ExitCode::FAILURE;
        }
    };
    // One startup thread gives debug App/future construction an explicit stack.
    // The runtime stays single-threaded; neither tasks nor threads are per Call.
    let execution = std::thread::Builder::new()
        .name("coaptic-cloud".into())
        .stack_size(FIXTURE_STACK_BYTES)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let runtime_ready = memory::Snapshot::capture();
            let future_bytes = Cell::new(0);
            let run = exercise(protected, process_start, runtime_ready, &future_bytes);
            future_bytes.set(std::mem::size_of_val(&run));
            runtime.block_on(run);
        });
    if execution.is_ok_and(|worker| worker.join().is_ok()) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
