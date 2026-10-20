//! Finite native-async UDP integration with startup-sized Service heap pools.
//!
//! Run with `--features cloud --bin peer-coaptic-cloud -- --unprotected` or
//! `--protected`. This adapter deliberately has no synchronous DatagramIo impl.
//! App progress waits for socket readiness or a protocol deadline, without a
//! polling sleep or a task spawned for each Call.
//!
//! Allocation observations cover App-future construction/polls and explicit
//! synchronous App operations on the current runtime thread. Runtime creation,
//! socket registration, executor work between those polls, OS network memory,
//! allocator bookkeeping and whole-process memory are outside that measurement.
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

const SCRATCH_BYTES: usize = 1473;
const BODY: [u8; 2000] = [0x5a; 2000];
const TINY: &[u8] = b"complete";
const RUN_LIMIT: Duration = Duration::from_secs(5);
const FIXTURE_STACK_BYTES: usize = 4 * 1024 * 1024;

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
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocation_request(false);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocation_request(true);
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
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
) {
    let mut timer = Timer { epoch };
    let mut clock = clock(epoch);
    loop {
        tokio::select! {
            result = observed_async(totals, || server.wait_async(now(epoch), &mut timer, pending())) => {
                result.expect("server native async readiness");
            }
            () = finished.notified() => return,
        }
        observed_async(totals, || {
            server.progress_async(now(epoch), &mut clock, &mut timer, now(epoch) + 1000)
        })
        .await
        .expect("server native async progress");
    }
}

async fn response(client: &mut Service, call: Call, epoch: Instant, totals: &Cell<Observations>) {
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
                    assert_eq!(result.code(), Code::CONTENT);
                    assert_eq!(result.payload(), BODY);
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

async fn exercise(protected: bool) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = Endpoint::from(socket.local_addr().unwrap());
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).unwrap();
    let security = protected.then_some(&secret);
    let required = configuration(usize::MAX).required_heap_bytes().unwrap();
    let mut server = bind(socket, required, security, true);
    let mut client = bind(client_socket, required, security, false);
    secret.fill(0);
    let capacities = configuration(required).pool_capacities();
    let totals = Cell::new(Observations::default());
    let finished = Notify::new();
    let epoch = Instant::now();
    tokio::time::timeout(RUN_LIMIT, async {
        tokio::join!(serve(&mut server, epoch, &finished, &totals), async {
            client_work(&mut client, peer, epoch, &totals).await;
            finished.notify_one();
        });
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
            "complete_responses": 16,
            "bytes_per_response": BODY.len(),
            "local_admission_refusals": 3,
            "cancellation_recovery": true,
            "app_future_polls": counts.future_polls,
            "pending_app_future_polls": counts.pending_polls,
            "measured_scopes": counts.scopes,
            "allocation_requests": counts.alloc,
            "reallocation_requests": counts.realloc,
            "client_received_datagrams": client.transport().received,
            "server_received_datagrams": server.transport().received,
            "request_warmups": 0,
            "fixture_thread_stack_bytes": FIXTURE_STACK_BYTES,
            "memory_scope": "requested Coaptic pool layouts and inline owner sizes; allocator/OS/runtime/socket registration memory unmeasured",
            "allocation_scope": "same-thread App future construction and polls plus explicit synchronous App operations; executor work between polls, startup and pending-future Drop excluded",
        })
    );
}

fn main() -> ExitCode {
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
            runtime.block_on(exercise(protected));
        });
    if execution.is_ok_and(|worker| worker.join().is_ok()) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
