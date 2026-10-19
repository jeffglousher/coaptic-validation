//! Native async commissioning and managed sessions with exclusive borrowed socket ownership.
use super::*;
use coaptic::app::{AsyncCallError, AsyncIoError};
use coaptic::platform::AsyncTimer;
use coaptic::provisioning::{ManagedAsyncError, PollError, RecoveryError};
use coaptic::storage::{AsyncDatagramIo, DatagramIoError, DatagramTransport};
use core::{future::Future, pin::pin, task::Poll};

/// A privileged console readiness source, without buffering or consuming bytes.
pub trait ConsoleWait {
    fn wait(&mut self) -> impl Future<Output = Result<(), Error>>;
}
struct Schedule<'a, P, L, W> {
    protocol: &'a mut P,
    local: &'a mut L,
    console: &'a mut W,
}

struct Borrowed<'a, T>(&'a mut T);

#[cfg(target_os = "none")]
pub(crate) fn managed_owner_bytes<T: AsyncDatagramIo>() -> usize {
    const {
        assert!(
            core::mem::size_of::<ManagedConnection<'_, Borrowed<'_, T>, EnrolledDevice>>()
                <= 64 * 1024
        );
    }
    core::mem::size_of::<ManagedConnection<'_, Borrowed<'_, T>, EnrolledDevice>>()
}
impl<T: DatagramTransport> DatagramTransport for Borrowed<'_, T> {
    type Error = T::Error;
    fn fill_random(&mut self, bytes: &mut [u8]) -> bool {
        self.0.fill_random(bytes)
    }
}
impl<T: AsyncDatagramIo> AsyncDatagramIo for Borrowed<'_, T> {
    async fn recv(&mut self, bytes: &mut [u8]) -> Result<(usize, Endpoint), Self::Error> {
        self.0.recv(bytes).await
    }
    async fn send(&mut self, to: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.0.send(to, bytes).await
    }
}

async fn local_ready(
    timer: &mut impl AsyncTimer,
    console: &mut impl ConsoleWait,
    deadline: Option<u64>,
) -> Result<(), Error> {
    let mut console = pin!(console.wait());
    let mut timer = pin!(async {
        if let Some(due) = deadline {
            timer.wait_until(due).await;
        } else {
            core::future::pending::<()>().await;
        }
    });
    core::future::poll_fn(|context| {
        if let Poll::Ready(result) = console.as_mut().poll(context) {
            return Poll::Ready(result);
        }
        timer.as_mut().poll(context).map(|()| Ok(()))
    })
    .await
}

// Preserve the synchronous owner's retry policy, but never interpret a clock
// failure after acceptance as an unsent packet or regenerate an identity.
fn retryable<E, C>(error: &ManagedAsyncError<E, C>) -> bool {
    match error {
        ManagedAsyncError::State(
            ManagedError::Busy
            | ManagedError::NotConnected
            | ManagedError::Capacity
            | ManagedError::Recovery(_),
        )
        | ManagedAsyncError::Deadline
        | ManagedAsyncError::Call(AsyncCallError::ProgressRequired { .. }) => true,
        ManagedAsyncError::Recovery(RecoveryError::Bootstrap(PollError::Io(io))) => {
            matches!(io, AsyncIoError::Transport(_) | AsyncIoError::Deadline)
        }
        ManagedAsyncError::Recovery(_) => true,
        ManagedAsyncError::Application(coaptic::app::Error::Saturated) => true,
        ManagedAsyncError::Application(coaptic::app::Error::Io(DatagramIoError::Io(io))) => {
            matches!(io, AsyncIoError::Transport(_) | AsyncIoError::Deadline)
        }
        ManagedAsyncError::Call(AsyncCallError::Request(
            coaptic::app::Error::Saturated | coaptic::app::Error::Io(_),
        )) => true,
        _ => false,
    }
}

fn uncertain_completion<E, C>(error: &ManagedAsyncError<E, C>) -> bool {
    match error {
        ManagedAsyncError::Clock(_)
        | ManagedAsyncError::State(ManagedError::Clock)
        | ManagedAsyncError::Application(coaptic::app::Error::CommitAfterSend)
        | ManagedAsyncError::Call(
            AsyncCallError::ClockAfterSend(_)
            | AsyncCallError::ClockRegressedAfterSend { .. }
            | AsyncCallError::CommitAfterSend,
        ) => true,
        ManagedAsyncError::Application(coaptic::app::Error::Io(DatagramIoError::Io(io)))
        | ManagedAsyncError::Recovery(RecoveryError::Bootstrap(PollError::Io(io))) => {
            !matches!(io, AsyncIoError::Transport(_) | AsyncIoError::Deadline)
        }
        _ => false,
    }
}

/// Run USB management and native async network sessions, preserving durable custody.
pub async fn run_async<T: AsyncDatagramIo, S: Store, C: Console>(
    mut socket: T,
    random: fn(&mut [u8]) -> bool,
    mut clock: impl FnMut() -> Option<u64>,
    mut store: S,
    mut console: C,
    timers: (&mut impl AsyncTimer, &mut impl AsyncTimer),
    mut console_ready: impl ConsoleWait,
) -> Result<(), Error> {
    let mut schedule = Schedule {
        protocol: timers.0,
        local: timers.1,
        console: &mut console_ready,
    };
    let mut device = Device::recover(&mut store)?;
    if device.is_some() {
        console.event(1);
    }
    let mut decoder = ConsoleFrames::new();
    let mut clock = CheckedClock::new(|| clock().ok_or(()));
    let mut pending = None;
    let mut network_stopped = false;
    loop {
        crate::cooperate().await;
        let Some(now) = next_time(&mut clock)? else {
            return Ok(());
        };
        let request = if let Some(request) = pending.take() {
            Some(request)
        } else {
            receive(&mut console, &mut decoder, now)?
        };
        if let Some(request) = request {
            match request {
                CommissioningRequest::Inspect => {
                    send(
                        &mut console,
                        &device
                            .as_ref()
                            .map_or(CommissioningReply::Empty, Device::reply),
                    )?;
                }
                CommissioningRequest::Initialize { kid } => {
                    if device.is_some() {
                        send(&mut console, &CommissioningReply::Refused(1))?;
                    } else {
                        // An ambiguous identity write stops instead of returning to
                        // an apparent empty state and generating another key.
                        device = Some(Device::initialize(&mut store, kid, random)?);
                        console.event(2);
                        send(
                            &mut console,
                            &device.as_ref().ok_or(Error::Identity)?.reply(),
                        )?;
                    }
                }
                CommissioningRequest::Challenge => {
                    if let Some(device) = &mut device {
                        let challenge = device
                            .pairing
                            .begin(&device.identity, now, random)
                            .map_err(|_| Error::Protocol)?;
                        send(&mut console, &CommissioningReply::Challenge(challenge))?;
                    } else {
                        send(&mut console, &CommissioningReply::Refused(2))?;
                    }
                }
                CommissioningRequest::Update { update, endpoint } => {
                    let Some(device) = &mut device else {
                        send(&mut console, &CommissioningReply::Refused(2))?;
                        continue;
                    };
                    let next_endpoint = if update.is_recovery_configuration() {
                        device.endpoint
                    } else {
                        Some(endpoint)
                    };
                    let mut next = Zeroizing::new([0; STORE_BYTES]);
                    let mut next_len = 0;
                    let result = update.apply(&mut device.pairing, now, |old, record| {
                        if update.is_recovery() {
                            recovery_ready(&mut store, &device.private, &device.identity, old)?;
                        }
                        prepare_pending(
                            &mut store,
                            &device.private,
                            &device.identity,
                            old,
                            record,
                        )?;
                        next_len = encode_store(
                            &device.private,
                            device.identity.peer().kid(),
                            record,
                            next_endpoint,
                            &mut next,
                        )?;
                        store.commit(&device.stored[..device.stored_len], &next[..next_len])
                    });
                    match result {
                        Ok(()) => {
                            device.stored = next;
                            device.stored_len = next_len;
                            device.endpoint = next_endpoint;
                            network_stopped = false;
                            send(
                                &mut console,
                                &CommissioningReply::Committed(device.pairing.checkpoint().clone()),
                            )?;
                        }
                        Err(PairingCommitError::State(_)) => {
                            send(&mut console, &CommissioningReply::Refused(3))?
                        }
                        Err(PairingCommitError::Store(_)) => {
                            // No more network work after an uncertain write.
                            let _ = send(&mut console, &CommissioningReply::Refused(4));
                            return Err(Error::Storage);
                        }
                    }
                }
                CommissioningRequest::Restart => {
                    send(&mut console, &CommissioningReply::Restarting)?;
                    console.restart()?;
                    return Ok(());
                }
            }
        }
        if let Some(device) = &device
            && device.pairing.checkpoint().enabled()
            && !network_stopped
        {
            // Returning a management request drops all old protocol caches,
            // exchanges and sessions before any policy mutation above.
            let result = session_async(
                device,
                &mut store,
                &mut socket,
                random,
                &mut clock,
                &mut console,
                &mut decoder,
                &mut schedule,
            )
            .await;
            match result {
                Ok(Some(request)) => pending = Some(request),
                Ok(None) => return Ok(()),
                Err(Error::Network) => {
                    // Drop the failed volatile owner, but keep USB administration.
                    // Do not repeatedly discard protocol history on remote input:
                    // only an explicit restart or committed policy update resumes it.
                    network_stopped = true;
                    console.event(5);
                }
                Err(error) => return Err(error),
            }
        }
        if pending.is_none() {
            local_ready(
                schedule.local,
                schedule.console,
                decoder.last_byte.map(|last| last.saturating_add(1000)),
            )
            .await?;
        }
    }
}

// Keep synchronous owner construction out of the coroutine poll frame. Its
// temporary storage must not remain reserved during every network/console poll.
#[inline(never)]
fn connection<'a, T: AsyncDatagramIo>(
    device: &'a Device,
    socket: &'a mut T,
    random: fn(&mut [u8]) -> bool,
    endpoint: Endpoint,
    start: u64,
) -> Result<ManagedConnection<'a, Borrowed<'a, T>, EnrolledDevice>, Error> {
    let mut connection = ManagedConnection::<_, EnrolledDevice>::from_local_pairing(
        &device.identity,
        &device.pairing,
        endpoint,
        Borrowed(socket),
        random,
        start,
    )
    .map_err(|_| Error::Network)?;
    connection
        .observable_manual("identity")
        .map_err(|_| Error::Network)?;
    Ok(connection)
}

#[allow(clippy::too_many_arguments)]
async fn session_async<T: AsyncDatagramIo, F: FnMut() -> Result<u64, ()>>(
    device: &Device,
    store: &mut impl Store,
    socket: &mut T,
    random: fn(&mut [u8]) -> bool,
    clock: &mut CheckedClock<F>,
    console: &mut impl Console,
    decoder: &mut ConsoleFrames,
    schedule: &mut Schedule<'_, impl AsyncTimer, impl AsyncTimer, impl ConsoleWait>,
) -> Result<Option<CommissioningRequest>, Error> {
    let endpoint = device.endpoint.ok_or(Error::Storage)?;
    let peer = device
        .pairing
        .peer()
        .map_err(|_| Error::Network)?
        .principal();
    let initiates = device.identity.peer().principal().fingerprint() > peer.fingerprint();
    let permission = device
        .pairing
        .checkpoint()
        .policy()
        .ok_or(Error::Storage)?
        .resource_policy();
    let telemetry = *permission == permissions(true);
    let write = telemetry || *permission == echo_permissions();
    if !write && *permission != permissions(false) {
        return Err(Error::Permissions);
    }
    let mut pending = recover_pending(device, store, telemetry)?;
    let Some(start) = next_time(clock)? else {
        return Ok(None);
    };
    let mut connection = connection(device, socket, random, endpoint, start)?;
    let mut subscription = ManagedSubscription::new("identity");
    if initiates {
        match connection.connect(start) {
            Ok(())
            | Err(ManagedError::Recovery(_) | ManagedError::Busy | ManagedError::Capacity) => {}
            Err(_) => return Err(Error::Network),
        }
    }
    let mut retry_at = start.saturating_add(30_000);
    let mut next_probe = start;
    let mut call = None;
    let mut call_started = start;
    let mut connected_reported = false;
    let mut failed_polls = 0u8;
    let mut receive_errors = 0;
    let mut reply = [0; 128];
    let mut sample = [0; 61];
    sample[16..20].copy_from_slice(&[0x83, 1, 0x58, 32]);
    sample[20..52].copy_from_slice(device.identity.peer().principal().fingerprint());
    sample[52] = 0x1b;
    loop {
        crate::cooperate().await;
        let Some(now) = next_time(clock)? else {
            return Ok(None);
        };
        if let Some(request) = receive(console, decoder, now)? {
            if matches!(request, CommissioningRequest::Inspect) {
                send(console, &device.reply())?;
            } else {
                return Ok(Some(request));
            }
        }
        match connection
            .progress_with_async(
                now,
                &mut || clock.now_ms(),
                schedule.protocol,
                now.saturating_add(250),
                |_, request, _| {
                    if request.path() == ["identity"] && request.method() == Some(Method::Get) {
                        let response = Response::content_copy(
                            device.identity.peer().principal().fingerprint(),
                        )
                        .max_age(10);
                        if request.is_observe_register() {
                            response.observe(0)
                        } else {
                            response
                        }
                    } else if request.path() == ["echo"] && request.method() == Some(Method::Post) {
                        if !write {
                            Response::new(Code::FORBIDDEN)
                        } else if request.payload().len() > 128 {
                            Response::new(Code::REQUEST_ENTITY_TOO_LARGE)
                        } else {
                            Response::content_copy(request.payload())
                        }
                    } else {
                        Response::new(Code::NOT_FOUND)
                    }
                },
            )
            .await
        {
            Ok(()) => failed_polls = 0,
            Err(ref error) if retryable(error) => {}
            Err(ref error) if uncertain_completion(error) => return Err(Error::Network),
            Err(ManagedAsyncError::Clock(_)) => return Err(Error::Clock),
            Err(_) => {
                failed_polls = failed_polls.saturating_add(1);
                if failed_polls >= 32 {
                    return Err(Error::Network);
                }
            }
        }
        let Some(now) = next_time(clock)? else {
            return Ok(None);
        };
        if connection.is_connected() {
            match connection.take_subscription_response_into(&mut subscription, &mut reply, now) {
                Ok(Some(Ok(response)))
                    if response.code() == Code::CONTENT
                        && response.payload() == peer.fingerprint() => {}
                Ok(None) => {}
                Ok(Some(_)) => retry_at = now,
                Err(
                    ManagedError::Busy | ManagedError::NotConnected | ManagedError::StaleHandle,
                ) => {}
                Err(_) => return Err(Error::Network),
            }
            match connection
                .poll_subscription_async(
                    &mut subscription,
                    now,
                    &mut || clock.now_ms(),
                    schedule.protocol,
                    now.saturating_add(250),
                )
                .await
            {
                Ok(_) => {}
                Err(ref error) if retryable(error) => {}
                Err(_) => return Err(Error::Network),
            }
        }
        let Some(now) = next_time(clock)? else {
            return Ok(None);
        };
        let response = if let Some(current) = call {
            match connection.take_response_into(current, &mut reply, now) {
                Ok(response) => response,
                Err(ManagedError::StaleHandle) => {
                    call = None;
                    next_probe = now;
                    None
                }
                Err(_) => return Err(Error::Network),
            }
        } else {
            None
        };
        if let Some(response) = response {
            call = None;
            match response {
                Ok(response)
                    if accept_sample(
                        &mut pending,
                        response.code(),
                        response.payload(),
                        if write {
                            &sample[16..]
                        } else {
                            peer.fingerprint()
                        },
                    )? =>
                {
                    if !connected_reported {
                        console.event(3);
                        connected_reported = true;
                    }
                    console.event(4);
                    next_probe = now.saturating_add(5_000);
                    retry_at = u64::MAX;
                }
                _ => {
                    // A completed protected call's liveness failure permits
                    // a fresh handshake; keep this owner's MID/cache history.
                    retry_at = now;
                    next_probe = now.saturating_add(5_000);
                }
            }
        }
        if let Some(current) = call
            && now.saturating_sub(call_started) >= 10_000
        {
            connection
                .cancel(current, now)
                .map_err(|_| Error::Network)?;
            call = None;
            retry_at = now;
            next_probe = now.saturating_add(5_000);
        }
        if initiates && call.is_none() && now >= retry_at {
            match connection.connect(now) {
                Ok(()) => retry_at = now.saturating_add(30_000),
                Err(ManagedError::Busy | ManagedError::Capacity) => {
                    retry_at = now.saturating_add(1_000)
                }
                Err(_) => retry_at = now.saturating_add(5_000),
            }
        }
        if call.is_none() && connection.is_connected() && now >= next_probe {
            if let Some(snapshot) = connection.diagnostic_snapshot(now) {
                console.diagnostics(&snapshot);
            }
            // Durable telemetry retains exact operation bytes until a matching receipt.
            // Read-only pairing uses an authenticated identity read instead.
            prepare_sample(&mut pending, &mut sample, now, random)?;
            let (method, path, payload, format) = if telemetry {
                (
                    Method::Post,
                    "telemetry",
                    &sample[..],
                    Some(ContentFormat::CBOR),
                )
            } else if write {
                (
                    Method::Post,
                    "echo",
                    &sample[16..],
                    Some(ContentFormat::CBOR),
                )
            } else {
                (Method::Get, "identity", &[][..], None)
            };
            match connection
                .request_async(
                    method,
                    path,
                    payload,
                    format,
                    now,
                    &mut || clock.now_ms(),
                    schedule.protocol,
                    now.saturating_add(250),
                )
                .await
            {
                Ok(request) => {
                    call = Some(request);
                    call_started = now;
                }
                Err(ref error) if retryable(error) => {
                    // Observe and application calls share the bounded packet pools.
                    // Admission pressure leaves the session intact and retries later.
                    next_probe = now.saturating_add(1_000);
                }
                Err(_) => return Err(Error::Network),
            }
        }
        let Some(wait_at) = next_time(clock)? else {
            return Ok(None);
        };
        let mut deadline = decoder.last_byte.map(|last| last.saturating_add(1000));
        let mut include = |value| {
            deadline = Some(deadline.map_or(value, |old| old.min(value)));
        };
        if call.is_some() {
            include(call_started.saturating_add(10_000));
        }
        if initiates && call.is_none() {
            include(retry_at);
        }
        if connection.is_connected() && call.is_none() {
            include(next_probe);
        }
        if let Some(due) = connection.next_subscription_poll_at(&subscription, wait_at) {
            include(due);
        }
        let mut local_error = None;
        let wake = connection
            .wait_async(wait_at, schedule.protocol, async {
                if let Err(error) = local_ready(schedule.local, schedule.console, deadline).await {
                    local_error = Some(error);
                }
            })
            .await;
        if matches!(&wake, Err(ManagedError::Clock)) {
            return Err(Error::Network);
        }
        if crate::receive_failed(&wake, &mut receive_errors) {
            return Err(Error::Network);
        }
        if let Some(error) = local_error {
            return Err(error);
        }
    }
}
