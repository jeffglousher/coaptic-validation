//! One retained telemetry operation over caller-owned protected I/O.
//!
//! The caller exclusively owns both records and installs the trusted mapping
//! from service endpoint/credentials to principal and resource. This is a
//! pairwise qualification adapter, not enrollment or a current-policy provider.
//! Each invocation sends at most one operation. A stopped/failed invocation
//! leaves pending work for explicit recovery; it never invents a replacement ID.
#![forbid(unsafe_code)]

use crate::{pending_telemetry, security_state};
use coaptic::platform::CheckedClock;
use coaptic::provisioning::{Principal, Receipt, TelemetryOperation};
use coaptic::storage::DatagramIo;
use coaptic::{App, Code, ContentFormat, Endpoint, profiles};

/// Caller-installed intended-service binding, checked before network access.
pub struct Service<'a> {
    pub endpoint: Endpoint,
    pub principal: Principal,
    pub resource: [u8; 32],
    pub credentials: &'a security_state::Credentials,
    /// Nonzero maximum elapsed time for this attempt, including a separate reply.
    pub timeout_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Pending(pending_telemetry::Error),
    Security(security_state::Error),
    NoPending,
    Resource,
    Bind,
    Stopped,
    Clock,
    Send,
    /// A datagram was accepted before its clock or local commit failed.
    /// Pending durable work remains for explicit recovery; delivery is uncertain.
    AfterSend,
    Checkpoint,
    Poll,
    Response,
    Refused,
    Deadline,
}

/// Recover, send the complete pending operation, and durably accept its receipt.
///
/// The application envelope is the 16-byte operation ID followed by the complete
/// payload at `telemetry`, with its original Content-Format. The service's trusted
/// route mapping supplies the resource identity; the receipt binds all of these
/// values. The authenticated response must be 2.04 and exactly one valid receipt.
/// Clock `None` requests a clean stop with pending work retained. A clock error,
/// failed checkpoint, expired deadline or 32 consecutive poll failures stops work.
/// A recovered completion returns without network I/O. No storage is initialized.
///
/// Storage commit/readback guarantees and monotonic time remain caller duties.
/// This routine establishes neither flash power-loss nor hostile rollback safety.
pub fn run<T: DatagramIo, S: security_state::Store, P: pending_telemetry::Store>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    mut clock: impl FnMut() -> Option<u64>,
    service: Service<'_>,
    security: S,
    pending: P,
) -> Result<Receipt, Error> {
    if service.timeout_ms == 0 {
        return Err(Error::Deadline);
    }
    let mut pending =
        pending_telemetry::Pending::recover(pending, service.credentials, service.principal)
            .map_err(Error::Pending)?;
    if pending
        .retained_resource()
        .map_err(Error::Pending)?
        .is_some_and(|resource| resource != service.resource)
    {
        return Err(Error::Resource);
    }
    if let Some(receipt) = pending.completion().map_err(Error::Pending)? {
        return Ok(receipt);
    }
    let operation = pending
        .pending()
        .map_err(Error::Pending)?
        .ok_or(Error::NoPending)?;
    let mut wire = [0; 16 + TelemetryOperation::MAX_PAYLOAD];
    wire[..16].copy_from_slice(operation.id().as_bytes());
    let length = 16 + operation.payload().len();
    wire[16..length].copy_from_slice(operation.payload());
    let format = operation.content_format();
    let (mut security, context) =
        security_state::State::recover(security, service.credentials).map_err(Error::Security)?;
    let mut app = App::profile::<profiles::Constrained>()
        .block_wise::<false>()
        .randomness(random)
        .oscore(context)
        .require_oscore_checkpoint()
        .bind(io)
        .map_err(|_| Error::Bind)?;
    let mut clock = CheckedClock::new(|| clock().ok_or(()));
    let now = next_time(&mut clock)?;
    let deadline = now.checked_add(service.timeout_ms).ok_or(Error::Deadline)?;
    let mut request = app
        .post("telemetry")
        .to(service.endpoint)
        .deadline(deadline)
        .payload(&wire[..length]);
    if let Some(format) = format {
        request = request.content_format(ContentFormat::new(format));
    }
    let call = request.send(now).map_err(|_| Error::Send)?;
    let mut failures = 0;
    let mut output = [0; 56];
    loop {
        let now = next_time(&mut clock)?;
        if now >= deadline {
            return Err(Error::Deadline);
        }
        let mut failed = false;
        let result = app.poll_with_oscore_checkpoint(now, |checkpoint| {
            let success = security.checkpoint(checkpoint).is_ok();
            failed |= !success;
            success
        });
        if failed {
            return Err(Error::Checkpoint);
        }
        if result.is_err() {
            failures += 1;
            if failures == 32 {
                return Err(Error::Poll);
            }
        } else {
            failures = 0;
        }
        if let Some(response) = app
            .take_response_into(call, &mut output)
            .map_err(|_| Error::Response)?
        {
            let response = response.map_err(|_| Error::Response)?;
            if response.code() != Code::CHANGED {
                return Err(Error::Refused);
            }
            // App binds this complete response to the intended peer's protected
            // outgoing call. Storage validates operation ID/content before commit.
            return pending
                .accept_authenticated_receipt(response.payload())
                .map_err(Error::Pending);
        }
    }
}

/// Native async equivalent of [`run`], with timer-bounded sends and retained ingress.
/// Cancellation preserves the authenticated pending operation and never generates a new ID.
#[cfg(feature = "async-network")]
pub async fn run_async<
    T: coaptic::storage::AsyncDatagramIo,
    S: security_state::Store,
    P: pending_telemetry::Store,
>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    mut clock: impl FnMut() -> Option<u64>,
    service: Service<'_>,
    security: S,
    pending: P,
    timers: (
        &mut impl coaptic::platform::AsyncTimer,
        &mut impl coaptic::platform::AsyncTimer,
    ),
) -> Result<Receipt, Error> {
    let (protocol_timer, local_timer) = timers;
    if service.timeout_ms == 0 {
        return Err(Error::Deadline);
    }
    let mut pending =
        pending_telemetry::Pending::recover(pending, service.credentials, service.principal)
            .map_err(Error::Pending)?;
    if pending
        .retained_resource()
        .map_err(Error::Pending)?
        .is_some_and(|resource| resource != service.resource)
    {
        return Err(Error::Resource);
    }
    if let Some(receipt) = pending.completion().map_err(Error::Pending)? {
        return Ok(receipt);
    }
    let operation = pending
        .pending()
        .map_err(Error::Pending)?
        .ok_or(Error::NoPending)?;
    let mut wire = [0; 16 + TelemetryOperation::MAX_PAYLOAD];
    wire[..16].copy_from_slice(operation.id().as_bytes());
    let length = 16 + operation.payload().len();
    wire[16..length].copy_from_slice(operation.payload());
    let format = operation.content_format();
    let (mut security, context) =
        security_state::State::recover(security, service.credentials).map_err(Error::Security)?;
    let mut app = App::profile::<profiles::Constrained>()
        .block_wise::<false>()
        .randomness(random)
        .oscore(context)
        .require_oscore_checkpoint()
        .bind(io)
        .map_err(|_| Error::Bind)?;
    let mut clock = CheckedClock::new(|| clock().ok_or(()));
    let now = next_time(&mut clock)?;
    let deadline = now.checked_add(service.timeout_ms).ok_or(Error::Deadline)?;
    let mut request = app
        .post("telemetry")
        .to(service.endpoint)
        .deadline(deadline)
        .payload(&wire[..length]);
    if let Some(format) = format {
        request = request.content_format(ContentFormat::new(format));
    }
    let call = request
        .send_async(now, || clock.now_ms(), protocol_timer)
        .await
        .map_err(|error| match error {
            coaptic::app::AsyncCallError::ClockAfterSend(_)
            | coaptic::app::AsyncCallError::ClockRegressedAfterSend { .. }
            | coaptic::app::AsyncCallError::CommitAfterSend => Error::AfterSend,
            coaptic::app::AsyncCallError::Request(coaptic::app::Error::DeadlineElapsed) => {
                Error::Deadline
            }
            _ => Error::Send,
        })?;
    let mut failures = 0;
    let mut output = [0; 56];
    loop {
        crate::cooperate().await;
        let now = next_time(&mut clock)?;
        if now >= deadline {
            return Err(Error::Deadline);
        }
        let mut failed = false;
        let result = app
            .progress_with_oscore_checkpoint_async(
                now,
                &mut || clock.now_ms(),
                protocol_timer,
                deadline,
                |checkpoint| {
                    let success = security.checkpoint(checkpoint).is_ok();
                    failed |= !success;
                    success
                },
            )
            .await;
        if failed {
            return Err(Error::Checkpoint);
        }
        use coaptic::{
            app::{AsyncIoError, Error as AppError},
            storage::DatagramIoError,
        };
        match &result {
            Err(
                AppError::CommitAfterSend
                | AppError::Io(DatagramIoError::Io(
                    AsyncIoError::ClockAfterSend(_) | AsyncIoError::ClockRegressedAfterSend { .. },
                )),
            ) => return Err(Error::AfterSend),
            Err(AppError::Io(DatagramIoError::Io(
                AsyncIoError::ClockBeforeSend(_) | AsyncIoError::ClockRegressedBeforeSend { .. },
            ))) => return Err(Error::Clock),
            _ => {}
        }
        if result.is_err() {
            failures += 1;
            if failures == 32 {
                return Err(Error::Poll);
            }
        } else {
            failures = 0;
        }
        if let Some(response) = app
            .take_response_into(call, &mut output)
            .map_err(|_| Error::Response)?
        {
            let response = response.map_err(|_| Error::Response)?;
            if response.code() != Code::CHANGED {
                return Err(Error::Refused);
            }
            // App binds this complete response to the intended peer's protected
            // outgoing call. Storage validates operation ID/content before commit.
            return pending
                .accept_authenticated_receipt(response.payload())
                .map_err(Error::Pending);
        }
        let now = next_time(&mut clock)?;
        if now >= deadline {
            return Err(Error::Deadline);
        }
        app.wait_async(now, protocol_timer, local_timer.wait_until(deadline))
            .await
            .map_err(|_| Error::Poll)?;
    }
}

fn next_time<F: FnMut() -> Result<u64, ()>>(clock: &mut CheckedClock<F>) -> Result<u64, Error> {
    clock.now_ms().map_err(|error| match error {
        coaptic::platform::ClockError::Source(()) => Error::Stopped,
        coaptic::platform::ClockError::Regressed { .. } => Error::Clock,
    })
}
