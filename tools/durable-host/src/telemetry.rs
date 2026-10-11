//! Finite protected telemetry service using one caller-installed pairwise binding.
//!
//! This qualification fixture trusts the caller's credential-to-principal mapping
//! and current policy provider. It performs no enrollment or identity discovery.
//! Journal effects are complete telemetry rows, not external actuator effects.
#![forbid(unsafe_code)]
use crate::{Journal, Policy};
use coaptic::message::OptionNumber;
use coaptic::platform::CheckedClock;
use coaptic::provisioning::{OperationId, ReceiptError, ReceiptStore, TelemetryOperation};
use coaptic::storage::DatagramIo;
use coaptic::{App, Code, ContentFormat, Endpoint, Response, resources};
use coaptic_esphome_probe::security_state::{self, Credentials, State, Store};

/// Explicit trusted fixture binding and work limits. No defaults authorize peers.
pub struct Binding<'a> {
    pub peer: Endpoint,
    pub credentials: &'a Credentials,
    pub policy: Policy,
    pub content_format: Option<u16>,
    pub timeout_ms: u64,
    pub max_polls: u32,
    /// Qualification fault: commit the first operation but withhold its receipt.
    pub drop_first_receipt: bool,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    pub polls: u32,
    pub admitted: u32,
    pub refused: u32,
    pub poll_errors: u32,
    pub receipts: u32,
    pub dropped_receipts: u32,
    pub effects: usize,
}
#[derive(Debug)]
pub enum Error {
    Bounds,
    Clock,
    Security(security_state::Error),
    Bind,
    Ready,
    Checkpoint,
    Poll,
    Journal(crate::Error),
    Send,
}

/// Restore durable security state, then serve until stop, deadline or poll budget.
///
/// `None` from the clock is a clean stop. Clock regression, persistence failure,
/// or 32 consecutive poll errors stops the session. Callbacks must finish in
/// bounded time. Missing state is never initialized. Requests are single complete
/// datagrams: all Block1/Q-Block1 options are refused rather than journaling a
/// fragment. Authenticated requests require the exact peer, POST path, format and
/// 16-byte ID plus at most 1024 payload bytes. The journal authorizes each commit.
/// Receipts are sent only after its effect/receipt transaction has been synced.
/// A send failure requires recovery of the same operation, never a new ID.
pub fn run<T: DatagramIo, S: Store>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    clock: impl FnMut() -> Option<u64>,
    binding: Binding<'_>,
    security: S,
    journal: &mut Journal,
) -> Result<Report, Error> {
    run_inner(
        io,
        random,
        clock,
        binding,
        security,
        journal,
        None::<fn() -> bool>,
    )
}

/// Like [`run`], with a bounded readiness callback after security recovery and
/// application binding, before network polling. The original deadline includes
/// initialization: expired or stopped initialization never announces readiness.
/// Returning false from `ready` refuses service without network I/O.
pub fn run_with_ready<T: DatagramIo, S: Store>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    clock: impl FnMut() -> Option<u64>,
    binding: Binding<'_>,
    security: S,
    journal: &mut Journal,
    ready: impl FnOnce() -> bool,
) -> Result<Report, Error> {
    run_inner(io, random, clock, binding, security, journal, Some(ready))
}

fn run_inner<T: DatagramIo, S: Store>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    mut clock: impl FnMut() -> Option<u64>,
    binding: Binding<'_>,
    security: S,
    journal: &mut Journal,
    ready: Option<impl FnOnce() -> bool>,
) -> Result<Report, Error> {
    if binding.timeout_ms == 0 || binding.max_polls == 0 {
        return Err(Error::Bounds);
    }
    let mut report = Report::default();
    let mut clock = CheckedClock::new(|| clock().ok_or(()));
    let started = match clock.now_ms() {
        Ok(now) => now,
        Err(coaptic::platform::ClockError::Source(())) => {
            report.effects = journal.effects().map_err(Error::Journal)?;
            return Ok(report);
        }
        Err(_) => return Err(Error::Clock),
    };
    let deadline = started
        .checked_add(binding.timeout_ms)
        .ok_or(Error::Bounds)?;
    let (mut security, context) =
        State::recover(security, binding.credentials).map_err(Error::Security)?;
    let mut app = App::with_resources(resources::SmallDevice::new().deferred::<1>())
        .randomness(random)
        .oscore(context)
        .require_oscore_checkpoint()
        .bind(io)
        .map_err(|_| Error::Bind)?;
    if let Some(ready) = ready {
        let now = match clock.now_ms() {
            Ok(now) => Some(now),
            Err(coaptic::platform::ClockError::Source(())) => None,
            Err(_) => return Err(Error::Clock),
        };
        if now.is_none_or(|now| now >= deadline) {
            report.effects = journal.effects().map_err(Error::Journal)?;
            return Ok(report);
        }
        if !ready() {
            return Err(Error::Ready);
        }
    }
    let mut failures = 0;
    while report.polls < binding.max_polls {
        let now = match clock.now_ms() {
            Ok(now) => now,
            Err(coaptic::platform::ClockError::Source(())) => break,
            Err(_) => return Err(Error::Clock),
        };
        if now >= deadline {
            break;
        }
        let context = app.oscore_mut().ok_or(Error::Bind)?;
        if context
            .sender_reservation_end()
            .is_some_and(|end| end.saturating_sub(context.sender_seq()) < 4)
        {
            security.refill(context).map_err(Error::Security)?;
        }
        let mut work = None;
        let mut body = [0; TelemetryOperation::MAX_PAYLOAD];
        let mut checkpoint_failed = false;
        report.polls += 1;
        let result = app.poll_with_oscore_checkpoint_and_dispatch(
            now,
            |checkpoint| {
                let success = security.checkpoint(checkpoint).is_ok();
                checkpoint_failed |= !success;
                success
            },
            |request, handle| {
                let payload = request.payload();
                if request.peer() != binding.peer
                    || request.code() != Code::POST
                    || request.path() != ["telemetry"]
                    || request.content_format()
                        != binding.content_format.map(|f| Ok(ContentFormat::new(f)))
                    || request.get_option(OptionNumber::BLOCK1).is_some()
                    || request.get_option(OptionNumber::Q_BLOCK1).is_some()
                    || !(16..=16 + TelemetryOperation::MAX_PAYLOAD).contains(&payload.len())
                {
                    report.refused += 1;
                    return Response::new(Code::BAD_REQUEST);
                }
                let Some(handle) = handle else {
                    report.refused += 1;
                    return Response::new(Code::SERVICE_UNAVAILABLE);
                };
                let id = OperationId::new(payload[..16].try_into().expect("checked length"));
                body[..payload.len() - 16].copy_from_slice(&payload[16..]);
                work = Some((handle, id, payload.len() - 16));
                report.admitted += 1;
                Response::deferred()
            },
        );
        if checkpoint_failed {
            return Err(Error::Checkpoint);
        }
        if result.is_err() {
            report.poll_errors += 1;
            failures += 1;
            if failures == 32 {
                return Err(Error::Poll);
            }
        } else {
            failures = 0;
        }
        if let Some((handle, id, length)) = work {
            // Failure after dispatch (e.g. empty ACK send) still leaves admitted
            // work. Its durable transaction is performed once, then recovery is
            // explicit if completion cannot be transmitted.
            let operation = TelemetryOperation::new(
                id,
                binding.policy.resource,
                binding.content_format,
                &body[..length],
            )
            .map_err(|_| Error::Bounds)?;
            let response = match journal.commit(
                &binding.policy.anchor,
                &binding.policy.principal,
                &operation,
            ) {
                Ok(receipt) => {
                    if binding.drop_first_receipt && report.dropped_receipts == 0 {
                        if !app.cancel_deferred(handle) {
                            return Err(Error::Send);
                        }
                        report.dropped_receipts += 1;
                        continue;
                    }
                    report.receipts += 1;
                    Response::new(Code::CHANGED).payload_copy(&receipt.encode())
                }
                Err(ReceiptError::Persistence(error)) => return Err(Error::Journal(error)),
                Err(error) => {
                    report.refused += 1;
                    Response::new(match error {
                        ReceiptError::Unauthorized => Code::FORBIDDEN,
                        ReceiptError::Capacity => Code::SERVICE_UNAVAILABLE,
                        _ => Code::BAD_REQUEST,
                    })
                }
            };
            app.complete(handle, response, now)
                .map_err(|_| Error::Send)?;
        }
    }
    report.effects = journal.effects().map_err(Error::Journal)?;
    Ok(report)
}
