//! Async qualification services using the same routes, bounded profile and durable barriers.
use super::*;
use coaptic::app::{AsyncIoError, Error as AppError};
use coaptic::platform::AsyncTimer;
use coaptic::storage::{AsyncDatagramIo, DatagramIoError};

// Transport acceptance followed by a failed clock is never treated as a
// retryable non-send. Stop this owner; its durable state is not regenerated.
fn reject_clock_failure<R, E, C>(
    result: &Result<R, AppError<AsyncIoError<E, C>>>,
) -> Result<(), &'static str> {
    match result {
        Err(
            AppError::CommitAfterSend
            | AppError::Io(DatagramIoError::Io(
                AsyncIoError::ClockBeforeSend(_)
                | AsyncIoError::ClockAfterSend(_)
                | AsyncIoError::ClockRegressedBeforeSend { .. }
                | AsyncIoError::ClockRegressedAfterSend { .. },
            )),
        ) => Err("clock or commit failure"),
        _ => Ok(()),
    }
}

/// Run the unprotected service with readiness and independent protocol/local timers.
pub async fn run_async<T: AsyncDatagramIo>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    mut clock: impl FnMut() -> Option<u64>,
    id: &[u8; 32],
    timers: (&mut impl AsyncTimer, &mut impl AsyncTimer),
) -> Result<(), &'static str> {
    let (protocol_timer, local_timer) = timers;
    let _owner = claim(id)?;
    let mut app = App::profile::<profiles::Constrained>()
        .randomness(random)
        .allow_unprotected()
        .block_wise::<true>()
        .route("identity", get(identity))
        .route("test", get(test))
        .route("echo", post(echo))
        .route("upload", post(upload))
        .route("large", get(large))
        .route("ticks", get(ticks))
        .well_known_core()
        .bind(io)
        .map_err(|_| "bind")?;
    let mut next = 0;
    let mut confirm_at = 0;
    let mut errors = 0;
    let mut receive_errors = 0;
    let mut tick = 0u32;
    let mut clock = CheckedClock::new(|| clock().ok_or(()));
    while let Some(now) = next_time(&mut clock)? {
        crate::cooperate().await;
        let result = app
            .progress_async(
                now,
                &mut || clock.now_ms(),
                protocol_timer,
                now.saturating_add(250),
            )
            .await;
        reject_clock_failure(&result)?;
        if result.is_err() {
            errors += 1;
            if errors >= 32 {
                return Err("poll failures");
            }
        } else {
            errors = 0;
        }
        let Some(now) = next_time(&mut clock)? else {
            return Ok(());
        };
        if now >= next {
            tick = tick.wrapping_add(1);
            TICKS.store(tick, Ordering::Relaxed);
            let response = Response::content_copy(&tick.to_be_bytes());
            if now >= confirm_at {
                // Keep CON due while pacing prevents delivery or the transport fails.
                let notified = app
                    .notify_confirmable_async(
                        now,
                        &["ticks"],
                        response,
                        &mut || clock.now_ms(),
                        protocol_timer,
                        now.saturating_add(250),
                    )
                    .await;
                reject_clock_failure(&notified)?;
                if notified.is_ok_and(|n| n > 0) {
                    confirm_at = now.saturating_add(OBSERVE_CONFIRM_MS);
                }
            } else {
                let notified = app
                    .notify_async(
                        now,
                        &["ticks"],
                        response,
                        &mut || clock.now_ms(),
                        protocol_timer,
                        now.saturating_add(250),
                    )
                    .await;
                reject_clock_failure(&notified)?;
            }
            next = now.saturating_add(250);
        }
        let Some(wait_at) = next_time(&mut clock)? else {
            return Ok(());
        };
        let wake = app
            .wait_async(wait_at, protocol_timer, local_timer.wait_until(next))
            .await;
        if crate::receive_failed(&wake, &mut receive_errors) {
            return Err("receive");
        }
    }
    Ok(())
}

/// Recover and run the protected service; checkpoint refusal stops before dispatch.
#[cfg(feature = "oscore")]
pub async fn run_protected_async<T: AsyncDatagramIo, S: crate::security_state::Store>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    mut clock: impl FnMut() -> Option<u64>,
    id: &[u8; 32],
    timers: (&mut impl AsyncTimer, &mut impl AsyncTimer),
    credentials: &crate::security_state::Credentials,
    store: S,
) -> Result<(), &'static str> {
    let (protocol_timer, local_timer) = timers;
    let _owner = claim(id)?;
    let (mut state, context) = crate::security_state::State::recover(store, credentials)
        .map_err(|_| "security recovery")?;
    let mut app = App::profile::<profiles::Constrained>()
        .randomness(random)
        .block_wise::<true>()
        .oscore(context)
        .require_oscore_checkpoint()
        .route("identity", get(identity))
        .route("test", get(test))
        .route("echo", post(echo))
        .route("upload", post(upload))
        .route("large", get(large))
        .route("ticks", get(ticks))
        .well_known_core()
        .bind(io)
        .map_err(|_| "bind")?;
    let mut next = 0;
    let mut confirm_at = 0;
    let mut errors = 0;
    let mut receive_errors = 0;
    let mut tick = 0u32;
    let mut clock = CheckedClock::new(|| clock().ok_or(()));
    while let Some(now) = next_time(&mut clock)? {
        crate::cooperate().await;
        let context = app.oscore().ok_or("missing security context")?;
        let remaining = context
            .sender_reservation_end()
            .ok_or("unguarded sender")?
            .saturating_sub(context.sender_seq());
        if remaining < 8 {
            state
                .refill(app.oscore_mut().ok_or("missing security context")?)
                .map_err(|_| "sender reservation")?;
        }
        let mut failed = false;
        let result = app
            .progress_with_oscore_checkpoint_async(
                now,
                &mut || clock.now_ms(),
                protocol_timer,
                now.saturating_add(250),
                |checkpoint| {
                    let success = state.checkpoint(checkpoint).is_ok();
                    failed |= !success;
                    success
                },
            )
            .await;
        reject_clock_failure(&result)?;
        if failed {
            return Err("security checkpoint");
        }
        if result.is_err() {
            errors += 1;
            if errors >= 32 {
                return Err("poll failures");
            }
        } else {
            errors = 0;
        }
        let Some(now) = next_time(&mut clock)? else {
            return Ok(());
        };
        if now >= next {
            tick = tick.wrapping_add(1);
            TICKS.store(tick, Ordering::Relaxed);
            // notify does not receive or dispatch; sender range is already granted.
            let response = Response::content_copy(&tick.to_be_bytes());
            if now >= confirm_at {
                if app
                    .notify_confirmable_async(
                        now,
                        &["ticks"],
                        response,
                        &mut || clock.now_ms(),
                        protocol_timer,
                        now.saturating_add(250),
                    )
                    .await
                    .map_err(|_| "notification")?
                    > 0
                {
                    confirm_at = now.saturating_add(OBSERVE_CONFIRM_MS);
                }
            } else {
                app.notify_async(
                    now,
                    &["ticks"],
                    response,
                    &mut || clock.now_ms(),
                    protocol_timer,
                    now.saturating_add(250),
                )
                .await
                .map_err(|_| "notification")?;
            }
            next = now.saturating_add(250);
        }
        let Some(wait_at) = next_time(&mut clock)? else {
            return Ok(());
        };
        let wake = app
            .wait_async(wait_at, protocol_timer, local_timer.wait_until(next))
            .await;
        if crate::receive_failed(&wake, &mut receive_errors) {
            return Err("receive");
        }
    }
    Ok(())
}
