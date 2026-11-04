//! Native async counterpart of the same finite reads. Awaited transport work is
//! included in preparation/progress; readiness suspension is included in wait.
use super::*;
use coaptic::platform::AsyncTimer;
use coaptic::storage::AsyncDatagramIo;

/// Execute the same 24 unprotected reads through native async I/O and timers.
#[allow(clippy::too_many_arguments)]
pub async fn run_unprotected_async<T: AsyncDatagramIo>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    now_ns: impl FnMut() -> Option<u64>,
    timers: (&mut impl AsyncTimer, &mut impl AsyncTimer),
    peer: Endpoint,
    identity: &[u8; 32],
    mut observe: impl FnMut(Observation) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    validate_identity(identity)?;
    let mut clock = Clock {
        source: now_ns,
        previous: 0,
    };
    clock.now()?;
    let mut app = App::profile::<profiles::Constrained>()
        .block_wise::<true>()
        .full_responses()
        .randomness(random)
        .allow_unprotected()
        .bind(io)
        .map_err(|_| "campaign bind")?;
    observe(Observation::Preparation {
        recovery_ns: 0,
        app_bytes: core::mem::size_of_val(&app),
    })?;
    run_operations(
        &mut app,
        &mut (),
        &mut clock,
        timers,
        peer,
        identity,
        observe,
    )
    .await
}

/// Execute the protected reads without resetting or provisioning durable state.
/// As in the synchronous initiator, replay state is checkpointed after each
/// progress pass and before collecting a response. No service routes are installed.
#[cfg(feature = "oscore")]
#[allow(clippy::too_many_arguments)]
pub async fn run_async<T: AsyncDatagramIo, S: Store>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    now_ns: impl FnMut() -> Option<u64>,
    timers: (&mut impl AsyncTimer, &mut impl AsyncTimer),
    credentials: &Credentials,
    store: S,
    peer: Endpoint,
    identity: &[u8; 32],
    mut observe: impl FnMut(Observation) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    validate_identity(identity)?;
    let mut clock = Clock {
        source: now_ns,
        previous: 0,
    };
    let began = clock.now()?;
    let (mut state, context) =
        State::recover(store, credentials).map_err(|_| "campaign security recovery")?;
    let recovery_ns = clock.now()? - began;
    let mut app = App::profile::<profiles::Constrained>()
        .block_wise::<true>()
        .full_responses()
        .randomness(random)
        .oscore(context)
        .bind(io)
        .map_err(|_| "campaign bind")?;
    observe(Observation::Preparation {
        recovery_ns,
        app_bytes: core::mem::size_of_val(&app),
    })?;
    run_operations(
        &mut app, &mut state, &mut clock, timers, peer, identity, observe,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_operations<T: AsyncDatagramIo>(
    app: &mut CampaignApp<T>,
    security: &mut impl SecurityPolicy<T>,
    clock: &mut Clock<impl FnMut() -> Option<u64>>,
    timers: (&mut impl AsyncTimer, &mut impl AsyncTimer),
    peer: Endpoint,
    identity: &[u8; 32],
    mut observe: impl FnMut(Observation) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let (protocol_timer, local_timer) = timers;
    let mut output = [0; 4096];
    for iteration in 0..8 {
        for (path, expected) in [
            ("identity", &identity[..]),
            ("test", &b"coaptic"[..]),
            ("large", &[0x5a; 2000][..]),
        ] {
            if security.needs_refill(app)? {
                let start = clock.now()?;
                security.refill(app)?;
                observe(Observation::Reservation {
                    elapsed_ns: clock.now()? - start,
                })?;
            }
            let start = clock.now()?;
            let deadline = start
                .checked_add(TIMEOUT_NS)
                .ok_or("campaign deadline overflow")?
                / 1_000_000;
            let call = app
                .get(path)
                .to(peer)
                .deadline(deadline)
                .send_async(
                    start / 1_000_000,
                    || clock.now().map(|now| now / 1_000_000),
                    protocol_timer,
                )
                .await
                .map_err(|_| "campaign request")?;
            let mut op = Operation {
                iteration,
                path,
                bytes: expected.len(),
                start_ns: start,
                elapsed_ns: 0,
                prepare_ns: clock.now()? - start,
                poll_ns: 0,
                checkpoint_ns: 0,
                take_ns: 0,
                verify_ns: 0,
                wait_ns: 0,
                polls: 0,
            };
            loop {
                crate::cooperate().await;
                let phase = clock.now()?;
                if phase - start >= TIMEOUT_NS || op.polls == POLL_LIMIT {
                    return Err("campaign deadline/poll bound");
                }
                app.progress_async(
                    phase / 1_000_000,
                    &mut || clock.now().map(|now| now / 1_000_000),
                    protocol_timer,
                    deadline,
                )
                .await
                .map_err(|_| "campaign poll")?;
                let after_poll = clock.now()?;
                op.poll_ns += after_poll - phase;
                op.polls += 1;
                security.checkpoint(app)?;
                let after_checkpoint = clock.now()?;
                op.checkpoint_ns += after_checkpoint - after_poll;
                let reply = app
                    .take_response_into(call, &mut output)
                    .map_err(|_| "campaign output")?;
                let after_take = clock.now()?;
                op.take_ns += after_take - after_checkpoint;
                if let Some(reply) = reply {
                    let reply = reply.map_err(|_| "campaign response")?;
                    verify(&reply, expected)?;
                    let end = clock.now()?;
                    if end - start >= TIMEOUT_NS {
                        return Err("campaign deadline/poll bound");
                    }
                    op.verify_ns = end - after_take;
                    op.elapsed_ns = end - start;
                    observe(Observation::Operation(op))?;
                    break;
                }
                let before_wait = clock.now()?;
                if before_wait - start >= TIMEOUT_NS {
                    return Err("campaign deadline/poll bound");
                }
                app.wait_async(
                    before_wait / 1_000_000,
                    protocol_timer,
                    local_timer.wait_until(deadline),
                )
                .await
                .map_err(|_| "campaign receive")?;
                op.wait_ns += clock.now()? - before_wait;
            }
        }
    }
    Ok(())
}
