//! Matched finite protected GET workload for host and constrained initiators.
//!
//! The caller owns transport, authenticated durable security storage, entropy,
//! scheduling and a monotonic nanosecond clock. This module needs neither std
//! nor allocation. It records complete operations, including response assembly,
//! verification, checkpoints and waits. Recovery/reservation is reported apart.
//! Host execution does not establish MCU execution or flash power-loss safety.
#![forbid(unsafe_code)]

use crate::security_state::{Credentials, State, Store};
use coaptic::storage::DatagramIo;
use coaptic::{App, Code, Endpoint, profiles};

pub const OPERATIONS: u32 = 24;
pub const TIMEOUT_NS: u64 = 5_000_000_000;
pub const POLL_LIMIT: u32 = 100_000;

#[derive(Clone, Copy, Debug)]
pub enum Observation {
    Preparation { recovery_ns: u64, app_bytes: usize },
    Reservation { elapsed_ns: u64 },
    Operation(Operation),
}

#[derive(Clone, Copy, Debug)]
pub struct Operation {
    pub iteration: u32,
    pub path: &'static str,
    pub bytes: usize,
    pub start_ns: u64,
    pub elapsed_ns: u64,
    pub prepare_ns: u64,
    pub poll_ns: u64,
    pub checkpoint_ns: u64,
    pub take_ns: u64,
    pub verify_ns: u64,
    pub wait_ns: u64,
    pub polls: u32,
}

struct Clock<F> {
    source: F,
    previous: u64,
}
impl<F: FnMut() -> Option<u64>> Clock<F> {
    fn now(&mut self) -> Result<u64, &'static str> {
        let now = (self.source)().ok_or("campaign stopped")?;
        if now < self.previous {
            return Err("campaign clock regression");
        }
        self.previous = now;
        Ok(now)
    }
}

/// Execute eight identity/test/2000-byte reads, in that order, with one live App.
///
/// `wait` must return in bounded time; its elapsed cost is included. `observe`
/// must preserve every observation or return an error. It runs after each
/// operation, outside its measured interval. No success observation is emitted
/// for a failed operation. A campaign succeeds only after all 24 verified reads.
/// Clock stop/regression, failed storage, poll errors, bad responses and either
/// the five-second or finite-poll bound stop immediately. No storage is reset.
/// The expected identity must identify the intended, source-verified server.
#[allow(clippy::too_many_arguments)]
pub fn run<T: DatagramIo, S: Store>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    now_ns: impl FnMut() -> Option<u64>,
    mut wait: impl FnMut(),
    credentials: &Credentials,
    store: S,
    peer: Endpoint,
    identity: &[u8; 32],
    mut observe: impl FnMut(Observation) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    if !identity.iter().all(u8::is_ascii_hexdigit) {
        return Err("campaign identity");
    }
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
    let mut output = [0; 4096];
    observe(Observation::Preparation {
        recovery_ns,
        app_bytes: core::mem::size_of_val(&app),
    })?;
    for iteration in 0..8 {
        for (path, expected) in [
            ("identity", &identity[..]),
            ("test", &b"coaptic"[..]),
            ("large", &[0x5a; 2000][..]),
        ] {
            let context = app.oscore_mut().ok_or("campaign context")?;
            if context
                .sender_reservation_end()
                .ok_or("campaign reservation")?
                .saturating_sub(context.sender_seq())
                < 8
            {
                let start = clock.now()?;
                state.refill(context).map_err(|_| "campaign refill")?;
                observe(Observation::Reservation {
                    elapsed_ns: clock.now()? - start,
                })?;
            }
            let start = clock.now()?;
            let call = app
                .get(path)
                .to(peer)
                .send(start / 1_000_000)
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
                let phase = clock.now()?;
                if phase - start >= TIMEOUT_NS || op.polls == POLL_LIMIT {
                    return Err("campaign deadline/poll bound");
                }
                app.poll(phase / 1_000_000).map_err(|_| "campaign poll")?;
                let after_poll = clock.now()?;
                op.poll_ns += after_poll - phase;
                op.polls += 1;
                state
                    .checkpoint(app.oscore().ok_or("campaign context")?.replay_checkpoint())
                    .map_err(|_| "campaign checkpoint")?;
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
                    // A late but otherwise correct response must not pass.
                    if end - start >= TIMEOUT_NS {
                        return Err("campaign deadline/poll bound");
                    }
                    op.verify_ns = end - after_take;
                    op.elapsed_ns = end - start;
                    observe(Observation::Operation(op))?;
                    break;
                }
                let before_wait = clock.now()?;
                wait();
                op.wait_ns += clock.now()? - before_wait;
            }
        }
    }
    Ok(())
}

fn verify(reply: &coaptic::Response<'_>, expected: &[u8]) -> Result<(), &'static str> {
    if reply.code() != Code::CONTENT || reply.payload_truncated() || reply.payload() != expected {
        return Err("campaign representation/identity");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn monotonic_clock_accepts_equal_ticks_and_refuses_regression_or_stop() {
        let mut values = [Some(3), Some(3), Some(2), None].into_iter();
        let mut clock = Clock {
            source: || values.next().flatten(),
            previous: 0,
        };
        assert_eq!(clock.now(), Ok(3));
        assert_eq!(clock.now(), Ok(3));
        assert_eq!(clock.now(), Err("campaign clock regression"));
        assert_eq!(clock.now(), Err("campaign stopped"));
    }
    #[test]
    fn complete_representation_refuses_wrong_code_corruption_and_short_body_then_recovers() {
        let valid = coaptic::Response::content(b"coaptic");
        assert!(verify(&valid, b"coaptic").is_ok());
        assert!(verify(&valid.payload_borrowed(b"coaptix"), b"coaptic").is_err());
        assert!(verify(&valid.payload_borrowed(b"coap"), b"coaptic").is_err());
        assert!(verify(&coaptic::Response::not_found(), b"coaptic").is_err());
        assert!(verify(&valid, b"coaptic").is_ok());
    }
}
