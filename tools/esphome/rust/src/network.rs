//! Bounded IPv4 UDP qualification with explicit plaintext or protected mode.
//! ESPHome owns the socket/task; this module owns fixed Coaptic state. Protected
//! mode requires unique credentials and authenticated durable security recovery.
//! No actuator or durable application-effect boundary is supplied here. Runtime
//! and storage custody remain caller-owned. Sources/images must be verified;
//! host tests do not establish device execution or flash power-loss behavior.
#![forbid(unsafe_code)]

use coaptic::platform::{CheckedClock, ClockError};
use coaptic::storage::DatagramIo;
use coaptic::{App, Request, Response, get, post, profiles};
use core::cell::Cell;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use critical_section::Mutex;

static ACTIVE: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));
static ID: [AtomicU8; 32] = [const { AtomicU8::new(0) }; 32];
static TICKS: AtomicU32 = AtomicU32::new(0);
#[cfg(test)]
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
const LARGE: [u8; 2000] = [0x5a; 2000];

struct Owner;
impl Drop for Owner {
    fn drop(&mut self) {
        critical_section::with(|section| ACTIVE.borrow(section).set(false));
    }
}

fn claim(id: &[u8; 32]) -> Result<Owner, &'static str> {
    if critical_section::with(|section| ACTIVE.borrow(section).replace(true)) {
        return Err("already running");
    }
    let owner = Owner;
    for (byte, value) in ID.iter().zip(id) {
        byte.store(*value, Ordering::Relaxed);
    }
    TICKS.store(0, Ordering::Relaxed);
    Ok(owner)
}

fn identity(_: Request<'_>) -> Response<'static> {
    let id = core::array::from_fn::<_, 32, _>(|i| ID[i].load(Ordering::Relaxed));
    Response::content_copy(&id)
}

fn test(_: Request<'_>) -> Response<'static> {
    Response::content(b"coaptic")
}

fn echo(request: Request<'_>) -> Response<'static> {
    let body = request.body().unwrap_or(request.payload());
    if body.len() > 128 {
        return Response::new(coaptic::Code::REQUEST_ENTITY_TOO_LARGE);
    }
    Response::content_copy(body)
}

fn upload(request: Request<'_>) -> Response<'static> {
    let body = request.body().unwrap_or(request.payload());
    let checksum = body
        .iter()
        .fold(0u32, |sum, byte| sum.rotate_left(5) ^ u32::from(*byte));
    let mut result = [0; 8];
    result[..4].copy_from_slice(&(body.len() as u32).to_be_bytes());
    result[4..].copy_from_slice(&checksum.to_be_bytes());
    Response::content_copy(&result)
}

fn large(_: Request<'_>) -> Response<'static> {
    Response::content(&LARGE)
}

fn ticks(_: Request<'_>) -> Response<'static> {
    Response::content_copy(&TICKS.load(Ordering::Relaxed).to_be_bytes()).observe(0)
}

// None is the platform's explicit stop signal, not a timestamp to substitute.
// Regression stops the service before any work using the refused reading.
fn next_time<C>(clock: &mut CheckedClock<C>) -> Result<Option<u64>, &'static str>
where
    C: FnMut() -> Result<u64, ()>,
{
    match clock.now_ms() {
        Ok(now) => Ok(Some(now)),
        Err(ClockError::Source(())) => Ok(None),
        Err(ClockError::Regressed { .. }) => Err("clock regression"),
    }
}

/// Runs until the owning platform returns `None` from its scheduling clock.
///
/// The caller owns the live transport and supplies a secure entropy function.
/// Only one service may run. A stopped service must not be rebound to the same
/// endpoint during EXCHANGE_LIFETIME; this adapter does not persist MID state.
/// The clock must bound consecutive ready polls with periodic scheduler yields
/// and bound idle waits so protocol timers progress. The ESPHome adapter yields
/// after 32 ready polls and waits at most 10 ms for socket readability when idle.
/// Consecutive transport/poll failures refuse after 32 iterations.
/// Equal ticks are allowed; a backward tick stops before another poll or notify.
/// The platform must extend wrapping counters and keep one epoch for this run.
pub fn run<T: DatagramIo>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    mut clock: impl FnMut() -> Option<u64>,
    id: &[u8; 32],
) -> Result<(), &'static str> {
    let _owner = claim(id)?;
    let mut app = App::profile::<profiles::Constrained>()
        .randomness(random)
        .allow_plaintext()
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
    let mut errors = 0;
    let mut tick = 0u32;
    let mut clock = CheckedClock::new(|| clock().ok_or(()));
    while let Some(now) = next_time(&mut clock)? {
        if app.poll(now).is_err() {
            errors += 1;
            if errors >= 32 {
                return Err("poll failures");
            }
        } else {
            errors = 0;
        }
        if now >= next {
            tick = tick.wrapping_add(1);
            TICKS.store(tick, Ordering::Relaxed);
            let _ = app.notify(now, &["ticks"], Response::content_copy(&tick.to_be_bytes()));
            next = now.saturating_add(250);
        }
    }
    Ok(())
}

/// Protected service: restore authenticated durable state before binding, require
/// every inbound checkpoint before dispatch, and stop on an uncertain commit.
/// No plaintext fallback, implicit provisioning or application durability claim.
/// Clock regression stops before another receive, reservation or checkpoint;
/// `None` remains an explicit clean stop. A restart requires normal durable
/// recovery and a safe endpoint lifetime, not a reset of live protocol timers.
#[cfg(feature = "oscore")]
pub fn run_protected<T: DatagramIo, S: super::security_state::Store>(
    io: T,
    random: fn(&mut [u8]) -> bool,
    mut clock: impl FnMut() -> Option<u64>,
    id: &[u8; 32],
    credentials: &super::security_state::Credentials,
    store: S,
) -> Result<(), &'static str> {
    let _owner = claim(id)?;
    let (mut state, context) = super::security_state::State::recover(store, credentials)
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
    let mut errors = 0;
    let mut tick = 0u32;
    let mut clock = CheckedClock::new(|| clock().ok_or(()));
    while let Some(now) = next_time(&mut clock)? {
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
        let result = app.poll_with_oscore_checkpoint(now, |checkpoint| {
            let success = state.checkpoint(checkpoint).is_ok();
            failed |= !success;
            success
        });
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
        if now >= next {
            tick = tick.wrapping_add(1);
            TICKS.store(tick, Ordering::Relaxed);
            // notify does not receive or dispatch; sender range is already granted.
            app.notify(now, &["ticks"], Response::content_copy(&tick.to_be_bytes()))
                .map_err(|_| "notification")?;
            next = now.saturating_add(250);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coaptic::Endpoint;
    use coaptic::message::{Message, MessageId, Opt, Token, Type, decode, encode};
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    struct Idle;
    impl DatagramIo for Idle {
        type Error = ();
        fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
            Ok(None)
        }
        fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, ()> {
            Ok(bytes.len())
        }
    }

    struct Scripted {
        incoming: VecDeque<Vec<u8>>,
        outgoing: Rc<RefCell<Vec<Vec<u8>>>>,
        fail: bool,
    }

    impl DatagramIo for Scripted {
        type Error = ();
        fn recv(&mut self, bytes: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
            if self.fail {
                return Err(());
            }
            Ok(self.incoming.pop_front().map(|packet| {
                bytes[..packet.len()].copy_from_slice(&packet);
                (packet.len(), Endpoint::v4([192, 0, 2, 1], 5683))
            }))
        }
        fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, ()> {
            self.outgoing.borrow_mut().push(bytes.to_vec());
            Ok(bytes.len())
        }
    }

    struct Tracked(Scripted, Rc<Cell<usize>>);
    impl DatagramIo for Tracked {
        type Error = ();
        fn recv(&mut self, b: &mut [u8]) -> Result<Option<(usize, coaptic::Endpoint)>, ()> {
            self.1.set(self.1.get() + 1);
            self.0.recv(b)
        }
        fn send(&mut self, to: coaptic::Endpoint, b: &[u8]) -> Result<usize, ()> {
            self.0.send(to, b)
        }
    }

    #[test]
    fn checked_network_clock_refuses_regression_before_io_and_releases_owner() {
        let _test = TEST_LOCK.lock().unwrap();
        let reads = Rc::new(Cell::new(0));
        let out = Rc::new(RefCell::new(Vec::new()));
        let io = Tracked(
            Scripted {
                incoming: (1..=3)
                    .map(|mid| request(mid, coaptic::Code::GET, "test", &[]))
                    .collect(),
                outgoing: out.clone(),
                fail: false,
            },
            reads.clone(),
        );
        let mut times = [100, 100, 99].into_iter();
        assert_eq!(
            run(
                io,
                |b| {
                    b.fill(42);
                    true
                },
                || times.next(),
                &[b'a'; 32]
            ),
            Err("clock regression")
        );
        assert_eq!(reads.get(), 2);
        assert_eq!(out.borrow().len(), 2);
        assert_eq!(TICKS.load(Ordering::Relaxed), 1);
        let mut times = [500_000, 500_001].into_iter();
        assert_eq!(
            run(
                Idle,
                |b| {
                    b.fill(42);
                    true
                },
                || times.next(),
                &[b'b'; 32]
            ),
            Ok(())
        );
    }

    fn request(mid: u16, code: coaptic::Code, path: &str, payload: &[u8]) -> Vec<u8> {
        let options = [Opt::uri_path(path)];
        let message = Message::new(Type::Confirmable, code, MessageId::new(mid))
            .with_token(Token::new(&[mid as u8]).unwrap())
            .with_options(&options)
            .with_payload(payload);
        let mut bytes = [0; 1152];
        let len = encode(&message, &mut bytes).unwrap();
        bytes[..len].to_vec()
    }

    #[test]
    fn stopped_service_releases_ownership_and_entropy_refusal_is_reported() {
        let _test = TEST_LOCK.lock().unwrap();
        let id = [b'a'; 32];
        assert_eq!(run(Idle, |_| false, || None, &id), Err("bind"));
        let outgoing = Rc::new(RefCell::new(Vec::new()));
        let mut polls = 0;
        let io = Scripted {
            incoming: VecDeque::from([
                request(1, coaptic::Code::POST, "echo", &[b'x'; 128]),
                request(2, coaptic::Code::POST, "echo", &[b'x'; 129]),
                request(3, coaptic::Code::GET, "test", &[]),
                request(4, coaptic::Code::GET, "identity", &[]),
            ]),
            outgoing: outgoing.clone(),
            fail: false,
        };
        assert_eq!(
            run(
                io,
                |bytes| {
                    bytes.fill(42);
                    true
                },
                || {
                    polls += 1;
                    (polls < 16).then_some(1000 + polls)
                },
                &id
            ),
            Ok(())
        );
        let packets = outgoing.borrow();
        assert_eq!(packets.len(), 4);
        for (index, (code, body)) in [
            (coaptic::Code::CONTENT, &[b'x'; 128][..]),
            (coaptic::Code::REQUEST_ENTITY_TOO_LARGE, &[][..]),
            (coaptic::Code::CONTENT, &b"coaptic"[..]),
            (coaptic::Code::CONTENT, &id[..]),
        ]
        .into_iter()
        .enumerate()
        {
            let response = decode(&packets[index]).unwrap();
            assert_eq!(response.code(), code);
            assert_eq!(response.payload(), body);
            assert_eq!(response.token().as_bytes(), &[(index + 1) as u8]);
        }
        drop(packets);
        let mut failures = 0;
        let broken = Scripted {
            incoming: VecDeque::new(),
            outgoing,
            fail: true,
        };
        assert_eq!(
            run(
                broken,
                |bytes| {
                    bytes.fill(42);
                    true
                },
                || {
                    failures += 1;
                    Some(2000 + failures)
                },
                &id
            ),
            Err("poll failures")
        );
        assert_eq!(failures, 32);
        for _ in 0..2 {
            let mut time = Some(1000);
            assert_eq!(
                run(
                    Idle,
                    |bytes| {
                        bytes.fill(42);
                        true
                    },
                    || time.take(),
                    &id
                ),
                Ok(())
            );
        }
        let (started, ready) = std::sync::mpsc::sync_channel(0);
        let (release, stopped) = std::sync::mpsc::sync_channel(0);
        std::thread::scope(|scope| {
            let owner = scope.spawn(move || {
                run(
                    Idle,
                    |bytes| {
                        bytes.fill(42);
                        true
                    },
                    || {
                        started.send(()).unwrap();
                        stopped
                            .recv_timeout(std::time::Duration::from_secs(5))
                            .unwrap();
                        None
                    },
                    &id,
                )
            });
            ready
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            assert_eq!(run(Idle, |_| false, || None, &id), Err("already running"));
            release.send(()).unwrap();
            assert_eq!(owner.join().unwrap(), Ok(()));
        });
        assert_eq!(run(Idle, |_| false, || None, &id), Err("bind"));
    }
    #[cfg(feature = "oscore")]
    mod protected {
        use super::*;
        use crate::security_state::{Credentials, Error, RECORD_BYTES, Store, provision};
        use coaptic::oscore::SecurityContext;
        #[derive(Default)]
        struct Data {
            record: Option<[u8; RECORD_BYTES]>,
            commits: usize,
            lose_ack_at: Option<usize>,
        }
        #[derive(Clone, Default)]
        struct Memory(Rc<RefCell<Data>>);
        impl Store for Memory {
            fn read(&mut self) -> Result<Option<[u8; RECORD_BYTES]>, Error> {
                Ok(self.0.borrow().record)
            }
            fn commit(&mut self, record: &[u8; RECORD_BYTES]) -> Result<(), Error> {
                let mut d = self.0.borrow_mut();
                d.commits += 1;
                d.record = Some(*record);
                if d.lose_ack_at == Some(d.commits) {
                    Err(Error::Unavailable)
                } else {
                    Ok(())
                }
            }
        }
        fn credentials() -> Credentials {
            Credentials {
                secret: [0x39; 32],
                salt: [0x42; 16],
                context: [0x27; 16],
                sender: 1,
                recipient: 2,
            }
        }
        fn peer_credentials() -> Credentials {
            let mut c = credentials();
            c.sender = 2;
            c.recipient = 1;
            c
        }
        fn execute(
            m: Memory,
            packets: Vec<Vec<u8>>,
        ) -> (Result<(), &'static str>, Vec<Vec<u8>>, usize) {
            let out = Rc::new(RefCell::new(Vec::new()));
            let reads = Rc::new(Cell::new(0));
            let io = Tracked(
                Scripted {
                    incoming: packets.into(),
                    outgoing: out.clone(),
                    fail: false,
                },
                reads.clone(),
            );
            let mut time = 0;
            let result = run_protected(
                io,
                |b| {
                    b.fill(0x39);
                    true
                },
                || {
                    time += 1;
                    (time < 20).then_some(time)
                },
                &[b'a'; 32],
                &credentials(),
                m,
            );
            let packets = out.borrow().clone();
            (result, packets, reads.get())
        }
        fn protected_request(
            ctx: &mut SecurityContext,
            mid: u16,
            code: coaptic::Code,
            path: &str,
            payload: &[u8],
        ) -> Vec<u8> {
            let options = [Opt::uri_path(path)];
            let plain = Message::new(Type::Confirmable, code, MessageId::new(mid))
                .with_token(Token::new(&[mid as u8]).unwrap())
                .with_options(&options)
                .with_payload(payload);
            let mut wire = [0; 1152];
            let n = ctx.protect_request(&plain, &mut wire).unwrap();
            wire[..n].to_vec()
        }

        #[test]
        fn checked_network_clock_preserves_checkpoint_and_authenticated_recovery() {
            let _test = TEST_LOCK.lock().unwrap();
            let mut memory = Memory::default();
            provision(&mut memory, &credentials()).unwrap();
            let mut peer = SecurityContext::derive(peer_credentials().parameters()).unwrap();
            let packets: Vec<_> = (1..=3)
                .map(|mid| protected_request(&mut peer, mid, coaptic::Code::GET, "test", &[]))
                .collect();
            let reads = Rc::new(Cell::new(0));
            let out = Rc::new(RefCell::new(Vec::new()));
            let io = Tracked(
                Scripted {
                    incoming: packets.clone().into(),
                    outgoing: out.clone(),
                    fail: false,
                },
                reads.clone(),
            );
            let mut times = [100, 100, 99].into_iter();
            let mut before_refusal = None;
            let result = run_protected(
                io,
                |b| {
                    b.fill(42);
                    true
                },
                || {
                    let now = times.next();
                    if now == Some(99) {
                        let data = memory.0.borrow();
                        before_refusal = Some((data.record, data.commits));
                    }
                    now
                },
                &[b'a'; 32],
                &credentials(),
                memory.clone(),
            );
            assert_eq!(result, Err("clock regression"));
            assert_eq!(reads.get(), 2);
            assert_eq!(out.borrow().len(), 2);
            assert_eq!(TICKS.load(Ordering::Relaxed), 1);
            let data = memory.0.borrow();
            assert_eq!(Some((data.record, data.commits)), before_refusal);
            drop(data);

            // Fresh run restores durable replay: consumed request refuses;
            // the request left unread at clock refusal still succeeds.
            let (result, recovered, _) =
                execute(memory, vec![packets[0].clone(), packets[2].clone()]);
            assert_eq!(result, Ok(()));
            assert_eq!(recovered.len(), 1);
            assert_eq!(
                decode(&recovered[0]).unwrap().message_id(),
                MessageId::new(3)
            );
            let mut responses = out.borrow().clone();
            responses.extend(recovered);
            let mut verifier = SecurityContext::derive(credentials().parameters()).unwrap();
            for (request, response) in packets.iter().zip(responses.iter()) {
                let mut scratch = [0; 1152];
                let (_, reference) = verifier
                    .unprotect_request(&decode(request).unwrap(), &mut scratch)
                    .unwrap();
                let response = decode(response).unwrap();
                assert!(response.oscore().is_some());
                let opened = peer
                    .unprotect_response(&response, reference, &mut scratch)
                    .unwrap();
                assert_eq!(opened.code(), coaptic::Code::CONTENT);
                assert_eq!(opened.payload(), b"coaptic");
            }
        }
        #[test]
        fn protected_service_refuses_missing_state_and_ambiguous_commit_before_response() {
            let _test = TEST_LOCK.lock().unwrap();
            let m = Memory::default();
            let (result, out, reads) =
                execute(m.clone(), vec![request(1, coaptic::Code::GET, "test", &[])]);
            assert_eq!(result, Err("security recovery"));
            assert!(out.is_empty());
            assert_eq!(reads, 0);
            provision(&mut m.clone(), &credentials()).unwrap();
            m.0.borrow_mut().lose_ack_at = Some(3);
            let mut peer = SecurityContext::derive(peer_credentials().parameters()).unwrap();
            let packet = protected_request(&mut peer, 2, coaptic::Code::GET, "test", &[]);
            let (result, out, _) = execute(m.clone(), vec![packet.clone()]);
            assert_eq!(result, Err("security checkpoint"));
            assert!(out.is_empty());
            // Commit happened, acknowledgment was lost: recovery retains replay.
            m.0.borrow_mut().lose_ack_at = None;
            let (result, out, _) = execute(m, vec![packet]);
            assert_eq!(result, Ok(()));
            assert!(out.is_empty());
        }
        #[test]
        fn protected_service_success_refusal_and_restart_replay_have_complete_authenticated_responses()
         {
            let _test = TEST_LOCK.lock().unwrap();
            let mut m = Memory::default();
            provision(&mut m, &credentials()).unwrap();
            let mut peer = SecurityContext::derive(peer_credentials().parameters()).unwrap();
            let mut bad_credentials = peer_credentials();
            bad_credentials.secret[0] ^= 1;
            let mut wrong = SecurityContext::derive(bad_credentials.parameters()).unwrap();
            let bad_key = protected_request(&mut wrong, 2, coaptic::Code::GET, "test", &[]);
            let mut tampered = protected_request(&mut peer, 3, coaptic::Code::GET, "test", &[]);
            *tampered.last_mut().unwrap() ^= 1;
            peer.take(Token::new(&[3]).unwrap()); // The deliberately corrupted request is cancelled.
            let good = protected_request(&mut peer, 4, coaptic::Code::GET, "test", &[]);
            let echo = protected_request(&mut peer, 5, coaptic::Code::POST, "echo", &[0x5a; 128]);
            let oversized =
                protected_request(&mut peer, 6, coaptic::Code::POST, "echo", &[0x5a; 129]);
            let (result, out, _) = execute(
                m.clone(),
                vec![
                    request(1, coaptic::Code::GET, "test", &[]),
                    bad_key,
                    tampered,
                    good.clone(),
                    echo.clone(),
                    oversized.clone(),
                ],
            );
            assert_eq!(result, Ok(()));
            assert_eq!(out.len(), 4); // Only plaintext4.01 plus the three authenticated requests.
            assert_eq!(decode(&out[0]).unwrap().code(), coaptic::Code::UNAUTHORIZED);
            let mut verifier = SecurityContext::derive(credentials().parameters()).unwrap();
            for (i, (packet, code, payload)) in [
                (good.clone(), coaptic::Code::CONTENT, &b"coaptic"[..]),
                (echo, coaptic::Code::CONTENT, &[0x5a; 128][..]),
                (oversized, coaptic::Code::REQUEST_ENTITY_TOO_LARGE, &[][..]),
            ]
            .into_iter()
            .enumerate()
            {
                let mut scratch = [0; 1152];
                let (_, reference) = verifier
                    .unprotect_request(&decode(&packet).unwrap(), &mut scratch)
                    .unwrap();
                let response = decode(&out[i + 1]).unwrap();
                assert!(response.oscore().is_some());
                let opened = peer
                    .unprotect_response(&response, reference, &mut scratch)
                    .unwrap();
                assert_eq!(opened.code(), code);
                assert_eq!(opened.payload(), payload);
            }
            let next = protected_request(&mut peer, 7, coaptic::Code::GET, "test", &[]);
            let (result, out, _) = execute(m, vec![good, next]);
            assert_eq!(result, Ok(()));
            assert_eq!(out.len(), 1);
            assert_eq!(decode(&out[0]).unwrap().message_id(), MessageId::new(7));
        }
    }
}
