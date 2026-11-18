//! Finite protected duplicate effects and Observe refusal/reuse; no provisioning.
use super::*;
use coaptic::app::Call;

fn wait<S: coaptic_esphome_probe::security_state::Store>(
    client: &mut Client,
    state: &mut State<'_, S>,
    clock: &Instant,
    call: Call,
    output: &mut [u8],
) -> Result<(Code, usize, Option<u32>)> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let poll = client.poll(clock.elapsed().as_millis() as u64);
        state
            .checkpoint(
                client
                    .oscore()
                    .ok_or("context missing")?
                    .replay_checkpoint(),
            )
            .map_err(|_| "recovery checkpoint")?;
        poll.map_err(|_| "recovery poll")?;
        if let Some(reply) = client
            .take_response_into(call, output)
            .map_err(|_| "recovery response buffer")?
        {
            let reply = reply.map_err(|_| "recovery exchange")?;
            return Ok((reply.code(), reply.payload().len(), reply.observe_seq()));
        }
        if Instant::now() >= deadline {
            return Err("recovery response deadline");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn count(
    client: &mut Client,
    state: &mut State<'_, FileStore>,
    clock: &Instant,
    peer: Endpoint,
) -> Result<u32> {
    let mut output = [0; 4096];
    let (code, n) = query(
        client,
        state,
        clock,
        peer,
        RequestSpec {
            code: Code::GET,
            path: "effects",
            payload: &[],
        },
        &mut output,
    )?;
    if code != Code::CONTENT || n != 4 {
        return Err("protected effects response");
    }
    Ok(u32::from_be_bytes(
        output[..4].try_into().expect("checked length"),
    ))
}

// Private elective cache-key option, not an IANA assignment. It distinguishes
// client subscriptions without selecting unsupported handler Uri-Queries.
const SELECTIONS: [[Opt<'static>; 1]; 3] = [
    [Opt::opaque(
        coaptic::message::OptionNumber::new(2048),
        b"slot0",
    )],
    [Opt::opaque(
        coaptic::message::OptionNumber::new(2048),
        b"slot1",
    )],
    [Opt::opaque(
        coaptic::message::OptionNumber::new(2048),
        b"slot2",
    )],
];

fn repeat_echo(client: &mut Client, state: &mut State<'_, FileStore>) -> Result<()> {
    use sha2::{Digest, Sha256};
    state
        .checkpoint(
            client
                .oscore()
                .ok_or("context missing")?
                .replay_checkpoint(),
        )
        .map_err(|_| "duplicate checkpoint gate")?;
    let io = client.transport_mut();
    let peer = io.duplicate_peer.ok_or("duplicate peer missing")?;
    // The first digest belongs to the response already authenticated by query.
    // Matching retained ciphertext cannot advance replay or create new effects.
    let expected = io
        .duplicate_reply
        .ok_or("authenticated duplicate response absent")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    if io
        .io
        .send(peer, &io.first[..io.length])
        .map_err(|_| "exact duplicate send")?
        != io.length
    {
        return Err("exact duplicate short send");
    }
    io.duplicated = true;
    let mut packets = 0;
    let mut bytes = [0; 1152];
    loop {
        if let Some((n, from)) = io.io.recv(&mut bytes).map_err(|_| "duplicate receive")? {
            packets += 1;
            if from == peer && <[u8; 32]>::from(Sha256::digest(&bytes[..n])) == expected {
                return Ok(());
            }
        }
        if packets >= 128 || Instant::now() >= deadline {
            return Err("cached duplicate response deadline");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn cancel<S: coaptic_esphome_probe::security_state::Store>(
    client: &mut Client,
    state: &mut State<'_, S>,
    clock: &Instant,
    peer: Endpoint,
    index: usize,
    call: Call,
) -> Result<()> {
    // A failed/ambiguous durable commit poisons State. Refuse even teardown
    // traffic until recovery instead of sending first and discovering it later.
    state
        .checkpoint(
            client
                .oscore()
                .ok_or("context missing")?
                .replay_checkpoint(),
        )
        .map_err(|_| "protected cancellation checkpoint gate")?;
    let cancel = client
        .get("ticks")
        .custom_options(&SELECTIONS[index])
        .to(peer)
        .deregister_call(call)
        .send(clock.elapsed().as_millis() as u64)
        .map_err(|_| "protected cancellation send")?;
    let mut output = [0; 4096];
    let (code, n, observe) = wait(client, state, clock, cancel, &mut output)?;
    if code != Code::CONTENT || n != 4 || observe.is_some() {
        return Err("protected cancellation response");
    }
    Ok(())
}

pub(super) fn campaign(
    client: &mut Client,
    state: &mut State<'_, FileStore>,
    clock: &Instant,
    peer: Endpoint,
    id: &str,
    path: &Path,
) -> Result<()> {
    let mut report = File::create_new(path).map_err(|_| "exclusive protected recovery report")?;
    let mut live = [None; 3];
    let mut before = None;
    let mut after = None;
    let mut capacity_reused = false;
    let mut duplicate_confirmed = false;
    let outcome = (|| {
        let mut output = [0; 4096];
        let (code, n) = query(
            client,
            state,
            clock,
            peer,
            RequestSpec {
                code: Code::GET,
                path: "identity",
                payload: &[],
            },
            &mut output,
        )?;
        if code != Code::CONTENT || &output[..n] != id.as_bytes() {
            return Err("protected recovery identity");
        }
        before = Some(count(client, state, clock, peer)?);
        client.transport_mut().duplicate_next = true;
        let (code, n) = query(
            client,
            state,
            clock,
            peer,
            RequestSpec {
                code: Code::POST,
                path: "echo",
                payload: b"finite duplicate effect",
            },
            &mut output,
        )?;
        if code != Code::CONTENT || &output[..n] != b"finite duplicate effect" {
            return Err("protected duplicate echo");
        }
        repeat_echo(client, state)?;
        duplicate_confirmed = true;
        after = Some(count(client, state, clock, peer)?);
        if !client.transport().duplicated || after.unwrap().wrapping_sub(before.unwrap()) != 1 {
            return Err("protected duplicate handler count");
        }
        for index in 0..3 {
            let call = client
                .get("ticks")
                .custom_options(&SELECTIONS[index])
                .to(peer)
                .observe()
                .send(clock.elapsed().as_millis() as u64)
                .map_err(|_| "protected Observe send")?;
            // Retain uncertain relations for bounded authenticated teardown too.
            live[index] = Some(call);
            let (code, n, observe) = wait(client, state, clock, call, &mut output)?;
            if code != Code::CONTENT || n != 4 || observe.is_some() != (index < 2) {
                return Err("protected Observe capacity refusal");
            }
            if index == 2 {
                live[index] = None;
            }
        }
        cancel(client, state, clock, peer, 0, live[0].unwrap())?;
        live[0] = None;
        let call = client
            .get("ticks")
            .custom_options(&SELECTIONS[2])
            .to(peer)
            .observe()
            .send(clock.elapsed().as_millis() as u64)
            .map_err(|_| "protected Observe reuse send")?;
        live[2] = Some(call);
        let (code, n, observe) = wait(client, state, clock, call, &mut output)?;
        if code != Code::CONTENT || n != 4 || observe.is_none() {
            return Err("protected Observe slot reuse");
        }
        capacity_reused = true;
        Ok(())
    })();
    let mut cleanup = Ok(());
    let mut unresolved_relations = 0u8;
    for (index, relation) in live.into_iter().enumerate() {
        if let Some(call) = relation
            && let Err(error) = cancel(client, state, clock, peer, index, call)
        {
            cleanup = Err(error);
            unresolved_relations |= 1 << index;
        }
    }
    let result = outcome.and(cleanup);
    writeln!(report, "{{\"passed\":{},\"security\":\"durable-oscore\",\"run_id\":\"{}\",\"before\":{:?},\"after\":{:?},\"duplicated_wire\":{},\"cached_reply_confirmed\":{},\"observe_capacity\":2,\"refused_and_reused\":{},\"unresolved_relations\":{},\"error\":{:?},\"cleanup_error\":{:?}}}",
        result.is_ok(), id, before.unwrap_or(0), after.unwrap_or(0), client.transport().duplicated,
        duplicate_confirmed, capacity_reused, unresolved_relations, outcome.err().unwrap_or(""), cleanup.err().unwrap_or(""))
        .map_err(|_| "protected recovery report")?;
    result
}

/// Keep one App/security owner alive across a scheduled device interruption.
/// A delayed completed Call and a subsequent fresh identity are both required;
/// the runner must also grade the source-bound physical Wi-Fi recovery receipt.
pub(super) fn reconnect(
    client: &mut Client,
    mut state: Option<&mut State<'_, FileStore>>,
    clock: &Instant,
    peer: Endpoint,
    id: &str,
    path: &Path,
    minimum_observation: Duration,
) -> Result<()> {
    let mut report = File::create_new(path).map_err(|_| "exclusive reconnect report")?;
    let campaign_start = Instant::now();
    let utc_anchor_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "reconnect UTC anchor")?
        .as_nanos();
    writeln!(report, "{{\"case\":\"reconnect_begin\",\"utc_anchor_ns\":{utc_anchor_ns},\"deadline_clock\":\"host_monotonic\"}}")
        .map_err(|_| "reconnect anchor report")?;
    let overall = campaign_start + Duration::from_secs(70);
    let protected = state.is_some();
    let mut delayed = false;
    let mut fresh_after_delay = false;
    let mut completed = 0;
    let outcome = (|| {
        for index in 0..128 {
            let started = Instant::now();
            if started >= overall {
                return Err("reconnect campaign deadline");
            }
            let now = clock.elapsed().as_millis() as u64;
            let remaining_ms = overall.duration_since(started).as_millis() as u64;
            if remaining_ms == 0 {
                return Err("reconnect campaign deadline");
            }
            let call = client
                .get("identity")
                .to(peer)
                .deadline(now.saturating_add(remaining_ms.min(15000)))
                .send(now)
                .map_err(|_| "reconnect send")?;
            let deadline = overall.min(started + Duration::from_secs(15));
            let token = u64::from_be_bytes(
                call.token()
                    .as_bytes()
                    .try_into()
                    .map_err(|_| "reconnect token width")?,
            );
            let mut output = [0; 4096];
            loop {
                if Instant::now() >= deadline {
                    return Err("reconnect response deadline");
                }
                let poll = client.poll(clock.elapsed().as_millis() as u64);
                if let Some(state) = state.as_deref_mut() {
                    state
                        .checkpoint(
                            client
                                .oscore()
                                .ok_or("reconnect context")?
                                .replay_checkpoint(),
                        )
                        .map_err(|_| "reconnect checkpoint")?;
                }
                poll.map_err(|_| "reconnect poll")?;
                if Instant::now() >= deadline {
                    return Err("reconnect response deadline");
                }
                if let Some(reply) = client
                    .take_response_into(call, &mut output)
                    .map_err(|_| "reconnect response buffer")?
                {
                    let reply = reply.map_err(|_| "reconnect exchange")?;
                    if reply.code() != Code::CONTENT || reply.payload() != id.as_bytes() {
                        return Err("reconnect source identity");
                    }
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("reconnect response deadline");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let elapsed_ns = started.elapsed().as_nanos();
            let elapsed_us = elapsed_ns / 1000;
            let start_ns = started.duration_since(campaign_start).as_nanos();
            completed += 1;
            fresh_after_delay = delayed && elapsed_us < 500000;
            delayed |= elapsed_us >= 500000;
            writeln!(report, "{{\"case\":\"reconnect_call\",\"index\":{index},\"token\":\"{token:016x}\",\"start_ns\":{start_ns},\"elapsed_ns\":{elapsed_ns},\"elapsed_us\":{elapsed_us},\"identity_verified\":true}}")
                .map_err(|_| "reconnect call report")?;
            if fresh_after_delay && campaign_start.elapsed() >= minimum_observation {
                return Ok(());
            }
            if Instant::now() >= overall {
                return Err("reconnect campaign deadline");
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        Err("delayed Call and fresh recovery not observed")
    })();
    writeln!(report, "{{\"passed\":{},\"case\":\"same_app_reconnect\",\"protected\":{protected},\"run_id\":\"{id}\",\"completed\":{completed},\"operation_bound\":128,\"delayed_call_completed\":{delayed},\"fresh_after_delay\":{fresh_after_delay},\"error\":{:?}}}", outcome.is_ok(), outcome.err().unwrap_or(""))
        .map_err(|_| "reconnect final report")?;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use coaptic_esphome_probe::security_state::{Error, RECORD_BYTES, Store};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    #[derive(Clone, Default)]
    struct Memory(Arc<Mutex<Option<[u8; RECORD_BYTES]>>>);
    impl Store for Memory {
        fn read(&mut self) -> std::result::Result<Option<[u8; RECORD_BYTES]>, Error> {
            Ok(*self.0.lock().unwrap())
        }
        fn commit(&mut self, bytes: &[u8; RECORD_BYTES]) -> std::result::Result<(), Error> {
            *self.0.lock().unwrap() = Some(*bytes);
            Ok(())
        }
    }
    fn fixture_credentials(sender: u8, recipient: u8) -> Credentials {
        Credentials {
            secret: [0x31; 32],
            salt: [0x52; 16],
            context: [0x73; 16],
            sender,
            recipient,
        }
    }

    #[test]
    fn one_app_finishes_a_call_across_udp_loss_then_verifies_fresh_identity() {
        let _owner = crate::NETWORK_SERVICE_TEST_LOCK.lock().unwrap();
        struct Blackout {
            io: UdpSocketIo<[u8; 1153]>,
            until: Instant,
        }
        impl coaptic::storage::DatagramTransport for Blackout {
            type Error = std::io::Error;
        }
        impl DatagramIo for Blackout {
            fn recv(&mut self, out: &mut [u8]) -> std::io::Result<Option<(usize, Endpoint)>> {
                let received = self.io.recv(out)?;
                Ok(if Instant::now() < self.until {
                    None
                } else {
                    received
                })
            }
            fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> std::io::Result<usize> {
                self.io.send(peer, bytes)
            }
        }
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let peer = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let clock = Instant::now();
            coaptic_esphome_probe::network::run(
                Blackout {
                    io: UdpSocketIo::new(socket, [0; 1153]).unwrap(),
                    until: Instant::now() + Duration::from_millis(800),
                },
                |b| getrandom::fill(b).is_ok(),
                || {
                    std::thread::yield_now();
                    (!server_stop.load(Ordering::Relaxed)
                        && clock.elapsed() < Duration::from_secs(20))
                    .then_some(clock.elapsed().as_millis() as u64)
                },
                &[b'a'; 32],
            )
        });
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut client = App::profile::<profiles::Constrained>()
            .allow_unprotected()
            .block_wise::<true>()
            .full_responses()
            .randomness(|b| getrandom::fill(b).is_ok())
            .bind(CaptureIo {
                io: UdpSocketIo::new(socket, [0; 1153]).unwrap(),
                first: [0; 1152],
                length: 0,
                duplicate_next: false,
                duplicated: false,
                duplicate_peer: None,
                duplicate_token: None,
                duplicate_reply: None,
            })
            .unwrap();
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "coaptic-reconnect-{}-{}.jsonl",
            std::process::id(),
            u64::from_ne_bytes(nonce)
        ));
        let result = reconnect(
            &mut client,
            None,
            &Instant::now(),
            peer.into(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &path,
            Duration::ZERO,
        );
        stop.store(true, Ordering::Relaxed);
        let server_result = server.join().unwrap();
        let report = std::fs::read_to_string(&path).unwrap();
        assert_eq!(result, Ok(()), "{report}");
        assert_eq!(server_result, Ok(()));
        assert!(report.contains("\"delayed_call_completed\":true,\"fresh_after_delay\":true"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn poisoned_checkpoint_refuses_cancellation_before_network_send() {
        struct Failing {
            memory: Memory,
            fail: Arc<AtomicBool>,
        }
        impl Store for Failing {
            fn read(&mut self) -> std::result::Result<Option<[u8; RECORD_BYTES]>, Error> {
                self.memory.read()
            }
            fn commit(&mut self, bytes: &[u8; RECORD_BYTES]) -> std::result::Result<(), Error> {
                if self.fail.load(Ordering::Relaxed) {
                    return Err(Error::Unavailable);
                }
                self.memory.commit(bytes)
            }
        }
        let host = fixture_credentials(2, 1);
        let fail = Arc::new(AtomicBool::new(false));
        let mut store = Failing {
            memory: Memory::default(),
            fail: Arc::clone(&fail),
        };
        provision(&mut store, &host).unwrap();
        let (mut state, context) = State::recover(store, &host).unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(25)))
            .unwrap();
        let peer: Endpoint = server.local_addr().unwrap().into();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut client = App::profile::<profiles::Constrained>()
            .block_wise::<true>()
            .randomness(|b| getrandom::fill(b).is_ok())
            .oscore(context)
            .bind(CaptureIo {
                io: UdpSocketIo::new(socket, [0; 1153]).unwrap(),
                first: [0; 1152],
                length: 0,
                duplicate_next: false,
                duplicated: false,
                duplicate_peer: None,
                duplicate_token: None,
                duplicate_reply: None,
            })
            .unwrap();
        let call = client
            .get("ticks")
            .custom_options(&SELECTIONS[0])
            .to(peer)
            .observe()
            .send(0)
            .unwrap();
        let mut bytes = [0; 1152];
        server.recv(&mut bytes).unwrap();
        fail.store(true, Ordering::Relaxed);
        let checkpoint = coaptic::oscore::ReplayCheckpoint::from_parts(1, 1).unwrap();
        assert_eq!(state.checkpoint(checkpoint), Err(Error::Unavailable));
        assert_eq!(
            cancel(&mut client, &mut state, &Instant::now(), peer, 0, call),
            Err("protected cancellation checkpoint gate")
        );
        assert!(server.recv(&mut bytes).is_err());
    }

    #[test]
    fn authenticated_udp_duplicates_and_observe_refusal_reuse_preserve_state() {
        let _owner = crate::NETWORK_SERVICE_TEST_LOCK.lock().unwrap();
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "coaptic-protected-recovery-{}-{}",
            std::process::id(),
            u64::from_ne_bytes(nonce)
        ));
        std::fs::create_dir(&root).unwrap();
        let host = fixture_credentials(2, 1);
        let device = fixture_credentials(1, 2);
        let mut device_store = Memory::default();
        provision(&mut device_store, &device).unwrap();
        let mut file = FileStore::open(&root.join("state"), true).unwrap();
        provision(&mut file, &host).unwrap();
        drop(file);
        let (mut state, context) =
            State::recover(FileStore::open(&root.join("state"), false).unwrap(), &host).unwrap();
        let generation = state.generation();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let peer = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let clock = Instant::now();
            coaptic_esphome_probe::network::run_protected(
                UdpSocketIo::new(socket, [0; 1153]).unwrap(),
                |b| getrandom::fill(b).is_ok(),
                || {
                    std::thread::yield_now();
                    (!server_stop.load(Ordering::Relaxed)
                        && clock.elapsed() < Duration::from_secs(30))
                    .then_some(clock.elapsed().as_millis() as u64)
                },
                &[b'a'; 32],
                &device,
                device_store,
            )
        });
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut client = App::profile::<profiles::Constrained>()
            .block_wise::<true>()
            .randomness(|b| getrandom::fill(b).is_ok())
            .oscore(context)
            .bind(CaptureIo {
                io: UdpSocketIo::new(socket, [0; 1153]).unwrap(),
                first: [0; 1152],
                length: 0,
                duplicate_next: false,
                duplicated: false,
                duplicate_peer: None,
                duplicate_token: None,
                duplicate_reply: None,
            })
            .unwrap();
        let result = campaign(
            &mut client,
            &mut state,
            &Instant::now(),
            peer.into(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &root.join("report"),
        );
        stop.store(true, Ordering::Relaxed);
        let server_result = server.join().unwrap();
        let report = std::fs::read_to_string(root.join("report")).unwrap();
        assert_eq!(result, Ok(()), "{report}");
        assert_eq!(server_result, Ok(()));
        assert!(state.generation() >= generation);
        drop(client);
        drop(state);
        let mut file = FileStore::open(&root.join("state"), false).unwrap();
        coaptic_esphome_probe::security_state::verify_record(&mut file, &host).unwrap();
        drop(file);
        for name in ["state", "report"] {
            std::fs::remove_file(root.join(name)).unwrap();
        }
        std::fs::remove_dir(root).unwrap();
    }
}
