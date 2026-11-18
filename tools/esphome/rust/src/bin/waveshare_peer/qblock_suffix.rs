//! One known-size NON Q-Block2 trailing-loss injection on host receive.
//! The device serves/reissues blocks; this does not prove MCU client recovery.
use super::*;

struct DropSuffix {
    io: UdpSocketIo<[u8; 1153]>,
    peer: Endpoint,
    armed: bool,
    first_seen: bool,
    dropped: bool,
    repair_sent: bool,
    token: Option<Token>,
    // Read-only wire graders never originate traffic or own replay admission.
    // Only the App context recovered from the durable record has that authority.
    graders: Option<(SecurityContext, SecurityContext)>,
    request: Option<coaptic::oscore::RequestRef>,
}
impl coaptic::storage::DatagramTransport for DropSuffix {
    type Error = std::io::Error;
}
impl DatagramIo for DropSuffix {
    fn recv(&mut self, bytes: &mut [u8]) -> std::io::Result<Option<(usize, Endpoint)>> {
        let received = self.io.recv(bytes)?;
        if let Some((n, peer)) = received
            && self.armed
            && peer == self.peer
            && let Ok(outer) = decode(&bytes[..n])
        {
            let mut opened = [0; 1152];
            let packet = if let Some((grader, _)) = &self.graders {
                let Some(request) = self.request else {
                    return Ok(received);
                };
                let Ok(packet) = grader.unprotect_response(&outer, request, &mut opened) else {
                    return Ok(received);
                };
                packet
            } else {
                outer
            };
            if packet.ty() == Type::NonConfirmable
                && packet.code() == Code::CONTENT
                && self.token == Some(packet.token())
                && packet.etag().next() == Some(&b"large-v1"[..])
                && packet.size2() == Some(Ok(2000))
                && let Some(Ok(block)) = packet.q_block2().next()
                && block.szx() == 6
            {
                if block.num() == 0 && block.more() && packet.payload().len() == 1024 {
                    self.first_seen = true;
                } else if self.first_seen
                    && !self.dropped
                    && block.num() == 1
                    && !block.more()
                    && packet.payload().len() == 976
                {
                    self.dropped = true;
                    return Ok(None);
                }
            }
        }
        Ok(received)
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> std::io::Result<usize> {
        let sent = self.io.send(peer, bytes)?;
        if sent == bytes.len()
            && self.armed
            && peer == self.peer
            && let Ok(outer) = decode(bytes)
        {
            let mut opened = [0; 1152];
            let packet = if let Some((_, mirror)) = &mut self.graders {
                // A replayed outbound request needs no new grading binding.
                let Ok((packet, request)) = mirror.unprotect_request(&outer, &mut opened) else {
                    return Ok(sent);
                };
                self.request = Some(request);
                packet
            } else {
                outer
            };
            if packet.code() == Code::GET
                && let Some(Ok(block)) = packet.q_block2().next()
            {
                if self.token.is_none() && block.num() == 0 {
                    self.token = Some(packet.token());
                }
                if self.dropped
                    && self.token == Some(packet.token())
                    && block.num() == 1
                    && block.szx() == 6
                {
                    self.repair_sent = true;
                }
            }
        }
        Ok(sent)
    }
}

pub(super) fn campaign(peer: SocketAddr, id: &str, path: &Path) -> Result<()> {
    selected(peer, id, path, None)
}

pub(super) fn protected(
    peer: SocketAddr,
    id: &str,
    path: &Path,
    c: &Credentials,
    state_path: &Path,
) -> Result<()> {
    selected(peer, id, path, Some((c, state_path)))
}

fn selected(
    peer: SocketAddr,
    id: &str,
    path: &Path,
    protection: Option<(&Credentials, &Path)>,
) -> Result<()> {
    let mut report = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "exclusive Q2 report")?;
    let mut marks = [false; 3];
    let outcome = execute(peer, id, protection, &mut marks);
    writeln!(report, "{{\"passed\":{},\"case\":\"known_size_non_qblock2_suffix\",\"security\":\"{}\",\"run_id\":\"{}\",\"first_size2_2000\":{},\"dropped_final_976\":{},\"suffix_repair_sent\":{},\"error\":{:?},\"scope\":\"host receive loss; device response reissue; no MCU client recovery proof\"}}",
        outcome.is_ok(), if protection.is_some() { "durable-oscore" } else { "unprotected" }, id, marks[0], marks[1], marks[2], outcome.err().unwrap_or("")).map_err(|_| "Q2 report write")?;
    outcome
}

fn execute(
    peer: SocketAddr,
    id: &str,
    protection: Option<(&Credentials, &Path)>,
    marks: &mut [bool; 3],
) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|_| "Q2 bind")?;
    socket.set_nonblocking(true).map_err(|_| "Q2 nonblocking")?;
    let mut state = None;
    let mut graders = None;
    let mut builder = App::profile::<profiles::Constrained>()
        .block_wise::<true>()
        .full_responses()
        .randomness(|b| getrandom::fill(b).is_ok());
    if let Some((c, state_path)) = protection {
        let (owner, context) = State::recover(FileStore::open(state_path, false)?, c)
            .map_err(|_| "Q2 durable recovery")?;
        let mirror = Credentials {
            secret: c.secret,
            salt: c.salt,
            context: c.context,
            sender: c.recipient,
            recipient: c.sender,
        };
        graders = Some((
            SecurityContext::derive(c.parameters()).map_err(|_| "Q2 response grader")?,
            SecurityContext::derive(mirror.parameters()).map_err(|_| "Q2 request grader")?,
        ));
        state = Some(owner);
        builder = builder.oscore(context);
    } else {
        builder = builder.allow_unprotected();
    }
    let mut app = builder
        .bind(DropSuffix {
            io: UdpSocketIo::new(socket, [0; 1153]).map_err(|_| "Q2 scratch")?,
            peer: peer.into(),
            armed: false,
            first_seen: false,
            dropped: false,
            repair_sent: false,
            token: None,
            graders,
            request: None,
        })
        .map_err(|_| "Q2 App bind")?;
    let clock = Instant::now();
    let outcome = (|| {
        for resource in ["identity", "large", "test"] {
            if let Some(state) = &mut state {
                state
                    .checkpoint(app.oscore().ok_or("Q2 context")?.replay_checkpoint())
                    .map_err(|_| "Q2 checkpoint gate")?;
            }
            app.transport_mut().armed = resource == "large";
            let request = app.get(resource).to(peer.into());
            let request = if resource == "large" {
                request.q_block2().non()
            } else {
                request
            };
            let call = request
                .send(clock.elapsed().as_millis() as u64)
                .map_err(|_| "Q2 request")?;
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut output = [0; 4096];
            loop {
                let poll = app.poll(clock.elapsed().as_millis() as u64);
                if let Some(state) = &mut state {
                    state
                        .checkpoint(app.oscore().ok_or("Q2 context")?.replay_checkpoint())
                        .map_err(|_| "Q2 checkpoint")?;
                }
                poll.map_err(|_| "Q2 poll")?;
                if let Some(reply) = app
                    .take_response_into(call, &mut output)
                    .map_err(|_| "Q2 response buffer")?
                {
                    let reply = reply.map_err(|_| "Q2 exchange")?;
                    let expected: &[u8] = match resource {
                        "identity" => id.as_bytes(),
                        "large" => &[0x5a; 2000],
                        _ => b"coaptic",
                    };
                    if reply.code() != Code::CONTENT || reply.payload() != expected {
                        return Err("Q2 complete body or identity");
                    }
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("Q2 deadline");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        if !app.transport().first_seen || !app.transport().dropped || !app.transport().repair_sent {
            return Err("known-size NON Q2 suffix injection absent");
        }
        Ok(())
    })();
    *marks = [
        app.transport().first_seen,
        app.transport().dropped,
        app.transport().repair_sent,
    ];
    outcome
}

#[cfg(test)]
mod tests {
    use super::super::protected_recovery::tests::{Memory, fixture_credentials};
    use super::*;
    use coaptic_esphome_probe::security_state::provision;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn missing_protected_state_retains_structured_failure() {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "coaptic-q2-missing-{}-{}",
            std::process::id(),
            u64::from_ne_bytes(nonce)
        ));
        std::fs::create_dir(&root).unwrap();
        let report = root.join("report");
        let result = protected(
            "127.0.0.1:9".parse().unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &report,
            &fixture_credentials(2, 1),
            &root.join("absent"),
        );
        assert!(result.is_err());
        let text = std::fs::read_to_string(&report).unwrap();
        assert!(text.contains("\"passed\":false"), "{text}");
        assert!(!root.join("absent").exists());
        std::fs::remove_file(report).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn real_udp_fixture_reissues_dropped_non_suffix_and_remains_live() {
        let _owner = crate::NETWORK_SERVICE_TEST_LOCK.lock().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let peer = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let clock = Instant::now();
            coaptic_esphome_probe::network::run(
                UdpSocketIo::new(socket, [0; 1153]).unwrap(),
                |b| getrandom::fill(b).is_ok(),
                || {
                    std::thread::yield_now();
                    (!server_stop.load(Ordering::Relaxed)
                        && clock.elapsed() < Duration::from_secs(15))
                    .then_some(clock.elapsed().as_millis() as u64)
                },
                &[b'a'; 32],
            )
        });
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "coaptic-q2-suffix-{}-{}.json",
            std::process::id(),
            u64::from_ne_bytes(nonce)
        ));
        let result = campaign(peer, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &path);
        stop.store(true, Ordering::Relaxed);
        let server_result = server.join().unwrap();
        let report = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(server_result, Ok(()));
        assert_eq!(result, Ok(()), "{report}");
        assert!(report.contains("\"first_size2_2000\":true,\"dropped_final_976\":true"));
    }
    #[test]
    fn protected_qblock_suffix_requires_authenticated_injection_and_repair() {
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
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let peer = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let clock = Instant::now();
            #[cfg(feature = "async-network")]
            {
                struct Timer<'a>(&'a Instant);
                impl coaptic::platform::AsyncTimer for Timer<'_> {
                    async fn wait_until(&mut self, deadline: u64) {
                        if let Some(when) = self.0.checked_add(Duration::from_millis(deadline)) {
                            async_io::Timer::at(when).await;
                        } else {
                            core::future::pending::<()>().await;
                        }
                    }
                }
                let mut protocol = Timer(&clock);
                let mut local = Timer(&clock);
                async_io::block_on(coaptic_esphome_probe::network::run_protected_async(
                    coaptic_async_host::Udp::new(socket, [0; 1153]).unwrap(),
                    |b| getrandom::fill(b).is_ok(),
                    || {
                        (!server_stop.load(Ordering::Relaxed)
                            && clock.elapsed() < Duration::from_secs(30))
                        .then_some(clock.elapsed().as_millis() as u64)
                    },
                    &[b'a'; 32],
                    (&mut protocol, &mut local),
                    &device,
                    device_store,
                ))
            }
            #[cfg(not(feature = "async-network"))]
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
        let result = protected(
            peer,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &root.join("report"),
            &host,
            &root.join("state"),
        );
        stop.store(true, Ordering::Relaxed);
        let server_result = server.join().unwrap();
        let report = std::fs::read_to_string(root.join("report")).unwrap();
        assert_eq!(result, Ok(()), "{report}");
        assert_eq!(server_result, Ok(()));
        assert!(report.contains("\"suffix_repair_sent\":true"));
        let mut file = FileStore::open(&root.join("state"), false).unwrap();
        coaptic_esphome_probe::security_state::verify_record(&mut file, &host).unwrap();
        drop(file);
        std::fs::remove_file(root.join("state")).unwrap();
        std::fs::remove_file(root.join("report")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
