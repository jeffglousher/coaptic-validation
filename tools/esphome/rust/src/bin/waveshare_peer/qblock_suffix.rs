//! One known-size NON Q-Block2 trailing-loss injection on host receive.
//! The device serves/reissues blocks; this does not prove MCU client recovery.
use super::*;

struct DropSuffix {
    io: UdpSocketIo<[u8; 1153]>,
    peer: Endpoint,
    armed: bool,
    first_seen: bool,
    dropped: bool,
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
            && let Ok(packet) = decode(&bytes[..n])
            && packet.ty() == Type::NonConfirmable
            && packet.code() == Code::CONTENT
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
        Ok(received)
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> std::io::Result<usize> {
        self.io.send(peer, bytes)
    }
}

pub(super) fn campaign(peer: SocketAddr, id: &str, path: &Path) -> Result<()> {
    let mut report = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "exclusive Q2 report")?;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|_| "Q2 bind")?;
    socket.set_nonblocking(true).map_err(|_| "Q2 nonblocking")?;
    let mut app = App::profile::<profiles::Constrained>()
        .allow_unprotected()
        .block_wise::<true>()
        .full_responses()
        .randomness(|b| getrandom::fill(b).is_ok())
        .bind(DropSuffix {
            io: UdpSocketIo::new(socket, [0; 1153]).map_err(|_| "Q2 scratch")?,
            peer: peer.into(),
            armed: false,
            first_seen: false,
            dropped: false,
        })
        .map_err(|_| "Q2 App bind")?;
    let clock = Instant::now();
    let outcome = (|| {
        for resource in ["identity", "large", "test"] {
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
                app.poll(clock.elapsed().as_millis() as u64)
                    .map_err(|_| "Q2 poll")?;
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
        if !app.transport().first_seen || !app.transport().dropped {
            return Err("known-size NON Q2 suffix injection absent");
        }
        Ok(())
    })();
    writeln!(report, "{{\"passed\":{},\"case\":\"known_size_non_qblock2_suffix\",\"security\":\"unprotected\",\"run_id\":\"{}\",\"first_size2_2000\":{},\"dropped_final_976\":{},\"error\":{:?},\"scope\":\"host receive loss; device response reissue; no MCU client recovery proof\"}}",
        outcome.is_ok(), id, app.transport().first_seen, app.transport().dropped, outcome.err().unwrap_or("")).map_err(|_| "Q2 report write")?;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn real_udp_fixture_reissues_dropped_non_suffix_and_remains_live() {
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
}
