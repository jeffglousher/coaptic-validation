//! Ordinary known-identity PSK mismatch; no Finished-message mutation.
use super::*;
use crate::pcap::Packet;
use std::sync::atomic::AtomicUsize;

const LIMIT: usize = 128;
const CASE_TIMEOUT: Duration = Duration::from_secs(5);

struct BoundedTap {
    tap: TapConn,
    count: AtomicUsize,
}
impl BoundedTap {
    fn admit(&self, bytes: usize) -> webrtc_util::Result<()> {
        if bytes > 2048 || self.count.fetch_add(1, Ordering::SeqCst) >= LIMIT {
            return Err(webrtc_util::Error::Other(
                "record-policy capture bound".into(),
            ));
        }
        Ok(())
    }
}
#[async_trait]
impl Conn for BoundedTap {
    async fn connect(&self, addr: SocketAddr) -> webrtc_util::Result<()> {
        self.tap.connect(addr).await
    }
    async fn recv(&self, bytes: &mut [u8]) -> webrtc_util::Result<usize> {
        let n = self.tap.inner.recv(bytes).await?;
        self.admit(n)?;
        let peer = *self.tap.peer.lock().expect("peer");
        self.tap
            .capture
            .push(peer, self.tap.local, &bytes[..n], false);
        Ok(n)
    }
    async fn recv_from(&self, bytes: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        let n = self.recv(bytes).await?;
        Ok((n, *self.tap.peer.lock().expect("peer")))
    }
    async fn send(&self, bytes: &[u8]) -> webrtc_util::Result<usize> {
        self.admit(bytes.len())?;
        self.tap.send(bytes).await
    }
    async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> webrtc_util::Result<usize> {
        if Some(target) != self.remote_addr() {
            return Err(webrtc_util::Error::Other("wrong owner".into()));
        }
        self.send(bytes).await
    }
    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        self.tap.local_addr()
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.tap.remote_addr()
    }
    async fn close(&self) -> webrtc_util::Result<()> {
        self.tap.close().await
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}
#[derive(Clone)]
struct Case {
    capture: Capture,
    packets: Vec<Packet>,
    endpoints: [SocketAddr; 2],
    authenticated: [bool; 2],
    completed: bool,
    failed_handshake: [bool; 2],
    cleaned: bool,
    elapsed: Duration,
}
async fn exchange(wrong: bool) -> Result<Case, PeerError> {
    let capture = Capture::new();
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| PeerError(e.to_string()))?;
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| PeerError(e.to_string()))?;
    let ca = client.local_addr().map_err(|e| PeerError(e.to_string()))?;
    let sa = server.local_addr().map_err(|e| PeerError(e.to_string()))?;
    client
        .connect(sa)
        .await
        .map_err(|e| PeerError(e.to_string()))?;
    server
        .connect(ca)
        .await
        .map_err(|e| PeerError(e.to_string()))?;
    let tapped = Arc::new(BoundedTap {
        tap: TapConn::new(Arc::new(server), capture.clone(), sa, ca),
        count: AtomicUsize::new(0),
    });
    let started = Instant::now();
    let (client, server) = tokio::time::timeout(CASE_TIMEOUT, async {
        tokio::join!(
            DTLSConn::new(
                Arc::new(client),
                psk_config(if wrong { b"wrong" } else { PSK_KEY }),
                true,
                None
            ),
            DTLSConn::new(tapped, psk_config(PSK_KEY), false, None)
        )
    })
    .await
    .map_err(|_| PeerError("handshake exceeded case deadline".into()))?;
    let authenticated = [client.is_ok(), server.is_ok()];
    let failed_handshake = [client.is_err(), server.is_err()];
    let mut completed = false;
    if let (Ok(client), Ok(server)) = (&client, &server) {
        use coaptic::message::{Message, MessageId, Opt, Token, Type, decode, encode};
        let token = Token::new(b"record").unwrap();
        let opts = [Opt::uri_path("secure")];
        let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(77))
            .with_token(token)
            .with_options(&opts);
        let mut out = [0; 128];
        let n = encode(&request, &mut out).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            client
                .write(&out[..n], None)
                .await
                .map_err(|e| PeerError(e.to_string()))?;
            let mut bytes = [0; 128];
            let n = server
                .read(&mut bytes, None)
                .await
                .map_err(|e| PeerError(e.to_string()))?;
            capture.push(ca, sa, &bytes[..n], true);
            let parsed = decode(&bytes[..n]).map_err(|e| PeerError(e.to_string()))?;
            if parsed.code() != Code::GET || parsed.token() != token {
                return Err(PeerError("unexpected request".into()));
            }
            let response = Message::new(Type::Acknowledgement, Code::CONTENT, parsed.message_id())
                .with_token(token)
                .with_payload(site::SECURE_BODY);
            let mut reply = [0; 128];
            let n = encode(&response, &mut reply).unwrap();
            server
                .write(&reply[..n], None)
                .await
                .map_err(|e| PeerError(e.to_string()))?;
            let n = client
                .read(&mut bytes, None)
                .await
                .map_err(|e| PeerError(e.to_string()))?;
            capture.push(sa, ca, &bytes[..n], true);
            let parsed = decode(&bytes[..n]).map_err(|e| PeerError(e.to_string()))?;
            if parsed.code() != Code::CONTENT
                || parsed.token() != token
                || parsed.payload() != site::SECURE_BODY
            {
                return Err(PeerError("inexact complete response".into()));
            }
            Ok::<(), PeerError>(())
        })
        .await;
        completed = matches!(result, Ok(Ok(())));
    }
    // Every successfully constructed connection is explicitly closed. Failed
    // constructors have already followed the reader fatal path; the dedicated
    // case runtime is then dropped before cleanup is marked in the report.
    for conn in [client.as_ref().ok(), server.as_ref().ok()]
        .into_iter()
        .flatten()
    {
        tokio::time::timeout(Duration::from_secs(1), conn.close())
            .await
            .map_err(|_| PeerError("close deadline".into()))?
            .map_err(|e| PeerError(e.to_string()))?;
    }
    Ok(Case {
        packets: capture.snapshot(),
        capture,
        endpoints: [ca, sa],
        authenticated,
        completed,
        failed_handshake,
        cleaned: false,
        elapsed: started.elapsed(),
    })
}
fn run_case(wrong: bool) -> Result<Case, PeerError> {
    let runtime = runtime()?;
    let result = runtime.block_on(exchange(wrong));
    runtime.shutdown_timeout(Duration::from_secs(1));
    let mut case = result?;
    case.cleaned = true;
    Ok(case)
}
fn records(bytes: &[u8]) -> Result<Vec<&[u8]>, String> {
    let mut rest = bytes;
    let mut result = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 13 || rest[1..3] != [0xfe, 0xfd] {
            return Err("invalid DTLS record header".into());
        }
        let n = usize::from(u16::from_be_bytes([rest[11], rest[12]]));
        if rest.len() < 13 + n {
            return Err("truncated DTLS record".into());
        }
        result.push(&rest[..13 + n]);
        rest = &rest[13 + n..];
    }
    Ok(result)
}
fn grade(case: &Case, wrong: bool) -> Result<(), String> {
    let [client, server] = case.endpoints;
    if client == server
        || !client.ip().is_loopback()
        || !server.ip().is_loopback()
        || !case.cleaned
        || case.elapsed > Duration::from_secs(9)
        || case.packets.is_empty()
        || case.packets.len() > LIMIT + 2
    {
        return Err("missing bounded ownership/cleanup".into());
    }
    let mut hello = false;
    let mut selected = false;
    let mut identity = false;
    let mut alert = false;
    let mut application = Vec::new();
    for packet in &case.packets {
        let from_client = packet.src == client && packet.dst == server;
        if !from_client && !(packet.src == server && packet.dst == client) {
            return Err("wrong endpoint".into());
        }
        if packet.decrypted {
            application.push(packet);
            continue;
        }
        for record in records(&packet.bytes)? {
            let epoch = u16::from_be_bytes([record[3], record[4]]);
            if from_client && epoch == 0 {
                hello |= crate::grade::client_hello_has_suite(record, 0xc0a8);
            }
            if !from_client && epoch == 0 {
                selected |= crate::grade::server_hello_suite(record) == Some(0xc0a8);
            }
            if from_client
                && epoch == 0
                && record[0] == 22
                && record.len() >= 27
                && record[13] == 16
            {
                identity |= record[19..22] == [0, 0, 0]
                    && record[25..] == [0, 8, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd'];
            }
            if record[0] == 21 && epoch == 0 {
                if wrong {
                    if from_client || record[13..] != [2, 20] {
                        return Err("wrong fatal record alert".into());
                    }
                    alert = true;
                } else if record[13..] != [1, 0] {
                    return Err("unexpected cleartext alert in success".into());
                }
            }
        }
    }
    if !hello || !selected || !identity {
        return Err("missing exact PSK negotiation/identity".into());
    }
    if wrong {
        if !alert
            || case.completed
            || case.authenticated != [false, false]
            || case.failed_handshake != [true, true]
            || !application.is_empty()
        {
            return Err("wrong key did not refuse before application".into());
        }
    } else {
        if !case.completed
            || case.authenticated != [true, true]
            || case.failed_handshake != [false, false]
            || application.len() != 2
        {
            return Err("incomplete authenticated exchange".into());
        }
        let captured = Capture::new();
        for packet in &case.packets {
            captured.push(packet.src, packet.dst, &packet.bytes, packet.decrypted);
        }
        crate::grade::Catalog::load()?.grade("TD_COAP_DTLS_01", &captured)?;
        let request = coaptic::message::decode(&application[0].bytes).map_err(|e| e.to_string())?;
        let response =
            coaptic::message::decode(&application[1].bytes).map_err(|e| e.to_string())?;
        if application[0].src != client
            || application[1].src != server
            || request.code() != Code::GET
            || request.ty() != coaptic::message::Type::Confirmable
            || request.message_id() != coaptic::message::MessageId::new(77)
            || request.token() != coaptic::message::Token::new(b"record").unwrap()
            || request.uri_path().collect::<Vec<_>>() != [Ok("secure")]
            || request.options().count() != 1
            || !request.payload().is_empty()
            || response.code() != Code::CONTENT
            || response.ty() != coaptic::message::Type::Acknowledgement
            || response.message_id() != request.message_id()
            || response.options().count() != 0
            || response.token() != request.token()
            || response.payload() != site::SECURE_BODY
        {
            return Err("inexact application result".into());
        }
    }
    Ok(())
}
fn command(path: &std::path::Path, program: &str, args: &[&str]) -> String {
    let output = std::process::Command::new(program)
        .args(args)
        .current_dir(path)
        .output()
        .unwrap();
    assert!(output.status.success(), "provenance command failed");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
fn identity(path: &std::path::Path) -> serde_json::Value {
    let revision = command(path, "git", &["rev-parse", "HEAD"]);
    let status = command(path, "git", &["status", "--porcelain"]);
    assert!(status.is_empty(), "capture requires clean source");
    serde_json::json!({"revision":revision,"dirty":false})
}
#[test]
fn dtls_record_policy_ordinary_wrong_key_refusal_and_fresh_recovery() {
    let _guard = crate::runner::harness_lock();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let suite = identity(root);
    let core = identity(&root.join("coaptic"));
    let provenance = serde_json::json!({
        "suite":suite,"core":core,
        "compiler":command(root,"rustc", &["-Vv"]),
        "backend_git_tree":command(root,"git", &["rev-parse","HEAD:vendor/webrtc-dtls"]),
        "backend_hash_algorithm":"git SHA-1 tree (all tracked vendored source)",
        "method":"three fresh loopback associations: intact, known-identity wrong PSK, intact recovery",
        "literal_dtls02":"SKIP: bad_record_mac20 is not prescribed decrypt_error51"
    });
    let directory = std::env::var_os("COAPTIC_OBSERVE_CAPTURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| root.join("target/pcaps"))
        .join("dtls-record-policy");
    std::fs::create_dir_all(&directory).unwrap();
    let mut reports = Vec::new();
    for (index, wrong) in [false, true, false].into_iter().enumerate() {
        let case = match run_case(wrong) {
            Ok(case) => case,
            Err(error) => {
                std::fs::write(directory.join("failure.json"), serde_json::to_vec_pretty(&serde_json::json!({"provenance":provenance,"case":index,"error":error.to_string(),"complete":false})).unwrap()).unwrap();
                panic!("case {index}: {error}");
            }
        };
        case.capture
            .write_pcap(
                std::fs::File::create(directory.join(format!("case-{index}.pcap"))).unwrap(),
            )
            .unwrap();
        reports.push(serde_json::json!({"case":index,"wrong_key":wrong,"endpoints":case.endpoints,"authenticated":case.authenticated,"failed_handshake":case.failed_handshake,"completed":case.completed,"cleaned":case.cleaned,"elapsed_ms":case.elapsed.as_millis(),"application_packets":case.packets.iter().filter(|p|p.decrypted).count()}));
        std::fs::write(
            directory.join("report.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"provenance":provenance,"cases":reports,"complete":false}),
            )
            .unwrap(),
        )
        .unwrap();
        grade(&case, wrong).unwrap();
        for mutation in 0..8 {
            let mut bad = case.clone();
            match mutation {
                0 => bad.cleaned = false,
                1 => bad.packets.clear(),
                2 => bad.packets[0].src = "127.0.0.1:1".parse().unwrap(),
                3 => bad.elapsed = Duration::from_secs(10),
                4 => bad.authenticated = [false, true],
                5 => bad.packets.retain(|p| {
                    p.decrypted
                        || !records(&p.bytes)
                            .unwrap()
                            .iter()
                            .any(|r| r[0] == 22 && r.get(13) == Some(&2))
                }),
                6 => bad.packets.retain(|p| {
                    p.decrypted
                        || !records(&p.bytes)
                            .unwrap()
                            .iter()
                            .any(|r| r[0] == 22 && r.get(13) == Some(&1))
                }),
                _ => bad.completed = !case.completed,
            }
            assert!(grade(&bad, wrong).is_err(), "mutation {mutation}");
        }
        if !wrong {
            for index in 0..2 {
                for mutation in 0..4 {
                    let mut bad = case.clone();
                    let packet = bad
                        .packets
                        .iter_mut()
                        .filter(|p| p.decrypted)
                        .nth(index)
                        .unwrap();
                    match mutation {
                        0 => packet.bytes[0] ^= 0x10,
                        1 => packet.bytes[3] ^= 1,
                        2 => packet.bytes[4] ^= 1,
                        _ if index == 0 => {
                            let pos = packet
                                .bytes
                                .windows(6)
                                .position(|b| b == b"secure")
                                .unwrap();
                            packet.bytes[pos] = b'x';
                        }
                        _ => *packet.bytes.last_mut().unwrap() ^= 1,
                    }
                    assert!(
                        grade(&bad, false).is_err(),
                        "application {index} mutation {mutation}"
                    );
                }
            }
        }
        if wrong {
            for replacement in [vec![], vec![1, 20], vec![2, 51], vec![2, 115]] {
                let mut bad = case.clone();
                if replacement.is_empty() {
                    bad.packets.retain(|p| p.bytes.first() != Some(&21));
                } else {
                    for p in &mut bad.packets {
                        if p.bytes.first() == Some(&21) {
                            p.bytes[13..15].copy_from_slice(&replacement);
                        }
                    }
                }
                assert!(grade(&bad, true).is_err());
            }
            assert!(
                crate::grade::Catalog::load()
                    .unwrap()
                    .grade("TD_COAP_DTLS_02", &case.capture)
                    .is_err()
            );
        }
    }
    assert_eq!(identity(root), suite, "suite changed during capture");
    assert_eq!(
        identity(&root.join("coaptic")),
        core,
        "core changed during capture"
    );
    std::fs::write(directory.join("report.json"), serde_json::to_vec_pretty(&serde_json::json!({"provenance":provenance,"cases":reports,"complete":true,"mutation_refusals":44})).unwrap()).unwrap();
    assert!(crate::catalog::skip_reason("TD_COAP_DTLS_02").is_some());
}
