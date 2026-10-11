//! Bounded intact-datagram qualification of DTLS03 with a Coaptic server.

use super::*;
use std::net::UdpSocket;

const MAX_DATAGRAMS: usize = 256;
const CASE_TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
struct RecordKey {
    kind: u8,
    epoch: u16,
    handshake: Option<(u8, u16, u32, u32)>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
struct Target {
    from_client: bool,
    records: Vec<RecordKey>,
}

fn u24(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])
}

fn handshake_records(bytes: &[u8]) -> Result<Vec<RecordKey>, PeerError> {
    let mut remaining = bytes;
    let mut records = Vec::new();
    while !remaining.is_empty() {
        if remaining.len() < 13 {
            return Err(PeerError("truncated gateway DTLS record".into()));
        }
        let n = usize::from(u16::from_be_bytes([remaining[11], remaining[12]]));
        if remaining.len() < 13 + n {
            return Err(PeerError("truncated gateway DTLS body".into()));
        }
        let kind = remaining[0];
        let epoch = u16::from_be_bytes([remaining[3], remaining[4]]);
        let body = &remaining[13..13 + n];
        if matches!(kind, 20 | 22) {
            let handshake = if kind == 22 && epoch == 0 {
                if body.len() < 12 {
                    return Err(PeerError("truncated plaintext handshake".into()));
                }
                if u24(&body[9..12]) as usize != body.len() - 12
                    || u24(&body[6..9]) + u24(&body[9..12]) > u24(&body[1..4])
                {
                    return Err(PeerError(
                        "invalid plaintext handshake fragment bounds".into(),
                    ));
                }
                Some((
                    body[0],
                    u16::from_be_bytes([body[4], body[5]]),
                    u24(&body[6..9]),
                    u24(&body[9..12]),
                ))
            } else {
                None
            };
            records.push(RecordKey {
                kind,
                epoch,
                handshake,
            });
        }
        remaining = &remaining[13 + n..];
    }
    Ok(records)
}

#[derive(Clone, serde::Serialize)]
struct Event {
    target: Target,
    bytes: Vec<u8>,
    forwarded: bool,
    source: SocketAddr,
    destination: SocketAddr,
    sent_from: SocketAddr,
    forwarded_bytes: Option<Vec<u8>>,
}

#[derive(Clone)]
struct Case {
    capture: Capture,
    packets: Vec<crate::pcap::Packet>,
    events: Vec<Event>,
    endpoints: [SocketAddr; 4], // client, gateway front/back, server
    completed: bool,
    client_authenticated: bool,
    server_authenticated: bool,
    elapsed: Duration,
}

struct Gateway {
    stop: Arc<AtomicBool>,
    events: Arc<Mutex<Vec<Event>>>,
    join: Option<JoinHandle<Result<(), PeerError>>>,
}

impl Gateway {
    fn start(
        front: UdpSocket,
        back: UdpSocket,
        client: SocketAddr,
        server: SocketAddr,
        target: Option<Target>,
        drop_limit: usize,
        capture: Capture,
    ) -> Result<Self, PeerError> {
        front
            .set_nonblocking(true)
            .map_err(|e| PeerError(e.to_string()))?;
        back.set_nonblocking(true)
            .map_err(|e| PeerError(e.to_string()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let events = Arc::new(Mutex::new(Vec::new()));
        let thread_events = Arc::clone(&events);
        let join = thread::spawn(move || {
            let mut dropped = 0;
            let mut bytes = [0; 2048];
            while !thread_stop.load(Ordering::SeqCst) {
                for (from_client, incoming, outgoing, source, destination) in [
                    (true, &front, &back, client, server),
                    (false, &back, &front, server, client),
                ] {
                    match incoming.recv_from(&mut bytes) {
                        Ok((n, peer)) => {
                            if peer != source || n == bytes.len() {
                                return Err(PeerError("gateway owner/size refusal".into()));
                            }
                            if thread_events.lock().expect("gateway events").len() == MAX_DATAGRAMS
                            {
                                return Err(PeerError("gateway capture limit".into()));
                            }
                            let key = Target {
                                from_client,
                                records: handshake_records(&bytes[..n])?,
                            };
                            let lose = target.as_ref() == Some(&key) && dropped < drop_limit;
                            capture.push(
                                source,
                                incoming
                                    .local_addr()
                                    .map_err(|e| PeerError(e.to_string()))?,
                                &bytes[..n],
                                false,
                            );
                            if !lose {
                                if outgoing
                                    .send_to(&bytes[..n], destination)
                                    .map_err(|e| PeerError(e.to_string()))?
                                    != n
                                {
                                    return Err(PeerError("gateway short send".into()));
                                }
                            } else {
                                dropped += 1;
                            }
                            let mut log = thread_events.lock().expect("gateway events");
                            log.push(Event {
                                target: key,
                                bytes: bytes[..n].to_vec(),
                                forwarded: !lose,
                                source,
                                destination,
                                sent_from: outgoing
                                    .local_addr()
                                    .map_err(|e| PeerError(e.to_string()))?,
                                forwarded_bytes: (!lose).then(|| bytes[..n].to_vec()),
                            });
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => return Err(PeerError(e.to_string())),
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        });
        Ok(Self {
            stop,
            events,
            join: Some(join),
        })
    }

    fn finish(mut self) -> Result<Vec<Event>, PeerError> {
        self.stop.store(true, Ordering::SeqCst);
        self.join
            .take()
            .expect("gateway join")
            .join()
            .map_err(|_| PeerError("gateway panic".into()))??;
        Ok(self.events.lock().expect("gateway events").clone())
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn io_from_conn(conn: DTLSConn, local: SocketAddr, peer: SocketAddr) -> DtlsIo {
    let (in_tx, incoming) = std_mpsc::channel();
    let (outgoing, out_rx) = tokio_mpsc::unbounded_channel();
    tokio::spawn(pump(Arc::new(conn), in_tx, out_rx));
    DtlsIo {
        incoming,
        outgoing,
        local,
        peer: Arc::new(Mutex::new(peer)),
    }
}

#[derive(Clone, Copy)]
pub(super) enum ClientKind {
    Coaptic,
    CoapRs,
}
impl ClientKind {
    fn direction(self) -> &'static str {
        match self {
            Self::Coaptic => "coaptic-to-coaptic",
            Self::CoapRs => "coap-rs-to-coaptic",
        }
    }
}

// The actual coap-rs client owns CoAP encoding, matching and delivery. Only
// authenticated transport bytes are tapped here; DTLS still uses the same backend.
struct CapturedRsClient {
    connection: Arc<DTLSConn>,
    local: SocketAddr,
    peer: SocketAddr,
    capture: Capture,
}
#[async_trait]
impl coap::client::ClientTransport for CapturedRsClient {
    async fn recv(&self, bytes: &mut [u8]) -> std::io::Result<(usize, Option<SocketAddr>)> {
        let n = self
            .connection
            .recv(bytes)
            .await
            .map_err(std::io::Error::other)?;
        self.capture.push(self.peer, self.local, &bytes[..n], true);
        Ok((n, Some(self.peer)))
    }
    async fn send(&self, bytes: &[u8]) -> std::io::Result<usize> {
        self.capture.push(self.local, self.peer, bytes, true);
        let n = self
            .connection
            .send(bytes)
            .await
            .map_err(std::io::Error::other)?;
        Ok(n)
    }
}

async fn rs_get_over_connection(
    conn: DTLSConn,
    local: SocketAddr,
    peer: SocketAddr,
    capture: Capture,
) -> Result<(), PeerError> {
    let connection = Arc::new(conn);
    let client = coap::client::CoAPClient::from_transport(CapturedRsClient {
        connection: Arc::clone(&connection),
        local,
        peer,
        capture,
    });
    let mut request = coap::request::RequestBuilder::request_path(
        "/secure",
        coap_lite::RequestType::Get,
        None,
        vec![],
        Some(format!("coaps://{peer}/secure")),
    )
    .build();
    request.message.set_token(vec![0x44, 0x54, 0x4c, 0x53]);
    let response = client
        .send(request)
        .await
        .map_err(|e| PeerError(format!("coap-rs GET /secure: {e}")))?;
    let _ = tokio::time::timeout(Duration::from_secs(1), connection.close()).await;
    if response.message.header.code
        != coap_lite::MessageClass::Response(coap_lite::ResponseType::Content)
        || response.message.payload != site::SECURE_BODY
    {
        return Err(PeerError("coap-rs authenticated complete response".into()));
    }
    Ok(())
}

async fn exchange(target: Option<Target>, client_kind: ClientKind) -> Result<Case, PeerError> {
    exchange_with_limit(target, 1, client_kind).await
}

async fn exchange_with_limit(
    target: Option<Target>,
    drop_limit: usize,
    client_kind: ClientKind,
) -> Result<Case, PeerError> {
    let capture = Capture::new();
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| PeerError(e.to_string()))?;
    let server = tokio::net::UdpSocket::bind("127.0.0.1:5684")
        .await
        .map_err(|e| PeerError(format!("TD server5684: {e}")))?;
    let front = UdpSocket::bind("127.0.0.1:0").map_err(|e| PeerError(e.to_string()))?;
    let back = UdpSocket::bind("127.0.0.1:0").map_err(|e| PeerError(e.to_string()))?;
    let client_addr = client.local_addr().map_err(|e| PeerError(e.to_string()))?;
    let server_addr = server.local_addr().map_err(|e| PeerError(e.to_string()))?;
    let front_addr = front.local_addr().map_err(|e| PeerError(e.to_string()))?;
    let back_addr = back.local_addr().map_err(|e| PeerError(e.to_string()))?;
    client
        .connect(front_addr)
        .await
        .map_err(|e| PeerError(e.to_string()))?;
    server
        .connect(back_addr)
        .await
        .map_err(|e| PeerError(e.to_string()))?;
    let gateway = Gateway::start(
        front,
        back,
        client_addr,
        server_addr,
        target,
        drop_limit,
        capture.clone(),
    )?;
    let mut serving = None;
    let mut client_authenticated = false;
    let mut server_authenticated = false;
    let started = Instant::now();
    let result = tokio::time::timeout(CASE_TIMEOUT, async {
        let (client_conn, ()) = tokio::try_join!(
            async {
                let conn = DTLSConn::new(Arc::new(client), psk_config(PSK_KEY), true, None)
                    .await
                    .map_err(|e| PeerError(format!("client handshake: {e}")))?;
                client_authenticated = true;
                Ok::<_, PeerError>(conn)
            },
            async {
                let conn = DTLSConn::new(Arc::new(server), psk_config(PSK_KEY), false, None)
                    .await
                    .map_err(|e| PeerError(format!("server handshake: {e}")))?;
                server_authenticated = true;
                // The server must keep receiving after sending its Finished,
                // even while the client is recovering a lost final flight.
                let io = CapturingIo::new(
                    io_from_conn(conn, server_addr, back_addr),
                    server_addr,
                    capture.clone(),
                )
                .decrypted();
                serving = Some(spawn_coaptic_server(io));
                Ok(())
            },
        )?;
        match client_kind {
            ClientKind::Coaptic => {
                let client_io = CapturingIo::new(
                    io_from_conn(client_conn, client_addr, front_addr),
                    client_addr,
                    capture.clone(),
                )
                .decrypted();
                tokio::task::spawn_blocking(move || coaptic_get_secure(client_io, front_addr))
                    .await
                    .map_err(|e| PeerError(e.to_string()))?
            }
            ClientKind::CoapRs => {
                rs_get_over_connection(client_conn, client_addr, front_addr, capture.clone()).await
            }
        }
    })
    .await;
    if let Some(serving) = serving {
        serving.stop();
    }
    let events = gateway.finish()?;
    let completed = match result {
        Ok(result) => {
            result?;
            true
        }
        Err(_) => false,
    };
    Ok(Case {
        packets: capture.snapshot(),
        capture,
        events,
        endpoints: [client_addr, front_addr, back_addr, server_addr],
        completed,
        client_authenticated,
        server_authenticated,
        elapsed: started.elapsed(),
    })
}

fn grade_case(case: &Case, target: Option<&Target>, complete: bool) -> Result<(), String> {
    use coaptic::message::{Type, decode};
    let [client, front, back, server] = case.endpoints;
    if case.endpoints.iter().any(|e| !e.ip().is_loopback())
        || server.port() != 5684
        || case
            .endpoints
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != 4
        || case.events.is_empty()
        || case.events.len() > MAX_DATAGRAMS
        || case.completed != complete
        || !case.server_authenticated
        || case.client_authenticated != complete
    {
        return Err("case bounds, endpoints or authenticated completion".into());
    }
    let wire: Vec<_> = case.packets.iter().filter(|p| !p.decrypted).collect();
    if wire.len() != case.events.len() {
        return Err("gateway wire/event count".into());
    }
    let mut lost = None;
    let mut lost_count = 0;
    let mut record_ids = std::collections::HashSet::new();
    for (index, (event, packet)) in case.events.iter().zip(&wire).enumerate() {
        let (source, destination, sent_from, received_at) = if event.target.from_client {
            (client, server, back, front)
        } else {
            (server, client, front, back)
        };
        if (event.source, event.destination, event.sent_from) != (source, destination, sent_from)
            || (packet.src, packet.dst) != (source, received_at)
            || packet.bytes != event.bytes
            || handshake_records(&event.bytes).map_err(|e| e.0)? != event.target.records
            || event.forwarded_bytes.as_deref() != event.forwarded.then_some(event.bytes.as_slice())
        {
            return Err("gateway ownership or intact datagram mismatch".into());
        }
        let mut records = event.bytes.as_slice();
        while !records.is_empty() {
            let epoch = u16::from_be_bytes([records[3], records[4]]);
            let sequence = records[5..11]
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
            if !record_ids.insert((event.source, epoch, sequence)) {
                return Err("record sequence reused by connection writer".into());
            }
            let size = 13 + usize::from(u16::from_be_bytes([records[11], records[12]]));
            records = &records[size..];
        }
        if !event.forwarded {
            if (complete && lost.is_some()) || Some(&event.target) != target {
                return Err("wrong or repeated loss".into());
            }
            lost.get_or_insert(index);
            lost_count += 1;
        }
    }
    if target.is_some() != lost.is_some() {
        return Err("loss target unconsumed".into());
    }
    if let Some(index) = lost {
        let target = target.expect("lost target");
        if complete {
            if !case.events[index + 1..]
                .iter()
                .any(|e| e.forwarded && &e.target == target)
            {
                return Err("lost packet did not retransmit".into());
            }
        } else {
            // Permanent intact loss must end at the finite client deadline,
            // without exposing application traffic or inventing completion.
            if case.elapsed < CASE_TIMEOUT
                || lost_count < 2
                || target.from_client
                || target
                    .records
                    .iter()
                    .map(|r| (r.kind, r.epoch))
                    .collect::<Vec<_>>()
                    != [(20, 0), (22, 1)]
                || case.events[index + 1..]
                    .iter()
                    .any(|e| e.forwarded && &e.target == target)
            {
                return Err("not a bounded permanent final-flight loss refusal".into());
            }
            let prior = case.events[..index]
                .iter()
                .rev()
                .find(|e| e.target.from_client)
                .ok_or("missing client Finished flight")?;
            if prior
                .target
                .records
                .iter()
                .map(|r| (r.kind, r.epoch))
                .collect::<Vec<_>>()
                != [(22, 0), (20, 0), (22, 1)]
                || case.events[index + 1..]
                    .iter()
                    .filter(|e| e.forwarded && e.target == prior.target)
                    .count()
                    < 2
            {
                return Err("missing intact client final-flight retries".into());
            }
        }
    }
    let app: Vec<_> = case.packets.iter().filter(|p| p.decrypted).collect();
    if !complete {
        if !app.is_empty() {
            return Err("failed handshake delivered application data".into());
        }
        return Ok(());
    }
    if app.len() != 4 {
        return Err("complete application exchange missing".into());
    }
    let mut request_bytes = None;
    let mut response_bytes = None;
    for (index, packet) in app.into_iter().enumerate() {
        if (packet.src, packet.dst)
            != [
                (client, front),
                (back, server),
                (server, back),
                (front, client),
            ][index]
        {
            return Err("application exchange order/endpoint direction".into());
        }
        let message = decode(&packet.bytes).map_err(|e| format!("application decode {e:?}"))?;
        if message.code() == Code::GET {
            if ![(client, front), (back, server)].contains(&(packet.src, packet.dst))
                || message.ty() != Type::Confirmable
                || message.token().is_empty()
                || message.payload() != b""
                || message.uri_path().collect::<Vec<_>>() != [Ok("secure")]
            {
                return Err("authenticated request owner/path".into());
            }
            if request_bytes.is_some_and(|old| old != packet.bytes.as_slice()) {
                return Err("request changed across gateway".into());
            }
            request_bytes = Some(packet.bytes.as_slice());
        } else {
            if ![(server, back), (front, client)].contains(&(packet.src, packet.dst))
                || message.ty() != Type::Acknowledgement
                || message.code() != Code::CONTENT
                || message.payload() != site::SECURE_BODY
            {
                return Err("authenticated complete response owner/body".into());
            }
            if response_bytes.is_some_and(|old| old != packet.bytes.as_slice()) {
                return Err("response changed across gateway".into());
            }
            response_bytes = Some(packet.bytes.as_slice());
        }
    }
    let request =
        decode(request_bytes.ok_or("missing request")?).map_err(|e| format!("request {e:?}"))?;
    let response =
        decode(response_bytes.ok_or("missing response")?).map_err(|e| format!("response {e:?}"))?;
    if request.token() != response.token() || request.message_id() != response.message_id() {
        return Err("application response token/MID".into());
    }
    let capture = Capture::new();
    for p in &case.packets {
        capture.push(p.src, p.dst, &p.bytes, p.decrypted);
    }
    crate::grade::Catalog::load()?.grade("TD_COAP_DTLS_01", &capture)
}

fn retain(cases: &[Case], targets: &[Target], client_kind: ClientKind) {
    let Some(directory) = std::env::var_os("COAPTIC_OBSERVE_CAPTURE_DIR") else {
        return;
    };
    let directory = std::path::PathBuf::from(directory).join(match client_kind {
        ClientKind::Coaptic => "dtls03-loss",
        ClientKind::CoapRs => "dtls03-coap-rs-loss",
    });
    std::fs::create_dir_all(&directory).unwrap();
    let mut reports = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        case.capture
            .write_pcap(
                std::fs::File::create(directory.join(format!("case-{index}.pcap"))).unwrap(),
            )
            .unwrap();
        reports.push(serde_json::json!({"case":index,"completed":case.completed,"client_authenticated":case.client_authenticated,"server_authenticated":case.server_authenticated,"elapsed_ms":case.elapsed.as_millis(),"endpoints":case.endpoints,"events":case.events,"application":case.packets.iter().filter(|p| p.decrypted).map(|p| serde_json::json!({"source":p.src,"destination":p.dst,"bytes":p.bytes})).collect::<Vec<_>>() }));
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let identity = |path: &std::path::Path| {
        let git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .arg("-C")
                .arg(path)
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        serde_json::json!({"revision":git(&["rev-parse","HEAD"]),"dirty":!git(&["status","--porcelain"]).is_empty()})
    };
    let report = serde_json::json!({"literal_td":"TD_COAP_DTLS_03","literal_complete":true,"literal_status":"PASS","direction":client_kind.direction(),"suite":identity(root),"core":identity(&root.join("coaptic")),"backend":"vendored webrtc-dtls 0.12.0 with bounded final-flight retention","normal_targets":targets,"cases":reports,"case_order":"baseline, six targeted one-datagram losses, permanent final-flight loss refusal, fresh recovery","fixture_mapping":"TD /secure stimulus chosen over inconsistent /test step; UDP server port5684; exact secure fixture body","limitations":"Coaptic-to-coap-rs remains SKIP; shared DTLS backend, not independent cryptographic interoperability; no first-party core DTLS, DTLS02 alert or RPK claim"});
    std::fs::write(
        directory.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}

fn qualify(client_kind: ClientKind) -> Result<(Vec<Case>, Vec<Target>), PeerError> {
    let baseline = runtime()?.block_on(exchange(None, client_kind))?;
    grade_case(&baseline, None, true).map_err(PeerError)?;
    let targets: Vec<_> = baseline
        .events
        .iter()
        .filter(|event| !event.target.records.is_empty())
        .map(|event| event.target.clone())
        .collect();
    if targets.len() != 6
        || targets
            .iter()
            .enumerate()
            .any(|(i, target)| targets[..i].contains(target))
    {
        return Err(PeerError(
            "normal handshake packetization changed; audit every target".into(),
        ));
    }
    let mut cases = vec![baseline];
    for target in &targets {
        let case = runtime()?.block_on(exchange(Some(target.clone()), client_kind))?;
        grade_case(&case, Some(target), true).map_err(PeerError)?;
        cases.push(case);
    }
    let refused = runtime()?.block_on(exchange_with_limit(
        Some(targets[5].clone()),
        MAX_DATAGRAMS,
        client_kind,
    ))?;
    grade_case(&refused, Some(&targets[5]), false).map_err(PeerError)?;
    cases.push(refused);
    let recovery = runtime()?.block_on(exchange(None, client_kind))?;
    grade_case(&recovery, None, true).map_err(PeerError)?;
    cases.push(recovery);
    retain(&cases, &targets, client_kind);
    Ok((cases, targets))
}

pub(super) fn run(client_kind: ClientKind) -> Result<Capture, PeerError> {
    let (cases, _) = qualify(client_kind)?;
    Ok(cases[0].capture.clone())
}

#[test]
fn dtls03_all_intact_losses_refuse_permanent_loss_and_fresh_recovery() {
    loss_campaign(ClientKind::Coaptic);
}
#[test]
fn dtls03_coap_rs_intact_losses_refuse_permanent_loss_and_fresh_recovery() {
    loss_campaign(ClientKind::CoapRs);
}
#[cfg(test)]
fn loss_campaign(client_kind: ClientKind) {
    let _guard = crate::runner::harness_lock();
    let (cases, targets) = qualify(client_kind).unwrap();
    assert!(cases[..7].iter().all(|case| case.completed));
    assert!(!cases[7].completed);
    assert!(cases[8].completed);
    let mut false_completion = cases[7].clone();
    false_completion.completed = true;
    assert!(grade_case(&false_completion, Some(&targets[5]), false).is_err());
    let mut false_authentication = cases[7].clone();
    false_authentication.client_authenticated = true;
    assert!(grade_case(&false_authentication, Some(&targets[5]), false).is_err());
    for index in 1..=6 {
        let target = &targets[index - 1];
        for fault in [
            "missing-loss",
            "wrong-target",
            "changed-wire",
            "wrong-owner",
            "false-completion",
            "missing-retry",
            "record-sequence-reuse",
            "application",
            "response-body",
            "response-token",
            "response-mid",
        ] {
            let mut changed = cases[index].clone();
            let lost = changed.events.iter().position(|e| !e.forwarded).unwrap();
            match fault {
                "missing-loss" => {
                    changed.events[lost].forwarded = true;
                    changed.events[lost].forwarded_bytes = Some(changed.events[lost].bytes.clone());
                }
                "wrong-target" => changed.events[lost].target.from_client ^= true,
                "changed-wire" => changed.events[lost].bytes[0] ^= 1,
                "wrong-owner" => changed.events[lost].source = changed.events[lost].destination,
                "false-completion" => changed.completed ^= true,
                "missing-retry" => {
                    let remove: Vec<_> = changed
                        .events
                        .iter()
                        .enumerate()
                        .map(|(i, e)| i > lost && &e.target == target)
                        .collect();
                    let mut wire_index = 0;
                    changed.packets.retain(|p| {
                        if p.decrypted {
                            true
                        } else {
                            let keep = !remove[wire_index];
                            wire_index += 1;
                            keep
                        }
                    });
                    changed.events = changed
                        .events
                        .into_iter()
                        .zip(remove)
                        .filter_map(|(e, remove)| (!remove).then_some(e))
                        .collect();
                }
                "record-sequence-reuse" => {
                    let retry = changed
                        .events
                        .iter()
                        .enumerate()
                        .find(|(i, event)| *i > lost && &event.target == target)
                        .unwrap()
                        .0;
                    let original_sequence = changed.events[lost].bytes[5..11].to_vec();
                    changed.events[retry].bytes[5..11].copy_from_slice(&original_sequence);
                    changed.events[retry].forwarded_bytes =
                        Some(changed.events[retry].bytes.clone());
                    changed
                        .packets
                        .iter_mut()
                        .filter(|packet| !packet.decrypted)
                        .nth(retry)
                        .unwrap()
                        .bytes = changed.events[retry].bytes.clone();
                }
                "response-body" | "response-token" | "response-mid" => {
                    for packet in changed
                        .packets
                        .iter_mut()
                        .filter(|p| p.decrypted && p.bytes[1] == 69)
                    {
                        let index = match fault {
                            "response-body" => packet.bytes.len() - 1,
                            "response-token" => 4,
                            "response-mid" => 3,
                            _ => unreachable!(),
                        };
                        packet.bytes[index] ^= 1;
                    }
                }
                "application" => {
                    if let Some(p) = changed.packets.iter_mut().find(|p| p.decrypted) {
                        *p.bytes.last_mut().unwrap() ^= 1;
                    } else {
                        let mut p = changed.packets[0].clone();
                        p.decrypted = true;
                        changed.packets.push(p);
                    }
                }
                _ => unreachable!(),
            }
            assert!(
                grade_case(&changed, Some(target), true).is_err(),
                "accepted case{index} {fault}"
            );
        }
    }
}

#[test]
fn dtls03_final_flight_loss_recovers_same_connection() {
    let _guard = crate::runner::harness_lock();
    let baseline = runtime()
        .unwrap()
        .block_on(exchange(None, ClientKind::Coaptic))
        .unwrap();
    grade_case(&baseline, None, true).unwrap();
    let targets: Vec<_> = baseline
        .events
        .iter()
        .filter(|event| !event.target.records.is_empty())
        .map(|event| event.target.clone())
        .collect();
    assert_eq!(targets.len(), 6);
    let final_flight = &targets[5];
    let recovered = runtime()
        .unwrap()
        .block_on(exchange(Some(final_flight.clone()), ClientKind::Coaptic))
        .unwrap();
    grade_case(&recovered, Some(final_flight), true).unwrap();
}
