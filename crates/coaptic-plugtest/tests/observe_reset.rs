//! RFC 7641 section 4.5 socket qualification, not TD_COAP_OBS_06 (CON).
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use coaptic::message::{Code, Message, MessageId, Opt, Token, Type, decode, encode, encode_uint};
use coaptic_plugtest::coaptic::CoapticPeer;
use coaptic_plugtest::pcap::Packet;
use coaptic_plugtest::peer::Peer;
use coaptic_plugtest::site;

fn send(socket: &UdpSocket, dest: SocketAddr, message: &Message<'_>) {
    let mut bytes = [0; 128];
    let n = encode(message, &mut bytes).unwrap();
    assert_eq!(socket.send_to(&bytes[..n], dest).unwrap(), n);
}

fn receive(socket: &UdpSocket, server: SocketAddr) -> Vec<u8> {
    let mut bytes = [0; 256];
    let (n, from) = socket.recv_from(&mut bytes).unwrap();
    assert_eq!(from, server);
    bytes[..n].to_vec()
}

fn register(socket: &UdpSocket, server: SocketAddr, mid: u16, token: &[u8]) {
    let observe = encode_uint(0);
    let options = [Opt::observe(&observe), Opt::uri_path("obs-non")];
    send(
        socket,
        server,
        &Message::new(Type::Confirmable, Code::GET, MessageId::new(mid))
            .with_token(Token::new(token).unwrap())
            .with_options(&options),
    );
    let bytes = receive(socket, server);
    let response = decode(&bytes).unwrap();
    assert_eq!(response.ty(), Type::Acknowledgement);
    assert_eq!(response.code(), Code::CONTENT);
    assert_eq!(response.token().as_bytes(), token);
    assert!(response.observe().is_some());
}

fn notify(
    peer: &mut CoapticPeer,
    socket: &UdpSocket,
    server: SocketAddr,
    token: &[u8],
) -> MessageId {
    std::thread::sleep(Duration::from_millis(3020));
    peer.notify(&["obs-non"], site::OBS_BODY_2).unwrap();
    let bytes = receive(socket, server);
    let response = decode(&bytes).unwrap();
    assert_eq!(response.ty(), Type::NonConfirmable);
    assert_eq!(response.code(), Code::CONTENT);
    assert_eq!(response.token().as_bytes(), token);
    assert_eq!(response.payload(), site::OBS_BODY_2);
    assert!(response.observe().is_some());
    response.message_id()
}

fn reset(peer: &mut CoapticPeer, socket: &UdpSocket, server: SocketAddr, mid: MessageId) {
    let before = peer.take_capture().snapshot().len();
    send(socket, server, &Message::new(Type::Reset, Code::EMPTY, mid));
    let deadline = Instant::now() + Duration::from_secs(1);
    while peer.take_capture().snapshot().len() == before {
        assert!(Instant::now() < deadline, "server did not receive reset");
        std::thread::sleep(Duration::from_millis(2));
    }
}

// Grade the server's single tap, so every datagram occurs exactly once. Exact
// order rejects missing refusal steps, an unmatched accepted reset, and any
// notification after removal, including during the health check.
fn grade(packets: &[Packet]) -> Result<(), String> {
    if packets.len() != 13 {
        return Err(format!("expected 13 packets, got {}", packets.len()));
    }
    let p: Vec<_> = packets
        .iter()
        .map(|p| decode(&p.bytes).map_err(|e| format!("{e:?}")))
        .collect::<Result<_, _>>()?;
    let server = packets[0].dst;
    let client = packets[0].src;
    for i in [0, 10] {
        if p[i].ty() != Type::Confirmable
            || p[i].code() != Code::GET
            || p[i].observe() != Some(Ok(0))
            || p[i].token().is_empty()
        {
            return Err(format!("registration {i}"));
        }
        if p[i + 1].ty() != Type::Acknowledgement
            || p[i + 1].code() != Code::CONTENT
            || p[i + 1].message_id() != p[i].message_id()
            || p[i + 1].token() != p[i].token()
            || p[i + 1].observe().is_none()
        {
            return Err(format!("registration response {i}"));
        }
    }
    for i in [2, 4, 6, 12] {
        let reg = if i == 12 { 10 } else { 0 };
        if packets[i].src != server
            || packets[i].dst != client
            || p[i].ty() != Type::NonConfirmable
            || p[i].code() != Code::CONTENT
            || p[i].token() != p[reg].token()
            || p[i].observe().is_none()
            || p[i].payload() != site::OBS_BODY_2
        {
            return Err(format!("notification {i}"));
        }
    }
    for i in [3, 5, 7] {
        if p[i].ty() != Type::Reset
            || p[i].code() != Code::EMPTY
            || !p[i].token().is_empty()
            || !p[i].payload().is_empty()
            || packets[i].dst != server
        {
            return Err(format!("reset {i}"));
        }
    }
    if packets[3].src != client
        || p[3].message_id() == p[2].message_id()
        || packets[5].src == client
        || p[5].message_id() != p[4].message_id()
        || packets[7].src != client
        || p[7].message_id() != p[6].message_id()
    {
        return Err("reset ownership".into());
    }
    if p[8].code() != Code::GET
        || p[8].observe().is_some()
        || p[9].code() != Code::CONTENT
        || p[9].ty() != Type::Acknowledgement
        || p[9].message_id() != p[8].message_id()
        || p[9].token() != p[8].token()
    {
        return Err("server health exchange".into());
    }
    Ok(())
}

#[test]
fn non_reset_requires_matching_endpoint_and_mid_then_allows_fresh_registration() {
    let mut peer = CoapticPeer::new();
    let server = peer.start_server().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
    register(&client, server, 10, b"old");
    let mid = notify(&mut peer, &client, server, b"old");
    reset(
        &mut peer,
        &client,
        server,
        MessageId::new(mid.get().wrapping_add(1)),
    );
    let mid = notify(&mut peer, &client, server, b"old");
    reset(&mut peer, &stranger, server, mid);
    let mid = notify(&mut peer, &client, server, b"old");
    reset(&mut peer, &client, server, mid);
    std::thread::sleep(Duration::from_millis(3020));
    peer.notify(&["obs-non"], site::OBS_BODY_2).unwrap();
    // Exceeds the 3-second NON hold; silence cannot pass merely because the
    // rate limiter postponed a still-registered observer's notification.
    client
        .set_read_timeout(Some(Duration::from_millis(3500)))
        .unwrap();
    let error = client.recv_from(&mut [0; 256]).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let options = [Opt::uri_path("test")];
    send(
        &client,
        server,
        &Message::new(Type::Confirmable, Code::GET, MessageId::new(11))
            .with_token(Token::new(b"health").unwrap())
            .with_options(&options),
    );
    assert_eq!(
        decode(&receive(&client, server)).unwrap().code(),
        Code::CONTENT
    );
    register(&client, server, 12, b"new");
    notify(&mut peer, &client, server, b"new");
    peer.stop_server();
    let capture = peer.take_capture();
    let packets = capture.snapshot();
    grade(&packets).unwrap();
    for mutation in [
        "missing-reset",
        "wrong-mid",
        "wrong-endpoint",
        "late-notification",
        "payload",
    ] {
        let mut changed = packets.clone();
        match mutation {
            "missing-reset" => {
                changed.remove(7);
            }
            "wrong-mid" => changed[7].bytes[3] ^= 1,
            "wrong-endpoint" => changed[7].src = stranger.local_addr().unwrap(),
            "late-notification" => {
                changed.insert(8, packets[6].clone());
            }
            "payload" => *changed[12].bytes.last_mut().unwrap() ^= 1,
            _ => unreachable!(),
        }
        assert!(grade(&changed).is_err(), "accepted {mutation}");
    }
    if let Some(directory) = std::env::var_os("COAPTIC_OBSERVE_CAPTURE_DIR") {
        std::fs::create_dir_all(&directory).unwrap();
        capture
            .write_pcap(
                std::fs::File::create(
                    std::path::PathBuf::from(directory).join("rfc7641-non-reset.pcap"),
                )
                .unwrap(),
            )
            .unwrap();
    }
    assert!(coaptic_plugtest::catalog::skip_reason("TD_COAP_OBS_06").is_some());
}
