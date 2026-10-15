//! RFC 8613 Appendix C vectors and a pairwise request/response.

extern crate std;

use super::{
    DeriveParams, Error, LIVE_REQUESTS, OscoreContext, RequestRef, SecurityContext, cbor,
    header::{self, OptionClass, PartialIv},
};
use crate::message::{
    BlockValue, Code, ContentFormat, Message, MessageId, NoResponse, Opt, OptionsBuilder, Token,
    Type, decode, encode, encode_uint,
};
use crate::storage::{DatagramIo, Endpoint};

fn hex(s: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    let n = s.len() / 2;
    assert!(n <= 64);
    for i in 0..n {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex_n(s: &str) -> ([u8; 64], usize) {
    (hex(s), s.len() / 2)
}

fn slice(buf: &[u8; 64], n: usize) -> &[u8] {
    &buf[..n]
}

const MASTER_SECRET: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];
const MASTER_SALT: [u8; 8] = [0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40];

fn client_c1() -> SecurityContext {
    SecurityContext::derive(DeriveParams {
        master_secret: &MASTER_SECRET,
        master_salt: &MASTER_SALT,
        sender_id: &[],
        recipient_id: &[0x01],
        id_context: &[],
    })
    .unwrap()
}

fn server_c1() -> SecurityContext {
    SecurityContext::derive(DeriveParams {
        master_secret: &MASTER_SECRET,
        master_salt: &MASTER_SALT,
        sender_id: &[0x01],
        recipient_id: &[],
        id_context: &[],
    })
    .unwrap()
}

#[derive(Default)]
struct Loopback {
    inbox: Option<(Endpoint, [u8; 256], usize)>,
    last_send: Option<(Endpoint, [u8; 256], usize)>,
}

impl DatagramIo for Loopback {
    type Error = &'static str;

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        let Some((ep, bytes, n)) = self.inbox.take() else {
            return Ok(None);
        };
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok(Some((n, ep)))
    }

    fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        let mut slot = [0u8; 256];
        slot[..bytes.len()].copy_from_slice(bytes);
        self.last_send = Some((dest, slot, bytes.len()));
        Ok(bytes.len())
    }
}

#[test]
fn c1_key_derivation_with_master_salt() {
    let client = client_c1();
    assert_eq!(
        client.sender_key(),
        &[
            0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4, 0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43,
            0x02, 0xff
        ]
    );
    assert_eq!(
        client.recipient_key(),
        &[
            0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca, 0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9,
            0x87, 0x10
        ]
    );
    assert_eq!(
        client.common_iv(),
        &[
            0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68, 0xee, 0xfb, 0x54, 0x98, 0x7c
        ]
    );

    let server = server_c1();
    assert_eq!(server.sender_key(), client.recipient_key());
    assert_eq!(server.recipient_key(), client.sender_key());
    assert_eq!(server.common_iv(), client.common_iv());
}

#[test]
fn c1_info_cbor() {
    let mut info = [0u8; 32];
    let n = cbor::encode_info(&mut info, &[], None, "Key", 16).unwrap();
    assert_eq!(&info[..n], &hex("8540f60a634b657910")[..9]);
    let n = cbor::encode_info(&mut info, &[0x01], None, "Key", 16).unwrap();
    assert_eq!(&info[..n], &hex("854101f60a634b657910")[..10]);
    let n = cbor::encode_info(&mut info, &[], None, "IV", 13).unwrap();
    assert_eq!(&info[..n], &hex("8540f60a6249560d")[..8]);
}

#[test]
fn c2_key_derivation_without_salt() {
    let client = SecurityContext::derive(DeriveParams {
        master_secret: &MASTER_SECRET,
        master_salt: &[],
        sender_id: &[0x00],
        recipient_id: &[0x01],
        id_context: &[],
    })
    .unwrap();
    assert_eq!(
        client.sender_key(),
        &[
            0x32, 0x1b, 0x26, 0x94, 0x32, 0x53, 0xc7, 0xff, 0xb6, 0x00, 0x3b, 0x0b, 0x64, 0xd7,
            0x40, 0x41
        ]
    );
    assert_eq!(
        client.recipient_key(),
        &[
            0xe5, 0x7b, 0x56, 0x35, 0x81, 0x51, 0x77, 0xcd, 0x67, 0x9a, 0xb4, 0xbc, 0xec, 0x9d,
            0x7d, 0xda
        ]
    );
    assert_eq!(
        client.common_iv(),
        &[
            0xbe, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9, 0x10, 0xc5, 0x2e, 0x99, 0xf9
        ]
    );
}

#[test]
fn c3_key_derivation_with_id_context() {
    let id_context = [0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3];
    let client = SecurityContext::derive(DeriveParams {
        master_secret: &MASTER_SECRET,
        master_salt: &MASTER_SALT,
        sender_id: &[],
        recipient_id: &[0x01],
        id_context: &id_context,
    })
    .unwrap();
    assert_eq!(
        client.sender_key(),
        &[
            0xaf, 0x2a, 0x13, 0x00, 0xa5, 0xe9, 0x57, 0x88, 0xb3, 0x56, 0x33, 0x6e, 0xee, 0xcd,
            0x2b, 0x92
        ]
    );
    assert_eq!(
        client.common_iv(),
        &[
            0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c, 0x0b, 0x71, 0x81, 0xb8, 0x5e
        ]
    );
}

#[test]
fn c4_protected_request() {
    let mut client = client_c1();
    client.set_sender_seq(20).unwrap();
    let mut host_path = OptionsBuilder::<2>::new();
    host_path.push(Opt::uri_host("localhost")).unwrap();
    host_path.push(Opt::uri_path("tv1")).unwrap();
    let plain = Message::new(Type::Confirmable, Code::GET, MessageId::new(0x5d1f))
        .with_token(Token::from_checked(&[0x00, 0x00, 0x39, 0x74]))
        .with_options(host_path.as_slice());

    let mut out = [0u8; 64];
    let n = client.protect_request(&plain, &mut out).unwrap();
    let (expected, en) =
        hex_n("44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e");
    assert_eq!(&out[..n], slice(&expected, en));
}

#[test]
fn c5_protected_request_nonzero_kid() {
    let mut client = SecurityContext::derive(DeriveParams {
        master_secret: &MASTER_SECRET,
        master_salt: &[],
        sender_id: &[0x00],
        recipient_id: &[0x01],
        id_context: &[],
    })
    .unwrap();
    client.set_sender_seq(20).unwrap();
    let mut host_path = OptionsBuilder::<2>::new();
    host_path.push(Opt::uri_host("localhost")).unwrap();
    host_path.push(Opt::uri_path("tv1")).unwrap();
    let plain = Message::new(Type::Confirmable, Code::GET, MessageId::new(0x71c3))
        .with_token(Token::from_checked(&[0x00, 0x00, 0xb9, 0x32]))
        .with_options(host_path.as_slice());

    let mut out = [0u8; 64];
    let n = client.protect_request(&plain, &mut out).unwrap();
    let (expected, en) =
        hex_n("440271c30000b932396c6f63616c686f737463091400ff4ed339a5a379b0b8bc731fffb0");
    assert_eq!(&out[..n], slice(&expected, en));
}

#[test]
fn c6_protected_request_kid_context() {
    let id_context = [0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3];
    let mut client = SecurityContext::derive(DeriveParams {
        master_secret: &MASTER_SECRET,
        master_salt: &MASTER_SALT,
        sender_id: &[],
        recipient_id: &[0x01],
        id_context: &id_context,
    })
    .unwrap();
    client.set_sender_seq(20).unwrap();
    let mut host_path = OptionsBuilder::<2>::new();
    host_path.push(Opt::uri_host("localhost")).unwrap();
    host_path.push(Opt::uri_path("tv1")).unwrap();
    let plain = Message::new(Type::Confirmable, Code::GET, MessageId::new(0x2f8e))
        .with_token(Token::from_checked(&[0xef, 0x9b, 0xbf, 0x7a]))
        .with_options(host_path.as_slice());

    let mut out = [0u8; 80];
    let n = client.protect_request(&plain, &mut out).unwrap();
    let (expected, en) = hex_n(
        "44022f8eef9bbf7a396c6f63616c686f73746b19140837cbf3210017a2d3ff72cd7273fd331ac45cffbe55c3",
    );
    assert_eq!(&out[..n], slice(&expected, en));
}

#[test]
fn c7_protected_response() {
    let mut client = client_c1();
    client.set_sender_seq(20).unwrap();
    let mut server = server_c1();

    let mut host_path = OptionsBuilder::<2>::new();
    host_path.push(Opt::uri_host("localhost")).unwrap();
    host_path.push(Opt::uri_path("tv1")).unwrap();
    let req = Message::new(Type::Confirmable, Code::GET, MessageId::new(0x5d1f))
        .with_token(Token::from_checked(&[0x00, 0x00, 0x39, 0x74]))
        .with_options(host_path.as_slice());

    let mut wire = [0u8; 64];
    let n = client.protect_request(&req, &mut wire).unwrap();
    let protected_req = decode(&wire[..n]).unwrap();
    let mut inner = [0u8; 64];
    let (_plain, request) = server
        .unprotect_request(&protected_req, &mut inner)
        .unwrap();

    let resp = Message::new(Type::Acknowledgement, Code::CONTENT, MessageId::new(0x5d1f))
        .with_token(Token::from_checked(&[0x00, 0x00, 0x39, 0x74]))
        .with_payload(b"Hello World!");

    let mut out = [0u8; 64];
    let n = server.protect_response(&resp, request, &mut out).unwrap();
    let (expected, en) = hex_n("64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106");
    assert_eq!(&out[..n], slice(&expected, en));

    let protected_resp = decode(&out[..n]).unwrap();
    let mut opened = [0u8; 64];
    let inner = client
        .unprotect_response(&protected_resp, request, &mut opened)
        .unwrap();
    assert_eq!(inner.code(), Code::CONTENT);
    assert_eq!(inner.payload(), b"Hello World!");
}

#[test]
fn c8_protected_response_with_piv() {
    let mut server = server_c1();
    let request = super::RequestRef::from_kid(&[], PartialIv::from_seq(20).unwrap()).unwrap();
    let resp = Message::new(Type::Acknowledgement, Code::CONTENT, MessageId::new(0x5d1f))
        .with_token(Token::from_checked(&[0x00, 0x00, 0x39, 0x74]))
        .with_payload(b"Hello World!");
    let mut out = [0u8; 64];
    let n = server
        .protect_response_with_piv(&resp, request, &mut out)
        .unwrap();
    // Appendix C.8
    let (expected, en) =
        hex_n("64445d1f00003974920100ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e");
    assert_eq!(&out[..n], slice(&expected, en));
}

#[test]
fn replay_rejects_duplicate_piv() {
    let mut client = client_c1();
    let mut server = server_c1();
    let mut path = OptionsBuilder::<1>::new();
    path.push(Opt::uri_path("tv1")).unwrap();
    let req = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(path.as_slice());
    let mut wire = [0u8; 64];
    let n = client.protect_request(&req, &mut wire).unwrap();
    let protected = decode(&wire[..n]).unwrap();
    let mut inner = [0u8; 64];
    server.unprotect_request(&protected, &mut inner).unwrap();
    let mut inner2 = [0u8; 64];
    assert_eq!(
        server.unprotect_request(&protected, &mut inner2),
        Err(Error::Replay)
    );
}

#[test]
fn trait_object_not_needed_but_impl_works() {
    fn protect<C: OscoreContext>(ctx: &mut C, msg: &Message<'_>, out: &mut [u8]) -> usize {
        ctx.protect_request(msg, out).unwrap()
    }
    let mut client = client_c1();
    let req = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
        .with_token(Token::from_checked(&[1]));
    let mut out = [0u8; 64];
    assert!(protect(&mut client, &req, &mut out) > 4);
}

#[test]
fn app_protected_get_round_trip() {
    use crate::{App, Request, Response, get, profiles};

    fn hello(_req: Request<'_>) -> Response<'static> {
        Response::content(b"Hello World!")
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("tv1", get(hello))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let call = client.get("tv1").to(server_ep).send(0).unwrap();
    let (_, bytes, n) = client.transport().last_send.expect("protected request");
    let req = decode(&bytes[..n]).unwrap();
    assert_eq!(req.code(), Code::POST);
    assert!(req.oscore().is_some());

    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.poll(0).unwrap();
    let (_, bytes, n) = server.transport().last_send.expect("protected response");
    let resp = decode(&bytes[..n]).unwrap();
    assert_eq!(resp.code(), Code::CHANGED);
    assert!(resp.oscore().is_some());

    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(0).unwrap();
    let response = client
        .take_response(call)
        .expect("unprotected response")
        .expect("remote response");
    assert_eq!(response.code(), Code::CONTENT);
    assert_eq!(response.payload(), b"Hello World!");
}

#[test]
fn app_five_sequential_oscore_gets() {
    use crate::{App, Request, Response, get, profiles};

    fn hello(_req: Request<'_>) -> Response<'static> {
        Response::content(b"ok")
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("tv1", get(hello))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    for i in 0..=LIVE_REQUESTS {
        let call = client
            .get("tv1")
            .to(server_ep)
            .send(u64::from(i as u32))
            .unwrap();
        let (_, bytes, n) = client.transport().last_send.expect("protected request");
        server.transport_mut().inbox = Some((client_ep, bytes, n));
        server.transport_mut().last_send = None;
        server.poll(u64::from(i as u32)).unwrap();
        let (_, bytes, n) = server
            .transport()
            .last_send
            .unwrap_or_else(|| panic!("response {i} dropped (live table?)"));
        client.transport_mut().inbox = Some((server_ep, bytes, n));
        client.poll(u64::from(i as u32)).unwrap();
        let response = client
            .take_response(call)
            .unwrap_or_else(|| panic!("call {i} incomplete"))
            .expect("remote response");
        assert_eq!(response.code(), Code::CONTENT);
        assert_eq!(response.payload(), b"ok");
    }
    assert_eq!(
        client.oscore().expect("ctx").sender_seq(),
        (LIVE_REQUESTS + 1) as u64
    );
}

#[test]
fn app_plain_response_does_not_complete_oscore_call() {
    use crate::{App, profiles};

    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let call = client.get("tv1").to(server_ep).send(0).unwrap();
    let (_, bytes, n) = client.transport().last_send.expect("protected request");
    let req = decode(&bytes[..n]).unwrap();
    assert!(req.oscore().is_some());

    let plain = Message::new(Type::Acknowledgement, Code::CONTENT, req.message_id())
        .with_token(req.token())
        .with_payload(b"pwned");
    let mut wire = [0u8; 256];
    let pn = encode(&plain, &mut wire).unwrap();
    client.transport_mut().inbox = Some((server_ep, wire, pn));
    client.poll(0).unwrap();
    assert!(
        client.take_response(call).is_none(),
        "unprotected 2.xx must not complete an OSCORE Call"
    );
}

#[test]
fn app_bad_ciphertext_is_silent_drop() {
    use crate::{App, Request, Response, get, profiles};

    fn hello(_req: Request<'_>) -> Response<'static> {
        Response::content(b"Hello World!")
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("tv1", get(hello))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let _ = client.get("tv1").to(server_ep).send(0).unwrap();
    let (_, mut bytes, n) = client.transport().last_send.expect("protected request");
    bytes[n - 1] ^= 0xff;
    let parsed = decode(&bytes[..n]).unwrap();
    assert!(parsed.oscore().is_some());
    assert!(parsed.code().is_request());

    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.transport_mut().last_send = None;
    server.poll(0).unwrap();
    assert!(
        server.transport().last_send.is_none(),
        "AEAD failure must not emit an unprotected 4.00"
    );
}

#[test]
fn app_oscore_con_retransmit_replays_protected_ack() {
    use crate::{App, Request, Response, get, profiles};
    use core::sync::atomic::{AtomicU32, Ordering};

    static HITS: AtomicU32 = AtomicU32::new(0);
    fn hello(_req: Request<'_>) -> Response<'static> {
        HITS.fetch_add(1, Ordering::SeqCst);
        Response::content(b"Hello World!")
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("tv1", get(hello))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let _ = client.get("tv1").to(server_ep).send(0).unwrap();
    let (_, bytes, n) = client.transport().last_send.expect("protected request");

    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.poll(0).unwrap();
    let first = server.transport().last_send.expect("first ACK");

    server.transport_mut().last_send = None;
    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.poll(1).unwrap();
    let replay = server.transport().last_send.expect("Dedup replay");
    assert_eq!(first, replay);
    assert_eq!(HITS.load(Ordering::SeqCst), 1);
}

#[test]
fn live_request_table_is_four_and_saturates() {
    let mut ctx = client_c1();
    let request = RequestRef::from_kid(&[], PartialIv::from_seq(1).unwrap()).unwrap();
    for i in 0..LIVE_REQUESTS {
        let token = Token::from_checked(&[i as u8 + 1]);
        ctx.remember(token, request).unwrap();
    }
    assert_eq!(
        ctx.remember(Token::from_checked(&[LIVE_REQUESTS as u8 + 1]), request),
        Err(Error::Saturated)
    );
}

#[test]
fn accept_notification_duplicate_piv_is_replay() {
    let mut ctx = client_c1();
    let token = Token::from_checked(&[1]);
    let request = RequestRef::from_kid(&[], PartialIv::from_seq(1).unwrap()).unwrap();
    ctx.remember_live(token, request, true).unwrap();

    ctx.accept_notification(token, None).unwrap();
    assert_eq!(
        ctx.accept_notification(token, None),
        Err(Error::Replay),
        "at most one notification without Partial IV"
    );

    let piv = PartialIv::from_seq(5).unwrap();
    ctx.accept_notification(token, Some(piv)).unwrap();
    assert_eq!(
        ctx.accept_notification(token, Some(piv)),
        Err(Error::Replay),
        "duplicate notify PIV is Replay (RFC 8613 §7.4.1)"
    );
    assert_eq!(
        ctx.accept_notification(token, Some(PartialIv::from_seq(4).unwrap())),
        Err(Error::Replay),
        "Notification Number must strictly increase"
    );
    ctx.accept_notification(token, Some(PartialIv::from_seq(6).unwrap()))
        .unwrap();
}

#[test]
fn observe_register_is_outer_fetch_and_dual_class() {
    let mut client = client_c1();
    let mut path = OptionsBuilder::<2>::new();
    path.push(Opt::uri_path("obs")).unwrap();
    path.push(Opt::observe_register()).unwrap();
    let req = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(path.as_slice());
    let mut wire = [0u8; 64];
    let n = client.protect_request(&req, &mut wire).unwrap();
    let outer = decode(&wire[..n]).unwrap();
    assert_eq!(outer.code(), Code::FETCH);
    assert_eq!(outer.observe().and_then(Result::ok), Some(0));
    assert!(outer.oscore().is_some());

    let mut server = server_c1();
    let mut inner = [0u8; 64];
    let (plain, _) = server.unprotect_request(&outer, &mut inner).unwrap();
    assert_eq!(plain.code(), Code::GET);
    assert_eq!(plain.observe().and_then(Result::ok), Some(0));
}

#[test]
fn observe_notification_inner_empty_outer_seq_and_piv() {
    let mut client = client_c1();
    let mut server = server_c1();
    let mut path = OptionsBuilder::<2>::new();
    path.push(Opt::uri_path("obs")).unwrap();
    path.push(Opt::observe_register()).unwrap();
    let req = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(path.as_slice());
    let mut wire = [0u8; 128];
    let n = client.protect_request(&req, &mut wire).unwrap();
    let protected_req = decode(&wire[..n]).unwrap();
    let mut inner = [0u8; 128];
    let (_plain, request) = server
        .unprotect_request(&protected_req, &mut inner)
        .unwrap();

    let seq = crate::message::encode_uint(3);
    let mut opts = OptionsBuilder::<1>::new();
    opts.push(Opt::observe(&seq)).unwrap();
    let resp = Message::new(Type::NonConfirmable, Code::CONTENT, MessageId::new(2))
        .with_token(Token::from_checked(&[1]))
        .with_options(opts.as_slice())
        .with_payload(b"obs-1");
    let n = server
        .protect_response_with_piv(&resp, request, &mut wire)
        .unwrap();
    let outer = decode(&wire[..n]).unwrap();
    assert_eq!(outer.code(), Code::CONTENT);
    assert_eq!(outer.observe().and_then(Result::ok), Some(3));
    assert_eq!(
        outer.max_age().and_then(Result::ok),
        Some(0),
        "Observe notification: Outer Max-Age 0 (RFC 8613 §4.1.3.1)"
    );
    let header = super::OscoreHeader::parse(outer.oscore().unwrap()).unwrap();
    assert!(header.piv.is_some(), "notification MUST carry a Partial IV");

    let opened = client
        .unprotect_response(&outer, request, &mut inner)
        .unwrap();
    assert_eq!(opened.code(), Code::CONTENT);
    assert_eq!(opened.payload(), b"obs-1");
    assert_eq!(opened.observe().and_then(Result::ok), Some(0));
}

#[test]
fn app_oscore_observe_register_notify() {
    use crate::{App, Request, Response, get, profiles};

    fn hello(_req: Request<'_>) -> Response<'static> {
        Response::content(b"obs-0").observe(0).max_age(0)
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("obs", get(hello))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let call = client.get("obs").observe().to(server_ep).send(0).unwrap();
    let (_, bytes, n) = client.transport().last_send.expect("protected register");
    let req = decode(&bytes[..n]).unwrap();
    assert_eq!(req.code(), Code::FETCH);
    assert!(req.oscore().is_some());
    assert_eq!(req.observe().and_then(Result::ok), Some(0));

    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.poll(0).unwrap();
    let (_, bytes, n) = server
        .transport()
        .last_send
        .expect("protected register ACK");
    let resp = decode(&bytes[..n]).unwrap();
    assert_eq!(resp.code(), Code::CONTENT);
    assert!(resp.oscore().is_some());
    assert_eq!(
        resp.max_age().and_then(Result::ok),
        Some(0),
        "Observe register ACK: Outer Max-Age 0"
    );

    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(0).unwrap();
    let initial = client
        .take_response(call)
        .expect("register")
        .expect("remote response");
    assert_eq!(initial.code(), Code::CONTENT);
    assert_eq!(initial.payload(), b"obs-0");
    assert!(initial.observe_seq().is_some());

    server.transport_mut().last_send = None;
    let sent = server
        .notify(10, &["obs"], Response::content(b"obs-1").max_age(0))
        .expect("notify");
    assert_eq!(sent, 1);
    let (_, bytes, n) = server.transport().last_send.expect("protected notify");
    let note = decode(&bytes[..n]).unwrap();
    assert!(note.oscore().is_some());
    assert_eq!(note.code(), Code::CONTENT);
    assert!(note.observe().is_some());

    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(10).unwrap();
    let got = client
        .take_response(call)
        .expect("protected notification")
        .expect("remote response");
    assert_eq!(got.payload(), b"obs-1");
    assert_eq!(got.observe_seq(), Some(0), "Inner Observe is empty");
    let old = (bytes, n);
    assert_eq!(
        server
            .notify(10_000, &["obs"], Response::content(b"obs-2").max_age(0))
            .unwrap(),
        1
    );
    let (_, bytes, n) = server.transport().last_send.unwrap();
    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(10_000).unwrap();
    let got = client.take_response(call).unwrap().unwrap();
    assert_eq!(got.payload(), b"obs-2");
    assert_eq!(
        got.observe_seq(),
        Some(0),
        "new PIV wins even with equal Inner Observe"
    );
    for (time, (bytes, n)) in [(10_001, old), (10_002, (bytes, n))] {
        client.transport_mut().inbox = Some((server_ep, bytes, n));
        client.poll(time).unwrap();
        assert!(
            client.take_response(call).is_none(),
            "old and duplicate PIV must not surface"
        );
    }
    assert_eq!(
        server
            .notify(20_000, &["obs"], Response::not_found().observe(99))
            .unwrap(),
        1
    );
    let (_, bytes, n) = server.transport().last_send.unwrap();
    let terminal = decode(&bytes[..n]).unwrap();
    assert!(terminal.oscore().is_some());
    assert!(terminal.observe().is_none());
    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(20_000).unwrap();
    let final_response = client.take_response(call).unwrap().unwrap();
    assert_eq!(final_response.code(), Code::NOT_FOUND);
    assert_eq!(final_response.observe_seq(), None);
    assert!(client.oscore().unwrap().lookup(call.token()).is_none());
    assert_eq!(
        server
            .notify(30_000, &["obs"], Response::content(b"later"))
            .unwrap(),
        0
    );
}

#[test]
fn first_notify_without_piv_after_register_is_accepted() {
    use crate::oscore::OscoreHeader;
    use crate::{App, Request, Response, get, profiles};

    fn hello(_req: Request<'_>) -> Response<'static> {
        Response::content(b"obs-0").observe(0)
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("obs", get(hello))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let call = client.get("obs").observe().to(server_ep).send(0).unwrap();
    let (_, req_bytes, req_n) = client.transport().last_send.expect("protected register");

    server.transport_mut().inbox = Some((client_ep, req_bytes, req_n));
    server.poll(0).unwrap();
    let (_, ack_bytes, ack_n) = server
        .transport()
        .last_send
        .expect("protected register ACK");
    let ack = decode(&ack_bytes[..ack_n]).unwrap();
    let ack_hdr = OscoreHeader::parse(ack.oscore().unwrap()).unwrap();
    assert!(
        ack_hdr.piv.is_none(),
        "register ACK uses request Partial IV (no OSCORE PIV)"
    );

    client.transport_mut().inbox = Some((server_ep, ack_bytes, ack_n));
    client.poll(0).unwrap();
    let _ = client
        .take_response(call)
        .expect("register")
        .expect("remote response");

    // Third-party first notify may omit Partial IV (RFC 8613 §4.1.3.5.2).
    // Register ACK must not have spent the §7.4.1 no-PIV budget.
    let mut helper = server_c1();
    let outer_req = decode(&req_bytes[..req_n]).unwrap();
    let mut inner = [0u8; 256];
    let (_plain, request) = helper
        .unprotect_request(&outer_req, &mut inner)
        .expect("unprotect register");
    let seq = encode_uint(1);
    let opts = [Opt::observe(&seq)];
    let notify = Message::new(Type::NonConfirmable, Code::CONTENT, MessageId::new(99))
        .with_token(call.token())
        .with_options(&opts)
        .with_payload(b"obs-1");
    let mut wire = [0u8; 256];
    let n = helper
        .protect_response(&notify, request, &mut wire)
        .expect("no-PIV notify");
    let note = decode(&wire[..n]).unwrap();
    let note_hdr = OscoreHeader::parse(note.oscore().unwrap()).unwrap();
    assert!(note_hdr.piv.is_none(), "crafted first notify has no PIV");

    client.transport_mut().inbox = Some((server_ep, wire, n));
    client.poll(10).unwrap();
    let got = client
        .take_response(call)
        .expect("first no-PIV notify after register")
        .expect("remote response");
    assert_eq!(got.payload(), b"obs-1");

    let n2 = helper
        .protect_response(&notify, request, &mut wire)
        .expect("second no-PIV");
    client.transport_mut().inbox = Some((server_ep, wire, n2));
    client.poll(11).unwrap();
    assert!(
        client.take_response(call).is_none(),
        "second notify without Partial IV is Replay (§7.4.1)"
    );
}

#[test]
fn app_plain_notify_does_not_complete_oscore_observe() {
    use crate::{App, Request, Response, get, profiles};

    fn hello(_req: Request<'_>) -> Response<'static> {
        Response::content(b"obs-0").observe(0)
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("obs", get(hello))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let call = client.get("obs").observe().to(server_ep).send(0).unwrap();
    let (_, bytes, n) = client.transport().last_send.expect("register");
    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.poll(0).unwrap();
    let (_, bytes, n) = server.transport().last_send.expect("ACK");
    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(0).unwrap();
    let _ = client
        .take_response(call)
        .expect("initial")
        .expect("remote response");

    let seq = crate::message::encode_uint(1);
    let opts = [Opt::observe(&seq)];
    let plain = Message::new(Type::NonConfirmable, Code::CONTENT, MessageId::new(99))
        .with_token(call.token())
        .with_options(&opts)
        .with_payload(b"pwned");
    let mut wire = [0u8; 256];
    let pn = encode(&plain, &mut wire).unwrap();
    client.transport_mut().inbox = Some((server_ep, wire, pn));
    client.poll(10).unwrap();
    assert!(
        client.take_response(call).is_none(),
        "plain Observe notify must not complete an OSCORE Call"
    );
}

#[test]
fn derive_rejects_identical_ids() {
    assert_eq!(
        SecurityContext::derive(DeriveParams {
            master_secret: &MASTER_SECRET,
            master_salt: &[],
            sender_id: &[1],
            recipient_id: &[1],
            id_context: &[],
        })
        .unwrap_err(),
        Error::IdCollision
    );
}

/// RFC 8613 Figure 5 + encode_as_outer decisions.
#[test]
fn figure5_option_class_matrix() {
    // Class U only.
    for n in [3, 7, 9, 35, 39] {
        assert_eq!(header::classify(n), OptionClass::Outer, "U-only {n}");
        assert!(!header::classify(n).in_plaintext());
        assert!(header::encode_as_outer(n));
    }
    // Hop-Limit (RFC 8768): not in Figure 5; proxy processing → Outer.
    assert_eq!(header::classify(16), OptionClass::Outer);
    assert!(header::encode_as_outer(16));

    // Dual (E+U).
    for n in [6, 14, 23, 27, 28, 60, 258] {
        assert_eq!(header::classify(n), OptionClass::Dual, "Dual {n}");
        assert!(header::classify(n).in_plaintext());
    }
    assert!(header::encode_as_outer(6), "Observe is both fields");
    assert!(
        !header::encode_as_outer(14),
        "application Max-Age stays Inner (§4.1.3.1)"
    );
    assert!(
        !header::encode_as_outer(23) && !header::encode_as_outer(27),
        "Block stays Inner-only on encode"
    );
    assert!(!header::encode_as_outer(28) && !header::encode_as_outer(60));
    assert!(
        !header::encode_as_outer(258),
        "No-Response MUST be Inner; Outer SHOULD NOT (§4.1.3.6)"
    );

    // Class E only (Figure 5), including ETag — not Dual.
    for n in [1, 4, 5, 8, 11, 12, 15, 17, 20] {
        assert_eq!(header::classify(n), OptionClass::Inner, "E-only {n}");
        assert!(header::classify(n).in_plaintext());
        assert!(!header::encode_as_outer(n));
    }
    // Unknown / later options: Class E (§4.1).
    for n in [19, 31, 99, 252, 292] {
        assert_eq!(header::classify(n), OptionClass::Inner, "unknown {n}");
        assert!(!header::encode_as_outer(n));
    }
}

fn inject_outer_opts(
    protected: &crate::message::ParsedMessage<'_>,
    extra: &[Opt<'_>],
    out: &mut [u8],
) -> usize {
    let mut opts = OptionsBuilder::<8>::new();
    for opt in protected.options() {
        opts.push(opt).unwrap();
    }
    for opt in extra {
        opts.push(*opt).unwrap();
    }
    let msg = Message::new(protected.ty(), protected.code(), protected.message_id())
        .with_token(protected.token())
        .with_options(opts.as_slice())
        .with_payload(protected.payload());
    msg.encode(out).unwrap()
}

#[test]
fn protect_keeps_max_age_etag_inner_not_outer() {
    let mut client = client_c1();
    let mut server = server_c1();
    let mut path = OptionsBuilder::<1>::new();
    path.push(Opt::uri_path("tv1")).unwrap();
    let req = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(path.as_slice());
    let mut wire = [0u8; 128];
    let n = client.protect_request(&req, &mut wire).unwrap();
    let protected_req = decode(&wire[..n]).unwrap();
    let mut inner = [0u8; 128];
    let (_plain, request) = server
        .unprotect_request(&protected_req, &mut inner)
        .unwrap();

    let age = encode_uint(120);
    let mut opts = OptionsBuilder::<2>::new();
    opts.push(Opt::etag(b"v1")).unwrap();
    opts.push(Opt::max_age(&age)).unwrap();
    let resp = Message::new(Type::Acknowledgement, Code::CONTENT, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(opts.as_slice())
        .with_payload(b"ok");
    let n = server.protect_response(&resp, request, &mut wire).unwrap();
    let outer = decode(&wire[..n]).unwrap();
    assert_eq!(outer.code(), Code::CHANGED);
    assert!(outer.oscore().is_some());
    assert!(
        outer.etag().next().is_none(),
        "ETag is Class E — must not appear Outer"
    );
    assert!(
        outer.max_age().is_none(),
        "successful non-Observe response must not copy application Max-Age to Outer"
    );

    let opened = client
        .unprotect_response(&outer, request, &mut inner)
        .unwrap();
    assert_eq!(opened.code(), Code::CONTENT);
    assert_eq!(opened.etag().next(), Some(&b"v1"[..]));
    assert_eq!(opened.max_age().and_then(Result::ok), Some(120));
}

#[test]
fn protect_keeps_no_response_inner_not_outer() {
    let mut client = client_c1();
    let nr = encode_uint(u32::from(NoResponse::SUPPRESS_ALL));
    let mut opts = OptionsBuilder::<2>::new();
    opts.push(Opt::uri_path("tv1")).unwrap();
    opts.push(Opt::no_response(&nr)).unwrap();
    let req = Message::new(Type::NonConfirmable, Code::POST, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(opts.as_slice());
    let mut wire = [0u8; 128];
    let n = client.protect_request(&req, &mut wire).unwrap();
    let outer = decode(&wire[..n]).unwrap();
    assert_eq!(outer.code(), Code::POST);
    assert!(
        outer.no_response().is_none(),
        "No-Response MUST be Inner; Outer SHOULD NOT (§4.1.3.6)"
    );

    let mut server = server_c1();
    let mut inner = [0u8; 128];
    let (plain, _) = server.unprotect_request(&outer, &mut inner).unwrap();
    assert_eq!(
        plain
            .no_response()
            .and_then(Result::ok)
            .map(NoResponse::get),
        Some(NoResponse::SUPPRESS_ALL)
    );
}

#[test]
fn protect_observe_response_outer_max_age_zero_keeps_inner() {
    let mut client = client_c1();
    let mut server = server_c1();
    let mut path = OptionsBuilder::<2>::new();
    path.push(Opt::uri_path("obs")).unwrap();
    path.push(Opt::observe_register()).unwrap();
    let req = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(path.as_slice());
    let mut wire = [0u8; 128];
    let n = client.protect_request(&req, &mut wire).unwrap();
    let protected_req = decode(&wire[..n]).unwrap();
    let mut inner = [0u8; 128];
    let (_plain, request) = server
        .unprotect_request(&protected_req, &mut inner)
        .unwrap();

    let seq = encode_uint(1);
    let age = encode_uint(90);
    let mut opts = OptionsBuilder::<2>::new();
    opts.push(Opt::observe(&seq)).unwrap();
    opts.push(Opt::max_age(&age)).unwrap();
    let resp = Message::new(Type::Acknowledgement, Code::CONTENT, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(opts.as_slice())
        .with_payload(b"obs");
    let n = server.protect_response(&resp, request, &mut wire).unwrap();
    let outer = decode(&wire[..n]).unwrap();
    assert_eq!(outer.code(), Code::CONTENT);
    assert_eq!(outer.max_age().and_then(Result::ok), Some(0));

    let opened = client
        .unprotect_response(&outer, request, &mut inner)
        .unwrap();
    assert_eq!(
        opened.max_age().and_then(Result::ok),
        Some(90),
        "Inner Max-Age is the application value; Outer 0 is discarded (§8.4)"
    );
}

#[test]
fn protect_observe_response_outer_max_age_options_full() {
    use crate::error::EncodeError;

    let mut client = client_c1();
    let mut server = server_c1();
    let mut path = OptionsBuilder::<2>::new();
    path.push(Opt::uri_path("obs")).unwrap();
    path.push(Opt::observe_register()).unwrap();
    let req = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(path.as_slice());
    let mut wire = [0u8; 256];
    let n = client.protect_request(&req, &mut wire).unwrap();
    let protected_req = decode(&wire[..n]).unwrap();
    let mut inner = [0u8; 256];
    let (_plain, request) = server
        .unprotect_request(&protected_req, &mut inner)
        .unwrap();

    // 14 Class U copies + Observe fill 15 outer slots; OSCORE is the 16th.
    // Injected Max-Age 0 must be OptionsFull, not a silent skip (§4.1.3.1).
    let seq = encode_uint(1);
    let mut opts = OptionsBuilder::<16>::new();
    for _ in 0..14 {
        opts.push(Opt::uri_host("x")).unwrap();
    }
    opts.push(Opt::observe(&seq)).unwrap();
    let resp = Message::new(Type::Acknowledgement, Code::CONTENT, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(opts.as_slice())
        .with_payload(b"obs");
    assert_eq!(
        server.protect_response(&resp, request, &mut wire),
        Err(Error::Encode(EncodeError::OptionsFull))
    );
}

#[test]
fn stitch_discards_injected_outer_etag_max_age_no_response() {
    let mut client = client_c1();
    let mut server = server_c1();
    let mut path = OptionsBuilder::<1>::new();
    path.push(Opt::uri_path("tv1")).unwrap();
    let req = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(path.as_slice());
    let mut wire = [0u8; 192];
    let n = client.protect_request(&req, &mut wire).unwrap();
    let protected_req = decode(&wire[..n]).unwrap();
    let mut inner = [0u8; 192];
    let (_plain, request) = server
        .unprotect_request(&protected_req, &mut inner)
        .unwrap();

    let age = encode_uint(45);
    let mut opts = OptionsBuilder::<2>::new();
    opts.push(Opt::etag(b"real")).unwrap();
    opts.push(Opt::max_age(&age)).unwrap();
    let resp = Message::new(Type::Acknowledgement, Code::CONTENT, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(opts.as_slice())
        .with_payload(b"ok");
    let n = server.protect_response(&resp, request, &mut wire).unwrap();
    let protected = decode(&wire[..n]).unwrap();

    let fake_age = encode_uint(3600);
    let fake_nr = encode_uint(u32::from(NoResponse::SUPPRESS_ALL));
    let injected = [
        Opt::etag(b"pwned"),
        Opt::max_age(&fake_age),
        Opt::no_response(&fake_nr),
    ];
    let mut tampered = [0u8; 192];
    let tn = inject_outer_opts(&protected, &injected, &mut tampered);
    let tampered_msg = decode(&tampered[..tn]).unwrap();
    assert_eq!(tampered_msg.etag().next(), Some(&b"pwned"[..]));
    assert_eq!(tampered_msg.max_age().and_then(Result::ok), Some(3600));
    assert!(tampered_msg.no_response().is_some());

    let opened = client
        .unprotect_response(&tampered_msg, request, &mut inner)
        .unwrap();
    assert_eq!(
        opened.etag().next(),
        Some(&b"real"[..]),
        "Outer ETag must not replace Inner ETag (§8.4)"
    );
    assert_eq!(
        opened.max_age().and_then(Result::ok),
        Some(45),
        "Outer Max-Age must not replace Inner Max-Age (§8.4)"
    );
    assert!(
        opened.no_response().is_none(),
        "Outer No-Response is ignored (§4.1.3.6)"
    );
}

#[test]
fn protect_keeps_block2_inner_not_outer() {
    let mut client = client_c1();
    let block = BlockValue::from_size(0, false, 1024).expect("szx").encode();
    let mut opts = OptionsBuilder::<2>::new();
    opts.push(Opt::uri_path("large")).unwrap();
    opts.push(Opt::block2(&block)).unwrap();
    let req = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(opts.as_slice());
    let mut wire = [0u8; 128];
    let n = client.protect_request(&req, &mut wire).unwrap();
    let outer = decode(&wire[..n]).unwrap();
    assert_eq!(outer.code(), Code::POST);
    assert!(outer.oscore().is_some());
    assert!(
        outer.block2().is_none(),
        "Inner Block-wise must not copy Block2 to Outer"
    );

    let mut server = server_c1();
    let mut inner = [0u8; 128];
    let (plain, _) = server.unprotect_request(&outer, &mut inner).unwrap();
    assert_eq!(plain.code(), Code::GET);
    let got = plain.block2().expect("Inner Block2").expect("val");
    assert_eq!(got.num(), 0);
    assert!(!got.more());
}

const LARGE: [u8; 2000] = [b'B'; 2000];
const WIRE: usize = 1472;

#[derive(Default)]
struct WideLoopback {
    inbox: Option<(Endpoint, [u8; WIRE], usize)>,
    last_send: Option<(Endpoint, [u8; WIRE], usize)>,
}

impl DatagramIo for WideLoopback {
    type Error = &'static str;

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        let Some((ep, bytes, n)) = self.inbox.take() else {
            return Ok(None);
        };
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok(Some((n, ep)))
    }

    fn send(&mut self, dest: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        if bytes.len() > WIRE {
            return Err("too long");
        }
        let mut slot = [0u8; WIRE];
        slot[..bytes.len()].copy_from_slice(bytes);
        self.last_send = Some((dest, slot, bytes.len()));
        Ok(bytes.len())
    }
}

fn pump_oscore_block(
    client: &mut crate::App<crate::storage::profiles::Default, WideLoopback, 8, true>,
    server: &mut crate::App<crate::storage::profiles::Default, WideLoopback, 8, true>,
    client_ep: Endpoint,
    server_ep: Endpoint,
    now: u64,
) {
    if let Some((_, bytes, n)) = client.transport_mut().last_send.take() {
        server.transport_mut().inbox = Some((client_ep, bytes, n));
        server.poll(now).unwrap();
    }
    if let Some((_, bytes, n)) = server.transport_mut().last_send.take() {
        client.transport_mut().inbox = Some((server_ep, bytes, n));
        client.poll(now).unwrap();
    }
}

#[test]
fn app_oscore_block2_get_assembles() {
    use crate::{App, Request, Response, get, profiles};

    fn hello(_: Request<'_>) -> Response<'static> {
        Response::content(&LARGE).content_format(ContentFormat::OCTET_STREAM)
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .route("large", get(hello))
        .bind(WideLoopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .bind(WideLoopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let call = client.get("large").to(server_ep).send(0).unwrap();
    let (_, bytes, n) = client.transport().last_send.expect("protected GET");
    let req = decode(&bytes[..n]).unwrap();
    assert!(req.oscore().is_some());
    assert!(req.block2().is_none(), "Block2 is Inner");

    for t in 0u64..8 {
        pump_oscore_block(&mut client, &mut server, client_ep, server_ep, t);
        if let Some(got) = client.take_response(call) {
            let got = got.expect("remote response");
            assert_eq!(got.code(), Code::CONTENT);
            assert_eq!(got.body().expect("assembled"), &LARGE[..]);
            assert!(
                server.metrics().block2_assemble >= 1 || client.metrics().block2_assemble >= 1,
                "Block2 path must not stay cold"
            );
            return;
        }
    }
    panic!("OSCORE Block2 GET did not complete");
}

#[test]
fn app_oscore_block1_put_assembles() {
    use crate::{App, Request, Response, profiles, put};

    fn accept(req: Request<'_>) -> Response<'static> {
        if req.body() == Some(&LARGE[..]) {
            Response::changed()
        } else {
            Response::new(Code::BAD_REQUEST)
        }
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .route("upload", put(accept))
        .bind(WideLoopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .bind(WideLoopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let call = client
        .put("upload")
        .payload(&LARGE)
        .content_format(ContentFormat::OCTET_STREAM)
        .to(server_ep)
        .send(0)
        .unwrap();
    let (_, bytes, n) = client.transport().last_send.expect("protected Block1");
    let req = decode(&bytes[..n]).unwrap();
    assert!(req.oscore().is_some());
    assert!(req.block1().is_none(), "Block1 is Inner");
    assert_eq!(req.code(), Code::POST);

    for t in 0u64..8 {
        pump_oscore_block(&mut client, &mut server, client_ep, server_ep, t);
        if let Some(got) = client.take_response(call) {
            let got = got.expect("remote response");
            assert_eq!(got.code(), Code::CHANGED);
            assert!(
                server.metrics().block1_assemble >= 1,
                "Block1 path must not stay cold"
            );
            return;
        }
    }
    panic!("OSCORE Block1 PUT did not complete");
}

#[test]
fn app_plain_block2_does_not_complete_oscore_call() {
    use crate::{App, Request, Response, get, profiles};

    fn hello(_: Request<'_>) -> Response<'static> {
        Response::content(&LARGE).content_format(ContentFormat::OCTET_STREAM)
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .route("large", get(hello))
        .bind(WideLoopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .bind(WideLoopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let call = client.get("large").to(server_ep).send(0).unwrap();
    pump_oscore_block(&mut client, &mut server, client_ep, server_ep, 0);
    assert!(
        client.take_response(call).is_none(),
        "first Block2 is not the complete body"
    );

    let token = call.token();
    let mid = client
        .transport()
        .last_send
        .map(|(_, bytes, n)| decode(&bytes[..n]).unwrap().message_id())
        .unwrap_or(MessageId::new(99));
    let last = BlockValue::from_size(1, false, 1024)
        .expect("num 1")
        .encode();
    let opts = [Opt::block2(&last)];
    let plain = Message::new(Type::Acknowledgement, Code::CONTENT, mid)
        .with_token(token)
        .with_options(&opts)
        .with_payload(&LARGE[1024..]);
    let mut wire = [0u8; WIRE];
    let pn = encode(&plain, &mut wire).unwrap();
    client.transport_mut().inbox = Some((server_ep, wire, pn));
    client.poll(1).unwrap();
    assert!(
        client.take_response(call).is_none(),
        "unprotected Block2 must not complete an OSCORE Call"
    );

    // Real protected remainder still completes.
    for t in 2u64..10 {
        pump_oscore_block(&mut client, &mut server, client_ep, server_ep, t);
        if let Some(got) = client.take_response(call) {
            let got = got.expect("remote response");
            assert_eq!(got.body().expect("assembled"), &LARGE[..]);
            return;
        }
    }
    panic!("protected Block2 remainder did not complete after plain inject");
}

#[test]
fn app_oscore_max_age_etag_stay_inner() {
    use crate::{App, Request, Response, get, profiles};

    fn hello(_req: Request<'_>) -> Response<'static> {
        Response::content(b"Hello World!").max_age(120).etag(b"v1")
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("tv1", get(hello))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let call = client.get("tv1").to(server_ep).send(0).unwrap();
    let (_, bytes, n) = client.transport().last_send.expect("protected request");
    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.poll(0).unwrap();
    let (_, bytes, n) = server.transport().last_send.expect("protected response");
    let resp = decode(&bytes[..n]).unwrap();
    assert_eq!(resp.code(), Code::CHANGED);
    assert!(resp.oscore().is_some());
    assert!(resp.etag().next().is_none(), "App ETag must stay Inner");
    assert!(
        resp.max_age().is_none(),
        "App Max-Age must stay Inner on a non-Observe success"
    );

    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(0).unwrap();
    let response = client
        .take_response(call)
        .expect("unprotected response")
        .expect("remote response");
    assert_eq!(response.code(), Code::CONTENT);
    assert_eq!(response.payload(), b"Hello World!");
    assert_eq!(response.etag_bytes(), Some(&b"v1"[..]));
}

#[test]
fn app_plain_etag_max_age_does_not_complete_oscore_call() {
    use crate::{App, profiles};

    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let call = client.get("tv1").to(server_ep).send(0).unwrap();
    let (_, bytes, n) = client.transport().last_send.expect("protected request");
    let req = decode(&bytes[..n]).unwrap();

    let age = encode_uint(60);
    let opts = [Opt::etag(b"pwned"), Opt::max_age(&age)];
    let plain = Message::new(Type::Acknowledgement, Code::CONTENT, req.message_id())
        .with_token(req.token())
        .with_options(&opts)
        .with_payload(b"pwned");
    let mut wire = [0u8; 256];
    let pn = encode(&plain, &mut wire).unwrap();
    client.transport_mut().inbox = Some((server_ep, wire, pn));
    client.poll(0).unwrap();
    assert!(
        client.take_response(call).is_none(),
        "unprotected ETag/Max-Age 2.xx must not complete an OSCORE Call"
    );
}

#[test]
fn app_unprotected_request_is_401_max_age_zero() {
    use crate::{App, Request, Response, get, profiles};

    fn hello(_req: Request<'_>) -> Response<'static> {
        Response::content(b"nope")
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("tv1", get(hello))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut path = OptionsBuilder::<1>::new();
    path.push(Opt::uri_path("tv1")).unwrap();
    let plain = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
        .with_token(Token::from_checked(&[1]))
        .with_options(path.as_slice());
    let mut wire = [0u8; 256];
    let pn = encode(&plain, &mut wire).unwrap();
    server.transport_mut().inbox = Some((client_ep, wire, pn));
    server.poll(0).unwrap();
    let (_, bytes, n) = server.transport().last_send.expect("unprotected 4.01");
    let resp = decode(&bytes[..n]).unwrap();
    assert_eq!(resp.code(), Code::UNAUTHORIZED);
    assert!(
        resp.oscore().is_none(),
        "OSCORE processing 4.01 is unprotected"
    );
    assert_eq!(
        resp.max_age().and_then(Result::ok),
        Some(0),
        "unprotected OSCORE 4.01 uses Max-Age 0 (§8.2 / §4.1.3.1)"
    );
}

#[test]
fn write_unprotected_rx_fails_loud_on_encode() {
    use crate::app::write_unprotected_rx;
    use crate::error::{EncodeError, SlotMessageError};
    use crate::storage::{EngineBuilder, Memory, SlotError, profiles};

    let mut engine = EngineBuilder::new()
        .profile::<profiles::Default>()
        .block_wise(false)
        .build(Memory::<profiles::Default>::new())
        .expect("engine");
    let rx = engine.acquire_rx().expect("rx");
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    engine
        .write_rx(rx, &[0x40, 0x01, 0x00, 0x01], peer)
        .expect("seed");

    let big = [0x41u8; 1500];
    let msg = Message::new(Type::Confirmable, Code::PUT, MessageId::new(1)).with_payload(&big);
    let mut buf = [0u8; 1600];
    let n = encode(&msg, &mut buf).unwrap();
    let inner = decode(&buf[..n]).unwrap();

    let err = write_unprotected_rx::<_, &'static str>(&mut engine, rx, &inner, peer).unwrap_err();
    assert_eq!(
        err,
        crate::Error::Message(SlotMessageError::Encode(EncodeError::BufferTooSmall))
    );
    assert_eq!(
        engine.release_rx(rx),
        Err(SlotError::NotOccupied),
        "failed write must release the RX slot"
    );
}

#[test]
fn write_unprotected_rx_fails_loud_on_slot_overflow() {
    use crate::app::write_unprotected_rx;
    use crate::error::{EncodeError, SlotMessageError};
    use crate::storage::{EngineBuilder, Memory, SlotError, profiles};

    let mut engine = EngineBuilder::new()
        .profile::<profiles::Constrained>()
        .block_wise(false)
        .build(Memory::<profiles::Constrained>::new())
        .expect("engine");
    let rx = engine.acquire_rx().expect("rx");
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    engine
        .write_rx(rx, &[0x40, 0x01, 0x00, 0x01], peer)
        .expect("seed");

    // Profile-sized scratch is Constrained RX (1152); 1200-byte Inner fails loud.
    let big = [0x41u8; 1200];
    let msg = Message::new(Type::Confirmable, Code::PUT, MessageId::new(1)).with_payload(&big);
    let mut buf = [0u8; 1472];
    let n = encode(&msg, &mut buf).unwrap();
    let inner = decode(&buf[..n]).unwrap();

    let err = write_unprotected_rx::<_, &'static str>(&mut engine, rx, &inner, peer).unwrap_err();
    assert_eq!(
        err,
        crate::Error::Message(SlotMessageError::Encode(EncodeError::BufferTooSmall))
    );
    assert_eq!(engine.release_rx(rx), Err(SlotError::NotOccupied));
}

#[test]
fn exhausted_sender_seq_is_oscore_error_not_block1() {
    use crate::{App, profiles};

    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .bind(Loopback::default())
        .unwrap();
    let mut ctx = client_c1();
    ctx.set_sender_seq(1 << 40).unwrap();
    client.set_oscore(ctx);

    let err = client
        .put("tv1")
        .payload(b"hello")
        .to(server_ep)
        .send(0)
        .unwrap_err();
    assert_eq!(
        err,
        crate::Error::Oscore(Error::SequenceExhausted),
        "protect SequenceExhausted must not collapse to BufferTooSmall / Block1 start"
    );
    assert!(
        client.transport().last_send.is_none(),
        "exhausted PIV must not emit a datagram"
    );
}

#[test]
fn exhausted_sender_seq_on_notify_is_oscore_error_not_block2() {
    use crate::{App, Request, Response, get, profiles};

    fn hello(_req: Request<'_>) -> Response<'static> {
        Response::content(b"obs-0").observe(0)
    }

    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);

    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .route("obs", get(hello))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());

    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());

    let _ = client.get("obs").observe().to(server_ep).send(0).unwrap();
    let (_, bytes, n) = client.transport().last_send.expect("register");
    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.poll(0).unwrap();
    assert!(server.transport().last_send.is_some(), "register ACK");

    server
        .oscore_mut()
        .expect("oscore")
        .set_sender_seq(1 << 40)
        .unwrap();
    server.transport_mut().last_send = None;
    let err = server
        .notify(10, &["obs"], Response::content(b"obs-1"))
        .unwrap_err();
    assert_eq!(
        err,
        crate::Error::Oscore(Error::SequenceExhausted),
        "protect SequenceExhausted must not collapse to BufferTooSmall / Block2 start"
    );
    assert!(
        server.transport().last_send.is_none(),
        "exhausted notify PIV must not emit a datagram"
    );
}

#[test]
fn partial_iv_sequence_boundaries_reject_overlong_values() {
    for seq in [0, 1, 255, 256, (1u64 << 40) - 1] {
        let piv = PartialIv::from_seq(seq).unwrap();
        assert_eq!(piv.seq(), seq);
        assert_eq!(PartialIv::from_bytes(piv.as_bytes()).unwrap(), piv);
    }
    assert_eq!(PartialIv::from_seq(0).unwrap().as_bytes(), &[0]);
    assert_eq!(PartialIv::from_seq(1u64 << 40), Err(Error::PartialIv));
    assert_eq!(PartialIv::from_seq(u64::MAX), Err(Error::PartialIv));
}

#[test]
fn app_oscore_qblock_recovery_refuses_plaintext_in_both_directions() {
    use crate::message::QBlockTransmission;
    use crate::storage::BlockKey;
    use crate::{App, profiles};

    for incoming_request in [true, false] {
        let peer = Endpoint::v4([192, 0, 2, 1], 5683);
        let key = BlockKey::new(Token::new(&[0xa1]).unwrap(), peer);
        let mut app = App::profile::<profiles::Default>()
            .deterministic_for_tests()
            .block_wise::<true>()
            .bind(Loopback::default())
            .unwrap();
        app.set_oscore(server_c1());
        // Advanced Engine injection deliberately omits authenticated request
        // references; timed App recovery must still refuse plaintext.
        for (num, payload) in [(0, &b"0123456789abcdef"[..]), (2, &b"01234567"[..])] {
            let block = BlockValue::from_size(num, num == 0, 16).unwrap();
            if incoming_request {
                app.engine_mut()
                    .apply_q_block1(key, block, payload, Some(40))
                    .unwrap();
            } else {
                app.engine_mut()
                    .apply_q_block2(key, block, payload, Some(40))
                    .unwrap();
            }
        }
        app.poll(0).unwrap();
        assert_eq!(
            app.poll(u64::from(QBlockTransmission::NON_RECEIVE_TIMEOUT_MS)),
            Err(crate::app::Error::Oscore(Error::Unsupported))
        );
        assert!(app.transport().last_send.is_none(), "no plaintext recovery");
        assert_eq!(app.engine_mut().tx_occupied(), 0, "no leaked TX slot");
    }
}

#[test]
fn context_debug_redacts_key_material() {
    let params = DeriveParams {
        master_secret: &[0x42; 16],
        master_salt: &[0x63; 8],
        sender_id: &[1],
        recipient_id: &[2],
        id_context: &[],
    };
    assert_eq!(
        std::format!("{params:?}"),
        r#"DeriveParams { master_secret: "[REDACTED]", master_salt: "[REDACTED]", .. }"#
    );
    let context = SecurityContext::derive(params).unwrap();
    assert_eq!(
        std::format!("{context:?}"),
        r#"SecurityContext { key_material: "[REDACTED]", sender_seq: 0, .. }"#
    );
}

#[test]
fn sender_sequence_advances_but_cannot_roll_back_or_exceed_exhaustion() {
    let mut ctx = client_c1();
    ctx.set_sender_seq(20).unwrap();
    assert_eq!(ctx.set_sender_seq(19), Err(Error::SequenceRollback));
    assert_eq!(ctx.sender_seq(), 20);
    ctx.set_sender_seq(20).unwrap();
    assert_eq!(ctx.set_sender_seq(u64::MAX), Err(Error::SequenceExhausted));
    assert_eq!(ctx.sender_seq(), 20);
    ctx.set_sender_seq(1 << 40).unwrap();
    assert_eq!(ctx.set_sender_seq(0), Err(Error::SequenceRollback));
    assert_eq!(ctx.sender_seq(), 1 << 40);
}

#[test]
fn cancelled_calls_reclaim_oscore_bindings_without_reusing_sender_sequence() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 2], 5683);
    let mut app = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    app.set_oscore(client_c1());
    for i in 0..12 {
        let call = app.get("value").to(peer).send(i).unwrap();
        assert!(app.oscore().unwrap().lookup(call.token()).is_some());
        assert!(app.cancel(call));
        assert!(app.oscore().unwrap().lookup(call.token()).is_none());
        assert_eq!(
            app.take_response(call).unwrap().unwrap_err(),
            crate::CallFailure::Cancelled
        );
        assert_eq!(app.engine_mut().tx_occupied(), 0);
        assert_eq!(app.oscore().unwrap().sender_seq(), i + 1);
    }
}

#[test]
fn app_echo_challenge_and_explicit_retry_stay_inner_in_same_oscore_context() {
    use crate::message::Echo;
    use crate::{App, Request, Response, get, profiles};
    fn policy(check: crate::EchoCheck) -> crate::EchoDecision {
        assert!(
            check.oscore_protected,
            "policy runs after OSCORE verification"
        );
        let issued = Echo::new(b"server-challenge").unwrap();
        if check.echo == Ok(Some(issued)) {
            crate::EchoDecision::Accept
        } else {
            crate::EchoDecision::Challenge(issued)
        }
    }
    fn hello(req: Request<'_>) -> Response<'static> {
        assert_eq!(req.echo(), Some(&b"server-challenge"[..]));
        Response::content(b"accepted")
    }
    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);
    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .echo_policy(policy)
        .block_wise::<false>()
        .route("value", get(hello))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());
    let mut challenge = None;
    for attempt in 0..2 {
        let mut request = client.get("value").to(server_ep);
        if let Some(echo) = challenge {
            request = request.echo(echo);
        }
        let call = request.send(attempt).unwrap();
        let (_, bytes, n) = client.transport().last_send.unwrap();
        let outer = decode(&bytes[..n]).unwrap();
        assert!(outer.oscore().is_some());
        assert_eq!(outer.echo(), None);
        server.transport_mut().inbox = Some((client_ep, bytes, n));
        server.poll(attempt).unwrap();
        let (_, bytes, n) = server.transport().last_send.unwrap();
        let outer = decode(&bytes[..n]).unwrap();
        assert!(outer.oscore().is_some());
        assert_eq!(outer.echo(), None);
        client.transport_mut().inbox = Some((server_ep, bytes, n));
        client.poll(attempt).unwrap();
        let response = client.take_response(call).unwrap().unwrap();
        if attempt == 0 {
            assert_eq!(response.code(), Code::UNAUTHORIZED);
            challenge = response.echo_option();
            assert_eq!(challenge, Some(Echo::new(b"server-challenge").unwrap()));
        } else {
            assert_eq!(response.code(), Code::CONTENT);
            assert_eq!(response.payload(), b"accepted");
        }
    }
}

#[test]
fn app_client_no_response_stays_inner_and_unsuppressed_error_is_delivered() {
    use crate::{App, Request, Response, profiles, put};
    fn handler(req: Request<'_>) -> Response<'static> {
        assert_eq!(req.no_response(), Some(Ok(NoResponse::new(2))));
        assert_eq!(req.payload(), b"update");
        Response::not_found()
    }
    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);
    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("value", put(handler))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());
    let call = client
        .put("value")
        .to(server_ep)
        .payload(b"update")
        .no_response(NoResponse::new(2))
        .send(0)
        .unwrap();
    let (_, bytes, n) = client.transport().last_send.unwrap();
    let outer = decode(&bytes[..n]).unwrap();
    assert!(outer.oscore().is_some());
    assert!(outer.no_response().is_none());
    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.poll(0).unwrap();
    let (_, bytes, n) = server.transport().last_send.unwrap();
    assert!(decode(&bytes[..n]).unwrap().oscore().is_some());
    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(1).unwrap();
    assert_eq!(
        client.take_response(call).unwrap().unwrap().code(),
        Code::NOT_FOUND
    );
}

#[test]
fn failed_client_sends_reclaim_bindings_without_reusing_sender_sequence() {
    use crate::{App, profiles};
    struct FailSend {
        fail: bool,
        short: bool,
        last_token: Option<Token>,
    }
    impl DatagramIo for FailSend {
        type Error = &'static str;
        fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
            Ok(None)
        }
        fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
            self.last_token = Some(decode(bytes).unwrap().token());
            if self.fail {
                Err("injected send failure")
            } else if self.short {
                Ok(bytes.len() - 1)
            } else {
                Ok(bytes.len())
            }
        }
    }
    let peer = Endpoint::v4([192, 0, 2, 2], 5683);
    for confirmable in [false, true] {
        for short in [false, true] {
            let mut app = App::profile::<profiles::Default>()
                .deterministic_for_tests()
                .block_wise::<false>()
                .bind(FailSend {
                    fail: !short,
                    short,
                    last_token: None,
                })
                .unwrap();
            app.set_oscore(client_c1());
            for i in 0..12 {
                let request = app.get("value").to(peer);
                let request = if confirmable { request } else { request.non() };
                assert!(request.send(i).is_err());
                let token = app.transport().last_token.unwrap();
                assert!(
                    app.oscore().unwrap().lookup(token).is_none(),
                    "failed send retained binding"
                );
                assert_eq!(app.engine_mut().tx_occupied(), 0);
                assert_eq!(app.oscore().unwrap().sender_seq(), i + 1);
            }
            app.transport_mut().fail = false;
            app.transport_mut().short = false;
            let call = app.get("value").to(peer).send(12).unwrap();
            assert!(app.oscore().unwrap().lookup(call.token()).is_some());
            assert!(app.cancel(call));
            assert_eq!(
                app.take_response(call).unwrap().unwrap_err(),
                crate::CallFailure::Cancelled
            );
            assert_eq!(app.oscore().unwrap().sender_seq(), 13);
            assert_eq!(app.engine_mut().tx_occupied(), 0);
            for cycle in 0..12 {
                let call = app
                    .get("value")
                    .observe()
                    .to(peer)
                    .send(20 + cycle)
                    .unwrap();
                assert!(app.oscore().unwrap().lookup(call.token()).is_some());
                app.transport_mut().fail = !short;
                app.transport_mut().short = short;
                assert!(
                    app.get("value")
                        .deregister_call(call)
                        .to(peer)
                        .send(20 + cycle)
                        .is_err()
                );
                assert!(app.oscore().unwrap().lookup(call.token()).is_none());
                assert_eq!(app.engine_mut().tx_occupied(), 0);
                assert_eq!(
                    app.take_response(call).unwrap().unwrap_err(),
                    crate::CallFailure::CancellationFailed
                );
                assert_eq!(app.oscore().unwrap().sender_seq(), 15 + 2 * cycle);
                app.transport_mut().fail = false;
                app.transport_mut().short = false;
            }
        }
    }
}

#[test]
fn protected_partial_upload_failure_releases_all_request_state() {
    use crate::storage::{BodyTag, SlotId};
    use crate::{App, profiles};
    struct FailNth {
        sends: usize,
        nth: usize,
        token: Option<Token>,
    }
    impl DatagramIo for FailNth {
        type Error = &'static str;
        fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
            Ok(None)
        }
        fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
            self.sends += 1;
            let outer = decode(bytes).unwrap();
            assert!(outer.oscore().is_some());
            self.token = Some(outer.token());
            if self.sends == self.nth {
                Err("injected failure")
            } else {
                Ok(bytes.len())
            }
        }
    }
    let peer = Endpoint::v4([192, 0, 2, 2], 5683);
    for qblock in [false, true] {
        for nth in 1..=if qblock { 3 } else { 1 } {
            let mut app = App::profile::<profiles::Default>()
                .deterministic_for_tests()
                .block_wise::<true>()
                .bind(FailNth {
                    sends: 0,
                    nth,
                    token: None,
                })
                .unwrap();
            app.set_oscore(client_c1());
            for i in 0..12 {
                let before = app.oscore().unwrap().sender_seq();
                app.transport_mut().sends = 0;
                let request = app.put("value").to(peer).payload(&[9; 3000]);
                let request = if qblock {
                    request
                        .non()
                        .q_block1()
                        .request_tag(BodyTag::new(b"upload").unwrap())
                } else {
                    request
                };
                assert!(request.send(i).is_err());
                assert_eq!(app.transport().sends, nth);
                assert!(
                    app.oscore()
                        .unwrap()
                        .lookup(app.transport().token.unwrap())
                        .is_none()
                );
                assert!(app.oscore().unwrap().sender_seq() > before);
                assert_eq!(app.engine_mut().tx_occupied(), 0);
                for index in 0..app.engine_mut().capacities().tx_body_slots.unwrap() {
                    assert!(
                        app.engine_mut()
                            .tx_body_transfer(SlotId::from_index(index))
                            .is_none()
                    );
                }
            }
            app.transport_mut().nth = usize::MAX;
            let call = app.get("value").to(peer).send(12).unwrap();
            assert!(app.cancel(call));
            assert_eq!(
                app.take_response(call).unwrap().unwrap_err(),
                crate::CallFailure::Cancelled
            );
        }
    }
}

#[test]
fn outer_observe_cannot_replace_protected_registration_or_notification() {
    fn replace_observe(
        message: &crate::message::ParsedMessage<'_>,
        value: u32,
        out: &mut [u8],
    ) -> usize {
        let encoded = encode_uint(value);
        let mut opts = OptionsBuilder::<8>::new();
        for opt in message.options() {
            if opt.number() != crate::message::OptionNumber::OBSERVE {
                opts.push(opt).unwrap();
            }
        }
        opts.push(Opt::observe(&encoded)).unwrap();
        Message::new(message.ty(), message.code(), message.message_id())
            .with_token(message.token())
            .with_options(opts.as_slice())
            .with_payload(message.payload())
            .encode(out)
            .unwrap()
    }
    for registration in [0, 1] {
        let mut client = client_c1();
        let mut server = server_c1();
        let encoded = encode_uint(registration);
        let opts = [Opt::observe(&encoded)];
        let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
            .with_token(Token::from_checked(&[1]))
            .with_options(&opts);
        let mut wire = [0; 256];
        let n = client.protect_request(&request, &mut wire).unwrap();
        let mut altered = [0; 256];
        let n = replace_observe(&decode(&wire[..n]).unwrap(), 1 - registration, &mut altered);
        let mut inner = [0; 256];
        let (opened, reference) = server
            .unprotect_request(&decode(&altered[..n]).unwrap(), &mut inner)
            .unwrap();
        assert_eq!(opened.observe().and_then(Result::ok), Some(registration));
        let seq = encode_uint(3);
        let opts = [Opt::observe(&seq)];
        let notification = Message::new(Type::NonConfirmable, Code::CONTENT, MessageId::new(2))
            .with_token(request.token())
            .with_options(&opts)
            .with_payload(b"data");
        let n = server
            .protect_response_with_piv(&notification, reference, &mut wire)
            .unwrap();
        let n = replace_observe(&decode(&wire[..n]).unwrap(), 0xffffff, &mut altered);
        let opened = client
            .unprotect_response(&decode(&altered[..n]).unwrap(), reference, &mut inner)
            .unwrap();
        assert_eq!(opened.observe().and_then(Result::ok), Some(0));
        assert_eq!(opened.payload(), b"data");
    }
}

#[test]
fn protected_observe_cancellation_selects_one_subscription_and_releases_binding() {
    use crate::{App, Request, Response, get, profiles};
    fn value(_: Request<'_>) -> Response<'static> {
        Response::content(b"value").observe(0)
    }
    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);
    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("obs", get(value))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());
    let mut calls = [None; 2];
    for (i, query) in ["a", "b"].into_iter().enumerate() {
        let call = client
            .get("obs")
            .observe()
            .query(query)
            .to(server_ep)
            .send(i as u64)
            .unwrap();
        let (_, bytes, n) = client.transport().last_send.unwrap();
        server.transport_mut().inbox = Some((client_ep, bytes, n));
        server.poll(i as u64).unwrap();
        let (_, bytes, n) = server.transport().last_send.unwrap();
        client.transport_mut().inbox = Some((server_ep, bytes, n));
        client.poll(i as u64).unwrap();
        assert!(
            client
                .take_response(call)
                .unwrap()
                .unwrap()
                .observe_seq()
                .is_some()
        );
        calls[i] = Some(call);
    }
    let a = calls[0].unwrap();
    let b = calls[1].unwrap();
    assert_eq!(
        client
            .get("obs")
            .deregister_call(a)
            .query("b")
            .to(server_ep)
            .send(2),
        Err(crate::app::Error::ObserveCancellationMismatch)
    );
    assert!(client.oscore().unwrap().lookup(a.token()).is_some());
    assert_eq!(
        client
            .get("obs")
            .deregister_call(a)
            .query("a")
            .to(server_ep)
            .send(2)
            .unwrap(),
        a
    );
    let (_, bytes, n) = client.transport().last_send.unwrap();
    assert!(decode(&bytes[..n]).unwrap().oscore().is_some());
    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.poll(2).unwrap();
    let (_, bytes, n) = server.transport().last_send.unwrap();
    assert!(decode(&bytes[..n]).unwrap().oscore().is_some());
    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(2).unwrap();
    assert!(
        client
            .take_response(a)
            .unwrap()
            .unwrap()
            .observe_seq()
            .is_none()
    );
    assert!(client.oscore().unwrap().lookup(a.token()).is_none());
    assert!(client.oscore().unwrap().lookup(b.token()).is_some());
    assert_eq!(
        server
            .notify(10, &["obs"], Response::content(b"only b"))
            .unwrap(),
        1
    );
    let (_, bytes, n) = server.transport().last_send.unwrap();
    assert_eq!(decode(&bytes[..n]).unwrap().token(), b.token());
    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(10).unwrap();
    assert_eq!(
        client.take_response(b).unwrap().unwrap().payload(),
        b"only b"
    );
    assert!(client.take_response(a).is_none());
}

#[test]
fn dual_role_protected_observe_uses_independent_same_token_relations() {
    use crate::{App, Request, Response, get, profiles};
    fn value(_: Request<'_>) -> Response<'static> {
        Response::content(b"initial").observe(0)
    }
    type Peer = App<profiles::Default, Loopback>;
    fn transfer(from: &Peer, to: &mut Peer, source: Endpoint, now: u64) {
        let (_, bytes, n) = from.transport().last_send.unwrap();
        assert!(decode(&bytes[..n]).unwrap().oscore().is_some());
        to.transport_mut().inbox = Some((source, bytes, n));
        to.poll(now).unwrap();
    }
    let ae = Endpoint::v4([192, 0, 2, 1], 5683);
    let be = Endpoint::v4([192, 0, 2, 2], 5683);
    let mut a = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("obs", get(value))
        .bind(Loopback::default())
        .unwrap();
    a.set_oscore(client_c1());
    let mut b = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("obs", get(value))
        .bind(Loopback::default())
        .unwrap();
    b.set_oscore(server_c1());
    let ac = a.get("obs").observe().to(be).send(0).unwrap();
    transfer(&a, &mut b, ae, 0);
    transfer(&b, &mut a, be, 0);
    assert!(
        a.take_response(ac)
            .unwrap()
            .unwrap()
            .observe_seq()
            .is_some()
    );
    let bc = b.get("obs").observe().to(ae).send(1).unwrap();
    assert_eq!(
        ac.token(),
        bc.token(),
        "independent requesters may use the same Token"
    );
    transfer(&b, &mut a, be, 1);
    transfer(&a, &mut b, ae, 1);
    assert!(
        b.take_response(bc)
            .unwrap()
            .unwrap()
            .observe_seq()
            .is_some()
    );
    assert_eq!(
        a.notify(10, &["obs"], Response::content(b"from a"))
            .unwrap(),
        1
    );
    transfer(&a, &mut b, ae, 10);
    assert_eq!(b.take_response(bc).unwrap().unwrap().payload(), b"from a");
    assert_eq!(
        b.notify(20, &["obs"], Response::content(b"from b"))
            .unwrap(),
        1
    );
    transfer(&b, &mut a, be, 20);
    assert_eq!(a.take_response(ac).unwrap().unwrap().payload(), b"from b");
    assert!(a.cancel(ac));
    assert_eq!(
        a.take_response(ac).unwrap().unwrap_err(),
        crate::CallFailure::Cancelled
    );
    assert_eq!(
        a.notify(10_000, &["obs"], Response::content(b"still serving"))
            .unwrap(),
        1
    );
    transfer(&a, &mut b, ae, 10_000);
    assert_eq!(
        b.take_response(bc).unwrap().unwrap().payload(),
        b"still serving"
    );
}

#[test]
fn protected_delete_delivers_terminal_notification_before_releasing_client_binding() {
    use crate::{App, Request, Response, get, profiles};
    fn value(_: Request<'_>) -> Response<'static> {
        Response::content(b"initial").observe(0)
    }
    fn remove(_: Request<'_>) -> Response<'static> {
        Response::deleted()
    }
    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);
    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("obs", get(value).delete(remove))
        .bind(Loopback::default())
        .unwrap();
    server.set_oscore(server_c1());
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(Loopback::default())
        .unwrap();
    client.set_oscore(client_c1());
    let observe = client.get("obs").observe().to(server_ep).send(0).unwrap();
    let (_, bytes, n) = client.transport().last_send.unwrap();
    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.poll(0).unwrap();
    let (_, bytes, n) = server.transport().last_send.unwrap();
    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(0).unwrap();
    assert!(
        client
            .take_response(observe)
            .unwrap()
            .unwrap()
            .observe_seq()
            .is_some()
    );
    let deletion = client.delete("obs").to(server_ep).send(1).unwrap();
    let (_, bytes, n) = client.transport().last_send.unwrap();
    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.poll(1).unwrap();
    let (_, bytes, n) = server.transport().last_send.unwrap();
    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(1).unwrap();
    assert_eq!(
        client.take_response(deletion).unwrap().unwrap().code(),
        Code::DELETED
    );
    assert!(client.oscore().unwrap().lookup(observe.token()).is_some());
    server.poll(2).unwrap();
    let (_, bytes, n) = server.transport().last_send.unwrap();
    let terminal = decode(&bytes[..n]).unwrap();
    assert!(terminal.oscore().is_some());
    assert_eq!(terminal.ty(), Type::Confirmable);
    assert_eq!(terminal.token(), observe.token());
    assert!(terminal.observe().is_none());
    client.transport_mut().inbox = Some((server_ep, bytes, n));
    client.poll(2).unwrap();
    let response = client.take_response(observe).unwrap().unwrap();
    assert_eq!(response.code(), Code::NOT_FOUND);
    assert!(response.observe_seq().is_none());
    assert!(client.oscore().unwrap().lookup(observe.token()).is_none());
    let (_, bytes, n) = client.transport().last_send.unwrap();
    assert!(decode(&bytes[..n]).unwrap().is_empty_ack());
    server.transport_mut().inbox = Some((client_ep, bytes, n));
    server.poll(3).unwrap();
    assert_eq!(server.engine_mut().tx_occupied(), 0);
    assert_eq!(
        server
            .notify(10, &["obs"], Response::content(b"gone"))
            .unwrap(),
        0
    );
    assert!(client.take_response(observe).is_none());
}

#[test]
fn notification_reset_preserves_opposite_direction_protected_subscription() {
    exercise_notification_reset_isolation(10, Type::NonConfirmable);
    exercise_notification_reset_isolation(86_400_011, Type::Confirmable);
}

fn exercise_notification_reset_isolation(now: u64, ty: Type) {
    use crate::{App, Request, Response, get, profiles};
    fn value(_: Request<'_>) -> Response<'static> {
        Response::content(b"initial").observe(0)
    }
    type Peer = App<profiles::Default, Loopback>;
    fn transfer(from: &Peer, to: &mut Peer, source: Endpoint, now: u64) {
        let (_, bytes, n) = from.transport().last_send.unwrap();
        assert!(decode(&bytes[..n]).unwrap().oscore().is_some());
        to.transport_mut().inbox = Some((source, bytes, n));
        to.poll(now).unwrap();
    }
    let ae = Endpoint::v4([192, 0, 2, 1], 5683);
    let be = Endpoint::v4([192, 0, 2, 2], 5683);
    let mut a = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("obs", get(value))
        .bind(Loopback::default())
        .unwrap();
    a.set_oscore(client_c1());
    let mut b = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .route("obs", get(value))
        .bind(Loopback::default())
        .unwrap();
    b.set_oscore(server_c1());
    let ac = a.get("obs").observe().to(be).send(0).unwrap();
    transfer(&a, &mut b, ae, 0);
    transfer(&b, &mut a, be, 0);
    assert!(
        a.take_response(ac)
            .unwrap()
            .unwrap()
            .observe_seq()
            .is_some()
    );
    let bc = b.get("obs").observe().to(ae).send(1).unwrap();
    assert_eq!(
        ac.token(),
        bc.token(),
        "independent requesters may use the same Token"
    );
    transfer(&b, &mut a, be, 1);
    transfer(&a, &mut b, ae, 1);
    assert!(
        b.take_response(bc)
            .unwrap()
            .unwrap()
            .observe_seq()
            .is_some()
    );
    if ty == Type::Confirmable {
        assert_eq!(
            a.notify(10, &["obs"], Response::content(b"first")).unwrap(),
            1
        );
        transfer(&a, &mut b, ae, 10);
        assert_eq!(b.take_response(bc).unwrap().unwrap().payload(), b"first");
    }
    assert_eq!(
        a.notify(now, &["obs"], Response::content(b"reject me"))
            .unwrap(),
        1
    );
    let (_, bytes, n) = a.transport().last_send.unwrap();
    assert_eq!(decode(&bytes[..n]).unwrap().ty(), ty);
    let mid = decode(&bytes[..n]).unwrap().message_id();
    let mut reset = [0u8; 256];
    let n = encode(&Message::new(Type::Reset, Code::EMPTY, mid), &mut reset).unwrap();
    // A reset from another endpoint must not remove either relation.
    a.transport_mut().inbox = Some((Endpoint::v4([192, 0, 2, 3], 5683), reset, n));
    a.poll(now + 1).unwrap();
    assert!(a.oscore().unwrap().lookup(ac.token()).is_some());
    assert!(
        a.engine_mut()
            .lookup_observe(crate::storage::ObserveKey::new(bc.token(), be))
            .is_some()
    );
    a.transport_mut().inbox = Some((be, reset, n));
    a.poll(now + 2).unwrap();
    assert!(a.oscore().unwrap().lookup(ac.token()).is_some());
    assert!(
        a.engine_mut()
            .lookup_observe(crate::storage::ObserveKey::new(bc.token(), be))
            .is_none()
    );
    assert_eq!(
        a.notify(now + 10_000, &["obs"], Response::content(b"stopped"))
            .unwrap(),
        0
    );
    assert_eq!(
        b.notify(now + 3, &["obs"], Response::content(b"still receiving"))
            .unwrap(),
        1
    );
    transfer(&b, &mut a, be, now + 3);
    assert_eq!(
        a.take_response(ac).unwrap().unwrap().payload(),
        b"still receiving"
    );
}

#[test]
fn protected_continuation_failures_release_bindings_without_sequence_reuse() {
    use crate::{App, profiles};
    const WIRE: usize = 2048;
    struct FaultIo {
        inbox: Option<(Endpoint, [u8; WIRE], usize)>,
        last: [u8; WIRE],
        len: usize,
        fail: bool,
        short: bool,
    }
    impl DatagramIo for FaultIo {
        type Error = &'static str;
        fn recv(&mut self, bytes: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
            Ok(self.inbox.take().map(|(peer, wire, n)| {
                bytes[..n].copy_from_slice(&wire[..n]);
                (n, peer)
            }))
        }
        fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
            if self.fail {
                return if self.short {
                    Ok(bytes.len() - 1)
                } else {
                    Err("continuation failure")
                };
            }
            self.last[..bytes.len()].copy_from_slice(bytes);
            self.len = bytes.len();
            Ok(bytes.len())
        }
    }
    let peer = Endpoint::v4([192, 0, 2, 2], 5683);
    for upload in [false, true] {
        for non in [false, true] {
            for short in [false, true] {
                let mut app = App::profile::<profiles::Default>()
                    .deterministic_for_tests()
                    .block_wise::<true>()
                    .bind(FaultIo {
                        inbox: None,
                        last: [0; WIRE],
                        len: 0,
                        fail: false,
                        short,
                    })
                    .unwrap();
                app.set_oscore(client_c1());
                let mut remote = server_c1();
                let other = app
                    .get("other")
                    .to(Endpoint::v4([192, 0, 2, 3], 5683))
                    .send(0)
                    .unwrap();
                for now in 1..=12 {
                    let previous_seq = app.oscore().unwrap().sender_seq();
                    app.transport_mut().fail = false;
                    let request = if upload {
                        app.put("value").payload(&[7; 3000])
                    } else {
                        app.get("value")
                    };
                    let request = if non { request.non() } else { request };
                    let call = request.to(peer).send(now).unwrap();
                    let parsed = decode(&app.transport().last[..app.transport().len]).unwrap();
                    let mut inner = [0u8; WIRE];
                    let (parsed, reference) =
                        remote.unprotect_request(&parsed, &mut inner).unwrap();
                    let block = if upload {
                        parsed.block1().unwrap().unwrap()
                    } else {
                        BlockValue::from_size(0, true, 16).unwrap()
                    }
                    .encode();
                    let opts = [if upload {
                        Opt::block1(&block)
                    } else {
                        Opt::block2(&block)
                    }];
                    let msg = Message::new(
                        if non {
                            Type::NonConfirmable
                        } else {
                            Type::Acknowledgement
                        },
                        if upload {
                            Code::CONTINUE
                        } else {
                            Code::CONTENT
                        },
                        parsed.message_id(),
                    )
                    .with_token(call.token())
                    .with_options(&opts)
                    .with_payload(if upload { &[][..] } else { &[5; 16][..] });
                    let mut wire = [0; WIRE];
                    let n = remote.protect_response(&msg, reference, &mut wire).unwrap();
                    app.transport_mut().inbox = Some((peer, wire, n));
                    app.transport_mut().fail = true;
                    assert!(app.poll(now).is_err());
                    assert_eq!(
                        app.take_response(call).unwrap().unwrap_err(),
                        crate::CallFailure::ContinuationFailed
                    );
                    assert!(app.take_response(call).is_none());
                    assert!(app.oscore().unwrap().lookup(call.token()).is_none());
                    assert!(app.oscore().unwrap().lookup(other.token()).is_some());
                    assert!(app.oscore().unwrap().sender_seq() >= previous_seq + 2);
                    assert!(app.take_response(other).is_none());
                    assert_eq!(app.engine_mut().tx_occupied(), 1);
                    assert_eq!(app.engine_mut().rx_occupied(), 0);
                    for i in 0..app.engine_mut().capacities().rx_body_slots.unwrap() {
                        assert!(
                            app.engine_mut()
                                .rx_body_transfer(crate::storage::SlotId::from_index(i))
                                .is_none()
                        );
                    }
                    for i in 0..app.engine_mut().capacities().tx_body_slots.unwrap() {
                        assert!(
                            app.engine_mut()
                                .tx_body_transfer(crate::storage::SlotId::from_index(i))
                                .is_none()
                        );
                    }
                }
                app.transport_mut().fail = false;
                assert!(app.cancel(other));
                assert!(app.get("recovered").to(peer).send(20).is_ok());
            }
        }
    }
}

#[test]
fn seeded_replay_window_matches_set_model() {
    use std::collections::BTreeSet;
    const SEED: u64 = 0x8613_0007_0004_0032;
    let mut random = SEED;
    let mut context = server_c1();
    let mut received = BTreeSet::<u64>::new();
    let mut highest = 0u64;
    let mut accepted = 0;
    let mut refused = 0;
    for case in 0..100_000 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let seq = match random % 5 {
            0 => highest,
            1 => highest.saturating_sub((random >> 8) % 64),
            2 => highest + 1,
            3 => highest + ((random >> 8) % 128),
            _ => (random >> 8) % (highest + 1),
        };
        let floor = highest.saturating_sub(31);
        let fresh = seq >= floor && !received.contains(&seq);
        assert_eq!(
            context.replay_fresh(seq),
            fresh,
            "seed={SEED:x} case={case} seq={seq}"
        );
        // A failed authentication does not commit replay state.
        if fresh && random & 0x10000 != 0 {
            accepted += 1;
            context.replay_accept(seq);
            highest = highest.max(seq);
            received.insert(seq);
            received.retain(|value| *value >= highest.saturating_sub(31));
        } else {
            refused += 1;
        }
        for query in [
            0,
            highest.saturating_sub(32),
            highest.saturating_sub(31),
            highest,
            highest + 1,
        ] {
            assert_eq!(
                context.replay_fresh(query),
                query >= highest.saturating_sub(31) && !received.contains(&query)
            );
        }
    }
    assert!(accepted > 1000 && refused > 1000);
    // Five-byte Partial IV edge, with reordering at both window boundaries.
    let max = (1u64 << 40) - 1;
    context.replay_accept(max);
    assert!(!context.replay_fresh(max));
    assert!(!context.replay_fresh(max - 32));
    assert!(context.replay_fresh(max - 31));
    context.replay_accept(max - 31);
    assert!(!context.replay_fresh(max - 31));
    std::println!("replay seed={SEED:x} cases=100000 accepted={accepted} uncommitted={refused}");
}

#[test]
fn corrupted_requests_do_not_poison_replay_acceptance_campaign() {
    let mut client = client_c1();
    let mut server = server_c1();
    let mut wire = [0u8; 128];
    let mut inner = [0u8; 128];
    for seq in 0..512u16 {
        let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(seq));
        let n = client.protect_request(&request, &mut wire).unwrap();
        let mut corrupted = wire;
        corrupted[n - 1] ^= 1 << (seq % 8);
        assert!(
            server
                .unprotect_request(&decode(&corrupted[..n]).unwrap(), &mut inner)
                .is_err()
        );
        assert!(server.replay_fresh(u64::from(seq)));
        let (opened, _) = server
            .unprotect_request(&decode(&wire[..n]).unwrap(), &mut inner)
            .unwrap();
        assert_eq!(opened.code(), Code::GET);
        assert!(!server.replay_fresh(u64::from(seq)));
        assert_eq!(
            server
                .unprotect_request(&decode(&wire[..n]).unwrap(), &mut inner)
                .unwrap_err(),
            Error::Replay
        );
    }
    std::println!(
        "authenticated replay campaign: 512 corrupt refusals, 512 originals accepted, 512 duplicates refused"
    );
}

#[test]
fn replay_checkpoint_validates_bounds_and_refuses_live_rollback() {
    use super::ReplayCheckpoint;
    let end = 1u64 << 40;
    for (left, bits) in [
        (end + 1, 0),
        (u64::MAX, 0),
        (end, 1),
        (end - 1, 2),
        (end - 31, u32::MAX),
    ] {
        assert_eq!(
            ReplayCheckpoint::from_parts(left, bits),
            Err(Error::ReplayState)
        );
    }
    for (left, bits) in [
        (0, 0),
        (0, u32::MAX),
        (end - 32, u32::MAX),
        (end - 1, 1),
        (end, 0),
    ] {
        assert_eq!(
            ReplayCheckpoint::from_parts(left, bits).unwrap().parts(),
            (left, bits)
        );
    }
    let mut context = server_c1();
    let initial = context.replay_checkpoint();
    for seq in [0, 2, 31, 32, 45] {
        context.replay_accept(seq);
    }
    let latest = context.replay_checkpoint();
    for invalid in [end, u64::MAX] {
        assert!(!context.replay_fresh(invalid));
        context.replay_accept(invalid);
        assert_eq!(context.replay_checkpoint(), latest);
    }
    assert_eq!(context.restore_replay(initial), Err(Error::ReplayRollback));
    assert_eq!(context.replay_checkpoint(), latest);
    let dropping_seen = ReplayCheckpoint::from_parts(20, (1 << 11) | (1 << 12)).unwrap();
    assert_eq!(
        context.restore_replay(dropping_seen),
        Err(Error::ReplayRollback)
    );
    assert_eq!(context.replay_checkpoint(), latest);
    let advancing = ReplayCheckpoint::from_parts(20, (1 << 11) | (1 << 12) | (1 << 25)).unwrap();
    context.restore_replay(advancing).unwrap();
    for seq in [0, 19, 31, 32, 45] {
        assert!(!context.replay_fresh(seq));
    }
    assert!(context.replay_fresh(20));
    context
        .restore_replay(ReplayCheckpoint::from_parts(end, 0).unwrap())
        .unwrap();
    for seq in [0, end - 1, end, u64::MAX] {
        assert!(!context.replay_fresh(seq));
        context.replay_accept(seq);
    }
    assert_eq!(context.replay_checkpoint().parts(), (end, 0));
}

#[test]
fn restored_recipient_checkpoint_refuses_old_authenticated_requests() {
    let mut client = client_c1();
    let mut server = server_c1();
    let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(1));
    let mut wire = [0u8; 128];
    let mut inner = [0u8; 128];
    let n = client.protect_request(&request, &mut wire).unwrap();
    server
        .unprotect_request(&decode(&wire[..n]).unwrap(), &mut inner)
        .unwrap();
    // Simulates the caller retaining the latest committed parts, with their
    // exact context identity. It does not claim filesystem durability.
    let parts = server.replay_checkpoint().parts();
    let mut restarted = server_c1();
    restarted.set_sender_seq(32).unwrap();
    restarted
        .restore_replay(super::ReplayCheckpoint::from_parts(parts.0, parts.1).unwrap())
        .unwrap();
    assert_eq!(
        restarted
            .unprotect_request(&decode(&wire[..n]).unwrap(), &mut inner)
            .unwrap_err(),
        Error::Replay
    );
    let n = client.protect_request(&request, &mut wire).unwrap();
    restarted
        .unprotect_request(&decode(&wire[..n]).unwrap(), &mut inner)
        .unwrap();
    assert!(!restarted.replay_fresh(1));
    assert_eq!(restarted.sender_seq(), 32);
}

#[test]
fn replay_checkpoint_restore_never_reopens_rejected_sequences_model() {
    let mut random = 0x0086_1375_0032_u64;
    for _ in 0..256 {
        let mut context = server_c1();
        for _ in 0..8 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            context.replay_accept(random % 200);
        }
        let before = context.replay_checkpoint();
        let refused: std::vec::Vec<_> =
            (0..300).filter(|seq| !context.replay_fresh(*seq)).collect();
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let candidate =
            super::ReplayCheckpoint::from_parts(random % 256, (random >> 8) as u32).unwrap();
        let (left, bits) = candidate.parts();
        let safe = left >= before.parts().0
            && refused
                .iter()
                .all(|seq| *seq < left || (*seq - left < 32 && bits & (1 << (*seq - left)) != 0));
        assert_eq!(context.restore_replay(candidate).is_ok(), safe);
        if safe {
            for seq in refused {
                assert!(!context.replay_fresh(seq));
            }
        } else {
            assert_eq!(context.replay_checkpoint(), before);
        }
    }
}

#[derive(Default)]
struct QWire {
    fail_send: bool,
    inbox: Option<(Endpoint, std::vec::Vec<u8>)>,
    sent: std::vec::Vec<std::vec::Vec<u8>>,
}
impl DatagramIo for QWire {
    type Error = &'static str;
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        let Some((peer, bytes)) = self.inbox.take() else {
            return Ok(None);
        };
        if bytes.len() > buf.len() {
            return Err("receive overflow");
        }
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(Some((bytes.len(), peer)))
    }
    fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        if core::mem::take(&mut self.fail_send) {
            return Err("injected send failure");
        }
        assert!(self.sent.len() < 16, "bounded test transcript");
        self.sent.push(bytes.to_vec());
        Ok(bytes.len())
    }
}

#[test]
fn app_oscore_qblock2_distinct_pivs_reorder_corruption_replay_and_cleanup() {
    use crate::{App, Request, Response, get, profiles};
    fn body(_: Request<'_>) -> Response<'static> {
        Response::content(&LARGE).etag(b"v1")
    }
    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);
    for order in [[0, 1], [1, 0]] {
        let mut client = App::profile::<profiles::Default>()
            .deterministic_for_tests()
            .block_wise::<true>()
            .bind(QWire::default())
            .unwrap();
        client.set_oscore(client_c1());
        let mut server = App::profile::<profiles::Default>()
            .deterministic_for_tests()
            .block_wise::<true>()
            .route("large", get(body))
            .bind(QWire::default())
            .unwrap();
        server.set_oscore(server_c1());
        for cycle in 0..6 {
            let now = cycle * 10;
            let call = client
                .get("large")
                .q_block2()
                .to(server_ep)
                .send(now)
                .unwrap();
            let request = client.transport_mut().sent.remove(0);
            server.transport_mut().inbox = Some((client_ep, request));
            server.poll(now).unwrap();
            let mut responses = core::mem::take(&mut server.transport_mut().sent);
            assert_eq!(responses.len(), 3);
            let ack = responses.remove(0);
            assert!(decode(&ack).unwrap().is_empty_ack());
            client.transport_mut().inbox = Some((server_ep, ack));
            client.poll(now).unwrap();
            assert!(client.take_response(call).is_none());
            for (index, wire) in responses.iter().enumerate() {
                let outer = decode(wire).unwrap();
                assert!(outer.q_block2().next().is_none(), "Q option remains Inner");
                let header = header::OscoreHeader::parse(outer.oscore().unwrap()).unwrap();
                assert_eq!(header.piv.unwrap().seq(), cycle * 2 + index as u64);
            }
            assert_eq!(server.oscore().unwrap().sender_seq(), cycle * 2 + 2);
            let checkpoint = client.oscore().unwrap().replay_checkpoint();
            let mut corrupt = responses[order[0]].clone();
            *corrupt.last_mut().unwrap() ^= 1;
            client.transport_mut().inbox = Some((server_ep, corrupt));
            client.poll(now + 1).unwrap();
            assert!(client.take_response(call).is_none());
            assert_eq!(client.oscore().unwrap().replay_checkpoint(), checkpoint);
            assert!(client.oscore().unwrap().lookup(call.token()).is_some());
            client.transport_mut().inbox = Some((server_ep, responses[order[0]].clone()));
            client.poll(now + 2).unwrap();
            assert!(client.take_response(call).is_none());
            let accepted = client.oscore().unwrap().replay_checkpoint();
            assert_ne!(accepted, checkpoint);
            assert!(client.oscore().unwrap().lookup(call.token()).is_some());
            client.transport_mut().inbox = Some((server_ep, responses[order[0]].clone()));
            client.poll(now + 3).unwrap();
            assert!(
                client.take_response(call).is_none(),
                "duplicate cannot fail/complete the Call"
            );
            assert_eq!(client.oscore().unwrap().replay_checkpoint(), accepted);
            client.transport_mut().inbox = Some((server_ep, responses[order[1]].clone()));
            client.poll(now + 4).unwrap();
            let response = client.take_response(call).unwrap().unwrap();
            assert_eq!(response.body(), Some(LARGE.as_slice()));
            assert_eq!(response.code(), Code::CONTENT);
            assert!(client.oscore().unwrap().lookup(call.token()).is_none());
            assert_eq!(client.engine_mut().tx_occupied(), 0);
            assert_eq!(client.engine_mut().rx_occupied(), 0);
            for index in 0..client.engine().capacities().rx_body_slots.unwrap() {
                assert!(
                    client
                        .engine()
                        .rx_body_transfer(crate::storage::SlotId::from_index(index))
                        .is_none()
                );
            }
            // Late protected response cannot create a new completed Call.
            client.transport_mut().inbox = Some((server_ep, responses[0].clone()));
            client.poll(now + 5).unwrap();
            assert!(client.take_response(call).is_none());
        }
    }
}

#[test]
fn app_oscore_qblock2_sequence_exhaustion_releases_body_without_plaintext_fallback() {
    use crate::{App, Request, Response, get, profiles};
    fn body(_: Request<'_>) -> Response<'static> {
        Response::content(&LARGE).etag(b"v1")
    }
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    let mut sender = client_c1();
    let q = BlockValue::from_size(0, true, 1024).unwrap().encode();
    let opts = [Opt::uri_path("large"), Opt::q_block2(&q)];
    let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
        .with_token(Token::new(&[3]).unwrap())
        .with_options(&opts);
    let mut wire = [0; WIRE];
    let n = sender.protect_request(&request, &mut wire).unwrap();
    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .route("large", get(body))
        .bind(QWire::default())
        .unwrap();
    let mut context = server_c1();
    context.set_sender_seq((1u64 << 40) - 1).unwrap();
    server.set_oscore(context);
    server.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
    assert_eq!(
        server.poll(0),
        Err(crate::app::Error::Oscore(Error::SequenceExhausted))
    );
    assert_eq!(server.transport().sent.len(), 2);
    assert!(
        decode(&server.transport_mut().sent.remove(0))
            .unwrap()
            .is_empty_ack()
    );
    let first = decode(&server.transport().sent[0]).unwrap();
    assert_eq!(
        header::OscoreHeader::parse(first.oscore().unwrap())
            .unwrap()
            .piv
            .unwrap()
            .seq(),
        (1u64 << 40) - 1
    );
    assert_eq!(server.oscore().unwrap().sender_seq(), 1u64 << 40);
    assert_eq!(server.engine_mut().tx_occupied(), 0);
    for index in 0..server.engine().capacities().tx_body_slots.unwrap() {
        assert!(
            server
                .engine()
                .tx_body_transfer(crate::storage::SlotId::from_index(index))
                .is_none()
        );
    }
}

#[test]
fn app_oscore_qblock2_accepts_one_no_piv_response_then_fresh_piv() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 2], 5683);
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .bind(QWire::default())
        .unwrap();
    client.set_oscore(client_c1());
    let call = client.get("large").q_block2().to(peer).send(0).unwrap();
    let wire = client.transport_mut().sent.remove(0);
    let request = decode(&wire).unwrap();
    let mut server = server_c1();
    let mut opened = [0; WIRE];
    let (_, request_ref) = server.unprotect_request(&request, &mut opened).unwrap();
    let mut replies = std::vec::Vec::new();
    let body = b"0123456789abcdefghijklmnopqrstuv";
    for num in 0..2 {
        let block = BlockValue::from_size(num, num == 0, 16).unwrap().encode();
        let size = encode_uint(32);
        let opts = [Opt::etag(b"v1"), Opt::size2(&size), Opt::q_block2(&block)];
        let response = Message::new(
            if num == 0 {
                Type::Acknowledgement
            } else {
                Type::NonConfirmable
            },
            Code::CONTENT,
            if num == 0 {
                request.message_id()
            } else {
                MessageId::new(900)
            },
        )
        .with_token(call.token())
        .with_options(&opts)
        .with_payload(&body[num as usize * 16..num as usize * 16 + 16]);
        let mut protected = [0; WIRE];
        let n = if num == 0 {
            server.protect_response(&response, request_ref, &mut protected)
        } else {
            server.protect_response_with_piv(&response, request_ref, &mut protected)
        }
        .unwrap();
        replies.push(protected[..n].to_vec());
    }
    let mut corrupt = replies[0].clone();
    *corrupt.last_mut().unwrap() ^= 1;
    client.transport_mut().inbox = Some((peer, corrupt));
    client.poll(1).unwrap();
    assert!(client.take_response(call).is_none());
    for now in 2..4 {
        client.transport_mut().inbox = Some((peer, replies[0].clone()));
        client.poll(now).unwrap();
        assert!(
            client.take_response(call).is_none(),
            "duplicate is silently ignored"
        );
        assert!(client.oscore().unwrap().lookup(call.token()).is_some());
    }
    client.transport_mut().inbox = Some((peer, replies[1].clone()));
    client.poll(4).unwrap();
    assert_eq!(
        client.take_response(call).unwrap().unwrap().body(),
        Some(body.as_slice())
    );
    assert!(client.oscore().unwrap().lookup(call.token()).is_none());
}

#[test]
fn app_oscore_repeated_qblock2_selection_preserves_inner_ranges_and_distinct_pivs() {
    use crate::{App, Request, Response, get, profiles};
    static BODY: [u8; 184] = [b'Q'; 184];
    fn body(_: Request<'_>) -> Response<'static> {
        Response::content(&BODY).etag(b"v1")
    }
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    let mut sender = client_c1();
    let options = [
        Opt::uri_path("large"),
        Opt::opaque(crate::message::OptionNumber::Q_BLOCK2, &[0x78]),
        Opt::opaque(crate::message::OptionNumber::Q_BLOCK2, &[0x80]),
        Opt::opaque(crate::message::OptionNumber::Q_BLOCK2, &[0x90]),
    ];
    let token = Token::new(&[7]).unwrap();
    let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(1))
        .with_token(token)
        .with_options(&options);
    let mut wire = [0; WIRE];
    let n = sender.protect_request(&request, &mut wire).unwrap();
    let request_ref = sender.lookup(token).unwrap();
    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .route("large", get(body))
        .bind(QWire::default())
        .unwrap();
    server.set_oscore(server_c1());
    server.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
    server.poll(0).unwrap();
    assert_eq!(server.transport().sent.len(), 4);
    assert!(
        decode(&server.transport_mut().sent.remove(0))
            .unwrap()
            .is_empty_ack()
    );
    for (index, bytes) in server.transport().sent.iter().enumerate() {
        let outer = decode(bytes).unwrap();
        assert!(outer.q_block2().next().is_none());
        assert_eq!(
            header::OscoreHeader::parse(outer.oscore().unwrap())
                .unwrap()
                .piv
                .unwrap()
                .seq(),
            index as u64
        );
        let mut plain = [0; WIRE];
        let inner = sender
            .unprotect_response(&outer, request_ref, &mut plain)
            .unwrap();
        let block = inner.q_block2().next().unwrap().unwrap();
        assert_eq!(block.num(), 7 + index as u32);
        assert_eq!(inner.payload(), &BODY[(7 + index) * 16..(8 + index) * 16]);
        assert_eq!(inner.size2(), Some(Ok(184)));
        assert_eq!(inner.etag().next(), Some(&b"v1"[..]));
    }
}

#[test]
fn app_oscore_qblock1_missing_metadata_returns_protected_bad_request() {
    use crate::{App, profiles, put};
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    for missing_tag in [true, false] {
        let mut sender = client_c1();
        let q = BlockValue::from_size(0, false, 16).unwrap().encode();
        let size = encode_uint(0);
        let mut options = OptionsBuilder::<4>::new();
        options.push(Opt::uri_path("upload")).unwrap();
        options.push(Opt::q_block1(&q)).unwrap();
        if missing_tag {
            options.push(Opt::size1(&size)).unwrap();
        } else {
            options.push(Opt::request_tag(&[])).unwrap();
        }
        let token = Token::new(&[3]).unwrap();
        let request = Message::new(Type::Confirmable, Code::PUT, MessageId::new(1))
            .with_token(token)
            .with_options(options.as_slice());
        let mut wire = [0; WIRE];
        let n = sender.protect_request(&request, &mut wire).unwrap();
        let request_ref = sender.lookup(token).unwrap();
        let mut server = App::profile::<profiles::Default>()
            .deterministic_for_tests()
            .block_wise::<true>()
            .route(
                "upload",
                put(|_| panic!("missing metadata reached handler")),
            )
            .bind(QWire::default())
            .unwrap();
        server.set_oscore(server_c1());
        server.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
        server.poll(0).unwrap();
        assert_eq!(server.transport().sent.len(), 1);
        let outer = decode(&server.transport().sent[0]).unwrap();
        assert!(outer.oscore().is_some());
        let mut plain = [0; WIRE];
        let inner = sender
            .unprotect_response(&outer, request_ref, &mut plain)
            .unwrap();
        assert_eq!(inner.code(), Code::BAD_REQUEST);
        assert_eq!(inner.token(), token);
        for index in 0..server.engine().capacities().rx_body_slots.unwrap() {
            assert!(
                server
                    .engine()
                    .rx_body_transfer(crate::storage::SlotId::from_index(index))
                    .is_none()
            );
        }
    }
}

#[test]
fn app_oscore_qblock1_ack_continue_and_complete_follow_payload_set() {
    use crate::{App, profiles, put};
    use core::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static BODY: [u8; 168] = [b'Q'; 168];
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    for non in [false, true] {
        CALLS.store(0, Ordering::SeqCst);
        let mut sender = client_c1();
        let mut server = App::profile::<profiles::Default>()
            .deterministic_for_tests()
            .block_wise::<true>()
            .route(
                "upload",
                put(|request| {
                    assert_eq!(request.body(), Some(BODY.as_slice()));
                    CALLS.fetch_add(1, Ordering::SeqCst);
                    crate::Response::changed()
                }),
            )
            .bind(QWire::default())
            .unwrap();
        server.set_oscore(server_c1());
        for num in 0..11 {
            let q = BlockValue::from_size(num, num < 10, 16).unwrap().encode();
            let size = encode_uint(BODY.len() as u32);
            let mut options = OptionsBuilder::<4>::new();
            options.push(Opt::uri_path("upload")).unwrap();
            options.push(Opt::q_block1(&q)).unwrap();
            options.push(Opt::size1(&size)).unwrap();
            options.push(Opt::request_tag(b"tag")).unwrap();
            let token = Token::new(&[num as u8]).unwrap();
            let mid = MessageId::new(100 + num as u16);
            let offset = num as usize * 16;
            let request = Message::new(
                if non {
                    Type::NonConfirmable
                } else {
                    Type::Confirmable
                },
                Code::PUT,
                mid,
            )
            .with_token(token)
            .with_options(options.as_slice())
            .with_payload(&BODY[offset..(offset + 16).min(BODY.len())]);
            let mut wire = [0; WIRE];
            let n = sender.protect_request(&request, &mut wire).unwrap();
            let request_ref = sender.lookup(token).unwrap();
            server.transport_mut().sent.clear();
            server.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
            if !non && num == 0 {
                server.transport_mut().fail_send = true;
                assert!(server.poll(u64::from(num)).is_err());
                assert!(server.transport().sent.is_empty());
                assert_eq!(CALLS.load(Ordering::SeqCst), 0);
                server.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
            }
            server.poll(u64::from(num)).unwrap();
            if non && num < 9 {
                assert!(server.transport().sent.is_empty());
            } else {
                assert_eq!(server.transport().sent.len(), 1);
                let outer = decode(&server.transport().sent[0]).unwrap();
                if !non && num < 10 {
                    assert!(outer.is_empty_ack());
                    assert_eq!(outer.message_id(), mid);
                    assert_eq!(outer.token(), Token::EMPTY);
                    // The exact protected retransmission is acknowledged again;
                    // no replayed plaintext is admitted to the body.
                    let ack = server.transport().sent[0].clone();
                    server.transport_mut().sent.clear();
                    server.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
                    server.poll(u64::from(num)).unwrap();
                    assert_eq!(server.transport().sent, [ack]);
                } else {
                    assert!(outer.oscore().is_some());
                    let mut plain = [0; WIRE];
                    let inner = sender
                        .unprotect_response(&outer, request_ref, &mut plain)
                        .unwrap();
                    assert_eq!(inner.token(), token);
                    assert_eq!(
                        inner.code(),
                        if num == 10 {
                            Code::CHANGED
                        } else {
                            Code::CONTINUE
                        }
                    );
                    if num == 9 {
                        assert_eq!(
                            inner.q_block1().unwrap().unwrap().encode().as_bytes(),
                            &[0x98]
                        );
                        assert!(inner.block1().is_none());
                    }
                }
            }
            assert_eq!(CALLS.load(Ordering::SeqCst), usize::from(num == 10));
            sender.take(token);
        }
        for index in 0..server.engine().capacities().rx_body_slots.unwrap() {
            assert!(
                server
                    .engine()
                    .rx_body_transfer(crate::storage::SlotId::from_index(index))
                    .is_none()
            );
        }
    }
}

#[test]
fn app_oscore_qblock2_exhaustion_retires_binding_or_accepts_deadline_completion() {
    use crate::message::QBlockTransmission;
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 2], 5683);
    for is_fetch in [false, true] {
        'case: for (arrival, fail) in [(false, false), (true, false), (false, true)] {
            let mut client = App::profile::<profiles::Default>()
                .deterministic_for_tests()
                .block_wise::<true>()
                .bind(QWire::default())
                .unwrap();
            client.set_oscore(client_c1());
            let request = if is_fetch {
                client
                    .fetch("large/part")
                    .payload(b"selection")
                    .content_format(ContentFormat::JSON)
                    .if_match(b"v0")
            } else {
                client.get("large/part").if_match(b"v0")
            };
            let call = request
                .query("x=1")
                .query("")
                .q_block2()
                .non()
                .to(peer)
                .send(0)
                .unwrap();
            let wire = client.transport_mut().sent.remove(0);
            let request = decode(&wire).unwrap();
            let mut server = server_c1();
            let mut opened = [0; WIRE];
            let (_, mut request_ref) = server.unprotect_request(&request, &mut opened).unwrap();
            let mut replies = std::vec::Vec::new();
            for num in 0..3 {
                let block = BlockValue::from_size(num, num != 2, 16).unwrap().encode();
                let size = encode_uint(48);
                let opts = [Opt::etag(b"v1"), Opt::size2(&size), Opt::q_block2(&block)];
                let message = Message::new(
                    Type::NonConfirmable,
                    Code::CONTENT,
                    MessageId::new(100 + num as u16),
                )
                .with_token(call.token())
                .with_options(&opts)
                .with_payload(&[b'A'; 16]);
                let mut protected = [0; WIRE];
                let n = server
                    .protect_response_with_piv(&message, request_ref, &mut protected)
                    .unwrap();
                replies.push(protected[..n].to_vec());
            }
            for index in [0, 2] {
                client.transport_mut().inbox = Some((peer, replies[index].clone()));
                client.poll(0).unwrap();
            }
            let id = (0..client.engine().capacities().rx_body_slots.unwrap())
                .map(crate::storage::SlotId::from_index)
                .find(|id| client.engine().rx_body_transfer(*id).is_some())
                .unwrap();
            for _ in 0..QBlockTransmission::NON_MAX_RETRANSMIT {
                let due = client
                    .engine()
                    .rx_body_transfer(id)
                    .unwrap()
                    .q_receive()
                    .unwrap()
                    .next_timeout_ms();
                if fail {
                    let sequence = client.oscore().unwrap().sender_seq();
                    client.transport_mut().fail_send = true;
                    assert!(client.poll(due).is_err());
                    assert_eq!(
                        client.take_response(call).unwrap().unwrap_err(),
                        crate::CallFailure::ContinuationFailed
                    );
                    assert!(client.oscore().unwrap().lookup(call.token()).is_none());
                    assert!(client.oscore().unwrap().sender_seq() > sequence);
                    assert!(client.engine().rx_body_transfer(id).is_none());
                    assert_eq!(client.engine_mut().tx_occupied(), 0);
                    assert_eq!(client.engine_mut().rx_occupied(), 0);
                    assert!(client.transport().sent.is_empty());
                    continue 'case;
                }
                client.poll(due).unwrap();
                assert_eq!(client.transport().sent.len(), 1);
                let wire = client.transport_mut().sent.remove(0);
                let outer = decode(&wire).unwrap();
                assert!(outer.oscore().is_some());
                assert_eq!(outer.ty(), Type::NonConfirmable);
                let (inner, fresh_ref) = server.unprotect_request(&outer, &mut opened).unwrap();
                assert_eq!(inner.code(), if is_fetch { Code::FETCH } else { Code::GET });
                assert_eq!(inner.if_match().next(), Some(&b"v0"[..]));
                if is_fetch {
                    assert_eq!(inner.payload(), b"selection");
                    assert_eq!(inner.content_format(), Some(Ok(ContentFormat::JSON)));
                    assert_eq!(inner.if_match().next(), Some(&b"v0"[..]));
                }
                assert_eq!(
                    inner.uri_path().collect::<std::vec::Vec<_>>(),
                    [Ok("large"), Ok("part")]
                );
                assert_eq!(
                    inner.uri_query().collect::<std::vec::Vec<_>>(),
                    [Ok("x=1"), Ok("")]
                );
                assert_eq!(
                    inner.q_block2().collect::<std::vec::Vec<_>>(),
                    [Ok(BlockValue::from_size(1, false, 16).unwrap())]
                );
                request_ref = fresh_ref;
                assert!(client.oscore().unwrap().lookup(call.token()).is_some());
            }
            let due = client
                .engine()
                .rx_body_transfer(id)
                .unwrap()
                .q_receive()
                .unwrap()
                .next_timeout_ms();
            if arrival {
                let block = BlockValue::from_size(1, true, 16).unwrap().encode();
                let size = encode_uint(48);
                let opts = [Opt::etag(b"v1"), Opt::size2(&size), Opt::q_block2(&block)];
                let response =
                    Message::new(Type::NonConfirmable, Code::CONTENT, MessageId::new(200))
                        .with_token(call.token())
                        .with_options(&opts)
                        .with_payload(&[b'A'; 16]);
                let mut wire = [0; WIRE];
                let n = server
                    .protect_response_with_piv(&response, request_ref, &mut wire)
                    .unwrap();
                client.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
            }
            client.poll(due).unwrap();
            assert!(client.transport().sent.is_empty());
            let outcome = client.take_response(call).unwrap();
            if arrival {
                assert_eq!(outcome.unwrap().body(), Some(&[b'A'; 48][..]));
            } else {
                assert_eq!(outcome.unwrap_err(), crate::CallFailure::TimedOut);
            }
            assert!(client.oscore().unwrap().lookup(call.token()).is_none());
            assert!(client.take_response(call).is_none());
            client.transport_mut().inbox = Some((peer, replies[1].clone()));
            client.poll(due + 1).unwrap();
            assert!(client.take_response(call).is_none());
            assert!(client.transport().sent.is_empty());
        }
    }
}

#[test]
fn app_oscore_confirmable_qupload_recovers_lost_ack_and_completes_repeatedly() {
    use crate::{App, Response, profiles, put};
    use core::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    CALLS.store(0, Ordering::SeqCst);
    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .bind(QWire::default())
        .unwrap();
    client.set_oscore(client_c1());
    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .route(
            "upload",
            put(|request| {
                assert_eq!(request.body(), Some(LARGE.as_slice()));
                CALLS.fetch_add(1, Ordering::SeqCst);
                Response::changed()
            }),
        )
        .bind(QWire::default())
        .unwrap();
    server.set_oscore(server_c1());
    for iteration in 0..6 {
        let now = iteration * 10000;
        client.transport_mut().sent.clear();
        server.transport_mut().sent.clear();
        let call = client
            .put("upload")
            .q_block1()
            .request_tag(crate::storage::BodyTag::new(&[iteration as u8]).unwrap())
            .payload(&LARGE)
            .to(server_ep)
            .send(now)
            .unwrap();
        assert_eq!(client.transport().sent.len(), 1);
        let first = client.transport_mut().sent.remove(0);
        assert_eq!(decode(&first).unwrap().ty(), Type::Confirmable);
        server.transport_mut().inbox = Some((client_ep, first.clone()));
        server.poll(now).unwrap();
        assert!(
            decode(&server.transport_mut().sent.remove(0))
                .unwrap()
                .is_empty_ack()
        );
        // Lose that ACK, then require byte-identical protected retransmission.
        client.poll(now + 3000).unwrap();
        assert_eq!(client.transport().sent.len(), 1);
        let retry = client.transport_mut().sent.remove(0);
        assert_eq!(retry, first);
        server.transport_mut().inbox = Some((client_ep, retry));
        server.poll(now + 3001).unwrap();
        let ack = server.transport_mut().sent.remove(0);
        assert!(decode(&ack).unwrap().is_empty_ack());
        client.transport_mut().inbox = Some((server_ep, ack));
        client.poll(now + 3002).unwrap();
        assert_eq!(client.transport().sent.len(), 1);
        let last = client.transport_mut().sent.remove(0);
        assert_eq!(decode(&last).unwrap().ty(), Type::Confirmable);
        assert_ne!(
            decode(&last).unwrap().message_id(),
            decode(&first).unwrap().message_id()
        );
        server.transport_mut().inbox = Some((client_ep, last));
        server.poll(now + 3003).unwrap();
        assert_eq!(server.transport().sent.len(), 1);
        let reply = server.transport_mut().sent.remove(0);
        assert!(decode(&reply).unwrap().oscore().is_some());
        client.transport_mut().inbox = Some((server_ep, reply));
        client.poll(now + 3004).unwrap();
        assert_eq!(
            client.take_response(call).unwrap().unwrap().code(),
            Code::CHANGED
        );
        assert!(client.oscore().unwrap().lookup(call.token()).is_none());
        assert_eq!(CALLS.load(Ordering::SeqCst), iteration as usize + 1);
        assert_eq!(client.engine_mut().tx_occupied(), 0);
        for index in 0..client.engine().capacities().tx_body_slots.unwrap() {
            assert!(
                client
                    .engine()
                    .tx_body_transfer(crate::storage::SlotId::from_index(index))
                    .is_none()
            );
        }
    }
}

#[test]
fn app_oscore_confirmable_qupload_failed_continuation_retires_binding() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 2], 5683);
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .bind(QWire::default())
        .unwrap();
    client.set_oscore(client_c1());
    for now in 0..12 {
        let call = client
            .put("upload")
            .q_block1()
            .request_tag(crate::storage::BodyTag::new(b"tag").unwrap())
            .payload(&LARGE)
            .to(peer)
            .send(now)
            .unwrap();
        let sent = client.transport_mut().sent.remove(0);
        let mid = decode(&sent).unwrap().message_id();
        let sequence = client.oscore().unwrap().sender_seq();
        let mut wire = [0; WIRE];
        let n = encode(&Message::empty_ack(mid), &mut wire).unwrap();
        client.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
        client.transport_mut().fail_send = true;
        assert!(client.poll(now).is_err());
        assert_eq!(
            client.take_response(call).unwrap().unwrap_err(),
            crate::CallFailure::ContinuationFailed
        );
        assert!(client.oscore().unwrap().lookup(call.token()).is_none());
        assert!(client.oscore().unwrap().sender_seq() > sequence);
        assert_eq!(client.engine_mut().tx_occupied(), 0);
        assert_eq!(client.engine_mut().rx_occupied(), 0);
        assert!(client.transport().sent.is_empty());
    }
}

#[test]
fn app_oscore_qblock2_failed_empty_ack_replays_without_reentering_handler() {
    use crate::{App, Response, get, profiles};
    use core::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    CALLS.store(0, Ordering::SeqCst);
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    let mut sender = client_c1();
    let q = BlockValue::from_size(0, true, 1024).unwrap().encode();
    let opts = [Opt::uri_path("large"), Opt::q_block2(&q)];
    let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(55))
        .with_token(Token::new(&[9]).unwrap())
        .with_options(&opts);
    let mut wire = [0; WIRE];
    let n = sender.protect_request(&request, &mut wire).unwrap();
    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .route(
            "large",
            get(|_| {
                CALLS.fetch_add(1, Ordering::SeqCst);
                Response::content(&LARGE).etag(b"v1")
            }),
        )
        .bind(QWire::default())
        .unwrap();
    server.set_oscore(server_c1());
    server.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
    server.transport_mut().fail_send = true;
    assert!(server.poll(0).is_err());
    assert!(server.transport().sent.is_empty());
    assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    for index in 0..server.engine().capacities().tx_body_slots.unwrap() {
        assert!(
            server
                .engine()
                .tx_body_transfer(crate::storage::SlotId::from_index(index))
                .is_none()
        );
    }
    server.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
    server.poll(1).unwrap();
    assert_eq!(server.transport().sent.len(), 1);
    let ack = decode(&server.transport().sent[0]).unwrap();
    assert!(ack.is_empty_ack());
    assert_eq!(ack.message_id(), MessageId::new(55));
    assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(server.oscore().unwrap().sender_seq(), 0);
}

#[test]
fn app_oscore_missing_report_retains_binding_for_refusal_and_protected_reissue() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 2], 5683);
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .bind(QWire::default())
        .unwrap();
    client.set_oscore(client_c1());
    let call = client
        .put("upload")
        .q_block1()
        .non()
        .request_tag(crate::storage::BodyTag::new(b"tag").unwrap())
        .payload(&LARGE)
        .to(peer)
        .send(0)
        .unwrap();
    assert_eq!(client.transport().sent.len(), 2);
    let last = client.transport_mut().sent.pop().unwrap();
    client.transport_mut().sent.clear();
    let mut server = server_c1();
    let request = decode(&last).unwrap();
    let mut scratch = [0; WIRE];
    let (_, request_ref) = server.unprotect_request(&request, &mut scratch).unwrap();
    let cf = ContentFormat::MISSING_BLOCKS.encode();
    let opts = [Opt::content_format(&cf)];
    for (index, payload) in [&[1, 1][..], &[0, 9][..], &[1][..]].into_iter().enumerate() {
        let report = Message::new(
            Type::NonConfirmable,
            Code::REQUEST_ENTITY_INCOMPLETE,
            MessageId::new(500 + index as u16),
        )
        .with_token(call.token())
        .with_options(&opts)
        .with_payload(payload);
        let mut protected = [0; WIRE];
        let n = server
            .protect_response_with_piv(&report, request_ref, &mut protected)
            .unwrap();
        // Authentication failures must not affect retained body/binding state.
        let mut corrupt = protected[..n].to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        client.transport_mut().inbox = Some((peer, corrupt));
        client.poll(index as u64 + 1).unwrap();
        assert!(client.transport().sent.is_empty());
        assert!(client.oscore().unwrap().lookup(call.token()).is_some());
        client.transport_mut().inbox = Some((peer, protected[..n].to_vec()));
        client.poll(index as u64 + 1).unwrap();
        assert!(client.take_response(call).is_none());
        assert!(client.oscore().unwrap().lookup(call.token()).is_some());
        if index < 2 {
            assert!(client.transport().sent.is_empty());
            // Authenticated malformed reports are replay-filtered too.
            client.transport_mut().inbox = Some((peer, protected[..n].to_vec()));
            client.poll(index as u64 + 1).unwrap();
            assert!(client.transport().sent.is_empty());
        }
    }
    assert_eq!(client.transport().sent.len(), 1);
    let wire = client.transport_mut().sent.remove(0);
    let outer = decode(&wire).unwrap();
    assert!(outer.oscore().is_some());
    assert_eq!(outer.ty(), Type::NonConfirmable);
    let (inner, recovery_ref) = server.unprotect_request(&outer, &mut scratch).unwrap();
    assert_eq!(inner.q_block1().unwrap().unwrap().num(), 1);
    assert_eq!(inner.payload(), &LARGE[1024..]);
    assert_eq!(inner.request_tag().next(), Some(&b"tag"[..]));
    let final_reply = Message::new(Type::NonConfirmable, Code::CHANGED, MessageId::new(600))
        .with_token(call.token());
    let mut wire = [0; WIRE];
    let n = server
        .protect_response(&final_reply, recovery_ref, &mut wire)
        .unwrap();
    client.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
    client.poll(4).unwrap();
    assert_eq!(
        client.take_response(call).unwrap().unwrap().code(),
        Code::CHANGED
    );
    assert!(client.oscore().unwrap().lookup(call.token()).is_none());
    assert_eq!(client.engine_mut().tx_occupied(), 0);
    for index in 0..client.engine().capacities().tx_body_slots.unwrap() {
        assert!(
            client
                .engine()
                .tx_body_transfer(crate::storage::SlotId::from_index(index))
                .is_none()
        );
    }
}

#[test]
fn app_oscore_fetch_format_refusal_is_protected_and_precedes_body_admission() {
    use crate::{App, fetch, profiles};
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    for case in 0..3 {
        let mut sender = client_c1();
        let cf = ContentFormat::TEXT_PLAIN.encode();
        let block = BlockValue::from_size(0, true, 16).unwrap().encode();
        let mut options = OptionsBuilder::<5>::new();
        options.push(Opt::uri_path("search")).unwrap();
        match case {
            0 => {}
            1 => {
                options
                    .push(Opt::opaque(
                        crate::message::OptionNumber::CONTENT_FORMAT,
                        &[1, 0, 0],
                    ))
                    .unwrap();
            }
            _ => {
                options.push(Opt::content_format(&cf)).unwrap();
                options.push(Opt::content_format(&cf)).unwrap();
            }
        }
        options.push(Opt::block1(&block)).unwrap();
        let token = Token::new(&[7]).unwrap();
        let request = Message::new(Type::Confirmable, Code::FETCH, MessageId::new(1))
            .with_token(token)
            .with_options(options.as_slice())
            .with_payload(&[b'A'; 16]);
        let mut wire = [0; WIRE];
        let n = sender.protect_request(&request, &mut wire).unwrap();
        let reference = sender.lookup(token).unwrap();
        let mut server = App::profile::<profiles::Default>()
            .deterministic_for_tests()
            .block_wise::<true>()
            .route(
                "search",
                fetch(|_| panic!("invalid format reached handler")),
            )
            .bind(QWire::default())
            .unwrap();
        server.set_oscore(server_c1());
        server.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
        server.poll(0).unwrap();
        assert_eq!(server.transport().sent.len(), 1);
        let outer = decode(&server.transport().sent[0]).unwrap();
        assert!(outer.oscore().is_some());
        let mut plain = [0; WIRE];
        let inner = sender
            .unprotect_response(&outer, reference, &mut plain)
            .unwrap();
        assert_eq!(
            inner.code(),
            if case == 0 {
                Code::BAD_REQUEST
            } else {
                Code::BAD_OPTION
            }
        );
        assert_eq!(server.engine_mut().rx_occupied(), 0);
        for index in 0..server.engine().capacities().rx_body_slots.unwrap() {
            assert!(
                server
                    .engine()
                    .rx_body_transfer(crate::storage::SlotId::from_index(index))
                    .is_none()
            );
        }
    }
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(QWire::default())
        .unwrap();
    client.set_oscore(client_c1());
    let seq = client.oscore().unwrap().sender_seq();
    assert_eq!(
        client.fetch("search").to(peer).send(0),
        Err(crate::Error::FetchContentFormatRequired)
    );
    assert_eq!(client.oscore().unwrap().sender_seq(), seq);
    assert!(client.transport().sent.is_empty());
}

#[test]
fn protected_response_matching_preserves_live_state_until_expected_peer_and_mid() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    let other = Endpoint::v4([192, 0, 2, 9], 5683);
    for case in 0..4 {
        let mut client = App::profile::<profiles::Default>()
            .deterministic_for_tests()
            .block_wise::<false>()
            .bind(QWire::default())
            .unwrap();
        client.set_oscore(client_c1());
        let outgoing = client.get("value").to(peer);
        let outgoing = if case == 2 {
            outgoing.non()
        } else if case == 3 {
            outgoing.observe()
        } else {
            outgoing
        };
        let call = outgoing.send(0).unwrap();
        let sent = client.transport_mut().sent.remove(0);
        let request = decode(&sent).unwrap();
        let mut server = server_c1();
        let mut scratch = [0; WIRE];
        let (_, reference) = server.unprotect_request(&request, &mut scratch).unwrap();
        let observe = encode_uint(0);
        let options = [Opt::observe(&observe)];
        let reply = Message::new(
            if case == 2 {
                Type::NonConfirmable
            } else {
                Type::Acknowledgement
            },
            Code::CONTENT,
            request.message_id(),
        )
        .with_token(call.token())
        .with_payload(b"correct")
        .with_options(if case == 3 { &options } else { &[] });
        let mut wire = [0; WIRE];
        let n = server
            .protect_response(&reply, reference, &mut wire)
            .unwrap();
        let good = wire[..n].to_vec();
        let mut mismatched = good.clone();
        let source = if case == 1 {
            let wrong = request.message_id().get().wrapping_add(1).to_be_bytes();
            mismatched[2..4].copy_from_slice(&wrong);
            peer
        } else {
            other
        };
        client.transport_mut().inbox = Some((source, mismatched));
        client.poll(1).unwrap();
        assert!(client.take_response(call).is_none());
        assert!(client.oscore().unwrap().lookup(call.token()).is_some());
        assert!(client.transport().sent.is_empty());
        client.transport_mut().inbox = Some((peer, good));
        client.poll(2).unwrap();
        assert_eq!(
            client.take_response(call).unwrap().unwrap().payload(),
            b"correct"
        );
        if case == 3 {
            for attempt in 0..2 {
                let sequence = encode_uint(1 + attempt);
                let options = [Opt::observe(&sequence)];
                let notification = Message::new(
                    Type::NonConfirmable,
                    Code::CONTENT,
                    MessageId::new(100 + attempt as u16),
                )
                .with_token(call.token())
                .with_options(&options)
                .with_payload(b"next");
                let n = server
                    .protect_response_with_piv(&notification, reference, &mut wire)
                    .unwrap();
                let good = wire[..n].to_vec();
                let mut bad = good.clone();
                let source = if attempt == 0 {
                    other
                } else {
                    // An ACK cannot become a notification after its exchange
                    // has completed, even with a matching Observe Token.
                    bad[0] = (bad[0] & !0x30) | 0x20;
                    peer
                };
                client.transport_mut().inbox = Some((source, bad));
                client.poll(3 + u64::from(attempt) * 2).unwrap();
                assert!(client.take_response(call).is_none());
                assert!(client.transport().sent.is_empty());
                client.transport_mut().inbox = Some((peer, good));
                client.poll(4 + u64::from(attempt) * 2).unwrap();
                assert_eq!(
                    client.take_response(call).unwrap().unwrap().payload(),
                    b"next"
                );
            }
            assert!(client.cancel(call));
        }
        assert!(client.oscore().unwrap().lookup(call.token()).is_none());
        assert_eq!(client.engine_mut().tx_occupied(), 0);
        assert_eq!(client.engine_mut().rx_occupied(), 0);
    }
}

#[test]
fn protected_response_rejection_and_failed_ack_preserve_pending_call() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    for case in 0..4 {
        let mut client = App::profile::<profiles::Default>()
            .deterministic_for_tests()
            .block_wise::<false>()
            .bind(QWire::default())
            .unwrap();
        client.set_oscore(client_c1());
        let call = client.get("value").to(peer).send(0).unwrap();
        let sent = client.transport_mut().sent.remove(0);
        let request = decode(&sent).unwrap();
        let mut server = server_c1();
        let mut scratch = [0; WIRE];
        let (_, reference) = server.unprotect_request(&request, &mut scratch).unwrap();
        let ty = match case {
            0 | 3 => Type::Confirmable,
            1 => Type::NonConfirmable,
            _ => Type::Acknowledgement,
        };
        let opts = [Opt::opaque(crate::message::OptionNumber::new(99), &[1])];
        let reply = Message::new(ty, Code::CONTENT, request.message_id())
            .with_token(call.token())
            .with_payload(b"correct")
            .with_options(if case == 3 { &[] } else { &opts });
        let mut wire = [0; WIRE];
        let n = server
            .protect_response_with_piv(&reply, reference, &mut wire)
            .unwrap();
        let retry = wire[..n].to_vec();
        client.transport_mut().inbox = Some((peer, retry.clone()));
        client.transport_mut().fail_send = case == 3;
        if case == 3 {
            assert!(client.poll(1).is_err());
        } else {
            client.poll(1).unwrap();
        }
        assert!(client.take_response(call).is_none());
        assert!(client.oscore().unwrap().lookup(call.token()).is_some());
        if case == 0 {
            assert_eq!(client.transport().sent.len(), 1);
            assert!(
                decode(&client.transport_mut().sent.remove(0))
                    .unwrap()
                    .is_empty_rst()
            );
        } else {
            assert!(client.transport().sent.is_empty());
        }
        let good = if case == 3 {
            retry
        } else {
            let reply = Message::new(ty, Code::CONTENT, request.message_id())
                .with_token(call.token())
                .with_payload(b"correct");
            let n = server
                .protect_response_with_piv(&reply, reference, &mut wire)
                .unwrap();
            wire[..n].to_vec()
        };
        client.transport_mut().inbox = Some((peer, good));
        client.poll(2).unwrap();
        assert_eq!(
            client.take_response(call).unwrap().unwrap().payload(),
            b"correct"
        );
        assert!(client.oscore().unwrap().lookup(call.token()).is_none());
        assert_eq!(client.engine_mut().tx_occupied(), 0);
        assert_eq!(client.engine_mut().rx_occupied(), 0);
    }
}

#[test]
fn protected_four_call_capacity_includes_uncollected_replies_and_recovers_repeatedly() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(QWire::default())
        .unwrap();
    client.set_oscore(client_c1());
    let mut server = server_c1();
    let mut scratch = [0; WIRE];
    let mut wire = [0; WIRE];
    for round in 0..16 {
        let mut calls = std::vec::Vec::new();
        let mut replies = std::vec::Vec::new();
        for index in 0..4 {
            let call = client.get("value").non().to(peer).send(round * 10).unwrap();
            let sent = client.transport_mut().sent.remove(0);
            let request = decode(&sent).unwrap();
            let (_, reference) = server.unprotect_request(&request, &mut scratch).unwrap();
            let payload = [index];
            let response = Message::new(Type::NonConfirmable, Code::CONTENT, request.message_id())
                .with_token(call.token())
                .with_payload(&payload);
            let n = server
                .protect_response(&response, reference, &mut wire)
                .unwrap();
            replies.push(wire[..n].to_vec());
            calls.push(call);
        }
        let sequence = client.oscore().unwrap().sender_seq();
        assert_eq!(
            client.get("fifth").non().to(peer).send(round * 10),
            Err(crate::Error::Saturated)
        );
        assert_eq!(client.oscore().unwrap().sender_seq(), sequence);
        assert!(client.transport().sent.is_empty());
        for reply in replies.into_iter().rev() {
            client.transport_mut().inbox = Some((peer, reply));
            client.poll(round * 10 + 1).unwrap();
        }
        for call in &calls {
            assert!(client.oscore().unwrap().lookup(call.token()).is_some());
        }
        assert_eq!(
            client.get("fifth").non().to(peer).send(round * 10 + 2),
            Err(crate::Error::Saturated)
        );
        for (index, call) in calls.into_iter().enumerate() {
            assert_eq!(
                client.take_response(call).unwrap().unwrap().payload(),
                &[index as u8]
            );
            assert!(client.oscore().unwrap().lookup(call.token()).is_none());
            assert!(client.take_response(call).is_none());
        }
        assert_eq!(client.engine_mut().tx_occupied(), 0);
        assert_eq!(client.engine_mut().rx_occupied(), 0);
    }
}

#[test]
fn protected_observe_and_q_response_admission_commits_replay_after_ack() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    for reject in [false, true] {
        for observe in [true, false] {
            for piv in [true, false] {
                let mut client = App::profile::<profiles::Default>()
                    .deterministic_for_tests()
                    .block_wise::<true>()
                    .bind(QWire::default())
                    .unwrap();
                client.set_oscore(client_c1());
                let request = client.get("value").to(peer);
                let call = if observe {
                    request.observe()
                } else {
                    request.q_block2()
                }
                .send(0)
                .unwrap();
                let sent = client.transport_mut().sent.remove(0);
                let request = decode(&sent).unwrap();
                let mut server = server_c1();
                let mut scratch = [0; WIRE];
                let (_, reference) = server.unprotect_request(&request, &mut scratch).unwrap();
                let number = encode_uint(0);
                let block = BlockValue::from_size(0, false, 16).unwrap().encode();
                let size = encode_uint(3);
                let mut opts = OptionsBuilder::<4>::new();
                if observe {
                    opts.push(Opt::observe(&number)).unwrap();
                } else {
                    opts.push(Opt::etag(b"v1")).unwrap();
                    opts.push(Opt::size2(&size)).unwrap();
                    opts.push(Opt::q_block2(&block)).unwrap();
                }
                if reject {
                    opts.push(Opt::opaque(crate::message::OptionNumber::new(99), &[1]))
                        .unwrap();
                }
                let message = Message::new(Type::Confirmable, Code::CONTENT, MessageId::new(100))
                    .with_token(call.token())
                    .with_options(opts.as_slice())
                    .with_payload(b"yes");
                let mut wire = [0; WIRE];
                let n = if piv {
                    server.protect_response_with_piv(&message, reference, &mut wire)
                } else {
                    server.protect_response(&message, reference, &mut wire)
                }
                .unwrap();
                let mut reply = wire[..n].to_vec();
                let checkpoint = client.oscore().unwrap().replay_checkpoint();
                client.transport_mut().fail_send = !reject;
                client.transport_mut().inbox = Some((peer, reply.clone()));
                if reject {
                    client.poll(1).unwrap();
                    assert!(
                        decode(&client.transport_mut().sent.remove(0))
                            .unwrap()
                            .is_empty_rst()
                    );
                    let mut valid = OptionsBuilder::<3>::new();
                    for option in opts.as_slice() {
                        if option.number() != crate::message::OptionNumber::new(99) {
                            valid.push(*option).unwrap();
                        }
                    }
                    let message =
                        Message::new(Type::Confirmable, Code::CONTENT, MessageId::new(101))
                            .with_token(call.token())
                            .with_options(valid.as_slice())
                            .with_payload(b"yes");
                    let n = server
                        .protect_response_with_piv(&message, reference, &mut wire)
                        .unwrap();
                    reply = wire[..n].to_vec();
                } else {
                    assert!(client.poll(1).is_err());
                }
                assert!(client.take_response(call).is_none());
                assert_eq!(client.oscore().unwrap().replay_checkpoint(), checkpoint);
                client.transport_mut().inbox = Some((peer, reply));
                client.poll(2).unwrap();
                let response = client.take_response(call).unwrap().unwrap();
                assert_eq!(response.body().unwrap_or(response.payload()), b"yes");
                assert_eq!(client.transport().sent.len(), 1);
                assert!(decode(&client.transport().sent[0]).unwrap().is_empty_ack());
                assert!(client.take_response(call).is_none());
                if observe {
                    assert!(client.cancel(call));
                }
                assert!(client.oscore().unwrap().lookup(call.token()).is_none());
            }
        }
    }
}

#[test]
fn protected_con_response_duplicates_are_acked_before_and_after_collection() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    let other = Endpoint::v4([192, 0, 2, 9], 5683);
    for mode in 0..3 {
        let mut client = App::profile::<profiles::Default>()
            .deterministic_for_tests()
            .block_wise::<true>()
            .bind(QWire::default())
            .unwrap();
        client.set_oscore(client_c1());
        let request = client.get("value").to(peer);
        let request = match mode {
            1 => request.observe(),
            2 => request.q_block2(),
            _ => request,
        };
        let call = request.send(0).unwrap();
        let sent = client.transport_mut().sent.remove(0);
        let request = decode(&sent).unwrap();
        let mut server = server_c1();
        let mut scratch = [0; WIRE];
        let (_, reference) = server.unprotect_request(&request, &mut scratch).unwrap();
        let number = encode_uint(0);
        let block = BlockValue::from_size(0, false, 16).unwrap().encode();
        let size = encode_uint(3);
        let mut opts = OptionsBuilder::<3>::new();
        if mode == 1 {
            opts.push(Opt::observe(&number)).unwrap();
        }
        if mode == 2 {
            opts.push(Opt::etag(b"v1")).unwrap();
            opts.push(Opt::size2(&size)).unwrap();
            opts.push(Opt::q_block2(&block)).unwrap();
        }
        let response = Message::new(Type::Confirmable, Code::CONTENT, MessageId::new(100))
            .with_token(call.token())
            .with_options(opts.as_slice())
            .with_payload(b"yes");
        let mut wire = [0; WIRE];
        let n = server
            .protect_response_with_piv(&response, reference, &mut wire)
            .unwrap();
        let reply = wire[..n].to_vec();
        for now in 1..=2 {
            client.transport_mut().inbox = Some((peer, reply.clone()));
            client.poll(now).unwrap();
            assert_eq!(client.transport().sent.len(), now as usize);
            assert!(
                decode(client.transport().sent.last().unwrap())
                    .unwrap()
                    .is_empty_ack()
            );
        }
        let result = client.take_response(call).unwrap().unwrap();
        assert_eq!(result.body().unwrap_or(result.payload()), b"yes");
        assert!(client.take_response(call).is_none());
        client.transport_mut().inbox = Some((other, reply.clone()));
        client.poll(3).unwrap();
        assert_eq!(client.transport().sent.len(), 2);
        client.transport_mut().inbox = Some((peer, reply.clone()));
        client.transport_mut().fail_send = true;
        assert!(client.poll(4).is_err());
        client.transport_mut().inbox = Some((peer, reply.clone()));
        client.poll(5).unwrap();
        assert_eq!(client.transport().sent.len(), 3);
        assert!(
            decode(client.transport().sent.last().unwrap())
                .unwrap()
                .is_empty_ack()
        );
        assert!(client.take_response(call).is_none());
        let before = client.oscore().unwrap().replay_checkpoint();
        client.transport_mut().inbox = Some((peer, reply));
        client
            .poll(u64::from(crate::message::Transmission::EXCHANGE_LIFETIME_MS) + 1)
            .unwrap();
        assert_eq!(client.transport().sent.len(), 3);
        assert_eq!(client.oscore().unwrap().replay_checkpoint(), before);
        assert_eq!(client.engine_mut().tx_occupied(), 0);
        assert_eq!(client.engine_mut().rx_occupied(), 0);
    }
}

#[test]
fn protected_response_inline_and_assembled_boundaries_reclaim_state() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    let body: [u8; 4097] = core::array::from_fn(|index| (index % 251) as u8);
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .bind(QWire::default())
        .unwrap();
    client.set_oscore(client_c1());
    let mut server = server_c1();
    let mut scratch = [0; WIRE];
    let mut wire = [0; WIRE];
    for mode in 0..3 {
        let lengths: &[usize] = if mode == 0 {
            &[127, 128, 129, 128]
        } else {
            &[4095, 4096, 4097, 4096, 4097, 4095]
        };
        for &len in lengths {
            let request = client.get("body").non().to(peer);
            let request = if mode == 2 {
                request.q_block2()
            } else {
                request
            };
            let call = request.send(0).unwrap();
            let sent = client.transport_mut().sent.remove(0);
            let request = decode(&sent).unwrap();
            let (_, mut reference) = server.unprotect_request(&request, &mut scratch).unwrap();
            let mut done = false;
            for (num, payload) in body[..len].chunks(1024).enumerate() {
                let block = BlockValue::from_size(num as u32, (num + 1) * 1024 < len, 1024)
                    .unwrap()
                    .encode();
                let size = encode_uint(len as u32);
                let mut opts = OptionsBuilder::<3>::new();
                if mode != 0 {
                    opts.push(Opt::etag(b"body")).unwrap();
                    opts.push(Opt::size2(&size)).unwrap();
                    opts.push(if mode == 2 {
                        Opt::q_block2(&block)
                    } else {
                        Opt::block2(&block)
                    })
                    .unwrap();
                }
                let response = Message::new(
                    Type::NonConfirmable,
                    Code::CONTENT,
                    MessageId::new(100 + num as u16),
                )
                .with_token(call.token())
                .with_options(opts.as_slice())
                .with_payload(payload);
                let n = server
                    .protect_response_with_piv(&response, reference, &mut wire)
                    .unwrap();
                client.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
                client.poll(num as u64 + 1).unwrap();
                if let Some(outcome) = client.take_response(call) {
                    if mode == 0 {
                        let response = outcome.unwrap();
                        assert_eq!(response.payload(), &body[..len.min(128)]);
                        assert_eq!(response.payload_src_len(), len);
                        assert_eq!(response.payload_truncated(), len > 128);
                        assert!(response.body().is_none());
                    } else if len <= 4096 {
                        assert_eq!(num + 1, len.div_ceil(1024));
                        assert_eq!(outcome.unwrap().body(), Some(&body[..len]));
                    } else {
                        assert_eq!(
                            outcome.unwrap_err(),
                            crate::CallFailure::BlockTransfer(
                                crate::error::BlockTransferError::Overflow
                            )
                        );
                    }
                    done = true;
                    break;
                }
                if !client.transport().sent.is_empty() {
                    let sent = client.transport_mut().sent.remove(0);
                    let request = decode(&sent).unwrap();
                    let (_, next) = server.unprotect_request(&request, &mut scratch).unwrap();
                    reference = next;
                }
            }
            assert!(done);
            assert!(client.take_response(call).is_none());
            assert!(client.oscore().unwrap().lookup(call.token()).is_none());
            assert!(client.transport().sent.is_empty());
            assert_eq!(client.engine_mut().rx_occupied(), 0);
            assert_eq!(client.engine_mut().tx_occupied(), 0);
            for index in 0..client.engine().capacities().rx_body_slots.unwrap() {
                assert!(
                    client
                        .engine()
                        .rx_body_transfer(crate::storage::SlotId::from_index(index))
                        .is_none()
                );
            }
        }
    }
}

#[test]
fn protected_qblock2_aligned_reselection_preserves_windows_and_uses_fresh_pivs() {
    use crate::{App, Request, Response, get, profiles};
    static BODY: [u8; 384] = [b'Q'; 384];
    fn body(_: Request<'_>) -> Response<'static> {
        Response::content(&BODY).etag(b"v1")
    }
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    let token = Token::new(b"q").unwrap();
    let mut sender = client_c1();
    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .route("large", get(body))
        .bind(QWire::default())
        .unwrap();
    server.set_oscore(server_c1());
    let key = crate::storage::BlockKey::new(token, peer)
        .with_identity(crate::storage::BodyTag::new(b"v1").unwrap());
    let id = server.engine_mut().start_q_block2(key, &BODY, 0).unwrap();
    for _ in 0..10 {
        server.engine_mut().next_q_block2(id).unwrap();
    }
    let mut previous = server.engine().tx_body_transfer(id).unwrap();
    let mut sequence = 0;
    for (index, num) in [0, 10, 10, 0, 30, 20].into_iter().enumerate() {
        let q = BlockValue::from_size(num, true, 16).unwrap().encode();
        let opts = [Opt::uri_path("large"), Opt::q_block2(&q)];
        let request = Message::new(
            Type::Confirmable,
            Code::GET,
            MessageId::new(100 + index as u16),
        )
        .with_token(token)
        .with_options(&opts);
        let mut wire = [0; WIRE];
        let n = sender.protect_request(&request, &mut wire).unwrap();
        let reference = sender.lookup(token).unwrap();
        server.transport_mut().sent.clear();
        server.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
        let result = server.poll(index as u64);
        if num == 30 {
            assert_eq!(
                result,
                Err(crate::Error::Block(
                    crate::error::BlockTransferError::OutsideWindow
                ))
            );
            assert!(server.transport().sent.is_empty());
            assert_eq!(server.engine().tx_body_transfer(id), Some(previous));
            assert_eq!(server.oscore().unwrap().sender_seq(), sequence);
            continue;
        }
        result.unwrap();
        let ack = server.transport_mut().sent.remove(0);
        assert!(decode(&ack).unwrap().is_empty_ack());
        assert_eq!(decode(&ack).unwrap().message_id(), request.message_id());
        let count = if num == 20 { 4 } else { 10 };
        assert_eq!(server.transport().sent.len(), count);
        for (offset, wire) in server.transport().sent.iter().enumerate() {
            let outer = decode(wire).unwrap();
            assert_eq!(outer.ty(), Type::NonConfirmable);
            assert!(outer.q_block2().next().is_none());
            assert_eq!(
                header::OscoreHeader::parse(outer.oscore().unwrap())
                    .unwrap()
                    .piv
                    .unwrap()
                    .seq(),
                sequence
            );
            sequence += 1;
            let mut plain = [0; WIRE];
            let response = sender
                .unprotect_response(&outer, reference, &mut plain)
                .unwrap();
            assert_eq!(
                response.q_block2().next().unwrap().unwrap().num(),
                num + offset as u32
            );
            assert_eq!(
                response.payload(),
                &BODY[(num as usize + offset) * 16..(num as usize + offset + 1) * 16]
            );
            assert_eq!(response.size2(), Some(Ok(384)));
        }
        if num == 20 {
            assert!(server.engine().tx_body_transfer(id).is_none());
        } else if index == 1 {
            previous = server.engine().tx_body_transfer(id).unwrap();
            assert_eq!(previous.window_base(), 10);
        } else {
            assert_eq!(server.engine().tx_body_transfer(id), Some(previous));
        }
        assert_eq!(server.engine_mut().rx_occupied(), 0);
        assert_eq!(server.engine_mut().tx_occupied(), 0);
    }
}

#[test]
fn protected_qblock1_timed_reports_bind_latest_request_and_reclaim_state() {
    use crate::storage::{BlockRole, SlotId};
    use crate::{App, Request, Response, profiles, put};
    use core::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static BODY: &[u8] = b"0123456789abcdefABCDEFGHIJKLMNOPqrstuvwxyz012345";
    fn upload(request: Request<'_>) -> Response<'static> {
        assert_eq!(request.body(), Some(BODY));
        CALLS.fetch_add(1, Ordering::SeqCst);
        Response::changed()
    }
    fn packet(
        sender: &mut SecurityContext,
        num: u32,
        different_tokens: bool,
        mid: u16,
    ) -> (std::vec::Vec<u8>, RequestRef) {
        let token = Token::new(&[if different_tokens { num as u8 } else { 9 }]).unwrap();
        let q = BlockValue::from_size(num, num < 2, 16).unwrap().encode();
        let size = encode_uint(48);
        let opts = [
            Opt::uri_path("upload"),
            Opt::q_block1(&q),
            Opt::size1(&size),
            Opt::request_tag(b"body"),
        ];
        let request = Message::new(Type::NonConfirmable, Code::PUT, MessageId::new(mid))
            .with_token(token)
            .with_options(&opts)
            .with_payload(&BODY[num as usize * 16..(num as usize + 1) * 16]);
        let mut wire = [0; WIRE];
        let n = sender.protect_request(&request, &mut wire).unwrap();
        (wire[..n].to_vec(), sender.lookup(token).unwrap())
    }
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    for expire in [false, true] {
        for fail_send in [false, true] {
            for different_tokens in [false, true] {
                CALLS.store(0, Ordering::SeqCst);
                let mut sender = client_c1();
                let mut server = App::profile::<profiles::Default>()
                    .deterministic_for_tests()
                    .block_wise::<true>()
                    .route("upload", put(upload))
                    .bind(QWire::default())
                    .unwrap();
                server.set_oscore(server_c1());
                let (zero, _) = packet(&mut sender, 0, different_tokens, 100);
                let (two, _) = packet(&mut sender, 2, different_tokens, 101);
                let (duplicate, latest) = packet(&mut sender, 2, different_tokens, 102);
                // A freshly protected duplicate updates the report reference;
                // the reordered older request must not replace it.
                for wire in [two, duplicate, zero] {
                    server.transport_mut().inbox = Some((peer, wire));
                    server.poll(0).unwrap();
                }
                assert!(server.transport().sent.is_empty());
                let id = (0..2)
                    .map(SlotId::from_index)
                    .find(|id| server.engine().rx_body_transfer(*id).is_some())
                    .unwrap();
                let before = server.engine().rx_body_transfer(id).unwrap();
                assert_eq!(before.role(), BlockRole::IncomingQBlock1);
                let checkpoint = server.oscore().unwrap().replay_checkpoint();
                let (mut corrupt, _) = packet(&mut sender, 1, different_tokens, 103);
                *corrupt.last_mut().unwrap() ^= 1;
                server.transport_mut().inbox = Some((peer, corrupt));
                server.poll(1).unwrap();
                assert_eq!(server.engine().rx_body_transfer(id), Some(before));
                assert_eq!(server.oscore().unwrap().replay_checkpoint(), checkpoint);
                let mut now = before.q_receive().unwrap().next_timeout_ms();
                if fail_send {
                    server.transport_mut().fail_send = true;
                    assert!(server.poll(now).is_err());
                    assert!(server.transport().sent.is_empty());
                    assert!(server.engine().rx_body_transfer(id).is_some());
                    now = server
                        .engine()
                        .rx_body_transfer(id)
                        .unwrap()
                        .q_receive()
                        .unwrap()
                        .next_timeout_ms();
                }
                server.poll(now).unwrap();
                let mut last_sequence = None;
                let check_report =
                    |wire: &[u8], sender: &mut SecurityContext, last: &mut Option<u64>| {
                        let outer = decode(wire).unwrap();
                        assert_eq!(outer.ty(), Type::NonConfirmable);
                        assert_eq!(
                            outer.token(),
                            Token::new(&[if different_tokens { 2 } else { 9 }]).unwrap()
                        );
                        let sequence = header::OscoreHeader::parse(outer.oscore().unwrap())
                            .unwrap()
                            .piv
                            .unwrap()
                            .seq();
                        assert!(last.is_none_or(|old| sequence > old));
                        *last = Some(sequence);
                        let mut plain = [0; WIRE];
                        let report = sender
                            .unprotect_response(&outer, latest, &mut plain)
                            .unwrap();
                        assert_eq!(report.code(), Code::REQUEST_ENTITY_INCOMPLETE);
                        assert_eq!(
                            report.content_format(),
                            Some(Ok(ContentFormat::MISSING_BLOCKS))
                        );
                        assert_eq!(report.payload(), &[1]); // CBOR sequence containing missing NUM=1.
                    };
                assert_eq!(server.transport().sent.len(), 1);
                check_report(
                    &server.transport_mut().sent.remove(0),
                    &mut sender,
                    &mut last_sequence,
                );
                if expire {
                    for _ in 0..=crate::message::QBlockTransmission::NON_MAX_RETRANSMIT {
                        let Some(transfer) = server.engine().rx_body_transfer(id) else {
                            break;
                        };
                        now = transfer.q_receive().unwrap().next_timeout_ms();
                        server.poll(now).unwrap();
                        for report in server.transport_mut().sent.drain(..) {
                            check_report(&report, &mut sender, &mut last_sequence);
                        }
                    }
                    assert!(server.engine().rx_body_transfer(id).is_none());
                    assert_eq!(CALLS.load(Ordering::SeqCst), 0);
                    // Reuse the reclaimed body slot and tag with a fresh upload.
                    for num in [0, 2] {
                        let (wire, _) =
                            packet(&mut sender, num, different_tokens, 200 + num as u16);
                        server.transport_mut().inbox = Some((peer, wire));
                        server.poll(now + 1).unwrap();
                    }
                }
                let (wire, final_ref) = packet(&mut sender, 1, different_tokens, 210);
                server.transport_mut().inbox = Some((peer, wire));
                server.poll(now + 2).unwrap();
                assert_eq!(CALLS.load(Ordering::SeqCst), 1);
                assert_eq!(server.transport().sent.len(), 1);
                let outer = decode(&server.transport().sent[0]).unwrap();
                let mut plain = [0; WIRE];
                assert_eq!(
                    sender
                        .unprotect_response(&outer, final_ref, &mut plain)
                        .unwrap()
                        .code(),
                    Code::CHANGED
                );
                assert!(server.engine().rx_body_transfer(id).is_none());
                assert_eq!(server.engine_mut().rx_occupied(), 0);
                assert_eq!(server.engine_mut().tx_occupied(), 0);
            }
        }
    }
}

#[test]
fn protected_qblock1_report_sequence_exhaustion_never_sends_plaintext() {
    use crate::storage::SlotId;
    use crate::{App, profiles, put};
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    let mut sender = client_c1();
    let mut server = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .route(
            "upload",
            put(|_| panic!("incomplete upload reached handler")),
        )
        .bind(QWire::default())
        .unwrap();
    let mut context = server_c1();
    context.set_sender_seq((1u64 << 40) - 1).unwrap();
    server.set_oscore(context);
    for num in [0, 2] {
        let q = BlockValue::from_size(num, num == 0, 16).unwrap().encode();
        let size = encode_uint(48);
        let opts = [
            Opt::uri_path("upload"),
            Opt::q_block1(&q),
            Opt::size1(&size),
            Opt::request_tag(b"body"),
        ];
        let request = Message::new(
            Type::NonConfirmable,
            Code::PUT,
            MessageId::new(100 + num as u16),
        )
        .with_token(Token::new(b"q").unwrap())
        .with_options(&opts)
        .with_payload(&[b'Q'; 16]);
        let mut wire = [0; WIRE];
        let n = sender.protect_request(&request, &mut wire).unwrap();
        server.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
        server.poll(0).unwrap();
    }
    let id = (0..2)
        .map(SlotId::from_index)
        .find(|id| server.engine().rx_body_transfer(*id).is_some())
        .unwrap();
    let due = server
        .engine()
        .rx_body_transfer(id)
        .unwrap()
        .q_receive()
        .unwrap()
        .next_timeout_ms();
    server.poll(due).unwrap();
    let bytes = server.transport_mut().sent.remove(0);
    let outer = decode(&bytes).unwrap();
    assert_eq!(
        header::OscoreHeader::parse(outer.oscore().unwrap())
            .unwrap()
            .piv
            .unwrap()
            .seq(),
        (1u64 << 40) - 1
    );
    let mut refused = 0;
    for _ in 0..=crate::message::QBlockTransmission::NON_MAX_RETRANSMIT {
        let Some(transfer) = server.engine().rx_body_transfer(id) else {
            break;
        };
        let result = server.poll(transfer.q_receive().unwrap().next_timeout_ms());
        if server.engine().rx_body_transfer(id).is_some() {
            assert_eq!(result, Err(crate::Error::Oscore(Error::SequenceExhausted)));
            refused += 1;
        } else {
            result.unwrap();
        }
        assert!(server.transport().sent.is_empty());
        assert_eq!(server.engine_mut().tx_occupied(), 0);
    }
    assert!(refused > 0);
    assert!(server.engine().rx_body_transfer(id).is_none());
    assert_eq!(server.oscore().unwrap().sender_seq(), 1u64 << 40);
}

#[test]
fn protected_observe_reregistration_continues_sequence_and_replaces_request_binding() {
    use crate::storage::ObserveKey;
    use crate::{App, Request, Response, get, profiles};
    fn value(_: Request<'_>) -> Response<'static> {
        Response::content(b"initial").observe(0)
    }
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    let token = Token::new(&[0x51]).unwrap();
    for fail_response in [false, true] {
        let mut server = App::profile::<profiles::Default>()
            .deterministic_for_tests()
            .block_wise::<false>()
            .route("obs", get(value))
            .bind(QWire::default())
            .unwrap();
        server.set_oscore(server_c1());
        let mut client = client_c1();
        let options = [Opt::observe_register(), Opt::uri_path("obs")];
        let mut wire = [0; 256];
        let mut opened = [0; 256];
        for round in 0..3u16 {
            let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(100 + round))
                .with_token(token)
                .with_options(&options);
            let n = client.protect_request(&request, &mut wire).unwrap();
            let reference = client.lookup(token).unwrap();
            let bytes = wire[..n].to_vec();
            let key = ObserveKey::new(token, peer);
            if round > 0 {
                let id = server.engine().lookup_observe(key).unwrap();
                let previous = server.engine().observe_interest(id).unwrap();
                // An unauthenticated refresh must not replace sequence or AAD.
                let mut corrupted = bytes.clone();
                *corrupted.last_mut().unwrap() ^= 1;
                server.transport_mut().inbox = Some((peer, corrupted));
                server.poll(u64::from(round) * 10_000).unwrap();
                assert_eq!(
                    server.engine().observe_interest(id).unwrap().seq(),
                    previous.seq()
                );
                assert_eq!(
                    server.engine().observe_interest(id).unwrap().oscore(),
                    previous.oscore()
                );
                assert!(server.transport().sent.is_empty());
            }
            server.transport_mut().fail_send = fail_response && round == 1;
            server.transport_mut().inbox = Some((peer, bytes));
            let result = server.poll(u64::from(round) * 10_000 + 1);
            if fail_response && round == 1 {
                assert!(matches!(result, Err(crate::app::Error::Io(_))));
                assert!(server.transport().sent.is_empty());
            } else {
                result.unwrap();
                let response = server.transport_mut().sent.remove(0);
                let outer = decode(&response).unwrap();
                assert_eq!(outer.observe(), Some(Ok(u32::from(round) * 2)));
                assert_eq!(
                    client
                        .unprotect_response(&outer, reference, &mut opened)
                        .unwrap()
                        .payload(),
                    b"initial"
                );
            }
            let id = server.engine().lookup_observe(key).unwrap();
            let row = server.engine().observe_interest(id).unwrap();
            assert_eq!(row.seq(), u32::from(round) * 2);
            assert_eq!(row.oscore(), Some(reference));
            assert_eq!(
                server
                    .notify(
                        u64::from(round) * 10_000 + 2,
                        &["obs"],
                        Response::content(b"next")
                    )
                    .unwrap(),
                1
            );
            let response = server.transport_mut().sent.remove(0);
            let outer = decode(&response).unwrap();
            assert_eq!(outer.observe(), Some(Ok(u32::from(round) * 2 + 1)));
            assert_eq!(
                client
                    .unprotect_response(&outer, reference, &mut opened)
                    .unwrap()
                    .payload(),
                b"next"
            );
            assert_eq!(server.engine_mut().tx_occupied(), 0);
            assert_eq!(server.engine_mut().rx_occupied(), 0);
        }
    }
}

#[test]
fn protected_client_reregistration_rebinds_and_reports_send_failure() {
    use crate::{App, Request, Response, get, profiles};
    fn value(_: Request<'_>) -> Response<'static> {
        Response::content(b"initial").observe(0)
    }
    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);
    for fail in [false, true] {
        let mut server = App::profile::<profiles::Default>()
            .deterministic_for_tests()
            .block_wise::<false>()
            .route("obs", get(value))
            .bind(QWire::default())
            .unwrap();
        server.set_oscore(server_c1());
        let mut client = App::profile::<profiles::Default>()
            .deterministic_for_tests()
            .block_wise::<false>()
            .bind(QWire::default())
            .unwrap();
        client.set_oscore(client_c1());
        for iteration in 0..8u64 {
            let now = iteration * 10_000;
            let call = client.get("obs").observe().to(server_ep).send(now).unwrap();
            let request = client.transport_mut().sent.remove(0);
            server.transport_mut().inbox = Some((client_ep, request));
            server.poll(now).unwrap();
            client.transport_mut().inbox = Some((server_ep, server.transport_mut().sent.remove(0)));
            client.poll(now + 1).unwrap();
            assert_eq!(
                client.take_response(call).unwrap().unwrap().payload(),
                b"initial"
            );
            assert_eq!(
                server
                    .notify(now + 2, &["obs"], Response::content(b"old"))
                    .unwrap(),
                1
            );
            let delayed = server.transport_mut().sent.remove(0);
            let old_reference = client.oscore().unwrap().lookup(call.token()).unwrap();
            client.transport_mut().fail_send = fail;
            let outcome = client
                .get("obs")
                .reregister_call(call)
                .to(server_ep)
                .send(now + 3);
            if fail {
                assert!(matches!(outcome, Err(crate::app::Error::Io(_))));
                assert_eq!(
                    client.take_response(call).unwrap().unwrap_err(),
                    crate::CallFailure::ReregistrationFailed
                );
                assert!(client.oscore().unwrap().lookup(call.token()).is_none());
            } else {
                assert_eq!(outcome.unwrap(), call);
                let new_reference = client.oscore().unwrap().lookup(call.token()).unwrap();
                assert!(new_reference.piv().seq() > old_reference.piv().seq());
                let refreshed = client.transport_mut().sent.remove(0);
                client.transport_mut().inbox = Some((server_ep, delayed));
                client.poll(now + 4).unwrap();
                assert!(
                    client.take_response(call).is_none(),
                    "old binding must not deliver after refresh"
                );
                server.transport_mut().inbox = Some((client_ep, refreshed));
                server.poll(now + 5).unwrap();
                client.transport_mut().inbox =
                    Some((server_ep, server.transport_mut().sent.remove(0)));
                client.poll(now + 6).unwrap();
                assert_eq!(
                    client.take_response(call).unwrap().unwrap().payload(),
                    b"initial"
                );
                assert_eq!(
                    server
                        .notify(now + 7, &["obs"], Response::content(b"new"))
                        .unwrap(),
                    1
                );
                client.transport_mut().inbox =
                    Some((server_ep, server.transport_mut().sent.remove(0)));
                client.poll(now + 8).unwrap();
                assert_eq!(
                    client.take_response(call).unwrap().unwrap().payload(),
                    b"new"
                );
                assert!(client.cancel(call));
                assert_eq!(
                    client.take_response(call).unwrap().unwrap_err(),
                    crate::CallFailure::Cancelled
                );
            }
            // Remove the remote relation so each iteration proves local capacity
            // reuse without exhausting the independent server's observer table.
            server
                .engine_mut()
                .take_observe(crate::storage::ObserveKey::new(call.token(), client_ep))
                .unwrap();
            assert_eq!(client.engine_mut().tx_occupied(), 0);
            assert_eq!(client.engine_mut().rx_occupied(), 0);
        }
    }
}

#[test]
fn protected_observe_format_refusal_precedes_replay_commit_and_body_admission() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    for body_mode in 0..3 {
        for fail_rst in [false, true] {
            let mut client = App::profile::<profiles::Default>()
                .deterministic_for_tests()
                .block_wise::<true>()
                .bind(QWire::default())
                .unwrap();
            client.set_oscore(client_c1());
            let call = client.get("obs").observe().to(peer).send(0).unwrap();
            let request = client.transport_mut().sent.remove(0);
            let mut server = server_c1();
            let mut scratch = [0; WIRE];
            let (_, reference) = server
                .unprotect_request(&decode(&request).unwrap(), &mut scratch)
                .unwrap();
            let other = client.get("other").non().to(peer).send(0).unwrap();
            client.transport_mut().sent.clear();
            let initial_format = encode_uint(u32::from(ContentFormat::TEXT_PLAIN.get()));
            let changed_format = encode_uint(u32::from(ContentFormat::OCTET_STREAM.get()));
            let block = BlockValue::from_size(0, true, 16).unwrap().encode();
            let size = encode_uint(32);
            for step in 0..2 {
                let seq = encode_uint(step);
                let mut opts = OptionsBuilder::<5>::new();
                opts.push(Opt::observe(&seq)).unwrap();
                opts.push(Opt::content_format(if step == 0 {
                    &initial_format
                } else {
                    &changed_format
                }))
                .unwrap();
                if step == 1 && body_mode != 0 {
                    opts.push(Opt::etag(b"v1")).unwrap();
                    opts.push(Opt::size2(&size)).unwrap();
                    opts.push(if body_mode == 1 {
                        Opt::block2(&block)
                    } else {
                        Opt::q_block2(&block)
                    })
                    .unwrap();
                }
                let response = Message::new(
                    Type::Confirmable,
                    Code::CONTENT,
                    MessageId::new(100 + step as u16),
                )
                .with_token(call.token())
                .with_options(opts.as_slice())
                .with_payload(b"abcdefghijklmnop");
                let mut wire = [0; WIRE];
                let n = server
                    .protect_response_with_piv(&response, reference, &mut wire)
                    .unwrap();
                let checkpoint = client.oscore().unwrap().replay_checkpoint();
                client.transport_mut().fail_send = step == 1 && fail_rst;
                client.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
                let result = client.poll(u64::from(step) + 1);
                if step == 0 {
                    result.unwrap();
                    assert_eq!(
                        client.take_response(call).unwrap().unwrap().payload(),
                        b"abcdefghijklmnop"
                    );
                    assert!(
                        decode(&client.transport_mut().sent.remove(0))
                            .unwrap()
                            .is_empty_ack()
                    );
                } else {
                    if fail_rst {
                        assert!(matches!(result, Err(crate::app::Error::Io(_))));
                    } else {
                        result.unwrap();
                        assert!(
                            decode(&client.transport_mut().sent.remove(0))
                                .unwrap()
                                .is_empty_rst()
                        );
                    }
                    assert_eq!(
                        client.take_response(call).unwrap().unwrap_err(),
                        crate::CallFailure::ObserveFormatMismatch
                    );
                    assert_eq!(client.oscore().unwrap().replay_checkpoint(), checkpoint);
                    assert!(client.oscore().unwrap().lookup(call.token()).is_none());
                    assert!(client.oscore().unwrap().lookup(other.token()).is_some());
                    assert!(
                        client
                            .engine()
                            .rx_body_transfer(crate::storage::SlotId::from_index(0))
                            .is_none()
                    );
                    client.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
                    client.poll(3).unwrap();
                    assert!(
                        client.transport().sent.is_empty(),
                        "a refused CON must not acquire an ACK replay entry"
                    );
                }
            }
            assert!(client.cancel(other));
            assert_eq!(client.engine_mut().tx_occupied(), 0);
            assert_eq!(client.engine_mut().rx_occupied(), 0);
        }
    }
}

#[test]
fn protected_observe_download_retains_registration_binding_across_followups() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .bind(QWire::default())
        .unwrap();
    client.set_oscore(client_c1());
    let call = client.get("obs").observe().to(peer).send(0).unwrap();
    let initial = client.transport_mut().sent.remove(0);
    let mut server = server_c1();
    let mut scratch = [0; WIRE];
    let (_, registration) = server
        .unprotect_request(&decode(&initial).unwrap(), &mut scratch)
        .unwrap();
    let cf = encode_uint(u32::from(ContentFormat::TEXT_PLAIN.get()));
    let sequence = encode_uint(0);
    let mut wire = [0; WIRE];
    let first = BlockValue::from_size(0, true, 16).unwrap().encode();
    let options = [
        Opt::etag(b"a"),
        Opt::observe(&sequence),
        Opt::content_format(&cf),
        Opt::block2(&first),
    ];
    let response = Message::new(Type::NonConfirmable, Code::CONTENT, MessageId::new(100))
        .with_token(call.token())
        .with_options(&options)
        .with_payload(b"abcdefghijklmnop");
    let n = server
        .protect_response_with_piv(&response, registration, &mut wire)
        .unwrap();
    let old_notification = wire[..n].to_vec();
    client.transport_mut().inbox = Some((peer, old_notification.clone()));
    client.poll(1).unwrap();
    assert!(client.take_response(call).is_none());
    let followup = client.transport_mut().sent.remove(0);
    let (request, continuation) = server
        .unprotect_request(&decode(&followup).unwrap(), &mut scratch)
        .unwrap();
    assert!(
        request.observe().is_none(),
        "body follow-up must not re-register the observation"
    );
    assert_eq!(request.block2().unwrap().unwrap().num(), 1);
    let last = BlockValue::from_size(1, false, 16).unwrap().encode();
    let options = [
        Opt::etag(b"a"),
        Opt::content_format(&cf),
        Opt::block2(&last),
    ];
    let response = Message::new(Type::Acknowledgement, Code::CONTENT, request.message_id())
        .with_token(call.token())
        .with_options(&options)
        .with_payload(b"qrstuvwxyzABCDEF");
    let n = server
        .protect_response(&response, continuation, &mut wire)
        .unwrap();
    client.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
    client.poll(2).unwrap();
    assert_eq!(
        client.take_response(call).unwrap().unwrap().body(),
        Some(&b"abcdefghijklmnopqrstuvwxyzABCDEF"[..])
    );
    let seq = encode_uint(1);
    let options = [Opt::observe(&seq), Opt::content_format(&cf)];
    let response = Message::new(Type::NonConfirmable, Code::CONTENT, MessageId::new(101))
        .with_token(call.token())
        .with_options(&options)
        .with_payload(b"new");
    let n = server
        .protect_response_with_piv(&response, registration, &mut wire)
        .unwrap();
    client.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
    client.poll(3).unwrap();
    assert_eq!(
        client.take_response(call).unwrap().unwrap().payload(),
        b"new"
    );
    client.transport_mut().inbox = Some((peer, old_notification));
    client.poll(4).unwrap();
    assert!(client.take_response(call).is_none());
    assert!(client.transport().sent.is_empty());
    assert!(client.cancel(call));
    assert!(client.oscore().unwrap().lookup(call.token()).is_none());
    assert_eq!(client.engine_mut().tx_occupied(), 0);
    assert_eq!(client.engine_mut().rx_occupied(), 0);
}

#[test]
fn observe_download_binding_is_bounded_and_does_not_reset_notification_freshness() {
    let mut client = client_c1();
    let mut server = server_c1();
    let mut wire = [0; WIRE];
    let mut scratch = [0; WIRE];
    for index in 0..LIVE_REQUESTS {
        let token = Token::new(&[index as u8]).unwrap();
        let registration = [Opt::observe_register(), Opt::uri_path("obs")];
        let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(index as u16))
            .with_token(token)
            .with_options(&registration);
        let n = client.protect_request(&request, &mut wire).unwrap();
        let (_, original) = server
            .unprotect_request(&decode(&wire[..n]).unwrap(), &mut scratch)
            .unwrap();
        client
            .accept_notification(token, Some(PartialIv::from_seq(100).unwrap()))
            .unwrap();
        let mut earlier = None;
        for q in [false, true] {
            let block = BlockValue::from_size(1, false, 16).unwrap().encode();
            let options = [
                Opt::uri_path("obs"),
                if q {
                    Opt::q_block2(&block)
                } else {
                    Opt::block2(&block)
                },
            ];
            let request = Message::new(
                Type::Confirmable,
                Code::GET,
                MessageId::new(10 + index as u16),
            )
            .with_token(token)
            .with_options(&options);
            let n = client.protect_request(&request, &mut wire).unwrap();
            let (_, latest) = server
                .unprotect_request(&decode(&wire[..n]).unwrap(), &mut scratch)
                .unwrap();
            if let Some(previous) = earlier {
                let response =
                    Message::new(Type::NonConfirmable, Code::CONTENT, MessageId::new(201))
                        .with_token(token)
                        .with_payload(b"obsolete download");
                let n = server
                    .protect_response_with_piv(&response, previous, &mut wire)
                    .unwrap();
                assert_eq!(
                    client.unprotect_bound_response(&decode(&wire[..n]).unwrap(), &mut scratch),
                    Err(Error::Decrypt)
                );
            }
            earlier = Some(latest);
            assert_ne!(latest, original);
            assert_eq!(client.lookup(token), Some(latest));
            assert_eq!(client.observe_request(token), Some(original));
            assert_eq!(
                client.notification_fresh(token, Some(PartialIv::from_seq(100).unwrap())),
                Err(Error::Replay)
            );
            client.accept_response_without_piv(token).unwrap();
            assert_eq!(client.response_without_piv_fresh(token), Err(Error::Replay));
            assert!(client.notification_fresh(token, None).is_ok());
            // Both retained references authenticate ordinary responses, but an
            // earlier intermediate download reference is not retained.
            for reference in [original, latest] {
                let response =
                    Message::new(Type::NonConfirmable, Code::CONTENT, MessageId::new(200))
                        .with_token(token)
                        .with_payload(b"bound");
                let n = server
                    .protect_response_with_piv(&response, reference, &mut wire)
                    .unwrap();
                let outer = decode(&wire[..n]).unwrap();
                let (inner, used) = client
                    .unprotect_bound_response(&outer, &mut scratch)
                    .unwrap();
                assert_eq!(used, reference);
                assert_eq!(inner.payload(), b"bound");
                wire[n - 1] ^= 1;
                assert_eq!(
                    client.unprotect_bound_response(&decode(&wire[..n]).unwrap(), &mut scratch),
                    Err(Error::Decrypt)
                );
            }
        }
    }
    let request = Message::new(Type::Confirmable, Code::GET, MessageId::new(999))
        .with_token(Token::new(&[99]).unwrap());
    assert_eq!(
        client.protect_request(&request, &mut wire),
        Err(Error::Saturated)
    );
    for index in 0..LIVE_REQUESTS {
        let token = Token::new(&[index as u8]).unwrap();
        assert!(client.take(token).is_some());
        assert!(client.observe_request(token).is_none());
    }
    assert!(client.protect_request(&request, &mut wire).is_ok());
}

#[test]
fn protected_large_server_notifications_assemble_and_recover_from_send_failure() {
    use crate::{App, Request, Response, get, profiles};
    const BODY: [u8; 4097] = [b'Z'; 4097];
    fn value<const N: usize>(request: Request<'_>) -> Response<'static> {
        Response::content(if request.is_observe_register() {
            b"initial"
        } else {
            &BODY[..N]
        })
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"v1")
        .observe(0)
    }
    let client_ep = Endpoint::v4([192, 0, 2, 1], 5683);
    let server_ep = Endpoint::v4([192, 0, 2, 2], 5683);
    let base = 86_400_000;
    for confirmable in [false, true] {
        for length in [2000, 4096, 4097] {
            for fail_send in [false, true] {
                let mut server = App::profile::<profiles::Default>()
                    .deterministic_for_tests()
                    .block_wise::<true>()
                    .route(
                        "obs",
                        get(if length == 2000 {
                            value::<2000>
                        } else {
                            value::<4096>
                        }),
                    )
                    .bind(QWire::default())
                    .unwrap();
                server.set_oscore(server_c1());
                let mut client = App::profile::<profiles::Default>()
                    .deterministic_for_tests()
                    .block_wise::<true>()
                    .bind(QWire::default())
                    .unwrap();
                client.set_oscore(client_c1());
                let call = client
                    .get("obs")
                    .observe()
                    .to(server_ep)
                    .send(base)
                    .unwrap();
                server.transport_mut().inbox =
                    Some((client_ep, client.transport_mut().sent.remove(0)));
                server.poll(base).unwrap();
                client.transport_mut().inbox =
                    Some((server_ep, server.transport_mut().sent.remove(0)));
                client.poll(base + 1).unwrap();
                assert_eq!(
                    client.take_response(call).unwrap().unwrap().payload(),
                    b"initial"
                );
                let response = Response::content(&BODY[..length])
                    .content_format(ContentFormat::OCTET_STREAM)
                    .etag(b"v1");
                if confirmable {
                    server
                        .engine_mut()
                        .record_observe_notify(
                            crate::storage::ObserveKey::new(call.token(), client_ep),
                            0,
                            MessageId::new(55),
                            false,
                        )
                        .unwrap();
                }
                server.transport_mut().fail_send = fail_send;
                let first = server.notify(base + 2, &["obs"], response);
                if length > 4096 {
                    assert!(matches!(
                        first,
                        Err(crate::app::Error::Block(
                            crate::error::BlockTransferError::Overflow
                        ))
                    ));
                    assert!(server.transport().sent.is_empty());
                    server.transport_mut().fail_send = false;
                    assert_eq!(
                        server
                            .notify(
                                base + 3,
                                &["obs"],
                                Response::content(b"small")
                                    .content_format(ContentFormat::OCTET_STREAM)
                            )
                            .unwrap(),
                        1
                    );
                    client.transport_mut().inbox =
                        Some((server_ep, server.transport_mut().sent.remove(0)));
                    client.poll(base + 3).unwrap();
                    assert_eq!(
                        client.take_response(call).unwrap().unwrap().payload(),
                        b"small"
                    );
                } else {
                    if fail_send {
                        assert!(matches!(first, Err(crate::app::Error::Io(_))));
                        assert!(server.transport().sent.is_empty());
                        assert!(
                            server
                                .engine()
                                .tx_body_transfer(crate::storage::SlotId::from_index(0))
                                .is_none()
                        );
                        assert_eq!(server.notify(base + 3, &["obs"], response).unwrap(), 1);
                    } else {
                        assert_eq!(first.unwrap(), 1);
                    }
                    let first_wire = &server.transport().sent[0];
                    assert_eq!(
                        decode(first_wire).unwrap().ty(),
                        if confirmable {
                            Type::Confirmable
                        } else {
                            Type::NonConfirmable
                        }
                    );
                    assert!(
                        super::OscoreHeader::parse(decode(first_wire).unwrap().oscore().unwrap())
                            .unwrap()
                            .piv
                            .is_some()
                    );
                    let mut complete = false;
                    for step in 0..8 {
                        if server.transport().sent.is_empty() {
                            break;
                        }
                        let response = server.transport_mut().sent.remove(0);
                        client.transport_mut().inbox = Some((server_ep, response));
                        client.poll(base + 10 + step).unwrap();
                        if let Some(reply) = client.take_response(call) {
                            assert_eq!(reply.unwrap().body(), Some(&BODY[..length]));
                            complete = true;
                            break;
                        }
                        while !client.transport().sent.is_empty() {
                            let request = client.transport_mut().sent.remove(0);
                            server.transport_mut().inbox = Some((client_ep, request));
                            server.poll(base + 10 + step).unwrap();
                        }
                    }
                    assert!(complete, "large notification did not complete");
                }
                while !client.transport().sent.is_empty() {
                    server.transport_mut().inbox =
                        Some((client_ep, client.transport_mut().sent.remove(0)));
                    server.poll(base + 100).unwrap();
                }
                server
                    .oscore_mut()
                    .unwrap()
                    .set_sender_seq(1u64 << 40)
                    .unwrap();
                assert!(matches!(
                    server.notify(base + 10_000, &["obs"], response),
                    Err(crate::app::Error::Oscore(Error::SequenceExhausted))
                ));
                assert!(
                    server.transport().sent.is_empty(),
                    "exhaustion must never fall back to plaintext"
                );
                assert!(client.cancel(call));
                server
                    .poll(
                        base + 10_000
                            + u64::from(crate::message::Transmission::EXCHANGE_LIFETIME_MS),
                    )
                    .unwrap();
                assert_eq!(server.engine_mut().tx_occupied(), 0);
                assert_eq!(server.engine_mut().rx_occupied(), 0);
                assert_eq!(client.engine_mut().tx_occupied(), 0);
                assert_eq!(client.engine_mut().rx_occupied(), 0);
            }
        }
    }
}

#[test]
fn protected_observe_aggregation_preserves_binding_sequence_and_queued_reply() {
    use crate::{App, profiles};
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    let mut client = App::profile::<profiles::Default>()
        .deterministic_for_tests()
        .block_wise::<false>()
        .bind(QWire::default())
        .unwrap();
    client.set_oscore(client_c1());
    let call = client.get("obs").observe().non().to(peer).send(0).unwrap();
    client.transport_mut().sent.clear();
    let reference = client.oscore().unwrap().lookup(call.token()).unwrap();
    let mut server = server_c1();
    let seq = encode_uint(0);
    let opts = [Opt::observe(&seq)];
    let response = Message::new(Type::NonConfirmable, Code::CONTENT, MessageId::new(100))
        .with_token(call.token())
        .with_options(&opts)
        .with_payload(b"queued");
    let mut wire = [0; WIRE];
    let n = server
        .protect_response_with_piv(&response, reference, &mut wire)
        .unwrap();
    client.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
    client.poll(1).unwrap();
    let sender_seq = client.oscore().unwrap().sender_seq();
    for _ in 0..32 {
        assert_eq!(
            client
                .get("obs")
                .observe()
                .etag(b"new")
                .to(peer)
                .send(2)
                .unwrap(),
            call
        );
        assert_eq!(
            client.oscore().unwrap().lookup(call.token()),
            Some(reference)
        );
        assert_eq!(client.oscore().unwrap().sender_seq(), sender_seq);
        assert!(client.transport().sent.is_empty());
    }
    assert_eq!(
        client.take_response(call).unwrap().unwrap().payload(),
        b"queued"
    );
    assert!(client.take_response(call).is_none());
    client.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
    client.poll(3).unwrap();
    assert!(
        client.take_response(call).is_none(),
        "aggregation must not reopen replay admission"
    );
    let terminal = Message::new(Type::NonConfirmable, Code::NOT_FOUND, MessageId::new(101))
        .with_token(call.token());
    let n = server
        .protect_response_with_piv(&terminal, reference, &mut wire)
        .unwrap();
    client.transport_mut().inbox = Some((peer, wire[..n].to_vec()));
    client.poll(4).unwrap();
    let next = client.get("obs").observe().non().to(peer).send(5).unwrap();
    assert_ne!(next, call, "a terminal subscription cannot be aggregated");
    assert_eq!(
        client.take_response(call).unwrap().unwrap().code(),
        Code::NOT_FOUND
    );
    assert!(client.cancel(next));
}
