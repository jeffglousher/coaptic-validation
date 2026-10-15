//! In-memory Engine-pair drivers for `TD_COAP_CORE_*`.

use coaptic::message::{Message, Opt, Token, Transmission, Type, empty_ack, empty_rst};
use coaptic::storage::{DedupEntry, Retransmit};
use coaptic::{Code, ContentFormat};

use crate::harness::{Pair, path_is, uri_query};

const TEST_BODY: &[u8] = b"core-test-payload";
const SEP_BODY: &[u8] = b"separate-payload";

pub fn run(id: &str) {
    match id {
        "TD_COAP_CORE_01" => basic(Type::Confirmable, Code::GET, Code::CONTENT, &["test"]),
        "TD_COAP_CORE_02" => basic(Type::Confirmable, Code::DELETE, Code::DELETED, &["test"]),
        "TD_COAP_CORE_03" => basic(Type::Confirmable, Code::PUT, Code::CHANGED, &["test"]),
        "TD_COAP_CORE_04" => basic(Type::Confirmable, Code::POST, Code::CREATED, &["test"]),
        "TD_COAP_CORE_05" => basic(Type::NonConfirmable, Code::GET, Code::CONTENT, &["test"]),
        "TD_COAP_CORE_06" => basic(Type::NonConfirmable, Code::DELETE, Code::DELETED, &["test"]),
        "TD_COAP_CORE_07" => basic(Type::NonConfirmable, Code::PUT, Code::CHANGED, &["test"]),
        "TD_COAP_CORE_08" => basic(Type::NonConfirmable, Code::POST, Code::CREATED, &["test"]),
        "TD_COAP_CORE_09" => separate(Type::Confirmable, Pair::client_token(4), &["separate"]),
        "TD_COAP_CORE_10" => {
            let token = Pair::client_token(4);
            assert!(!token.is_empty());
            basic_token(
                Type::Confirmable,
                Code::GET,
                Code::CONTENT,
                &["test"],
                token,
            );
        }
        "TD_COAP_CORE_11" => separate(Type::Confirmable, Pair::client_token(8), &["separate"]),
        "TD_COAP_CORE_12" => {
            basic_token(
                Type::Confirmable,
                Code::GET,
                Code::CONTENT,
                &["test"],
                Token::EMPTY,
            );
        }
        "TD_COAP_CORE_13" => {
            basic(
                Type::Confirmable,
                Code::GET,
                Code::CONTENT,
                &["seg1", "seg2", "seg3"],
            );
        }
        "TD_COAP_CORE_14" => core_14_uri_query(),
        "TD_COAP_CORE_15" => core_15_lossy_piggyback(),
        "TD_COAP_CORE_16" => core_16_lossy_separate(),
        "TD_COAP_CORE_17" => separate(Type::NonConfirmable, Pair::client_token(4), &["separate"]),
        "TD_COAP_CORE_18" => core_18_location_path(),
        "TD_COAP_CORE_19" => core_19_location_query(),
        "TD_COAP_CORE_20" => core_20_accept(),
        "TD_COAP_CORE_21" => core_21_etag(),
        "TD_COAP_CORE_22" => core_22_if_match(),
        "TD_COAP_CORE_23" => core_23_if_none_match(),
        "TD_COAP_CORE_31" => core_31_ping(),
        other => panic!("unknown CORE id {other} (do not invent TDs)"),
    }
}

fn basic(ty: Type, req: Code, resp: Code, path: &[&str]) {
    basic_token(ty, req, resp, path, Pair::client_token(2));
}

fn basic_token(ty: Type, req: Code, resp: Code, path: &[&str], token: Token) {
    let mut pair = Pair::new();
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let extra: &[Opt<'_>] = if req == Code::PUT || req == Code::POST {
        &[Opt::content_format(&cf)]
    } else {
        &[]
    };
    let payload: &[u8] = if req == Code::PUT || req == Code::POST {
        TEST_BODY
    } else {
        &[]
    };
    let (tx, mid) = pair.client_request(ty, req, token, path, extra, payload);
    let rx = pair.exchange_client(tx);
    let parsed = pair.server.decode_rx(rx).expect("server decode");
    assert_eq!(parsed.ty(), ty);
    assert_eq!(parsed.code(), req);
    assert_eq!(parsed.token(), token);
    assert!(path_is(parsed, path), "path {path:?}");
    pair.server
        .insert_dedup(DedupEntry::new(parsed.message_id(), pair.client_ep))
        .expect("dedup");

    let reply_ty = if ty == Type::Confirmable {
        Type::Acknowledgement
    } else {
        Type::NonConfirmable
    };
    let reply_mid = if ty == Type::Confirmable {
        mid
    } else {
        pair.server_ids.next()
    };
    let body: &[u8] = if resp == Code::CONTENT {
        TEST_BODY
    } else {
        &[]
    };
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let extra: &[Opt<'_>] = if resp == Code::CONTENT {
        &[Opt::content_format(&cf)]
    } else {
        &[]
    };
    let stx = pair.server_reply(reply_ty, resp, reply_mid, token, extra, body);
    pair.server.release_rx(rx).expect("release server RX");
    let crx = pair.exchange_server(stx);
    assert!(
        pair.client.match_response_rx(crx).expect("match").is_some(),
        "{req:?} response unmatched"
    );
    let got = pair.client.decode_rx(crx).expect("client decode");
    assert_eq!(got.code(), resp);
    assert_eq!(got.token(), token);
    if ty == Type::Confirmable {
        assert_eq!(got.ty(), Type::Acknowledgement);
        assert_eq!(got.message_id(), mid);
    } else {
        assert_eq!(got.ty(), Type::NonConfirmable);
    }
    if resp == Code::CONTENT {
        assert_eq!(got.payload(), TEST_BODY);
        assert_eq!(
            got.content_format().expect("cf").expect("val"),
            ContentFormat::TEXT_PLAIN
        );
    }
    pair.client.release_rx(crx).ok();
}

fn separate(req_ty: Type, token: Token, path: &[&str]) {
    let mut pair = Pair::new();
    let (tx, mid) = pair.client_request(req_ty, Code::GET, token, path, &[], &[]);
    if req_ty == Type::Confirmable {
        pair.client_track_con(tx, mid);
    }
    let rx = pair.exchange_client(tx);
    let parsed = pair.server.decode_rx(rx).expect("decode");
    assert!(path_is(parsed, path));
    assert_eq!(parsed.token(), token);

    if req_ty == Type::Confirmable {
        let ack = empty_ack(mid);
        let stx = pair.server_send(&ack);
        let crx = pair.exchange_server(stx);
        let pending = pair.client.match_empty_ack_rst_rx(crx).expect("empty ACK");
        assert!(pending.is_some(), "empty ACK must clear pending CON");
        if let Some(id) = pending {
            pair.client.release_tx(id).ok();
        }
        pair.client.release_rx(crx).ok();
    }

    let smid = pair.server_ids.next();
    let reply_ty = if req_ty == Type::Confirmable {
        Type::Confirmable
    } else {
        Type::NonConfirmable
    };
    pair.server.release_rx(rx).ok();
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let extra = [Opt::content_format(&cf)];
    let stx = pair.server_reply(reply_ty, Code::CONTENT, smid, token, &extra, SEP_BODY);
    let crx = pair.exchange_server(stx);
    assert!(
        pair.client
            .match_response_rx(crx)
            .expect("separate match")
            .is_some()
    );
    let got = pair.client.decode_rx(crx).expect("client decode");
    assert_eq!(got.code(), Code::CONTENT);
    assert_eq!(got.token(), token);
    assert_eq!(got.payload(), SEP_BODY);
    if req_ty == Type::Confirmable {
        assert_eq!(got.ty(), Type::Confirmable);
        let cack = empty_ack(got.message_id());
        let ctx = pair.client.acquire_tx().expect("client ACK TX");
        pair.client.encode_tx(ctx, &cack).expect("encode ACK");
        let srx = pair.client_to_server(ctx);
        pair.client.release_tx(ctx).ok();
        let cleared = pair.server.match_empty_ack_rst_rx(srx).expect("server ACK");
        assert!(cleared.is_some());
        if let Some(id) = cleared {
            pair.server.release_tx(id).ok();
        }
        pair.server.release_rx(srx).ok();
    }
    pair.client.release_rx(crx).ok();
}

fn core_14_uri_query() {
    let mut pair = Pair::new();
    let token = Pair::client_token(2);
    let extra = [
        Opt::uri_query("first=1"),
        Opt::uri_query("second=2"),
        Opt::uri_query("third=3"),
    ];
    let (tx, mid) =
        pair.client_request(Type::Confirmable, Code::GET, token, &["query"], &extra, &[]);
    let rx = pair.exchange_client(tx);
    let parsed = pair.server.decode_rx(rx).expect("decode");
    assert!(path_is(parsed, &["query"]));
    assert_eq!(uri_query(parsed), ["first=1", "second=2", "third=3"]);
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let extra = [Opt::content_format(&cf)];
    let stx = pair.server_reply(
        Type::Acknowledgement,
        Code::CONTENT,
        mid,
        token,
        &extra,
        TEST_BODY,
    );
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    assert!(pair.client.match_response_rx(crx).expect("match").is_some());
    pair.client.release_rx(crx).ok();
}

fn core_15_lossy_piggyback() {
    let mut pair = Pair::new();
    let token = Pair::client_token(2);
    let (tx, mid) = pair.client_request(Type::Confirmable, Code::GET, token, &["test"], &[], &[]);
    pair.client_track_con(tx, mid);
    assert!(
        pair.client.pending_con(tx).is_some(),
        "CORE_15 pending CON must stay on TX"
    );
    pair.now_ms = u64::from(Transmission::ACK_TIMEOUT_MS);
    let Retransmit::Due(pending) = pair
        .client
        .progress(pair.now_ms)
        .retransmit()
        .expect("retransmission launched")
    else {
        panic!("CORE_15 expected Due");
    };
    assert_eq!(pending.message_id(), mid);
    let rx = pair.client_to_server(pending.tx_slot());
    let parsed = pair.server.decode_rx(rx).expect("decode retry");
    assert_eq!(parsed.code(), Code::GET);
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let extra = [Opt::content_format(&cf)];
    let stx = pair.server_reply(
        Type::Acknowledgement,
        Code::CONTENT,
        mid,
        token,
        &extra,
        TEST_BODY,
    );
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    assert!(pair.client.match_response_rx(crx).expect("match").is_some());
    let _ = pair.client.take_pending_con(mid, pair.server_ep);
    pair.client.release_rx(crx).ok();
    pair.client.release_tx(tx).ok();
}

fn core_16_lossy_separate() {
    let mut pair = Pair::new();
    let token = Pair::client_token(2);
    let (tx, mid) =
        pair.client_request(Type::Confirmable, Code::GET, token, &["separate"], &[], &[]);
    pair.client_track_con(tx, mid);
    let rx = pair.client_to_server(tx);
    let ack = empty_ack(mid);
    let stx = pair.server_send(&ack);
    pair.server.release_tx(stx).ok();
    let smid = pair.server_ids.next();
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let extra = [Opt::content_format(&cf)];
    let stx = pair.server_reply(
        Type::Confirmable,
        Code::CONTENT,
        smid,
        token,
        &extra,
        SEP_BODY,
    );
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    assert!(pair.client.match_response_rx(crx).expect("match").is_some());
    let pending = pair.client.take_pending_con(mid, pair.server_ep);
    assert!(
        pending.is_some(),
        "CON response should leave pending CON takeable (ACK was lost)"
    );
    if let Some(id) = pending {
        pair.client.release_tx(id).ok();
    }
    pair.client.release_rx(crx).ok();
}

fn core_18_location_path() {
    let mut pair = Pair::new();
    let token = Pair::client_token(2);
    let loc = [
        Opt::location_path("location1"),
        Opt::location_path("location2"),
    ];
    let (tx, mid) = pair.client_request(
        Type::Confirmable,
        Code::POST,
        token,
        &["test"],
        &[],
        TEST_BODY,
    );
    let rx = pair.exchange_client(tx);
    let stx = pair.server_reply(Type::Acknowledgement, Code::CREATED, mid, token, &loc, &[]);
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    let got = pair.client.decode_rx(crx).expect("decode");
    let segs: Vec<_> = got.location_path().map(|s| s.expect("utf8")).collect();
    assert_eq!(segs, ["location1", "location2"]);
    assert!(pair.client.match_response_rx(crx).expect("match").is_some());
    pair.client.release_rx(crx).ok();
}

fn core_19_location_query() {
    let mut pair = Pair::new();
    let token = Pair::client_token(2);
    let loc = [
        Opt::location_query("first=1"),
        Opt::location_query("second=2"),
    ];
    let (tx, mid) = pair.client_request(
        Type::Confirmable,
        Code::POST,
        token,
        &["test"],
        &[],
        TEST_BODY,
    );
    let rx = pair.exchange_client(tx);
    let stx = pair.server_reply(Type::Acknowledgement, Code::CREATED, mid, token, &loc, &[]);
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    let got = pair.client.decode_rx(crx).expect("decode");
    let qs: Vec<_> = got.location_query().map(|s| s.expect("utf8")).collect();
    assert_eq!(qs, ["first=1", "second=2"]);
    assert!(pair.client.match_response_rx(crx).expect("match").is_some());
    pair.client.release_rx(crx).ok();
}

fn core_20_accept() {
    let mut pair = Pair::new();
    let token = Pair::client_token(2);
    let accept = ContentFormat::TEXT_PLAIN.encode();
    let extra = [Opt::accept(&accept)];
    let (tx, mid) =
        pair.client_request(Type::Confirmable, Code::GET, token, &["test"], &extra, &[]);
    let rx = pair.exchange_client(tx);
    let parsed = pair.server.decode_rx(rx).expect("decode");
    assert_eq!(
        parsed.accept().expect("Accept").expect("val"),
        ContentFormat::TEXT_PLAIN
    );
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let extra = [Opt::content_format(&cf)];
    let stx = pair.server_reply(
        Type::Acknowledgement,
        Code::CONTENT,
        mid,
        token,
        &extra,
        TEST_BODY,
    );
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    assert!(pair.client.match_response_rx(crx).expect("match").is_some());
    pair.client.release_rx(crx).ok();
}

fn core_21_etag() {
    let mut pair = Pair::new();
    let token = Pair::client_token(2);
    let (tx, mid) =
        pair.client_request(Type::Confirmable, Code::GET, token, &["validate"], &[], &[]);
    let rx = pair.exchange_client(tx);
    let etag = b"etag1";
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let extra = [Opt::content_format(&cf), Opt::etag(etag)];
    let stx = pair.server_reply(
        Type::Acknowledgement,
        Code::CONTENT,
        mid,
        token,
        &extra,
        TEST_BODY,
    );
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    let got = pair.client.decode_rx(crx).expect("decode");
    let tags: Vec<_> = got.etag().collect();
    assert_eq!(tags, [etag.as_slice()]);
    assert!(pair.client.match_response_rx(crx).expect("match").is_some());
    pair.client.release_rx(crx).ok();

    let extra = [Opt::etag(etag)];
    let token2 = Pair::client_token(3);
    let (tx2, mid2) = pair.client_request(
        Type::Confirmable,
        Code::GET,
        token2,
        &["validate"],
        &extra,
        &[],
    );
    let rx2 = pair.exchange_client(tx2);
    let extra = [Opt::etag(etag)];
    let stx2 = pair.server_reply(
        Type::Acknowledgement,
        Code::VALID,
        mid2,
        token2,
        &extra,
        &[],
    );
    pair.server.release_rx(rx2).ok();
    let crx2 = pair.exchange_server(stx2);
    assert_eq!(
        pair.client.decode_rx(crx2).expect("decode").code(),
        Code::VALID
    );
    pair.client.match_response_rx(crx2).ok();
    pair.client.release_rx(crx2).ok();
}

fn core_22_if_match() {
    let mut pair = Pair::new();
    let token = Pair::client_token(2);
    let etag = b"etag1";
    let extra = [Opt::if_match(etag)];
    let (tx, mid) = pair.client_request(
        Type::Confirmable,
        Code::PUT,
        token,
        &["validate"],
        &extra,
        TEST_BODY,
    );
    let rx = pair.exchange_client(tx);
    let parsed = pair.server.decode_rx(rx).expect("decode");
    let tags: Vec<_> = parsed.if_match().collect();
    assert_eq!(tags, [etag.as_slice()]);
    let stx = pair.server_reply(Type::Acknowledgement, Code::CHANGED, mid, token, &[], &[]);
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    assert_eq!(
        pair.client.decode_rx(crx).expect("decode").code(),
        Code::CHANGED
    );
    pair.client.match_response_rx(crx).ok();
    pair.client.release_rx(crx).ok();

    let token2 = Pair::client_token(3);
    let extra = [Opt::if_match(b"wrong")];
    let (tx2, mid2) = pair.client_request(
        Type::Confirmable,
        Code::PUT,
        token2,
        &["validate"],
        &extra,
        &[],
    );
    let rx2 = pair.exchange_client(tx2);
    let stx2 = pair.server_reply(
        Type::Acknowledgement,
        Code::PRECONDITION_FAILED,
        mid2,
        token2,
        &[],
        &[],
    );
    pair.server.release_rx(rx2).ok();
    let crx2 = pair.exchange_server(stx2);
    assert_eq!(
        pair.client.decode_rx(crx2).expect("decode").code(),
        Code::PRECONDITION_FAILED
    );
    pair.client.match_response_rx(crx2).ok();
    pair.client.release_rx(crx2).ok();
}

fn core_23_if_none_match() {
    let mut pair = Pair::new();
    let token = Pair::client_token(2);
    let extra = [Opt::if_none_match()];
    let (tx, mid) = pair.client_request(
        Type::Confirmable,
        Code::PUT,
        token,
        &["validate"],
        &extra,
        &[],
    );
    let rx = pair.exchange_client(tx);
    assert!(pair.server.decode_rx(rx).expect("decode").if_none_match());
    let stx = pair.server_reply(
        Type::Acknowledgement,
        Code::PRECONDITION_FAILED,
        mid,
        token,
        &[],
        &[],
    );
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    assert_eq!(
        pair.client.decode_rx(crx).expect("decode").code(),
        Code::PRECONDITION_FAILED
    );
    pair.client.match_response_rx(crx).ok();
    pair.client.release_rx(crx).ok();
}

fn core_31_ping() {
    let mut pair = Pair::new();
    let mid = pair.client_ids.next();
    let ping = Message::new(Type::Confirmable, Code::EMPTY, mid);
    let tx = pair.client.acquire_tx().expect("TX");
    pair.client.encode_tx(tx, &ping).expect("encode ping");
    pair.client
        .record_pending_con(tx, pair.server_ep, mid, pair.now_ms, 0)
        .expect("pending ping");
    let rx = pair.exchange_client(tx);
    let parsed = pair.server.decode_rx(rx).expect("decode ping");
    assert!(parsed.is_empty());
    assert_eq!(parsed.ty(), Type::Confirmable);
    assert!(parsed.token().is_empty());
    assert!(parsed.payload().is_empty());
    let rst = empty_rst(mid);
    let stx = pair.server_send(&rst);
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    let pending = pair.client.match_empty_ack_rst_rx(crx).expect("RST match");
    assert!(pending.is_some(), "ping RST must match pending CON");
    assert!(
        pair.client
            .decode_rx(crx)
            .expect("decode RST")
            .is_empty_rst()
    );
    if let Some(id) = pending {
        pair.client.release_tx(id).ok();
    }
    pair.client.release_rx(crx).ok();
}
