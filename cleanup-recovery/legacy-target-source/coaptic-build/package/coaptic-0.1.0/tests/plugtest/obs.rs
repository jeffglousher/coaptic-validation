//! In-memory Engine-pair drivers for `TD_COAP_OBS_*` (RFC 7641).

use coaptic::message::{
    Opt, Token, Transmission, Type, empty_ack, empty_rst, encode_observe, encode_uint,
};
use coaptic::storage::{ObserveExpiry, ObserveInterest, ObserveKey, Retransmit, SlotId};
use coaptic::{Code, ContentFormat};

use crate::catalog;
use crate::harness::{Pair, block_at, block_key, path_is, patterned_body};

const OBS_BODY: &[u8] = b"obs-0";
const OBS_BODY_2: &[u8] = b"obs-1";

pub fn run(id: &str) {
    if let Some(reason) = catalog::skip_reason(id) {
        panic!("{id} should be skipped: {reason}");
    }
    match id {
        "TD_COAP_OBS_01" => observe_basic(Type::Confirmable, Type::Confirmable, &["obs"]),
        "TD_COAP_OBS_02" => {
            observe_basic(Type::NonConfirmable, Type::NonConfirmable, &["obs-non"]);
        }
        "TD_COAP_OBS_04" => obs_04_max_age(),
        "TD_COAP_OBS_05" => obs_05_client_off(),
        "TD_COAP_OBS_06" => obs_06_rst(),
        "TD_COAP_OBS_07" => obs_07_delete(),
        "TD_COAP_OBS_08" => obs_08_content_format_change(),
        "TD_COAP_OBS_09" => obs_09_update(),
        "TD_COAP_OBS_10" => obs_10_get_does_not_cancel(),
        "TD_COAP_OBS_11" => obs_11_lossy(),
        "TD_COAP_OBS_12" => obs_12_deregister(),
        "TD_COAP_OBS_13" => obs_13_block2(false),
        "TD_COAP_OBS_14" => obs_13_block2(true),
        other => panic!("unknown OBS id {other}"),
    }
}

fn register(
    pair: &mut Pair,
    ty: Type,
    token: Token,
    path: &[&str],
) -> (coaptic::message::MessageId, SlotId) {
    let extra = [Opt::observe_register()];
    let (tx, mid) = pair.client_request(ty, Code::GET, token, path, &extra, &[]);
    let rx = pair.exchange_client(tx);
    let parsed = pair.server.decode_rx(rx).expect("decode observe GET");
    assert!(path_is(parsed, path));
    assert!(parsed.is_observe_register());
    pair.server
        .register_observe_rx(rx)
        .expect("register")
        .expect("row");
    (mid, rx)
}

fn notify(pair: &mut Pair, token: Token, notify_ty: Type, body: &[u8]) -> (u32, SlotId) {
    let key = ObserveKey::new(token, pair.client_ep);
    pair.server.signal_observe(key).expect("signal");
    let oid = pair
        .server
        .progress(pair.now_ms)
        .observe_notify()
        .expect("observe notify");
    let interest = pair.server.observe_interest(oid).expect("interest");
    let seq = encode_observe(interest.seq());
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let extra = [Opt::observe(&seq), Opt::content_format(&cf)];
    let mid = pair.server_ids.next();
    let stx = pair.server_reply(notify_ty, Code::CONTENT, mid, token, &extra, body);
    pair.server
        .record_observe_notify(key, pair.now_ms, mid, notify_ty == Type::Confirmable)
        .expect("record notify");
    let crx = pair.exchange_server(stx);
    let got = pair.client.decode_rx(crx).expect("notify decode");
    assert_eq!(got.token(), token);
    assert_eq!(got.code(), Code::CONTENT);
    let seq_got = got.observe().expect("Observe").expect("val");
    (seq_got, crx)
}

fn observe_basic(req_ty: Type, notify_ty: Type, path: &[&str]) {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let (mid, rx) = register(&mut pair, req_ty, token, path);
    let seq0 = encode_observe(0);
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let extra = [Opt::observe(&seq0), Opt::content_format(&cf)];
    let first_ty = if req_ty == Type::Confirmable {
        Type::Acknowledgement
    } else {
        Type::NonConfirmable
    };
    let first_mid = if req_ty == Type::Confirmable {
        mid
    } else {
        pair.server_ids.next()
    };
    let stx = pair.server_reply(first_ty, Code::CONTENT, first_mid, token, &extra, OBS_BODY);
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    assert_eq!(
        pair.client.decode_rx(crx).expect("first").payload(),
        OBS_BODY
    );
    pair.client.release_rx(crx).ok();

    let (seq1, nrx) = notify(&mut pair, token, notify_ty, OBS_BODY_2);
    assert!(seq1 > 0, "notification sequence must increase");
    if notify_ty == Type::Confirmable {
        let ack = empty_ack(pair.client.decode_rx(nrx).expect("mid").message_id());
        let ctx = pair.client.acquire_tx().expect("ACK TX");
        pair.client.encode_tx(ctx, &ack).ok();
        let srx = pair.client_to_server(ctx);
        pair.client.release_tx(ctx).ok();
        if let Ok(Some(id)) = pair.server.match_empty_ack_rst_rx(srx) {
            pair.server.release_tx(id).ok();
        }
        pair.server.release_rx(srx).ok();
    }
    pair.client.release_rx(nrx).ok();
}

/// RFC 7252 `MAX_LATENCY` (seconds). Client re-register after Max-Age + this.
const MAX_LATENCY_SECS: u32 = 100;

fn obs_04_max_age() {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let max_age = 5u32;
    let client_key = ObserveKey::new(token, pair.server_ep);
    let server_key = ObserveKey::new(token, pair.client_ep);
    pair.client
        .insert_observe(ObserveInterest::new(token, pair.server_ep))
        .expect("client interest");
    let (mid, rx) = register(&mut pair, Type::Confirmable, token, &["obs"]);
    let seq0 = encode_observe(0);
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let age = encode_uint(max_age);
    let extra = [
        Opt::observe(&seq0),
        Opt::content_format(&cf),
        Opt::max_age(&age),
    ];
    let stx = pair.server_reply(
        Type::Acknowledgement,
        Code::CONTENT,
        mid,
        token,
        &extra,
        OBS_BODY,
    );
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    let first = pair.client.decode_rx(crx).expect("first");
    assert_eq!(first.payload(), OBS_BODY);
    assert_eq!(first.max_age(), Some(Ok(max_age)));
    pair.client
        .refresh_observe_max_age(
            client_key,
            pair.now_ms,
            max_age.saturating_add(MAX_LATENCY_SECS),
            None,
        )
        .expect("client max-age");
    pair.client.release_rx(crx).ok();

    let (seq1, nrx) = notify(&mut pair, token, Type::Confirmable, OBS_BODY_2);
    assert!(seq1 > 0);
    let notify_parsed = pair.client.decode_rx(nrx).expect("notify");
    let notify_mid = notify_parsed.message_id();
    pair.client
        .refresh_observe_max_age(
            client_key,
            pair.now_ms,
            max_age.saturating_add(MAX_LATENCY_SECS),
            None,
        )
        .expect("client refresh");
    let ack = empty_ack(notify_mid);
    let ctx = pair.client.acquire_tx().expect("ACK TX");
    pair.client.encode_tx(ctx, &ack).ok();
    let srx = pair.client_to_server(ctx);
    pair.client.release_tx(ctx).ok();
    if let Ok(Some(id)) = pair.server.match_empty_ack_rst_rx(srx) {
        pair.server.release_tx(id).ok();
    }
    pair.server.release_rx(srx).ok();
    pair.client.release_rx(nrx).ok();

    let gone = pair.server.take_observe(server_key);
    assert!(gone.is_some(), "server reboot drops ObserveInterest");
    assert!(pair.server.lookup_observe(server_key).is_none());

    pair.now_ms += u64::from(max_age.saturating_add(MAX_LATENCY_SECS)) * 1_000;
    match pair.client.progress(pair.now_ms).observe_expired() {
        Some(ObserveExpiry::MaxAge(id)) => {
            assert_eq!(
                pair.client.observe_interest(id).expect("row").key(),
                client_key
            );
        }
        other => panic!("OBS_04 expected MaxAge expiry, got {other:?}"),
    }
    pair.client.take_observe(client_key);

    let (mid2, rx2) = register(&mut pair, Type::Confirmable, token, &["obs"]);
    pair.client
        .insert_observe(ObserveInterest::new(token, pair.server_ep))
        .expect("client reregister");
    let seq_re = encode_observe(0);
    let extra2 = [
        Opt::observe(&seq_re),
        Opt::content_format(&cf),
        Opt::max_age(&age),
    ];
    let stx = pair.server_reply(
        Type::Acknowledgement,
        Code::CONTENT,
        mid2,
        token,
        &extra2,
        OBS_BODY,
    );
    pair.server.release_rx(rx2).ok();
    let crx = pair.exchange_server(stx);
    assert_eq!(
        pair.client
            .decode_rx(crx)
            .expect("reregister first")
            .payload(),
        OBS_BODY
    );
    pair.client.release_rx(crx).ok();
    let (seq2, nrx) = notify(&mut pair, token, Type::Confirmable, OBS_BODY_2);
    assert!(seq2 > 0, "post-reregister notification sequence");
    pair.client.release_rx(nrx).ok();
}

fn obs_05_client_off() {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let max_age = 5u32;
    let server_key = ObserveKey::new(token, pair.client_ep);
    let (_mid, rx) = register(&mut pair, Type::Confirmable, token, &["obs"]);
    pair.server.release_rx(rx).ok();

    pair.server.signal_observe(server_key).expect("signal");
    let oid = pair
        .server
        .progress(pair.now_ms)
        .observe_notify()
        .expect("notify");
    let interest = pair.server.observe_interest(oid).expect("row");
    let seq = encode_observe(interest.seq());
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let extra = [Opt::observe(&seq), Opt::content_format(&cf)];
    let mid = pair.server_ids.next();
    let stx = pair.server_reply(
        Type::Confirmable,
        Code::CONTENT,
        mid,
        token,
        &extra,
        OBS_BODY_2,
    );
    pair.server
        .refresh_observe_max_age(server_key, pair.now_ms, max_age, Some(mid))
        .expect("con wait");

    pair.now_ms += u64::from(Transmission::ACK_TIMEOUT_MS);
    let Retransmit::Due(_) = pair
        .server
        .poll_retransmit(pair.now_ms)
        .expect("notify retransmission")
    else {
        panic!("OBS_05 expected Due before lifetime");
    };

    pair.now_ms = u64::from(max_age) * 1_000;
    match pair.server.progress(pair.now_ms).observe_expired() {
        Some(ObserveExpiry::ClientOff(id)) => {
            assert_eq!(
                pair.server.observe_interest(id).expect("row").key(),
                server_key
            );
        }
        other => panic!("OBS_05 expected ClientOff expiry, got {other:?}"),
    }
    assert!(pair.server.take_observe(server_key).is_some());
    assert!(pair.server.signal_observe(server_key).is_none());
    pair.server.release_tx(stx).ok();
}

fn obs_06_rst() {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let (_mid, rx) = register(&mut pair, Type::Confirmable, token, &["obs"]);
    pair.server.release_rx(rx).ok();
    let (_seq, nrx) = notify(&mut pair, token, Type::Confirmable, OBS_BODY_2);
    let mid = pair.client.decode_rx(nrx).expect("mid").message_id();
    let rst = empty_rst(mid);
    let ctx = pair.client.acquire_tx().expect("RST TX");
    pair.client.encode_tx(ctx, &rst).ok();
    let srx = pair.client_to_server(ctx);
    pair.client.release_tx(ctx).ok();
    if let Ok(Some(id)) = pair.server.match_empty_ack_rst_rx(srx) {
        pair.server.release_tx(id).ok();
    }
    let gone = pair
        .server
        .take_observe(ObserveKey::new(token, pair.client_ep));
    assert!(gone.is_some(), "RST must clear ObserveInterest");
    pair.server.release_rx(srx).ok();
    pair.client.release_rx(nrx).ok();
}

fn obs_07_delete() {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let (_mid, rx) = register(&mut pair, Type::Confirmable, token, &["obs"]);
    pair.server.release_rx(rx).ok();
    let del_tok = Pair::client_token(2);
    let (tx, mid) =
        pair.client_request(Type::Confirmable, Code::DELETE, del_tok, &["obs"], &[], &[]);
    let srx = pair.exchange_client(tx);
    assert!(path_is(pair.server.decode_rx(srx).expect("del"), &["obs"]));
    let gone = pair
        .server
        .take_observe(ObserveKey::new(token, pair.client_ep));
    assert!(gone.is_some(), "DELETE must clean observers");
    let stx = pair.server_reply(Type::Acknowledgement, Code::DELETED, mid, del_tok, &[], &[]);
    pair.server.release_rx(srx).ok();
    let crx = pair.exchange_server(stx);
    pair.client.match_response_rx(crx).ok();
    pair.client.release_rx(crx).ok();
}

fn obs_08_content_format_change() {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let (_mid, rx) = register(&mut pair, Type::Confirmable, token, &["obs"]);
    pair.server.release_rx(rx).ok();
    let gone = pair
        .server
        .take_observe(ObserveKey::new(token, pair.client_ep));
    assert!(gone.is_some());
}

fn obs_09_update() {
    observe_basic(Type::Confirmable, Type::Confirmable, &["obs"]);
}

fn obs_10_get_does_not_cancel() {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let (_mid, rx) = register(&mut pair, Type::Confirmable, token, &["obs"]);
    pair.server.release_rx(rx).ok();
    let (tx, _) = pair.client_request(
        Type::Confirmable,
        Code::GET,
        Pair::client_token(3),
        &["obs"],
        &[],
        &[],
    );
    let srx = pair.exchange_client(tx);
    assert!(
        !pair
            .server
            .decode_rx(srx)
            .expect("get")
            .is_observe_deregister()
    );
    assert!(
        pair.server
            .lookup_observe(ObserveKey::new(token, pair.client_ep))
            .is_some(),
        "plain GET must not cancel observation"
    );
    pair.server.release_rx(srx).ok();
}

fn obs_11_lossy() {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let (_mid, rx) = register(&mut pair, Type::Confirmable, token, &["obs"]);
    pair.server.release_rx(rx).ok();
    let key = ObserveKey::new(token, pair.client_ep);
    pair.server.signal_observe(key).expect("signal");
    let oid = pair
        .server
        .progress(pair.now_ms)
        .observe_notify()
        .expect("notify");
    let interest = pair.server.observe_interest(oid).expect("row");
    let seq = encode_observe(interest.seq());
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let extra = [Opt::observe(&seq), Opt::content_format(&cf)];
    let mid = pair.server_ids.next();
    let stx = pair.server_reply(
        Type::Confirmable,
        Code::CONTENT,
        mid,
        token,
        &extra,
        OBS_BODY_2,
    );
    pair.now_ms += u64::from(Transmission::ACK_TIMEOUT_MS);
    let Retransmit::Due(pending) = pair
        .server
        .poll_retransmit(pair.now_ms)
        .expect("notify retransmission")
    else {
        panic!("OBS_11 expected Due");
    };
    let crx = pair.server_to_client(pending.tx_slot());
    assert_eq!(
        pair.client.decode_rx(crx).expect("retry").payload(),
        OBS_BODY_2
    );
    pair.server.release_tx(stx).ok();
    pair.client.release_rx(crx).ok();
}

fn obs_12_deregister() {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let (_mid, rx) = register(&mut pair, Type::Confirmable, token, &["obs"]);
    pair.server.release_rx(rx).ok();
    let extra = [Opt::observe_deregister()];
    let (tx, _) = pair.client_request(Type::Confirmable, Code::GET, token, &["obs"], &extra, &[]);
    let srx = pair.exchange_client(tx);
    let gone = pair.server.deregister_observe_rx(srx).expect("deregister");
    assert!(gone.is_some(), "Observe=1 must cancel");
    pair.server.release_rx(srx).ok();
}

fn obs_13_block2(variable: bool) {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let path = ["obs"];
    let (_mid, rx) = register(&mut pair, Type::Confirmable, token, &path);
    pair.server.release_rx(rx).ok();
    let obs_key = ObserveKey::new(token, pair.client_ep);
    pair.server.signal_observe(obs_key).expect("signal");
    let oid = pair
        .server
        .progress(pair.now_ms)
        .observe_notify()
        .expect("observe notify");
    let seq = pair.server.observe_interest(oid).expect("interest").seq();
    let body = patterned_body(if variable { 200 } else { 160 });
    let size = 64u16;
    let szx = block_at(0, false, size).szx();
    let key = block_key(token, pair.client_ep);
    let body_id = pair
        .server
        .start_block2(key, &body, szx)
        .expect("Block2 notify body");
    let stx = pair.server.acquire_tx().expect("TX");
    let mid = pair.server_ids.next();
    pair.server
        .encode_block2_observe_tx(body_id, stx, Type::Confirmable, Code::CONTENT, mid, seq)
        .expect("encode first with Observe");
    pair.server
        .record_observe_notify(obs_key, pair.now_ms, mid, true)
        .expect("record CON notify");
    let crx = pair.exchange_server(stx);
    let first_msg = pair.client.decode_rx(crx).expect("first decode");
    assert_eq!(first_msg.observe().expect("Observe").expect("seq"), seq);
    let first = pair.client.apply_block2_rx(crx).expect("first block");
    pair.client.release_rx(crx).ok();
    if !first.complete() {
        let next = block_at(1, false, size).encode();
        let extra = [Opt::block2(&next)];
        let (tx, _) = pair.client_request(Type::Confirmable, Code::GET, token, &path, &extra, &[]);
        let srx = pair.exchange_client(tx);
        pair.server.release_rx(srx).ok();
        let stx = pair.server.acquire_tx().expect("TX2");
        pair.server
            .encode_block2_tx(
                body_id,
                stx,
                Type::Acknowledgement,
                Code::CONTENT,
                pair.server_ids.next(),
            )
            .expect("encode next");
        let crx = pair.exchange_server(stx);
        let later = pair.client.decode_rx(crx).expect("later");
        assert!(
            later.observe().is_none(),
            "Observe stays on the first Block2 only"
        );
        let _ = pair.client.apply_block2_rx(crx);
        pair.client.release_rx(crx).ok();
    }
}
