//! Public-App ownership proofs before admitting pressure timing samples.
//!
//! These tests do not measure performance. Protected traffic, TX pressure,
//! cancellation and complete body continuations still need separate proofs.
use super::*;
use coaptic::storage::{SlotId, Storage};
use std::sync::atomic::{AtomicUsize, Ordering};

static HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

fn counted_representation(_: Request<'_>) -> Response<'static> {
    HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
    Response::content(&SMALL_BODY)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"fixture")
}

#[test]
fn rx_credit_survives_incoming_refusal_and_collection_recovers_unprotected() {
    HANDLER_CALLS.store(0, Ordering::SeqCst);
    let mut app = App::with_resources(coaptic::resources::SmallDevice::new())
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .full_responses()
        .route("bench", get(counted_representation))
        .allow_unprotected()
        .bind(core_io())
        .unwrap();
    assert_eq!(app.engine_mut().capacities().rx_datagram_slots, 2);
    assert_eq!(app.engine_mut().capacities().tx_datagram_slots, 2);

    // A real outbound call receives a complete response. Collection, rather
    // than a bare pool acquisition, is what owns the retained RX reservation.
    let call = app.get("retained").to(PEER).send(0).unwrap();
    let (call_mid, call_token) = {
        let io = app.transport_mut();
        let n = io.output_len.take().unwrap();
        let request = decode(&io.output[..n]).unwrap();
        assert_eq!(request.code(), Code::GET);
        (request.message_id(), request.token())
    };
    let response = Message::new(Type::Acknowledgement, Code::CONTENT, call_mid)
        .with_token(call_token)
        .with_payload(b"retained-response");
    let io = app.transport_mut();
    io.input_len = Some(response.encode(&mut io.input).unwrap());
    app.poll(1).unwrap();
    assert_eq!(app.engine_mut().rx_occupied(), 1);
    assert_eq!(app.engine_mut().tx_occupied(), 0);
    assert!(app.transport().output_len.is_none());
    let (held, held_pin) = {
        let pool = app.engine_mut().storage_mut().rx_datagram();
        assert_eq!(pool.occupied_count(), 1);
        let a = SlotId::from_index(0);
        let b = SlotId::from_index(1);
        assert_ne!(pool.is_occupied(a), pool.is_occupied(b));
        let id = if pool.is_occupied(a) { a } else { b };
        (id, pool.is_pinned(id))
    };
    let before = app.metrics();

    let mid = MessageId::new(40_000);
    let token = Token::new(&40_000_u64.to_be_bytes()).unwrap();
    let options = [Opt::uri_path("bench")];
    let request = Message::con(Code::GET, mid, token).with_options(&options);
    let io = app.transport_mut();
    io.input_len = Some(request.encode(&mut io.input).unwrap());
    // This is the incoming server poll absent from the core outbound-call test.
    app.poll(2).unwrap();
    assert!(app.transport().input_len.is_none());
    let io = app.transport_mut();
    let n = io.output_len.take().unwrap();
    let refusal = decode(&io.output[..n]).unwrap();
    assert_eq!(refusal.ty(), Type::Acknowledgement);
    assert_eq!(refusal.message_id(), mid);
    assert_eq!(refusal.token(), token);
    assert_eq!(refusal.code(), Code::SERVICE_UNAVAILABLE);
    assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(
        app.metrics().admission_rx_refused,
        before.admission_rx_refused + 1
    );
    assert_eq!(
        app.metrics().admission_tx_refused,
        before.admission_tx_refused
    );
    {
        let pool = app.engine_mut().storage_mut().rx_datagram();
        assert_eq!(pool.occupied_count(), 1);
        assert!(pool.is_occupied(held));
        assert_eq!(pool.is_pinned(held), held_pin);
    }

    let mut collected = [0; 32];
    let retained = app
        .take_response_into(call, &mut collected)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(retained.message_id(), Some(call_mid));
    assert_eq!(retained.token(), Some(call_token));
    assert_eq!(retained.code(), Code::CONTENT);
    assert_eq!(retained.payload(), b"retained-response");
    assert_eq!(app.engine_mut().rx_occupied(), 0);
    assert!(
        !app.engine_mut()
            .storage_mut()
            .rx_datagram()
            .is_occupied(held)
    );
    assert!(
        app.take_response_into(call, &mut collected)
            .unwrap()
            .is_none()
    );

    // A different MID/token proves fresh admission rather than cached replay.
    let mid = MessageId::new(40_001);
    let token = Token::new(&40_001_u64.to_be_bytes()).unwrap();
    let request = Message::con(Code::GET, mid, token).with_options(&options);
    let io = app.transport_mut();
    io.input_len = Some(request.encode(&mut io.input).unwrap());
    app.poll(3).unwrap();
    let io = app.transport_mut();
    let n = io.output_len.take().unwrap();
    verify_reply(&decode(&io.output[..n]).unwrap(), mid, token, &SMALL_BODY).unwrap();
    assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(app.engine_mut().rx_occupied(), 0);
    assert_eq!(
        app.metrics().admission_rx_refused,
        before.admission_rx_refused + 1
    );
}
