//! Public-App ownership proofs before admitting pressure timing samples.
//!
//! These tests do not measure performance. The TX refusal/recovery proofs below
//! are UNRUN pending qualification against both pinned admission arms. Protected
//! RX pressure, Observe cancellation and complete Block2 remain future work;
//! these cases do not establish completion of Stage B.
use super::*;
use coaptic::storage::Storage;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

static HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

fn counted_representation(_: Request<'_>) -> Response<'static> {
    HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
    Response::content(&SMALL_BODY)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"fixture")
}

#[test]
fn rx_credit_survives_incoming_refusal_and_collection_recovers_unprotected() {
    let _guard = FIXTURE_LOCK.lock().unwrap();
    HANDLER_CALLS.store(0, Ordering::SeqCst);
    // The resource-based builder already retains complete client responses.
    let mut app = App::with_resources(coaptic::resources::SmallDevice::new())
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .route("bench", get(counted_representation))
        .allow_unprotected()
        .bind(core_io())
        .unwrap();
    assert_eq!(app.engine_mut().capacities().rx_datagram_slots, 2);
    assert_eq!(app.engine_mut().capacities().tx_datagram_slots, 2);

    // Inventory genuine public pool addresses, returning every reservation
    // before protocol work. Released IDs confer no ownership across reuse:
    // below they are read-only locators, rebound to the actual retained reply.
    let rx_ids = {
        let pool = app.engine_mut().storage_mut().rx_datagram();
        assert_eq!(pool.occupied_count(), 0);
        let cursor = pool.cursor();
        let a = pool.acquire().unwrap();
        let b = pool.acquire().unwrap();
        assert_ne!(a, b);
        assert_eq!(pool.occupied_count(), 2);
        pool.release(a).unwrap();
        pool.release(b).unwrap();
        assert_eq!(pool.occupied_count(), 0);
        assert_eq!(pool.cursor(), cursor);
        [a, b]
    };

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
        let [a, b] = rx_ids;
        assert_ne!(pool.is_occupied(a), pool.is_occupied(b));
        let id = if pool.is_occupied(a) { a } else { b };
        (id, pool.is_pinned(id))
    };
    {
        let reply = app.engine_mut().decode_rx(held).unwrap();
        assert_eq!(reply.message_id(), call_mid);
        assert_eq!(reply.token(), call_token);
        assert_eq!(reply.code(), Code::CONTENT);
        assert_eq!(reply.payload(), b"retained-response");
    }
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
    {
        let reply = app.engine_mut().decode_rx(held).unwrap();
        assert_eq!(reply.message_id(), call_mid);
        assert_eq!(reply.token(), call_token);
        assert_eq!(reply.code(), Code::CONTENT);
        assert_eq!(reply.payload(), b"retained-response");
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

#[test]
fn tx_credit_survives_refusal_and_release_recovers_unprotected() {
    let _guard = FIXTURE_LOCK.lock().unwrap();
    tx_credit_survives_refusal_and_release_recovers(false);
}

#[test]
fn tx_credit_survives_refusal_and_release_recovers_oscore() {
    let _guard = FIXTURE_LOCK.lock().unwrap();
    tx_credit_survives_refusal_and_release_recovers(true);
}

fn tx_credit_survives_refusal_and_release_recovers(protected: bool) {
    HANDLER_CALLS.store(0, Ordering::SeqCst);
    let derive = |sender_id, recipient_id| {
        coaptic::oscore::SecurityContext::derive(coaptic::oscore::DeriveParams {
            master_secret: &[0x37; 16],
            master_salt: &[0x51; 8],
            sender_id,
            recipient_id,
            id_context: &[],
        })
        .unwrap()
    };
    let resources = coaptic::resources::SmallDevice::new();
    assert_eq!(resources.route_capacity(), 4);
    assert_eq!(resources.client_capacity(), 1);
    assert_eq!(resources.deferred_capacity(), 0);
    assert_eq!(resources.association_capacity(), 1);
    assert_eq!(resources.security_request_capacity(), 4);
    let builder = App::with_resources(resources)
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .route("bench", get(counted_representation));
    let (builder, mut client) = if protected {
        (builder.oscore(derive(&[1], &[])), Some(derive(&[], &[1])))
    } else {
        (builder.allow_unprotected(), None)
    };
    let mut app = builder.bind(core_io()).unwrap();
    let capacities = app.engine_mut().capacities();
    assert_eq!(capacities.rx_datagram_slots, 2);
    assert_eq!(capacities.tx_datagram_slots, 2);
    assert_eq!(capacities.rx_body_slots, None);
    assert_eq!(capacities.tx_body_slots, None);
    assert_eq!(capacities.rx_body_bytes, None);
    assert_eq!(capacities.tx_body_bytes, None);
    assert_eq!(SMALL_BODY.len(), 32);
    assert_eq!(app.engine_mut().rx_occupied(), 0);
    assert_eq!(app.engine_mut().tx_occupied(), 0);
    assert_eq!(app.engine_mut().storage_mut().dedup().occupied_count(), 0);
    assert!(app.transport().input_len.is_none());
    assert!(app.transport().output_len.is_none());

    // This reservation is fixture-owned, with no pending CON or cached reply
    // owning it. Encoding a sentinel does not enqueue a transmission. Its bytes
    // and endpoint let us detect theft/reuse as well as a lost occupancy bit.
    let held = app.engine_mut().acquire_tx().unwrap();
    let sentinel_mid = MessageId::new(39_999);
    let sentinel_token = Token::new(b"held").unwrap();
    let sentinel = Message::new(Type::NonConfirmable, Code::CONTENT, sentinel_mid)
        .with_token(sentinel_token)
        .with_payload(b"fixture-owned-tx");
    app.engine_mut().encode_tx(held, &sentinel).unwrap();
    app.engine_mut().set_tx_endpoint(held, PEER).unwrap();
    let held_pin = app.engine_mut().tx_is_pinned(held);
    assert!(!held_pin); // No Access guard may span a mutable App poll.
    assert!(app.engine_mut().pending_con(held).is_none());
    assert_eq!(app.engine_mut().tx_occupied(), 1);
    assert_eq!(
        capacities.tx_datagram_slots - app.engine_mut().tx_occupied(),
        1
    );
    assert!(app.transport().output_len.is_none());
    app.poll(0).unwrap();
    assert!(app.transport().output_len.is_none());
    assert_eq!(app.engine_mut().tx_occupied(), 1);
    assert_eq!(app.engine_mut().storage_mut().dedup().occupied_count(), 0);
    let before = app.metrics();

    let options = [Opt::uri_path("bench")];
    let mid = MessageId::new(41_000);
    let token = Token::new(&41_000_u64.to_be_bytes()).unwrap();
    let request = Message::con(Code::GET, mid, token).with_options(&options);
    let io = app.transport_mut();
    io.input_len = Some(match client.as_mut() {
        Some(context) => context.protect_request(&request, &mut io.input).unwrap(),
        None => request.encode(&mut io.input).unwrap(),
    });
    app.poll(1).unwrap();
    assert!(app.transport().input_len.is_none());
    let mut opened = [0; WIRE];
    {
        let io = app.transport_mut();
        let n = io.output_len.take().unwrap();
        let wire = decode(&io.output[..n]).unwrap();
        assert_eq!(wire.ty(), Type::Acknowledgement);
        assert_eq!(wire.message_id(), mid);
        assert_eq!(wire.token(), token);
        let refusal = match client.as_mut() {
            Some(context) => {
                let binding = context.take(token).unwrap();
                context
                    .unprotect_response(&wire, binding, &mut opened)
                    .unwrap()
            }
            None => wire,
        };
        assert_eq!(refusal.ty(), Type::Acknowledgement);
        assert_eq!(refusal.message_id(), mid);
        assert_eq!(refusal.token(), token);
        assert_eq!(refusal.code(), Code::SERVICE_UNAVAILABLE);
    }
    assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(
        app.metrics().admission_tx_refused,
        before.admission_tx_refused + 1
    );
    assert_eq!(
        app.metrics().admission_rx_refused,
        before.admission_rx_refused
    );
    assert_eq!(
        app.metrics().admission_refusal_sent,
        before.admission_refusal_sent + 1
    );
    assert_eq!(
        app.metrics().admission_refusal_unsent,
        before.admission_refusal_unsent
    );
    assert_eq!(app.engine_mut().rx_occupied(), 0);
    assert_eq!(app.engine_mut().tx_occupied(), 1);
    assert_eq!(
        capacities.tx_datagram_slots - app.engine_mut().tx_occupied(),
        1
    );
    {
        let pool = app.engine_mut().storage_mut().tx_datagram();
        assert!(pool.is_occupied(held));
        assert_eq!(pool.is_pinned(held), held_pin);
    }
    assert!(app.engine_mut().pending_con(held).is_none());
    assert_eq!(app.engine_mut().tx_endpoint(held), Some(PEER));
    {
        let retained = app.engine_mut().decode_tx(held).unwrap();
        assert_eq!(retained.ty(), Type::NonConfirmable);
        assert_eq!(retained.code(), Code::CONTENT);
        assert_eq!(retained.message_id(), sentinel_mid);
        assert_eq!(retained.token(), sentinel_token);
        assert_eq!(retained.payload(), b"fixture-owned-tx");
    }
    // The sole new row is the inline refusal replay. It cannot own the held
    // slot or hide an eviction that supplied the control response's credit.
    assert_eq!(app.engine_mut().storage_mut().dedup().occupied_count(), 1);
    let row = app
        .engine_mut()
        .lookup_dedup(coaptic::storage::DedupKey::new(mid, PEER))
        .unwrap();
    assert!(
        app.engine_mut()
            .dedup_entry(row)
            .unwrap()
            .tx_pin()
            .is_none()
    );
    assert!(app.transport().output_len.is_none());

    // Release only the genuine fixture reservation, exactly once. No crypto,
    // dedup history, protocol state or sequence numbers are reset for recovery.
    app.engine_mut().release_tx(held).unwrap();
    assert!(
        !app.engine_mut()
            .storage_mut()
            .tx_datagram()
            .is_occupied(held)
    );
    assert!(!app.engine_mut().tx_is_pinned(held));
    assert_eq!(app.engine_mut().tx_occupied(), 0);
    assert_eq!(
        capacities.tx_datagram_slots - app.engine_mut().tx_occupied(),
        2
    );
    let recovered_mid = MessageId::new(41_001);
    let recovered_token = Token::new(&41_001_u64.to_be_bytes()).unwrap();
    let request = Message::con(Code::GET, recovered_mid, recovered_token).with_options(&options);
    let io = app.transport_mut();
    io.input_len = Some(match client.as_mut() {
        Some(context) => context.protect_request(&request, &mut io.input).unwrap(),
        None => request.encode(&mut io.input).unwrap(),
    });
    app.poll(2).unwrap();
    assert!(app.transport().input_len.is_none());
    {
        let io = app.transport_mut();
        let n = io.output_len.take().unwrap();
        let wire = decode(&io.output[..n]).unwrap();
        assert_eq!(wire.ty(), Type::Acknowledgement);
        assert_eq!(wire.message_id(), recovered_mid);
        assert_eq!(wire.token(), recovered_token);
        let reply = match client.as_mut() {
            Some(context) => {
                let binding = context.take(recovered_token).unwrap();
                context
                    .unprotect_response(&wire, binding, &mut opened)
                    .unwrap()
            }
            None => wire,
        };
        verify_reply(&reply, recovered_mid, recovered_token, &SMALL_BODY).unwrap();
    }
    assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(app.engine_mut().rx_occupied(), 0);
    assert_eq!(
        app.metrics().admission_tx_refused,
        before.admission_tx_refused + 1
    );
    assert_eq!(
        app.metrics().admission_rx_refused,
        before.admission_rx_refused
    );
    assert_eq!(
        app.metrics().admission_refusal_sent,
        before.admission_refusal_sent + 1
    );
    assert_eq!(
        app.metrics().admission_refusal_unsent,
        before.admission_refusal_unsent
    );
    assert!(app.transport().output_len.is_none());
}
