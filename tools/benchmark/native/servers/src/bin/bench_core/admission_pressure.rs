//! Public-App ownership proofs before admitting pressure timing samples.
//!
//! These tests do not measure performance. The original four RX/TX cases passed
//! both pinned arms at C5 in run 41129635329/1. The two Observe cancellation
//! and two notification-backed Block2 cases are UNRUN. Ordinary borrowed Block2
//! selects directly from handler bytes; the new cases explicitly use App.notify
//! snapshot ownership after a real Observe registration.
//! Stage B pressure / continuation timing qualification remains outstanding.
use super::*;
use coaptic::storage::Storage;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

static HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

fn fixture_lock() -> std::sync::MutexGuard<'static, ()> {
    // Only the counter is shared; every case resets it and creates a fresh App.
    // Preserve an earlier test's failure without masking later cases as poison.
    FIXTURE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

fn counted_representation(_: Request<'_>) -> Response<'static> {
    HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
    Response::content(&SMALL_BODY)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"fixture")
}

#[test]
fn rx_credit_survives_incoming_refusal_and_collection_recovers_unprotected() {
    let _guard = fixture_lock();
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
fn rx_credit_survives_incoming_refusal_and_collection_recovers_oscore() {
    let _guard = fixture_lock();
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
    // One context pair serves both directions throughout, including recovery.
    let mut peer = derive(&[], &[1]);
    let resources = coaptic::resources::SmallDevice::new();
    assert_eq!(resources.route_capacity(), 4);
    assert_eq!(resources.client_capacity(), 1);
    assert_eq!(resources.deferred_capacity(), 0);
    assert_eq!(resources.association_capacity(), 1);
    assert_eq!(resources.security_request_capacity(), 4);
    let mut app = App::with_resources(resources)
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .route("bench", get(counted_representation))
        .oscore(derive(&[1], &[]))
        .bind(core_io())
        .unwrap();
    let capacities = app.engine_mut().capacities();
    assert_eq!(capacities.rx_datagram_slots, 2);
    assert_eq!(capacities.tx_datagram_slots, 2);
    assert_eq!(capacities.rx_body_slots, None);
    assert_eq!(capacities.tx_body_slots, None);
    assert_eq!(capacities.rx_body_bytes, None);
    assert_eq!(capacities.tx_body_bytes, None);
    assert_eq!(SMALL_BODY.len(), 32);
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
    // Scratch is reused for peer authentication and the retained-byte snapshot.
    let mut scratch = [0; WIRE];
    let call = app.get("retained").to(PEER).send(0).unwrap();
    let (call_mid, call_token) = {
        let io = app.transport_mut();
        let n = io.output_len.take().unwrap();
        let wire = decode(&io.output[..n]).unwrap();
        assert!(wire.oscore().is_some());
        let (request, binding) = peer.unprotect_request(&wire, &mut scratch).unwrap();
        assert_eq!(request.code(), Code::GET);
        let mid = request.message_id();
        let token = request.token();
        let response = Message::new(Type::Acknowledgement, Code::CONTENT, mid)
            .with_token(token)
            .with_payload(b"retained-response");
        io.input_len = Some(
            peer.protect_response(&response, binding, &mut io.input)
                .unwrap(),
        );
        (mid, token)
    };
    app.poll(1).unwrap();
    assert!(app.transport().input_len.is_none());
    assert!(app.transport().output_len.is_none());
    assert_eq!(app.engine_mut().rx_occupied(), 1);
    assert_eq!(app.engine_mut().tx_occupied(), 0);
    let (held, held_pin) = {
        let pool = app.engine_mut().storage_mut().rx_datagram();
        assert_eq!(pool.occupied_count(), 1);
        let [a, b] = rx_ids;
        assert_ne!(pool.is_occupied(a), pool.is_occupied(b));
        let id = if pool.is_occupied(a) { a } else { b };
        (id, pool.is_pinned(id))
    };
    assert!(!held_pin);
    assert_eq!(app.engine_mut().rx_endpoint(held), Some(PEER));
    {
        // Rebind inventoried locators to the actual authenticated Call reply.
        // The pinned App writes opened Inner bytes over the received packet.
        let reply = app.engine_mut().decode_rx(held).unwrap();
        assert_eq!(reply.message_id(), call_mid);
        assert_eq!(reply.token(), call_token);
        assert_eq!(reply.ty(), Type::Acknowledgement);
        assert_eq!(reply.code(), Code::CONTENT);
        assert_eq!(reply.payload(), b"retained-response");
    }
    let held_len = {
        let bytes = app.engine_mut().access_rx(held).unwrap();
        scratch[..bytes.len()].copy_from_slice(&bytes);
        bytes.len()
    }; // Drop the pin before polling; snapshot actual post-authentication bytes.
    let before = app.metrics();
    let options = [Opt::uri_path("bench")];
    let mid = MessageId::new(if call_mid == MessageId::new(42_000) {
        42_001
    } else {
        42_000
    });
    let token = if call_token == Token::new(b"rx-busy").unwrap() {
        Token::new(b"rx-other").unwrap()
    } else {
        Token::new(b"rx-busy").unwrap()
    };
    assert_ne!(mid, call_mid);
    assert_ne!(token, call_token);
    let request = Message::con(Code::GET, mid, token).with_options(&options);
    let io = app.transport_mut();
    io.input_len = Some(peer.protect_request(&request, &mut io.input).unwrap());
    app.poll(2).unwrap();
    assert!(app.transport().input_len.is_none());
    assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(
        app.metrics().admission_rx_refused,
        before.admission_rx_refused + 1
    );
    assert_eq!(
        app.metrics().admission_tx_refused,
        before.admission_tx_refused
    );
    assert_eq!(
        app.metrics().admission_refusal_sent,
        before.admission_refusal_sent + 1
    );
    assert_eq!(
        app.metrics().admission_refusal_unsent,
        before.admission_refusal_unsent
    );
    assert_eq!(app.engine_mut().rx_occupied(), 1);
    assert_eq!(app.engine_mut().tx_occupied(), 0);
    {
        let pool = app.engine_mut().storage_mut().rx_datagram();
        assert_eq!(pool.occupied_count(), 1);
        assert!(pool.is_occupied(held));
        assert_eq!(pool.is_pinned(held), held_pin);
    }
    assert_eq!(app.engine_mut().rx_endpoint(held), Some(PEER));
    {
        let bytes = app.engine_mut().access_rx(held).unwrap();
        assert_eq!(&*bytes, &scratch[..held_len]);
        let reply = decode(&bytes).unwrap();
        assert_eq!(reply.message_id(), call_mid);
        assert_eq!(reply.token(), call_token);
        assert_eq!(reply.code(), Code::CONTENT);
        assert_eq!(reply.payload(), b"retained-response");
    }
    // Snapshot verified; reuse its scratch to authenticate the actual refusal.
    {
        let io = app.transport_mut();
        let n = io.output_len.take().unwrap();
        let wire = decode(&io.output[..n]).unwrap();
        assert!(wire.oscore().is_some());
        let binding = peer.take(token).unwrap();
        let refusal = peer
            .unprotect_response(&wire, binding, &mut scratch)
            .unwrap();
        assert_eq!(refusal.ty(), Type::Acknowledgement);
        assert_eq!(refusal.message_id(), mid);
        assert_eq!(refusal.token(), token);
        assert_eq!(refusal.code(), Code::SERVICE_UNAVAILABLE);
    }
    assert!(app.transport().output_len.is_none());
    let retained = app
        .take_response_into(call, &mut scratch)
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
    assert!(!app.engine_mut().rx_is_pinned(held));
    assert!(
        app.take_response_into(call, &mut scratch)
            .unwrap()
            .is_none()
    );

    // Fresh MID, token and sender sequence under the continuous peer context.
    let recovered_mid = MessageId::new(if call_mid == MessageId::new(42_002) {
        42_003
    } else {
        42_002
    });
    let recovered_token = if call_token == Token::new(b"rx-fresh").unwrap() {
        Token::new(b"rx-next").unwrap()
    } else {
        Token::new(b"rx-fresh").unwrap()
    };
    assert_ne!(recovered_mid, call_mid);
    assert_ne!(recovered_mid, mid);
    assert_ne!(recovered_token, call_token);
    assert_ne!(recovered_token, token);
    let request = Message::con(Code::GET, recovered_mid, recovered_token).with_options(&options);
    let io = app.transport_mut();
    io.input_len = Some(peer.protect_request(&request, &mut io.input).unwrap());
    app.poll(3).unwrap();
    assert!(app.transport().input_len.is_none());
    {
        let io = app.transport_mut();
        let n = io.output_len.take().unwrap();
        let wire = decode(&io.output[..n]).unwrap();
        assert!(wire.oscore().is_some());
        let binding = peer.take(recovered_token).unwrap();
        let reply = peer
            .unprotect_response(&wire, binding, &mut scratch)
            .unwrap();
        verify_reply(&reply, recovered_mid, recovered_token, &SMALL_BODY).unwrap();
    }
    assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(app.engine_mut().rx_occupied(), 0);
    assert_eq!(
        app.metrics().admission_rx_refused,
        before.admission_rx_refused + 1
    );
    assert_eq!(
        app.metrics().admission_tx_refused,
        before.admission_tx_refused
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

#[test]
fn tx_credit_survives_refusal_and_release_recovers_unprotected() {
    let _guard = fixture_lock();
    tx_credit_survives_refusal_and_release_recovers(false);
}

#[test]
fn tx_credit_survives_refusal_and_release_recovers_oscore() {
    let _guard = fixture_lock();
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

fn counted_observe_representation(_: Request<'_>) -> Response<'static> {
    HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
    Response::content(&SMALL_BODY)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"fixture")
        .observe(0)
}

#[test]
fn observe_cancel_under_tx_pressure_releases_relation_and_recovers_unprotected() {
    let _guard = fixture_lock();
    observe_cancel_under_tx_pressure_releases_relation_and_recovers(false);
}

#[test]
fn observe_cancel_under_tx_pressure_releases_relation_and_recovers_oscore() {
    let _guard = fixture_lock();
    observe_cancel_under_tx_pressure_releases_relation_and_recovers(true);
}

fn observe_cancel_under_tx_pressure_releases_relation_and_recovers(protected: bool) {
    // Both wrappers hold FIXTURE_LOCK; this helper must not lock again.
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
        .route("bench", get(counted_observe_representation));
    let (builder, mut peer) = if protected {
        (builder.oscore(derive(&[1], &[])), Some(derive(&[], &[1])))
    } else {
        (builder.allow_unprotected(), None)
    };
    let mut app = builder.bind(core_io()).unwrap();
    let capacities = app.engine_mut().capacities();
    assert_eq!(capacities.rx_datagram_slots, 2);
    assert_eq!(capacities.tx_datagram_slots, 2);
    assert_eq!(capacities.observe_entries, 2);
    assert_eq!(capacities.rx_body_slots, None);
    assert_eq!(capacities.tx_body_slots, None);
    assert_eq!(capacities.rx_body_bytes, None);
    assert_eq!(capacities.tx_body_bytes, None);
    assert_eq!(SMALL_BODY.len(), 32);
    // Test-only scratch/snapshot buffers are separate from App storage.
    // No access guard or pin spans a mutable poll.
    let mut opened = [0; WIRE];
    let mut sentinel_bytes = [0; WIRE];
    // Fixed security_capacity + 1 cycles exercise binding/row reclamation.
    // Fifteen request/response exchanges (30 internal datagrams), distinct
    // MIDs/tokens, monotonic virtual polls 1..=15.
    // One continuous context pair; no history, key, sequence or table resets.
    for cycle in 0..5_u16 {
        let base = 44_000 + cycle * 3;
        let token = Token::new(&u64::from(base).to_be_bytes()).unwrap();
        let key = coaptic::storage::ObserveKey::new(token, PEER);
        // Each cycle registers, cancels under pressure, then recovers via GET.
        let mut held = None;
        let mut held_len = 0;
        let mut before = app.metrics();
        for phase in 0..3_u16 {
            let mid = MessageId::new(base + phase);
            let request_token = if phase == 2 {
                Token::new(&u64::from(base + 2).to_be_bytes()).unwrap()
            } else {
                token
            };
            let observe_options = [
                if phase == 0 {
                    Opt::observe_register()
                } else {
                    Opt::observe_deregister()
                },
                Opt::uri_path("bench"),
            ];
            let ordinary_options = [Opt::uri_path("bench")];
            let options = if phase == 2 {
                &ordinary_options[..]
            } else {
                &observe_options[..]
            };
            let request = Message::con(Code::GET, mid, request_token).with_options(options);
            let io = app.transport_mut();
            io.input_len = Some(match peer.as_mut() {
                Some(context) => context.protect_request(&request, &mut io.input).unwrap(),
                None => request.encode(&mut io.input).unwrap(),
            });
            app.poll(u64::from(cycle * 3 + phase + 1)).unwrap();
            assert!(app.transport().input_len.is_none());
            {
                let io = app.transport_mut();
                let n = io.output_len.take().unwrap();
                let wire = decode(&io.output[..n]).unwrap();
                assert_eq!(wire.oscore().is_some(), protected);
                let reply = match peer.as_mut() {
                    Some(context) => {
                        let binding = context.take(request_token).unwrap();
                        context
                            .unprotect_response(&wire, binding, &mut opened)
                            .unwrap()
                    }
                    None => wire,
                };
                assert_eq!(reply.ty(), Type::Acknowledgement);
                assert_eq!(reply.message_id(), mid);
                assert_eq!(reply.token(), request_token);
                if phase == 1 {
                    assert_eq!(reply.code(), Code::SERVICE_UNAVAILABLE);
                    assert!(reply.observe().is_none());
                } else {
                    verify_reply(&reply, mid, request_token, &SMALL_BODY).unwrap();
                    assert_eq!(reply.observe(), if phase == 0 { Some(Ok(0)) } else { None });
                }
            }
            assert_eq!(app.engine_mut().rx_occupied(), 0);
            assert!(app.transport().output_len.is_none());
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
            assert_eq!(
                HANDLER_CALLS.load(Ordering::SeqCst),
                usize::from(cycle) * 2 + if phase == 2 { 2 } else { 1 }
            );
            if phase == 0 {
                let relation = app.engine_mut().lookup_observe(key).unwrap();
                let interest = app.engine_mut().observe_interest(relation).unwrap();
                assert_eq!(interest.key(), key);
                assert!(!interest.resource().is_none());
                assert_eq!(interest.content_format(), Some(ContentFormat::OCTET_STREAM));
                assert_eq!(interest.seq(), 0);
                assert_eq!(app.engine_mut().storage_mut().observe().occupied_count(), 1);
                // No initial cache pin can be evicted to manufacture TX credit.
                assert_eq!(app.engine_mut().tx_occupied(), 0);
                let id = app.engine_mut().acquire_tx().unwrap();
                let sentinel =
                    Message::new(Type::NonConfirmable, Code::CONTENT, MessageId::new(43_999))
                        .with_token(Token::new(b"held").unwrap())
                        .with_payload(b"fixture-owned-tx");
                app.engine_mut().encode_tx(id, &sentinel).unwrap();
                app.engine_mut().set_tx_endpoint(id, PEER).unwrap();
                held_len = {
                    let bytes = app.engine_mut().access_tx(id).unwrap();
                    sentinel_bytes[..bytes.len()].copy_from_slice(&bytes);
                    bytes.len()
                };
                assert!(!app.engine_mut().tx_is_pinned(id));
                assert!(app.engine_mut().pending_con(id).is_none());
                assert_eq!(app.engine_mut().tx_occupied(), 1);
                held = Some(id);
                before = app.metrics();
            } else {
                assert!(app.engine_mut().lookup_observe(key).is_none());
                assert_eq!(app.engine_mut().storage_mut().observe().occupied_count(), 0);
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
                if phase == 1 {
                    let id = held.take().unwrap();
                    assert_eq!(app.engine_mut().tx_occupied(), 1);
                    assert!(app.engine_mut().storage_mut().tx_datagram().is_occupied(id));
                    assert!(!app.engine_mut().tx_is_pinned(id));
                    assert!(app.engine_mut().pending_con(id).is_none());
                    assert_eq!(app.engine_mut().tx_endpoint(id), Some(PEER));
                    {
                        let bytes = app.engine_mut().access_tx(id).unwrap();
                        assert_eq!(&*bytes, &sentinel_bytes[..held_len]);
                    }
                    // Only the fixture's reservation is released, exactly once.
                    app.engine_mut().release_tx(id).unwrap();
                    assert!(!app.engine_mut().storage_mut().tx_datagram().is_occupied(id));
                    assert!(!app.engine_mut().tx_is_pinned(id));
                }
                assert_eq!(app.engine_mut().tx_occupied(), 0);
            }
        }
        assert!(held.is_none());
    }
    assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 10);
    assert_eq!(app.metrics().admission_tx_refused, 5);
    assert_eq!(app.metrics().admission_rx_refused, 0);
    assert_eq!(app.metrics().admission_refusal_sent, 5);
    assert_eq!(app.metrics().admission_refusal_unsent, 0);
}

// Test-only nonuniform representation: equal-sized blocks cannot hide an offset
// error. Production BODY and default_app remain unchanged.
const NOTIFICATION_BODY: [u8; 64] =
    *b"0123456789abcdefABCDEFGHIJKLMNOPqrstuvwxyz#$%^&*ZYXWVUTSRQPONMLK";

fn counted_notification_representation(_: Request<'_>) -> Response<'static> {
    HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
    notification_representation().observe(0)
}

fn notification_representation() -> Response<'static> {
    Response::content(&NOTIFICATION_BODY)
        .content_format(ContentFormat::OCTET_STREAM)
        .etag(b"notify64")
}

#[test]
fn block2_notification_under_rx_pressure_preserves_body_and_completes_unprotected() {
    let _guard = fixture_lock();
    block2_notification_under_rx_pressure_preserves_body_and_completes(false);
}

#[test]
fn block2_notification_under_rx_pressure_preserves_body_and_completes_oscore() {
    let _guard = fixture_lock();
    block2_notification_under_rx_pressure_preserves_body_and_completes(true);
}

fn block2_notification_under_rx_pressure_preserves_body_and_completes(protected: bool) {
    use coaptic::storage::SlotId;
    // Wrappers own FIXTURE_LOCK. One continuous security pair serves both
    // directions, notification, downloads and recovery; no resets or rebinding.
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
    // Explicit test-only client retention option, with the production default
    // allocated capacities: route1, Calls4, deferred0, association1/security4,
    // RX/TX4x1472, dedup8, Observe4, RXbody1x1024, TXbody2x1024.
    // The two body slots permit snapshot replacement. Pool sidecars belong to
    // these capacities, not additional payload buffers. Extra fixture scratch:
    // one WIRE auth buffer, one 128B postponed wire reply, three 128B exact RX
    // snapshots plus lengths/IDs/metadata, one copied BlockTransfer sidecar,
    // 64B assembly and 32B collection.
    // This is neither a whole-memory nor a stack measurement.
    let builder = App::builder()
        .full_responses()
        .routes::<1>()
        .block_wise::<true>()
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .route("bench", get(counted_notification_representation));
    let (builder, mut peer) = if protected {
        (builder.oscore(derive(&[1], &[])), Some(derive(&[], &[1])))
    } else {
        (builder.allow_unprotected(), None)
    };
    let mut app = builder
        .bind_alloc(
            core_io(),
            Capacities {
                rx_datagram_slots: 4,
                rx_datagram_bytes: 1472,
                tx_datagram_slots: 4,
                tx_datagram_bytes: 1472,
                dedup_entries: 8,
                observe_entries: 4,
                rx_body_slots: Some(1),
                rx_body_bytes: Some(1024),
                tx_body_slots: Some(2),
                tx_body_bytes: Some(1024),
            },
        )
        .unwrap();
    let capacities = app.engine_mut().capacities();
    assert_eq!(capacities.rx_datagram_slots, 4);
    assert_eq!(capacities.tx_datagram_slots, 4);
    assert_eq!(capacities.rx_body_slots, Some(1));
    assert_eq!(capacities.tx_body_slots, Some(2));
    assert_eq!(capacities.rx_body_bytes, Some(1024));
    assert_eq!(capacities.tx_body_bytes, Some(1024));
    assert_eq!(capacities.dedup_entries, 8);
    assert_eq!(capacities.observe_entries, 4);
    // Public inventory only; every temporary reservation is returned before
    // protocol work. IDs below are locators, rebound to actual App-owned bytes.
    let rx_ids = {
        let pool = app.engine_mut().storage_mut().rx_datagram();
        assert_eq!(pool.occupied_count(), 0);
        let cursor = pool.cursor();
        let ids: [SlotId; 4] = std::array::from_fn(|_| pool.acquire().unwrap());
        for id in ids {
            pool.release(id).unwrap();
        }
        assert_eq!(pool.occupied_count(), 0);
        assert_eq!(pool.cursor(), cursor);
        ids
    };
    let body_ids = {
        let pool = app.engine_mut().storage_mut().tx_body().unwrap();
        assert_eq!(pool.occupied_count(), 0);
        let cursor = pool.cursor();
        let ids: [SlotId; 2] = std::array::from_fn(|_| pool.acquire().unwrap());
        for id in ids {
            pool.release(id).unwrap();
        }
        assert_eq!(pool.occupied_count(), 0);
        assert_eq!(pool.cursor(), cursor);
        ids
    };
    let mut opened = [0; WIRE];
    let mut postponed = [0; 128];
    let mut postponed_len = 0;
    let mut calls = [None; 3];
    let mut mids = [MessageId::new(0); 3];
    let mut tokens = [Token::EMPTY; 3];
    let mut held = [None; 3];
    let mut snapshots = [[0; 128]; 3];
    let mut lengths = [0; 3];
    let payloads: [&[u8]; 3] = [b"retained-one", b"retained-two", b"retained-three"];
    macro_rules! bind_reply {
        ($i:expr) => {{
            let i = $i;
            let mut found = rx_ids.into_iter().filter(|id| {
                app.engine_mut()
                    .storage_mut()
                    .rx_datagram()
                    .is_occupied(*id)
                    && !held.contains(&Some(*id))
            });
            let id = found.next().unwrap();
            assert!(found.next().is_none());
            held[i] = Some(id);
            assert!(!app.engine_mut().rx_is_pinned(id));
            assert_eq!(app.engine_mut().rx_endpoint(id), Some(PEER));
            let reply = app.engine_mut().decode_rx(id).unwrap();
            assert_eq!(reply.message_id(), mids[i]);
            assert_eq!(reply.token(), tokens[i]);
            assert_eq!(
                reply.ty(),
                if i == 2 {
                    Type::NonConfirmable
                } else {
                    Type::Acknowledgement
                }
            );
            assert_eq!(reply.code(), Code::CONTENT);
            assert_eq!(
                reply.content_format(),
                Some(Ok(ContentFormat::OCTET_STREAM))
            );
            assert_eq!(reply.etag().next(), Some(&b"call"[..]));
            assert_eq!(reply.payload(), payloads[i]);
            let bytes = app.engine_mut().access_rx(id).unwrap();
            assert!(bytes.len() <= snapshots[i].len());
            lengths[i] = bytes.len();
            snapshots[i][..bytes.len()].copy_from_slice(&bytes);
        }};
    }
    macro_rules! retained_unchanged {
        ($count:expr) => {{
            assert_eq!(app.engine_mut().rx_occupied(), $count);
            for i in 0..$count {
                let id = held[i].unwrap();
                assert!(app.engine_mut().storage_mut().rx_datagram().is_occupied(id));
                assert!(!app.engine_mut().rx_is_pinned(id));
                assert_eq!(app.engine_mut().rx_endpoint(id), Some(PEER));
                let bytes = app.engine_mut().access_rx(id).unwrap();
                assert_eq!(&*bytes, &snapshots[i][..lengths[i]]);
            }
        }};
    }
    for i in 0..3 {
        // Third setup Call is deliberately NON: leaving a CON to this same
        // physical endpoint pending would block notify under NSTART. Target
        // registration and all continuation GETs below remain CON.
        let outgoing = app.get("retained").to(PEER);
        let call = if i == 2 {
            outgoing.non().send(4)
        } else {
            outgoing.send((i * 2) as u64)
        }
        .unwrap();
        calls[i] = Some(call);
        let io = app.transport_mut();
        let n = io.output_len.take().unwrap();
        let wire = decode(&io.output[..n]).unwrap();
        assert_eq!(wire.oscore().is_some(), protected);
        assert_eq!(wire.code(), if protected { Code::POST } else { Code::GET });
        assert_eq!(
            wire.ty(),
            if i == 2 {
                Type::NonConfirmable
            } else {
                Type::Confirmable
            }
        );
        let (request, binding) = match peer.as_mut() {
            Some(context) => {
                let (request, binding) = context.unprotect_request(&wire, &mut opened).unwrap();
                (request, Some(binding))
            }
            None => (wire, None),
        };
        assert_eq!(request.code(), Code::GET);
        tokens[i] = request.token();
        mids[i] = if i == 2 {
            // A NON response has a fresh peer MID, not an echo requirement.
            MessageId::new(if request.message_id() == MessageId::new(47_999) {
                47_998
            } else {
                47_999
            })
        } else {
            request.message_id()
        };
        let format = ContentFormat::OCTET_STREAM.encode();
        let options = [Opt::etag(b"call"), Opt::content_format(&format)];
        let response = Message::new(
            if i == 2 {
                Type::NonConfirmable
            } else {
                Type::Acknowledgement
            },
            Code::CONTENT,
            mids[i],
        )
        .with_token(tokens[i])
        .with_options(&options)
        .with_payload(payloads[i]);
        let n = match peer.as_mut() {
            Some(context) => context
                .protect_response(&response, binding.unwrap(), &mut io.input)
                .unwrap(),
            None => response.encode(&mut io.input).unwrap(),
        };
        let outer = decode(&io.input[..n]).unwrap();
        assert_eq!(outer.message_id(), mids[i]);
        assert_eq!(outer.token(), tokens[i]);
        assert_eq!(
            outer.ty(),
            if i == 2 {
                Type::NonConfirmable
            } else {
                Type::Acknowledgement
            }
        );
        assert_eq!(
            outer.code(),
            if protected {
                Code::CHANGED
            } else {
                Code::CONTENT
            }
        );
        assert_eq!(outer.oscore().is_some(), protected);
        if i == 2 {
            postponed_len = n;
            postponed[..n].copy_from_slice(&io.input[..n]);
        } else {
            io.input_len = Some(n);
            app.poll((i * 2 + 1) as u64).unwrap();
            assert!(app.transport().input_len.is_none());
            assert!(app.transport().output_len.is_none());
            bind_reply!(i);
            retained_unchanged!(i + 1);
        }
    }
    assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 0);
    let token = Token::new(b"notify").unwrap();
    assert!(!tokens.contains(&token));
    let mut observing_binding = None;
    let mut assembly = [0; 64];
    let mut body = None;
    let mut body_snapshot = None;
    let before = app.metrics();
    // Stage0 registers, stage1 explicitly exercises the public adaptive NON
    // notification, stages2..4 fetch notification blocks1..3, stage5 recovers.
    for stage in 0..6_u16 {
        let num = if stage <= 1 { 0 } else { u32::from(stage - 1) };
        let mid = MessageId::new(48_000 + stage);
        let request_token = if stage == 5 {
            Token::new(b"recover").unwrap()
        } else {
            token
        };
        if stage == 1 {
            assert_eq!(
                app.notify(6, &["bench"], notification_representation())
                    .unwrap(),
                1
            );
        } else {
            let block = coaptic::message::BlockValue::new(num, false, 0)
                .unwrap()
                .encode();
            let registration = [
                Opt::observe_register(),
                Opt::uri_path("bench"),
                Opt::block2(&block),
            ];
            let continuation = [Opt::uri_path("bench"), Opt::block2(&block)];
            let recovery = [Opt::uri_path("bench")];
            let options = if stage == 0 {
                &registration[..]
            } else if stage == 5 {
                &recovery[..]
            } else {
                &continuation[..]
            };
            let request = Message::con(Code::GET, mid, request_token).with_options(options);
            let io = app.transport_mut();
            io.input_len = Some(match peer.as_mut() {
                Some(context) => context.protect_request(&request, &mut io.input).unwrap(),
                None => request.encode(&mut io.input).unwrap(),
            });
            app.poll(if stage == 0 { 5 } else { u64::from(stage) + 6 })
                .unwrap();
            assert!(app.transport().input_len.is_none());
        }
        {
            let io = app.transport_mut();
            let n = io.output_len.take().unwrap();
            let wire = decode(&io.output[..n]).unwrap();
            assert_eq!(wire.oscore().is_some(), protected);
            assert_eq!(
                wire.code(),
                if protected && stage >= 2 {
                    Code::CHANGED
                } else {
                    Code::CONTENT
                }
            );
            assert_eq!(
                wire.ty(),
                if stage == 1 {
                    Type::NonConfirmable
                } else {
                    Type::Acknowledgement
                }
            );
            if stage != 1 {
                assert_eq!(wire.message_id(), mid);
            }
            assert_eq!(wire.token(), request_token);
            let reply = match peer.as_mut() {
                Some(context) => {
                    let binding = if stage == 1 {
                        // RequestRef is publicly Copy/Clone on all three pins.
                        // Notification authenticates against the registration,
                        // never a guessed followup or a second trial binding.
                        observing_binding.unwrap()
                    } else {
                        let binding = context.take(request_token).unwrap();
                        if stage == 0 {
                            observing_binding = Some(binding);
                        }
                        binding
                    };
                    context
                        .unprotect_response(&wire, binding, &mut opened)
                        .unwrap()
                }
                None => wire,
            };
            assert_eq!(reply.ty(), wire.ty());
            assert_eq!(reply.message_id(), wire.message_id());
            assert_eq!(reply.token(), request_token);
            assert_eq!(reply.code(), Code::CONTENT);
            assert_eq!(
                reply.content_format(),
                Some(Ok(ContentFormat::OCTET_STREAM))
            );
            let mut tags = reply.etag();
            assert_eq!(tags.next(), Some(&b"notify64"[..]));
            assert!(tags.next().is_none());
            if stage == 5 {
                assert!(reply.block2().is_none());
                assert!(reply.observe().is_none());
                assert_eq!(reply.payload(), &NOTIFICATION_BODY);
            } else {
                let block = reply.block2().unwrap().unwrap();
                assert_eq!(block.num(), num);
                assert_eq!(block.szx(), 0);
                assert_eq!(block.more(), num < 3);
                assert_eq!(
                    reply.payload(),
                    &NOTIFICATION_BODY[num as usize * 16..(num as usize + 1) * 16]
                );
                if stage == 0 {
                    assert_eq!(reply.observe(), Some(Ok(0)));
                } else if stage == 1 {
                    assert!(reply.observe().unwrap().is_ok());
                } else {
                    assert!(reply.observe().is_none());
                }
                if stage != 0 {
                    // Start NEW assembly at notification block0. The initial
                    // registration fragment is validated but never assembled.
                    assembly[num as usize * 16..(num as usize + 1) * 16]
                        .copy_from_slice(reply.payload());
                }
            }
        }
        assert!(app.transport().output_len.is_none());
        assert_eq!(
            HANDLER_CALLS.load(Ordering::SeqCst),
            if stage == 5 { 2 } else { 1 }
        );
        if stage == 1 {
            let mut owned = body_ids.into_iter().filter(|id| {
                app.engine_mut()
                    .storage_mut()
                    .tx_body()
                    .unwrap()
                    .is_occupied(*id)
            });
            body = Some(owned.next().unwrap());
            assert!(owned.next().is_none());
            let id = body.unwrap();
            assert_eq!(
                app.engine_mut().tx_body_payload(id),
                Some(&NOTIFICATION_BODY[..])
            );
            let transfer = app.engine_mut().tx_body_transfer(id).unwrap();
            assert_eq!(
                transfer.key(),
                coaptic::storage::BlockKey::new(token, PEER)
                    .with_identity(coaptic::storage::BodyTag::new(b"notify64").unwrap())
            );
            assert_eq!(transfer.role(), coaptic::storage::BlockRole::OutgoingBlock2);
            assert_eq!(transfer.szx(), 0);
            body_snapshot = Some(transfer);
            let io = app.transport_mut();
            io.input[..postponed_len].copy_from_slice(&postponed[..postponed_len]);
            io.input_len = Some(postponed_len);
            app.poll(7).unwrap();
            assert!(app.transport().input_len.is_none());
            assert!(app.transport().output_len.is_none());
            bind_reply!(2);
        }
        if (1..=3).contains(&stage) {
            let id = body.unwrap();
            assert_eq!(
                app.engine_mut()
                    .storage_mut()
                    .tx_body()
                    .unwrap()
                    .occupied_count(),
                1
            );
            assert!(
                app.engine_mut()
                    .storage_mut()
                    .tx_body()
                    .unwrap()
                    .is_occupied(id)
            );
            assert!(!app.engine_mut().tx_body_is_pinned(id));
            assert_eq!(
                app.engine_mut().tx_body_payload(id),
                Some(&NOTIFICATION_BODY[..])
            );
            let transfer = app.engine_mut().tx_body_transfer(id).unwrap();
            assert_eq!(transfer.token(), token);
            assert_eq!(transfer.endpoint(), PEER);
            assert_eq!(transfer.szx(), 0);
            // Explicit range selection preserves the entire retained sidecar,
            // including issuance flags, selection and notification metadata.
            // Actual progress is checked from wire NUM/M and exact payloads.
            assert_eq!(transfer, body_snapshot.unwrap());
            assert_eq!(transfer.filled(), NOTIFICATION_BODY.len());
            assert_eq!(transfer.identity().as_slice(), Some(&b"notify64"[..]));
            retained_unchanged!(3);
            assert_eq!(
                capacities.rx_datagram_slots - app.engine_mut().rx_occupied(),
                1
            );
        } else if stage == 0 {
            retained_unchanged!(2);
        } else if stage == 4 {
            assert_eq!(assembly, NOTIFICATION_BODY);
            let id = body.unwrap();
            assert!(
                !app.engine_mut()
                    .storage_mut()
                    .tx_body()
                    .unwrap()
                    .is_occupied(id)
            );
            assert_eq!(
                app.engine_mut()
                    .storage_mut()
                    .tx_body()
                    .unwrap()
                    .occupied_count(),
                0
            );
            assert!(app.engine_mut().tx_body_transfer(id).is_none());
            retained_unchanged!(3);
            // Only public Call collection releases RX ownership, once per Call.
            let mut collected = [0; 32];
            for i in 0..3 {
                let call = calls[i].unwrap();
                let reply = app
                    .take_response_into(call, &mut collected)
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(reply.message_id(), Some(mids[i]));
                assert_eq!(reply.token(), Some(tokens[i]));
                assert_eq!(reply.code(), Code::CONTENT);
                assert_eq!(reply.format(), Some(ContentFormat::OCTET_STREAM));
                assert_eq!(reply.etag_bytes(), Some(&b"call"[..]));
                assert_eq!(reply.payload(), payloads[i]);
                assert!(
                    app.take_response_into(call, &mut collected)
                        .unwrap()
                        .is_none()
                );
                assert!(
                    !app.engine_mut()
                        .storage_mut()
                        .rx_datagram()
                        .is_occupied(held[i].unwrap())
                );
                assert_eq!(app.engine_mut().rx_occupied(), 2 - i);
            }
        } else if stage == 5 {
            assert_eq!(app.engine_mut().rx_occupied(), 0);
        }
        assert_eq!(
            app.metrics().admission_rx_refused,
            before.admission_rx_refused
        );
        assert_eq!(
            app.metrics().admission_tx_refused,
            before.admission_tx_refused
        );
        assert_eq!(
            app.metrics().admission_refusal_sent,
            before.admission_refusal_sent
        );
        assert_eq!(
            app.metrics().admission_refusal_unsent,
            before.admission_refusal_unsent
        );
    }
    // The Observe relation legitimately remains; this proves body and Call
    // recovery, not cancellation or whole-subscription reclamation.
    assert!(
        app.engine_mut()
            .lookup_observe(coaptic::storage::ObserveKey::new(token, PEER))
            .is_some()
    );
    assert_eq!(app.engine_mut().storage_mut().observe().occupied_count(), 1);
    assert_eq!(
        app.engine_mut()
            .storage_mut()
            .rx_body()
            .unwrap()
            .occupied_count(),
        0
    );
    assert_eq!(
        app.engine_mut()
            .storage_mut()
            .tx_body()
            .unwrap()
            .occupied_count(),
        0
    );
    assert_eq!(app.engine_mut().rx_occupied(), 0);
}
