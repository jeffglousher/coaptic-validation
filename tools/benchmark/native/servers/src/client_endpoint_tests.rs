use super::*;
use crate::{Client, client_capacities};
use coaptic::{
    App, Call, Code,
    message::{BlockValue, Message, MessageId, Opt, Type, decode, encode},
    oscore::{DeriveParams, SecurityContext},
};
use std::time::Duration;

fn context(server: bool) -> SecurityContext {
    SecurityContext::derive(DeriveParams {
        master_secret: &[1; 16],
        master_salt: &[2; 8],
        sender_id: if server { &[1] } else { &[] },
        recipient_id: if server { &[] } else { &[1] },
        id_context: &[],
    })
    .unwrap()
}

struct Fixture {
    server: UdpSocket,
    client: Client<EndpointIo>,
    context: Option<SecurityContext>,
    peers: [Endpoint; LANES],
    locals: [SocketAddr; LANES],
    count: usize,
}
impl Fixture {
    fn new(count: usize, protected: bool, size: usize) -> Self {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let SocketAddr::V4(remote) = server.local_addr().unwrap() else {
            unreachable!()
        };
        let io = EndpointIo::new(remote, count).unwrap();
        let peers = io.peers();
        let locals = std::array::from_fn(|i| {
            SocketAddr::V4(io.lanes[i.min(count - 1)].as_ref().unwrap().local)
        });
        let builder = App::builder()
            .routes::<1>()
            .block_wise::<true>()
            .full_responses()
            .deterministic_for_tests();
        let builder = if protected {
            builder.oscore(context(false))
        } else {
            builder.allow_unprotected()
        };
        let mut caps = client_capacities(size, count);
        caps.rx_datagram_slots = 5;
        caps.tx_datagram_slots = 5;
        Self {
            server,
            client: builder.bind_alloc(io, caps).unwrap(),
            context: protected.then(|| context(true)),
            peers,
            locals,
            count,
        }
    }
    fn start(&mut self, lane: usize, now: u64) -> Call {
        self.client
            .get("bench")
            .to(self.peers[lane])
            .send(now)
            .unwrap()
    }
    fn request(&self) -> (Vec<u8>, usize) {
        let mut bytes = [0; 1473];
        let (n, from) = self.server.recv_from(&mut bytes).unwrap();
        let lane = self.locals[..self.count]
            .iter()
            .position(|p| *p == from)
            .unwrap();
        (bytes[..n].to_vec(), lane)
    }
    fn response(
        &mut self,
        request: &[u8],
        body: &[u8],
        block: Option<BlockValue>,
        ty: Type,
    ) -> Vec<u8> {
        let outer = decode(request).unwrap();
        let mut inner = [0; 1472];
        let reference = self
            .context
            .as_mut()
            .map(|ctx| ctx.unprotect_request(&outer, &mut inner).unwrap().1);
        let block = block.map(BlockValue::encode);
        let format = coaptic::message::encode_uint(42);
        let mut opts = vec![Opt::etag(b"fixture"), Opt::content_format(&format)];
        if let Some(ref b) = block {
            opts.push(Opt::block2(b));
        }
        let reply = Message::new(
            ty,
            Code::CONTENT,
            if ty == Type::Acknowledgement {
                outer.message_id()
            } else {
                MessageId::new(500)
            },
        )
        .with_token(outer.token())
        .with_options(&opts)
        .with_payload(body);
        let mut wire = [0; 1472];
        let n = if let Some(reference) = reference {
            self.context
                .as_ref()
                .unwrap()
                .protect_response(&reply, reference, &mut wire)
                .unwrap()
        } else {
            encode(&reply, &mut wire).unwrap()
        };
        wire[..n].to_vec()
    }
    fn send(&self, lane: usize, bytes: &[u8]) {
        self.server.send_to(bytes, self.locals[lane]).unwrap();
    }
    fn poll(&mut self, now: u64) {
        for _ in 0..8 {
            let _ = self.client.poll(now);
        }
    }
    fn pending(&mut self, calls: &[Call]) {
        for &call in calls {
            assert!(self.client.take_response(call).is_none());
        }
    }
    fn collect(&mut self, call: Call, expected: &[u8]) {
        let mut output = vec![0; expected.len()];
        let reply = self
            .client
            .take_response_into(call, &mut output)
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(reply.payload(), expected);
    }
    fn empty(&mut self) {
        assert_eq!(self.client.resource_usage().client_requests.occupied, 0);
        assert_eq!(self.client.resource_usage().client_replies.occupied, 0);
        assert_eq!(self.client.storage_usage().rx_body.unwrap().occupied, 0);
        assert_eq!(self.client.storage_usage().tx_datagram.occupied, 0);
        assert_eq!(self.client.storage_usage().rx_datagram.occupied, 0);
    }
}

#[test]
fn real_pair_keys_survive_physical_and_sends_use_original_sockets() {
    let mut f = Fixture::new(4, true, 64);
    let calls: Vec<_> = (0..4).map(|i| f.start(i, 0)).collect();
    assert_eq!(
        calls
            .iter()
            .map(|c| c.token())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        4
    );
    assert_eq!(f.client.oscore().unwrap().sender_seq(), 4);
    for i in 0..4 {
        assert_eq!(f.peers[i], f.peers[i].physical());
        for j in 0..i {
            assert_ne!(f.peers[i].physical(), f.peers[j].physical());
        }
        let (request, lane) = f.request();
        let reply = f.response(&request, &[lane as u8; 64], None, Type::Acknowledgement);
        f.send(lane, &reply);
    }
    // Every Call and actual source port is live before any App receive poll.
    f.poll(1);
    for (i, call) in calls.into_iter().enumerate() {
        f.collect(call, &[i as u8; 64]);
    }
    f.empty();
}

#[test]
fn wrong_socket_sender_token_mid_ciphertext_and_replay_do_not_steal_authority() {
    for protected in [false, true] {
        let mut f = Fixture::new(2, protected, 64);
        let calls = [f.start(0, 0), f.start(1, 0)];
        let (req0, lane0) = f.request();
        let (req1, lane1) = f.request();
        assert_ne!(lane0, lane1);
        let reply0 = f.response(&req0, &[0; 64], None, Type::Acknowledgement);
        let reply1 = f.response(&req1, &[1; 64], None, Type::Acknowledgement);
        let seq = f.client.oscore().map(SecurityContext::sender_seq);
        let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
        attacker.send_to(&reply0, f.locals[lane0]).unwrap();
        f.send(lane1, &reply0);
        f.poll(1);
        f.pending(&calls);
        // ACK MID is guarded before looking up the protected request binding.
        let mut wrong_mid = reply0.clone();
        wrong_mid[3] ^= 1;
        f.send(lane0, &wrong_mid);
        f.poll(2);
        f.pending(&calls);
        let mut wrong_token = reply0.clone();
        wrong_token[4] ^= 1;
        f.send(lane0, &wrong_token);
        f.poll(3);
        f.pending(&calls);
        if protected {
            let mut ciphertext = reply0.clone();
            *ciphertext.last_mut().unwrap() ^= 1;
            f.send(lane0, &ciphertext);
            f.poll(4);
            f.pending(&calls);
        }
        assert_eq!(f.client.oscore().map(SecurityContext::sender_seq), seq);
        f.send(lane0, &reply0);
        f.poll(5);
        f.collect(calls[lane0], &[0; 64]);
        f.send(lane1, &reply0);
        f.send(lane0, &reply0);
        f.poll(6);
        f.pending(&[calls[lane1]]);
        f.send(lane1, &reply1);
        f.poll(7);
        f.collect(calls[lane1], &[1; 64]);
        f.empty();
        let next = f.start(lane0, 8);
        let (request, lane) = f.request();
        f.send(lane, &reply0);
        f.poll(9);
        f.pending(&[next]);
        let response = f.response(&request, &[9; 64], None, Type::Acknowledgement);
        f.send(lane, &response);
        f.poll(10);
        f.collect(next, &[9; 64]);
        f.empty();
    }
}

#[test]
fn bounded_rotation_preserves_last_to_first_fairness_and_rejects_oversize_prefix() {
    let mut f = Fixture::new(4, false, 64);
    let io = f.client.transport_mut();
    for round in 0..4 {
        for i in 0..4 {
            f.server
                .send_to(&[round * 4 + i as u8], f.locals[i])
                .unwrap();
        }
        for i in 0..4 {
            let mut output = [0; 1472];
            let (n, peer) = io.recv(&mut output).unwrap().unwrap();
            assert_eq!(n, 1);
            assert_eq!(peer, f.peers[i]);
            assert_eq!(io.cursor, (i + 1) % 4);
        }
    }
    // With all K lanes invalid, one recv consumes at most one packet per lane.
    for i in 0..4 {
        for _ in 0..2 {
            f.server.send_to(&[0; 1473], f.locals[i]).unwrap();
        }
    }
    assert!(io.recv(&mut [0; 1472]).unwrap().is_none());
    assert_eq!(io.cursor, 0);
    // A quiet lane's valid packet behind its invalid datagram is serviced on
    // the next bounded pass, while a busy invalid lane cannot monopolize it.
    f.server.send_to(b"quiet", f.locals[3]).unwrap();
    for _ in 0..8 {
        f.server.send_to(&[0; 1473], f.locals[0]).unwrap();
    }
    assert!(io.recv(&mut [0; 1472]).unwrap().is_none());
    let mut out = [0; 1472];
    assert_eq!(io.recv(&mut out).unwrap(), Some((5, f.peers[3])));
    assert_eq!(&out[..5], b"quiet");
    assert_eq!(io.cursor, 0);
    // No valid-looking prefix is passed to the decoder after truncation, even
    // when Windows reports WSAEMSGSIZE rather than the received length.
    f.server.send_to(&[0; 4096], f.locals[1]).unwrap();
    assert!(io.recv(&mut out).unwrap().is_none());
    assert!(io.send(Endpoint::v4([127, 0, 0, 1], 1), b"bad").is_err());
}

#[test]
fn global_send_budget_is_shared_across_sockets_including_controls() {
    let mut f = Fixture::new(4, false, 64);
    let io = f.client.transport_mut();
    io.sent = SEND_BUDGET - 1;
    assert_eq!(io.send(f.peers[3], b"last").unwrap(), 4);
    for peer in f.peers {
        assert!(io.send(peer, b"over").is_err());
    }
    assert_eq!(io.sent, SEND_BUDGET);
    assert_eq!(io.lanes.iter().flatten().map(|l| l.sent).sum::<u64>(), 1);
}

#[test]
fn interleaved_same_etag_multiblock_pairs_remain_distinct_and_one_cancel_recovers() {
    for protected in [false, true] {
        for count in [2, 4] {
            for cancel in [false, true] {
                let mut f = Fixture::new(count, protected, 2048);
                let calls: Vec<_> = (0..count).map(|i| f.start(i, 0)).collect();
                let mut next = vec![None; count];
                for _ in 0..count {
                    let (request, lane) = f.request();
                    let body = vec![lane as u8 + 1; 1024];
                    let reply = f.response(
                        &request,
                        &body,
                        Some(BlockValue::from_size(0, true, 1024).unwrap()),
                        Type::Acknowledgement,
                    );
                    f.send(lane, &reply);
                }
                // All first blocks coexist in their endpoint-keyed body owners.
                f.poll(1);
                f.pending(&calls);
                for _ in 0..count {
                    let (request, lane) = f.request();
                    assert!(next[lane].replace(request).is_none());
                }
                assert_eq!(f.client.storage_usage().rx_body.unwrap().occupied, count);
                if cancel {
                    assert!(f.client.cancel(calls[0]));
                    assert!(f.client.take_response(calls[0]).unwrap().is_err());
                }
                for lane in (0..count).rev() {
                    let request = next[lane].as_ref().unwrap();
                    let reply = f.response(
                        request,
                        &vec![lane as u8 + 1; 1024],
                        Some(BlockValue::from_size(1, false, 1024).unwrap()),
                        Type::Acknowledgement,
                    );
                    f.send(lane, &reply);
                }
                f.poll(2);
                for (lane, call) in calls.into_iter().enumerate() {
                    if !cancel || lane != 0 {
                        f.collect(call, &vec![lane as u8 + 1; 2048]);
                    }
                }
                f.empty();
                let call = f.start(0, 3);
                let (request, lane) = f.request();
                assert_eq!(lane, 0);
                let reply = f.response(&request, &[7; 64], None, Type::Acknowledgement);
                f.send(lane, &reply);
                f.poll(4);
                f.collect(call, &[7; 64]);
                f.empty();
            }
        }
    }
}

#[test]
fn retransmission_and_separate_response_ack_stay_on_original_lane_without_new_nonce() {
    for protected in [false, true] {
        let mut f = Fixture::new(2, protected, 64);
        let call = f.start(1, 0);
        let (request, lane) = f.request();
        assert_eq!(lane, 1);
        let seq = f.client.oscore().map(SecurityContext::sender_seq);
        f.poll(4000);
        let (retry, retry_lane) = f.request();
        assert_eq!(retry_lane, lane);
        assert_eq!(retry, request);
        assert_eq!(f.client.oscore().map(SecurityContext::sender_seq), seq);
        let reply = f.response(&request, &[3; 64], None, Type::Confirmable);
        f.send(lane, &reply);
        f.poll(4001);
        f.collect(call, &[3; 64]);
        let (ack, ack_lane) = f.request();
        assert_eq!(ack_lane, lane);
        let ack = decode(&ack).unwrap();
        assert_eq!(ack.ty(), Type::Acknowledgement);
        assert_eq!(ack.code(), Code::EMPTY);
        assert_eq!(ack.message_id(), MessageId::new(500));
        f.empty();
    }
}

#[test]
fn four_live_calls_do_not_bound_global_replay_skew() {
    let mut f = Fixture::new(4, true, 64);
    let delayed = f.start(0, 0);
    let (delayed_wire, lane) = f.request();
    assert_eq!(lane, 0);
    for round in 0..14 {
        let calls: Vec<_> = (1..4).map(|i| f.start(i, round * 2)).collect();
        for _ in 1..4 {
            let (request, lane) = f.request();
            let reply = f.response(&request, &[4; 64], None, Type::Acknowledgement);
            f.send(lane, &reply);
        }
        f.poll(round * 2 + 1);
        for call in calls {
            f.collect(call, &[4; 64]);
        }
        f.pending(&[delayed]);
    }
    assert_eq!(f.client.oscore().unwrap().sender_seq(), 43);
    let before = f.context.as_ref().unwrap().replay_checkpoint();
    let error = f
        .context
        .as_mut()
        .unwrap()
        .unprotect_request(&decode(&delayed_wire).unwrap(), &mut [0; 1472])
        .unwrap_err();
    assert_eq!(error, coaptic::oscore::Error::Replay);
    assert_eq!(f.context.as_ref().unwrap().replay_checkpoint(), before);
    assert!(f.client.cancel(delayed));
    assert!(f.client.take_response(delayed).unwrap().is_err());
    f.empty();
    let fresh = f.start(0, 40);
    let (request, lane) = f.request();
    let reply = f.response(&request, &[5; 64], None, Type::Acknowledgement);
    f.send(lane, &reply);
    f.poll(41);
    f.collect(fresh, &[5; 64]);
    f.empty();
}

#[test]
fn refusal_short_output_timeout_cancel_and_reuse_release_lane_owners() {
    for protected in [false, true] {
        let mut f = Fixture::new(4, protected, 2048);
        // An unmapped logical endpoint refuses at send. No transport budget or
        // binding may remain held, and the consumed sender nonce never rewinds.
        assert!(
            f.client
                .get("bench")
                .to(Endpoint::v4([127, 0, 0, 1], 9))
                .send(0)
                .is_err()
        );
        let seq = f.client.oscore().map(SecurityContext::sender_seq);
        f.empty();
        let call = f.start(0, 1);
        let (request, lane) = f.request();
        let reply = f.response(&request, &[7; 64], None, Type::Acknowledgement);
        f.send(lane, &reply);
        f.poll(2);
        assert!(f.client.take_response_into(call, &mut [0; 1]).is_err());
        assert_eq!(f.client.resource_usage().completed_replies, 1);
        assert_eq!(f.client.resource_usage().client_requests.occupied, 1);
        let retained = f.client.take_response(call).unwrap().unwrap();
        assert_eq!(retained.payload(), &[7; 64]);
        f.empty();
        let call = f.start(0, 3);
        let (retained, lane) = f.request();
        assert_eq!(lane, 0);
        let sent_seq = f.client.oscore().map(SecurityContext::sender_seq);
        f.poll(4000);
        let (retry, lane) = f.request();
        assert_eq!(lane, 0);
        assert_eq!(retry, retained);
        assert_eq!(f.client.oscore().map(SecurityContext::sender_seq), sent_seq);
        assert!(f.client.cancel(call));
        assert!(f.client.take_response(call).unwrap().is_err());
        f.empty();
        // Production complete-operation deadline cleanup uses these same two
        // operations; the existing run_window failure tests verify the path.
        let call = f.start(0, 5000);
        let _ = f.request();
        for now in [9000, 17000, 33000, 65000, 130000, 300000] {
            f.poll(now);
        }
        assert!(f.client.take_response(call).unwrap().is_err());
        f.empty();
        let fresh = f.start(0, 300001);
        // Drain the bounded retained retry datagrams; the fresh Token must be
        // observed on the identical local socket, never a replacement socket.
        let mut wire = None;
        for _ in 0..6 {
            let (request, lane) = f.request();
            assert_eq!(lane, 0);
            if decode(&request).unwrap().token() == fresh.token() {
                wire = Some(request);
                break;
            }
        }
        let reply = f.response(&wire.unwrap(), &[8; 64], None, Type::Acknowledgement);
        f.send(0, &reply);
        f.poll(300002);
        f.collect(fresh, &[8; 64]);
        f.empty();
        if let Some(seq) = seq {
            assert!(f.client.oscore().unwrap().sender_seq() > seq);
        }
    }
}

#[test]
fn actual_service_ordinary_calls_use_borrowed_server_blocks_and_four_client_bodies() {
    fn representation(_: coaptic::Request<'_>) -> coaptic::Response<'static> {
        coaptic::Response::content(&[6; 2048])
            .content_format(coaptic::ContentFormat::OCTET_STREAM)
            .etag(b"fixture")
    }
    for protected in [false, true] {
        let Fixture {
            server,
            mut client,
            peers,
            ..
        } = Fixture::new(4, protected, 2048);
        server.set_nonblocking(true).unwrap();
        let resources = coaptic::resources::Service::new();
        let heap = coaptic::storage::AllocMemory::<coaptic::message::Token>::required_heap_bytes(
            resources.pool_capacities(),
        )
        .unwrap();
        let builder = App::with_resources(resources.allocated(heap))
            .deterministic_for_tests()
            .route("bench", coaptic::get(representation));
        let builder = if protected {
            builder.oscore(context(true))
        } else {
            builder.allow_unprotected()
        };
        let mut server = builder
            .bind(coaptic::storage::UdpSocketIo::new(server, [0; 1473]).unwrap())
            .unwrap();
        let calls: Vec<_> = peers
            .iter()
            .map(|p| client.get("bench").to(*p).send(0).unwrap())
            .collect();
        for _ in 0..16 {
            server.poll(1).unwrap();
        }
        // Ordinary classic GET borrows during dispatch and releases its body
        // admission credit before returning; four live Calls are not four
        // retained server snapshots.
        assert_eq!(server.storage_usage().tx_body.unwrap().occupied, 0);
        assert_eq!(client.resource_usage().client_requests.occupied, 4);
        for _ in 0..16 {
            client.poll(2).unwrap();
        }
        assert_eq!(client.storage_usage().rx_body.unwrap().occupied, 4);
        for now in 3..60 {
            client.poll(now).unwrap();
            server.poll(now).unwrap();
        }
        for call in calls {
            let mut output = [0; 2048];
            let reply = client
                .take_response_into(call, &mut output)
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(reply.payload(), &[6; 2048]);
        }
        assert_eq!(client.resource_usage().client_requests.occupied, 0);
        assert_eq!(client.storage_usage().rx_body.unwrap().occupied, 0);
    }
}

#[test]
fn actual_body_occupancy_refusal_preserves_owners_retained_ciphertext_and_recovery() {
    fn representation(_: coaptic::Request<'_>) -> coaptic::Response<'static> {
        coaptic::Response::content(&[6; 2048])
            .content_format(coaptic::ContentFormat::OCTET_STREAM)
            .etag(b"fixture")
    }
    // All initial body owners are explicitly public-storage fixtures. Real
    // App/socket requests exercise ordinary borrowed-path admission refusal.
    // This is not a claim of five real clients or retained ordinary GET bodies.
    macro_rules! exercise {
        ($resources:expr, $expected_slots:expr, $count:expr) => {{
            #[inline(never)]
            fn run(protected: bool, count: usize) {
                use coaptic::storage::{BlockKey, ExchangeKey};
                let Fixture {
                    server,
                    mut client,
                    peers,
                    locals,
                    ..
                } = Fixture::new(count, protected, 2048);
                server.set_nonblocking(true).unwrap();
                let builder = App::with_resources($resources)
                    .deterministic_for_tests()
                    .route("bench", coaptic::get(representation));
                let builder = if protected {
                    builder.oscore(context(true))
                } else {
                    builder.allow_unprotected()
                };
                let mut server = builder
                    .bind(coaptic::storage::UdpSocketIo::new(server, [0; 1473]).unwrap())
                    .unwrap();
                let slots = server.storage_usage().tx_body.unwrap().capacity;
                assert_eq!(slots, $expected_slots);
                let mut fixtures = Vec::new();
                for i in 0..slots {
                    let key = BlockKey::new(
                        coaptic::message::Token::new(&[240 + i as u8]).unwrap(),
                        Endpoint::v4([127, 0, 0, 1], 20000 + i as u16),
                    );
                    fixtures.push(
                        server
                            .engine_mut()
                            .start_block2(key, &[9; 2048], 6)
                            .unwrap(),
                    );
                }
                assert!(server.engine_mut().acquire_tx_body().is_none());
                let calls: Vec<_> = peers[..count]
                    .iter()
                    .map(|p| client.get("bench").to(*p).send(0).unwrap())
                    .collect();
                let exchange = client
                    .engine()
                    .lookup_exchange(ExchangeKey::new(calls[0].token(), peers[0]))
                    .unwrap();
                let tx = client.engine().exchange_entry(exchange).unwrap().tx_slot();
                let retained_request = client.engine_mut().access_tx(tx).unwrap().to_vec();
                let mut wire = [0; 1473];
                let (n, from) = server.transport().socket().peek_from(&mut wire).unwrap();
                assert_eq!(from, locals[0]);
                assert_eq!(&wire[..n], retained_request);
                let mut refused = 0;
                for _ in 0..32 {
                    match server.poll(1) {
                        Err(coaptic::Error::Block(
                            coaptic::error::BlockTransferError::Saturated,
                        )) => refused += 1,
                        Ok(_) => {}
                        Err(e) => panic!("unexpected body-boundary outcome: {e:?}"),
                    }
                }
                assert_eq!(refused, count);
                assert_eq!(server.storage_usage().tx_body.unwrap().occupied, slots);
                for &id in &fixtures {
                    assert_eq!(server.engine().tx_body_payload(id), Some(&[9; 2048][..]));
                }
                assert_eq!(
                    &*client.engine_mut().access_tx(tx).unwrap(),
                    retained_request
                );
                let sequence = client.oscore().map(SecurityContext::sender_seq);
                let replay = server.oscore().map(SecurityContext::replay_checkpoint);
                client.poll(4000).unwrap();
                let (n, from) = server.transport().socket().peek_from(&mut wire).unwrap();
                assert_eq!(from, locals[0]);
                assert_eq!(&wire[..n], retained_request);
                for _ in 0..32 {
                    let _ = server.poll(4000);
                }
                assert_eq!(client.oscore().map(SecurityContext::sender_seq), sequence);
                assert_eq!(
                    server.oscore().map(SecurityContext::replay_checkpoint),
                    replay
                );
                for &id in &fixtures {
                    assert_eq!(server.engine().tx_body_payload(id), Some(&[9; 2048][..]));
                }
                for call in calls {
                    assert!(client.cancel(call));
                    assert!(client.take_response(call).unwrap().is_err());
                }
                let released = fixtures.pop().unwrap();
                server.engine_mut().release_tx_body(released).unwrap();
                assert_eq!(server.storage_usage().tx_body.unwrap().occupied, slots - 1);
                let fresh = client.get("bench").to(peers[0]).send(4001).unwrap();
                for _ in 0..8 {
                    server.poll(4002).unwrap();
                }
                let (n, peer) = client
                    .transport_mut()
                    .recv(&mut wire[..1472])
                    .unwrap()
                    .unwrap();
                assert_eq!(peer, peers[0]);
                let cached_response = wire[..n].to_vec();
                let fresh_sequence = client.oscore().map(SecurityContext::sender_seq);
                let fresh_replay = server.oscore().map(SecurityContext::replay_checkpoint);
                // Withhold the first accepted response. The real server replays
                // its cached protected bytes exactly, without nonce/replay reset.
                client.poll(8001).unwrap();
                for _ in 0..8 {
                    server.poll(8001).unwrap();
                }
                let (n, peer) = client
                    .transport_mut()
                    .recv(&mut wire[..1472])
                    .unwrap()
                    .unwrap();
                assert_eq!(peer, peers[0]);
                assert_eq!(&wire[..n], cached_response);
                assert_eq!(
                    client.oscore().map(SecurityContext::sender_seq),
                    fresh_sequence
                );
                assert_eq!(
                    server.oscore().map(SecurityContext::replay_checkpoint),
                    fresh_replay
                );
                server
                    .transport()
                    .socket()
                    .send_to(&cached_response, locals[0])
                    .unwrap();
                for now in 8002..8060 {
                    client.poll(now).unwrap();
                    server.poll(now).unwrap();
                }
                let mut output = [0; 2048];
                let reply = client
                    .take_response_into(fresh, &mut output)
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(reply.payload(), &[6; 2048]);
                assert_eq!(client.resource_usage().client_requests.occupied, 0);
                assert_eq!(client.storage_usage().rx_body.unwrap().occupied, 0);
                for id in fixtures {
                    assert_eq!(server.engine().tx_body_payload(id), Some(&[9; 2048][..]));
                    server.engine_mut().release_tx_body(id).unwrap();
                }
            }
            for protected in [false, true] {
                run(protected, $count);
            }
        }};
    }
    exercise!(
        coaptic::resources::SmallDevice::new().block_wise::<true>(),
        1,
        2
    );
    exercise!(
        coaptic::resources::SmallDevice::new().block_wise::<true>(),
        1,
        4
    );
    exercise!(coaptic::resources::Service::new(), 4, 2);
    exercise!(
        {
            let r = coaptic::resources::Service::new();
            let heap =
                coaptic::storage::AllocMemory::<coaptic::message::Token>::required_heap_bytes(
                    r.pool_capacities(),
                )
                .unwrap();
            r.allocated(heap)
        },
        4,
        2
    );
}
