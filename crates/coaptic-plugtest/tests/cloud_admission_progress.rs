//! Finite caller-scheduled admission/protected-progress qualification; not a TD.
#![cfg(feature = "edhoc")]

use coaptic::message::{Code, Message, MessageId, Opt, Token, Type, decode};
use coaptic::oscore::SecurityContext;
use coaptic::provisioning::{
    AdmissionLimits, AdmissionRegistry, Association, CloudAdmission, CoapProvisioner,
    CredentialReference, Identity, PeerTrust, Status, TrustAnchor,
};
use coaptic::storage::{DatagramIo, Endpoint};

const SERVER: Endpoint = Endpoint::v4([192, 0, 2, 254], 5683);
const EXPIRY: u64 = 247_000;
type Cloud<'a> = CloudAdmission<'a, 3, 1, 3, 4>;

fn endpoint(n: u8) -> Endpoint {
    Endpoint::v4([192, 0, 2, n], 49152)
}

fn identity(n: u8) -> Identity {
    let mut key = [0; 32];
    key[31] = n;
    Identity::from_private_key(key, n).unwrap()
}

// Deterministic cryptographic fixtures only, never a platform entropy source.
fn entropy(n: u8) -> impl FnMut(&mut [u8]) -> bool {
    move |out| {
        out.fill(0);
        *out.last_mut().unwrap() = n;
        true
    }
}

fn no_entropy(_: &mut [u8]) -> bool {
    panic!("duplicate/refused traffic must not perform fresh ephemeral-key work")
}

struct Registry(Vec<PeerTrust>);

impl AdmissionRegistry for Registry {
    fn resolve(&self, reference: CredentialReference) -> Option<&PeerTrust> {
        self.0
            .iter()
            .find(|entry| entry.checkpoint().peer().kid() == reference.kid())
    }
}

#[derive(Default)]
struct Sink(Vec<(Endpoint, Vec<u8>)>);

impl DatagramIo for Sink {
    type Error = u8;

    fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, u8> {
        panic!("caller owns receive scheduling")
    }

    fn send(&mut self, to: Endpoint, bytes: &[u8]) -> Result<usize, u8> {
        self.0.push((to, bytes.to_vec()));
        Ok(bytes.len())
    }
}

impl Sink {
    fn pop(&mut self, to: Endpoint) -> Vec<u8> {
        assert_eq!(
            self.0.len(),
            1,
            "one flush spends at most one send opportunity"
        );
        let (actual, bytes) = self.0.pop().unwrap();
        assert_eq!(actual, to);
        bytes
    }
}

fn begin<'a>(
    cloud: &mut Cloud<'_>,
    registry: &Registry,
    server: &Identity,
    client: &'a Identity,
    address: Endpoint,
    now: u64,
) -> (CoapProvisioner<'a>, Vec<u8>, Vec<u8>) {
    let mut peer = CoapProvisioner::start(client, server.peer(), SERVER, now, entropy(3)).unwrap();
    let mut sink = Sink::default();
    peer.flush(&mut sink, now).unwrap();
    let request = sink.pop(SERVER);
    assert_eq!(
        cloud.ingest(&request, address, now, registry, no_entropy),
        Ok(Status::Progress)
    );
    cloud.flush(&mut sink, now, registry).unwrap();
    let challenge = sink.pop(address);
    assert_eq!(decode(&challenge).unwrap().code(), Code::UNAUTHORIZED);
    peer.ingest(&challenge, SERVER, now, no_entropy, |_| {
        panic!("Echo cannot authorize")
    })
    .unwrap();
    peer.flush(&mut sink, now).unwrap();
    let retry = sink.pop(SERVER);
    assert_eq!(
        cloud.ingest(&retry, address, now, registry, entropy(4)),
        Ok(Status::Progress)
    );
    cloud.flush(&mut sink, now, registry).unwrap();
    let message2 = sink.pop(address);
    assert_eq!(decode(&message2).unwrap().code(), Code::CHANGED);
    (peer, retry, message2)
}

struct Owner {
    client: SecurityContext,
    server: SecurityContext,
    association: Association,
    completed: usize,
}

fn finish(
    cloud: &mut Cloud<'_>,
    registry: &Registry,
    server: &Identity,
    client: &Identity,
    address: Endpoint,
    now: u64,
) -> Owner {
    let (mut peer, _, message2) = begin(cloud, registry, server, client, address, now);
    peer.ingest(&message2, SERVER, now, no_entropy, |_| true)
        .unwrap();
    let mut sink = Sink::default();
    peer.flush(&mut sink, now).unwrap();
    let message3 = sink.pop(SERVER);
    assert_eq!(
        cloud.ingest(&message3, address, now, registry, no_entropy),
        Ok(Status::Complete)
    );
    assert!(cloud.take_session(now, registry).unwrap().is_none());
    cloud.flush(&mut sink, now, registry).unwrap();
    let message4 = sink.pop(address);
    peer.ingest(&message4, SERVER, now, no_entropy, |_| true)
        .unwrap();
    let (session, association) = cloud
        .take_session(now, registry)
        .unwrap()
        .unwrap()
        .into_parts();
    assert_eq!(session.principal(), &client.peer().principal());
    Owner {
        client: peer.take_session().unwrap().into_parts().0,
        server: session.into_parts().0,
        association,
        completed: 0,
    }
}

impl Owner {
    fn request(&mut self, mid: u16) -> Vec<u8> {
        let token = Token::from_checked(&mid.to_be_bytes());
        let body: [u8; 192] = core::array::from_fn(|i| (i as u8).wrapping_add(mid as u8));
        let options = [
            Opt::uri_path("progress"),
            Opt::new(coaptic::message::OptionNumber::CONTENT_FORMAT, &[42]),
        ];
        let message = Message::con(Code::POST, MessageId::new(mid), token)
            .with_options(&options)
            .with_payload(&body);
        let mut wire = [0; 512];
        let n = self.client.protect_request(&message, &mut wire).unwrap();
        wire[..n].to_vec()
    }

    fn complete(&mut self, cloud: &mut Cloud<'_>, registry: &Registry, now: u64, mid: u16) {
        let wire = self.request(mid);
        assert_eq!(
            cloud
                .route_oscore(&wire, self.association.endpoint(), now, registry)
                .unwrap(),
            Some(self.association)
        );
        let parsed = decode(&wire).unwrap();
        assert!(parsed.oscore().is_some());
        let expected_ref = self.client.lookup(parsed.token()).unwrap();
        let mut clear = [0; 512];
        let (plain, reference) = self.server.unprotect_request(&parsed, &mut clear).unwrap();
        assert_eq!(reference, expected_ref);
        assert_eq!(plain.code(), Code::POST);
        assert_eq!(plain.message_id(), MessageId::new(mid));
        assert_eq!(plain.token(), Token::from_checked(&mid.to_be_bytes()));
        assert_eq!(
            plain.payload(),
            &core::array::from_fn::<_, 192, _>(|i| (i as u8).wrapping_add(mid as u8))
        );
        assert_eq!(
            plain.options().collect::<Vec<_>>(),
            vec![
                Opt::uri_path("progress"),
                Opt::new(coaptic::message::OptionNumber::CONTENT_FORMAT, &[42])
            ]
        );
        let response_body: [u8; 256] = core::array::from_fn(|i| (i as u8).wrapping_add(mid as u8));
        let response_options = [Opt::new(
            coaptic::message::OptionNumber::CONTENT_FORMAT,
            &[42],
        )];
        let response = Message::new(Type::Acknowledgement, Code::CONTENT, MessageId::new(mid))
            .with_token(plain.token())
            .with_options(&response_options)
            .with_payload(&response_body);
        let mut reply = [0; 512];
        let n = self
            .server
            .protect_response(&response, reference, &mut reply)
            .unwrap();
        let protected = decode(&reply[..n]).unwrap();
        assert!(protected.oscore().is_some());
        let mut opened = [0; 512];
        let actual = self
            .client
            .unprotect_response(&protected, expected_ref, &mut opened)
            .unwrap();
        assert_eq!(actual.code(), Code::CONTENT);
        assert_eq!(actual.ty(), Type::Acknowledgement);
        assert_eq!(actual.message_id(), MessageId::new(mid));
        assert_eq!(actual.token(), plain.token());
        assert_eq!(actual.options().collect::<Vec<_>>(), response_options);
        assert_eq!(actual.payload(), response_body);
        assert!(self.client.take(plain.token()).is_some());
        self.completed += 1;
    }
}

#[test]
fn pending_saturation_expiry_and_owner_churn_preserve_scheduled_protected_progress() {
    let server = identity(254);
    let peers: Vec<_> = (1..=5).map(identity).collect();
    let registry = Registry(
        peers
            .iter()
            .enumerate()
            .map(|(i, peer)| {
                PeerTrust::install(
                    &server,
                    peer.peer(),
                    TrustAnchor::genesis([(i + 1) as u8; 32]).unwrap(),
                    |_, _, _| Ok::<_, ()>(()),
                )
                .unwrap()
            })
            .collect(),
    );
    let mut cloud = Cloud::new(&server, 0, AdmissionLimits::default(), entropy(9)).unwrap();
    let mut first = finish(&mut cloud, &registry, &server, &peers[0], endpoint(1), 0);
    let mut second = finish(
        &mut cloud,
        &registry,
        &server,
        &peers[1],
        endpoint(2),
        1_000,
    );
    // Routing metadata cannot transfer authentication to a different owner.
    let cross_owner = first.request(9_000);
    assert_eq!(
        cloud
            .route_oscore(&cross_owner, endpoint(2), 1_000, &registry)
            .unwrap(),
        None
    );
    let mut refused_plaintext = [0; 512];
    assert!(
        second
            .server
            .unprotect_request(&decode(&cross_owner).unwrap(), &mut refused_plaintext)
            .is_err()
    );
    assert!(
        first
            .client
            .take(Token::from_checked(&9_000u16.to_be_bytes()))
            .is_some()
    );
    let (_abandoned, attack, cached) = begin(
        &mut cloud,
        &registry,
        &server,
        &peers[4],
        endpoint(5),
        2_000,
    );
    let mut sink = Sink::default();
    let mut refused = 0;
    // Explicit schedule: one hostile datagram, one admission flush, one complete
    // exchange for each established owner. No scheduler-independent claim.
    for step in 0..32u16 {
        let now = 2_001 + u64::from(step);
        let status = cloud
            .ingest(&attack, endpoint(5), now, &registry, no_entropy)
            .unwrap();
        refused += usize::from(status == Status::Ignored);
        cloud.flush(&mut sink, now, &registry).unwrap();
        if !sink.0.is_empty() {
            assert_eq!(sink.pop(endpoint(5)), cached);
        }
        assert_eq!(cloud.next_deadline(), Some(EXPIRY));
        first.complete(&mut cloud, &registry, now, 10_000 + step);
        second.complete(&mut cloud, &registry, now, 20_000 + step);
    }
    assert_eq!(
        refused, 26,
        "six cached sends remain after the initial two datagrams"
    );
    assert_eq!((first.completed, second.completed), (32, 32));

    let mut waiting =
        CoapProvisioner::start(&peers[2], server.peer(), SERVER, 3_000, entropy(5)).unwrap();
    waiting.flush(&mut sink, 3_000).unwrap();
    let waiting_m1 = sink.pop(SERVER);
    assert_eq!(
        cloud.ingest(&waiting_m1, endpoint(3), 3_000, &registry, no_entropy),
        Ok(Status::Ignored)
    );
    assert!(cloud.take_session(3_000, &registry).unwrap().is_none());
    cloud.flush(&mut sink, EXPIRY + 1_999, &registry).unwrap();
    assert!(sink.0.is_empty());
    assert_eq!(cloud.next_deadline(), Some(EXPIRY + 2_000));
    assert_eq!(
        cloud.ingest(
            &waiting_m1,
            endpoint(3),
            EXPIRY + 1_999,
            &registry,
            no_entropy
        ),
        Ok(Status::Ignored)
    );
    cloud.flush(&mut sink, EXPIRY + 2_000, &registry).unwrap();
    assert_eq!(cloud.next_deadline(), None);
    let now = EXPIRY + 2_000;
    let mut third = finish(&mut cloud, &registry, &server, &peers[2], endpoint(3), now);
    first.complete(&mut cloud, &registry, now, 11_000);
    second.complete(&mut cloud, &registry, now, 21_000);
    third.complete(&mut cloud, &registry, now, 31_000);

    let mut fourth =
        CoapProvisioner::start(&peers[3], server.peer(), SERVER, now, entropy(6)).unwrap();
    fourth.flush(&mut sink, now).unwrap();
    let fourth_m1 = sink.pop(SERVER);
    assert_eq!(
        cloud.ingest(&fourth_m1, endpoint(4), now, &registry, no_entropy),
        Ok(Status::Ignored)
    );
    assert!(cloud.release(first.association));
    assert!(!cloud.release(first.association));
    let stale = first.request(12_000);
    assert_eq!(
        cloud
            .route_oscore(&stale, endpoint(1), now, &registry)
            .unwrap(),
        None
    );
    let mut replacement = finish(
        &mut cloud,
        &registry,
        &server,
        &peers[3],
        endpoint(4),
        now + 1_000,
    );
    assert_ne!(
        replacement.association.local_connection_id(),
        first.association.local_connection_id()
    );
    second.complete(&mut cloud, &registry, now + 1_000, 22_000);
    third.complete(&mut cloud, &registry, now + 1_000, 32_000);
    replacement.complete(&mut cloud, &registry, now + 1_000, 42_000);
    assert_eq!(
        (
            first.completed,
            second.completed,
            third.completed,
            replacement.completed
        ),
        (33, 34, 2, 1)
    );
    if let Some(path) = std::env::var_os("COAPTIC_CLOUD_PROGRESS_REPORT") {
        let report = serde_json::json!({
            "schema": "coaptic-cloud-admission-progress/1", "passed": true,
            "association_slots": 3, "pending_slots": 1, "retained_slots": 3, "source_slots": 4,
            "hostile_datagrams": 32, "budget_refusals": refused, "cached_replies": 6,
            "cross_owner_protected_refusals": 1,
            "protected_completions_per_owner": [first.completed, second.completed, third.completed, replacement.completed],
            "request_body_bytes": 192, "response_body_bytes": 256,
            "pending_started_ms": 2000, "pending_original_expiry_ms": EXPIRY + 2000,
            "proofs": ["pending-full refusal", "no fresh entropy on repeated/refused requests", "original expiry without renewal",
                       "active-full refusal", "release and stale-route refusal", "replacement admission", "cross-owner route and authentication refusal", "exact authenticated bodies and metadata"],
            "limits": ["caller round-robin scheduling", "finite in-memory workload", "fixture entropy and installed trust",
                       "low-level OSCORE owners, not App capacity", "no socket, sustained availability, throughput or hardware claim"]
        });
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    println!(
        "finite admission qualification: 32 hostile packets, {refused} budget refusals, 70 complete protected responses; original expiry and released-route refusal passed; caller round-robin, no sustained-availability claim"
    );
}
