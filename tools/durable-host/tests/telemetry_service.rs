mod support;
use coaptic::provisioning::{OperationId, Receipt, TelemetryOperation};
use coaptic::storage::DatagramIo;
use coaptic::{App, Code, ContentFormat, Endpoint, profiles};
use coaptic_durable_host::{Authority, Journal, Policy, telemetry};
use coaptic_esphome_probe::security_state as security;
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

#[derive(Clone, Default)]
struct Memory(Rc<RefCell<Option<[u8; security::RECORD_BYTES]>>>);
impl security::Store for Memory {
    fn read(&mut self) -> Result<Option<[u8; security::RECORD_BYTES]>, security::Error> {
        Ok(*self.0.borrow())
    }
    fn commit(&mut self, bytes: &[u8; security::RECORD_BYTES]) -> Result<(), security::Error> {
        *self.0.borrow_mut() = Some(*bytes);
        Ok(())
    }
}
type Packets = Rc<RefCell<VecDeque<Vec<u8>>>>;
struct Io {
    peer: Endpoint,
    incoming: Packets,
    outgoing: Packets,
}
impl DatagramIo for Io {
    type Error = ();
    fn recv(&mut self, bytes: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
        Ok(self.incoming.borrow_mut().pop_front().map(|wire| {
            bytes[..wire.len()].copy_from_slice(&wire);
            (wire.len(), self.peer)
        }))
    }
    fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, ()> {
        self.outgoing.borrow_mut().push_back(bytes.to_vec());
        Ok(bytes.len())
    }
}
const CLIENT: Endpoint = Endpoint::v4([192, 0, 2, 1], 5683);
const SERVER: Endpoint = Endpoint::v4([192, 0, 2, 2], 5683);
fn credentials(server: bool) -> security::Credentials {
    security::Credentials {
        secret: [0x21; 32],
        salt: [0x43; 16],
        context: [0x65; 16],
        sender: if server { 2 } else { 1 },
        recipient: if server { 1 } else { 2 },
    }
}
fn random(bytes: &mut [u8]) -> bool {
    getrandom::fill(bytes).is_ok()
}
#[derive(Clone, Copy)]
enum Mode {
    Success,
    Drop,
    WrongKey,
    Plain,
    WrongPath,
    WrongFormat,
    Short,
    WrongPeer,
}
fn exchange(
    journal: &mut Journal,
    policy: Policy,
    client_store: Memory,
    server_store: Memory,
    mode: Mode,
) -> (telemetry::Report, Option<(Code, Vec<u8>)>) {
    let c2s = Packets::default();
    let s2c = Packets::default();
    let client_io = Io {
        peer: SERVER,
        incoming: s2c.clone(),
        outgoing: c2s.clone(),
    };
    let server_io = Io {
        peer: CLIENT,
        incoming: c2s,
        outgoing: s2c,
    };
    let mut credentials = credentials(false);
    let server_credentials = self::credentials(true);
    let client_store = if matches!(mode, Mode::WrongKey) {
        credentials.secret[0] ^= 1;
        let mut m = Memory::default();
        security::provision(&mut m, &credentials).unwrap();
        m
    } else {
        client_store
    };
    let (mut client_security, context) =
        security::State::recover(client_store, &credentials).unwrap();
    let builder = App::profile::<profiles::Constrained>()
        .block_wise::<false>()
        .randomness(random);
    let mut client = if matches!(mode, Mode::Plain) {
        builder.allow_plaintext().bind(client_io).unwrap()
    } else {
        builder
            .oscore(context)
            .require_oscore_checkpoint()
            .bind(client_io)
            .unwrap()
    };
    let mut wire = [7; 16 + 1024];
    wire[..16].fill(9);
    let payload = if matches!(mode, Mode::Short) {
        &wire[..15]
    } else {
        &wire[..]
    };
    let path = if matches!(mode, Mode::WrongPath) {
        "wrong"
    } else {
        "telemetry"
    };
    let format = if matches!(mode, Mode::WrongFormat) {
        43
    } else {
        42
    };
    let call = client
        .post(path)
        .to(SERVER)
        .payload(payload)
        .content_format(ContentFormat::new(format))
        .send(0)
        .unwrap();
    let mut output = [0; 56];
    let mut reply = None;
    let mut polls = 0;
    let report = telemetry::run(
        server_io,
        random,
        || {
            polls += 1;
            if polls > 30 || reply.is_some() {
                return None;
            }
            let _ = if matches!(mode, Mode::Plain) {
                client.poll(polls)
            } else {
                client.poll_with_oscore_checkpoint(polls, |c| client_security.checkpoint(c).is_ok())
            };
            if let Some(response) = client.take_response_into(call, &mut output).unwrap() {
                let response = response.unwrap();
                reply = Some((response.code(), response.payload().to_vec()));
            }
            Some(polls)
        },
        telemetry::Binding {
            peer: if matches!(mode, Mode::WrongPeer) {
                SERVER
            } else {
                CLIENT
            },
            credentials: &server_credentials,
            policy,
            content_format: Some(42),
            timeout_ms: 100,
            max_polls: 40,
            drop_first_receipt: matches!(mode, Mode::Drop),
        },
        server_store,
        journal,
    )
    .unwrap();
    (report, reply)
}
#[test]
fn durable_service_refuses_invalid_traffic_then_recovers_and_deduplicates_after_reopen() {
    let path =
        std::env::temp_dir().join(format!("coaptic-telemetry-service-{}", std::process::id()));
    let policy = support::policy(1);
    let authority = Authority::new(policy);
    let mut journal = Journal::create(&path, authority.clone(), 2).unwrap();
    let mut c = Memory::default();
    let mut s = Memory::default();
    security::provision(&mut c, &credentials(false)).unwrap();
    security::provision(&mut s, &credentials(true)).unwrap();
    for mode in [
        Mode::WrongKey,
        Mode::Plain,
        Mode::WrongPath,
        Mode::WrongFormat,
        Mode::Short,
        Mode::WrongPeer,
    ] {
        let (report, reply) = exchange(&mut journal, policy, c.clone(), s.clone(), mode);
        assert_eq!(report.effects, 0);
        assert_eq!(report.receipts, 0);
        assert!(!reply.is_some_and(|r| r.0 == Code::CHANGED));
    }
    let (report, reply) = exchange(&mut journal, policy, c.clone(), s.clone(), Mode::Drop);
    assert_eq!(report.effects, 1);
    assert_eq!(report.dropped_receipts, 1);
    assert!(reply.is_none());
    drop(journal);
    let mut journal = Journal::open(&path, authority.clone()).unwrap();
    let (report, reply) = exchange(&mut journal, policy, c.clone(), s.clone(), Mode::Success);
    assert_eq!(report.effects, 1);
    assert_eq!(report.receipts, 1);
    let (code, bytes) = reply.unwrap();
    assert_eq!(code, Code::CHANGED);
    let receipt = Receipt::decode(&bytes).unwrap();
    let payload = [7; 1024];
    let operation = TelemetryOperation::new(
        OperationId::new([9; 16]),
        policy.resource,
        Some(42),
        &payload,
    )
    .unwrap();
    assert_eq!(receipt.digest(), operation.digest());
    let (store, generation, digest) = policy.anchor.parts();
    authority
        .replace(Policy {
            anchor: coaptic::provisioning::TrustAnchor::from_parts(store, generation + 1, digest)
                .unwrap(),
            enabled: false,
            ..policy
        })
        .unwrap();
    let (report, reply) = exchange(&mut journal, policy, c, s, Mode::Success);
    assert_eq!(report.effects, 1);
    assert_eq!(report.receipts, 0);
    assert_eq!(reply.unwrap().0, Code::FORBIDDEN);
    drop(journal);
    std::fs::remove_file(path).unwrap();
}
struct NoIo;
impl DatagramIo for NoIo {
    type Error = ();
    fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
        panic!("unexpected receive")
    }
    fn send(&mut self, _: Endpoint, _: &[u8]) -> Result<usize, ()> {
        panic!("unexpected send")
    }
}
struct FaultStore {
    inner: Memory,
    commits: usize,
    fail_at: usize,
}
impl security::Store for FaultStore {
    fn read(&mut self) -> Result<Option<[u8; security::RECORD_BYTES]>, security::Error> {
        self.inner.read()
    }
    fn commit(&mut self, bytes: &[u8; security::RECORD_BYTES]) -> Result<(), security::Error> {
        self.commits += 1;
        if self.commits == self.fail_at {
            Err(security::Error::Unavailable)
        } else {
            self.inner.commit(bytes)
        }
    }
}
#[test]
fn service_clock_and_storage_refusals_precede_network_and_recover() {
    let path = std::env::temp_dir().join(format!(
        "coaptic-host-service-bounds-{}",
        std::process::id()
    ));
    let policy = support::policy(1);
    let mut journal = Journal::create(&path, Authority::new(policy), 1).unwrap();
    let credentials = credentials(true);
    let mut state = Memory::default();
    security::provision(&mut state, &credentials).unwrap();
    let before = *state.0.borrow();
    let binding = |timeout_ms| max_binding(&credentials, policy, timeout_ms);
    assert!(matches!(
        telemetry::run(
            NoIo,
            random,
            || Some(0),
            binding(0),
            state.clone(),
            &mut journal
        ),
        Err(telemetry::Error::Bounds)
    ));
    assert!(matches!(
        telemetry::run(
            NoIo,
            random,
            || Some(u64::MAX),
            binding(1),
            state.clone(),
            &mut journal
        ),
        Err(telemetry::Error::Bounds)
    ));
    assert_eq!(*state.0.borrow(), before);
    let report = telemetry::run(
        NoIo,
        random,
        || None,
        binding(1),
        state.clone(),
        &mut journal,
    )
    .unwrap();
    assert_eq!(report.polls, 0);
    assert_eq!(*state.0.borrow(), before);
    assert!(matches!(
        telemetry::run(
            NoIo,
            random,
            || Some(0),
            binding(1),
            FaultStore {
                inner: state.clone(),
                commits: 0,
                fail_at: 1
            },
            &mut journal
        ),
        Err(telemetry::Error::Security(security::Error::Unavailable))
    ));
    let mut n = 0;
    assert!(matches!(
        telemetry::run(
            NoIo,
            random,
            || {
                n += 1;
                Some(if n == 1 { 10 } else { 9 })
            },
            binding(100),
            state.clone(),
            &mut journal
        ),
        Err(telemetry::Error::Clock)
    ));
    let mut n = 0;
    let report = telemetry::run(
        NoIo,
        random,
        || {
            n += 1;
            Some(if n == 1 { 0 } else { 1 })
        },
        binding(1),
        state,
        &mut journal,
    )
    .unwrap();
    assert_eq!(report.polls, 0);
    assert_eq!(report.effects, 0);
    drop(journal);
    std::fs::remove_file(path).unwrap();
}
fn max_binding(
    credentials: &security::Credentials,
    policy: Policy,
    timeout_ms: u64,
) -> telemetry::Binding<'_> {
    telemetry::Binding {
        peer: CLIENT,
        credentials,
        policy,
        content_format: Some(42),
        timeout_ms,
        max_polls: 10,
        drop_first_receipt: false,
    }
}
fn protected_request() -> Vec<u8> {
    use coaptic::message::{Message, MessageId, Opt, Token, Type};
    let c = credentials(false);
    let mut context = coaptic::oscore::SecurityContext::derive(c.parameters()).unwrap();
    let format = ContentFormat::new(42).encode();
    let options = [Opt::uri_path("telemetry"), Opt::content_format(&format)];
    let message = Message::new(Type::Confirmable, Code::POST, MessageId::new(11))
        .with_token(Token::new(b"receipt").unwrap())
        .with_options(&options)
        .with_payload(&[9; 16]);
    let mut wire = [0; 1152];
    let length = context.protect_request(&message, &mut wire).unwrap();
    wire[..length].to_vec()
}
#[test]
fn checkpoint_and_ambiguous_journal_refuse_receipt_then_reopen_recovers() {
    let path = std::env::temp_dir().join(format!(
        "coaptic-host-service-uncertain-{}",
        std::process::id()
    ));
    let policy = support::policy(1);
    let authority = Authority::new(policy);
    let mut journal = Journal::create(&path, authority.clone(), 2).unwrap();
    let credentials = credentials(true);
    let mut state = Memory::default();
    security::provision(&mut state, &credentials).unwrap();
    let wire = protected_request();
    let incoming = Packets::default();
    incoming.borrow_mut().push_back(wire.clone());
    let outgoing = Packets::default();
    let mut ticks = 0;
    let result = telemetry::run(
        Io {
            peer: CLIENT,
            incoming,
            outgoing: outgoing.clone(),
        },
        random,
        || {
            ticks += 1;
            Some(ticks)
        },
        max_binding(&credentials, policy, 100),
        FaultStore {
            inner: state.clone(),
            commits: 0,
            fail_at: 2,
        },
        &mut journal,
    );
    assert!(matches!(result, Err(telemetry::Error::Checkpoint)));
    assert_eq!(journal.effects().unwrap(), 0);
    assert!(outgoing.borrow().is_empty());
    // The failed checkpoint did not authorize application dispatch. Retry that
    // same wire after state recovery, then simulate an ambiguous synced commit.
    journal.set_checkpoint(|stage| {
        if stage == coaptic_durable_host::Stage::AfterSync {
            Err(std::io::Error::other(
                "injected lost commit acknowledgement",
            ))
        } else {
            Ok(())
        }
    });
    let incoming = Packets::default();
    incoming.borrow_mut().push_back(wire);
    let outgoing = Packets::default();
    let mut ticks = 0;
    let result = telemetry::run(
        Io {
            peer: CLIENT,
            incoming,
            outgoing: outgoing.clone(),
        },
        random,
        || {
            ticks += 1;
            Some(ticks)
        },
        max_binding(&credentials, policy, 100),
        state.clone(),
        &mut journal,
    );
    assert!(matches!(result, Err(telemetry::Error::Journal(_))));
    for packet in outgoing.borrow().iter() {
        assert_eq!(
            coaptic::message::decode(packet).unwrap().code(),
            Code::EMPTY
        );
    }
    assert!(journal.effects().is_err());
    drop(journal);
    let journal = Journal::open(&path, authority).unwrap();
    assert_eq!(journal.effects().unwrap(), 1);
    drop(journal);
    std::fs::remove_file(path).unwrap();
}
