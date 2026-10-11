mod support;

use coaptic::provisioning::{OperationId, Receipt, ReceiptStore, TelemetryOperation};
use coaptic::storage::DatagramIo;
use coaptic::{App, Code, ContentFormat, Endpoint, Response, resources};
use coaptic_durable_host::{Authority, Journal, Policy};
use coaptic_esphome_probe::{
    pending_telemetry as pending, protected_telemetry as runner, security_state as security,
};
use std::{cell::RefCell, collections::VecDeque, path::Path, rc::Rc};

#[derive(Clone, Default)]
struct Security(Rc<RefCell<Option<[u8; security::RECORD_BYTES]>>>);
impl security::Store for Security {
    fn read(&mut self) -> Result<Option<[u8; security::RECORD_BYTES]>, security::Error> {
        Ok(*self.0.borrow())
    }
    fn commit(&mut self, bytes: &[u8; security::RECORD_BYTES]) -> Result<(), security::Error> {
        *self.0.borrow_mut() = Some(*bytes);
        Ok(())
    }
}

#[derive(Default)]
struct PendingData {
    bytes: Option<[u8; pending::RECORD_BYTES]>,
    commits: usize,
    fail_at: Option<usize>,
}
#[derive(Clone, Default)]
struct Pending(Rc<RefCell<PendingData>>);
impl pending::Store for Pending {
    fn read(&mut self) -> Result<Option<[u8; pending::RECORD_BYTES]>, pending::Error> {
        Ok(self.0.borrow().bytes)
    }
    fn commit(&mut self, bytes: &[u8; pending::RECORD_BYTES]) -> Result<(), pending::Error> {
        let mut state = self.0.borrow_mut();
        state.commits += 1;
        state.bytes = Some(*bytes);
        if state.fail_at == Some(state.commits) {
            Err(pending::Error::Storage)
        } else {
            Ok(())
        }
    }
}

type Packets = Rc<RefCell<VecDeque<Vec<u8>>>>;
struct Io {
    local: Endpoint,
    incoming: Packets,
    outgoing: Packets,
}
impl DatagramIo for Io {
    type Error = ();
    fn recv(&mut self, bytes: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
        Ok(self.incoming.borrow_mut().pop_front().map(|wire| {
            bytes[..wire.len()].copy_from_slice(&wire);
            (wire.len(), self.local)
        }))
    }
    fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, ()> {
        self.outgoing.borrow_mut().push_back(bytes.to_vec());
        Ok(bytes.len())
    }
}
const CLIENT: Endpoint = Endpoint::v4([192, 0, 2, 1], 5683);
const SERVER: Endpoint = Endpoint::v4([192, 0, 2, 2], 5683);
const PAYLOAD: [u8; 1024] = [0x67; 1024];

fn fixture_credentials() -> security::Credentials {
    security::Credentials {
        secret: [0x19; 32],
        salt: [0x27; 16],
        context: [0x38; 16],
        sender: 1,
        recipient: 2,
    }
}
fn random(bytes: &mut [u8]) -> bool {
    getrandom::fill(bytes).is_ok()
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Success,
    LoseReply,
    WrongKey,
    BadReceipt,
    Refused,
    ClockRegression,
    Deadline,
}

fn exchange(
    path: &Path,
    policy: Policy,
    saved: Pending,
    client_state: Security,
    server_state: Security,
    mode: Mode,
) -> Result<Receipt, runner::Error> {
    let credentials = fixture_credentials();
    let mut peer_credentials = fixture_credentials();
    peer_credentials.sender = 2;
    peer_credentials.recipient = 1;
    let mut journal = Journal::open(path, Authority::new(policy)).unwrap();
    let server_state = if mode == Mode::WrongKey {
        peer_credentials.secret[0] ^= 1;
        let mut memory = Security::default();
        security::provision(&mut memory, &peer_credentials).unwrap();
        memory
    } else {
        server_state
    };
    let (mut security, context) =
        security::State::recover(server_state, &peer_credentials).unwrap();
    let c2s = Packets::default();
    let s2c = Packets::default();
    let server_io = Io {
        local: CLIENT,
        incoming: c2s.clone(),
        outgoing: s2c.clone(),
    };
    let client_io = Io {
        local: SERVER,
        incoming: s2c,
        outgoing: c2s,
    };
    let mut server = App::with_resources(resources::SmallDevice::new().deferred::<1>())
        .randomness(random)
        .oscore(context)
        .require_oscore_checkpoint()
        .bind(server_io)
        .unwrap();
    let mut polls = 0;
    let mut dispatched = false;
    let result = runner::run(
        client_io,
        random,
        || {
            polls += 1;
            if polls > 20 {
                return None;
            }
            if mode == Mode::ClockRegression && polls == 2 {
                return Some(0);
            }
            let now = polls;
            let mut work = None;
            let polled = server.poll_with_oscore_checkpoint_and_dispatch(
                now,
                |checkpoint| security.checkpoint(checkpoint).is_ok(),
                |request, handle| {
                    dispatched = true;
                    assert_ne!(mode as u8, Mode::WrongKey as u8);
                    assert_eq!(request.content_format(), Some(Ok(ContentFormat::new(42))));
                    assert_eq!(&request.payload()[..16], &[9; 16]);
                    assert_eq!(&request.payload()[16..], &PAYLOAD);
                    work = Some(handle.unwrap());
                    Response::deferred()
                },
            );
            if mode != Mode::WrongKey {
                polled.unwrap();
            }
            if let Some(handle) = work {
                let operation = TelemetryOperation::new(
                    OperationId::new([9; 16]),
                    policy.resource,
                    Some(42),
                    &PAYLOAD,
                )
                .unwrap();
                let receipt = journal
                    .commit(&policy.anchor, &policy.principal, &operation)
                    .unwrap();
                assert_eq!(journal.effects().unwrap(), 1);
                if mode == Mode::LoseReply {
                    return None;
                }
                if mode == Mode::Deadline {
                    return Some(now);
                }
                let mut bytes = receipt.encode();
                if mode == Mode::BadReceipt {
                    bytes[16] ^= 1;
                }
                let response = if mode == Mode::Refused {
                    Response::new(Code::FORBIDDEN)
                } else {
                    Response::new(Code::CHANGED).payload_copy(&bytes)
                };
                server.complete(handle, response, now).unwrap();
            }
            Some(now)
        },
        runner::Service {
            endpoint: SERVER,
            principal: policy.principal,
            resource: policy.resource,
            credentials: &credentials,
            timeout_ms: 10,
        },
        client_state,
        saved,
    );
    if mode == Mode::WrongKey || mode == Mode::ClockRegression {
        assert!(!dispatched);
    }
    result
}

#[test]
fn retained_adapter_refuses_bad_responses_and_recovers_lost_reply_without_duplicate_effect() {
    for ambiguous in [false, true] {
        let directory =
            std::env::temp_dir().join(format!("coaptic-pending-adapter-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("journal");
        let policy = support::policy(1);
        drop(Journal::create(&path, Authority::new(policy), 2).unwrap());
        let credentials = fixture_credentials();
        let mut peer_credentials = fixture_credentials();
        peer_credentials.sender = 2;
        peer_credentials.recipient = 1;
        let mut client = Security::default();
        let mut server = Security::default();
        security::provision(&mut client, &credentials).unwrap();
        security::provision(&mut server, &peer_credentials).unwrap();
        let mut saved = Pending::default();
        pending::provision(&mut saved, &credentials, policy.principal).unwrap();
        pending::Pending::recover(saved.clone(), &credentials, policy.principal)
            .unwrap()
            .begin(
                OperationId::new([9; 16]),
                policy.resource,
                Some(42),
                &PAYLOAD,
            )
            .unwrap();
        for (mode, expected) in [
            (Mode::LoseReply, runner::Error::Stopped),
            (Mode::WrongKey, runner::Error::Deadline),
            (
                Mode::BadReceipt,
                runner::Error::Pending(pending::Error::InvalidReceipt),
            ),
            (Mode::Refused, runner::Error::Refused),
            (Mode::ClockRegression, runner::Error::Clock),
            (Mode::Deadline, runner::Error::Deadline),
        ] {
            assert_eq!(
                exchange(
                    &path,
                    policy,
                    saved.clone(),
                    client.clone(),
                    server.clone(),
                    mode
                ),
                Err(expected)
            );
            let restored =
                pending::Pending::recover(saved.clone(), &credentials, policy.principal).unwrap();
            let operation = restored.pending().unwrap().unwrap();
            assert_eq!(operation.id(), OperationId::new([9; 16]));
            assert_eq!(operation.payload(), PAYLOAD);
            assert!(restored.completion().unwrap().is_none());
        }
        // Completion commit reaches storage but its acknowledgement is lost.
        if ambiguous {
            let fail_at = saved.0.borrow().commits + 2;
            saved.0.borrow_mut().fail_at = Some(fail_at);
            assert_eq!(
                exchange(
                    &path,
                    policy,
                    saved.clone(),
                    client.clone(),
                    server.clone(),
                    Mode::Success
                ),
                Err(runner::Error::Pending(pending::Error::Storage))
            );
            saved.0.borrow_mut().fail_at = None;
        }
        let receipt =
            exchange(&path, policy, saved.clone(), client, server, Mode::Success).unwrap();
        assert_eq!(receipt.sequence(), 1);
        for (resource, expected) in [
            (policy.resource, Ok(receipt)),
            ([0; 32], Err(runner::Error::Resource)),
        ] {
            assert_eq!(
                runner::run(
                    NoIo,
                    |_| panic!("completed operation needs no entropy"),
                    || panic!("completed operation needs no clock"),
                    runner::Service {
                        endpoint: SERVER,
                        principal: policy.principal,
                        resource,
                        credentials: &credentials,
                        timeout_ms: 10,
                    },
                    Security::default(),
                    saved.clone()
                ),
                expected
            );
        }
        let restored = pending::Pending::recover(saved, &credentials, policy.principal).unwrap();
        assert!(restored.pending().unwrap().is_none());
        assert_eq!(restored.completion().unwrap(), Some(receipt));
        assert_eq!(
            Journal::open(&path, Authority::new(policy))
                .unwrap()
                .effects()
                .unwrap(),
            1
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}

struct NoIo;
impl DatagramIo for NoIo {
    type Error = ();
    fn recv(&mut self, _: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
        panic!("preflight/completion must not receive")
    }
    fn send(&mut self, _: Endpoint, _: &[u8]) -> Result<usize, ()> {
        panic!("preflight/completion must not send")
    }
}

#[test]
fn missing_state_and_wrong_resource_refuse_before_entropy_clock_or_io() {
    let credentials = fixture_credentials();
    let policy = support::policy(1);
    let mut saved = Pending::default();
    let attempt = |saved, resource| {
        runner::run(
            NoIo,
            |_| panic!("preflight must not read entropy"),
            || panic!("preflight must not read clock"),
            runner::Service {
                endpoint: SERVER,
                principal: policy.principal,
                resource,
                credentials: &credentials,
                timeout_ms: 10,
            },
            Security::default(),
            saved,
        )
    };
    assert_eq!(
        attempt(saved.clone(), policy.resource),
        Err(runner::Error::Pending(pending::Error::Missing))
    );
    pending::provision(&mut saved, &credentials, policy.principal).unwrap();
    assert_eq!(
        attempt(saved.clone(), policy.resource),
        Err(runner::Error::NoPending)
    );
    pending::Pending::recover(saved.clone(), &credentials, policy.principal)
        .unwrap()
        .begin(
            OperationId::new([9; 16]),
            policy.resource,
            Some(42),
            &PAYLOAD,
        )
        .unwrap();
    assert_eq!(
        attempt(saved.clone(), [0; 32]),
        Err(runner::Error::Resource)
    );
    assert_eq!(
        attempt(saved.clone(), policy.resource),
        Err(runner::Error::Security(security::Error::Missing))
    );
    for (timeout_ms, start) in [(0, 0), (1, u64::MAX)] {
        let mut security = Security::default();
        security::provision(&mut security, &credentials).unwrap();
        assert_eq!(
            runner::run(
                NoIo,
                random,
                || Some(start),
                runner::Service {
                    endpoint: SERVER,
                    principal: policy.principal,
                    resource: policy.resource,
                    credentials: &credentials,
                    timeout_ms,
                },
                security,
                saved.clone()
            ),
            Err(runner::Error::Deadline)
        );
    }
}
