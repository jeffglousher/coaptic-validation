mod support;

use coaptic::oscore::{DeriveParams, SecurityContext};
use coaptic::provisioning::{OperationId, Receipt, ReceiptError, ReceiptStore, TelemetryOperation};
use coaptic::storage::UdpSocketIo;
use coaptic::{App, Code, ContentFormat, Endpoint, Response, resources};
use coaptic_durable_host::{Authority, Journal, Policy};
use coaptic_esphome_probe::{
    pending_telemetry::{self, Error as PendingError, Pending, RECORD_BYTES, Store},
    security_state::Credentials,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::UdpSocket,
    path::Path,
    time::{Duration, Instant},
};

// Each reconnect provisions fresh ephemeral pairwise keys. The fixture's trusted
// mapping assigns this one protected context to the full principal in Policy.
// This is not enrollment, EDHOC authentication or retained-key restart proof.
fn exchange(
    path: &Path,
    policy: Policy,
    pending: &TelemetryOperation<'_>,
    lose_reply: bool,
    wrong_key: bool,
    expected: Code,
) -> Option<Receipt> {
    let mut journal = Journal::open(path, Authority::new(policy)).unwrap();
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).unwrap();
    let context = |sender: &[u8], recipient: &[u8], key: &[u8]| {
        SecurityContext::derive(DeriveParams {
            master_secret: key,
            master_salt: &[],
            sender_id: sender,
            recipient_id: recipient,
            id_context: &[],
        })
        .unwrap()
    };
    let server_context = context(&[2], &[1], &secret);
    if wrong_key {
        secret[0] ^= 1;
    }
    let client_context = context(&[1], &[2], &secret);
    secret.fill(0);
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let peer = Endpoint::from(socket.local_addr().unwrap());
    let mut server = App::with_resources(resources::SmallDevice::new().deferred::<1>())
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .oscore(server_context)
        .bind(UdpSocketIo::new(socket, [0; 1153]).unwrap())
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut client = App::with_resources(resources::SmallDevice::new())
        .randomness(|bytes| getrandom::fill(bytes).is_ok())
        .oscore(client_context)
        .bind(UdpSocketIo::new(socket, [0; 1153]).unwrap())
        .unwrap();
    let mut wire = [0; 16 + TelemetryOperation::MAX_PAYLOAD];
    wire[..16].copy_from_slice(pending.id().as_bytes());
    wire[16..16 + pending.payload().len()].copy_from_slice(pending.payload());
    let call = client
        .post("telemetry")
        .to(peer)
        .content_format(ContentFormat::new(42))
        .payload(&wire[..16 + pending.payload().len()])
        .send(0)
        .unwrap();
    let clock = Instant::now();
    let mut output = [0; 56];
    let mut dispatched = false;
    loop {
        let now = clock.elapsed().as_millis() as u64;
        let mut work = None;
        let polled = server.poll_with(now, |request, candidate| {
            dispatched = true;
            assert!(!wrong_key, "unauthenticated request reached application");
            assert_eq!(request.content_format(), Some(Ok(ContentFormat::new(42))));
            assert_eq!(request.payload(), &wire[..16 + pending.payload().len()]);
            let mut bytes = [0; 16 + TelemetryOperation::MAX_PAYLOAD];
            bytes[..request.payload().len()].copy_from_slice(request.payload());
            work = Some((candidate.unwrap(), bytes, request.payload().len()));
            Response::deferred()
        });
        if !wrong_key {
            polled.unwrap();
        }
        if let Some((handle, bytes, length)) = work {
            // Blocking persistence occurs after polling, with one bounded work item.
            let operation = TelemetryOperation::new(
                OperationId::new(bytes[..16].try_into().unwrap()),
                policy.resource,
                Some(42),
                &bytes[16..length],
            )
            .unwrap();
            let result = journal.commit(&policy.anchor, &policy.principal, &operation);
            if lose_reply {
                assert!(result.is_ok());
                assert_eq!(journal.effects().unwrap(), 1);
                println!("protected lost reply: committed one effect; pending ID/content retained");
                return None;
            }
            let response = match result {
                Ok(receipt) => Response::new(Code::CHANGED).payload_copy(&receipt.encode()),
                Err(ReceiptError::Unauthorized) => Response::new(Code::FORBIDDEN),
                Err(ReceiptError::Conflict) => Response::new(Code::CONFLICT),
                other => panic!("unexpected persistence outcome: {other:?}"),
            };
            server.complete(handle, response, now).unwrap();
        }
        client.poll(now).unwrap();
        if let Some(response) = client.take_response_into(call, &mut output).unwrap() {
            let response = response.unwrap();
            assert!(!wrong_key);
            assert_eq!(response.code(), expected);
            assert_eq!(journal.effects().unwrap(), 1);
            if expected == Code::CHANGED {
                // App authenticated the response under this intended service's
                // fresh context and bound it to this outgoing Call before exposure.
                let receipt = pending.accept_receipt(response.payload()).unwrap();
                println!("protected receipt accepted: sequence=1 effects=1");
                return Some(receipt);
            }
            assert!(pending.accept_receipt(response.payload()).is_err());
            println!("protected refusal: {expected:?}; pending operation unchanged");
            return None;
        }
        if wrong_key && clock.elapsed() >= Duration::from_millis(200) {
            assert!(!dispatched);
            assert_eq!(journal.effects().unwrap(), 1);
            println!("wrong-key refusal: no application dispatch or accepted receipt");
            return None;
        }
        assert!(
            clock.elapsed() < Duration::from_secs(5),
            "protected receipt timed out"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn protected_reconnect_retains_complete_pending_work_and_authenticates_receipt() {
    let directory =
        std::env::temp_dir().join(format!("coaptic-receipt-network-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("journal");
    let policy = support::policy(1);
    drop(Journal::create(&path, Authority::new(policy), 2).unwrap());
    let payload = [0x67; TelemetryOperation::MAX_PAYLOAD];
    let pending_path = directory.join("pending");
    let mut credentials = Credentials {
        secret: [0; 32],
        salt: [0; 16],
        context: [0; 16],
        sender: 1,
        recipient: 2,
    };
    getrandom::fill(&mut credentials.secret).unwrap();
    getrandom::fill(&mut credentials.salt).unwrap();
    getrandom::fill(&mut credentials.context).unwrap();
    // This independent storage context survives each freshly keyed network session.
    let mut store = PendingFile::open(&pending_path, true);
    pending_telemetry::provision(&mut store, &credentials, policy.principal).unwrap();
    let mut saved = Pending::recover(store, &credentials, policy.principal).unwrap();
    saved
        .begin(
            OperationId::new([9; 16]),
            policy.resource,
            Some(42),
            &payload,
        )
        .unwrap();
    exchange(
        &path,
        policy,
        &saved.pending().unwrap().unwrap(),
        true,
        false,
        Code::CHANGED,
    );
    drop(saved);
    let mut saved = Pending::recover(
        PendingFile::open(&pending_path, false),
        &credentials,
        policy.principal,
    )
    .unwrap();
    let pending = saved.pending().unwrap().unwrap();
    assert_eq!(pending.id(), OperationId::new([9; 16]));
    assert_eq!(pending.payload(), &payload);
    exchange(&path, policy, &pending, false, true, Code::CHANGED);
    let revoked = Policy {
        enabled: false,
        ..policy
    };
    exchange(&path, revoked, &pending, false, false, Code::FORBIDDEN);
    let receipt = exchange(&path, policy, &pending, false, false, Code::CHANGED).unwrap();
    let changed =
        TelemetryOperation::new(pending.id(), policy.resource, Some(42), b"changed").unwrap();
    exchange(&path, policy, &changed, false, false, Code::CONFLICT);
    assert_eq!(
        exchange(&path, policy, &pending, false, false, Code::CHANGED),
        Some(receipt)
    );
    // exchange exposes the receipt only after App authenticates the successful
    // intended-service reply; storage completion must survive a separate reopen.
    saved
        .accept_authenticated_receipt(&receipt.encode())
        .unwrap();
    drop(saved);
    let completed = Pending::recover(
        PendingFile::open(&pending_path, false),
        &credentials,
        policy.principal,
    )
    .unwrap();
    assert!(completed.pending().unwrap().is_none());
    assert_eq!(completed.completion(), Ok(Some(receipt)));
    drop(completed);
    println!("pending file reopened: same complete operation, durable receipt, one journal effect");
    std::fs::remove_dir_all(directory).unwrap();
}

// Qualification-only caller backend. File sync/readback is a host boundary,
// not evidence for power loss, durable directory creation or hostile rollback.
struct PendingFile(File);
impl PendingFile {
    fn open(path: &Path, provision: bool) -> Self {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(provision)
            .open(path)
            .unwrap();
        file.try_lock().unwrap();
        Self(file)
    }
}
impl Drop for PendingFile {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
impl Store for PendingFile {
    fn read(&mut self) -> Result<Option<[u8; RECORD_BYTES]>, PendingError> {
        let len = self.0.metadata().map_err(|_| PendingError::Storage)?.len();
        if len == 0 {
            return Ok(None);
        }
        if len != RECORD_BYTES as u64 {
            return Err(PendingError::Corrupt);
        }
        self.0
            .seek(SeekFrom::Start(0))
            .map_err(|_| PendingError::Storage)?;
        let mut bytes = [0; RECORD_BYTES];
        self.0
            .read_exact(&mut bytes)
            .map_err(|_| PendingError::Storage)?;
        Ok(Some(bytes))
    }
    fn commit(&mut self, bytes: &[u8; RECORD_BYTES]) -> Result<(), PendingError> {
        self.0
            .seek(SeekFrom::Start(0))
            .map_err(|_| PendingError::Storage)?;
        self.0.write_all(bytes).map_err(|_| PendingError::Storage)?;
        self.0.sync_all().map_err(|_| PendingError::Storage)
    }
}
