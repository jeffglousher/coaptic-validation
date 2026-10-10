mod support;
use coaptic::provisioning::{
    OperationId, ReceiptError, ReceiptStore, TelemetryOperation, TrustAnchor,
};
use coaptic_durable_host::{Authority, Error, Journal, Stage};
use std::cell::Cell;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{
    Barrier, OnceLock,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "coaptic-receipt-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> std::path::PathBuf {
        self.0.join("journal")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn operation(id: u8, payload: &[u8]) -> TelemetryOperation<'_> {
    TelemetryOperation::new(OperationId::new([id; 16]), [5; 32], Some(42), payload).unwrap()
}

#[test]
fn durable_duplicate_conflict_capacity_and_authorization() {
    let directory = Directory::new();
    let policy = support::policy(1);
    let authority = Authority::new(policy);
    let mut store = Journal::create(&directory.file(), authority.clone(), 1).unwrap();
    assert!(Journal::create(&directory.file(), authority.clone(), 1).is_err());
    assert!(matches!(
        Journal::open(&directory.file(), authority.clone()),
        Err(Error::Lock(_))
    ));
    let receipt = store
        .commit(&policy.anchor, &policy.principal, &operation(1, b"value"))
        .unwrap();
    assert_eq!(
        store
            .commit(&policy.anchor, &policy.principal, &operation(1, b"value"))
            .unwrap(),
        receipt
    );
    assert!(matches!(
        store.commit(&policy.anchor, &policy.principal, &operation(1, b"changed")),
        Err(ReceiptError::Conflict)
    ));
    assert!(matches!(
        store.commit(&policy.anchor, &policy.principal, &operation(2, b"value")),
        Err(ReceiptError::Capacity)
    ));
    assert!(matches!(
        store.commit(
            &policy.anchor,
            &support::policy(2).principal,
            &operation(1, b"value")
        ),
        Err(ReceiptError::Unauthorized)
    ));
    let wrong =
        TelemetryOperation::new(OperationId::new([1; 16]), [9; 32], Some(42), b"value").unwrap();
    assert!(matches!(
        store.commit(&policy.anchor, &policy.principal, &wrong),
        Err(ReceiptError::Unauthorized)
    ));
    let mut revoked = policy;
    revoked.anchor = TrustAnchor::from_parts([3; 32], 2, [6; 32]).unwrap();
    revoked.enabled = false;
    authority.replace(revoked).unwrap();
    assert!(authority.replace(policy).is_err());
    for anchor in [policy.anchor, revoked.anchor] {
        assert!(matches!(
            store.commit(&anchor, &policy.principal, &operation(1, b"value")),
            Err(ReceiptError::Unauthorized)
        ));
    }
    drop(store);
    let mut store = Journal::open(&directory.file(), authority.clone()).unwrap();
    assert_eq!(store.effects().unwrap(), 1);
    assert!(matches!(
        store.commit(&policy.anchor, &policy.principal, &operation(1, b"value")),
        Err(ReceiptError::Unauthorized)
    ));
    let mut restored = revoked;
    restored.anchor = TrustAnchor::from_parts([3; 32], 3, [8; 32]).unwrap();
    restored.enabled = true;
    authority.replace(restored).unwrap();
    assert_eq!(
        store
            .commit(&restored.anchor, &policy.principal, &operation(1, b"value"))
            .unwrap(),
        receipt
    );
    assert_eq!(store.effects().unwrap(), 1);
}

thread_local! { static FAIL: Cell<Option<Stage>> = const { Cell::new(None) }; }
fn fail_once(stage: Stage) -> std::io::Result<()> {
    if FAIL.with(|value| value.get()) == Some(stage) {
        FAIL.with(|value| value.set(None));
        Err(std::io::Error::other("injected persistence failure"))
    } else {
        Ok(())
    }
}

#[test]
fn failed_before_write_recovers_and_uncertain_commit_requires_reopen() {
    let directory = Directory::new();
    let policy = support::policy(1);
    let authority = Authority::new(policy);
    let mut store = Journal::create(&directory.file(), authority.clone(), 2).unwrap();
    store.set_checkpoint(fail_once);
    FAIL.with(|value| value.set(Some(Stage::BeforeWrite)));
    assert!(matches!(
        store.commit(&policy.anchor, &policy.principal, &operation(1, b"a")),
        Err(ReceiptError::Persistence(_))
    ));
    assert_eq!(store.effects().unwrap(), 0);
    let first = store
        .commit(&policy.anchor, &policy.principal, &operation(1, b"a"))
        .unwrap();
    FAIL.with(|value| value.set(Some(Stage::AfterSync)));
    assert!(matches!(
        store.commit(&policy.anchor, &policy.principal, &operation(2, b"b")),
        Err(ReceiptError::Persistence(_))
    ));
    assert!(matches!(
        store.commit(&policy.anchor, &policy.principal, &operation(2, b"b")),
        Err(ReceiptError::Persistence(Error::NeedsRecovery))
    ));
    assert!(matches!(store.effects(), Err(Error::NeedsRecovery)));
    drop(store);
    let mut store = Journal::open(&directory.file(), authority).unwrap();
    assert_eq!(store.effects().unwrap(), 2);
    assert_eq!(
        store
            .commit(&policy.anchor, &policy.principal, &operation(1, b"a"))
            .unwrap(),
        first
    );
    assert_eq!(
        store
            .commit(&policy.anchor, &policy.principal, &operation(2, b"b"))
            .unwrap()
            .sequence(),
        2
    );
    assert_eq!(store.effects().unwrap(), 2);
}

#[test]
fn identical_operation_ids_are_scoped_to_the_full_principal() {
    let directory = Directory::new();
    let first = support::policy(1);
    let authority = Authority::new(first);
    let mut store = Journal::create(&directory.file(), authority.clone(), 2).unwrap();
    let payload = [0xab; TelemetryOperation::MAX_PAYLOAD];
    let operation = operation(1, &payload);
    let receipt = store
        .commit(&first.anchor, &first.principal, &operation)
        .unwrap();
    let mut second = support::policy(2);
    second.anchor = TrustAnchor::from_parts([3; 32], 2, [6; 32]).unwrap();
    authority.replace(second).unwrap();
    assert!(matches!(
        store.commit(&first.anchor, &second.principal, &operation),
        Err(ReceiptError::Unauthorized)
    ));
    assert!(matches!(
        store.commit(&second.anchor, &first.principal, &operation),
        Err(ReceiptError::Unauthorized)
    ));
    let other = store
        .commit(&second.anchor, &second.principal, &operation)
        .unwrap();
    assert_eq!(receipt.sequence(), 1);
    assert_eq!(other.sequence(), 2);
    drop(store);
    let mut store = Journal::open(&directory.file(), authority).unwrap();
    assert_eq!(store.effects().unwrap(), 2);
    assert_eq!(
        store
            .commit(&second.anchor, &second.principal, &operation)
            .unwrap(),
        other
    );
}

#[test]
fn missing_truncated_corrupt_and_partial_storage_refuse_without_reset() {
    let directory = Directory::new();
    let policy = support::policy(1);
    let authority = Authority::new(policy);
    assert!(Journal::open(&directory.file(), authority.clone()).is_err());
    let mut store = Journal::create(&directory.file(), authority.clone(), 2).unwrap();
    store.set_checkpoint(fail_once);
    FAIL.with(|value| value.set(Some(Stage::PartialWrite)));
    assert!(matches!(
        store.commit(&policy.anchor, &policy.principal, &operation(1, b"a")),
        Err(ReceiptError::Persistence(_))
    ));
    drop(store);
    let original = std::fs::read(directory.file()).unwrap();
    assert!(matches!(
        Journal::open(&directory.file(), authority.clone()),
        Err(Error::Corrupt)
    ));
    assert_eq!(std::fs::read(directory.file()).unwrap(), original);
    for bytes in [&original[..10], &[0u8; 44][..]] {
        std::fs::write(directory.file(), bytes).unwrap();
        assert!(Journal::open(&directory.file(), authority.clone()).is_err());
        assert_eq!(std::fs::read(directory.file()).unwrap(), bytes);
    }
}

static FENCE: OnceLock<(Barrier, Barrier)> = OnceLock::new();
fn wait_at_sync(stage: Stage) -> std::io::Result<()> {
    if stage == Stage::BeforeSync {
        let (entered, release) = FENCE.get().unwrap();
        entered.wait();
        release.wait();
    }
    Ok(())
}

#[test]
fn policy_update_waits_for_effect_and_receipt_commit() {
    FENCE.set((Barrier::new(2), Barrier::new(2))).unwrap();
    let directory = Directory::new();
    let policy = support::policy(1);
    let authority = Authority::new(policy);
    let mut store = Journal::create(&directory.file(), authority.clone(), 2).unwrap();
    store.set_checkpoint(wait_at_sync);
    let commit = std::thread::spawn(move || {
        store
            .commit(&policy.anchor, &policy.principal, &operation(1, b"a"))
            .unwrap()
    });
    FENCE.get().unwrap().0.wait();
    let (send, receive) = mpsc::channel();
    let mut revoked = policy;
    revoked.enabled = false;
    revoked.anchor = TrustAnchor::from_parts([3; 32], 2, [6; 32]).unwrap();
    let updater = std::thread::spawn(move || {
        authority.replace(revoked).unwrap();
        send.send(()).unwrap();
    });
    assert!(receive.recv_timeout(Duration::from_millis(50)).is_err());
    FENCE.get().unwrap().1.wait();
    assert_eq!(commit.join().unwrap().sequence(), 1);
    receive.recv_timeout(Duration::from_secs(5)).unwrap();
    updater.join().unwrap();
}

fn fixture(action: &str, path: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_receipt_fixture"))
        .arg(action)
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn actual_process_termination_preserves_one_effect_after_lost_ack() {
    for stage in [
        Stage::BeforeWrite,
        Stage::PartialWrite,
        Stage::BeforeSync,
        Stage::AfterSync,
    ] {
        let directory = Directory::new();
        let path = directory.file();
        assert!(fixture("init", &path).status.success());
        let mut child = Command::new(env!("CARGO_BIN_EXE_receipt_fixture"))
            .arg("commit")
            .arg(&path)
            .env("COAPTIC_FIXTURE_STOP", format!("{stage:?}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let output = child.stdout.take().unwrap();
        let (send, receive) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(output).read_line(&mut line);
            let _ = send.send((result, line));
        });
        let ready = receive.recv_timeout(Duration::from_secs(10));
        child.kill().unwrap();
        let status = child.wait().unwrap();
        reader.join().unwrap();
        assert!(!status.success());
        let (result, line) = ready.unwrap();
        result.unwrap();
        assert_eq!(line.trim(), format!("checkpoint:{stage:?}"));
        let recovered = fixture("commit", &path);
        eprintln!(
            "process_stage={stage:?} killed={status:?} retry_status={:?} stdout={:?} stderr={:?}",
            recovered.status,
            String::from_utf8_lossy(&recovered.stdout),
            String::from_utf8_lossy(&recovered.stderr)
        );
        if stage == Stage::PartialWrite {
            assert!(!recovered.status.success());
            assert!(String::from_utf8_lossy(&recovered.stderr).contains("Corrupt"));
        } else {
            assert!(
                recovered.status.success(),
                "{}",
                String::from_utf8_lossy(&recovered.stderr)
            );
            assert_eq!(
                String::from_utf8_lossy(&recovered.stdout).trim(),
                "effects:1 receipt:1"
            );
            assert_eq!(
                String::from_utf8_lossy(&fixture("commit", &path).stdout).trim(),
                "effects:1 receipt:1"
            );
        }
    }
}
