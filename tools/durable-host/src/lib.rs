//! Bounded consuming reference for durable telemetry effects and receipts.
//!
//! The application effect is the complete telemetry row in this journal. Its
//! receipt is part of that same checksummed record; no external actuator or
//! second database is claimed atomic. File `sync_all` is the commit boundary.
//! This reference qualifies process recovery, not power loss or hostile rollback.
//! Checksums detect accidental corruption; the caller protects the file from
//! malicious replacement and supplies independently current policy on startup.

use coaptic::provisioning::{
    OperationId, Principal, Receipt, ReceiptError, ReceiptStore, TelemetryOperation, TrustAnchor,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub const MAX_ROWS: usize = 16;
const HEADER: usize = 44;
const DATA: usize = 1149;
const RECORD: usize = DATA + 32;
const MAGIC: &[u8; 8] = b"COAPRC01";

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Lock(String),
    Corrupt,
    Policy,
    NeedsRecovery,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Caller-installed authoritative permission, separate from receipt storage.
/// This value must come from an authenticated current-policy provider.
#[derive(Clone, Copy)]
pub struct Policy {
    pub anchor: TrustAnchor,
    pub principal: Principal,
    pub resource: [u8; 32],
    pub enabled: bool,
}

/// Serializes policy updates against the entire effect/receipt transaction.
#[derive(Clone)]
pub struct Authority(Arc<Mutex<Policy>>);
impl Authority {
    pub fn new(current: Policy) -> Self {
        Self(Arc::new(Mutex::new(current)))
    }
    /// Same authority, strictly newer generation. The caller authenticates updates.
    pub fn replace(&self, next: Policy) -> Result<(), Error> {
        let mut current = self.0.lock().map_err(|_| Error::Policy)?;
        let (store, generation, _) = current.anchor.parts();
        let (next_store, next_generation, _) = next.anchor.parts();
        if store != next_store || next_generation <= generation {
            return Err(Error::Policy);
        }
        *current = next;
        Ok(())
    }
}

/// Fault-injection boundaries for the qualification driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    BeforeWrite,
    PartialWrite,
    BeforeSync,
    AfterSync,
}
pub type Checkpoint = fn(Stage) -> std::io::Result<()>;

#[derive(Clone)]
struct Row {
    bytes: [u8; RECORD],
}
impl Row {
    fn new(principal: &Principal, operation: &TelemetryOperation<'_>, sequence: u64) -> Self {
        let mut bytes = [0; RECORD];
        bytes[..8].copy_from_slice(&sequence.to_be_bytes());
        bytes[8..40].copy_from_slice(principal.fingerprint());
        bytes[40..56].copy_from_slice(operation.id().as_bytes());
        bytes[56..88].copy_from_slice(operation.resource());
        if let Some(format) = operation.content_format() {
            bytes[88] = 1;
            bytes[89..91].copy_from_slice(&format.to_be_bytes());
        }
        bytes[91..93].copy_from_slice(&(operation.payload().len() as u16).to_be_bytes());
        bytes[93..93 + operation.payload().len()].copy_from_slice(operation.payload());
        bytes[1117..1149].copy_from_slice(operation.digest());
        let digest = blake3::hash(&bytes[..DATA]);
        bytes[DATA..].copy_from_slice(digest.as_bytes());
        Self { bytes }
    }
    fn id(&self) -> OperationId {
        OperationId::new(self.bytes[40..56].try_into().unwrap())
    }
    fn receipt(&self) -> Receipt {
        Receipt::from_parts(
            self.id(),
            self.bytes[1117..1149].try_into().unwrap(),
            u64::from_be_bytes(self.bytes[..8].try_into().unwrap()),
        )
        .unwrap()
    }
    fn validate(&self, sequence: u64) -> Result<(), Error> {
        let bytes = &self.bytes;
        if blake3::hash(&bytes[..DATA]).as_bytes() != &bytes[DATA..]
            || u64::from_be_bytes(bytes[..8].try_into().unwrap()) != sequence
        {
            return Err(Error::Corrupt);
        }
        let len = u16::from_be_bytes(bytes[91..93].try_into().unwrap()) as usize;
        if len > TelemetryOperation::MAX_PAYLOAD || bytes[93 + len..1117].iter().any(|b| *b != 0) {
            return Err(Error::Corrupt);
        }
        let format = match bytes[88] {
            0 if bytes[89..91] == [0, 0] => None,
            1 => Some(u16::from_be_bytes(bytes[89..91].try_into().unwrap())),
            _ => return Err(Error::Corrupt),
        };
        let operation = TelemetryOperation::new(
            self.id(),
            bytes[56..88].try_into().unwrap(),
            format,
            &bytes[93..93 + len],
        )
        .map_err(|_| Error::Corrupt)?;
        if operation.digest() != &bytes[1117..1149] {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}

/// Exclusively owned bounded journal. Missing or malformed storage never resets.
pub struct Journal {
    file: File,
    authority: Authority,
    rows: [Option<Row>; MAX_ROWS],
    len: usize,
    capacity: usize,
    uncertain: bool,
    checkpoint: Checkpoint,
}

impl Drop for Journal {
    fn drop(&mut self) {
        // On Unix, a concurrent fork can temporarily inherit the same open file
        // description until exec. Closing our handle alone then leaves its flock
        // held by the child. Explicitly release our ownership before closing.
        // No journal operations may follow Drop; close remains the fallback if
        // unlock fails. A subsequent owner still has to acquire the file lock.
        let _ = self.file.unlock();
    }
}

impl Journal {
    /// Explicit first provisioning only; refuses an existing path.
    pub fn create(path: &Path, authority: Authority, capacity: usize) -> Result<Self, Error> {
        if !(1..=MAX_ROWS).contains(&capacity) {
            return Err(Error::Corrupt);
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.try_lock()
            .map_err(|error| Error::Lock(error.to_string()))?;
        let mut header = [0; HEADER];
        header[..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&(capacity as u32).to_be_bytes());
        let digest = blake3::hash(&header[..12]);
        header[12..].copy_from_slice(digest.as_bytes());
        file.write_all(&header)?;
        file.sync_all()?;
        Ok(Self::empty(file, authority, capacity))
    }

    fn empty(file: File, authority: Authority, capacity: usize) -> Self {
        Self {
            file,
            authority,
            rows: std::array::from_fn(|_| None),
            len: 0,
            capacity,
            uncertain: false,
            checkpoint: |_| Ok(()),
        }
    }

    /// Recover complete records under exclusive ownership. Truncated/corrupt
    /// journals refuse; no automatic truncation, reset or operation-ID replacement.
    pub fn open(path: &Path, authority: Authority) -> Result<Self, Error> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        file.try_lock()
            .map_err(|error| Error::Lock(error.to_string()))?;
        let length = file.metadata()?.len();
        if length < HEADER as u64 || length > (HEADER + MAX_ROWS * RECORD) as u64 {
            return Err(Error::Corrupt);
        }
        let mut header = [0; HEADER];
        file.read_exact(&mut header)?;
        if &header[..8] != MAGIC || blake3::hash(&header[..12]).as_bytes() != &header[12..] {
            return Err(Error::Corrupt);
        }
        let capacity = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
        if !(1..=MAX_ROWS).contains(&capacity)
            || !(length - HEADER as u64).is_multiple_of(RECORD as u64)
        {
            return Err(Error::Corrupt);
        }
        let count = (length as usize - HEADER) / RECORD;
        if count > capacity {
            return Err(Error::Corrupt);
        }
        let mut store = Self::empty(file, authority, capacity);
        for index in 0..count {
            let mut row = Row { bytes: [0; RECORD] };
            store.file.read_exact(&mut row.bytes)?;
            row.validate(index as u64 + 1)?;
            if store.rows[..index]
                .iter()
                .flatten()
                .any(|old| old.bytes[8..56] == row.bytes[8..56])
            {
                return Err(Error::Corrupt);
            }
            store.rows[index] = Some(row);
        }
        // A complete uncertain write becomes durable before any recovered receipt.
        store.file.sync_all()?;
        store.len = count;
        Ok(store)
    }

    /// Number of committed application effects (one complete telemetry row each).
    pub fn effects(&self) -> Result<usize, Error> {
        if self.uncertain {
            Err(Error::NeedsRecovery)
        } else {
            Ok(self.len)
        }
    }

    /// Install a bounded test checkpoint. Production integrations should retain
    /// the default no-op; callbacks run while the authoritative policy fence is held.
    pub fn set_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.checkpoint = checkpoint;
    }
}

impl ReceiptStore for Journal {
    type Error = Error;
    fn commit(
        &mut self,
        expected: &TrustAnchor,
        principal: &Principal,
        operation: &TelemetryOperation<'_>,
    ) -> Result<Receipt, ReceiptError<Error>> {
        if self.uncertain {
            return Err(ReceiptError::Persistence(Error::NeedsRecovery));
        }
        let policy = self
            .authority
            .0
            .lock()
            .map_err(|_| ReceiptError::Persistence(Error::Policy))?;
        if !policy.enabled
            || policy.anchor != *expected
            || policy.principal != *principal
            || policy.resource != *operation.resource()
        {
            return Err(ReceiptError::Unauthorized);
        }
        if let Some(row) = self.rows[..self.len]
            .iter()
            .flatten()
            .find(|row| &row.bytes[8..40] == principal.fingerprint() && row.id() == operation.id())
        {
            let receipt = row.receipt();
            return if receipt.digest() == operation.digest() {
                Ok(receipt)
            } else {
                Err(ReceiptError::Conflict)
            };
        }
        if self.len == self.capacity {
            return Err(ReceiptError::Capacity);
        }
        (self.checkpoint)(Stage::BeforeWrite)
            .map_err(|error| ReceiptError::Persistence(Error::Io(error)))?;
        let row = Row::new(principal, operation, self.len as u64 + 1);
        let write = (|| -> std::io::Result<()> {
            let end = self.file.seek(SeekFrom::End(0))?;
            if end != (HEADER + self.len * RECORD) as u64 {
                return Err(std::io::Error::other(
                    "journal changed under exclusive ownership",
                ));
            }
            self.file.write_all(&row.bytes[..RECORD / 2])?;
            (self.checkpoint)(Stage::PartialWrite)?;
            self.file.write_all(&row.bytes[RECORD / 2..])?;
            (self.checkpoint)(Stage::BeforeSync)?;
            self.file.sync_all()?;
            (self.checkpoint)(Stage::AfterSync)?;
            Ok(())
        })();
        if let Err(error) = write {
            self.uncertain = true;
            return Err(ReceiptError::Persistence(Error::Io(error)));
        }
        let receipt = row.receipt();
        self.rows[self.len] = Some(row);
        self.len += 1;
        // Keep the mutex guard live until both effect and receipt are committed.
        drop(policy);
        Ok(receipt)
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    #[test]
    fn drop_releases_lock_even_while_an_inherited_description_remains_open() {
        // A duplicated descriptor models the open-file-description lifetime
        // inherited by a concurrent fork, without unsafe code or timing races.
        let public = [
            0x02, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96,
        ];
        let authority = Authority::new(Policy {
            anchor: TrustAnchor::from_parts([3; 32], 1, [4; 32]).unwrap(),
            principal: coaptic::provisioning::PinnedPeer::from_public_key(&public, 1)
                .unwrap()
                .principal(),
            resource: [5; 32],
            enabled: true,
        });
        let path = std::env::temp_dir().join(format!("coaptic-lock-drop-{}", std::process::id()));
        let store = Journal::create(&path, authority.clone(), 1).unwrap();
        let inherited = store.file.try_clone().unwrap();
        assert!(matches!(
            Journal::open(&path, authority.clone()),
            Err(Error::Lock(_))
        ));
        drop(store);
        let reopened = Journal::open(&path, authority).unwrap();
        assert_eq!(reopened.effects().unwrap(), 0);
        drop(inherited);
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }
}
