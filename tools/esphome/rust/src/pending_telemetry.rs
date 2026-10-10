//! One caller-owned durable telemetry operation, without allocation.
//!
//! Provision offline, persist pending work before sending it, and authenticate
//! the intended service's successful response before accepting its receipt.
//! Completion is exposed only after durable commit and exact readback. An
//! ambiguous write poisons the session until recovery; it never creates new work.
//! The caller exclusively owns storage and supplies current authorization.
//! HMAC detects corruption/substitution, not a valid old snapshot. Flash power
//! loss, rollback freshness and key custody require separate qualification.
//!
//! Enable `telemetry` explicitly. Use a storage record separate from the existing
//! 100-byte OSCORE reservation/replay record; never reuse its platform key/file.
//! Recovery re-commits and reads back a validated record to reconcile a previous
//! uncertain durability result. It refuses unavailable or malformed storage.
//! The live network service does not automatically invoke this API.
//!
//! The caller issues a unique ID, calls [`Pending::begin`], then transmits only
//! the operation returned by [`Pending::pending`]. Retries and fresh security
//! sessions use those same bytes. After current-policy and service authentication,
//! pass the complete successful response to [`Pending::accept_authenticated_receipt`].
//! Only a durable [`Pending::completion`] permits the next operation. Runtime,
//! scheduling, credentials, storage exclusivity and pending data capture remain
//! caller-owned. This record bounds stored content, not whole-task stack usage.
#![forbid(unsafe_code)]

use super::security_state::Credentials;
use coaptic::provisioning::{OperationId, Principal, Receipt, TelemetryOperation};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub const RECORD_BYTES: usize = 1214;
const TAG: usize = 1182;
const RECEIPT: usize = 1126;
const MAGIC: &[u8; 8] = b"COAPPND1";
const _: () = assert!(TelemetryOperation::MAX_PAYLOAD == 1024);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Missing,
    Present,
    Storage,
    Corrupt,
    Poisoned,
    Pending,
    NotPending,
    InvalidOperation,
    InvalidReceipt,
    IdReused,
    Stale,
    Exhausted,
}

/// Fixed-record durable storage, exclusively owned for the live session.
/// Wrong lengths/read errors must fail. Missing data never means "start over".
/// Read-before-write is not compare/exchange or multi-writer synchronization.
pub trait Store {
    fn read(&mut self) -> Result<Option<[u8; RECORD_BYTES]>, Error>;
    /// Return success only after the platform's declared durable commit boundary.
    fn commit(&mut self, record: &[u8; RECORD_BYTES]) -> Result<(), Error>;
}

fn mac(credentials: &Credentials, domain: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&credentials.secret).expect("fixed key length");
    mac.update(domain);
    mac.update(&credentials.salt);
    mac.update(&credentials.context);
    mac.update(&[credentials.sender, credentials.recipient]);
    mac
}

fn identity(credentials: &Credentials, principal: Principal) -> [u8; 32] {
    let mut mac = mac(credentials, b"Coaptic pending owner v1\0");
    mac.update(principal.fingerprint());
    mac.finalize().into_bytes().into()
}

fn sign(bytes: &mut [u8; RECORD_BYTES], credentials: &Credentials) {
    let mut mac = mac(credentials, b"Coaptic pending record v1\0");
    mac.update(&bytes[..TAG]);
    bytes[TAG..].copy_from_slice(&mac.finalize().into_bytes());
}

fn operation(bytes: &[u8; RECORD_BYTES]) -> Result<TelemetryOperation<'_>, Error> {
    let length = u16::from_be_bytes(bytes[100..102].try_into().unwrap()) as usize;
    if length > TelemetryOperation::MAX_PAYLOAD
        || bytes[102 + length..RECEIPT].iter().any(|byte| *byte != 0)
    {
        return Err(Error::Corrupt);
    }
    let format = match bytes[97] {
        0 if bytes[98..100] == [0, 0] => None,
        1 => Some(u16::from_be_bytes(bytes[98..100].try_into().unwrap())),
        _ => return Err(Error::Corrupt),
    };
    TelemetryOperation::new(
        OperationId::new(bytes[49..65].try_into().unwrap()),
        bytes[65..97].try_into().unwrap(),
        format,
        &bytes[102..102 + length],
    )
    .map_err(|_| Error::Corrupt)
}

fn validate(
    bytes: &[u8; RECORD_BYTES],
    credentials: &Credentials,
    principal: Principal,
) -> Result<(), Error> {
    let mut mac = mac(credentials, b"Coaptic pending record v1\0");
    mac.update(&bytes[..TAG]);
    mac.verify_slice(&bytes[TAG..])
        .map_err(|_| Error::Corrupt)?;
    if &bytes[..8] != MAGIC
        || bytes[8..40] != identity(credentials, principal)
        || u64::from_be_bytes(bytes[40..48].try_into().unwrap()) == 0
    {
        return Err(Error::Corrupt);
    }
    match bytes[48] {
        0 if bytes[49..TAG].iter().all(|byte| *byte == 0) => Ok(()),
        1 if bytes[RECEIPT..TAG].iter().all(|byte| *byte == 0) => operation(bytes).map(|_| ()),
        2 => operation(bytes)?
            .accept_receipt(&bytes[RECEIPT..TAG])
            .map(|_| ())
            .map_err(|_| Error::Corrupt),
        _ => Err(Error::Corrupt),
    }
}

/// Explicit offline first provisioning. Existing storage always refuses.
pub fn provision(
    store: &mut impl Store,
    credentials: &Credentials,
    principal: Principal,
) -> Result<(), Error> {
    if store.read()?.is_some() {
        return Err(Error::Present);
    }
    let mut bytes = [0; RECORD_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..40].copy_from_slice(&identity(credentials, principal));
    bytes[40..48].copy_from_slice(&1u64.to_be_bytes());
    sign(&mut bytes, credentials);
    store.commit(&bytes)?;
    if store.read()? != Some(bytes) {
        return Err(Error::Storage);
    }
    Ok(())
}

/// At most one pending operation; the record also retains its final receipt.
/// Caller-issued operation IDs must be unique for this full principal. The last
/// completed ID cannot be reused; this bounded record is not an all-history set.
pub struct Pending<'a, S> {
    store: S,
    credentials: &'a Credentials,
    bytes: [u8; RECORD_BYTES],
    poisoned: bool,
}

impl<'a, S: Store> Pending<'a, S> {
    pub fn recover(
        mut store: S,
        credentials: &'a Credentials,
        principal: Principal,
    ) -> Result<Self, Error> {
        let bytes = store.read()?.ok_or(Error::Missing)?;
        validate(&bytes, credentials, principal)?;
        // A previous ambiguous write may be readable but not yet durable. Reaffirm
        // the validated record before exposing pending work or completed receipts.
        store.commit(&bytes)?;
        if store.read()? != Some(bytes) {
            return Err(Error::Storage);
        }
        Ok(Self {
            store,
            credentials,
            bytes,
            poisoned: false,
        })
    }

    pub fn into_store(self) -> S {
        self.store
    }

    /// Only durably recorded work is eligible for transmission. Recovery returns
    /// the same ID and every content byte; it never regenerates an operation ID.
    pub fn pending(&self) -> Result<Option<TelemetryOperation<'_>>, Error> {
        self.ready()?;
        if self.bytes[48] == 1 {
            operation(&self.bytes).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn completion(&self) -> Result<Option<Receipt>, Error> {
        self.ready()?;
        if self.bytes[48] == 2 {
            Receipt::decode(&self.bytes[RECEIPT..TAG])
                .map(Some)
                .ok_or(Error::Corrupt)
        } else {
            Ok(None)
        }
    }

    pub fn begin(
        &mut self,
        id: OperationId,
        resource: [u8; 32],
        format: Option<u16>,
        payload: &[u8],
    ) -> Result<(), Error> {
        self.ready()?;
        if self.bytes[48] == 1 {
            return Err(Error::Pending);
        }
        if self.bytes[48] == 2 && &self.bytes[49..65] == id.as_bytes() {
            return Err(Error::IdReused);
        }
        TelemetryOperation::new(id, resource, format, payload)
            .map_err(|_| Error::InvalidOperation)?;
        let mut next = self.next()?;
        next[48..TAG].fill(0);
        next[48] = 1;
        next[49..65].copy_from_slice(id.as_bytes());
        next[65..97].copy_from_slice(&resource);
        if let Some(format) = format {
            next[97] = 1;
            next[98..100].copy_from_slice(&format.to_be_bytes());
        }
        next[100..102].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        next[102..102 + payload.len()].copy_from_slice(payload);
        self.persist(next)
    }

    /// The caller must first authenticate a successful response from the intended
    /// service for this operation's originating principal under current policy.
    /// This method matches complete receipt bytes; it is not network authentication.
    pub fn accept_authenticated_receipt(&mut self, bytes: &[u8]) -> Result<Receipt, Error> {
        self.ready()?;
        if self.bytes[48] == 0 {
            return Err(Error::NotPending);
        }
        let receipt = operation(&self.bytes)?
            .accept_receipt(bytes)
            .map_err(|_| Error::InvalidReceipt)?;
        if self.bytes[48] == 2 {
            return if self.completion()? == Some(receipt) {
                Ok(receipt)
            } else {
                Err(Error::InvalidReceipt)
            };
        }
        let mut next = self.next()?;
        next[48] = 2;
        next[RECEIPT..TAG].copy_from_slice(&receipt.encode());
        self.persist(next)?;
        Ok(receipt)
    }

    fn ready(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }

    fn next(&self) -> Result<[u8; RECORD_BYTES], Error> {
        let generation = u64::from_be_bytes(self.bytes[40..48].try_into().unwrap())
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let mut next = self.bytes;
        next[40..48].copy_from_slice(&generation.to_be_bytes());
        Ok(next)
    }

    fn persist(&mut self, mut next: [u8; RECORD_BYTES]) -> Result<(), Error> {
        sign(&mut next, self.credentials);
        // Conservative poison covers failed preflight reads as well as ambiguous
        // commits/readback. Recovery is the only way to regain transmission eligibility.
        self.poisoned = true;
        if self.store.read()? != Some(self.bytes) {
            return Err(Error::Stale);
        }
        self.store.commit(&next)?;
        if self.store.read()? != Some(next) {
            return Err(Error::Storage);
        }
        self.bytes = next;
        self.poisoned = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coaptic::provisioning::PinnedPeer;
    use std::{cell::RefCell, rc::Rc};

    #[derive(Clone, Copy, Default)]
    enum Fault {
        #[default]
        None,
        BeforeWrite,
        AfterWrite,
        PartialWrite,
        CorruptReadback,
        MissingReadback,
    }
    #[derive(Default)]
    struct Memory {
        record: Option<[u8; RECORD_BYTES]>,
        commits: usize,
        fault: Fault,
        fail_read: bool,
    }
    #[derive(Clone, Default)]
    struct Backend(Rc<RefCell<Memory>>);
    impl Store for Backend {
        fn read(&mut self) -> Result<Option<[u8; RECORD_BYTES]>, Error> {
            let mut memory = self.0.borrow_mut();
            if core::mem::take(&mut memory.fail_read) {
                return Err(Error::Storage);
            }
            Ok(memory.record)
        }
        fn commit(&mut self, record: &[u8; RECORD_BYTES]) -> Result<(), Error> {
            let mut memory = self.0.borrow_mut();
            memory.commits += 1;
            match core::mem::take(&mut memory.fault) {
                Fault::BeforeWrite => return Err(Error::Storage),
                Fault::PartialWrite => {
                    let bytes = memory.record.get_or_insert([0; RECORD_BYTES]);
                    bytes[..RECORD_BYTES / 2].copy_from_slice(&record[..RECORD_BYTES / 2]);
                    return Err(Error::Storage);
                }
                Fault::AfterWrite => {
                    memory.record = Some(*record);
                    return Err(Error::Storage);
                }
                Fault::CorruptReadback => {
                    let mut bytes = *record;
                    bytes[TAG] ^= 1;
                    memory.record = Some(bytes);
                    return Ok(());
                }
                Fault::MissingReadback => memory.fail_read = true,
                Fault::None => (),
            }
            memory.record = Some(*record);
            Ok(())
        }
    }
    fn credentials() -> Credentials {
        // Public, in-memory qualification fixture only; never deployed credentials.
        Credentials {
            secret: [0x55; 32],
            salt: [0x66; 16],
            context: [0x77; 16],
            sender: 1,
            recipient: 2,
        }
    }
    fn principal(kid: u8) -> Principal {
        let public = [
            0x02, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96,
        ];
        PinnedPeer::from_public_key(&public, kid)
            .unwrap()
            .principal()
    }
    fn initialized(credentials: &Credentials) -> Backend {
        let mut backend = Backend::default();
        provision(&mut backend, credentials, principal(1)).unwrap();
        backend
    }
    fn receipt(pending: &Pending<'_, Backend>) -> Receipt {
        let op = pending.pending().unwrap().unwrap();
        Receipt::from_parts(op.id(), *op.digest(), 7).unwrap()
    }
    #[test]
    fn complete_operation_and_receipt_survive_recovery_without_replacement() {
        let credentials = credentials();
        let backend = initialized(&credentials);
        let mut pending = Pending::recover(backend.clone(), &credentials, principal(1)).unwrap();
        let payload = [0xab; 1024];
        let id = OperationId::new([9; 16]);
        pending.begin(id, [3; 32], Some(42), &payload).unwrap();
        let expected = receipt(&pending);
        drop(pending);
        let mut recovered = Pending::recover(backend.clone(), &credentials, principal(1)).unwrap();
        let op = recovered.pending().unwrap().unwrap();
        assert_eq!(op.id(), id);
        assert_eq!(op.resource(), &[3; 32]);
        assert_eq!(op.content_format(), Some(42));
        assert_eq!(op.payload(), payload);
        let before = backend.0.borrow().record;
        assert_eq!(
            recovered.begin(OperationId::new([8; 16]), [3; 32], None, b"new"),
            Err(Error::Pending)
        );
        assert_eq!(backend.0.borrow().record, before);
        assert_eq!(
            recovered.accept_authenticated_receipt(&expected.encode()),
            Ok(expected)
        );
        let mut completed =
            Pending::recover(recovered.into_store(), &credentials, principal(1)).unwrap();
        assert!(completed.pending().unwrap().is_none());
        assert_eq!(completed.completion(), Ok(Some(expected)));
        assert_eq!(
            completed.accept_authenticated_receipt(&expected.encode()),
            Ok(expected)
        );
        assert_eq!(
            completed.begin(id, [3; 32], None, b"new"),
            Err(Error::IdReused)
        );
        completed
            .begin(OperationId::new([10; 16]), [3; 32], None, b"next")
            .unwrap();
        assert_eq!(completed.pending().unwrap().unwrap().payload(), b"next");
    }
    #[test]
    fn invalid_content_and_receipts_refuse_without_storage_mutation() {
        let credentials = credentials();
        let backend = initialized(&credentials);
        let mut pending = Pending::recover(backend.clone(), &credentials, principal(1)).unwrap();
        let before = backend.0.borrow().record;
        assert_eq!(
            pending.begin(OperationId::new([1; 16]), [3; 32], None, &[0; 1025]),
            Err(Error::InvalidOperation)
        );
        assert_eq!(backend.0.borrow().record, before);
        pending
            .begin(OperationId::new([1; 16]), [3; 32], None, b"")
            .unwrap();
        let expected = receipt(&pending);
        let before = backend.0.borrow().record;
        let mut changed = expected.encode();
        changed[16] ^= 1;
        for bytes in [&expected.encode()[..55], &changed[..], &[0; 57][..]] {
            assert_eq!(
                pending.accept_authenticated_receipt(bytes),
                Err(Error::InvalidReceipt)
            );
            assert_eq!(backend.0.borrow().record, before);
        }
        pending
            .accept_authenticated_receipt(&expected.encode())
            .unwrap();
    }
    #[test]
    fn missing_corrupt_wrong_owner_and_wrong_context_never_reinitialize() {
        let credentials = credentials();
        let mut absent = Backend::default();
        assert!(matches!(
            Pending::recover(absent.clone(), &credentials, principal(1)),
            Err(Error::Missing)
        ));
        provision(&mut absent, &credentials, principal(1)).unwrap();
        let before = absent.0.borrow().record;
        assert_eq!(
            provision(&mut absent, &credentials, principal(1)),
            Err(Error::Present)
        );
        assert!(matches!(
            Pending::recover(absent.clone(), &credentials, principal(2)),
            Err(Error::Corrupt)
        ));
        let mut wrong = super::tests::credentials();
        wrong.context[0] ^= 1;
        assert!(matches!(
            Pending::recover(absent.clone(), &wrong, principal(1)),
            Err(Error::Corrupt)
        ));
        assert_eq!(absent.0.borrow().record, before);
        absent.0.borrow_mut().record.as_mut().unwrap()[70] ^= 1;
        let corrupt = absent.0.borrow().record;
        assert!(matches!(
            Pending::recover(absent.clone(), &credentials, principal(1)),
            Err(Error::Corrupt)
        ));
        assert_eq!(absent.0.borrow().record, corrupt);
    }
    #[test]
    fn every_write_boundary_poison_refuses_until_explicit_supported_recovery() {
        for completing in [false, true] {
            for fault in [
                Fault::BeforeWrite,
                Fault::AfterWrite,
                Fault::PartialWrite,
                Fault::CorruptReadback,
                Fault::MissingReadback,
            ] {
                let credentials = credentials();
                let backend = initialized(&credentials);
                let mut pending =
                    Pending::recover(backend.clone(), &credentials, principal(1)).unwrap();
                let mut expected = None;
                if completing {
                    pending
                        .begin(OperationId::new([1; 16]), [3; 32], None, b"same")
                        .unwrap();
                    expected = Some(receipt(&pending));
                }
                backend.0.borrow_mut().fault = fault;
                let outcome = if let Some(expected) = expected {
                    pending
                        .accept_authenticated_receipt(&expected.encode())
                        .map(|_| ())
                } else {
                    pending.begin(OperationId::new([1; 16]), [3; 32], None, b"same")
                };
                assert!(outcome.is_err());
                assert_eq!(pending.pending().err(), Some(Error::Poisoned));
                assert_eq!(pending.completion(), Err(Error::Poisoned));
                assert_eq!(
                    pending.begin(OperationId::new([2; 16]), [3; 32], None, b"replacement"),
                    Err(Error::Poisoned)
                );
                let recovered = Pending::recover(pending.into_store(), &credentials, principal(1));
                if matches!(fault, Fault::PartialWrite | Fault::CorruptReadback) {
                    assert!(matches!(recovered, Err(Error::Corrupt)));
                    continue;
                }
                let mut recovered = recovered.unwrap();
                if completing {
                    if recovered.pending().unwrap().is_some() {
                        recovered
                            .accept_authenticated_receipt(&expected.unwrap().encode())
                            .unwrap();
                    }
                    assert_eq!(recovered.completion(), Ok(expected));
                } else {
                    if recovered.pending().unwrap().is_none() {
                        recovered
                            .begin(OperationId::new([1; 16]), [3; 32], None, b"same")
                            .unwrap();
                    }
                    assert_eq!(
                        recovered.pending().unwrap().unwrap().id(),
                        OperationId::new([1; 16])
                    );
                    assert_eq!(recovered.pending().unwrap().unwrap().payload(), b"same");
                }
            }
        }
    }
    #[test]
    fn failed_recovery_and_stale_writers_cannot_expose_eligible_work() {
        let credentials = credentials();
        let backend = initialized(&credentials);
        backend.0.borrow_mut().fault = Fault::BeforeWrite;
        assert!(matches!(
            Pending::recover(backend.clone(), &credentials, principal(1)),
            Err(Error::Storage)
        ));
        let mut first = Pending::recover(backend.clone(), &credentials, principal(1)).unwrap();
        let mut stale = Pending::recover(backend.clone(), &credentials, principal(1)).unwrap();
        first
            .begin(OperationId::new([1; 16]), [3; 32], None, b"first")
            .unwrap();
        let before = backend.0.borrow().record;
        assert_eq!(
            stale.begin(OperationId::new([2; 16]), [3; 32], None, b"second"),
            Err(Error::Stale)
        );
        assert_eq!(stale.pending().err(), Some(Error::Poisoned));
        assert_eq!(backend.0.borrow().record, before);
    }

    #[test]
    fn provisioning_failures_are_recovered_without_implicit_reinitialization() {
        for fault in [
            Fault::BeforeWrite,
            Fault::AfterWrite,
            Fault::PartialWrite,
            Fault::CorruptReadback,
            Fault::MissingReadback,
        ] {
            let credentials = credentials();
            let mut backend = Backend::default();
            backend.0.borrow_mut().fault = fault;
            assert_eq!(
                provision(&mut backend, &credentials, principal(1)),
                Err(Error::Storage)
            );
            let recovered = Pending::recover(backend.clone(), &credentials, principal(1));
            match fault {
                Fault::BeforeWrite => assert!(matches!(recovered, Err(Error::Missing))),
                Fault::PartialWrite | Fault::CorruptReadback => {
                    assert!(matches!(recovered, Err(Error::Corrupt)))
                }
                _ => assert!(recovered.unwrap().pending().unwrap().is_none()),
            }
            if backend.0.borrow().record.is_some() {
                assert_eq!(
                    provision(&mut backend, &credentials, principal(1)),
                    Err(Error::Present)
                );
            }
        }
    }

    #[test]
    fn generation_exhaustion_and_preflight_read_failure_are_explicit() {
        let credentials = credentials();
        let backend = initialized(&credentials);
        {
            let mut memory = backend.0.borrow_mut();
            let bytes = memory.record.as_mut().unwrap();
            bytes[40..48].copy_from_slice(&u64::MAX.to_be_bytes());
            sign(bytes, &credentials);
        }
        let mut pending = Pending::recover(backend.clone(), &credentials, principal(1)).unwrap();
        let before = backend.0.borrow().record;
        assert_eq!(
            pending.begin(OperationId::new([1; 16]), [3; 32], None, b"new"),
            Err(Error::Exhausted)
        );
        assert_eq!(backend.0.borrow().record, before);
        let backend = initialized(&credentials);
        let mut pending = Pending::recover(backend.clone(), &credentials, principal(1)).unwrap();
        let before = backend.0.borrow().record;
        backend.0.borrow_mut().fail_read = true;
        assert_eq!(
            pending.begin(OperationId::new([1; 16]), [3; 32], None, b"new"),
            Err(Error::Storage)
        );
        assert_eq!(pending.pending().err(), Some(Error::Poisoned));
        assert_eq!(backend.0.borrow().record, before);
        let mut recovered =
            Pending::recover(pending.into_store(), &credentials, principal(1)).unwrap();
        recovered
            .begin(OperationId::new([1; 16]), [3; 32], None, b"new")
            .unwrap();
    }
}
