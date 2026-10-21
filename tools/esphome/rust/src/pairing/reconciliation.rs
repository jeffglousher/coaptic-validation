//! Receipt-only repair while revoked. The local host authenticates current-owner
//! approval and the original service's existing journal row; no effect is run here.
//! Initial repair authenticates the originating grant against retained work.
//! After rebinding, retries authenticate only the exact completed operation and
//! receipt under the current tombstone, not the original grant's history.

use super::*;
use crate::pending_telemetry::{Metadata, Pending};
use coaptic::provisioning::{PairingChallenge, PairingError, Receipt};

impl Device {
    fn unchanged(&self, store: &mut impl Store) -> Result<(), Error> {
        let mut bytes = Zeroizing::new([0; STORE_BYTES]);
        let len = store.read(&mut bytes)?;
        if len != self.stored_len || bytes[..len] != self.stored[..self.stored_len] {
            return Err(Error::Storage);
        }
        Ok(())
    }

    fn retained<S: Store>(
        &self,
        store: &mut S,
        prior: &PairingRecord,
    ) -> Result<(Metadata, bool), Error> {
        let current = self.pairing.checkpoint();
        current
            .validate_reconciliation_prior(prior)
            .map_err(|_| Error::Pending)?;
        if prior
            .policy()
            .is_none_or(|policy| *policy.resource_policy() != permissions(true))
        {
            return Err(Error::Pending);
        }
        self.unchanged(store)?;
        let bytes = store.pending_read()?.ok_or(Error::Pending)?;
        let principal = self.identity.peer().principal();
        // A completed current-bound record is the durable retry checkpoint after
        // both phases succeeded but the local response was lost.
        if let Ok(Some(metadata)) = Pending::<PendingStore<'_, S>>::metadata_bound(
            &bytes,
            pending_binding(&self.private, current),
            principal,
        ) {
            if metadata.receipt.is_some() && metadata.resource == telemetry_resource() {
                return Ok((metadata, true));
            }
            return Err(Error::Pending);
        }
        let metadata = Pending::<PendingStore<'_, S>>::metadata_bound(
            &bytes,
            pending_binding(&self.private, prior),
            principal,
        )
        .map_err(|_| Error::Pending)?
        .ok_or(Error::Pending)?;
        if metadata.resource != telemetry_resource() {
            return Err(Error::Pending);
        }
        Ok((metadata, false))
    }

    pub(super) fn pending_reply(
        &self,
        store: &mut impl Store,
        prior: &PairingRecord,
    ) -> CommissioningReply {
        match self.retained(store, prior) {
            Ok((metadata, _)) => CommissioningReply::Pending {
                id: metadata.id,
                resource: metadata.resource,
                digest: metadata.digest,
                receipt: metadata.receipt,
            },
            Err(_) => CommissioningReply::Refused(6),
        }
    }

    pub(super) fn reconcile_receipt(
        &mut self,
        store: &mut impl Store,
        challenge: &PairingChallenge,
        prior: &PairingRecord,
        receipt: Receipt,
        now: u64,
    ) -> Result<Receipt, PairingCommitError<Error>> {
        let (metadata, current_bound) = self
            .retained(store, prior)
            .map_err(|_| PairingCommitError::State(PairingError::Binding))?;
        if metadata.id != receipt.id()
            || &metadata.digest != receipt.digest()
            || metadata.receipt.is_some_and(|previous| previous != receipt)
        {
            return Err(PairingCommitError::State(PairingError::Binding));
        }
        let private = &*self.private;
        let principal = self.identity.peer().principal();
        let expected = &self.stored[..self.stored_len];
        self.pairing.reconcile(challenge, prior, now, |current| {
            {
                let binding = pending_binding(private, if current_bound { current } else { prior });
                let mut pending =
                    Pending::recover_bound(PendingStore(&mut *store), binding, principal)
                        .map_err(|_| Error::Storage)?;
                pending
                    .accept_authenticated_receipt(&receipt.encode())
                    .map_err(|_| Error::Storage)?;
                if !current_bound {
                    pending
                        .rebind_completed(pending_binding(private, current), principal)
                        .map_err(|_| Error::Storage)?;
                }
            }
            let mut bytes = Zeroizing::new([0; STORE_BYTES]);
            let len = store.read(&mut bytes)?;
            if len != expected.len() || bytes[..len] != *expected {
                return Err(Error::Storage);
            }
            Ok(())
        })?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending_telemetry::RECORD_BYTES;
    use coaptic::provisioning::{EnrollmentPolicy, OperationId};

    #[derive(Default)]
    struct Memory {
        identity: Vec<u8>,
        pending: Option<[u8; RECORD_BYTES]>,
        writes: usize,
        fail: Option<(usize, bool)>,
        corrupt: Option<usize>,
        replacement: Option<(usize, Vec<u8>)>,
    }
    impl Store for Memory {
        fn read(&mut self, out: &mut [u8; STORE_BYTES]) -> Result<usize, Error> {
            out[..self.identity.len()].copy_from_slice(&self.identity);
            Ok(self.identity.len())
        }
        fn commit(&mut self, old: &[u8], next: &[u8]) -> Result<(), Error> {
            if old != self.identity {
                return Err(Error::Storage);
            }
            self.identity = next.to_vec();
            Ok(())
        }
        fn pending_read(&mut self) -> Result<Option<[u8; RECORD_BYTES]>, Error> {
            Ok(self.pending)
        }
        fn pending_commit(&mut self, bytes: &[u8; RECORD_BYTES]) -> Result<(), Error> {
            self.writes += 1;
            if self.fail == Some((self.writes, false)) {
                return Err(Error::Storage);
            }
            self.pending = Some(*bytes);
            if self.corrupt == Some(self.writes) {
                self.pending.as_mut().unwrap()[RECORD_BYTES - 1] ^= 1;
            }
            if self
                .replacement
                .as_ref()
                .is_some_and(|(at, _)| *at == self.writes)
            {
                self.identity = self.replacement.take().unwrap().1;
            }
            if self.fail == Some((self.writes, true)) {
                return Err(Error::Storage);
            }
            Ok(())
        }
    }
    fn random(out: &mut [u8]) -> bool {
        out.fill(1);
        true
    }
    fn persist(device: &mut Device, store: &mut Memory) {
        let mut bytes = Zeroizing::new([0; STORE_BYTES]);
        let len = encode_store(
            &device.private,
            device.identity.peer().kid(),
            device.pairing.checkpoint(),
            device.endpoint,
            &mut bytes,
        )
        .unwrap();
        store
            .commit(&device.stored[..device.stored_len], &bytes[..len])
            .unwrap();
        device.stored = bytes;
        device.stored_len = len;
    }
    fn revoked() -> (Device, Memory, PairingRecord, Receipt) {
        let mut store = Memory::default();
        let mut device = Device::initialize(&mut store, 17, random).unwrap();
        let peer = Identity::from_private_key([2; 32], 18).unwrap().peer();
        let challenge = device.pairing.begin(&device.identity, 0, random).unwrap();
        device
            .pairing
            .pair(
                &challenge,
                EnrollmentPolicy::new(peer, [7; 32], permissions(true)).unwrap(),
                1,
                |old, next| {
                    prepare_pending(&mut store, &device.private, &device.identity, old, next)
                },
            )
            .unwrap();
        device.endpoint = Some(Endpoint::v4([192, 0, 2, 1], 5683));
        persist(&mut device, &mut store);
        let prior = device.pairing.checkpoint().clone();
        let receipt = {
            let mut pending = Pending::recover_bound(
                PendingStore(&mut store),
                pending_binding(&device.private, &prior),
                device.identity.peer().principal(),
            )
            .unwrap();
            pending
                .begin(
                    OperationId::new([3; 16]),
                    telemetry_resource(),
                    Some(60),
                    b"original retained effect",
                )
                .unwrap();
            let operation = pending.pending().unwrap().unwrap();
            Receipt::from_parts(operation.id(), *operation.digest(), 42).unwrap()
        };
        let challenge = device.pairing.begin(&device.identity, 2, random).unwrap();
        device
            .pairing
            .revoke(&challenge, &[7; 32], 3, |old, next| {
                prepare_pending(&mut store, &device.private, &device.identity, old, next)
            })
            .unwrap();
        persist(&mut device, &mut store);
        (device, store, prior, receipt)
    }

    #[test]
    fn revoked_receipt_reconciliation_preserves_identity_and_lost_reply_is_idempotent() {
        let (mut device, mut store, prior, receipt) = revoked();
        let identity = store.identity.clone();
        let tombstone = device.pairing.checkpoint().commitment();
        let before = store.pending;
        assert!(matches!(
            device.pending_reply(&mut store, &prior),
            CommissioningReply::Pending { receipt: None, .. }
        ));
        assert_eq!(store.pending, before);
        let challenge = device.pairing.begin(&device.identity, 4, random).unwrap();
        assert_eq!(
            device
                .reconcile_receipt(&mut store, &challenge, &prior, receipt, 5)
                .unwrap(),
            receipt
        );
        assert_eq!(store.identity, identity);
        assert_eq!(device.pairing.checkpoint().commitment(), tombstone);
        assert!(!device.pairing.checkpoint().enabled());
        assert!(
            device
                .reconcile_receipt(&mut store, &challenge, &prior, receipt, 6)
                .is_err()
        );
        let completed = store.pending;
        let mut device = Device::recover(&mut store).unwrap().unwrap();
        assert!(
            matches!(device.pending_reply(&mut store, &prior), CommissioningReply::Pending { receipt: Some(actual), .. } if actual == receipt)
        );
        let challenge = device.pairing.begin(&device.identity, 7, random).unwrap();
        assert_eq!(
            device
                .reconcile_receipt(&mut store, &challenge, &prior, receipt, 8)
                .unwrap(),
            receipt
        );
        assert_eq!(store.pending, completed);
        assert_eq!(store.identity, identity);
    }

    #[test]
    fn each_ambiguous_phase_recovers_only_the_original_receipt() {
        for phase in 1..=3 {
            for after in [false, true] {
                let (mut device, mut store, prior, receipt) = revoked();
                let identity = store.identity.clone();
                store.fail = Some((store.writes + phase, after));
                let challenge = device.pairing.begin(&device.identity, 4, random).unwrap();
                assert!(matches!(
                    device.reconcile_receipt(&mut store, &challenge, &prior, receipt, 5),
                    Err(PairingCommitError::Store(_))
                ));
                assert!(device.pairing.begin(&device.identity, 6, random).is_err());
                store.fail = None;
                let mut device = Device::recover(&mut store).unwrap().unwrap();
                let challenge = device.pairing.begin(&device.identity, 7, random).unwrap();
                assert_eq!(
                    device
                        .reconcile_receipt(&mut store, &challenge, &prior, receipt, 8)
                        .unwrap(),
                    receipt
                );
                assert_eq!(store.identity, identity);
                assert!(!device.pairing.checkpoint().enabled());
            }
        }
    }

    #[test]
    fn wrong_receipt_missing_corrupt_and_changed_identity_refuse_without_replacement() {
        let (mut device, mut store, prior, receipt) = revoked();
        let original = store.pending;
        let wrong = Receipt::from_parts(receipt.id(), [9; 32], receipt.sequence()).unwrap();
        let challenge = device.pairing.begin(&device.identity, 4, random).unwrap();
        assert!(
            device
                .reconcile_receipt(&mut store, &challenge, &prior, wrong, 5)
                .is_err()
        );
        assert_eq!(store.pending, original);
        for kind in 0..3 {
            store.pending = original;
            match kind {
                0 => store.pending = None,
                1 => store.pending.as_mut().unwrap()[100] ^= 1,
                _ => store.identity[20] ^= 1,
            }
            let before = store.pending;
            let challenge = device.pairing.begin(&device.identity, 6, random).unwrap();
            assert!(
                device
                    .reconcile_receipt(&mut store, &challenge, &prior, receipt, 7)
                    .is_err()
            );
            assert_eq!(store.pending, before);
        }
    }

    #[test]
    fn concurrent_checkpoint_change_and_corrupt_readback_never_report_completion() {
        for corrupt in [false, true] {
            let (mut device, mut store, prior, receipt) = revoked();
            let identity = store.identity.clone();
            if corrupt {
                store.corrupt = Some(store.writes + 2);
            } else {
                let mut replacement = Zeroizing::new([0; STORE_BYTES]);
                let len = encode_store(
                    &device.private,
                    device.identity.peer().kid(),
                    device.pairing.checkpoint(),
                    Some(Endpoint::v4([192, 0, 2, 2], 5683)),
                    &mut replacement,
                )
                .unwrap();
                store.replacement = Some((store.writes + 1, replacement[..len].to_vec()));
            }
            let challenge = device.pairing.begin(&device.identity, 4, random).unwrap();
            assert!(matches!(
                device.reconcile_receipt(&mut store, &challenge, &prior, receipt, 5),
                Err(PairingCommitError::Store(_))
            ));
            assert!(device.pairing.begin(&device.identity, 6, random).is_err());
            let retained = store.pending;
            let mut recovered = Device::recover(&mut store).unwrap().unwrap();
            assert!(!recovered.pairing.checkpoint().enabled());
            if corrupt {
                assert_eq!(store.identity, identity);
                assert!(matches!(
                    recovered.pending_reply(&mut store, &prior),
                    CommissioningReply::Refused(6)
                ));
                let challenge = recovered
                    .pairing
                    .begin(&recovered.identity, 7, random)
                    .unwrap();
                assert!(
                    recovered
                        .reconcile_receipt(&mut store, &challenge, &prior, receipt, 8)
                        .is_err()
                );
                assert_eq!(store.pending, retained);
            } else {
                assert_ne!(store.identity, identity);
                let challenge = recovered
                    .pairing
                    .begin(&recovered.identity, 7, random)
                    .unwrap();
                assert_eq!(
                    recovered
                        .reconcile_receipt(&mut store, &challenge, &prior, receipt, 8)
                        .unwrap(),
                    receipt
                );
                assert_eq!(store.pending, retained);
            }
        }
    }
}
