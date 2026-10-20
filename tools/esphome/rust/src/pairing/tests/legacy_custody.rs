use super::*;

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    PendingRead,
    CommitBefore,
    CommitAfter,
    BadReadback,
    AppearingRecord,
    IdentityBefore,
    IdentityAfter,
    OversizedRead,
    ClaimBefore,
    ClaimAfter,
}

#[derive(Default)]
struct Backend {
    memory: Memory,
    fault: Fault,
    reads: usize,
    pending_reads: usize,
    pending_commits: usize,
    claim: Option<[u8; 32]>,
    claims: usize,
}
impl Store for Backend {
    fn claim_legacy_custody(&mut self, claim: &[u8; 32]) -> Result<(), Error> {
        self.claims += 1;
        if self.claim.is_some() || matches!(self.fault, Fault::ClaimBefore) {
            return Err(Error::Storage);
        }
        self.claim = Some(*claim);
        if matches!(self.fault, Fault::ClaimAfter) {
            Err(Error::Storage)
        } else {
            Ok(())
        }
    }
    fn read(&mut self, output: &mut [u8; STORE_BYTES]) -> Result<usize, Error> {
        self.reads += 1;
        let len = self.memory.read(output)?;
        match self.fault {
            Fault::IdentityBefore if self.reads == 2 => output[0] ^= 1,
            Fault::IdentityAfter if self.reads == 3 => output[0] ^= 1,
            Fault::OversizedRead if self.reads == 2 => return Ok(STORE_BYTES + 1),
            _ => {}
        }
        Ok(len)
    }
    fn commit(&mut self, _: &[u8], _: &[u8]) -> Result<(), Error> {
        panic!("legacy custody must never commit identity or policy")
    }
    fn pending_read(
        &mut self,
    ) -> Result<Option<[u8; crate::pending_telemetry::RECORD_BYTES]>, Error> {
        self.pending_reads += 1;
        if matches!(self.fault, Fault::PendingRead) {
            return Err(Error::Storage);
        }
        if matches!(self.fault, Fault::AppearingRecord) && self.pending_reads == 2 {
            self.memory.pending = Some([7; crate::pending_telemetry::RECORD_BYTES]);
        }
        self.memory.pending_read()
    }
    fn pending_commit(
        &mut self,
        bytes: &[u8; crate::pending_telemetry::RECORD_BYTES],
    ) -> Result<(), Error> {
        self.pending_commits += 1;
        if matches!(self.fault, Fault::CommitBefore) {
            return Err(Error::Storage);
        }
        self.memory.pending_commit(bytes)?;
        match self.fault {
            Fault::CommitAfter => Err(Error::Storage),
            Fault::BadReadback => {
                self.memory.pending.as_mut().unwrap()[0] ^= 1;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn legacy(
    permission: Option<[u8; 32]>,
    revoked: bool,
) -> (Backend, [u8; LEGACY_CUSTODY_PERMIT_BYTES]) {
    let private = [1; 32];
    let identity = Identity::from_private_key(private, 17).unwrap();
    let record = PairingRecord::unpaired(&identity, [9; 32]).unwrap();
    let mut pairing = LocalPairing::restore(&identity, record).unwrap();
    if let Some(permission) = permission {
        let peer = Identity::from_private_key([2; 32], 18).unwrap().peer();
        let policy =
            coaptic::provisioning::EnrollmentPolicy::new(peer, [7; 32], permission).unwrap();
        let challenge = pairing.begin(&identity, 0, random).unwrap();
        pairing
            .pair(&challenge, policy, 1, |_, _| Ok::<_, Error>(()))
            .unwrap();
    }
    if revoked {
        let challenge = pairing.begin(&identity, 2, random).unwrap();
        pairing
            .revoke(&challenge, &[7; 32], 3, |_, _| Ok::<_, Error>(()))
            .unwrap();
    }
    let record = pairing.checkpoint();
    let mut bytes = [0; STORE_BYTES];
    let len = encode_store(
        &private,
        17,
        record,
        permission.map(|_| Endpoint::v4([127, 0, 0, 1], 5683)),
        &mut bytes,
    )
    .unwrap();
    let mut permit = [0; LEGACY_CUSTODY_PERMIT_BYTES];
    permit[..32].copy_from_slice(identity.peer().principal().fingerprint());
    permit[32..64].copy_from_slice(record.store());
    permit[64..72].copy_from_slice(&record.revision().to_be_bytes());
    permit[72..104].copy_from_slice(&record.commitment());
    permit[104..].fill(4);
    let memory = Memory {
        bytes: bytes[..len].to_vec(),
        ..Memory::default()
    };
    (
        Backend {
            memory,
            ..Backend::default()
        },
        permit,
    )
}

#[test]
fn reviewed_legacy_initialization_preserves_exact_identity_policy_and_stops_replay() {
    let (mut store, permit) = legacy(Some(echo_permissions()), false);
    let original = store.memory.bytes.clone();
    initialize_legacy_custody(&mut store, &permit).unwrap();
    assert_eq!(store.memory.bytes, original);
    assert_eq!(store.pending_commits, 1);
    assert_eq!(
        store.claim,
        Some(blake3::derive_key(
            "coaptic legacy custody migration claim v1",
            &permit
        ))
    );
    let device = Device::recover(&mut store).unwrap().unwrap();
    assert_eq!(
        device.pending_custody(&mut store),
        coaptic::provisioning::CommissioningPending::Complete
    );
    let committed = store.memory.pending;
    assert!(initialize_legacy_custody(&mut store, &permit).is_err());
    assert_eq!(store.pending_commits, 1);
    assert_eq!(store.memory.pending, committed);
    assert_eq!(store.memory.bytes, original);
}

#[test]
fn consumed_permit_cannot_recreate_deleted_history_even_after_ambiguous_claim() {
    for fault in [
        Fault::None,
        Fault::ClaimAfter,
        Fault::CommitBefore,
        Fault::CommitAfter,
    ] {
        let (mut store, permit) = legacy(Some(echo_permissions()), false);
        store.fault = fault;
        let _ = initialize_legacy_custody(&mut store, &permit);
        assert!(store.claim.is_some());
        store.memory.pending = None;
        store.fault = Fault::None;
        let commits = store.pending_commits;
        assert!(initialize_legacy_custody(&mut store, &permit).is_err());
        assert_eq!(store.pending_commits, commits);
        assert!(store.memory.pending.is_none());
    }
}

#[test]
fn every_checkpoint_binding_and_nonzero_evidence_is_required_before_writes() {
    for position in [0, 32, 71, 72] {
        let (mut store, mut permit) = legacy(Some(echo_permissions()), false);
        permit[position] ^= 1;
        assert!(initialize_legacy_custody(&mut store, &permit).is_err());
        assert_eq!(store.pending_commits, 0);
        assert!(store.memory.pending.is_none());
    }
    let (mut store, mut permit) = legacy(Some(echo_permissions()), false);
    permit[104..].fill(0);
    assert!(initialize_legacy_custody(&mut store, &permit).is_err());
    assert_eq!(store.reads, 0);
}

#[test]
fn no_initial_identity_readonly_telemetry_or_revoked_grant_can_use_legacy_permit() {
    for (permission, revoked) in [
        (None, false),
        (Some(permissions(false)), false),
        (Some(permissions(true)), false),
        (Some(echo_permissions()), true),
    ] {
        let (mut store, permit) = legacy(permission, revoked);
        assert!(initialize_legacy_custody(&mut store, &permit).is_err());
        assert_eq!(store.pending_commits, 0);
    }
    let (_, permit) = legacy(Some(echo_permissions()), false);
    let mut store = Backend::default();
    assert!(initialize_legacy_custody(&mut store, &permit).is_err());
    assert!(store.memory.bytes.is_empty());
    assert_eq!(store.pending_commits, 0);
    store.memory.bytes = vec![0; 31];
    assert!(initialize_legacy_custody(&mut store, &permit).is_err());
    assert_eq!(store.pending_commits, 0);
}

#[test]
fn present_corrupt_or_unresolved_history_is_never_overwritten() {
    for unresolved in [false, true] {
        let (mut store, permit) = legacy(Some(echo_permissions()), false);
        initialize_legacy_custody(&mut store, &permit).unwrap();
        let device = Device::recover(&mut store).unwrap().unwrap();
        if unresolved {
            let mut pending = crate::pending_telemetry::Pending::recover_bound(
                PendingStore(&mut store),
                pending_binding(&device.private, device.pairing.checkpoint()),
                device.identity.peer().principal(),
            )
            .unwrap();
            pending
                .begin(
                    coaptic::provisioning::OperationId::new([8; 16]),
                    telemetry_resource(),
                    None,
                    b"retained",
                )
                .unwrap();
        } else {
            store.memory.pending.as_mut().unwrap()[0] ^= 1;
        }
        let pending = store.memory.pending;
        let commits = store.pending_commits;
        assert!(initialize_legacy_custody(&mut store, &permit).is_err());
        assert_eq!(store.memory.pending, pending);
        assert_eq!(store.pending_commits, commits);
    }
}

#[test]
fn read_races_and_ambiguous_commits_refuse_without_mutating_identity() {
    for fault in [
        Fault::PendingRead,
        Fault::CommitBefore,
        Fault::CommitAfter,
        Fault::BadReadback,
        Fault::AppearingRecord,
        Fault::IdentityBefore,
        Fault::IdentityAfter,
        Fault::OversizedRead,
        Fault::ClaimBefore,
        Fault::ClaimAfter,
    ] {
        let (mut store, permit) = legacy(Some(echo_permissions()), false);
        let original = store.memory.bytes.clone();
        store.fault = fault;
        assert!(initialize_legacy_custody(&mut store, &permit).is_err());
        assert_eq!(store.memory.bytes, original);
        assert!(store.pending_commits <= 1);
    }
}
