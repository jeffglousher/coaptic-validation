//! Explicit migration of a proven unused legacy qualification namespace.
//!
//! The platform selects a reviewed permit before creating any protocol owner.
//! Its evidence digest names externally verified deployment provenance; the
//! digest is not a signature or proof of that history. Missing bytes, an echo
//! grant or operator approval alone never establish eligibility. This is not
//! recovery of a lost operation and supplies no physical rollback protection.

use super::{Device, Error, PendingStore, STORE_BYTES, Store, echo_permissions, pending_binding};
use zeroize::Zeroizing;

/// Device principal, store, big-endian revision, record commitment and reviewed
/// evidence digest. All fields bind one exact legacy checkpoint.
pub const LEGACY_CUSTODY_PERMIT_BYTES: usize = 32 + 32 + 8 + 32 + 32;

/// Initialize only a missing, independently proven unused enrolled namespace.
///
/// Call once under exclusive platform storage ownership before starting either
/// synchronous or asynchronous services. The caller must independently review
/// complete controlled-deployment provenance and bind its digest into the permit.
/// Default operation never calls this function. A retained selected permit must
/// be removed after the attempt: every present record refuses, including a prior
/// successful or ambiguous commit. Normal authenticated recovery can then
/// reaffirm readable state; this path never overwrites it or changes policy.
///
/// The complete identity/policy blob is freshly compared before and after the
/// pending commit. Any failed/ambiguous write or readback must stop all protocol
/// owners; the caller must not retry the mutation or continue with a fresh grant.
/// A separate create-only durable claim is consumed before writing Pending, so
/// later deletion cannot reuse a permit retained in a firmware image. Neither
/// claim nor history may be cleared by an automatic recovery path.
#[inline(never)]
pub fn initialize_legacy_custody(
    store: &mut impl Store,
    permit: &[u8; LEGACY_CUSTODY_PERMIT_BYTES],
) -> Result<(), Error> {
    let revision = u64::from_be_bytes(permit[64..72].try_into().unwrap());
    if revision == 0
        || [
            &permit[..32],
            &permit[32..64],
            &permit[72..104],
            &permit[104..],
        ]
        .into_iter()
        .any(|field| field.iter().all(|byte| *byte == 0))
    {
        return Err(Error::Permissions);
    }
    let device = Device::recover(store)?.ok_or(Error::Storage)?;
    let record = device.pairing.checkpoint();
    if device.identity.peer().principal().fingerprint() != &permit[..32]
        || record.store() != &permit[32..64]
        || record.revision() != revision
        || record.commitment() != permit[72..104]
        || !record.enabled()
        || record
            .policy()
            .is_none_or(|policy| *policy.resource_policy() != echo_permissions())
    {
        return Err(Error::Permissions);
    }
    if store.pending_read()?.is_some() {
        return Err(Error::Storage);
    }
    let mut fresh = Zeroizing::new([0; STORE_BYTES]);
    let len = store.read(&mut fresh)?;
    if len != device.stored_len || fresh[..len] != device.stored[..device.stored_len] {
        return Err(Error::Storage);
    }
    let claim = blake3::derive_key("coaptic legacy custody migration claim v1", permit);
    store.claim_legacy_custody(&claim)?;
    crate::pending_telemetry::provision_bound(
        &mut PendingStore(store),
        pending_binding(&device.private, record),
        device.identity.peer().principal(),
    )
    .map_err(|_| Error::Storage)?;
    fresh.fill(0);
    let len = store.read(&mut fresh)?;
    if len != device.stored_len || fresh[..len] != device.stored[..device.stored_len] {
        return Err(Error::Storage);
    }
    Ok(())
}
