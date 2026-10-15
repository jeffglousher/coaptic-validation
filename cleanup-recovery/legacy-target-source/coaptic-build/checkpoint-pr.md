Add a validated recipient ReplayCheckpoint and monotonic restore operation to the caller-owned OSCORE context. A restore cannot lower the live rejection floor or erase received bits still in its window; invalid persisted bounds and rollback return typed errors without mutation. Public replay helpers refuse sequences outside the five-byte range.

The checkpoint contains no keys and is not a storage/wire format. Rustdoc requires the caller to authenticate context identity, prevent persisted rollback, commit before application effects, restore/reserve sender sequences separately and account for lost request/Observe bindings. A newly derived context cannot detect a stale checkpoint by itself. App has no durable pre-handler checkpoint barrier; uncertain recovery requires a fresh cryptographic context.

Proofs include valid/invalid boundary construction, unchanged state on refusal, conservative advance, full-range refusal, authenticated request replay after context restoration, and 256 set-model restore trials. This does not qualify disk crash consistency or full application restart.

All 11 CONTRIBUTING checks, both dogfood baselines, all 16 pinned cross-target builds and the seeded campaigns passed at 7eaa3ad; rebased 2a8c31a has identical tree. 562 library unit tests passed. Source-bound checkpoint-cross-TARGET.json and checkpoint-seeded.json plus checkpoint-validation-*.log retained under D:\coaptic-build. CI required.

Advances #201/#202. Reviewed RFC 8613 section 7.5 contract, rollback/error behavior, bounds, ownership, portability and evidence limits.
