# Durable host receipt reference

This Rust reference consumes Coaptic's `ReceiptStore` contract. Its application
effect is one complete telemetry row in a bounded journal. The row contains the
full principal, operation ID, canonical resource, content format, payload and
matching receipt metadata. Effect and receipt therefore share one commit record.
It does not claim an atomic transaction with an external actuator or database.

Run after checking out and preparing the selected library revision:

```sh
cargo test --locked --manifest-path tools/durable-host/Cargo.toml
cargo clippy --locked --manifest-path tools/durable-host/Cargo.toml --all-targets -- -D warnings
```

The host uses Rust 1.97.1 or later. Coaptic enables `std,edhoc` without `alloc`;
the consuming host may allocate. Storage has at most 16 rows, each with a
1024-byte payload bound. Full-principal/operation-ID duplicates recover the
original receipt; changed content conflicts. A full journal refuses new work
while still allowing authorized duplicate recovery. This reference has no
eviction, compaction or unbounded growth.

`Journal::create` is explicit first provisioning and refuses existing paths.
`Journal::open` requires existing valid storage and exclusive file ownership.
The commit boundary is a complete checksummed record followed by `File::sync_all`.
An error after writing begins poisons that instance; neither commits nor effect
counts are available until recovery. A complete uncertain record can be verified
and synced on reopen. A truncated or corrupt record refuses without resetting
or trimming the journal. Missing storage never justifies starting a new operation.

The caller supplies an `Authority` from independently current authenticated
policy. It is separate from journal recovery. Its mutex remains held from the
anchor/principal/resource check through the effect/receipt commit, serializing
policy replacement against commits. Updates require the same authority and a
strictly newer generation. Revoked, wrong-principal, wrong-resource and stale
requests cannot commit or retrieve an old receipt. Production integrations must
obtain current policy again after restart; this module does not install an
enrollment or durable policy authority.

The `receipt_fixture` executable is a local qualification driver using public
identity metadata, with no private keys or network service. It retains the same
fixture operation ID and content across separate processes. Integration tests
actually kill children before writing, midway through a record, before syncing,
and after syncing before acknowledgement. Retrying complete/reconcilable work
returns one effect and the same receipt; a torn record refuses. Other tests cover
exclusive ownership, duplicates, conflicts, capacity, current-policy fencing,
cross-principal scoping, storage failure and recovery. `accept_receipt` checks
the fixture's complete returned bytes; a real network client must first
authenticate a successful response from its intended service.

File locking is cooperative, checksums are not authentication, and the caller
protects storage against unauthorized replacement. A valid old snapshot cannot
be recognized as stale by this journal alone. The evidence concerns ordinary
host process termination, not flash power loss, malicious rollback, production
key custody or the complete device/HA flow. Real network integration must also
bound queues and run blocking persistence outside the CoAP polling path.
