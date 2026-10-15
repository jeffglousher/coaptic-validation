A queued Observe notification selected a slot before ingress. When a full Observe table re-registered the same Token, ingress replaced that slot and the old opportunity sent an unsolicited notification for the new row. An unrelated response-send failure also consumed the queued signal before notification delivery.

App now reserves a pending candidate without changing its sequence/pending bit, then claims it after ingress. A replacement registration starts without a pending signal. Claim rechecks role, pending state and notification NSTART. The public Engine::progress contract is unchanged; no new per-row or App storage is added.

Regression evidence: full-table same-resource and different-resource replacements reproduced the extra notification on the old implementation; both now send only the registration response and deliver sequence 1 after a fresh signal. An injected unrelated response-send error retains the pending signal and sequence 0, then successfully delivers sequence 1. Existing Observe deletion, congestion, expiry, role, saturation and protected tests pass.

Validation: all 15 CONTRIBUTING checks and both two-iteration dogfood comparisons passed at fa4f017, then clean rebase to 50563c04f8f374f02bae8b896b8a7d021c6478b1. All-features inventory: 592 passing unit tests. Windows MSVC stable Rust 1.97.1 and library MSRV 1.85. CI retains Linux/process/seeded/cross-build evidence; no device execution or full Observe conformance claim.

Related: #201 and #202. Client re-registration API, query-specific sources and large notification lifecycle remain open.
