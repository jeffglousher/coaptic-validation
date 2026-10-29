# Bounded hot-path screen, October 29

Six source-work candidates were developed and a seventh was parked. **The combined
batch is not promoted as a performance improvement.** Its complete source remains
in [core PR699](https://github.com/jeffglousher/coaptic/pull/699) and
`combined-candidates.patch`. Only the independent notification-scratch memory
change is selected separately; the other five mechanisms stay staged.

## Exact cohorts

All native preparations use Rust 1.99.0, unchanged companion
`dd74a00ba3550326945fb058ab3213b7b5ad720e`, source-matched locked inputs, identical
build flags and the same frozen baseline loopback client. The actual copied
executables and compiler inputs are hashed in the three `*-prepared.json` files.

- Baseline A: core `28d9f1a61d15121d75d5dd426ad8d6b5cc891005`.
- First candidate B: `f4fb8e85dfc5c78f9031aa3360c9888b9f4aa093`.
- Refined candidate B: `c39b100c8eecae3a630b669df15aac912eaf4f90`.

Each cohort predeclares **A1/B1/B2/A2**, creating two opposite-order pairs. Files
with `v2-` belong to the refinement, whose receipts use the same logical A/B labels.
All original arrays, failures and both sets of comparisons remain. No replacement
runs or further performance variants were taken. Gzip members are the complete
original JSON bytes, not rounded summaries.

All eight runs pass functionally. Their durations are
14.694/14.558/14.125/13.996 seconds, then
13.923/14.177/14.089/14.200 seconds. Preparation is separate in the receipts.
Every run includes nine reliability phases, two real Observe lifecycle proofs,
16 socket cells, six separate C1 core cells and ten unsupported core cells. The
socket cells verify 512 measured operations plus 64 warmups per run; core cells
verify 96 measured plus 768 warmups with 24,576 separate calibrations. Each Observe
mode verifies six complete 4096-byte representations, deregistration, refusal and
controlled local-cancellation recovery. App inline and requested pool-heap owners
are unchanged in every matched cell. Configuration limits are never traded away.

## Why the combined changes remain staged

The first candidate reduces repeated datagram metadata initialization, adds an
empty retained-body shortcut, combines two OSCORE binding searches, carries the
parsed response PIV, indexes Observe route slots directly and right-sizes private
notification options. These are source-work hypotheses, not measured hotspot
attribution.

The first cohort's unprotected SmallDevice/Observe GET median rises
67.650 to 74.500 us and 70.850 to 75.300 us: **+6.850/+4.450 us**. Its body lookup
adds a live-count query before the same scan when the sole body slot is occupied.
That is a source-work counterexample; it does not establish the measured cause.

The refinement caches body capacity once and limits that shortcut to pools above
one slot. Zero/single-slot configurations retain the original lookup. The earlier
cell changes to +4.200/−1.550 us, but Gateway rises **+11.800/+14.450 us unprotected**
and **+23.350/+13.500 us under OSCORE**. Other rows include improvements and mixed
signs. Keep every row in `receipt.json` and all four `compare-*.json` files. Do not
cherry-pick favorable Service or Device observations or call this a CPU win.

The request-binding/PIV changes affect client reception, which server-only core
timing excludes. One populated route cannot measure route-index scaling. The
SmallObserve socket cell times ordinary representation GETs; the separate Observe
proof is functional. Short quick-suite medians do not qualify CPU, extreme tails,
throughput, physical performance or whole memory.

## Independently selected notification memory change

The notification-only source is core `e3acff4651d280c0ee0ed20d2cba8f8586067803`
(later documentation commits may follow). Only `encode_notification` changes its
private `OptionsBuilder<24>` to `<4>`, for its four reachable ETag/Observe/
Content-Format/Max-Age options. The generic response encoder and public builder
capacity are unchanged; no accepted feature is removed.

The actual Windows x64 Rust layouts are **584 and 104 bytes**, a **480-byte local
object reduction**. `layout-checks.json` records the compiler, source, linked
library and executable hashes; `notification-layout.rs` is the complete measuring
program. These public option types are byte-identical across baseline, both
combined sources and the notification-only source. This is not an emitted-frame,
peak-stack, CPU or whole-memory claim; the optimizer may already eliminate parts
of an old temporary.

Execution reuse is explicit. The 1,212 all-feature and 715 no-default library
passes ran at `f4fb8e8`. Its three notification test bodies and golden encoder,
production notification encoder and outbound protection/adapters match the
notification-only subset as recorded in `notification-reuse.json`. The tests
cover 16 metadata combinations, eight boundary values and four TX capacities in
each security mode, plus error/recovery and response-validation precedence.
Fresh fixed Memory starts with zero metadata; restoring the baseline acquire
reset repeats that initialization. No body search, route snapshot or response
unprotection is used by these encoder tests.

The notification-only source has fresh strict all-target Clippy checks with all
features and no defaults, plus Rust 1.89 production checks in both modes. **No
new library-test or quick-suite executable was built for that subset.** The earlier
whole-batch suites are not relabeled as its measurements. This limits delivery to
the independently reviewed local-object change and reused wire-equivalence proof.

The original combined candidate's two Clippy raw logs were not retained. Its
`batch-r3-checks.json` preserves the pass summaries and expected output hashes,
so that lint evidence is **summary-only**. `variant-clippy-all.log.gz` and
`variant-clippy-fixed.log.gz` instead contain the refinement's output and match
`variant-lint-checks.json`; their earlier `f4-pass` filenames were incorrect.
The notification-only raw lint logs are separately prefixed `notification-`.
Library-test logs, failed checks and all eight raw benchmark receipts remain.

## Bounds and retained failures

Initial new-test aliases, allocated body alignment and association feature-gating
failures remain in compressed logs and failed check receipts. They were repaired
before the passing precursor tests. No production defect was found in independent
general correctness/security reviews; source review is not a performance verdict.

The parent reused the registered D: compiler lane, with no new target/cache or
worktree. Cumulative sampled positive output stays within 256 MiB; private
metadata stays within 256 KiB and this publication within 512 KiB. Receipts include
restoration of the clean dependency checkout and canonical lock. Exact totals and
input hashes are in `receipt.json`. Local consistency checks are not independent
build attestation. No Linux/device rerun or fresh eBPF deployment occurred here;
prior results and both 50% objectives remain unchanged.
