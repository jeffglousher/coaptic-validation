# Admission headroom: fixed Stage A wall screen

This preregisters an early rejection screen for core #716. It uses the unchanged
`bench-core` complete server `App::poll` probe. A passing result only permits
developing Stage B; it does not authorize promoting the optimization.

## Immutable comparison

- Baseline A: core `623c82db1a6606ec86cd56bb52009988b9f0d87e`.
- Candidate B: core `8782a6a0b0aef2facf51bec884cfe37f2a80f28d`.
- Candidate changes only the ample-headroom admission guard and boundary tests.
- The companion commit that runs this plan freezes the runner, native fixture,
  manifests, locks and workflow. Record the full commit and tree, compiler/Cargo
  bytes and versions, flags, selected lock, binaries, host and selected CPU.
- Rust 1.99.0, Windows MSVC, release thin LTO / one codegen unit, debug information
  level 1, forced frame pointers, incremental compilation off and two build jobs.
  Build the two revisions serially in one owned reusable hosted target lane.

## Fixed observations

For each of four cells, run baseline then candidate (AB), followed by candidate
then baseline (BA). This is exactly 16 fresh serial native processes. Each runs
60,000 measured requests plus 128 warmups, totaling 960,000 measured and 2,048
warmup operations. Each process uses 60,128 distinct MIDs, without wrap. Protected
processes retain their normal sequence/replay progression and authenticate every
response. There is no replay of prepared protected traffic or counter reset.

The exact commands, with each selected binary substituted for `EXE`, are:

```text
EXE 60000 unprotected --small-device
EXE 60000 oscore --small-device
EXE 60000 unprotected
EXE 60000 oscore
```

Wall timing is the default; `--wall` is not a supported argument. Preparation,
protection and complete response verification are outside the existing poll
timer. Fixture receive/send copies and all server App work remain inside it.
Keep every latency and all 4,096 calibration values. Do not subtract calibration,
remove outliers, replace cohorts or pool AB and BA into one apparent success.

SmallDevice is fixed Constrained storage: 32-byte representation, four route
slots with one populated, one Call, zero deferred rows, RX/TX each 2 x 1152,
dedup 4, Observe 2, and blockwise/body storage disabled. The Default fixture is
allocated: 64-byte representation, one route, four Calls, zero deferred rows,
RX/TX each 4 x 1472, dedup 8, Observe 4, RX body 1 x 1024 and TX bodies 2 x 1024.
Both use C1 CON, one association and four request bindings. These capacities are
identical between A and B within each cell; the two configurations are separate.

The SmallDevice JSON reports extra verification/capacity fields. The unchanged
seven-field Default JSON does not report them. For Default, label completion and
capacities as established from pinned source plus successful native execution,
not as independently emitted JSON counters. Validate the actual schemas.

## Frozen analysis and gates

Split each arm into 60 consecutive blocks of 1,000 operations and calculate each
block mean with `math.fsum`. Use 10,000 bootstrap replicates, seed 20261030,
independently resampling the 60 block means of each arm. Always normalize as
candidate / baseline, including BA. Retain raw arrays and block means so the
calculation is reproducible. Use the equal-tail 2.5th and 97.5th percentiles;
linearly interpolate at `(replicate_count - 1) * quantile`. Reset the fixed-seed
generator for each comparison. These conditional intervals describe two process
comparisons; they do not make the blocks independent host-level replications.

Both unprotected cells are benefit cells. In **each** AB and BA round they need
mean candidate/baseline <= 0.99 and upper 95% bound < 1.00. Both OSCORE cells are
regression guards, requiring upper 95% bound <= 1.02 in each round. Any failed or
uncertain gate ends Stage A without a replacement cohort, relaxed threshold or
alternate source variant. Retain every observation, including later selected
cells if a complete run collected them before final analysis.

No CPU, socket latency, emitted stack, device benefit, peak/whole memory or 50%
objective follows. Per-call clocks perturb the measured work. The earlier flame
profile supplies hypotheses; it does not establish the expected saving.

## Bounds and custody

Use one dedicated hosted Windows job, capped at 35 minutes. Source/lock mutations
belong to outer orchestration so it can restore known inputs after a settled
Cargo worker failure. Do not overwrite unexpected edits. Unresolved descendant
cleanup or abrupt outer/job termination leaves restoration unknown: retain the
failure, stop further work and dispose of the ephemeral VM. This is not universal
crash recovery. No shared runtime, kernel policy, device or ETW session changes.

The build phase has an 830-second overall owner deadline; each serial Cargo
worker has a shorter deadline within a <=450-second outer wrapper. Measurement
has a 300-second inner deadline, 30 seconds per native process and a <=450-second
outer owner. Shared process-wrapper limits remain unchanged. Combined process
stdout/stderr is capped at 2 MiB. Run the nonempty fixed native `wall_` test census
on both revisions before measurement.

Owned target, Cargo registry and temporary output are limited to 8 GiB; retained
hosted evidence to 64 MiB. Monitor disk/RSS and refuse at configured bounds.
These are monitored owner scopes, not a hard whole-VM quota or RAM measurement.
Provisioned Rust/Python prerequisites are outside that build-output scope.
Local receipts fit the parent's existing 1 MiB phase; no local native compilation
or raw-array download is needed. Retain evidence through review and delivery;
remove only settled exclusive output with no consumer.

Prepared evidence must bind this exact workload/plan and both source/binary
identities before any measurement child launches. Check restoration, immutable
inputs and binaries on success and settled failures. Preserve structured primary
and cleanup errors, bounded logs, and which selected work was not run.

## Stage B remains unimplemented

Only if every Stage A gate passes, design bounded full-poll regression cells for
retained RX pressure, held TX pressure, registered Observe cancellation and body
continuations under pressure. Verify actual retained ownership, authenticated
outcomes, refusal/removal semantics and fresh recovery outside timing. A merely
acquired RX row may be processed or released by a poll; it is not proof of
pressure. A cancellation may correctly remove its relation and return 5.03.
First-fragment success does not establish a complete-body exchange.

Do not promote the candidate before Stage B passes. Linux and device confirmation
are separate later decisions. The original profiling campaign stays stopped;
this screen creates no new trace and changes no profiler cap.

## Retained setup failure

Run `41084281643/1` stopped before native test execution or measurements. The
baseline test-list process exited successfully and listed the four expected
functions under `batch_tests::`; the runner incorrectly required `tests::`.
The correction binds the same four functions to their actual Rust module and
tests the observed listing with LF and CRLF. Both revisions must still complete
the exact census before measurement. The workload, process selection, budgets,
statistical method and acceptance gates are unchanged; this setup failure
establishes no performance result.
