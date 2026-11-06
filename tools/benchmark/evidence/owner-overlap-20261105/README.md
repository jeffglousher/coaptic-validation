# Integrated owner-overlap experiment — not accepted

The integration reduces selected memory owners and aggregate complete-App CPU
cost. It does **not** meet the prospective preservation rule: six of 28 cell
upper bounds exceed 1.02. It is an experimental commit, not a production merge.
See [the comparable tables and charts](comparison.html).

Baseline: `bd63199b652193b4c0a882e5840e72d992cf1362`.
Candidate: `cc8e20aac1acc6df4dcb79deeca6523108b62fbe`.
The candidate combines request-phase lifetime separation and shared option
traversal with compact inline/TX replay ownership and active TX writes. The
source patch is relative to the pinned baseline. All 924 alloc+oscore library
tests passed; a general independent source review found no actionable
correctness/security defect. Neither result overrides the runtime failure.

## Method and decision

`METHOD-BEFORE.json` fixes the rule before sampling. This is a new integration
and cohort under the user's updated acceptance rule, not a reclassification of
older failed experiments. Memory improvement requires CPU preservation: every
cell and ordinary/all sync/async aggregate one-sided 95% upper ratio must be at
most 1.02. Exact memory owners must not grow; selected complete futures must not
grow. A nonsignificant CPU difference alone is insufficient.

One cohort: 16 paired processes per cell, AB BA BA AB repeated four times,
28 cells, 896 timing outputs. Equal-weight geometric ratios use process log
ratios and Student t with 15 degrees of freedom. Raw samples, stderr, qualifiers,
producer, build/test logs and layout diagnostics are hashed in observations.zip.
There is no trimming, replacement, early stopping or unchanged resampling.
`failed_point_guards` is a legacy field name: in this cohort it contains failures
of the **upper confidence bound**, not point-estimate failures.

All-workload sync CPU ratio is 0.97936 (upper 0.98309); async is 0.99509
(upper 0.99981). SmallDevice protected async has ratio 1.02681, upper 1.03671.
The other five failed bounds mostly leave preservation unresolved; they are not
all established regressions. Full per-cell values remain visible in the report.

The probes measure thread CPU cycles for the complete server-App drive in
memory transport. Async uses the actual wait/progress path, immediate-ready
transport and a pending timer with manual polling. Client preparation,
authentication, transport bridge and verification are outside the measured
server interval. Results do not establish network throughput/latency, scheduler
cost, device peak RAM or a fresh comparison with libcoap.

## Matched capacities and memory accounting

SmallDevice: Constrained, four routes, one Call, no deferred rows, four security
requests, one association, two RX/two TX datagrams of 1152 bytes, four dedup rows,
two Observe rows, no body pools. Service: 32 routes, four Calls, eight deferred
rows, four security requests, one association; 32 RX/32 TX datagrams of 1472
bytes, 64 dedup rows, 32 Observe rows, four RX/four TX bodies of 16384 bytes.
Qualifiers retain the full ordinary and retained-workload configurations.
Fixed and allocated storage are separate cells. Capacities were not reduced.

SmallDevice App falls 14936 to 14872 bytes; Service fixed App 315656 to 314632.
Allocated Service App stays 35672 bytes while requested server-pool heap falls
282512 to 281488. Service client pool heap also falls 37060 to 36932 bytes.
Selected complete SmallDevice progress future falls 15952 to 14000 bytes;
Service fixed and allocated futures fall 16912 to 14960. These compiler sizes
are not task reservations or measured stack peaks. The reused baseline layout
capture is an incomplete broad-filter prefix; the three selected records are
complete and the compiler succeeded. The candidate layout capture is complete.
The verifier checks exact archived hashes and selected records.

The fixed Service App's largest nested owner is Engine memory: 279624 bytes.
Within that owner, bodies take 136688, RX and TX 49104 each, Observe 20784,
dedup 19536, exchanges 4400, cursor 8. Those values are **already inside** the
314632-byte App, not extra memory. Allocated pool heap is likewise a distinct
owner, not a synonym for fixed inline memory. No sum of overlapping views is
presented as a peak.

## What the ownership study found

Preallocation reserves bounded capacity. It cannot by itself make independent
scratch arrays, metadata copies or suspended futures share that storage.

- `dispatch_rx_io_async` copies RX into `Mem::RxScratch`. ParsedMessage borrows
  that scratch while request dispatch mutably borrows the whole Engine. This
  keeps the scratch live across child sends. Protected dispatch also writes the
  opened plaintext back into RX. Both costs remain in this candidate.
- Replay ownership is now a safe inline/TX enum, but a fixed enum still reserves
  its largest variant. It saves 16 bytes per row, not the whole 256-byte inline
  payload for each TX-owned row. Scalar TX writes avoid an emitted whole-row
  copy; valid inline retention still copies bytes. This is not zeroization.
- `take_response` copies an assembled RX body into a separate 4098-byte App hold
  before releasing the Engine slot. That is a real overlapping owner. Simply
  replacing it with a borrow would change slot release timing and observable
  capacity; a release-aware response owner needs explicit design and regression
  checks. It is not a free deletion and is not fixed here.
- Literal `.clone()` is a poor inventory of the hot costs: implicit Copy values,
  assignments, `.copied()` and `copy_from_slice` matter too. Large source-level
  values are not automatically emitted copies; retained assembly evidence from
  the preceding experiments distinguishes these cases.

Next target: remove RX-to-dispatch staging through a safe separation of RX
borrows from Engine mutation, including protected writeback, async cancellation
and capacity recovery. Do not add a full-size replacement scratch, reduce pools,
or claim the 4 KiB response hold is removed before its release contract is solved.
The protected async result warrants inspecting emitted transfers, but source
layout alone does not prove the cause. The previously tried argument grouping
reduced one initial future span without reducing the complete future; it is not
an untested remedy. Do not rerun this unchanged integration.

## Reproduce without resampling

Run `python -B verify.py` from any directory. It checks 1916 archive members,
recomputes all 28 cells and nine aggregates from 896 timing outputs, compares
capacities and exact memory deltas, checks patches/fixtures and complete selected
future records, and reproduces `runtime_accepted: false`. It needs the adjacent
`dispatch-scratch-20261104/fixture` and `receive-scratch-20261105/observations.zip`
already committed in this repository. `python -B render.py` recreates the report.

`prepare.py CORE_REPO NEW_OUTPUT baseline|candidate` materializes source and
the existing seven-file probe fixture without creating a Git worktree. Build
with the recorded toolchain/profile and an existing compatible lane. Native
binary and PDB hashes and normalized production source hashes are in
source-verification.json. The original baseline executable predates bd63199's
documentation-only change; the retained source-equivalence proof identifies
that reuse. Inspect the archived producer/method before any future experiment;
do not run it to replace this failed cohort.
