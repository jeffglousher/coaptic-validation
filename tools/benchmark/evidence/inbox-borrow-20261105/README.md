# Inbox metadata borrowing ? not accepted

Candidate d35d9c659b3e6cc3ca0b582883168d2865fb2011 against pinned
bd63199b652193b4c0a882e5840e72d992cf1362 removes a separate reply-metadata
hold and borrows the collected inbox row. Collected rows are reusable and do not
consume admission credits or protocol-state occupancy. The two new regressions
and all924 alloc+oscore library tests pass; general independent static review
found no actionable correctness/security defect.

Every matched App saves688 bytes, including SmallDevice14936?14248 and Service
fixed315656?314968 / allocated35672?34984. Pool heap and configured capacities
are unchanged. Selected complete futures remain15952 bytes for SmallDevice and
16912 for Service. These are owner/compiler sizes, not measured peak stack.
The baseline layout capture is an incomplete broad-filter prefix, with all three
selected records complete; candidate capture is complete.

The completed64-pair cohort fails the prospective CPU preservation gate despite
near-neutral aggregates: all sync ratio0.99958, upper1.00160; all async1.00117,
upper1.00324. Four per-cell upper bounds exceed1.02. SmallDevice unprotected sync
has ratio1.02813/upper1.03426; SmallDevice unprotected async1.01334/1.02714;
Service allocated OSCORE async16384 bytes1.00986/1.02143; retained fixed
unprotected sync11264 bytes1.01889/1.03531. Do not call all four proven
regressions, or use aggregate neutrality to override them. No production merge.

METHOD-BEFORE fixes64 pairs, AB BA BA AB repeated16times,28 matched cells,
one-sided95 upper ratios<=1.02 per cell and ordinary/all sync/async aggregate,
exact owner reduction and complete-future nongrowth. Student t df63 uses the
conservative rounded factor1.67 (CDF0.9500594226). No trimming, replacement or
partial-cohort reuse. CPU is complete server-App thread cycles in memory
transport; actual sync and async progress are exercised. Client preparation,
authentication and verification are outside that interval. No network latency,
throughput, device-peak or fresh libcoap ranking is implied.

The original pipe-capture attempt failed after383 timing outputs: Python3.13
raised MemoryError while starting a subprocess reader thread and hung. Only the
verified owned interpreter was terminated. The failed-pipe archive namespace
preserves its raw outputs, error and planned method with no acceptance verdict.
A changed harness writes stdout/stderr directly to files and parses after child
completion, avoiding that thread path. The candidate namespace contains the
separate complete3584-output cohort, using identical native binaries and gates.
No claim is made about the underlying system-wide cause of MemoryError.

Run python -B verify.py to check8191 archived members, all3584 complete timing
outputs, capacities, exact688-byte deltas, pinned fixtures/patch and selected
future records. The original383 outputs are hashed but never used for the
completed cohort's statistics. Adjacent dispatch-scratch-20261104 fixtures and
receive-scratch-20261105 baseline layout archive are reused. prepare.py
CORE_REPO NEW_OUTPUT baseline|candidate recreates exact source/fixture inputs.
Native binary/PDB hashes and normalized source hashes are retained.

The implementation adds an occupancy predicate alongside Option occupancy.
Flattening that redundant representation is a new source hypothesis; this
completed failure must not be resampled or relabeled. The128-byte inline
Response payload copy and4098-byte assembled-body hold are still present.
