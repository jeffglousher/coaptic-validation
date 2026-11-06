# Flat inbox occupancy: not accepted

Candidate 1d7b3d8c9a7053fc03d50b8c12e1d0db1215ba01 against pinned
bd63199b652193b4c0a882e5840e72d992cf1362 flattens redundant Option/row-state
occupancy while retaining the preceding metadata-borrowing change. All 924
alloc+oscore library tests and independent general source review pass.

SmallDevice App shrinks from 14936 to 14248 bytes; Service fixed from 315656
to 314968; Service allocated from 35672 to 34984. Each saves 688 bytes.
Allocated pool heap and capacities are unchanged. Selected complete progress
futures remain 15952 bytes (SmallDevice) and 16912 (Service fixed/allocated).
These are compiler/owner sizes, not measured peak memory.

The completed 64-pair, 28-cell cohort is rejected: five cell upper bounds exceed
1.02. All-sync point ratio is 1.000217, upper 1.003286; all-async 0.998512,
upper 1.000732. Aggregate preservation does not override individual failures.
See comparison.html for every cell and comparison with both earlier candidates.
Those are separate cohorts against the same source, not direct head-to-head runs.
Do not resample unchanged source, move gates, or call failure a delivered gain.

METHOD-BEFORE.json fixes AB BA BA AB repeated 16 times, complete server-App
thread cycles, one-sided 95% upper ratios <=1.02 per cell and ordinary/all
sync/async aggregate, owner reduction and selected complete-future nongrowth.
The conservative Student t factor is 1.67 (63 degrees of freedom). No trimming,
replacement or partial-cohort reuse. Direct file subprocess output avoids the
preceding pipe-reader failure. Actual synchronous and asynchronous App paths
run with matched security, body and protocol capacities, memory transport,
immediate-ready I/O and a pending timer. Client preparation/authentication and
verification are outside timing. This is not network latency/throughput,
device peak memory, a scheduler comparison or a new libcoap ranking.

Run python -B verify.py to recompute 3584 timing outputs and the failed verdict
from 7298 hashed archive members, verify capacities, exact owner changes,
fixtures, source patch and selected future records. prepare.py recreates source
and fixture inputs. The adjacent dispatch-scratch fixture and receive-scratch
baseline archive are required. Baseline broad layout capture is incomplete but
its three selected future records are complete; candidate capture is complete.

Additional diagnostics.zip is separately hashed in diagnostic-sha256.json.
The baseline targeted App layout build succeeded and restored candidate fixture
source afterward. The debug-level-1 PDB lacked detailed App field types; the
empty baseline-app-types.txt records that limitation. Layout shows field order
changed as well as inbox size. SmallDevice poll code is 24167 versus 24183 bytes,
with the same 5712-byte selected frame. Disassembly contains calls with a
1152-byte zero-fill argument corresponding to source scratch initialization.
Neither field order nor these static calls establish dynamic CPU attribution.
No timing samples were added or modified by these diagnostics.

The 128-byte Response payload copy and assembled-body copy/release timing remain.
The next experiment must address a distinct evidenced cost, not tune this failed
layout repeatedly. No production change from this candidate is merged.
