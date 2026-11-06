# Owned replay reclaim integration

Exact candidate `32c32d1997fd416f9cd80feeaa867eb4d8b452bb` versus pinned baseline
`bd63199b652193b4c0a882e5840e72d992cf1362` fails the frozen CPU preservation rule and is rejected.
All 64 pairs across 28 workloads are retained; 3 cell
upper bounds exceed 1.02. `comparison.html` contains CPU charts and comparable
tables. Earlier failures remain rejected; no unchanged candidate was resampled.

The bounded diagnostic in sibling `replay-cost-diagnostic-20261106` establishes
two extra key searches per TX reclamation after the first 31 pinned replies.
The owned reclaim hook avoids both searches for allocated unique-key storage,
and combines one search for public fixed storage while preserving duplicate-key
behavior. TX release precedes removal of the first matching key, then replacement.
Deadline ties retain earliest-slot selection, deadlines remain full u64, and the
ordinary rotating acquisition cursor is preserved. Custom storage keeps the
generic fallback. The occupancy index also restores its immediate-free-cursor
fast path. No resident fields, allocations or capacity reductions are added.

The integrated source retains compact inline/TX replay ownership, scalar active
TX writes, a u32 occupancy/message-ID filter, and direct full retained-chunk
initialization. Filter matches still require the complete endpoint/key.
The compact replay type defines equality/hashing by key, deadline and current
replay owner. Discarded inactive bytes no longer affect identity; this observable
pre-release value-semantic change is documented in rustdoc. This is not a claim
of identical historical inactive-byte identity.

Host SmallDevice App saves 56 bytes; fixed Service App saves 832. Allocated Service
saves 24 inline bytes plus 832 requested pool bytes. Selected complete futures
and encoder frames are unchanged. However, the newly inspected fixed-Service
reclaim frame grows from 784 to 816 bytes, independently failing nongrowth.
SmallDevice reclaim stays800; allocated reclaim falls800 to784. Emitted code
adds a304-byte row copy versus the preceding compact-layout source.
Actual Thumbv7EM unit-transport App reductions
are 24/320/16 bytes for SmallDevice/fixed Service/allocated Service. Startup
allocation counts match baseline. These are exact owners, not peak RAM, and
requested heap excludes allocator metadata and rounding. Static target layout
does not establish device execution. Capacities and security remain matched.

Before timing: 929 library, 11 allocation/failure-injection, 27 retained-Q and
13 footprint checks pass. A final test-only correction ensures pinned TX release
failure is exercised, and that focused model passes. General static review of
42c8234 to 32c32d1 found no actionable issue. Callback count/order has source
inspection rather than a dedicated assertion. The initial wrong test-target
invocation is retained; it failed before compilation.

Run `python -B verify.py` here to independently recompute all paired results and
check hashes, capacities, exit records and owner ledgers without executing probes.
Use `python prepare.py CORE_REPO NEW_OUTPUT candidate` to reconstruct the source.
The unchanged fixture lives in sibling `dispatch-scratch-20261104/fixture`.
`observations.zip` retains exact binaries/PDBs, raw outputs and exits;
`diagnostics.zip` retains build/test/review records and selected disassembly;
`layout32.zip` retains the audit fixture, source hashes, layouts and constants.
Local owner/mailbox metadata is excluded from portable archives.

The benchmark measures complete server-App thread CPU cycles with immediate
memory transport, actual sync/async progress and a pending timer. Client work is
outside the clock. It does not measure network latency, maximum throughput,
whole-system peak memory or a new libcoap ranking. No causal comparison should
be inferred between separate experimental cohorts. Broader qualification and
production merge are separate from this frozen runtime verdict.
