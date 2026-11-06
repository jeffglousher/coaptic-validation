# Combined replay occupancy and message-ID filter

Exact candidate `42c823463b1d7eac5cca31df58e1dac7b243d610` versus pinned baseline
`bd63199b652193b4c0a882e5840e72d992cf1362` fails the frozen CPU preservation rule and is rejected.
All64 paired runs across28 workloads are retained; 5
cell upper bounds exceed1.02. `comparison.html` contains the comparable tables
and CPU chart. No failed source was resampled or reclassified.

The integration retains compact inline/TX replay ownership, scalar active-owner
writes and direct initialization of full retained chunks. One u32 per replay
slot now combines occupancy and a message-ID rejection filter. Values0/1 mean
free/acquired-empty; mid+2 represents all16-bit IDs. A filter match still requires
the exact endpoint/key. Full-u64 deadlines stay in rows, with unchanged expiry,
duplicate-key behavior and TX release ordering. No capacity is reduced.

The compact replay type explicitly defines equality/hashing by key, deadline and
current replay owner. Discarded inactive replay bytes no longer affect identity;
this observable pre-release value-semantic change is documented in rustdoc.
Protocol replay selection and authenticated retained bytes remain covered by
the regression checks; this is not a claim of identical inactive-byte identity.

Host SmallDevice App saves56 bytes; fixed Service App saves832. Allocated Service
saves24 inline bytes plus832 requested pool bytes. Selected complete futures and
encoder frames are unchanged. Actual Thumbv7EM unit-transport Apps save24 bytes
SmallDevice,320 fixed Service,16 allocated Service. Static layout is not device
execution. Startup allocation counts match baseline, including failure recovery.
Requested heap excludes allocator metadata and rounding; this is not peak RAM.

Run `python -B verify.py` here to independently recompute all paired results and
check retained hashes, capacities, exit records and owner ledgers without running
native probes. Use `python prepare.py CORE_REPO NEW_OUTPUT candidate` for source
reconstruction. The unchanged fixture is in sibling
`dispatch-scratch-20261104/fixture`. `observations.zip` retains exact binaries,
PDBs, methods, raw outputs and exits; `diagnostics.zip` contains tests, review and
selected disassembly; `layout32.zip` retains the audit fixture, actual layouts,
source hashes and LLVM constants. The pinned32-bit baseline is reused unchanged.

Before timing:927 library,11 allocation/failure-injection,27 retained-Q and13
footprint checks passed. General read-only review found no actionable issue.
An initial command used the wrong test-target spelling and did not compile;
that invocation failure and the corrected passing run are both retained.

The benchmark measures complete server-App thread CPU cycles with immediate
memory transport, actual synchronous or asynchronous progress and a pending
timer. Client preparation/authentication and verification are outside the server
interval. No network latency, throughput, hardware or new libcoap ranking claim.
Earlier failures are retained in the sibling evidence folders, especially
`deadline-cache-20261106`, `replay-chunk-staging-20261106` and
`replay-scan-index-20261106`. Separate cohorts do not establish causal CPU
attribution. No trimming, early stopping or replacement samples are permitted.
