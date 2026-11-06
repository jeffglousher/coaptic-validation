# Deadline-only replay cache and chunk staging

Exact candidate `55388e3caf1345afd50706661030eadf00e0c15f` versus pinned baseline
`bd63199b652193b4c0a882e5840e72d992cf1362` fails the frozen CPU preservation rule and is rejected.
All 64 paired runs across 28 workloads are retained; 6
cell upper bounds exceed 1.02. See `comparison.html` for comparable tables and
the chart. No failed source was resampled or reclassified.

The integration retains compact inline/TX replay ownership, active-owner writes
and direct initialization of full retained chunks. Only full-u64 deadlines are
cached; exact borrowed key lookup replaces the previous cached MID filter.
No capacity or clock range is reduced. The selected host SmallDevice App saves
32 bytes; Service fixed App or allocated pool saves 512 bytes. Selected complete
futures and encoder frames are unchanged. Actual Thumbv7EM App/table sizes are
unchanged, with unit transport; this is a layout audit, not device execution.

Allocated replay tables make one additional bounded startup allocation.
Requested heap excludes allocator bookkeeping/rounding. No peak-RAM, network
throughput, latency, hardware or new libcoap ranking claim follows from these
in-memory complete-server-App thread-cycle measurements.

Run `python -B verify.py` here to recompute all paired results and verify retained
bytes without executing native probes. Use `python prepare.py CORE_REPO NEW_OUTPUT
candidate` for source reconstruction; the unchanged fixture lives in sibling
`dispatch-scratch-20261104/fixture`. Exact candidate binaries/PDBs, method,
raw observations and process-exit records are in `observations.zip`.
`diagnostics.zip` retains build/test logs, review and selected disassembly.
`layout32.zip` retains source hashes, actual type layouts, LLVM constants and
the no_std audit fixture; its baseline capture is reused from the pinned audit.

Before timing: 926 library, 11 allocation/failure-injection, 27 retained-Q and
13 footprint tests passed, as did formatting. General read-only review found
no actionable correctness issue. The host and target memory records count
owners separately and do not add nested storage twice.

The earlier failures are in sibling `replay-chunk-staging-20261106` and
`replay-scan-index-20261106`; original decisions, capture failures and untimed
frame regressions remain intact. This changed-source cohort adds no replacement
samples and uses the same 64 pairs, baseline, capacities and CPU gates.
