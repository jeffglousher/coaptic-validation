# Shared phase storage with static resident capacity

Exact native candidate 3e592adb1fd52c5e6918af1b4e810bb874413bad versus pinned
baseline bd63199b652193b4c0a882e5840e72d992cf1362 passes the frozen runtime preservation rule; qualification and merge are separate.
All 64 pairs across 28 workloads are retained; 0 cell bounds fail.
Complete server-App CPU change: sync -0.625%,
async -0.625%.
comparison.html contains the chart and comparable owner/workload tables.
Slowest point: retained fixed OSCORE sync +0.851%, upper bound +1.299%, within
the declared 2% tolerance. Aggregate gains do not mean every workload is faster.

Blockwise dispatch shares the collected-response backing. Five retained-send
helpers borrow immutable SendResponse metadata. ResidentScratch declares fixed
writable capacity as a type constant; no runtime capacity field is stored.
NonZeroU16 body length permits enum niche reuse. Original replay, client inbox
and retained chunk implementations remain. Previous failed cohorts remain failed.

The prospective memory rule requires no selected App/pool, future or emitted-frame
growth and strictly smaller complete Service progress futures. Resident App/pool
shrink is not required for this lifetime-only target. Every workload and both
ordinary/all sync/async CPU upper 95% bounds must be at most 1.02.
No earlier failure is reclassified under this rule.

## Matched memory owners

- SmallDevice App: 14,936 to 14,936 bytes (+0).
- Service fixed App: 315,656 to 315,656 bytes (+0).
- Service allocated App: 35,672 to 35,672 bytes (+0).
- Service allocated pool heap: 282,512 to 282,512 bytes (+0).
- SmallDevice complete progress future: 15,952 to 15,952 bytes (+0).
- Service fixed complete progress future: 16,912 to 15,496 bytes (-1,416).
- Service allocated complete progress future: 16,912 to 15,496 bytes (-1,416).

Nested owners must not be added again. Requested heap excludes allocator metadata
and rounding; complete future objects are not peak stack or task reservations.
Selected Thumbv7EM unit-transport App/table layouts remain equal to baseline.
No target runtime claim. Untimed precursor 73e3aaf grew both selected Service Apps
by 8 bytes; its source, checks and failure remain in untimed-precursor.zip.

SmallDevice uses Constrained, 4 routes, 1 Call, 0 deferred, 4 security requests,
1 association, 2 RX/2 TX datagrams of 1152 bytes, 4 dedup, 2 Observe, no bodies.
Ordinary Service uses 32 routes, 4 Calls, 8 deferred, 4 security requests,
1 association, 32 RX/32 TX datagrams of 1472 bytes, 64 dedup, 32 Observe,
4 RX/4 TX bodies of 16384 bytes. Reported capacity fields are compared; unchanged
pinned fixture/source preserves capacities absent from individual outputs.

926 library, 11 allocation, 27 retained-Q, 13 footprint and 5 scratch-admission
checks pass at 9f2c014. Exact 3e592ad adds one rustdoc line only; check-reuse.json
records the byte comparison. Formatting and strict all-target/all-feature lint
pass at 3e592ad. The original missing-doc lint failure remains in diagnostics.
General static review found no actionable issue. All nine final qualification lanes
pass: strict no-default lint, all-feature tests (1681 passed, one explicitly ignored
idle microbenchmark), no-default/alloc/oscore/std library tests, both Rust 1.89
feature checks and rustdoc. qualification.json and logs retain commands/results.
Portable reconstruction now verifies all 148 native source hashes after explicit
LF normalization; the initial host CRLF mismatch is retained.

Selected encoder frames remain 1280/1296 bytes; reclaim frames do not grow.
Custom resident scratch implementations must declare stable writable CAPACITY;
actual readable/writable slices are checked before entropy. Temporary scratch
bounds and datagram-only behavior remain unchanged. Custom large scratch changes
initialized variant on body collection. Startup and custom-switch costs are
unmeasured. Body release timing and the 4096-byte collection limit are unchanged.

Run `python -B verify.py` to verify retained hashes/exits and recompute CPU results
without executing probes. `prepare.py CORE_REPO NEW_OUTPUT candidate` reconstructs
the exact native source from baseline and patch. The unchanged fixture is sibling
dispatch-scratch-20261104/fixture. observations.zip retains binaries/PDBs and raw
samples; diagnostics.zip retains builds/checks/review/lowering; layout32.zip has
the target static evidence. Local owner/mailbox metadata is excluded.

Actual sync and async wait/progress use immediate-ready memory transport and a
pending timer. Client preparation/authentication/verification are outside the
clock. No socket latency, maximum throughput, peak device RAM, executor policy,
hardware qualification or new libcoap ranking follows from this cohort.
