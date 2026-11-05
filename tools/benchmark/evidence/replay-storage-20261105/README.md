# Replay-owner experiments: not accepted

Both candidates reduce retained memory but fail the frozen complete-App runtime
acceptance rules. Neither is ready for merge. Do not repeat either unchanged
cohort or weaken its gates. Sources and all observed failures are retained here.

The baseline is core `bd63199b652193b4c0a882e5840e72d992cf1362` (#741).
Its reused native binaries were built at production-equivalent `f84f3c1`;
`source-verification.json` links the existing equivalence evidence, records the
toolchain and verifies the actual integrated fixture against 149 source files.
The seven probe inputs match the existing dispatch-scratch fixture hashes.

## Changes and results

`shared` (`c590a663291d12aab98520dec3a2c4344de1721f`) overlays mutually exclusive
256-byte inline replay and a retained TX pin in a safe private enum. It adds no
allocation and changes no capacity. The whole 28-cell sync ratio is
0.9920329685, upper95 1.0015245637; async is 1.0002273617, upper95 1.0176487367.
Both original ordinary-mode groups also fail, and two cell point guards fail.

`owned-scan` (`6d6f68b881e051248cabf7697ba02d6947355ca9`) additionally removes a
redundant occupancy read from fixed/allocated dedup payload lookup. Every payload
write requires acquisition and every successful release clears it. This affects
packet retention and async deadline scans. Whole sync is 1.0009088926, upper95
1.0088785128; async is 0.9854188858, upper95 0.9939030958. Ordinary async also
passes, but ordinary sync fails. SmallDevice unprotected sync point ratio
1.0518564717 fails its 1.02 guard. Pooled improvement cannot rescue this result.

Both variants have the same measured owned-memory reductions:

- SmallDevice App including transport: 14,936 to 14,872 bytes (4 dedup rows).
- Fixed Service App including transport: 315,656 to 314,632 bytes (64 rows).
- Allocated Service requested pool heap: 282,512 to 281,488 bytes; its App stays
  35,672 bytes. The allocated client heap shrinks 37,060 to 36,932 bytes (8 rows).
- Retained Q-Block2 fixed App: 112,728 to 112,472 bytes (16 rows); allocated App
  remains 42,704 bytes. That qualifier does not report allocated pool heap.

Configured routes, Calls, deferred rows, security requests, associations, datagram,
Observe and body capacities remain unchanged. The ordinary fixture reports their
full ledgers. Retained capacities are in the unchanged `retained.rs` fixture.
Nested owners are not added twice. These are object/requested-heap observations,
not whole-system peak memory, allocator overhead, stack use or device RAM proof.
Complete future/frame layouts and executable-size tradeoffs were not qualified
for these rejected candidates.

Equality/hash now describe active replay ownership, discarding old inactive bytes.
`tx_pin` borrows instead of taking the entry by value; ordinary calls work, but
method-item users expecting `fn(DedupEntry)` must adapt. General independent static
reviews found no protocol, pin-release or lifecycle defect. This does not establish
runtime acceptance. The shared candidate passed 871 no-default+oscore library
tests; integration passed 924 no-default+alloc,oscore library tests. Its first test
compile failed for a missing explicit `std` test import; failure and corrected run
are archived. No complete feature/Clippy/doc campaign was run after runtime rejection.

## Method and reproduction

Twenty ordinary cells cover SmallDevice32 and fixed/allocated Service1024/16384;
eight retained cells cover fixed/allocated Q-Block2 11264 bytes. Every profile has
unprotected/OSCORE and actual sync/async operation. Async uses native wait+progress
with an immediate-ready in-memory transport and a pending timer. This does not
measure socket latency or executor overhead. Client preparation/authentication and
verification remain outside the complete server-App thread-cycle interval.

Each cohort retains four paired processes in AB, BA, BA, AB order, CPU0 affinity,
128 warmups, 8192 operations for ordinary32/1024 and 1024 otherwise. Equal-weight
geometric process-mean ratios use one-sided Student-t upper95 on four paired logs
(df3, factor2.3533634348). Both sync and async upper95 must be below1 in ordinary20
and all28; every cell point must be at most1.02. No trimming or replacement.
Memory gates were declared before either cohort: capacities and non-owner ledger
fields equal, owned App/heap bytes cannot grow, ordinary server owners strictly
shrink, retained fixed App strictly shrinks. No runtime gates changed.

Run `python verify.py shared` and `python verify.py owned-scan` to verify every
archive hash, all 448 timing outputs, response assertions and reported capacity/memory fields
and independently recompute both rejections. Each invocation checks its 224 timing
outputs and all archive hashes. The first offline verifier mistakenly expected
the 64-row Service saving in the distinct 16-row retained fixture; its expected
delta was corrected to256. Measurement acceptance and raw samples were unchanged.
The later evidence review added explicit SmallDevice pool-field comparisons.
Retained outputs omit a capacity ledger; their capacities are preserved by the
pinned fixture/source, not checked through absent output fields.

Run `python prepare.py CORE_REPO NEW_OUTPUT baseline`, `shared` or `owned-scan`
to materialize source without modifying a checkout. Build with the recorded Rust
toolchain and an existing compatible target, incremental0/jobs1,
`RUSTFLAGS=-Cforce-frame-pointers=yes`:

```text
cargo build --release --locked --manifest-path OUTPUT/probe/Cargo.toml --bin dispatch-probe
cargo build --release --locked --manifest-path OUTPUT/probe/Cargo.toml --bin retained-probe --features oscore,alloc
```

Copy each binary before a later build replaces it. Original `measure.py` producers
are in the archive beside their METHOD/results; adjust only their four executable
paths and use a fresh output directory to reproduce. They require Python psutil
and Windows QueryThreadCycleTime. Different absolute source paths are disclosed;
binary hashes identify what actually ran. Historical failures remain failures even
if a later independent reproduction differs.

## Diagnostic context

The archive also retains two distinct baseline-only phase diagnostics, exact
patches, raw counters/results, methods and build logs. Apply either diagnostic
patch at a prepared baseline output root; it covers both coaptic and probe files.
Use its METHOD cells and ordinary build command above. Version2 narrows scheduling
work; it is not a repeat acceptance cohort. Instant/atomic instrumentation perturbs
code generation and inclusive times: do not add nested rows, subtract them as
exact shares or compare the two instrumented binaries as performance gains.
SmallDevice async finish-send maps to a different helper and was uninstrumented;
zero calls there are missing coverage. Constructors were near the clock floor;
Service scheduling/deadline work was material enough to inspect further.

The [earlier libcoap comparison](../receive-scratch-20261105/README.md) remains
applicable: parsing borrowed views is useful, but libcoap's temporary plaintext
PDU/option merge/payload copies are not an inherently cheaper design. The attempted
Rust direct-opening integration failed its runtime checks and remains retired.
No cross-library speed or memory ranking follows from source inspection.
