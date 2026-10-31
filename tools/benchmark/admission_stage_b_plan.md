# Finite admission Stage B regression screen

This is a source contract, not execution evidence. All new native builds,
qualification and timings are NOT RUN. The successful Stage A cohort is not
repeated. The rejected dedup campaign stays stopped. Core PR716 remains held.

`admission_stage_b_contract.json` is the immutable scalar/tuple contract after
canonical sorted-key, compact UTF-8 JSON encoding (no trailing newline in hash).
Its SHA256 is 161b7fd033cd7c2cc37b203f878b4307de913e2da2b651bacdbe9e84c186a83c. Implementation-source and suite/tree hashes are
bound separately after source freeze; the contract cannot contain its own source
hash. No runtime count, cell, threshold or revision overrides are accepted.

## Selected work and boundaries

Five cases, in order rx, tx, observe_cancel, notification_block2, ordinary_block2;
for each, unprotected then OSCORE; for each cell, AB then BA process order.
This is 40 fresh serial processes, 128 identically verified warmup cycles plus
1000 measured cycles per process. RX/TX/cancellation have one `poll` stratum;
each Block2 case has separate `num1`, `num2`, `num3` strata. Retain 72000 measured
complete App polls, without pooling fragment positions, security modes or orders.

Time only the complete selected App::poll with Instant and optimizer barriers.
Transport copies, inbound authentication, admission and response protection inside
that poll remain measured. Prepare requests/security and pressure first; verify
all results, wire metadata, authentication, owners and cleanup afterward. The
instrumented release integration-test harness is not socket, CPU, device or
whole-memory evidence. A failed prefix is retained as a failure, never a smaller
successful sample. Keep every selected latency and 4096 calibration readings;
calibration is never subtracted and no outlier is discarded.

RX and TX use unchanged SmallDevice fixed Constrained capacities and 32-byte
responses. Observe cancellation registers first, then cancels under a real held
TX sentinel; expected 5.03 still must remove the relation. Verify sentinel bytes,
endpoint, pin, ownership and exact refusal metrics, release once and recover.
RX holds a genuinely completed Call response through the incoming refusal;
collection, never a bare pool reservation, releases its credit.

Both Block2 cases use unchanged Default allocated capacities and a nonuniform
64-byte body with stable format/ETag. Notification uses three completed Call RX
owners, real Observe=0/Block2 NUM0 registration, public NON App.notify and three
fresh CON followups without Observe. The third setup Call is NON with its actual
response postponed until after authenticated notification; this avoids NSTART
blocking. Assemble anew from notification block0. Match the complete established
body sidecar through incomplete requested ranges; check wire NUM/SZX/M separately,
handler exclusion, full payload, final body release and one-time Call collection.
Cancel the relation legally before the next cycle and verify ordinary recovery.
Ordinary Block2 holds two completed Calls, sets up NUM0 without Observe, then times
NUM1/2/3 separately, requiring one handler call per block, exact fragments and no
retained TX body after each reply. Three held owners correctly cause ordinary
RX refusal: test that counterexample, not a fictional handler-free cached path.

Actual per-cycle internal datagrams are rx6, tx4, observe6, notification19,
ordinary14; handler counts are1,1,2,3,5. UDP datagrams are zero. Counts are based
on every observed input consumption and output message, outside clocks. An
unexplained extra output/eviction/refusal/owner invalidates the process.

## Continuous protocol state

One App and one context pair per process, freshly derived from24 random bytes
once; no key, replay, sequence, association or history resets. Never log secrets.
Consume fixture-side bindings with peer.take(token), authenticate with that ref,
and use the copied original observing ref only for its notification. Public Call
collection retires App-side bindings. No private constructors/fresh-PIV shortcuts.

Each cycle starts at248000*cycle milliseconds with an empty untimed expiration
poll, only after prior Calls, bodies, pending entries and Observe relation have
been explicitly settled. This is declared virtual empty-history traffic, not
saturated-history behavior. Due dedup expiry precedes receive; installed OSCORE
associations/contexts have no clock expiry. Max phase15. Notification phases are
empty0, Call1 send1/reply2, Call2 send3/reply4, third NON send5, register6,
notify7, third reply8, followups9/10/11, cancel12 and recovery13. The19 datagrams
are not19 clock phases. After the last cycle, perform the final empty expiration
at279744000ms and verify settlement again. Other cases use increasing phases
within0..15 and their exact per-case protocol sequence.

Peer-originated fresh MIDs are16*cycle+phase in0..18047; ACKs instead echo actual
App Call MIDs. The third NON response has a fresh peer MID. Fixture tokens are
eight-byte big-endian values in the finite reserved set0..18047. Preserve the
relationship token through registration/download/cancellation; use a new token
for recovery and next relationship. Check all App-generated eight-byte tokens
against that finite set and a whole-process3384-token ledger. A collision refuses,
never retries. Check every fresh PIV and actual public sender-sequence deltas;
maximum11280 fresh allocations/direction and at most2 wire PIV bytes. Ordinary
bound responses follow protocol nonce binding, not a fabricated fresh sequence.

## Isolated executable and software qualification

Keep bench-core.rs and admission_pressure.rs byte-identical to9ceac13. Do not
factor or rewrite the proven58KB module. Add an empty admission-stage-b feature
and explicit [[test]] target admission-stage-b at
native/servers/tests/admission-stage-b.rs, required-features admission-stage-b.
Reuse public core APIs and the small source-equivalent CoreIo/factory pattern in
that separate integration fixture; no production binary or factory changes.
No new dependency or lock resolution. Old plan/owner/descriptor values, source
pins, native artifact selection and proof/StageA/dedup behavior stay unchanged.

Build via the existing outer source/lock custody wrapper:

    cargo test --release --locked --target x86_64-pc-windows-msvc --manifest-path tools/benchmark/native/servers/Cargo.toml -p bench-rust-server --test admission-stage-b --features admission-stage-b --no-run --message-format=json-render-diagnostics

Select exactly one Cargo target.name=admission-stage-b, target.kind containing
`test`, profile.test=true, with exactly one executable and matching owned PDB from
that artifact's filenames. Normal binary/profile.test=false or foreign/multiple
artifacts refuse. Retain/hash the actual test EXE/PDB before launch.

Ten timing tests are ignored and named in the contract. List them with:

    <exe> --ignored stage_b:: --list

Run exactly one selected case, e.g.:

    <exe> --ignored --exact stage_b::rx_oscore --test-threads=1 --nocapture --format=terse --color=never

Use a dedicated newline-prefixed `COAPTIC_STAGE_B_RESULT ` marker followed by
one compact JSON object and a newline. Validate exactly one result, one libtest
pass, zero failed/ignored/measured, return0, no unexpected stdout/stderr. Terse
libtest output may separate the test result marker from its dot/summary; do not
reuse a parser that demands `test NAME ... ok` on one line with nocapture output.
Actual hosted output-format qualification is required before timing dispatch.

Before any campaign, run twelve nonignored stage_b_validation tests from the
contract, each in its own exact selection with --test-threads=1 --nocapture
--format=terse --color=never: ten cells for16 continuous verified cycles without
clocks or latency output, plus ordinary-three-RX-owner refusal for16 cycles in
both modes. Every successful qualification test emits exactly one newline-prefixed
`COAPTIC_STAGE_B_QUALIFICATION ` compact JSON object with exact keys schema,
contract_sha256, case, security, cycles, passed, measurement. schema is
coaptic-admission-stage-b-qualification/1, cycles=16, passed=true,
measurement="NOT RUN". The two negative-case IDs are ordinary_three_rx_owners_refuse;
other IDs match the five case names. This exercises the real terse libtest/prefix
parser without producing timing samples. List these12 separately; also list the
10 ignored timing tests. Retain/hash the test artifact pair before its first
validation launch and verify those bytes afterward. A build of either arm must
pass all12 exact qualification processes before a successful build handoff.
Software proof mode stops after both
arms (24 qualification executions). A later campaign builds and qualifies both
fresh artifact pairs again, then launches its separate40 timing processes. Prove repeat reuse
beyond four bindings, legal relation/Call/body cleanup and exact phase counts.
Feature-off defaults/censuses and both old source files remain unchanged. Reuse
old run41142584716 only for those byte-identical proofs; do not infer the new
integration driver works. Qualification purpose stage-b-qualification cannot
feed measurement purpose stage-b-regression. Keep outer custody/refusals intact.

## Native result schema

Exact root keys: schema, contract_sha256, contract, case, security, profile,
operations, warmup, calibration_samples, verified_cycles, latencies_ns,
calibration_ns, internal_datagrams, udp_datagrams, handler_calls, clock_ms,
metrics, sender_sequences, memory, settled. No extra keys. schema is the native
schema in the contract. contract is the complete compile-time included JSON
object; contract_sha256 is its pinned canonical hash. No runtime count/cell knobs.
The selected test defines its literal case/security. capacities are the profile
object inside contract, independently asserted against actual App/Engine setup.

latencies_ns maps exactly the case labels to1000 uint128 nanoseconds each;
calibration_ns contains4096 uint128 values. Reject bool-as-int, nonfinite values,
wrong lengths/labels and selected latencies greater than30s. A positive group
mean is required. clock_ms is [0,279744000]. Counts include all1128 verified
cycles, whereas arrays include exactly1000 measured cycles. Metrics is exactly
the seven per-case counter names in contract (admission_rx_refused,
admission_tx_refused, admission_refusal_sent, admission_refusal_unsent,
observe_register, observe_cancel, observe_notify) multiplied by1128. Native
assertions also classify other transport/cache changes and refuse unexplained
state; they do not relax unexpected metrics to fit a result.

sender_sequences is null for unprotected; for OSCORE it is exactly app, peer,
fresh_app, fresh_peer, max_piv_bytes. app/peer are [before,after], initial0,
nondecreasing <=11280; fresh counts equal the actual observed allocation deltas,
max_piv_bytes=2. Check every fresh allocation/encoded PIV outside clocks and
never treat a bound response without PIV as a missing allocation.

memory is exactly app_inline_bytes, app_pool_requested_heap_bytes,
fixture_inline_bytes, fixture_requested_heap_bytes, fixture_total_requested_bytes,
peer_context_nested_bytes, latency_bytes, calibration_bytes, token_ledger_bytes,
serializer_buffer_bytes, remaining. App includes its CoreIo arrays; don't add
them twice. fixture_total=fixture_inline+fixture_requested_heap<=262144 includes
all explicit auxiliary owners, peer context, metadata/scratch and serialization
buffer. Peer size is nested information, not an extra addition. Fixed maximum
arrays are48000+65536+27072 bytes; stream JSON through fixed8192B serialization
buffer, not a growing String. SmallDevice App pool heap is0; Default requested
pool heap comes from the exact public MemoryLayout. remaining is the literal
`allocator/runtime/initialization/peak-stack costs unknown`. These are requested
owners, not a whole-process or peak-memory guarantee.

settled is exactly calls_collected_once, peer_bindings_consumed, rx_empty,
tx_empty, observe_empty, bodies_empty, pending_empty, io_empty, dedup_expired,
all true after final expiry. Known Calls are collected once and checked again;
public operations/source-backed retirement establish App binding settlement,
not an invented private binding-count inspection. Replay/security history is
preserved, not reported empty.

## Analysis, contract isolation and budgets

For each of18 security/path strata and each AB/BA order, form20 consecutive
50-value block means with math.fsum. Reset Random(20261030) for every comparison;
each replicate draws A20 first and B20 second with replacement, even in BA.
10000 replicate ratios are Bmean/Amean. Upper one-sided95 is the linear .95
quantile at(n-1)*.95. All36 upper bounds must be<=1.02. Report each result and
orientation; no pooling/exclusion/calibration subtraction/replacement. The bounds
are conditional on one process per arm/order, not independent processes per block
or simultaneous95% coverage. Missing/invalid/inconclusive/failed data stops promotion.

Thread an allowlisted StageB contract/hash and purpose through owner, worker
specs, build/artifact receipts, sample selections, results and analysis. Expected
identity comes from frozen source, never from supplied evidence. Reject cross-mode
or cross-contract evidence before process launch. Preserve old contract values,
worker/error custody and affinity restoration. The old test suite remains valid.
Prefer a small separate StageB module explicitly passed the existing runner API;
avoid circular imports/double __main__ modules or changing globals per selection.

Reuse830s build owner,400/450s Cargo,8GiB build,64MiB hosted evidence with4MiB
failure reserve,300/450s measurement,30s/process,2MiB combined process output,
35min job. Forty maxima exceed the aggregate300s limit: exhaustion is a retained
failure, never a cap raise or a successful prefix. Measure all40 selected healthy
processes before all36 decisions; source/runtime/resource failures stop later work
with attempted/incomplete/not-run census. The aggregate evidence cap dominates
per-process limits. No local Cargo/build/native execution on constrained disks.

The new owned private phase D:/CoapticCurrent/admission-stage-b-20261030 and any
future public retained bundle together have a1MiB cap. Complete selected arrays
must be reconstructible within it before promotion; retention failure refuses
without dropping samples or enlarging caps. The earlier continuation phase is
closed65391/65536B and unchanged. Source implementations retain0B private output.
Parent owns final source freeze, software proof, preregistration, dispatch,
review and promotion; all new execution remains NOT RUN.


## Retained qualification failure and primary-context correction

Qualification run41151191502/1 at41cad50 compiled armA and passed114 portable
checks. A's rx_unprotected passed16 untimed cycles; rx_oscore then failed with
macro-located assertion left0/right1 at fixture.rs:1147. The remaining22 native
cases, armB build and all timing were NOT RUN. The original sealed collector is
24395B, SHA256 f393110575fd493727ad01fba1eb53eaef5c53b2f3f4fc2ddbe2d2c32c4381e6.

Source inspection found the sequence observer used association_at(0), although
Builder.oscore attaches an unnamed primary context. That observer always fell
back to zero. The corrected fixture reads the live primary context through
App.oscore; it neither changes protocol state nor resets a sequence. Cycle
checks now identify the case, cycle and counter. The original macro panic did
not identify its narrower assertion; the source defect is independently clear.
Corrected compilation and all24 qualification executions remain UNRUN until a
separately recorded source-specific dispatch. Counts, capacities, protocol,
clock boundary, contract hash, gates and all prior failures remain unchanged.
