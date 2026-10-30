# RX and TX ownership proofs before pressure timing

This plan covers three public-App correctness tests with SmallDevice resources:
unprotected retained-response RX pressure, and fixture-owned TX pressure in
unprotected and OSCORE traffic. The expanded native cohort is UNRUN at this
integration handoff. Portable Python mocks are not native execution. Historical
run [41094806564](https://github.com/jeffglousher/coaptic-validation/actions/runs/41094806564)
passed the original single unprotected RX proof on both arms; it does not
establish the new TX assertions or the expanded three-test census.

The immutable core arms are A 623c82db1a6606ec86cd56bb52009988b9f0d87e and
B 8782a6a0b0aef2facf51bec884cfe37f2a80f28d. The parent checkout's unrelated
dedup branch is not an input. The companion source is bound by the dispatch's
immutable expected suite SHA, complete tracked snapshots, and normalized LF SHA256
pins for bench-core.rs and bench_core/admission_pressure.rs in
admission_wall_screen.py. The four-line cfg(test) module include changes the native
fixture source hash intentionally. It does not change production behavior:
removing that exact include yields the historical normalized production fixture
SHA256 fe144de7598da4b753e668a17a8cbd91033896691a0ee045c5be711e784c0272.
No old fixture pin is claimed to match the new test source.

The exact pressure test census is:

    admission_pressure::rx_credit_survives_incoming_refusal_and_collection_recovers_unprotected
    admission_pressure::tx_credit_survives_refusal_and_release_recovers_oscore
    admission_pressure::tx_credit_survives_refusal_and_release_recovers_unprotected

Both arms must list and pass all three tests. An old successful RX-only listing
or completion cannot satisfy the expanded proof. Both arms must also pass exactly
these four original wall tests, with their observed module namespace:

    batch_tests::wall_cli_bounds_and_mixed_flag_refusal
    batch_tests::wall_exact_presets_both_payloads_verify_without_growth
    batch_tests::wall_full_metadata_and_complete_payload_are_required
    batch_tests::wall_missing_bad_response_and_authentication_refuse_then_recover

The proof retains RX credit through a real outbound client's completed response.
The public resource-based builder already enables full-response retention. Before
protocol setup, the proof inventories genuine RX IDs with acquire/release and
checks that the pool is empty again with its original cursor. Released IDs are
only read-only pool locators; they do not grant ownership across reuse. The
single occupied locator is rebound to the retained response by decoding and
checking its MID, token, code and payload both before and after the incoming poll.
Only response collection releases that live reservation.
It injects an incoming GET with a different MID/token and checks matching 5.03,
zero handler calls, one RX refusal metric increment, and the same held slot,
pin state and occupancy after poll. It collects the exact held response, verifies
credit release and one-time collection, then uses another fresh GET to verify
content recovery and one handler call. This is ownership evidence, not timing.

Each TX test reserves one genuine public TX slot, leaving exactly one free
control slot. It encodes a sentinel without queuing a transmission and records
the slot's bytes, endpoint, occupancy and pin state. An incoming fresh request
must receive a matching 5.03, increment the TX refusal metric once, leave the
handler uncalled, and preserve the reservation and sentinel. The dedup table is
empty before pressure; the refusal's inline replay must not own a TX pin or hide
an eviction. Only the fixture releases its reservation, once, then a distinct
MID/token request must recover the complete expected response and one handler
call. OSCORE protection and response authentication use one continuous context;
no sequence, key, replay or binding state is reset for recovery. All three tests
serialize the shared handler counter through a module mutex, including ordinary
parallel native-test invocations. No timer or performance sample is added.

Run admission_wall_screen.py proof with the same required --core,
--expected-suite and --output arguments as build/all. The existing outer
source/lock transaction and shared wrapper own both arm builds and restoration.
Each arm runs wall listing/execution, pressure listing/execution, then retains
the Cargo build artifact pair. Census output and per-arm purpose/test receipts
are revalidated before retaining/loading artifacts. The final proof-complete.json
is written only after both verified arms and final source checks. It reports
passed, both test sets, ownership-proof purpose, measurements NOT RUN, limited
scope and unimplemented cases. No measure worker or 60000-operation binary
measurement is launched. Proof evidence cannot satisfy stage-a-screen purpose;
build -> measure retains the same stage-a-screen identity.

The registered ci.yml workflow_dispatch route requires admission_wall_screen=true,
admission_pressure_proof=true and stack_profile=false. Orphan and mixed proof
requests fail without validation, profiling or measurement jobs. The reusable
admission-wall-screen.yml accepts typed proof_only:boolean, default false,
through workflow_call or direct workflow_dispatch. Strict true/false environment
validation selects literal CLI proof or all; input is never shell source.

Existing budgets remain 830 seconds build owner, 400 seconds Cargo / 450 seconds
outer worker, 8 GiB build and 64 MiB evidence, including the existing reserve.
Existing source restoration, unresolved cleanup and reporting-error contracts
apply. No new job cap or profiling dependency is introduced.

Protected RX, Observe cancellation and Block2 continuation proofs remain
UNIMPLEMENTED. The two TX tests are implemented but UNRUN. This cohort is not
Stage B completion or promotion. Establish
correctness proofs before quantitative timing. A future four-case by two-mode by
ABBA timing design would total 32 processes; its matrix and gates are not frozen.
Do not infer those missing cases from the implemented RX/TX tests.

Stage A run 41086130074 at c58e47e36ebc5d90d3301fb62fa244d5e4803aae
already completed 16 processes and eight passing gates with independent review;
no retiming is requested. Original failed run 41084281643 remains historical
evidence of the wrong module-prefix refusal. admission_wall_plan.md and its
schedule, statistics and gates remain unchanged. This proof adds no CPU, device,
whole-memory, protocol certification or general performance claim.

## Retained compile failure

PR check run 41093144320 at 2a550c1 passed 668 benchmark Python tests with
17 skips, then native test compilation failed: the ConfiguredBuilder has no
full_responses method, and SlotId::from_index is private. No RX proof executed.
The correction removes the redundant builder call, uses genuine public pool IDs,
and binds the revised native source hash. Profile capacities, the test census,
workload pins and all process/resource limits remained fixed. The corrected
single RX proof subsequently passed on both arms in run 41094806564. That
historical outcome remains separate from the current expanded cohort.

The expanded cohort changes only the cfg(test) pressure module, its source pin,
declared census, portable refusal coverage and this plan. Production fixture
behavior, core arms, Stage A plan/statistics and all process/resource limits stay
unchanged. The original dedup screen at immutable suite b0d4662 remains rejected;
no new dedup screen, timing process or replacement sample is authorized here.

## Retained expanded-cohort compile failure

PR check run 41121946433, job 124289889389, at cca98fbb ran 689 portable
tests successfully (17 skipped), then failed native test compilation with E0599 at the
new `dedup_entry_ref` call. That accessor exists on the two admission pins but
is absent from the core checked by ordinary CI. The correction uses the
existing by-value `dedup_entry` accessor for the same test-only TX-pin assertion.
It does not change core code or weaken the ownership check. The normalized
pressure source hash is rebound. New TX execution remains unrun; no two-arm
proof or timing process was dispatched from the failed commit.
