# Single RX ownership proof before pressure timing

This plan covers one public-App correctness proof, with SmallDevice resources,
full_responses and unprotected traffic. Native source is newly written and UNRUN
at this integration handoff. Portable Python mocks are not native execution.

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

The sole pressure test's exact qualified namespace is:

    admission_pressure::rx_credit_survives_incoming_refusal_and_collection_recovers_unprotected

Its declared census is exactly one test. Both arms must also list and pass exactly
these four original wall tests, with their observed module namespace:

    batch_tests::wall_cli_bounds_and_mixed_flag_refusal
    batch_tests::wall_exact_presets_both_payloads_verify_without_growth
    batch_tests::wall_full_metadata_and_complete_payload_are_required
    batch_tests::wall_missing_bad_response_and_authentication_refuse_then_recover

The proof retains RX credit through a real outbound client's completed response.
It injects an incoming GET with a different MID/token and checks matching 5.03,
zero handler calls, one RX refusal metric increment, and the same held slot,
pin state and occupancy after poll. It collects the exact held response, verifies
credit release and one-time collection, then uses another fresh GET to verify
content recovery and one handler call. This is ownership evidence, not timing.

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

Protected RX, TX pressure, cancellation and Block2 continuation proofs are
UNIMPLEMENTED. This single proof is not Stage B completion or promotion. Establish
correctness proofs before quantitative timing. A future four-case by two-mode by
ABBA timing design would total 32 processes; its matrix and gates are not frozen.
Do not infer those cases from this single unprotected test.

Stage A run 41086130074 at c58e47e36ebc5d90d3301fb62fa244d5e4803aae
already completed 16 processes and eight passing gates with independent review;
no retiming is requested. Original failed run 41084281643 remains historical
evidence of the wrong module-prefix refusal. admission_wall_plan.md and its
schedule, statistics and gates remain unchanged. This proof adds no CPU, device,
whole-memory, protocol certification or general performance claim.
