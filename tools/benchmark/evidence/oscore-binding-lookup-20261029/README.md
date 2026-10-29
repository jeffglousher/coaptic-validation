# Rejected OSCORE binding lookup ? 2026-10-29

**REJECT; production change remains unmerged.** [Run 40941479068](https://github.com/jeffglousher/coaptic/actions/runs/40941479068), attempt 1, measures the authenticated client response-opening entrypoint against the exact original two-search method in one executable. Candidate `3474c106d5f1ea95f001bbb8e12fd35298775b45`, baseline `869d4354f4a29158fe3644b8d5d71b9b0bb591d6`; sources remain in [PR705](https://github.com/jeffglousher/coaptic/pull/705).

- Normal-entry mean: **+2.871% / +1.009%**, both 95% intervals above zero.
- First-slot mean: **+12.893% / +0.830%**; round 1 upper95 **+19.539%** fails the +2% guard.
- Original-binding fallback: **+0.483% / +0.099%**; no benefit established.
- Isolated lookup: **?21.154% / ?21.166%**; that improvement did not improve the full entrypoint. Its regression cause is unestablished.

All four arms and **134 correctness tests** pass. Fixtures check plaintext/reference equality, real fallback, obsolete-binding rejection and tampering. Two rounds run AB then BA; four metrics, 30 samples each, 0.5 s warmup and 1 s measurement. `std::hint::black_box` surrounds inputs/outputs, never the gap between old searches. Temporary Criterion 0.5.1 has default features off. Rust 1.99.0, Linux x86_64 CPU0, release thin LTO, one codegen unit, `std,oscore`, no defaults.

Frozen acceptance requires normal improvement ?2% and upper95 below zero in both rounds, improving lookup direction, and first-slot/fallback upper95 regression ?2%. Rejection ends sampling and eight-profile expansion.

`data.json.gz` is a JSON `files` map retaining **all 72 exact Criterion JSON members**, selected lock, injected manifest/test typing, correctness output, decision, relevant input/source projection and fixture lines. `derived/` entries are explicitly derived. Full source maps, full archive and executable bytes are not retained here. `receipt.json.gz` preserves the exact collector receipt; `index.json` hashes all publication files.

Earlier runs 40936640828 and 40938869342 failed compilation: all correctness/timing arms NOT RUN, zero samples. Fixes used Cargo-managed LTO and two temporary typed empty-slice assertions; setup-policy amendments are retained in source history. Cases and thresholds stayed fixed; no measured result was replaced.

These are immutable authentication wall costs, without replay admission. No socket/process-CPU, CPU50, hardware, emitted-stack or whole-memory gain is established. Compiler/executable identities and hosted cleanup remain producer evidence; no ELF was uploaded. Prior delivered notification-scratch savings remain intact.
