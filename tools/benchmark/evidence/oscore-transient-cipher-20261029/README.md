# Rejected transient cipher prototype - 2026-10-29

**REJECT; production prototype remains unmerged.** [Run 40951035071](https://github.com/jeffglousher/coaptic/actions/runs/40951035071), attempt 1, compares authenticated client response opening in one executable. Candidate `636ad4e22185b5bf7b4d9f6e8641388814539511`, baseline `869d4354f4a29158fe3644b8d5d71b9b0bb591d6`; source and temporary harness remain in [PR707](https://github.com/jeffglousher/coaptic/pull/707). The candidate retains a transient lazy AES schedule across latest/original response-binding attempts; ordinary one-shot decryption and both binding searches remain unchanged.

- Ordinary round-robin responses: **+3.452% / +3.149%**.
- First-slot ordinary responses: **+2.816% / +2.605%**.
- Latest-bound Observe responses with PIV: **+2.189% / +1.839%**. All three normal-path upper95 guards exceed +2% in both rounds.
- Genuine fallback with PIV: **-10.544% / -10.662%**; without PIV: **-10.409% / -10.517%**. All four upper95 bounds are below zero and means pass the required 5% improvement.
- Rejected two-attempt traffic with PIV: **-15.505% / -15.269%**; without PIV: **-15.989% / -15.898%**.

Both fallback modes must improve >=5% with upper95 below zero in both rounds; each normal/rejection upper95 regression must remain <=2%. The six failed normal guards reject the implementation despite real fallback gains. No sample replacement, changed gate or eight-profile expansion follows. The result preserves a fallback-reuse engineering lead; it does not prove that the Option or any particular instruction caused the normal-path cost. A different design would be a separate experiment.

All four arms, **136 OSCORE correctness tests**, and 48 fixture records pass. There are **28 arrays / 840 positive finite Criterion sample pairs**, not 840 socket operations. Each arm verifies complete plaintext, accepted reference, output/tails, genuine fallback, obsolete-binding rejection and tampering before and after timing. Three independent fixture key contexts separate ordinary, explicit-PIV and absent-PIV modes. Each encryption has a fresh nonce; repeated decryption does not exercise replay admission.

Two rounds run AB then BA. Seven metrics use Criterion 0.5.1 without default features, 30 samples, 0.5 s warmup, 1 s measurement, 10,000 resamples and 95% intervals. Round 2 ratios and interval endpoints are inverted/reversed to report candidate/baseline. `std::hint::black_box` surrounds inputs and full outputs, never baseline searches or cipher setup. Setup/assertions remain outside clocks. Rust 1.99.0, Linux x86_64 CPU0, release thin LTO, one codegen unit, `std,oscore`, no defaults. The baseline contains both the exact original entrypoint and original authentication loop using unchanged one-shot AEAD.

The job took 299 s, including a reported 228 s release build; the proof/comparison step took 281 s. Preparation and instrumented authentication timings are separate. The earlier quick check uses Rust 1.99.1 and the identical source tree: 1,208 all-feature and 711 minimal-feature library passes, formatting and strict Clippy. It is separate producer evidence, not this benchmark's compiler or an MSRV claim.

`data.json.gz` retains all **126 exact Criterion JSON members**, selected lock, temporary manifest/test typing, frozen plan, correctness output, decision and explicit derived input/fixture projections. Complete source maps and binary bytes are not retained here. `receipt.json.gz` preserves the exact 10,191-byte collector receipt; `index.json` hashes the publication. The collector verified all 358 canonical and 362 reconstructed frozen source claims; compiler/executable identities and hosted process cleanup remain producer evidence. No ELF was uploaded or independently rehashed.

These are immutable client-authentication wall intervals, without replay admission. No socket/process-CPU, server CPU50, hardware, emitted-stack or whole-memory improvement is established. Existing delivered memory reductions remain intact. The prototype's normal-path regressions bar default promotion; functionality passing does not waive performance guards.
