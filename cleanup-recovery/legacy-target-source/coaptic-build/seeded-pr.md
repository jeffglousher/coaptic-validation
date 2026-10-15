Add reproducible finite campaigns with explicit positive/refusal oracles and archived evidence. The pinned runner requires named tests and expected pass counts, so an empty test selection cannot pass.

Tested surface:
- 50,000 datagram cases from hand-written packets, bit mutations and arbitrary bytes: 20,080 accepted views preserve header/Token/options/payload through canonical encoding; 29,920 are refused. Guaranteed-invalid version/Token-length and too-small output buffers are checked separately.
- 50,000 CBOR mutations: problem-detail known fields survive canonicalization; missing-block sequences remain ascending and bounded; insufficient destinations refuse.
- 100,000 replay-window steps compare with an independent set model, including duplicates, stale/reordered arrivals, uncommitted authentication and the five-byte sequence boundary.
- 512 real encrypted request sequences each refuse corruption, accept the original and refuse its replay.

All 11 CONTRIBUTING checks passed with 559 library unit tests plus the two new integration campaigns. Source-bound final report is retained at D:\coaptic-build\seeded-qualification-final.json; logs seeded-validation-*.log. Final rebased head 08808f5 has the same tree as locally validated c313978. CI archives pinned-compiler campaign evidence.

No coverage percentage, exhaustive fuzzing, compound networking/lifecycle soak or device execution claim. Those remain open in #202. Reviewed oracle independence, deterministic reproduction, bounded work, failure reporting, packaging and claim precision. Advances #202.
