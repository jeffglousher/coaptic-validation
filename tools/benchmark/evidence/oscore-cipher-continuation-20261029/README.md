# Response cipher continuation: REJECT

[Run 40958010326](https://github.com/jeffglousher/coaptic/actions/runs/40958010326), attempt 1, compares candidate `905a3977b2c502349dbcce16988719a1696fda47` (tree `07eca0938417b9f2b87bc7759b08c57ef5942f1b`) with baseline `869d4354f4a29158fe3644b8d5d71b9b0bb591d6` in one executable. This separate source design replaces the rejected lazy-state prototype with a local cipher and a raw-authentication-failure continuation. It reuses existing private AAD, nonce and plaintext backing; one-shot opening and both binding searches remain unchanged. No normal-path equivalence or stack reduction is asserted.

**REJECT.** [Core #709](https://github.com/jeffglousher/coaptic/pull/709) remains unmerged. First-slot mean regression is +2.727% / +8.411%; upper95 is +5.431% / +13.257%, exceeding the frozen +2% limit in both rounds. Fallback gains pass, but do not override either failure. The precise regression cause remains unknown. No replacement samples, relaxed gates, eight-profile expansion or further cipher variant follows this campaign. The prior #707 REJECT and all its data remain separate.

Seven metric changes below are candidate/baseline, with normalized 95% intervals, round 1 / round 2. Negative means faster; positive means slower. These describe immutable authenticated-opening wall intervals, not socket transactions, process CPU or replay admission.

- `normal-no-piv`: -9.147999% [-14.664366, -3.780156] / +0.284811% [-0.532838, +1.088623].
- `first-slot-no-piv`: +2.727049% [+0.865403, +5.430722] / +8.410783% [+4.591455, +13.257234].
- `latest-observe-piv`: -0.784432% [-1.770534, +0.271622] / +0.690847% [-0.486703, +1.870054].
- `fallback-piv`: -17.037730% [-17.600694, -16.470699] / -14.638152% [-15.262807, -13.896950].
- `fallback-no-piv`: -16.921815% [-20.073969, -13.978016] / -15.105218% [-16.485914, -13.605328].
- `rejected-piv`: -19.052602% [-23.017632, -16.083704] / -16.873107% [-17.470471, -16.301333].
- `rejected-no-piv`: -18.398123% [-20.044898, -17.068222] / -17.021164% [-17.681519, -16.436412].

The frozen plan requires BOTH fallback means <= -5% and upper95 < 0 in BOTH rounds, and EVERY other upper95 regression <= +2% in BOTH rounds. Correctness and all identity gates are mandatory. Four arms run baseline/candidate then candidate/baseline on the same CPU and executable; round 2 reciprocates the Criterion ratio and reverses/inverts interval bounds. No pooled confidence interval or cross-run machine comparison is used.

139 release OSCORE correctness tests pass, with zero failures and one ignored probe. All four arms pass with 48 matching fixture records and complete response/reference/error/tail checks. The 126 retained Criterion JSON files contain 28 sample records, each with 30 time/iteration pairs: 840 positive finite pairs. The collector's 56-array count counts times and iterations separately. Authentication outcomes preserve latest/original fallback and reject obsolete/tampered inputs. Repeated immutable decryption does not establish App replay admission.

The measured build uses Rust 1.99.0, Linux x86_64 CPU0, Criterion 0.5.1 without default features, release thin LTO/one codegen unit and `std,oscore` without defaults. Each arm uses 30 samples, 0.5-second warmup, 1-second measurement, 10,000 bootstrap resamples and 95% intervals. The 219-second job includes a reported 155-second release build; the proof step is 205 seconds. Four timed libtest processes total 46.77 seconds. Setup, build and authentication intervals are distinct nested costs.

Separate [quick run 40957984918](https://github.com/jeffglousher/coaptic/actions/runs/40957984918) passes formatting, strict all-target/all-feature Clippy and 1,211 all-feature plus 711 no-default library tests. Its synthetic merge tree exactly matches the candidate, but it uses Rust 1.99.1. These producer results are not MSRV or the timing compiler's evidence. `extended_oscore` integration and the full feature matrix were not run; rejection ends further qualification.

`data.json.gz` preserves 132 exact producer text members: all 126 Criterion JSON files, correctness output, decision, selected lock, injected manifest, temporary typing record and frozen plan. Two clearly named `derived/` projections retain selected input identities and all fixture lines plus original stdout hashes. Complete 358/362 source maps were checked by the collector and remain remote; the projections do not contain those full maps. `receipt.json.gz` losslessly preserves the exact 12,246-byte collector receipt. `index.json` hashes each publication payload.

Remote artifact 12933854223 has 205 safe unique members, 237,852 compressed / 819,606 expanded bytes and SHA256 `e357763f7b0814b27964437d10c6e7d144aff2fd1d524ed97889bb1f2ab4b59e`. Paths, CRCs and member hashes were checked in RAM. No archive extraction, object execution, local compiler target or cache was created. The ELF is absent: executable/compiler identities, content rechecks, resource enforcement and process settlement remain producer-attested. No independent kernel cleanup, emitted-frame/peak-stack, physical, CPU50, server/socket or whole-memory qualification follows. Existing accepted memory improvements remain unchanged.
