# Classified dedup screen: rejected

[Run 41110877140, attempt 1](https://github.com/jeffglousher/coaptic-validation/actions/runs/41110877140/attempts/1) completed all 16 measurement processes. Default unprotected failed in both AB and BA order; Default OSCORE failed in AB order. The other five comparisons passed. These failures reject this candidate under the frozen contract. SmallDevice results do not override the Default failures.

Core [PR #717](https://github.com/jeffglousher/coaptic/pull/717) is closed without merge. Screen tooling [PR #232](https://github.com/jeffglousher/coaptic-validation/pull/232) was merged separately after review and 30 passing checks. There is no core or API promotion, retry, replacement sample, changed gate, or pooled appeal. The cost cause remains unknown.

## Reproduce the evidence checks

Run `python -B verify.py` from this directory. It uses only the Python standard library and performs no native execution, subprocess invocation, or network access. Reproducing the expected failed gates is verification success.

The verifier reconstructs all 110 original UTF-8 text members byte for byte, validates all 16 schemas and commands, checks capacities and 22 native process receipts, checks both exact native test censuses, and recalculates every comparison from the raw arrays. Its pure schema and statistics definitions were AST-extracted from immutable suite `b0d4662`, following the admission bundle strategy; it does not invoke the producer entrypoint.

All 960,000 latency values and 65,536 calibration values are retained. Each process contains 60,000 measured operations, 128 warmups, and 4,096 separate calibrations. Each comparison uses 60 consecutive blocks of 1,000 operations, `math.fsum`, 10,000 bootstrap replicates, and `Random(20261030)` reset per comparison. Each replicate draws 60 A blocks before 60 B blocks. Intervals use linear equal-tail 0.025/0.975 quantiles. Unprotected requires mean B/A <= 0.99 and upper95 < 1; OSCORE requires upper95 <= 1.02, separately for each profile and order. There is no filtering, pooling, or calibration subtraction.

## Identities and storage

Suite: `b0d46620d443e7dd63aa1ff3fb8d70c83f3841b0`, tree `f7353494b65141a09afaa3acf6c1fa503af0166c`.

Baseline core: `623c82db1a6606ec86cd56bb52009988b9f0d87e`, tree `4f349c19039de513487dff283289658402593991`. Candidate core: `8f1f138c825f431149ed8a0a7eefbb6be6cb1b6a`, tree `598db5cb5bd3851381d783f1bc02ecf664e778a5`. Contract descriptor SHA-256: `0695f09dac05154c1a461d0816f060e8c5aee9945487e3312a181504870cb2a1`.

Artifact `13003363402` is 3,971,677 bytes, SHA-256 `3fb7ac36815a2a23e6ae772a5ea7e6d943a1ec7f3f7649e67c914fac5ed9a10c`. Its 114 safe, unique regular members expand to 15,764,233 bytes. Packaging checked the API digest, CRCs, sizes and hashes in RAM with 64 MiB compressed/expanded, 256-member and 32 MiB/member bounds; authorization was stripped on foreign redirects.

`data.json.gz` contains deterministic gzip JSON with an XZ/base64 payload and exact member offsets. All 110 text members are preserved; four EXE/PDB files are excluded. Their actual sizes, CRCs and hashes remain in the sealed collector manifest. No ZIP or executable bytes are retained here. The remote artifact expires November 13, 2026; future executable replay availability is not guaranteed.

`collector.json.gz` preserves the 34,814-byte sealed receipt exactly, SHA-256 `df7db235354c84612c6baab58d5d6d15ff179e2e6027e1dd90f28987089490f3`. Compressed preregistration and dispatch records preserve their original bytes. `index.json` records canonical Git byte sizes and hashes. A scoped `.gitattributes` rule prevents checkout conversion.

## Scope and limits

This is conditional two-process Windows, socket-free server `App::poll` wall evidence. Request preparation/protection and full response verification/authentication are outside the clock. SmallDevice uses fixed Constrained storage, a 32-byte response and four dedup entries; Default uses allocated storage, a 64-byte response and eight entries. The full route, Call, deferred, security and body capacities are retained in the verifier and collector.

SmallDevice emits a capacity ledger. Default emits seven fields; its capacities and 60,128 verified completions are established by pinned source plus successful exit, not an emitted verified-count field. Distinct MIDs at a fixed endpoint and full-table fresh-key eviction/retry follow from source inspection. Replacement, duplicate replay, pinned replies and spare-capacity performance are unmeasured.

The collector's source-map, golden/API checks, 79 portable tests and four native wall tests per arm are attributed evidence. Compiler execution, affinity, source restoration and RSS remain producer-attested. VM retirement is unverified. There was no ETW recording. No CPU, socket, device, stack, whole-memory or general-host performance claim follows.

Coordination limitations are preserved: the collector missed startup-before-audit mailbox ordering, the parent displayed bounded block means in tool output, and mailbox retention gaps prevent complete historical accounting. Packaging completed its supplied cursor traversals, relevant reads/acknowledgements and resource check before artifact work. Credential-pattern scanning is heuristic; no match is not proof that every possible secret is absent.

Root/Coaptic owns this evidence through parent review and delivery. The bundle plus attributes delta is bounded by 310,000 bytes within the combined 1 MiB evidence allowance. No new build, workload, capture or measurement was performed to package it.
