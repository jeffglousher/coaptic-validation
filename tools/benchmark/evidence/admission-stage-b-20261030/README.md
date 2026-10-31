# Stage B rejected screen — STOP

Candidate `8782a6a0b0aef2facf51bec884cfe37f2a80f28d` is rejected: **13 of
36 required gates failed; 23 passed**. All 40 timing processes, 24 qualification
executions, four listing commands and 114 portable checks completed. The first
RX / unprotected / AB / poll upper bound is `1.0345551317572643`, above the
inclusive `1.02` limit. A passing stratum is not a general performance benefit.
There was no missing/invalid/inconclusive gate. No rerun, replacement, cap raise,
pooling appeal, filtering or calibration subtraction changes this decision.

The parent recorded STOP, closed core PR 716 without merge, and closed issue 713
as measurement complete. This bundle preserves the rejected result for review;
it does not authorize promotion. [screen.html](screen.html) shows every exact
comparison with accessible values and optional filters, without external assets
or network requests. It has not been browser-rendered by the evidence publisher;
the parent owns visual review after freeze.

## Immutable identities

- Run [41154445351/1](https://github.com/jeffglousher/coaptic-validation/actions/runs/41154445351),
  `workflow_dispatch`, completed failure; hosted Windows job
  `2026-10-31T01:15:28Z` to `2026-10-31T01:27:44Z`.
- Runner source `c65604510749424bc3efc2b54157bef08c036c42`, tree
  `901553be75877c3c59e309d4252028d8abb8ba55`.
- A `623c82db1a6606ec86cd56bb52009988b9f0d87e`, tree
  `4f349c19039de513487dff283289658402593991`.
- B `8782a6a0b0aef2facf51bec884cfe37f2a80f28d`, tree
  `ebc37d15f4d37aa2dfd322db16aff4d448c3d321`.
- Frozen contract SHA-256
  `161b7fd033cd7c2cc37b203f878b4307de913e2da2b651bacdbe9e84c186a83c`,
  purpose `stage-b-regression`.
- Current artifact `13024269755`, ZIP `5090445` bytes, API and actual SHA-256
  `9a41a3511034bb316c82cd4c662043b7b074677f6ce40ffad174385a4fab5b70`;
  274 regular members, `15287649` expanded bytes.

## Retention and reconstruction

`data.json.gz` reconstructs **all 270 original text members byte for byte**,
including empty stderr, every process/qualification/listing output, raw timing
output, result/failure receipts, source manifests, build output and logs present
in the artifact. No text member was truncated or dropped. Its concatenated UTF-8
payload is XZ-compressed, base64 encoded and wrapped in deterministic gzip with
zero timestamp. Offsets, lengths, SHA-256 and CRC32 identify every original text.
The index records raw and Git blob hashes, sizes and decompressed payload hashes.
The full original manifest remains in the exact sealed timing collector.

Only four original binary members are excluded: A/B integration-test EXE/PDB
pairs. Their names, sizes, actual hashes and CRCs remain in the collector. The
collector checked the binaries in RAM; the publisher checked all 274 current ZIP
members again in RAM against that manifest and the API ZIP digest. No ZIP or
binary was written to disk. The ZIP was downloaded once for this new publication
purpose after collector custody release. Redirects stripped authorization on a
foreign host. Remote artifact expiry may make those four binaries unavailable;
the standalone verifier can verify retained metadata but cannot rehash absent
binary bytes. The excluded pairs are not needed to reconstruct any timing array.

`collectors.json.gz` retains three sealed receipts exactly: original qualification
failure 41151191502 (24395 bytes), corrected qualification 41152630644 (32397
bytes), and full timing 41154445351 (77438 bytes). Their actual hashes are fixed
in `verify.py`. The corrected qualification receipt's actual **64 hexadecimal**
hash is `4a698384e84dd29234652cfdfba74dcff7a3e34a2b47b6f063ae299ecaea6d99`.
The earlier 65-character handoff typo is explicitly corrected in the retained
root correction record; the original receipt remains unchanged.

`parent-records.json.gz` retains every phase-root file present at packaging,
excluding collector bytes already retained separately. It includes OWNER,
source/review/correction, all qualification/timing preregistrations and dispatches,
receipt-hash correction and the parent STOP/core closure records. Exact filenames,
sizes and hashes are in `index.json`. This is a complete-at-packaging snapshot,
not a claim to include future publication/merge delivery metadata. Two exact
immutable runner source files are additionally retained under `frozen-source/`
for attributed schema-validator reuse. No private bytes were modified.

## Standalone verification

Run `python -B verify.py` from any directory, using Python's standard library.
Add `--self-test` for the RAM-only refusal, roundtrip and heuristic scan checks.
The verifier performs no network, subprocess, producer entrypoint, native runtime
execution or writes. A reproduced failed gate is verification **SUCCESS**.

It verifies file/Git/payload/member integrity; reconstructs all 270 text members;
checks all 40 exact native schemas, strict JSON and libtest output markers,
counters, PIV bounds, memory ledgers, settled states, command/schedule/arm/profile
and purpose bindings; checks all 24 qualification outputs and four exact named
listings; and checks source/build/core/binary metadata relationships as retained
data. The exact pinned pure validator functions are AST-extracted from retained
`c656045` source with literal constant and definition census checks. This reuse is
attributed, rather than presented as an independent runtime implementation.
The original collector independently checked 1505 immutable source file hashes;
this standalone bundle binds their retained maps and collector hashes, not their
absent full source contents or compiler behavior.

All **72000 latency values and 163840 calibration values** are retained; each
process has 128 warmup and 1000 measured cycles, with 4096 separate calibrations.
Every integer is checked for exact count, bound and non-boolean type. Statistics
are independently recomputed from the original latency arrays: 20 consecutive
blocks of 50 with `math.fsum`; 10000 replicates; `Random(20261030)` reset per
comparison; A20 draws then B20 even for BA; one-sided linear 95th percentile at
`(n-1)*.95` using **weighted endpoint interpolation**, inclusive upper `<=1.02`.
All 36 producer and collector floats must match exactly, with the fixed STOP
vector. The collector's initial difference-form interpolation differed one ULP
on comparison 26; weighted endpoints reproduce the frozen producer exactly and
do not change decisions. No sample is dropped and calibration is not subtracted.

`checks.json` records data-only verification and RAM-only refusal checks, the
publication security heuristic, coordination exceptions and resource budget.
It does not create a new native measurement or qualification claim.

## Scope, exceptions and custody

The evidence is instrumented release integration-test **complete App::poll wall
time**, with preparation/authentication/checks/cleanup outside clocks. It is
conditional on each process pair. Two process orders cannot establish host
independence or simultaneous 95% coverage. It is not CPU/socket/device/stack or
whole-memory evidence. Cause of the timing failures is unknown. Source-derived
footprints account only for identified memory; allocator/runtime/initialization/
peak-stack costs remain unknown, rather than a whole-resource guarantee.

Compiler/tool execution, serial process execution, affinity, RSS, restoration and
cleanup remain producer attestations. VM retirement is unknown. Worker prepared
spec/task files and tool executable bytes are absent; their prepared/tool byte
hashes cannot be independently reread. The artifact does retain actual owner/build
bytes and their bindings. No ETW or C# evidence was selected. A cleanup scalar is
not ETW-stop proof. Completed workflow logs were independently checked by the
collector; their manifest is retained, while workflow-log ZIP bytes outside this
artifact are not retained here.

The original macro failure's detailed causality is unknown. The independently
identified observer defect was that `association_at(0)` did not describe the
primary unnamed OSCORE context. Corrected source used `App.oscore().sender_seq`
and qualified separately before timing; both the failed and corrected receipts
remain. Original qualification polling included 17/21-second exceptions; timing
included an initial jobs-status API 13.9-second exception, explicitly sealed.
Mailbox startup/wrap retention gaps and unavailable companion notices remain
recorded; no complete coordination-history claim follows from later successful
GET/ACK. Publisher startup used the supplied host hook identity and read full
relevant notices before acting.

The publisher owns only this subtree and one scoped `.gitattributes` append.
The public bundle plus exact attributes delta is capped at 700000 bytes; the
combined private/public phase ceiling is 1048576 bytes. No local Cargo/build,
native test/workload, ETW, replay, install, run polling, new measurement, ref,
commit, push, PR action or cleanup was performed for this publication.
No old evidence, fixture, workflow, runner or contract bytes changed. The parent
owns independent publication review, integration and squash merge. After freeze,
all publisher write/read holds are released to the parent; private retained phase
records remain owned by the parent, with no deletion or runtime-retirement claim.
