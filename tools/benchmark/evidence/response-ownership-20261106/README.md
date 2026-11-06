# Response ownership: four rejected candidates

All four candidates are rejected against merged core baseline
`fd7d18a72f795779e352443ebdeef9533be7fb27`. Nothing in this package is an
accepted optimization. Preserve the sources, failures and original gates;
do not repeat unchanged candidates or infer runtime benefit from smaller futures.

- **Borrowed handler, `04c1c8377cdd2896de91310c81714eb10865eaba`:** separates
  request handling from reply encoding and permits request-backed responses.
  Complete SmallDevice, fixed Service and allocated Service futures shrink by
  928, 1,024 and 992 bytes respectively. The one complete runtime cohort fails
  17 workload bounds. All-workload sync ratio is 1.005496 (upper95 1.007985);
  async is 1.025043 (upper95 1.027402). Dispatch code and selected polling frames
  grow as well. Smaller futures did not make this integration acceptable.
- **Unified reply view, `3a1e6004444beadd984d7f6e9c5c7573ce077ddb`:** uses one
  reply-view path instead of separate ordinary/assembled dispatch paths. It is
  rejected before timing: selected SmallDevice, fixed Service, allocated Default
  and allocated Service polling frames grow by 320, 784, 304 and 528 bytes.
  No runtime cohort or CPU gain exists for this source.
- **Response metadata, `6ad0bfd2eb7347cf6d2399ccf5cba47a0df9024f`:** owns only
  the message fields needed after receive processing, without a public API
  change. All three selected complete futures shrink by 120 bytes, and 1,219
  library tests pass. The allocated Service dispatch polling frame grows by
  16 bytes, violating the prospective frame guard. This is an untimed rejection;
  source review and passing tests do not override it.

- **Borrowed response origin, `9e5bad550fcc7cb3a29323efeeaea58dfb270896`:**
  borrows peer and receive-time fields from the already borrowed immutable reply
  metadata. All three selected complete futures shrink by 216 bytes. The fixed
  Service dispatch frame shrinks by 32 bytes, but the allocated Service frame
  grows by 16 bytes and fails the same prospective guard. This source is rejected
  before timing; no CPU cohort exists. Its 1,220 library tests pass with a
  `private_interfaces` warning. The later visibility-only cleanup `5690c31` is
  retained separately as an **unbuilt** patch and has no qualification claim.

## Evidence and limits

The native baseline executables are the accepted phase-sharing candidate
`3e592adb1fd52c5e6918af1b4e810bb874413bad`, whose production source matches
merged `fd7d18a`. Their exact hashes are retained in `baseline-reuse.json` and
the executables remain in
[phase-sharing-static-20261106](../phase-sharing-static-20261106/README.md).
The new baseline is explicit; these results are not comparisons to the older
`bd63199` baseline used before that merge.

Borrowed-handler has all 64 fixed process pairs for each of the same 28 cells:
20 ordinary SmallDevice32 and fixed/allocated Service1024/16384 cells, plus eight
retained Q-Block2 11264-byte cells. Both actual synchronous poll and asynchronous
wait/progress execute in unprotected and established OSCORE modes. Every cell
and the ordinary/all sync/async aggregate upper95 ratio must be at most 1.02.
Process-mean log ratios use Student-t df63 with conservative critical value 1.67.
The order is AB, BA, BA, AB repeated sixteen times, CPU0, 128 warmup operations,
8192 operations for ordinary32/1024 and 1024 for large/retained cells. No trimming,
replacement, early stopping or pooled rescue occurred.

QueryThreadCycleTime covers the complete server App drive with the original
memory transport, pending timer and manual polling. Client preparation,
authentication and verification are outside the interval. These are CPU-cycle
observations, not socket latency, executor scheduling, peak memory, target
qualification or a libcoap ranking. The fixture's ordinary/static handlers do
not use the new borrowed-response capability, so there is no dynamic-handler
speed claim.

All recorded resident App/requested-pool owners stay unchanged. The original
selected futures are 15,952 bytes for SmallDevice and 15,496 bytes for each
Service storage backend. The verifier compares those exact compiler records,
common host App sizes and the selected Thumbv7EM App/table sizes. Compiler future
objects and selected polling/encoder/reclaim frames are separate measurements;
they must not be added to nested App/pool owners or interpreted as peak stack.
No reserved stack reduction is justified.

The borrowed/unified approaches introduce a ReplyPartition storage capability
and higher-ranked handler lifetime requirements. The borrowed storage view
copies Metrics (92 bytes, plus optional diagnostics) and restores it on drop.
Configured pools and inline response capacity remain unchanged. Their fixture
adaptation adds ReplyPartition bounds **and changes the retained callback return
signature from `Response<'static>` to `Response<'_>`**. The executable handler
bodies are unchanged. Original METHOD text saying only trait bounds is preserved
as an original record; this paragraph corrects that omission. The metadata
and borrowed-origin candidates use the unmodified original seven-file fixture.

## Checks and preserved failures

Borrowed-handler retains an earlier direct-lifetime compile failure (six E0502
borrow conflicts and one E0308 callback mismatch), initial build failures, their
logs and subsequent source changes. Its twelve focused passing checks belong to
a production precursor, before the redundant inner body owner was removed and
lazy lookup restored. They are **not final-candidate qualification**. The expanded
protected/counter regression patch in
`borrowed-handler.zip/post-review-unmeasured-tests.patch` was never run and is
not applied by the reconstruction script. Unified-reply has build/layout
evidence and its failed preflight, not a runtime result. Response-metadata keeps
the 1,219-test log, focused test attempts, source review and failed frame check.
Borrowed-origin retains the 1,220-test log and earlier failed test attempts; its
`unbuilt-visibility-cleanup.patch` is not applied by `prepare.py`. The tested
constructor visibility produces a warning, so no full qualification is claimed.

The frame gate for unified-reply, response-metadata and borrowed-origin was
written before runtime work and stopped all three candidates. The later
dispatch-frame diagnosis does not replace or retroactively alter borrowed-handler's already failed CPU
cohort. Larger generated code is a possible cost explanation, not measured causal
attribution. No unsupported whole-behavior or qualification claim follows from
passing a focused test.

## Reproduce offline

Run `python -B verify.py` with Python's standard library. It verifies all 7,524
archive members and SHA256 manifests, matches the pinned baseline/candidate
executables, checks all 3,640 process exits in their expected order, recomputes
all 3,584 timing outputs and every aggregate/cell bound, and confirms rejection.
It also verifies fixture reconstruction, exact selected layout records, resident
owner preservation and all three untimed stack-frame refusals. It does not run
native code, build, fetch dependencies or sample again.

`python -B prepare.py CORE_REPO NEW_OUTPUT VARIANT` materializes exact source
from the merged baseline plus its recorded patch. VARIANT is `baseline`,
`borrowed-handler`, `unified-reply`, `response-metadata` or
`borrowed-response-origin`. The destination must not exist. It reuses the sibling
dispatch fixture, verifies original hashes,
reconstructs the two type-only fixture adaptations when needed and verifies the
adapted hashes. The archived native producers retain their original paths;
native reproduction would require a compatible Windows MSVC/Rust 1.99.1 lane,
release thin LTO, one codegen unit, debug=1 and forced frame pointers. Source
reconstruction is not authorization to rerun rejected cohorts.

The archives retain native EXE/PDB files, source and fixture patches, raw
observations, methods, scripts, assembly, layouts, build/test logs and refusal
records. Private OWNER, resource identity and board notice files are excluded.
The package is below its 100 MiB tracked-output budget and should remain with
the experiment record; original source and native evidence roots are untouched.
