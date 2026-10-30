# Stack profiling

This tooling attributes observed stack samples. It changes no App behavior and
does not establish a performance improvement. Keep each source, operating system,
workload, process, thread and capture cohort separate.

## Portable analysis

`stack_profile.py` accepts `coaptic-stack-profile/1` JSON and the supported
`perf script` cpu-clock text format. It produces a standalone interactive flame
graph, with zoom, symbol filtering, and self/inclusive tables. It needs only
Python's standard library; the HTML uses no network resources.

```text
python -B tools/benchmark/stack_profile.py perf perf-samples.txt profile.json --identity identity.json --scope server-main
python -B tools/benchmark/stack_profile.py render profile.json profile.html
```

Outputs must be new files. Each input/output is limited to 16 MiB; a profile has
at most 100,000 stacks, 128 frames per stack and 200,000 frame occurrences. Full
symbols remain intact, including Rust generics and semicolons. Mixed PID/TID
input is refused. The perf importer retains event timestamps, periods, addresses
and module names; it does not infer loss or CPU-mode completeness from text.

The schema requires immutable identity strings for source, tool, workload,
capture, platform and cohort. Measurement kind is `sampled_cpu` or
`elapsed_wall`, with an explicit unit. Scope names one PID and optional TID plus
`unknown`, `user`, `kernel` or `mixed` CPU mode. Each stack lists full symbols in
root-to-leaf order with a positive weight and sample count. Totals reconcile with
stack sums. Quality records lost, unresolved and refused counts, using `null`
when unknown, and explanatory notes. Unknown never means zero.

Self weight belongs to the leaf. Inclusive symbol weight counts a stack once
even when that symbol recurs. Flame widths describe full call paths, retaining
recursion. Inclusive and self values overlap and must not be added together.

## Windows capture

The manual `windows-stack-profile.yml` workflow builds a profiling variant of
the native `bench-core` and a tooling-only pinned TraceEvent exporter. It runs on
a dedicated ephemeral Windows VM with an elevated token. Local UAC, services,
kernel registry settings and persistent machine policy are outside this recipe.

The existing Suite CI dispatcher can select this recipe without running the
validation matrix. For a reviewed feature branch, use its branch name as the
workflow ref and a full core SHA as the workload source:

```text
gh workflow run ci.yml --repo jeffglousher/coaptic-validation --ref REVIEWED_BRANCH -f stack_profile=true -f library_revision=FULL_CORE_SHA
```

Verify the actual run's suite/core identities before consuming its evidence.
After the dedicated workflow is present on the default branch, it can also be
dispatched directly with `core_sha`. No capture runs on ordinary pull requests.

Windows Profile collection uses a 1 ms sampling interval. TraceEvent sets that
machine-wide interval. This tool stops only its owned session by handle and does
not restore a previous interval, so this route is restricted to the dedicated
hosted VM. Linux's existing 997 Hz route remains a distinct
measurement. Different operating systems, compiler output and transports can
produce different distributions.

The workload is the existing **64-byte Default allocated, socket-free server
App batch**, not the 32-byte SmallDevice socket suite. Each fresh worker prepares
requests outside capture, drives 50,000 complete server exchanges during the
work gate, and verifies every response after capture. Protected workers create
fresh key material. Sixteen empty gates and 128 warmups remain unchanged.
There are eight serial captured workers and one unprofiled control per security
mode. Only one fixture is live at once; its existing declared ceiling is 32 MiB.

On Windows, the fixture includes `workload_thread_id`, obtained once with
`GetCurrentThreadId` on the synchronous batch thread before the measured gates.
The runner sends `start` and validates this fixture before requesting the target
inventory. It requires a positive u32 TID present exactly once in the exact PID's
bounded thread inventory, checks the EXE, and retains the tool's seven-digit UTC
process start time verbatim. `main_thread_id` is nullable inventory information;
it does not select the workload thread. Capture rechecks that selected TID against
the pinned process lifetime. Linux fixture JSON and all gate events are unchanged.

Capture retains source/tool identities, EXE/PDB identities, process lifetime and
window, complete ordered frames, unresolved frames and observed totals. Local
matching PDBs are used; symbol-server resolution is excluded. Preparation,
request encryption, response authentication and post-capture verification are
separate from the captured server drive. Capture boundaries still include
driver overhead; rank App ancestry separately and retain the other samples.

No cohort is silently combined with another. Loss, symbol mismatch, unknown or
truncated ancestry, and insufficient eligible App-rooted samples prevent a
qualified ranking. The source-guided nomination floor remains 200 eligible
App-rooted samples per cohort. A completed workflow alone is not qualification.
Unprofiled controls describe capture context; their time is not subtracted.

Build targets, package caches and temporary conversion files belong to the
ephemeral job, with an aggregate 8 GiB sampled refusal bound. The C# tool is built
from a hash-verified copy of its source files inside that owned output; SDK files
generated beside the project are counted there, while the original checkouts
must remain clean. Evidence has a
separate 256 MiB sampled refusal bound. Direct capture children, including ETL
conversion, have a sampled 1 GiB working-set refusal bound each (2 GiB combined).
These monitors do not establish a hard quota, whole-job peak or build completion
estimate. The Windows INetCache compatibility junction is pruned only when it
points to its expected ordinary `IE` backing directory inside the owned root,
without a reparse chain. Backing files are counted through their ordinary path;
other reparse entries are refused. The nominal 64 MiB ETW ring is not a hard
ETL/merge/export storage cap.
Each process and phase has a finite deadline, and failures retain bounded
receipts. Existing local build lanes, caches, firmware and credentials are
preserved.

## Offline replay of the first Windows cohort

`windows_replay.py` is a hosted-only exporter capability route for the original
run **41013864895, attempt 1**, artifact **12959160518**. That run passed 63
portable Python checks, both builds and 49 tool model assertions. Its one
`unprotected-capture-00` ETW session stopped explicitly, then export refused
module identity. It produced no profile. The remaining cohorts and controls
were not run. Replay never records a replacement cohort, executes the workload,
requests a live target inventory, enables ETW or builds Rust/native code.

On a reviewed clean source revision, select both dispatcher inputs:

```text
gh workflow run ci.yml --repo jeffglousher/coaptic-validation --ref REVIEWED_BRANCH -f stack_profile=true -f stack_profile_replay=true -f library_revision=8af71fe4aa73b3bb76a921a836a1a9647d75f361
```

The dedicated reusable/manual workflow also accepts `replay=true` (default
false). Capture remains the default route. Replay skips Rust provisioning and
builds only the eight staged C# tooling sources with exact SDK 8.0.427, isolated
owned NuGet/user/temp paths and the existing build flags. Its hosted command is:

```powershell
python -B tools/benchmark/windows_replay.py --core coaptic --expected-core 8af71fe4aa73b3bb76a921a836a1a9647d75f361 --expected-suite $env:SUITE_SHA --output "$env:RUNNER_TEMP/coaptic-stack-profile"
```

The source under replay is the clean reviewed exporter source. The capture
remains attributed to original suite `a074120d6f50b1c061e2ab5b0940837c9d51b63e`
and core `8af71fe4aa73b3bb76a921a836a1a9647d75f361`, PID 4936, TID 7436,
serialized process start `2026-10-30T06:28:42.3648387+00:00`, capture UUID
`b9ca443c-4f73-4316-8219-8d9f4e346a48`. There is no pooling across App ancestry,
other ancestry, unknown frames or cohorts.

The downloader uses `GITHUB_TOKEN` with job-scoped `actions:read`. It accepts only
the code-pinned artifact metadata and ZIP SHA256
`3eaee1ec332399c8ece875eb748836a01ebb377c5c67860501c24f1eca54c76a`.
It follows one explicit HTTPS artifact-storage redirect using a fresh request
without Authorization; further redirects fail. Tokens and signed URLs are not
logged. Metadata is bounded to 64 KiB, individual network reads to 15 seconds,
and the entire worker to 830 seconds inside a 900-second contained outer worker.

The archive is held in RAM: at most 8 MiB compressed, 32 MiB expanded, 64
ordinary unique members and 16 MiB per member, with compression-ratio, path,
CRC and hash checks. This fixture additionally requires exactly 34 members,
3,368,810 ZIP bytes and 14,837,202 expanded bytes. All members are checked in
RAM; only `binaries/bench-core.exe`, `binaries/bench_core.pdb`,
`unprotected-capture-00/capture.json` and `unprotected-capture-00/capture.etl`
are materialized, with separately pinned exact sizes and SHA256 hashes.
No original ZIP is retained.

The root must be fresh and exactly `RUNNER_TEMP/coaptic-stack-profile`.
The original receipt requires `D:\a\_temp\coaptic-stack-profile\evidence\`
followed by those member names. A different runner temp path refuses replay and
retains the reason. Neither receipt bytes, embedded config, absolute input paths
nor provenance are rewritten. The replay receipt retains the original receipt
bytes as UTF-8, its hash, original build receipt and every archive member hash.
Materialization uses exclusive new files and refuses existing links/reparse
paths. Source identities are checked before and after tooling/export.

Metadata and selftest precede export into a fresh output and empty scratch.
Original input pins, local EXE/PDB identity, loss and sample gates remain intact.
The exporter selects a unique native mapping covering the complete window
before inspecting its metadata. It validates the complete bounded `FileOnly`
raw stream, retaining earlier contradictions even after a zero or matching
record. Nonzero image IDs and checksums must agree with the owned PE; an empty
DebugID requires age zero, and every present GUID/age must match. A recorded-zero
image ID supplies no corroboration and is reported separately from a match.
It can be used only with the independently verified live-owned file binding.
Symbol lookup is restricted to the selected process, module index, window and
address range. Other frames remain unresolved. Relevant synthetic metadata
without trustworthy PID attribution refuses export.

This is attribution of a trusted owned fixture. The receipt and held file hashes
do not prove exact in-memory executable bytes or exclude executable replacement
before those files were locked. No ETL-discovered module path is opened.

ETL is capped
at 128 MiB and conversion at a sampled 256 MiB refusal bound. The aggregate
8 GiB owned build and 256 MiB evidence bounds remain unchanged; sampled direct
child RSS limits are 4 GiB during build and 1 GiB during export. These are
refusal monitors, not hard quotas or whole-job peak measurements.

Failure receipts and bounded exporter stderr are always uploaded from the same
evidence path. Nonzero export remains failure; any bounded
`profile.json.module-diagnostic.json` is retained alongside its log, without
automatic repair, retry or new capture. The original strict refusal and its
field-level diagnostic remain part of the historical evidence.
Offline replay **41018752790** passed 88 portable checks, the SDK 8.0.427
tool build and 49 pure-model assertions. Its four retained input files match the
original byte pins. The single target module agrees on name, loaded base, size
and checksum; the refused predicate is ETL ImageId `0` against the owned PE
value `0x6ae43917`. Both Version 3 rundown events record zero timestamps. This
is a recorded zero, not an absent field; its cause remains unknown. The original
refusal and bounded field diagnostic remain retained. No profile was emitted.

A successful export renders the canonical interactive profile
with a diagnostic-only banner and records separate ancestry/quality counts.
[The first exported profile](evidence/windows-stack-capability-20261030/README.md)
contains 41 samples, including 33 with App ancestry, below the unchanged
200-sample nomination floor. Offline run 41023864069 passes the SDK build,
113 pure C# model assertions and all 88 portable checks. Rust callers resolve;
91 system-frame occurrences remain unresolved. This proves the single
capture-to-viewer path, with no qualified hotspot ranking or CPU gain.
The profile identity names the original capture tool; the replay build receipt
identifies the current exporter. Browser checks cover zoom, filtering and reset.
The other original 15 captures and two controls remain not run.

## Separate live C1 server-thread screen

The [live C1 plan](windows_live_c1_plan.md) defines a separate capability workload
for collecting more server App samples. It preserves the old batch workload,
cohort plan and historical evidence. Source integration and native validation
must pass before any live recording.

```
gh workflow run ci.yml --repo jeffglousher/coaptic-validation --ref REVIEWED_BRANCH -f stack_profile=true -f stack_profile_live=true -f library_revision=FULL_CORE_SHA
```

This selects exactly four captures and two controls in the plan's serial order,
each with fresh process/key material. One million fresh requests follow 128
warmups. The main server thread runs the unchanged Default allocated App; one
client helper prepares and authenticates requests through a single bounded
handoff slot. The helper remains alive until the collector stops. Its crypto
samples are excluded by the explicitly reported server TID, while scheduling
and synchronization still affect the fixture. Retain those server-thread paths
and unresolved frames alongside App ancestry.

The live fixture uses virtual `index * 8 ms` protocol time to permit safe MID
reuse across wraps. The existing batch uses real monotonic elapsed time. The
live workload is socket-free protocol progress, not a socket traffic rate or a
device measurement. It is neither a comparison with the old batch nor a CPU
improvement claim. Runtime and sample sufficiency remain unproven.

The work deadline is 90 seconds, the collector deadline 120 seconds, the live
capture worker deadline 1,000 seconds and outer containment 1,060 seconds. Only
this new workload uses a 40-minute hosted job. All old batch deadlines remain
unchanged. Failure retains actual counters; a completed prefix cannot become a
successful smaller cohort. The existing 200 App-sample floor, quality refusals
and no-pooling rule remain in force. Live and pinned offline replay are mutually
exclusive; no extra recording is performed by the replay path.
Prepared builds and ownership receipts bind the exact workload and cohort plan;
`build` and `capture` must use the same `--workload` selection. A mismatch refuses
before tooling or native capture launch. Live preparation records the focused
native-test census and log hash; a zero-test filter is refused.

## Linux and the Waveshare device

The existing Linux runner produces flat reports, inline caller trees and raw
stack readouts. The portable analyzer can render its supported text. Earlier
captures remain attributed to their historical revisions. The October 29
current-source attempts failed before valid capture; they establish no current
hotspot ranking. Prerequisite diagnostics now retain bounded stdout/stderr and
the exact failing command without weakening capture gates.

The commissioned Waveshare image has optional bounded elapsed-event tracing in
source. That is a different measurement from sampled CPU stacks. Its inclusion
in a live image, device clock semantics and capture quality must be established
before adapting it to `elapsed_wall`. This work neither reflashes the device nor
claims a cross-device CPU comparison.
