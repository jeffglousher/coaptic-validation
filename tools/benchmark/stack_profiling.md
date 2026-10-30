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
ephemeral job, with an aggregate 8 GiB sampled refusal bound. Evidence has a
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
