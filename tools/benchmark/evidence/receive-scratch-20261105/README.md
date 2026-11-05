# Receive scratch investigation: rejected candidates

No runtime optimization is accepted from this investigation. All four candidates
failed the frozen complete-App acceptance checks and were retired. Preserve these
results; do not repeat unchanged candidates, replace samples or relax the gates.
The next implementation needs a distinct, measured source of runtime cost.

Baseline is core `bd63199b652193b4c0a882e5840e72d992cf1362` (#741). Reused
baseline executables were built from `f84f3c199763910e246d8599aca0e29077a73ad1`;
the earlier [packet-dispatch evidence](../packet-dispatch-20261104/) establishes
production equivalence. Later baseline changes are tests/docs. Absolute source
paths differ between arms. No cross-library ranking or hardware claim is made.

## Results

Ratios below are candidate/baseline complete server-App thread cycles, followed
by their one-sided 95% upper bound. Smaller is better. All are the declared
28-cell mix; the separate 20 ordinary cells also remain in each result.

- `direct`, `79a79ea3`: App-private direct request opening removes plaintext
  staging on eligible requests. Sync 1.004774 (1.010621), async 1.007644
  (1.018279); six point guards fail. No complete-future reduction established.
- `request-phase`, `bd28f6fd`: separates authenticated request handling from
  ingress/client-response states. Sync 1.007140 (1.008819), async 1.015618
  (1.020176); eight point guards fail.
- `metadata`, `fbba2ab4`: adds a shared option traversal for No-Response, proxy
  checks and validation. Sync 0.978681 (0.985191), async 1.001121 (1.003465);
  two point guards fail. A synchronous gain does not establish async acceptance.
- `grouped`, `40f13c91`: also groups the request coroutine inputs. Sync 0.993628
  (0.996076), async 1.001285 (1.011339); four point guards fail.

The last three candidates reduce the matched Constrained/CoreIo/routes4 complete
`progress_async` future from 15,952 to 14,000 bytes, or 1,952 bytes. Grouping
reduces the request child's initial input span from 7,328 to 208 bytes without
further reducing the complete future. This is compiler layout, not measured peak
RAM, stack use or a proven runtime explanation. It is a different fixture from
the earlier all-feature/routes1 future check. See [memory.json](memory.json).

All qualifier App/pool/capacity ledgers match. General read-only reviewers found
no actionable code defects. The corrected direct-opening candidate passes 147
focused tests; request-phase and metadata each pass 870 no-default+oscore library
tests. Grouped inputs compile in native ordinary/retained and layout lanes, but
additional library qualification stopped after runtime rejection. Core retirement
commit `af73b0c` restores the exact baseline tree. None of these results authorizes
merging candidate production code.

## Method and scope

Windows x86_64 MSVC, Ryzen 7 5800X3D, rustc 1.99.1, LLVM 23.1.1; release thin LTO,
one codegen unit, debug=1 and `RUSTFLAGS=-Cforce-frame-pointers=yes`. Candidate
builds use one Cargo job and incremental compilation off in the existing shared
lane. The probe manifests, lockfile and source are unchanged from the retained
[dispatch-scratch fixture](../dispatch-scratch-20261104/fixture/).

Ordinary cells: SmallDevice/Constrained 32-byte payload and Service fixed/allocated
1,024/16,384-byte payload, each unprotected/established OSCORE and sync/async.
Retained cells: fixed/allocated 11,264-byte Q-Block2, two requests and eleven data
packets per operation, both security and execution modes. Capacities and complete
App ledgers are present in all raw qualifiers. No capacity is reduced for a gain.

Four paired processes use AB, BA, BA, AB order on CPU0, with affinity restored.
Each process warms up 128 operations, then measures 8,192 ordinary short operations
or 1,024 large/retained operations. `QueryThreadCycleTime` covers complete server
App driving; preparation, bridge transport and client verification are outside
the clock. Async uses actual wait/progress, immediately ready in-memory transport,
a pending timer and manual polling. This does not measure socket/executor latency.

Acceptance requires both sync and async upper95 ratios below 1 for both the
ordinary20 and all28 groups, plus every cell point ratio at most 1.02. Equal-weight
process-mean log ratios use Student-t df3, one-sided95 factor 2.3533634348. No
trimming, sample replacement, pooling across candidates or threshold changes.
Original METHOD files and all 896 timing process outputs are retained.

## Libcoap approach comparison

Inspected both the companion's pinned upstream
[`851533c3`](https://github.com/obgm/libcoap/blob/851533c3cf63d16984d370ce39d586ecb3694971/src/coap_oscore.c)
and current source
[`45ace062`](https://github.com/obgm/libcoap/blob/45ace062bf5cbe60ef9e4e4883fc844228c5f8ca/src/coap_oscore.c).
Both decrypt into a temporary plaintext PDU, use its wire bytes for parsing, then
merge options and copy payload into a separate final PDU. Current encryption
also stages plaintext and ciphertext. The transferable idea is a parse view over
decrypted wire, not importing dynamic PDU growth. The Rust adaptation to final
bounded scratch failed the runtime test above. Allocator, crypto backend, service
capabilities and session ownership differ; this is source comparison only.

## Retained failures and reproduction

`observations.zip` retains raw measurements/qualifiers, producer scripts, compiler
layouts and relevant build/test failures. SHA-256 manifests cover every entry.
The public-output direct-opening prototype failed two unchanged error-buffer
immutability tests; it was corrected before timing by retaining the public staged
path. Initial all-feature compilation ran out of LLVM memory before tests. A
reduced test build first had a test constructor typo. The broad baseline layout
filter exceeded its 2 MiB budget after compilation succeeded; its prefix is
explicitly incomplete, though the selected records used here are complete.

The metadata retained probe was initially built without its top-level OSCORE
feature. Qualification refused before any timing rows. Its METHOD, failure and
outputs remain under `qualification-build-failure/`; corrected compilation used
the established `--features oscore,alloc` before the sole measured cohort.
Native executables/PDBs remain with the owner, including that failed build;
their timing identities are in METHOD. Diagnostic binaries are never timed.

Verify without compiling or resampling:

```text
python verify.py direct
python verify.py request-phase
python verify.py metadata
python verify.py grouped
python verify_memory.py
```

Materialize exact source/fixture inputs into a new directory, using a core clone
containing the baseline commit. Variants are `baseline`, `direct`, `request-phase`,
`metadata` and `grouped`. No new Git worktree or Cargo target is created:

```text
python prepare.py CORE_REPO NEW_OUTPUT grouped
```

Use the existing registered Cargo lane, with the environment stated above:

```text
cargo build --locked --offline --release --bin dispatch-probe
cargo build --locked --offline --release --bin retained-probe --features oscore,alloc
```

Exact runtime producer scripts are retained inside each archive variant. Their
local executable paths must be mapped to separately retained baseline/candidate
executables before a deliberately authorized new experiment. Verification itself
never launches them. All four hypotheses above are closed without another run.
