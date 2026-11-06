# Short replay integration

Exact candidate `6760b72a8ed07b6a108cde24eeb36e552a0f076d` versus pinned baseline
`bd63199b652193b4c0a882e5840e72d992cf1362` fails the frozen runtime preservation rule and is rejected.
All64 pairs across28 workloads are retained; 2 cell
upper bounds exceed1.02. `comparison.html` contains CPU charts and comparable
tables. Earlier failures remain rejected; no unchanged candidate was resampled.

The previous candidate returned a complete replay row across the callback,
introducing an extra304-byte copy. The new callback fills borrowed16-byte scratch
and returns only an optional length. Storage validates the length and constructs
the same-key/deadline replay row. Callbacks returningNone or an excessive length
skip insertion after release/removal. An empty encoding retains the ordinary
empty replay behavior. Public fixed-table duplicate and rotating cursor behavior
are unchanged; allocated unique-key storage still avoids both repeated searches.

The bounded diagnostic in sibling `replay-cost-diagnostic-20261106` establishes
two extra key searches per TX reclamation after the first 31 pinned replies.
The owned reclaim hook avoids both searches for allocated unique-key storage,
and combines one search for public fixed storage while preserving duplicate-key
behavior. TX release precedes removal of the first matching key, then replacement.
Deadline ties retain earliest-slot selection, deadlines remain full u64, and the
ordinary rotating acquisition cursor is preserved. Custom storage keeps the
generic fallback. The occupancy index also restores its immediate-free-cursor
fast path. No resident fields, allocations or capacity reductions are added.

The integrated source retains compact inline/TX replay ownership, scalar active
TX writes, a u32 occupancy/message-ID filter, and direct full retained-chunk
initialization. Filter matches still require the complete endpoint/key.
The compact replay type defines equality/hashing by key, deadline and current
replay owner. Discarded inactive bytes no longer affect identity; this observable
pre-release value-semantic change is documented in rustdoc. This is not a claim
of identical historical inactive-byte identity.

Host SmallDevice App saves56 bytes; fixed Service App saves832. Allocated
Service saves24 inline bytes plus832 requested pool bytes. Selected complete
futures and encoder frames are unchanged. Selected reclaim frames become544
bytes in all four monomorphizations: baseline800 SmallDevice/Constrained with
bodies/allocated Service and784 fixed Service. The extra304-byte row-return
copy is absent. These reservations are not peak stack.

Actual Thumbv7EM unit-transport App reductions are24/320/16 bytes for SmallDevice,
fixed Service and allocated Service. Startup allocation counts match baseline.
These are exact owners, not peak RAM; heap excludes allocator metadata/rounding.
Static target layout does not establish device execution. Capacities/security
remain matched.

Before timing:931 library,11 allocation/failure-injection,27 retained-Q and13
footprint checks pass. General static review of pinned baselinebd63199 to6760b72 found no
actionable issue. Dedicated callback order/count checks close the previous
coverage gap; models exercise None, zero and excessive encoding lengths.

Run `python -B verify.py` here to independently recompute all paired results and
check hashes, capacities, exit records and owner ledgers without executing probes.
Use `python prepare.py CORE_REPO NEW_OUTPUT candidate` to reconstruct the source.
The unchanged fixture lives in sibling `dispatch-scratch-20261104/fixture`.
`observations.zip` retains exact binaries/PDBs, raw outputs and exits;
`diagnostics.zip` retains build/test/review records and selected disassembly;
`layout32.zip` retains the audit fixture, source hashes, layouts and constants.
Local owner/mailbox metadata is excluded from portable archives.

The benchmark measures complete server-App thread CPU cycles with immediate
memory transport, actual sync/async progress and a pending timer. Client work is
outside the clock. It does not measure network latency, maximum throughput,
whole-system peak memory or a new libcoap ranking. No causal comparison should
be inferred between separate experimental cohorts. Broader qualification and
production merge are separate from this frozen runtime verdict.

The integrated candidate additionally uses a128-byte short replay variant for
lengths1..128, preserving full256-byte capacity. Key/deadline metadata precedes
the replay payload. The final emitted writer copies128 payload bytes plus metadata,
with8-byte caller and helper frames. Two untimed precursors are retained:
80a184c copied128 payload bytes but grew the caller frame8 to56; bf2c371 restored
8-byte frames but recovered a304-byte whole-row memcpy. Neither was timed.
6760b72 passes active bytes separately across the borrowed boundary. These static
facts motivated the cohort; they are not independent whole-App performance gains.
All lengths0..256,257-byte refusal, canonical long-to-short equality and TX owner
transitions are covered. Compact identity now describes current active replay;
discarded inactive replay bytes do not participate in equality/hash. Hash output
is not a stable serialized format. Startup capacities and security stay unchanged.

Measured binaries are exactly6760b72. Focused checks run formatted0c30dad, whose only change is the exact rustfmt output for the short writer; format-only.patch and format-equivalence.json preserve this distinction. Initial formatting failure was fixed before timing.
