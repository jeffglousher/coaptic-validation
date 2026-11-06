# Borrowed send metadata integration

Exact native candidate995ae9379c6ab5c8d0608edfda970a674efbbc9b versus pinned
baselinebd63199b652193b4c0a882e5840e72d992cf1362 is rejected under the frozen runtime preservation rule.
All64 pairs across28 workloads are retained; 2 cell bounds fail.
Complete App CPU change: sync-1.491%,
async-2.254%.
`comparison.html` contains the chart and comparable owner/workload tables.

Blockwise dispatch shares the existing collected-response backing. Datagram-only
dispatch retains temporary scratch. The original owned client inbox is restored, excluding independent inbox borrowing. Five retained-send helpers now borrow immutable SendResponse from their callers. Metadata owners, security fields, ACK ordering and cancellation guards remain unchanged.
The replay integration uses compact exclusive owners, short128-byte copies,
borrowed reclaim encoding, occupancy/MID metadata, reduced key searches and
row-presence borrowing. Full retained chunks initialize directly from body data.
This is the first combined measurement of these source changes. Previous failed
cohorts remain failed; their gains are not summed or treated as causal effects.

Host SmallDevice App14936 to14880 (-56); fixed Service315656 to314840 (-816).
Allocated Service App35672 to35664 (-8), requested pool282512 to281680 (-832).
Client App16944 to16936 (-8), requested pool37060 to36956 (-104).
Retained fixed App112728 to112536 (-192), allocated42704 to42696 (-8).
Service complete progress futures16912 to15496 (-1416); SmallDevice15952 unchanged.
These owners must not be added to nested fields again. Requested heap excludes
allocator metadata/rounding; compiler futures are not peak stack or task reserves.

Thumbv7EM unit-transport App layouts: Small11304 to11280, fixed Service307504
to307192, allocated App28184 to28176. Replay tables4/64 remain1240/19720.
No target execution claim. Host and target use matched configured capacities.

SmallDevice uses Constrained,4routes,1Call,0deferred,4security requests,1association,
2RX/2TX datagrams1152bytes,4dedup,2Observe,no bodies. Ordinary Service uses32routes,
4Calls,8deferred,4security requests,1association,32RX/32TX datagrams1472bytes,
64dedup,32Observe,4RX/4TX bodies16384bytes. Raw qualifiers retain all configurations.

933 library,11 allocation/failure-injection,27 retained-Q,13 footprint and4
scratch-admission checks pass at exact 995ae93, as do formatting and strict all-target/all-feature lint. General integration review found no actionable issue in restored inbox ownership, shared scratch lifetimes, release timing, admission or cancellation. Prior replay review remains valid.

Encoder frames remain1280/1296; reclaim frames544 versus baseline784–800.
Short replay copies128 payload bytes plus metadata with full256-byte capacity.
Its helper reserves8 bytes; all eight inspected caller reservations match or
shrink. Compiler reservation evidence does not establish peak stack.

Tradeoffs: the shared owner adds enum/capacity metadata already included above.
Large custom scratch switches initialized variants on body collection; startup
and custom switch costs are outside the steady-state server clock. Body-slot
release timing and4096-byte collection limit stay unchanged. Custom profiles
select ResidentRxScratch separately from temporary scratch, preserving App
Send/Sync when temporary scratch has an Rc marker. Compact equality/hash describes
active replay, excluding discarded inactive bytes. Packet staging, protected
plaintext writeback and128-byte Response payload copying remain.

Run `python -B verify.py` to verify hashes, exits, capacities, memory and independently
recompute CPU results without executing probes. `prepare.py CORE_REPO NEW_OUTPUT
candidate` reconstructs exact native sources using the pinned baseline and patch.
The unchanged fixture is sibling dispatch-scratch-20261104/fixture.
observations.zip retains exact binaries/PDBs and raw samples; diagnostics.zip has
build/check/review/lowering records; layout32.zip contains static target evidence.
Local owner/mailbox metadata is excluded. Broader qualification, if run after a
passing runtime result, is recorded separately in qualification.json/its logs.

The clock covers complete server App work with actual sync and async wait/progress,
immediate-ready memory transport and pending timer. Client preparation/authentication/
verification are outside. No network throughput/latency, executor policy, peak
memory, device qualification or new libcoap ranking follows from this cohort.

Nested metadata evidence: nested-comparison.json retains eight actual fixed/allocated future owners against ecf1747. These are nested alternatives, not additional peak RAM savings. Untimed precursor88afd58 and exact build/check/source records are in untimed-precursor.zip. Its helper futures shrink152 bytes each; no timing claim.
