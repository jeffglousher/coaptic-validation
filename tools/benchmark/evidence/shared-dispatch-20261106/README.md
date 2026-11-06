# Shared dispatch storage: rejected integration

Measured source90e3ef952ad87eeabd0ee288c55256b21e2eba5a, pinned baseline
bd63199b652193b4c0a882e5840e72d992cf1362. Blockwise dispatch borrows existing
assembled-response storage. Datagram-only dispatch retains its on-demand owner;
zero-sized providers and direct owner access avoid extra references across await.
The prior flat inbox/metadata borrowing changes remain integrated.

SmallDevice App14936 ->14248 bytes, selected complete future15952 unchanged.
Service fixed App315656 ->314984; allocated App35672 ->35000; allocated pool
heap282512 unchanged. Both Service complete futures16912 ->15496, down1416
bytes (8.37%). Service App saves672 bytes, including the16-byte overhead relative
to flat-inbox source. No configured capacities or whole-App ceilings changed.
These are exact owner/compiler sizes, not peak stack or whole-system RAM.

The single completed64-pair cohort fails four per-cell upper CPU bounds.
All-sync ratio1.0019488, upper1.0041814; all-async0.9957673, upper0.9972674.
Failed upper bounds: fixed/unprotected/sync16384=1.0217461;
fixed/OSCORE/sync1024=1.0267780; fixed/OSCORE/sync16384=1.0291835;
allocated/OSCORE/sync1024=1.0216423. See comparison.html for all28 cells and
previous distinct cohorts. Aggregate improvement does not override failure.

926 alloc+oscore library tests (including pending-I/O cancellation),13 footprint
checks and2 admission checks pass for measured90e3ef9. General source review
found a supported custom-profile Send/Sync regression: temporary scratch became
part of App's resident type. The measured source is therefore also rejected on
behavior. No production optimization from this integration is merged.

Correctionbf195624c9080631767fcd8f3bdfd322fb6557df separates resident initialized
bytes from temporary scratch. Custom implementors explicitly select
ResidentRxScratch; repository implementations and admission checks are updated.
Four admission tests include App Send+Sync assertions with Rc-marked temporary
scratch and independent resident read/write bounds before entropy. Those four,
926 library tests and13 footprint tests pass. corrected.patch retains this repair;
it is not performance-qualified or independently rereviewed. Do not repeat the
failed runtime hypothesis merely because a correctness fix changed the source.

The method was fixed before timing:64 pairs/cell, AB BA BA AB repeated16times,
28 matched workloads, complete server-App thread cycles, one-sided95 upper CPU
ratio<=1.02 for every cell and ordinary/all sync/async aggregates. Conservative
Student t factor1.67 with63 degrees of freedom. Exact owner reduction and selected
complete-future nongrowth are independently required. No trimming or replacement.
Sync and actual async progress run in memory transport with immediate-ready I/O
and pending timer. Client setup/authentication/verification are outside the clock.
No network throughput, latency, scheduler, device-peak or new libcoap claim.

Run python -B verify.py to hash7298 observation members and29 diagnostic members,
recompute all3584 timing outputs, check capacities and owner deltas, verify exact
source/fixtures, selected future records and failed verdict. prepare.py recreates
baseline or measured candidate with adjacent dispatch-scratch fixtures. The
receive-scratch baseline layout is an incomplete broad-filter prefix; the three
selected records are complete. The final candidate layout capture is complete.

Diagnostics preserve the failed pre-timing designs: universal persistent scratch
would exceed the SmallDevice whole-App ceiling;6e892a9 grows its future64 bytes;
d03e2d6 grows it48 (compiler succeeded but diagnostic output hit the2MiB ceiling);
872a0fd grows it16. Moving allocation back into dispatch, passing a zero-sized
provider by value and removing the second slice eliminate that growth in90e3ef9.
No timing was run on those layouts. Native baseline symbols confirm the retained
1152-byte zero-fill call is memset; static presence is not cycle attribution.

Tradeoffs: large custom scratch switches initialized variants on body collection;
construction and collection costs remain outside this steady-state server clock.
Packet staging copies, protected plaintext writeback and128-byte Response inline
payload copying remain. Body-slot release timing and4096-byte collection capacity
are unchanged. The next investigation should target replay-table key/deadline
traversal and persistent payload initialization, rather than more layout variants.
