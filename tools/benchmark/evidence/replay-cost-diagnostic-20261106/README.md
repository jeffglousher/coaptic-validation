# Replay cost diagnostic

This instrumented comparison is diagnostic evidence, not production acceptance.
It compares pinned baseline `bd63199b652193b4c0a882e5840e72d992cf1362` with rejected
occupancy integration `42c823463b1d7eac5cca31df58e1dac7b243d610`: allocated Service,
unprotected 1024/16384-byte complete requests, synchronous and actual asynchronous
operation. All 16 pairs per cell and 128 successful process exits are retained.

The important finding is an exact count: for `n` response packets (including
warmup), lookup runs `n + 2*(n-31)` times. After the 32-slot TX pool preserves its
one-slot headroom, each new response reclaims an older pinned replay. Generic
reclamation removes the key and inserts an empty ACK, doing two extra searches.
This motivates the subsequent owned-reclaim implementation; it does not prove
that implementation improves complete-App runtime.

The source-level replay-row copies are already scalarized in the retained
uninstrumented compiler output. No 256-byte replay-copy saving is claimed for
changing those borrows. The archive includes selected reclaim disassembly,
symbol/frame records, commands and hashes from the uninstrumented candidate.

Phase cycles include clock overhead and warmup. Empty clock intervals average
roughly 834–841 cycles, substantial compared with the measured functions.
Instrumentation changes compiler output and phases may nest. Do not add their
costs, subtract empty intervals, infer production CPU shares, or replace the
failed uninstrumented cohort with this result. The raw `black_box` flag describes
optimizer barriers; it does not mean instrumentation was absent. Client work is
outside the complete server-App clock. No network latency or throughput claim.

`diagnostic.zip` retains both exact instrumented binaries/PDBs, source hashes,
instrumentation/probe patches, build and measurement scripts, raw observations,
and the original CRLF preparation failure before compilation. The corrected
builder restored the original fixture after both builds. Portable evidence
excludes local owner and mailbox metadata. Native ownership records remain local.

Run `python -B verify.py` to independently check hashes, all phase counts and
summary calculations without running the native binaries. Build scripts contain
the original host paths and need an isolated, reconstructed fixture to reproduce;
do not run them against a shared active fixture.
