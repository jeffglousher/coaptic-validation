# Regular option parser regression gate

This source-specific campaign follows normal screen 41302227568. That screen
passed all eight preregistered gates using four actual process pairs per order.
Its complete raw evidence remains separate. Do not repeat it or change the parser
in response to subsequent regression results.

The frozen contract is `regular_option_regression_contract.json`; its canonical
JSON content, excluding the final newline, hashes to
`bcb57fc34170707f1395a449d9f511a3fb292f094599b6f1c35a630581c6a205`.
The baseline is c655b3aac485c3b88d3811b4da836b56210fce5b and the candidate is
ca78a33b2cbf04bf43325b71c103c939caf341e4. Exact companion source/tree and file
hashes must be frozen after implementation and independent review, before launch.
Later documentation or CI-only commits do not become the measured source.

## Work and decisions

Retain the existing five pressure and continuation workloads, both security
modes, and AB/BA orders: 40 timing processes and 36 separate decisions. The
unchanged pressure driver is reused through a new thin integration entry with
this experiment's full contract and hash. The original admission contract,
entry, case bodies, earlier results and STOP decision remain unchanged.

Add one long-option workload in each storage profile and security mode. Each
cycle sends Uri-Path `bench`, then an elective option 42 with 13 value bytes;
then a fresh request with elective option 280 and 269 value bytes. They are
unknown to this implementation, and OSCORE classifies them as Inner/Class E.
The two complete server polls are timed and retained separately as
`delta13_len13` and `delta14_len269`. A fresh ordinary recovery request is
verified outside the clock. This covers both extended delta forms and both
extended length forms on the authenticated server path.

The new matrix adds 16 processes and 16 decisions. The combined campaign has
56 timing processes, 104,000 measured poll intervals and 229,376 calibration
values. All 32 selected qualification executions must pass before any timing.
Every one of the 52 regression decisions must pass. No missing, invalid,
failed or inconclusive result can be treated as a pass.

Each timing process retains one App and, when protected, one fresh context
pair through 128 verified warmup cycles and 1,000 measured cycles. Keep the
virtual 248,000 ms cycle stride, declared empty-history progress and fresh
MIDs/tokens. The long workload uses phases 1, 2 and 3, maximum MID 18,035 and
3,384 fresh peer requests without sequence, replay-window or key resets.
Verify complete responses, authentication, ownership, counters and recovery
outside timing. A failed prefix is evidence of failure, never a smaller cohort.

## Analysis and limits

Use the existing Stage B comparison function unchanged for every labelled
stratum and order: 20 consecutive blocks of 50 observations, 10,000 independent
arm bootstrap draws, Random(20261030) reset for each comparison, A20 draws
before B20, linear one-sided 95th percentile, B/A even in BA. Require the upper
bound to be at most 1.02. Do not pool paths, modes, profiles or orders; remove
outliers; subtract calibration; replace processes; or revise gates after data.

These remain conditional Windows release integration-test App wall comparisons.
Two processes per comparison and their blocks do not establish independent-host
or simultaneous 95% coverage, CPU share, socket/device performance, maximum
latency, complete stacks or whole-process memory. Client preparation and
verification outside the timer can affect cache and scheduling. This campaign
is a regression gate and makes no additional benefit claim.

## Storage, execution and custody

Use the existing feature `admission-stage-b` and the separate integration target
`regular-option-parser-regression`. Select the exact test executable and its
matching PDB; a normal bench-core binary is not that artifact. Keep old selectors
and their default plans, owners, hashes and results unchanged. Workers resolve
only allowlisted immutable contexts; evidence cannot choose its own contract.

The long fixture owns two fixed latency arrays (32,000 bytes), 4,096 calibration
values (65,536 bytes), bounded wire/authentication/context scratch and an
8,192-byte serializer buffer. It has no outbound-Call token ledger. Report its
actual App inline owner, requested pool heap and fixture owners separately;
CoreIo is already nested in App. Preserve the 256 KiB explicit fixture ceiling.
Compiler initialization, runtime allocation and peak stack remain unknown.

Keep the existing 830-second build owner, 400/450-second Cargo bounds,
300/450-second measurement bounds, 30-second process limit, 35-minute job,
8 GiB build, 64 MiB evidence, 4 MiB failure reserve and 2 MiB process output
bounds. Aggregate bounds dominate individual maxima; exhaustion is a retained
refusal. No cap increase or replacement recording is authorized.

The parent owns source/lock transactions and must confirm descendant settlement
before restoration. Refuse foreign edits and preserve unresolved staged inputs.
Reporting failures must not erase the primary error or unresolved custody.
Compiler/tool execution, affinity, cleanup and restoration remain attributed to
the producer; VM retirement is not inferred from a successful receipt.
