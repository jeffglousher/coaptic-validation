# SmallDevice replay diagnostic

Pinned baseline bd63199 versus rejected candidate6760b72, instrumented separately
from the complete-App acceptance cohort. Sixteen paired processes for each
sync/async and unprotected/OSCORE combination,1024 operations plus128 warmups.
All128 processes exit successfully. This does not requalify the failed candidate.

Every process constructs and stores1152 replay rows, runs1152 expiry passes and
performs2300 lookups: one duplicate lookup per request plus a key-based victim
removal after the four-row table fills, n+(n-4). Counts match both sources.
Replies are exactly55 bytes unprotected and66 bytes protected in every sample.
Both fit the existing128-byte short owner. Full256-byte capacity remains intact.

Empty clock intervals average844.78 cycles for baseline and834.63 for candidate.
Construction/lookup/expiry intervals are mostly close to that overhead. Store
includes nested lookup instrumentation. Do not subtract clock cost, sum phases,
infer production CPU shares or identify a causal regression from these timings.
Construction's instrumented mean increases in all four cells, but instrumentation
itself changes lowering and code placement. This motivates inspection only.

Code-path inspection finds an independent redundant condition: entry_ref checks
occupancy before reading Option<DedupEntry>, while initialization, acquisition
and release clear absent rows. A present row already proves occupied. The next
candidate tests removal of that repeated check in fixed/allocated storage, with
unchanged thresholds, capacities and original refusal/recovery semantics. It
requires its own ordinary complete-App comparison; this diagnostic is not proof.

`diagnostic.zip` preserves both instrumented source patches, base source hashes,
probe patch, clock hook, immutable EXE/PDB files, build logs, all raw observations
and exact method/results. The setup UTF-16 decoding failure occurred before any
fixture mutation or build and is retained. The build restored all148 original
candidate source hashes and the original probe bytes, removing only its own
temporary cost_probe.rs. No production source includes instrumentation.

Run `python -B verify.py` to verify hashes, counts, wire lengths, all phase means,
ratios and process exits without executing probes. Archived build.py contains
original host paths: reconstruct isolated fixture sources before adapting it;
never execute it blindly against a shared checkout. Local owner/mailbox metadata
is excluded. Compiler warnings are for temporary diagnostic public items; the
uninstrumented production candidate separately passed all-feature strict lint.
