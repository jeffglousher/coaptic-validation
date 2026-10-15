Separate authenticated response freshness checks from replay-state commit. App commits Observe notification order, the one no-PIV budget, and Q response replay windows only after critical-option validation and successful CON acknowledgment. A failed ACK or rejected response must not consume state needed by a pending Call. This is an in-memory ordering change, not a durable checkpoint barrier.

Eight explicit cases cover Observe/Q responses with and without response PIVs, each under ACK-send failure or critical-option rejection. Failed ACKs accept a byte-identical retry; rejected messages allow a later acceptable fresh-PIV response. Recipient checkpoints remain unchanged before admission, and exactly one response is delivered. Existing replay, corruption, reorder and capacity tests continue to pass.

Validation at b8a439f: all 15 CONTRIBUTING checks and both two-iteration dogfood baselines pass on Windows MSVC; 619 all-feature library tests. Logs D:\coaptic-build\replay-commit-validation-*.log. Hosted checks required before merge. Already-admitted CON duplicate ACK retention, independent OSCORE interop and caller-owned durable replay storage remain separate work.

Refs #201. Depends on #256.
