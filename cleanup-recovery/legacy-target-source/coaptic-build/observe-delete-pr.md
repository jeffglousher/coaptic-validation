Successful DELETE previously removed observers without sending their terminal response. This change queues 4.04 CON notifications, retains pending work across local send failures, and accounts for pending terminal delivery when pacing other notifications. ACK or retry exhaustion releases delivery state; unrelated observers survive.

Tests cover multiple observers sharing an endpoint, retransmission/ACK and exhaustion, 12 repeated send failures, failed DELETE, existing NON pacing, and a real protected client/server deletion exchange. Reviewed lifecycle, resource bounds, protocol behavior, failure cleanup, API documentation, and evidence scope.

Validation at 1c2d0a00fffa3e833020a8bad39270c4fbee9962: all 11 CONTRIBUTING checks, both dogfood baselines, 553 library unit tests, and Windows native process suite passed (26 enabled cases, 5 explicit libcoap DTLS build exclusions, 8 pairing benchmarks). Local logs and source-bound JSON are retained under D:\coaptic-build\observe-delete-*. Linux CI remains required. The process suite does not independently qualify Observe; the new Observe proofs are in-process tests.

Advances #201. Full Observe and RFC qualification remain open; no publication or release tag.
