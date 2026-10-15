Match protected Outer response routing against the exchange or client Observe relation before processing request-binding and notification state. Piggybacked ACKs require the request MID; established unsolicited notifications require CON/NON. Plaintext Observe uses the same notification type rule.

Tests exercise ordinary ACK/NON responses, mismatched peer/MID followed by valid delivery, initial Observe responses, established notification delivery and invalid ACK-shaped notifications followed by valid delivery. Plaintext tests reject unsolicited ACK notifications with both old and different MIDs. Protocol source: RFC 7252 section 5.3.2 and RFC 7641 notification types. No full OSCORE qualification claim.

Validation at 70510ff: all 15 CONTRIBUTING checks plus both two-iteration dogfood baselines passed on Windows MSVC; 616 all-feature library tests. Logs retained at D:\coaptic-build\response-matching-validation-*.log. Hosted checks and source-bound artifacts are required before merge. Independent OSCORE peers, older concurrent request bindings and durable caller storage remain separate gaps.

Refs #201. Depends on #254.
