Retain empty ACKs for accepted CON responses in the existing bounded dedup table. Duplicates replay the ACK before OSCORE processing, including after the caller collects the response, without a second delivery. Failed initial ACK sends still retry response admission.

Tests cover ordinary, Observe and Q responses; duplicates before/after collection; wrong endpoints; failed replay sends; expiry; plaintext terminal notification duplicates versus new unsolicited responses; and eviction after nine responses fill the eight-row default cache. Rustdoc states peer/Outer-MID identity, EXCHANGE_LIFETIME expiry and eviction under pressure. No new body pool or heap allocation.

Validation at cecff51: all 15 CONTRIBUTING checks plus both two-iteration dogfood baselines pass on Windows MSVC; 621 all-feature library tests. Logs: D:\coaptic-build\response-acks-validation-*.log. Hosted checks required before merge. Cache retention is bounded, not a guarantee under arbitrary traffic pressure; independent OSCORE interop remains unqualified.

Refs #201. Depends on #257.
