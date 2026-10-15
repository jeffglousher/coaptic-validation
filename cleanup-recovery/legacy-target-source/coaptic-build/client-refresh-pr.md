Outgoing::reregister_call refreshes a live Observe subscription with the same Call/Token and exact bounded request identity, excluding ETag as permitted by RFC 7641 section 3.3.1. It preserves notification ordering and the original absolute deadline, retires queued/pending state before reusing the Token, and reports ReregistrationFailed if the new send fails. Scheduling and the recommended randomized delay after Max-Age remain caller-owned.

Tests cover GET/FETCH, six identity mismatch classes refused before I/O, changed ETags, three successive refreshes, stale CON/NON rejection without acknowledging the fresh request, stale piggybacked ACK ending RTO, deadline preservation, protected binding replacement, rejection of delayed old-binding ciphertext, and eight repeated success/failure cycles with capacity cleanup. Ordinary subscribe resets an earlier explicit target selection. No added per-Call storage.

All 15 CONTRIBUTING checks plus both two-iteration dogfood baselines pass on Windows MSVC; 633 all-feature library tests. Logs D:\coaptic-build\client-refresh-validation-*.log. Hosted checks required before merge. This is bounded App behavior, not independent-peer Observe qualification, persistent sequence continuity or full large-notification coverage.

Refs #201. Depends on #265.
