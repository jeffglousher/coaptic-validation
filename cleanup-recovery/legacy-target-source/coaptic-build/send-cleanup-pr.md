A client send that failed after OSCORE protection retained its request binding even though no Call was returned. Repeated local transport failures could exhaust the fixed request table. Partial Q-Block sends also need to retire earlier retained datagrams.

The App now retires request-owned exchanges, pending datagrams, upload bodies and protection bindings when initial sending fails. Other calls remain intact. Sender sequence numbers continue advancing; an I/O error does not establish non-delivery, so documentation explicitly preserves caller responsibility for retry uncertainty.

Validation: a regression test failed before the fix and passes after it. Repeated CON/NON transport-error and short-send cases exceed binding capacity and then demonstrate a successful send. Classic/Q-Block upload tests inject failure at the first, second and third datagram, preserve another active CON and verify body/TX cleanup. Protected partial-upload tests verify cleanup and monotonic sequence state. All eleven CONTRIBUTING.md checks passed (518 all-feature library tests); rebasing onto merged #218 left the tested tree unchanged. Linux CI supplies separate process evidence; no full fault/conformance claim.

Contributes to #201 and #202; their remaining acceptance stays open. Source: RFC 8613 sender sequence/nonce uniqueness and RFC 7252 unreliable transport semantics.
