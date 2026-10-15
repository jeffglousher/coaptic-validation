Completed App replies discarded Location, Max-Age, Echo and unknown elective options. Retain a bounded encoded header (24 options, 512 bytes including header and Token, eight values per Location option) and expose all received option values alongside typed getters. Overflow yields CallFailure::ResponseMetadataBounds with cleanup, rather than a partial snapshot.

Block2/Q-Block2 retain the first accepted fragment's metadata without exposing an incomplete reply. Receive timestamps remain attached to that header, so assembly time does not extend Observe Max-Age. Malformed elective values remain available through received_options while typed getters omit them; malformed Observe cannot establish a subscription.

Proof covers exact Location/Echo/Max-Age/unknown values; 512/513-byte, 24/25-option and 8/9 Location limits; four distinct untaken replies and subsequent capacity recovery; first-fragment-only Block2 metadata and Observe; partial-body cleanup on later metadata overflow; and malformed elective values. This is not full Observe notification ordering or independent OSCORE/Q-Block qualification.

All eleven CONTRIBUTING.md checks, both dogfood comparisons and release peer builds passed at 892791454c5fbef6b595333116a35f5ea89fea04 (510 all-feature library tests). Windows process suite is running; Linux CI required before merge. Footprint budgets explicitly include five 512-byte header buffers (four rows and a borrowed-reply hold), plus the hold's inline payload and endpoint. No heap or additional assembled-body buffer. Existing Default/Constrained body-pool separation and Response copy bounds pass.

Progress on #201/#200; remaining audit acceptance stays open.
