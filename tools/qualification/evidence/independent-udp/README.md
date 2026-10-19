# Independent UDP profile evidence

The reports retain exact core/suite sources, dirty flags, lock hashes, executable hashes, peer commands, and complete bounded datagram traces. These are Windows IPv4 loopback **unprotected** process exchanges. The libcoap binary uses upstream `851533c3cf63d16984d370ce39d586ecb3694971`, MSVC Release, DTLS/OSCORE disabled. No routed IPv6, independent EDHOC, protected-profile, or physical proof is implied.

The Coaptic desktop peer reserves an 8 MiB worker stack for debug construction temporaries and a 4096-byte caller response-copy buffer with `full_responses`. These are host fixture resources, not embedded retained App RAM. The native peer bounds tokens to 64 bytes, while Coaptic selects a 32-byte token profile. The pinned coap-rs/coap-lite decoder's compact-only limit is verified by its Rust test; its ordinary control requests can legally use empty tokens.

- `bd05c11`: original failed run, including host stack overflow; not protocol proof.
- `7eaf9bd`: first actual wire captures, including both initial-Valid counterexamples and libcoap's nonzero registration refusal. Some other failures were fixture/output-oracle defects; those records remain intact.
- `04924f2`: targeted corrected native token negotiation, reverse metadata/URI and 64-byte permanent-refusal/fresh-recovery captures. Failed rows remain failed.
- `d28d3a1`: targeted full discovery payload, reverse large/nonzero Observe, and coap-rs compact controls pass.
- `3337d3d`: both initial-Valid directions and related large/nonzero Observe profiles pass against the core fixes. The separate native nonzero refusal control received 4.00 but initially timed out in the CLI's three-notification collector; its failed record is preserved.

The positive nonzero initial Observe profile remains unsupported by the pinned libcoap server: `src/coap_net.c` rejects nonzero Block2 at registration before calling the handler. RFC7959 section 2.6 defines whole-resource observation and first-block notifications, but does not explicitly require acceptance of that initial selector. This is a selected capability limitation, not a claim of general RFC nonconformance. A separate refusal/recovery control must not be counted as successful Observe support.

Contracts exercised: RFC6690 discovery metadata and quoted extensions; RFC7252 sections 5.10.1/6 URI option identity; RFC8974 sections 2.1/2.2.2 extended wire tokens, probing and permanent capacity refusal; RFC7641 registration/notifications and RFC7959 section 2.6 whole Observe representations. Observe grading binds every continuation ACK to its exact request MID/full token, ETags, advancing serials, every block, and exact application bytes. Fresh compact requests check server reuse. Source changes and failed rows are never silently relabeled as current successes.

Final refusal control: `6183341` passes exact Observe=0/Block2 NUM=1 request identity, echoed 4.00, immediate CLI reporting, and a fresh compact request. The final peer build and strict all-target peer Clippy passed against core `618334166a5112474099198ac5c20b72e45fbc74` and suite `83ed754`. The earlier five classic Observe passes remain explicitly bound to `3337d3d`; the subsequent core refinement concerned Q notification state, not these classic captures.

Selected results: 15 of the original 16 cases have passing evidence across the named matching-source runs; one positive native nonzero Observe profile is unsupported. The additional negative refusal/recovery control passes separately. No failed historical row has been changed to a pass. Three Python oracle tests and 28 Rust peer tests passed during this batch; terminal error handling was subsequently compiled, linted, and exercised by the final live refusal control.
