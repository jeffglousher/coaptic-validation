App previously reclaimed an exhausted Q body before processing a payload already received in the same poll. A last missing payload at the final retry deadline therefore could not complete. Download expiry also left the client call and partial inbox entry active after freeing the body.

Run the bounded Q recovery/expiry step after ingress and notify App when a client download expires. App completes it as CallFailure::TimedOut and retires exchange, partial inbox, body and request-binding state in that poll. The public advanced Engine::progress contract remains unchanged. This replaces the pre-dispatch opportunity snapshot/revalidation from #244 with scheduling against current state.

Proof: last-hole upload arrival at the final give-up deadline failed before the fix; it now completes with exact bytes. No-arrival expiry still reclaims the body. Client tests cover exact-deadline completion versus typed timeout, another live call, subsequent body completion before consuming the old outcome, and empty datagram pools. Protected tests cover binding cleanup, late-response refusal, deadline completion and no plaintext fallback. Timed protected recovery itself remains explicitly Unsupported.

Validation: all 15 CONTRIBUTING checks and both two-iteration dogfood comparisons passed at 3274e75 before a clean rebase to bfd4d5a5ecf60d7907a5199e34b5ecf05e07b85f. All-features unit inventory: 595 passing. Windows MSVC stable Rust 1.97.1 and library MSRV 1.85. Hosted CI retains Linux/process/seeded/cross-build evidence. No full Q conformance, device runtime or performance claim.

Related: #201 and #202. Outgoing message-type/congestion policy, client missing-block reissue, protected recovery and Q Observe remain open.
