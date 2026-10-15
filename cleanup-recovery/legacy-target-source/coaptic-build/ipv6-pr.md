Add IPv6 loopback addressing to the independent Rust and C peers and five explicit UDP pair cases: Coaptic self-pair and both directions with coap-rs/libcoap. Each checks exact GET, 4.04, 2000-byte Block2 assembly and subsequent valid service. A hand-written CoAP request over a separate AF_INET6 socket records the actual ::1 response, so silent IPv4 fallback cannot pass.

The capability manifest now requires 36 full cases, or 31 enabled plus five explicit C-DTLS exclusions on the local Windows build. Scoped/link-local IPv6, IPv6 DTLS and combined fault schedules remain explicitly unqualified. Existing timing pairings remain IPv4 and unchanged.

All 14 local checks (11 CONTRIBUTING, both dogfood baselines, peer clippy), 15 Python harness tests and all 31 enabled Windows process cases passed. Final clean-source report d03fd62 is D:\coaptic-build\ipv6-process-final.json; rebased c66b314 has identical tree. Release Rust peers and native MSVC C peer rebuilt. Earlier df3d33c report predates only the remaining-gap wording correction. Linux CI remains required.

Reviewed actual address-family proof, peer isolation, bounds, protocol refusal, harness accounting and claim precision. Advances #200/#202; no full IPv6 or RFC conformance claim.
