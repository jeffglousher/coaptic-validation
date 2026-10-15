Download follow-ups could silently drop If-Match, If-None-Match and Content-Format outside FETCH. Retain those bounded options for every live Call. Classic Block2 also retains request ETag; Q-Block2 omits it to avoid a 2.03 cache-validation reply in place of requested payloads (RFC 9177 section 4.4). Non-FETCH request payloads are not repeated by this change.

Evidence: 18 combinations of GET/FETCH/POST, classic continuation/Q window/timed Q recovery, and If-Match/If-None-Match verify exact follow-up options. Protected GET recovery checks authenticated Inner If-Match. Repeated oversized tag refusal occurs before I/O, with empty If-Match and maximum-length tags accepted afterward. The four-call metadata costs 96 host bytes including alignment; footprint tests account for it explicitly while retaining body-pool exclusion checks.

Validation at 8bd9681: all 15 CONTRIBUTING checks and both two-iteration dogfood baselines pass locally on Windows MSVC, including 611 all-feature library tests. Logs retained at D:\coaptic-build\download-conditions-validation-*.log. Hosted source-bound qualification is required before merge; device runtime and full independent option coverage remain unqualified.

Refs #201. Depends on #251. This does not close the umbrella or claim complete RFC conformance.
