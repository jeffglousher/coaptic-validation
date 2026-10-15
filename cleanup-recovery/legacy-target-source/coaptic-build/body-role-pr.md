Request and response transfers sharing a peer, Token and Request-Tag now retain independent body storage. Incoming lookup includes the transfer role in both fixed and allocated backends; client upload continuation and cleanup select upload roles explicitly instead of taking the first matching server response body.

Regression proof: the incoming shared-key case failed with IdentityMismatch before the fix. The shared oracle covers both backends, both arrival orders, classic/Q upload and download combinations, malformed continuation refusal without mutation, exact completion and independent release. Twelve App cases cover upload completion, cancellation and continuation-send failure while preserving an unrelated retained server body with the same key.

Validation at 29258cc (rebased without implementation changes): all 15 CONTRIBUTING checks plus both two-iteration dogfood baselines pass on Windows MSVC; 629 all-feature library tests. Logs: D:\coaptic-build\body-role-validation-*.log. Hosted checks required before merge. This closes the tested transfer-role collision, not complete multi-peer lifecycle or RFC coverage.

Refs #201, #202. Depends on #263.
