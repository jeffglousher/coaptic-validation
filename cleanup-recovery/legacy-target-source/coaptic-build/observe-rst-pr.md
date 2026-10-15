A reset rejecting a server notification must retire that server relation while preserving independent outgoing client bindings. Remove the cross-direction Token cleanup; the server request reference already lives on the removed observer row.

Regression proof uses two real protected Apps with identical Tokens in opposite directions. Both NON and CON rejection preserve the other subscription and its next notification. A reset from another endpoint leaves the relation intact. The test failed on the previous implementation and passes after this change.

Validation: all 11 CONTRIBUTING checks, both dogfood baselines, 554 library unit tests, and 26 enabled Windows process cases passed at 9b047a7. Rebased e57e4ff has an identical tree. Five libcoap DTLS cases are explicitly excluded on this Windows build. Logs: D:\coaptic-build\observe-rst-validation-*.log; source-bound process report: observe-rst-process.json. Linux CI is required; the existing process suite does not independently qualify Observe.

Advances #201; broader Observe qualification remains open. Reviewed protocol matching, ownership, failure paths, bounded state, API impact and test evidence.
