Remaining literal Observe work was rechecked against the vendored block.yml and current source. #410 is implementing OBS_01 CON notification qualification; it does not close OBS_06. Follow-up #416 tracks the complete OBS_06 same-endpoint client restart, discarded CON, matching RST, bounded quiet period and fresh-registration recovery, initially Coaptic client/server only.

Other concrete fixture dependencies remain:
- OBS_12: same-owner Observe=1 cancellation, preserving token and endpoint; core deregister_call exists.
- OBS_10: unrelated GET on the existing client owner; the current harness send_request drops that owner's observation/socket.
- OBS_09: actual local resource mutation and matching delivered payload; sending a chosen notification alone does not establish changed resource state.
- OBS_04: server state loss plus caller-scheduled Max-Age refresh using the original token; core explicitly leaves scheduling to the caller.
- OBS_05/11: controlled loss and captured retransmission/final timeout behavior.
- OBS_07/08: resource deletion/content-format mutation and terminal notification/cessation.
- OBS_13/14: complete large and variable-size Observe Block2 delivery, including the required initial-response variants.

These are remaining qualification requirements, not blanket claims of missing core capability. Unsupported peer directions remain SKIP; this umbrella stays open.
