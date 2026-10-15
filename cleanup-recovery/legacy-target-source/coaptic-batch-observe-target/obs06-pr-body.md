Completes the vendored TD_COAP_OBS_06 in the Coaptic-client/Coaptic-server direction using real loopback UDP. After delivered and acknowledged CON notifications, the client drops protocol state while retaining the exact CapturingIo/socket. It discards the next old notification and sends a matching RST. Three attempted updates during three one-second quiet intervals produce neither traffic nor delivered updates; fresh registration on the same endpoint then receives two complete acknowledged CON notifications.

Strict grading requires fourteen unique datagrams including recovery and binds endpoints, resource, tokens, MIDs, bodies, sequence values and empty RST. Twelve mutated traces must fail. A separate socket test proves wrong-peer and wrong-MID resets preserve the legitimate observation. Quiet duration and application non-delivery are live runner assertions; packet grading validates the wire sequence.

Both coap-rs directions remain SKIP. This is a plaintext protocol-state restart fixture, not physical reboot, authenticated peer ownership, flash recovery or sustained availability.

Validation: focused OBS_06 socket/mutation test and live wrong-control test pass after normal merge of companion main; scoped Clippy with warnings denied, formatting and diff checks pass. OBS_01 both-client regression passed before the merge; owned source/test files exactly match that reviewed source after merge. Core baseline is 9a74f2362040fde40d3b869229b4abf9c319bd35. PCAP/source provenance retained at D:\coaptic-batch-observe-target\restart-evidence (clean tested pre-merge suite6c2ab65; owned qualification code unchanged).

Tracks jeffglousher/coaptic#416 under jeffglousher/coaptic#199/#202. Close child only after required final core integration pin merges.
