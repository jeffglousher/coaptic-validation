# Finite independent Observe and token receipts

The authoritative row-to-result mapping is [independent-profiles.json](../../../interop/independent-profiles.json). It adds seven named profile directions and eleven bootstrap option-envelope directions without changing the existing 181-case process inventory or evaluator. Every selector names one receipt with its tested core and companion commits and SHA256. This is source-bound finite interoperability evidence, not a latest-source sweep or long-term stability result.

All seven Observe/token profile directions have passing results: four selected query/FETCH directions, two confirmable Q-Observe directions, and one protected extended-token boundary. The bootstrap receipt independently supplies four groups/eleven directions. Native libedhoc cryptography uses a custom CoAP envelope; it is not represented as a complete native CoAP stack.

## Retained failures and corrections

Original reports are byte-for-byte copies. The first Linux run retains six fixture failures and the protected-token pass. Windows-first retains two selected-direction passes and four failures. The latter exposed a real Coaptic Q client fault: automatic next-window requests raced an ACK-driven CON train, and valid duplicate blocks terminated the Call. Core 389d5ab includes the corrected behavior and focused regressions.

The selected reverse failures required native stateless FETCH configuration and a 4-second notification wait beyond the existing 3-second endpoint NON hold. There was no proven server relation loss. Windows-four then passed both reverse selected directions. The next Q batch corrected fixture producer admission retry and fully collected initial M1 representations. Windows-q-first retains successful three-epoch peer exchanges with failed ancillary grading: an exact repeated recovery block and a solicited cancellation reply were incorrectly rejected. PR114 corrects those classifications without weakening identity or payload checks.

Windows-q-controls passes Coaptic-to-libcoap completely. Its reverse peer completed all three representations but the Coaptic server exited with status 1 before a fresh request; the cause was not captured. A reverse-only diagnostic capture then passed all peer and raw controls without a code change. The earlier exit remains unexplained and is tracked in [companion issue115](https://github.com/jeffglousher/coaptic-validation/issues/115): a Windows UDP asynchronous error is a hypothesis, not a finding. No adapter policy changed and no repeat campaign was run. The retained diagnostic wrapper reads bounded post-ready stdout only after process exit; its exact hash is included in the result. It did not execute that failure branch in the passing capture.

## Exact scope

Q profiles use 22 blocks of 32 bytes (704 bytes), actual MAX_PAYLOADS 10, requested SZX 6 from Coaptic or 1 from native, negotiated SZX 1. Captures require full endpoint/token/epoch/ETag/Size2/body identity, ACKs for CON notifications, exact final-window 20/21 recovery, next epoch, cancellation quiet and fresh recovery. Only exact same-epoch duplicate payloads are tolerated. Host fixture storage and 8 MiB worker stack are not embedded App RAM claims.

Windows native DTLS/OSCORE were disabled. Protected proof comes only from the retained Linux protected-token row: 32-byte protected success, 64-byte authenticated capacity refusal, tamper/no effect and fresh recovery. Current Windows binaries were reused only after byte hashes and unchanged Rust/native sources and Cargo locks were checked; the reused-build record is embedded in the final receipts. The cancelled queued Linux retry has no qualification result.
