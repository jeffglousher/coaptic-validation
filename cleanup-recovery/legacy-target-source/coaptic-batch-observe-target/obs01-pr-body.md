Qualifies the complete vendored TD_COAP_OBS_01 with a Coaptic server and either Coaptic or coap-rs client over real loopback UDP. Registration and two complete CON notifications must be acknowledged, preserve token/content format, and advance the Observe sequence. Strict grading binds endpoints, resource path, full payloads, MID ownership and the six-datagram exchange; 12 independent mutations per client must fail.

Coap-rs server directions remain SKIP because that fixture has no controlled CON source. OBS_06 and other unsupported literal Observe cases remain SKIP in this PR; the previous NON reset proof is not counted as CON qualification.

The core baseline is merged coaptic#413 at 9a74f2362040fde40d3b869229b4abf9c319bd35. Its tree exactly matches tested source 32d98a3a03360d8c13b3ef0dcd570053ddf46a79 (2bb2c28c042ca49729c2b427f14aa57dc9d03956).

Validation (focused only):
- New OBS_01 socket test: both clients pass, 24 altered traces refused.
- Existing OBS_02 socket test and RFC7641 NON reset qualification pass.
- Scoped interop/observe_reset Clippy with warnings denied; formatting and diff checks pass.
- Two PCAPs and source provenance retained locally at D:\coaptic-batch-observe-target\con-evidence. This is loopback interoperability evidence, not hardware or routed-network qualification.

Tracks jeffglousher/coaptic#410 and refines jeffglousher/coaptic#199/#202. The child remains open until this qualification and the final core integration pin merge.
