Candidate: `68bed08603eda8ee36b9b30108e28cf7668022f3`; Coaptic library `9a96d9bab679078f7f009746f69c35ad8e883d51`. Both checkouts clean.

Focused validation:

- 44 benchmark Python tests passed, including independent authentication, request binding, replay/tamper/wrong-key refusal, malformed control and Block2 rejection, failure accounting, per-stratum smoke coverage and dependency mutation.
- Native benchmark release builds and warning-free Clippy passed; Rust formatting and `git diff --check` passed.
- Real UDP Coaptic and aiocoap protected fixtures passed complete Block2 delivery, plaintext/wrong-key/tamper/replay refusal and fresh valid recovery.
- Final matched smoke passed 16 cells with zero request, warmup or invalid-cell failures. Small and 64 KiB bodies were exercised in both plaintext and OSCORE strata.

Read-only Bugbot review identified three P2 defects: illegal Empty ACK acceptance for NON requests, incomplete Block2 option/size validation, and dropped uvloop configuration with incorrect provenance. All three were fixed and covered by focused tests before the finite campaign started. The raw review findings and failed preliminary observations remain retained locally.

The ten-session matched campaign is underway with five plaintext server libraries plus the separately labelled codec fixture and two native OSCORE fixtures. A serial native-driver current/5039 source comparison uses identical benchmark fixture source, compiler, lockfile, feature set and resource configuration. Final counts, uncertainty, sources and limitations will be attached before integration. DTLS, impairment, HTTP/3, hardware and saturation qualification remain outside this finite child of jeffglousher/coaptic#341.
