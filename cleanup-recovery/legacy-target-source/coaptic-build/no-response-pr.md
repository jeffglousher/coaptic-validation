The App client now sends explicit No-Response bitmaps (including a present zero), retains them across Block2 follow-ups, and keeps them inside OSCORE protection. Suppression never completes a call as success: an empty ACK only stops retransmission, and the caller must use a deadline or cancellation for silence. Unsuppressed errors remain observable.

Fragmented uploads with No-Response and Observe registration with a suppressing bitmap are explicit typed refusals before I/O. These are App API boundaries, not claims that the RFC prohibits these combinations.

Validation at 0e1ef64e8589009c61d1d09708b7af5df7c41ec5: all eleven CONTRIBUTING.md local checks passed, including Rust 1.85, packaging, both feature configurations and the DTLS/OSCORE harness. The all-feature library suite passed 515 tests. New tests cover CON/NON, masks 0/2/26, actual/suppressed/unsuppressed responses, deadline cleanup, deregistration, upload/registration refusal, retained download options and protected inner policy.

Source: RFC 7967 sections 2, 2.2 and 3.1; RFC 8613 section 4.1.3.6. Contributes to #201; does not close the remaining client/Observe/Q-Block/randomness audit. Windows local evidence; Linux process evidence is supplied by CI. No full conformance or performance claim.
