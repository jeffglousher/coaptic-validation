When a Q-Block payload arrived exactly at a missing-block recovery deadline, App dispatched it and then sent a recovery report computed before ingress. A completed upload could therefore be followed by 4.08, or a completed download by an obsolete GET.

Revalidate the bounded recovery opportunity against the current body identity, role, block geometry, timer and holes after dispatch/give-up. Completion, reclamation or a reset receive timer invalidates the old opportunity. No extra body-transfer copy is retained.

Proof: the new upload test failed on the old code with a stale missing-block report. Tests cover filling one of two holes and resetting the deadline, reporting only the remaining hole at the new deadline, complete upload bytes/status at the deadline, and complete client Q-Block2 assembly with no obsolete outgoing GET. Existing recovery and protected-path refusal tests remain active.

Validation: all 15 CONTRIBUTING commands and both two-iteration dogfood baseline comparisons passed on 43ad8cc before a clean rebase to 961f30b9ffa38b5e25924d86eb2cacca032077ae; identical implementation tree relative to the merged parent. All-features inventory: 590 passing unit tests. Windows MSVC, stable Rust 1.97.1; Rust 1.85 core/all-feature checks passed. CI retains Linux, process, seeded and cross-code-generation evidence. No device execution or full Q-Block conformance claim.

Related: #201 and #202. Timed protected recovery, mixed-type outgoing batches/congestion control and client missing-block reissue remain open.
