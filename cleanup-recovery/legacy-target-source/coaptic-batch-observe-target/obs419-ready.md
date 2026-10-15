Implementation is ready for review at local suite commit 0d662afa871cbf867b52989b04a30195f29b625d, based on companion PR24. Publication is intentionally waiting for that prerequisite to merge.

Focused evidence: both literal UDP scenarios pass; 16 trace mutations per scenario refuse (32 total); live wrong-path/wrong-peer cancellation attempts refuse before I/O and preserve notification delivery, then valid cancellation/re-registration succeeds. The unsupported-backend hook refuses without I/O. OBS_01 and OBS_06 regressions and scoped Clippy pass; no full local suite was run.

Clean-source captures and provenance are retained under D:\coaptic-batch-observe-target\owner-evidence. Core source is 9a74f2362040fde40d3b869229b4abf9c319bd35. Coap-rs directions remain SKIP. This issue stays open pending companion publication/merge and the final integration pin.
