Allocated body storage now enforces the same stable Q-Block total length as fixed storage before writing a continuation. A regression reproduced allocated storage completing a body when fixed storage correctly returned LengthInconsistent.

The same wire oracle now runs against both backends for upload/download, unchanged/changed Tokens, missing/zero/short/long/maximal size indications, retained bytes/progress on refusal and corrected completion. Classic Block's changing/disappearing size-estimate matrix also runs against both backends, preserving the distinction between classic estimates and Q-Block total lengths.

Validation at 93ae236: all 15 CONTRIBUTING checks and both two-iteration dogfood baselines pass on Windows MSVC; 627 all-feature library tests (existing tests now exercise both backends). Logs D:\coaptic-build\alloc-size-validation-*.log. Hosted checks required before merge. This is size-validation parity, not a claim of complete backend differential qualification.

Refs #201, #202. Depends on #262.
