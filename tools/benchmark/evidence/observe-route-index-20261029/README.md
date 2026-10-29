# Observe route lookup: REJECT

[Run 40970202099/1](https://github.com/jeffglousher/coaptic/actions/runs/40970202099), core `96505cf772ffb01c3f0037ada79f1570034021c5`, compares the checked slot lookup with a frozen direct-copy poll/engine/scan oracle from `176c337d350a4f601e4c2a02b9bdfdcaf0792a92`. [PR711](https://github.com/jeffglousher/coaptic/pull/711) remains unmerged; no runtime optimization is delivered.

The timed entry is one complete due NON-notification App poll, with a bounded in-memory transport. Fixed Constrained-derived resources use one Observe entry/Call, zero deferred rows, four request bindings, one association, no blockwise bodies, and a 32-byte payload. Eight cells cover 4/32 populated routes, first/last selection and unprotected/OSCORE. Authentication and verification are outside clocks.

Both 32-route last-slot cells miss the frozen mean <= -5% and upper95 < 0 gates in both AB/BA rounds. Their changes are +3.297%/+1.510% unprotected and -0.613%/-1.398% OSCORE. Ten of twelve other upper95 <= +2% guards fail. Producer `INCONCLUSIVE/REJECT` is preserved; complete data support REJECT. No replacement samples or changed gates. Cause unknown.

877 correctness tests, 48 fixture lines and same-head quick checks (1209/716 tests, Clippy/fmt) pass. Data retain 166 exact texts including all 144 Criterion JSON files (960 pairs/16 intervals), logs, plan and the earlier Clippy failure. Two input receipts reconstruct byte-exactly from the pinned Git tree and labeled projections. Collector receipt is verbatim; index hashes canonical bytes. Original ZIP and all 246 members were verified in RAM; omitted duplicate source/build/meta payloads expire remotely November 5.

Compiler/binary identity, cleanup and resource limits remain producer-attested. No CPU50, UDP/device, emitted-stack or whole-memory gain follows. Full parameters, nested timings, counts and limits are in the receipt and plan.
