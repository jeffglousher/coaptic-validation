# Quick recipes: recorded functional results

These are separate development checks at the sources in [receipt.json](receipt.json).
They establish no CPU reduction, qualified tracing overhead or whole-memory result.
The eight numeric host configurations remain fixed across library iterations.

- **Windows:** core `04b7166`, companion `670a757`; all 16 socket cells,
  six supported C1 core cells, nine reliability phases and both Observe flows
  passed in **43.9005 seconds**. Preparation took **143.9488 seconds** separately.
  Socket work completed 512 measured operations and 64 warmups; core probes
  completed 96 measured operations and 768 warmups, with 24,576 separate clock
  calibrations and existing `black_box` boundaries. Ten core cells remain
  unsupported. This was one candidate regression run, without a matched timing
  improvement claim. Core #698 merged as `28d9f1a`, with tree equality to the
  tested candidate.
- **Deployed XDP:** [run 40680516988](https://github.com/jeffglousher/coaptic-validation/actions/runs/40680516988),
  companion `d037e902`, core `1538814`, passed. The owned veth fixture delivered
  four reference frames before attachment, eight while attached and four after
  detach. Attached deltas were five syntax, one malformed, one oversized and one
  uninspected frame; all eight passed unchanged. Program-ID/SKB checks, detach
  absence, unchanged recovery counters and interface cleanup passed. The cycle
  took **819 ms**; tool setup took 6 seconds, build/check 54 seconds and the
  hosted job 81 seconds. Opaque OSCORE syntax does not prove authentication.
- **Authenticated socket syscall observation:** corrected
  [run 40683333178](https://github.com/jeffglousher/coaptic-validation/actions/runs/40683333178),
  companion `8a043591`, native/BPF core `28d9f1a`, functionally passed all eight
  windows: **16,000 measured operations plus 160 warmups**, with four ON captures.
  Each ON capture recorded 2,000 successful `sendto`, 2,000 successful `recvfrom`,
  2,000 EAGAIN `recvfrom` and 2,000 successful `epoll_wait` calls; other bins and
  anomaly counters were zero. Python 206 tests, Rust 12 tests, Clippy and builds
  passed. The diagnostic phase took **19 seconds**; setup/check took 14 seconds,
  helper/BPF work 70 seconds, native build 166 seconds and the hosted job
  302 seconds. Every CPU gate failed: 0.04 to 0.06 CPU seconds per window versus
  the required 0.20. Three of four pair latency guards also failed. **All overhead
  ratios are withheld.** No load increase, gate change or replacement cohort
  was used to qualify them.
- **Waveshare:** the existing commissioned image passed a protected echo and
  four warmup plus 24 measured protected 32-byte identity reads. The timing
  process took **9.0838 seconds**, including 8.5908 seconds of session setup;
  this is host-observed operation timing on a retained host binary and old
  firmware, not current-library performance. The live run ID matched the
  retained normal image. Current-source host/archive compilation hit output
  guards, so no fresh firmware or OTA was accepted. Identity, credentials, NVS
  and grants were preserved. A reusable current-source firmware refresh remains
  unfinished; the device does not implement the host's eight profiles.

The original [syscall run 40680521078](https://github.com/jeffglousher/coaptic-validation/actions/runs/40680521078)
failed before builds and benchmark windows: 48 fixture errors arose when Linux
host metadata reached a mocked `Popen`. The corrected test isolates
`platform.platform()`; production code and assertions are unchanged. The failed
receipt remains retained.

The collector checked artifact paths, CRCs and member hashes in memory. Syscall
binary hashes are remote build metadata: binary bytes were absent from its
artifact and were not independently rehashed. Passed-window cleanup propagation
and disabled acknowledgements support syscall cleanup; there is no independent
post-detach kernel inventory. Raw arrays and full logs remain in the named
artifacts and retained private evidence; the public receipt contains summaries
and sealed-input hashes. App authentication remains separate from XDP syntax
observation. Kernel/helper costs, peak stack, whole memory, remaining matrix
cells and both 50% CPU targets remain open.
