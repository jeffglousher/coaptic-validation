Host no-default-features checks do not establish embedded code generation. Add a non-published no_std workspace probe that instantiates a bounded App with client/server dispatch and optional OSCORE. A pinned Rust 1.97.1 runner builds release code for Cortex-M0, Cortex-M4, RV32 and WebAssembly, each with core, alloc, OSCORE and alloc+OSCORE features. CI retains a source-bound JSON report for every target.

All 16 local target/feature builds passed at bf7c49e; rebased 13d233d has the identical tree. All 11 CONTRIBUTING host checks and probe clippy passed. Reports D:\coaptic-build\cross-TARGET.json include clean source, full compiler identity, exact commands and outcomes. This adds no library runtime dependency and shares the workspace lockfile/build directory.

Scope is explicitly compile/code generation only: no linked firmware, device/emulator execution, target stack high-water, allocator behavior, entropy or transport integration, or big-endian runtime qualification. These remain open in #202. Reviewed target assumptions, feature isolation, reproducibility, CI failure visibility, packaging and claim precision.

Advances #202; does not close it.
