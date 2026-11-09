# Exact-H host, startup and Wi-Fi evidence

This package retains the fresh exact-H host comparison and the separate completed
ESP32-S3 Wi-Fi development screen. All host/Wi-Fi latency vectors, including failed
decisions, are retained. Startup/functional qualification has its own dataset and
contributes no speed samples. No H source/profile adoption or completed speed goal
is implied by a passing offline verifier.

The fresh host gates pass: H Mio/C goodput 1.30214 and H async/C 1.12069.
Against accepted a85, the ratios are 0.97949 Mio and 1.01798 async; these are mixed
throughput point estimates, with no CPU inference. The separate Wi-Fi screen
fails for both profiles: strict-best-C latency ratios 1.06576 sync and 1.47413 async.
Against their own contemporary Rust controls, ratios are 1.16421 and 0.94793,
while physical static SRAM falls 3,584 and 256 bytes respectively. Original stack
reservations remain. Startup qualification passes 48 reads per mode and stays
excluded from the 1,152 speed reads. Boot/cell variation and all tails are in data.

The accompanying runtime change consumes task-local notifications before native
parking while continuing to probe child readiness and deadlines. Production
async_network.rs matches the measured 32f8 runtime; the subsequent 9b90 addition
is a test-only future-deadline regression. Focused driver checks pass 11/11 with
network/OSCORE and 12/12 with pairing, including that test in both configurations,
against accepted a85 core. Existing 32f8 Clippy and Xtensa checks are retained.
The change adds one shared atomic word (4 bytes); no isolated complete-App CPU
gain is claimed for it. H profile acceptance remains separate.

Use Python 3.10+ from the exported package directory:

```text
python -B verify.py
python -B test_export.py
```

The verifier regrades the original host logic from sanitized full records, every
Wi-Fi cell/tail and boot comparison, actual promising decisions, memory/resource
ledgers, exported CPU/cache/task/settling policy and numeric startup guards. It checks gzip/raw hashes and exact source
normalization: 679 baseline files, three replaced existing files, one new test file,
680 effective files and 676 unchanged files. The original build report/script are
not rewritten. All original report/method/freeze digests remain linked.

Host gates require each H mode's 12-case aggregate goodput/C >=1.03 and each of
three round geometric ratios >1, with all completion/capacity/failure checks.
Report all cases, descriptive pooled tails and comparisons to accepted a85;
three rounds do not establish per-case CPU preservation or isolated CPU gains.
Mio and actual async use their original HostControl configuration and capacities.
C matches the declared static unprotected GET/CON/Block2 workload with dynamic
allocation; whole-feature/capacity/security parity is not claimed.

The Wi-Fi gate requires all six pooled median ratios below the strongest of two
contemporaneous C controls, geometric latency ratio <=0.97 and each boot's geometric
ratio below each C control, plus resource/stability guards. Both opposite boot
orders and all observations remain. Two boot clusters are descriptive, not RF or
long-duration stability qualification. Ethernet host/AP/device Wi-Fi are included.
Original 96 KiB/192 KiB Rust and 16 KiB C stacks are preserved. Stack reservations,
observed lifetime use, static IRAM aliases, heap snapshots and cache reservations
are distinct overlapping owners; do not sum them twice or infer peak/minimum RAM.
Only instruction-cache settings are frozen per image. Data-cache defaults may be
reconstructed, but are not per-image attestations in these records.

Public data omits IP/MAC, run/session/process identities, user paths, raw API,
configuration, credentials, binaries, firmware, ELF and NVS. Original private
reports remain retained and are not reconstructible from the whitelisted export.
Numeric vectors and hash commitments allow the published statistical regrade.
Physical source/identity/restoration/API and production-probe/archive/SDK/finalizer
joins remain private producer attestations; this is not an independent firmware
rebuild kit. Source patches name the actual H and 32f8 revisions and link the
subsequent runtime regression test without claiming those images were compiled
from the later wrapper commit.

`export.py` reads explicit private roots only after `--parent-clocks-released`.
It writes a new `package/` under its own directory and refuses existing output.
Supply `--native-root`, `--core-repo`, `--suite-repo`, `--runtime-target` and the
clock-release flag. It does no build, hardware action, network call or benchmark.
The combined private preparation/export budget is 8 MiB; originals stay outside it.
The package's adopted:false flag refers to H and its profiles. Runtime source delivery and performance acceptance remain separate claims.
