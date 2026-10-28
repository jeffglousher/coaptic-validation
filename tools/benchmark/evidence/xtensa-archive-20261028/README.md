# Hosted Xtensa archive proof

[Run 40694497672, attempt 1](https://github.com/jeffglousher/coaptic-validation/actions/runs/40694497672)
built the public pairing/async Rust archive successfully on Ubuntu 24.04.
The job took 127 seconds: tool setup took 57.297 seconds and the archive build
54.840 seconds. Processing took 113.989 seconds; these are nested durations.

The actual inputs were companion `a4c11efd73e4dcb72d4799f19ffe52600af05e1b`
and core `28d9f1a61d15121d75d5dd426ad8d6b5cc891005`. Rust compiler commit
`8ea53bcd7257011cbf96f6398551bdc650b04334` used Linux x64 and LLVM 21.1.3.
Four official SDK payloads passed exact size and SHA256 checks before extraction
or installation. The unchanged locked helper selected `network,standalone,oscore,pairing,async-network`
for `xtensa-esp32s3-none-elf`.

The archive is 4,738,968 bytes, SHA256
`c6b6bf185b65954feb9a0b3969905029070b4b7d26406060f42b3a08e60ae568`.
Parent and independent review checked all 166 canonical source hashes, seven
lock hashes, 46 ELF32 little-endian relocatable Xtensa objects and six unique
strong global function exports. [build.json](build.json) preserves the exact
producer manifest; [receipt.json](receipt.json) records collection and verification.
The binary is retained as a build input outside Git.

Sampled owned runner storage reached 4,252,146,576 bytes. This is a sampled total
of the workspace and owned temporary directory, without a growth baseline; it
is not a continuous peak or a memory measurement. The job limits were 45 minutes,
40 minutes of processing, 10 GiB sampled owned storage, a 1 GiB free-space floor,
128 KiB logs, a 16 MiB archive and a 32 MiB artifact.

The first workflow review found missing component checksum gates in the espup
route; the executed repair checks all four payloads explicitly. The parent's
first read-only acceptance wrapper stopped at a Windows process-settlement guard
before writing the archive. That failure remains retained; the corrected bounded
wrapper passed, and the hosted build was not rerun.

This proves public Rust archive compilation, identity, object format and exports.
It does not prove equivalence to the original Windows ancillary SDK, final C++
callback resolution/linkage, a firmware image, device behavior, hardware performance,
whole memory or either 50% CPU target. Existing device firmware remains unchanged.
[Issue #217](https://github.com/jeffglousher/coaptic-validation/issues/217) remains
open for bounded local firmware assembly, preserving app-only OTA and paired proof.
