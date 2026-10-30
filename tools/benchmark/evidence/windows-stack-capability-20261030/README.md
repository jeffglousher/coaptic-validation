# Windows stack profiling capability

One original unprotected App workload has a complete capture-to-profile path.
[Offline export 41023864069](https://github.com/jeffglousher/coaptic-validation/actions/runs/41023864069)
compiles the reviewed exporter, passes 88 Python checks and 113 pure C# model
assertions, then exports the preserved trace. No new workload or ETW session
runs during replay. This is a capability proof, not a hotspot ranking.

The profile has 41 sampled events, 548 frame occurrences and 40 distinct symbols.
Thirty-three samples have App ancestry; eight do not. That is below the unchanged
200 eligible App-rooted sample floor. Inclusive/self observations include
`poll_engine` 33/2 and `dispatch_rx` 30/6. These counts overlap and are not CPU
percentages. Other observed paths include response encoding, reply retention and
storage. No optimization is nominated from this small capture.

There are 91 unresolved frame occurrences: 41 each in ntdll and kernel32, plus
nine in vcruntime140. Reported lost/refused counts are zero. Export reports no
conversion or depth truncation; the replay qualification conservatively leaves
truncation unknown. Unwind/inline completeness, circular overwrite coverage and
CPU mode remain unknown. No qualified CPU share, speed, stack, whole-memory or
device gain follows.

## Sources and workload

Capture: run **41013864895**, attempt 1; suite
`a074120d6f50b1c061e2ab5b0940837c9d51b63e`; core
`8af71fe4aa73b3bb76a921a836a1a9647d75f361`.
Export: run **41023864069**, attempt 1; suite
`acaf137d1cf7d45770e7ebfbbefb40d01a815466`, tree
`fc0c419b7dc56e6eae4980a18ccf502fb997841d`.
The profile identity preserves the original capture source and tool. The replay
build receipt identifies the current exporter separately. Compiler/tool binary
identity and hosted cleanup remain producer-attested; retained input bytes have
independent hashes.

Windows Server 2022, x64; nominal 1 ms sampled-profile interval. PID 4936 and
workload TID 7436 are historical identities. The original QPC window is
`[11015011619,11015466321)` at 10 MHz, or 45.4702 ms, including capture-control
transit. Event weights count SampledProfile events, not milliseconds or the ETW
payload Count. All 41 timestamps and aligned frame projections match the raw
canonical profile and fall inside that window.

The socket-free batch serves 64-byte representations with Default allocated App
storage, one populated route, zero deferred rows, four Calls, one association
capacity and four request bindings. RX and TX each have four 1472-byte datagrams;
dedup has eight entries, Observe four; RX body storage is one 1024-byte slot and
TX body storage two 1024-byte slots, with blockwise enabled. The native workload
completed 50,000 exchanges plus 128 warmups and verified all 50,128 replies.
Preparation and verification are outside capture; server App work and fixture
copies are inside. This is not the 32-byte fixed SmallDevice route. No sockets,
firmware or device state participate.

## Files and integrity

`index.json` hashes exact committed, decompressed inputs and stored files:

- `profile.json.gz`: exact canonical profile, 123,902 bytes after decompression.
- `profile.html.gz`: exact producer interactive flame viewer, 155,367 bytes.
- `receipt.json.gz`: exact sealed collector receipt, 30,264 bytes.
- `export-receipt.json.gz`: exact exporter receipt and metadata provenance.
- `checks.json`: parent projection/browser checks and review limits.
- `retained-failures.json`: prior setup and export dispositions.

Decompress the HTML and open it locally, or render the JSON with
`tools/benchmark/stack_profile.py`. Both views retain full symbols, unknown frames,
filtering and zoom. Table dictionary order can change between renderer processes;
decoded profile/table/tree content and the HTML template agree. The exact producer
HTML is retained here.

The current artifact **12962613183** is 3,361,067 bytes, SHA256
`4d4a79662e3858a2a1fbbf68acfb9db1d684a1ad766e14a17b45bcbcd648371e`.
All 23 members passed CRC, length and SHA checks; the four original ETL, receipt,
EXE and PDB inputs match their source pins. Their bytes and paths remain unchanged.
The raw archive is retained privately without extraction, not published here.
GitHub artifact retention expires on 2026-11-13; run links are not permanent raw
input storage. Earlier failures remain retained; the other 15 original captures
and two controls were not run. No cohort was replaced or silently pooled.

R16 found no source defects. R17 found no defects in inspected raw evidence; it
did not repeat every sample/projection comparison or the complete four-file source
comparison. Parent checks fill those specific comparison gaps. The recorded zero
ETL ImageId is unavailable corroboration, not a metadata match; empty DebugID is
not a match. Attribution uses the independent held live-owned file binding and
complete bounded raw contradiction checks. It does not attest exact in-memory
bytes or exclude hostile executable replacement before file locking.

See [the profiling guide](../../stack_profiling.md) for privilege, ownership,
resource limits, Linux support and device-trace boundaries. Local capture remains
refused without elevation; Windows uses a dedicated ephemeral hosted VM. No
Linux or device CPU qualification follows from this Windows result.
