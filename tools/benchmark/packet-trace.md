# Socket-boundary validation captures

Run with the benchmark Python environment (aiocoap and its crypto dependencies):

```
python tools/benchmark/packet_trace.py capture --manifest prepared.json --output PRIVATE_NEW_DIRECTORY
python tools/benchmark/packet_trace.py grade --directory PRIVATE_NEW_DIRECTORY/PEER-con-65536
python -m unittest discover -s tools/benchmark -p test_packet_trace.py
```

Each CoAP peer gets a fresh server per 64/65536-byte CON/NON case. Readiness goes
directly to the server; the captured driver starts with OSCORE sequence 2^32,
one complete bootstrap, three operations, one warmup and concurrency one. All five
representations are verified. It runs through a UDP relay,
**never during throughput measurement**. Relay-induced timing is not benchmark
evidence. HTTP/3 is excluded. Exact manifest hash and executable identities are
retained; the prepared manifest remains necessary to resolve the source records.

PCAP uses DLT_USER0 (147): every record is the actual received UDP payload. There
are no fabricated Ethernet/IP headers. The sidecar records direction, client and
relay socket addresses, wall time and a payload digest. This validates the socket
boundary, not kernel packet receipt, IP checksums, NIC behavior or packet loss.
The relay caps 10,000 frames, 16 client endpoints, and 14 MiB packet/sidecar output;
logs are capped at 64 KiB each with refusal on overflow. The case output budget is
16 MiB including metadata. Failure records are preserved; reruns require a new
output directory. Capture incompleteness and any unexplained packet/control are
failures, not silently discarded noise.

Offline unprotected grading checks exact exchange identity, status, Content-Format,
complete deterministic body, Block2 offsets/M/SZX and consistent ETags when
provided. OSCORE grading independently authenticates requests and responses using
aiocoap and the existing benchmark context/body oracle. It rejects tampering,
partial representations, missing controls and truncated or changed capture files.
A sole authenticated 4.01 Echo challenge is permitted only during the bootstrap;
the retry must echo its exact value and use a fresh MID and OSCORE sequence. This
control is counted separately, never as a successful representation. Offline totals
include bootstrap and warmup; they are not timed-operation counts.
The finite workload does not qualify arbitrary CoAP traffic/retransmission policy.

Each case retains a **fresh synthetic 24-byte credential** solely for offline
grading. It is never an installed device credential. Keep the output directory in
private storage; do not commit or publish it. POSIX credential mode is 0600;
Windows privacy depends on the parent directory ACL. Packet captures and manifests
are integrity-indexed, not digitally attested: the grader cannot establish custody
against someone rewriting all artifacts. Preserve original evidence separately.

DTLS records can be checked for framing, lengths and encrypted application epochs.
Without session secrets, that is **not offline authentication or decrypted-body
proof**. The independent online Go driver's successful complete-operation record
is retained separately. `authenticated: false` in offline DTLS results is explicit.
No capture tools, drivers, administrator privileges or system settings are needed.
