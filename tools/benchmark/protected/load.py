"""Matched unprotected/OSCORE external UDP driver using independent aiocoap crypto.

One outstanding datagram per worker; no retransmission, fresh MID per block.
Python/GIL and authentication/byte validation are included in measured time.
This driver is a separate measurement stratum from the native Rust load driver.
"""
import argparse
import concurrent.futures
import json
import socket
import threading
import time
from array import array

import aiocoap
from aiocoap.message import Direction
from context import Context, SECURITY


class DriverError(Exception):
    pass


class GroupObservation:
    """One worker's verified intervals and measured datagram counts."""
    def __init__(self, operations):
        self.first_send_ns = None
        self.final_receive_ns = None
        self.first_sends = array("Q", [0]) * operations
        self.final_receives = array("Q", [0]) * operations
        self.wire = dict(
            data_requests=0,
            received_datagrams=0,
            matching_empty_acks=0,
            piggybacked_responses=0,
            separate_con_responses=0,
            separate_non_responses=0,
            sent_response_acks=0,
        )

    def record_verified(self, index, epoch):
        first, last = self.first_send_ns, self.final_receive_ns
        if first is None or last is None or not epoch <= first <= last:
            raise DriverError("invalid verified I/O interval")
        # Zero identifies a group slot with no verified operation.
        self.first_sends[index] = first - epoch + 1
        self.final_receives[index] = last - epoch + 1


# One immutable window covers any payload accepted by recv(65535), including
# every phase of the fixture's 251-byte period. Comparison still checks every
# byte; Python-level per-byte arithmetic is outside the measured hot path.
_MAX_RECEIVE = 65535
_FIXTURE_WINDOW = bytes(range(251)) * ((_MAX_RECEIVE + 250 + 250) // 251)


def body_matches(body, offset):
    if offset < 0 or not 0 < len(body) <= _MAX_RECEIVE:
        return False
    start = offset % 251
    return body == _FIXTURE_WINDOW[start:start + len(body)]


def check_body(message, offset, size, etag, requested_block=None, *, fixture=False):
    counts = {}
    for option in message.opt.option_list():
        number = int(option.number)
        counts[number] = counts.get(number, 0) + 1
        if number not in (4, 12, 14, 23, 28) and option.number.is_critical():
            raise ValueError("unsupported critical response option")
    if counts.get(12) != 1 or counts.get(23, 0) > 1:
        raise ValueError("duplicate/missing response option")
    if message.code != aiocoap.CONTENT or message.opt.content_format != 42:
        raise ValueError("response status/Content-Format")
    if len(message.opt.etags) > 1 or any(not 1 <= len(v) <= 8 for v in message.opt.etags):
        raise ValueError("invalid ETag")
    current = message.opt.etags
    if fixture and (current != (b"fixture",) or counts.get(28, 0) > 1
                    or (message.opt.size2 is not None and message.opt.size2 != size)):
        raise ValueError("fixture ETag/Size2 mismatch")
    if etag is not None and current != etag:
        raise ValueError("changed representation ETag")
    body = message.payload
    if offset + len(body) > size or not body_matches(body, offset):
        raise ValueError("representation mismatch")
    block = message.opt.block2
    if block is None:
        if requested_block is not None or offset:
            raise ValueError("missing negotiated Block2")
        if offset + len(body) != size:
            raise ValueError("incomplete representation")
        return size, None, current
    if block.size_exponent == 7 or block.start != offset or len(body) > block.size:
        raise ValueError("Block2 range")
    if requested_block is not None and block.size_exponent > requested_block[2]:
        raise ValueError("Block2 size increased")
    end = offset + len(body)
    if block.more:
        if len(body) != block.size or end >= size:
            raise ValueError("Block2 M/length")
        return end, (end // block.size, False, block.size_exponent), current
    if end != size:
        raise ValueError("incomplete representation")
    return end, None, current


def wait_for_slot(due_ns):
    while True:
        now = time.perf_counter_ns()
        remaining = due_ns - now
        if remaining <= 0:
            return now
        if remaining > 150_000:
            time.sleep((remaining - 150_000) / 1_000_000_000)


class Worker:
    def __init__(self, args, number, context, crypto_lock):
        self.args, self.number = args, number
        self.context, self.crypto_lock = context, crypto_lock
        self.expected_exchange = getattr(args, "expect_exchange", None)
        self.mid = 0
        self.retired = []
        self.bootstrap_echo_challenges = 0
        self.socket = self.new_socket()

    def new_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.connect((self.args.host, self.args.port))
        return sock

    def close(self):
        self.socket.close()
        for sock in self.retired:
            sock.close()

    def exchange(self, sequence, *, bootstrap=False, observation=None):
        start = time.perf_counter_ns()
        if self.mid + (self.args.bytes + 15) // 16 > 65536:
            try:
                fresh = self.new_socket()
            except OSError as error:
                raise DriverError("endpoint rotation") from error
            self.retired.append(self.socket)
            self.socket = fresh
            self.mid = 0
        deadline = time.monotonic() + self.args.timeout_ms / 1000
        token = ((self.number << 48) | sequence).to_bytes(8, "big")
        offset, etag = 0, None
        # The native comparison client starts with GET and follows the server's
        # first Block2 choice. Keep explicit negotiation in the other campaigns.
        block = (0, False, 6) if self.args.bytes > 1024 and self.expected_exchange is None else None
        echo = None
        expected = None if bootstrap else self.expected_exchange
        response_mids = set() if expected == "separate-con" else None
        while True:
            saw_empty_ack = False
            mid = self.mid
            self.mid += 1
            request = aiocoap.Message(code=aiocoap.GET, uri_path=("bench",), block2=block)
            request.opt.echo = echo
            request.mid, request.mtype, request.token = mid, aiocoap.CON if self.args.mode == "con" else aiocoap.NON, token
            if self.context:
                with self.crypto_lock:
                    outgoing, binding = self.context.protect(request)
                    outgoing.mid, outgoing.mtype, outgoing.token = mid, request.mtype, token
                    # A shared identity reserves and dispatches each sequence
                    # atomically. Do not create local reordering wider than the
                    # recipient's bounded replay window before UDP sees it.
                    self.socket.send(outgoing.encode())
            else:
                self.socket.send(request.encode())
            if observation is not None:
                if observation.first_send_ns is None:
                    observation.first_send_ns = time.perf_counter_ns()
                observation.wire["data_requests"] += 1
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("complete representation deadline")
                self.socket.settimeout(remaining)
                wire = self.socket.recv(_MAX_RECEIVE)
                received_at = None
                if observation is not None:
                    received_at = time.perf_counter_ns()
                    observation.wire["received_datagrams"] += 1
                if wire == bytes([0x60, 0, mid >> 8, mid & 255]):
                    if self.args.mode != "con":
                        raise ValueError("ACK for NON request")
                    if expected and (saw_empty_ack or expected == "piggyback"):
                        raise ValueError("unexpected extra empty ACK")
                    saw_empty_ack = True
                    if observation is not None:
                        observation.wire["matching_empty_acks"] += 1
                    continue
                response = aiocoap.Message.decode(wire)
                if response.code == aiocoap.EMPTY:
                    raise ValueError("malformed empty control")
                if response.token != token:
                    if expected:
                        raise ValueError("unexpected response token in matched exchange")
                    continue
                if response.mtype == aiocoap.RST or (response.mtype == aiocoap.ACK and self.args.mode != "con"):
                    raise ValueError("response type")
                if response.mtype == aiocoap.ACK and response.mid != mid:
                    if expected:
                        raise ValueError("unexpected piggyback MID in matched exchange")
                    continue
                if expected == "separate-con" and (not saw_empty_ack or response.mtype != aiocoap.CON):
                    raise ValueError("expected empty ACK followed by a separate CON")
                if response_mids is not None:
                    if response.mid in response_mids:
                        raise ValueError("reused separate response MID within one read")
                    response_mids.add(response.mid)
                if expected == "piggyback" and response.mtype != aiocoap.ACK:
                    raise ValueError("expected piggybacked response")
                if self.context:
                    if response.opt.oscore is None:
                        raise ValueError("unprotected application response")
                    response.direction = Direction.INCOMING
                    with self.crypto_lock:
                        plain, _ = self.context.unprotect(response, binding)
                else:
                    if response.opt.oscore is not None:
                        raise ValueError("unexpected protection")
                    plain = response
                challenge = plain.code == aiocoap.UNAUTHORIZED and plain.opt.echo is not None
                if challenge:
                    # libcoap initializes its recipient replay window with an
                    # authenticated RFC 8613 Appendix B.1.2 Echo challenge. Only
                    # the explicit untimed bootstrap may retry it, once.
                    options = list(plain.opt.option_list())
                    if (not bootstrap or self.context is None or echo is not None or offset
                            or len(options) != 1 or int(options[0].number) != 252
                            or not 1 <= len(plain.opt.echo) <= 40 or plain.payload):
                        raise ValueError("unexpected/malformed authenticated Echo challenge")
                    echo = plain.opt.echo
                    self.bootstrap_echo_challenges += 1
                else:
                    offset, block, etag = check_body(plain, offset, self.args.bytes, etag, block,
                                                     fixture=self.expected_exchange is not None)
                    echo = None
                # A separate CON response is acknowledged only after authentication.
                if response.mtype == aiocoap.CON:
                    ack = aiocoap.Message(code=aiocoap.EMPTY)
                    ack.mtype, ack.mid = aiocoap.ACK, response.mid
                    self.socket.send(ack.encode())
                    if observation is not None:
                        observation.wire["sent_response_acks"] += 1
                break
            if challenge:
                continue
            if observation is not None:
                if response.mtype == aiocoap.ACK:
                    observation.wire["piggybacked_responses"] += 1
                elif response.mtype == aiocoap.CON:
                    observation.wire["separate_con_responses"] += 1
                else:
                    observation.wire["separate_non_responses"] += 1
            if block is None:
                if observation is not None:
                    observation.final_receive_ns = received_at
                return time.perf_counter_ns() - start

    def bootstrap(self):
        # Every matched peer performs the same complete, byte-verified GET
        # before warmup and timing. Errors abort setup; no sample is filtered.
        self.exchange(0, bootstrap=True)


def run(args):
    if args.host != "127.0.0.1":
        raise ValueError("benchmark credentials and sockets are loopback only")
    for value, low, high in ((args.port, 1, 65535), (args.bytes, 1, 1048576), (args.concurrency, 1, 128),
                             (args.operations, 1, 200000), (args.warmup, 0, 10000), (args.timeout_ms, 1, 60000),
                             (args.sequence, 0, 1 << 36)):
        if not low <= value <= high:
            raise ValueError("driver bounds")
    rate = getattr(args, "rate", None)
    if rate is not None and not (1 <= rate <= 1_000_000 and args.operations <= rate * 120):
        raise ValueError("invalid offered rate or paced duration")
    group_starts = getattr(args, "group_starts", False)
    if group_starts and (rate is None or args.mode != "con" or args.operations % args.concurrency):
        raise ValueError("group starts require paced CON and complete groups")
    slot_width = args.concurrency if group_starts else 1
    per_endpoint = 65536 // ((args.bytes + 15) // 16)
    # Reserve a complete bootstrap plus a possible Echo retry conservatively
    # as two operations, including the smallest one-datagram representation.
    reserved = sum(max(1, (args.operations // args.concurrency + (i < args.operations % args.concurrency)
                          + args.warmup + 2 + per_endpoint - 1) // per_endpoint) for i in range(args.concurrency))
    if reserved > 1024:
        raise ValueError("driver endpoint reservation exceeds 1024")
    expected = getattr(args, "expect_exchange", None)
    if expected is not None and (args.mode != "con" or expected not in ("piggyback", "separate-con")):
        raise ValueError("wire shape requires a CON request and a known exchange")
    observations = None
    if group_starts or expected:
        observations = [GroupObservation(args.operations // args.concurrency if group_starts else 0)
                        for _ in range(args.concurrency)]
    context = Context(args.credentials, sequence=args.sequence) if args.security == SECURITY else None
    lock = threading.Lock()
    workers = [Worker(args, i, context, lock) for i in range(args.concurrency)]
    barrier = threading.Barrier(args.concurrency + 1)

    def work(worker):
        warmup_failed, failures, latencies, reasons = 0, 0, [], {}
        observation = observations[worker.number] if observations is not None else None
        worker_slot = 0 if group_starts else worker.number
        sequence = 1
        for _ in range(args.warmup):
            try:
                worker.exchange(sequence)
            except Exception:
                warmup_failed += 1
            sequence += 1
        barrier.wait()
        barrier.wait()
        count = args.operations // args.concurrency + (worker.number < args.operations % args.concurrency)
        missed = 0
        max_lateness = 0
        for index in range(count):
            if rate is not None:
                ordinal = index * args.concurrency + worker_slot
                due = start + ordinal * 1_000_000_000 // rate
                next_due = start + (ordinal + slot_width) * 1_000_000_000 // rate
                actual = wait_for_slot(due)
                missed += int(actual >= next_due)
                max_lateness = max(max_lateness, actual - due)
            try:
                if observation is None:
                    latency = worker.exchange(sequence)
                else:
                    observation.first_send_ns = None
                    observation.final_receive_ns = None
                    latency = worker.exchange(sequence, observation=observation)
                    if group_starts:
                        observation.record_verified(index, start)
                latencies.append(latency)
            except Exception as error:
                failures += 1
                label = type(error).__name__
                reasons[label] = reasons.get(label, 0) + 1
            sequence += 1
        return latencies, failures, warmup_failed, reasons, missed, max_lateness

    try:
        for worker in workers:
            worker.bootstrap()
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = [pool.submit(work, worker) for worker in workers]
            barrier.wait()
            start = time.perf_counter_ns()
            cpu_start = time.process_time_ns() if group_starts else None
            barrier.wait()
            rows = [future.result() for future in futures]
            elapsed = time.perf_counter_ns() - start
            client_cpu = time.process_time_ns() - cpu_start if cpu_start is not None else None
        latencies = [n for row in rows for n in row[0]]
        failed, warmup_failed = sum(row[1] for row in rows), sum(row[2] for row in rows)
        reasons = {}
        for row in rows:
            for key, value in row[3].items():
                reasons[key] = reasons.get(key, 0) + value
        report = dict(schema="coaptic-load/1", protocol="coap", security=args.security, mode=args.mode,
                    concurrency=args.concurrency, warmup=args.warmup, attempted=args.operations,
                    completed=len(latencies), failed=failed, warmup_failed=warmup_failed, driver_failures=reasons.get("DriverError", 0),
                    endpoint_rotations=sum(len(w.retired) for w in workers), verified_bytes=len(latencies) * args.bytes,
                    bootstrap_completed=len(workers),
                    bootstrap_echo_challenges=sum(w.bootstrap_echo_challenges for w in workers),
                    bootstrap="complete verified GET per worker before warmup/timing; at most one authenticated Echo retry",
                    elapsed_ns=elapsed, latencies_ns=latencies, failure_types=reasons, clock="time.perf_counter_ns",
                    measurement="closed-loop; Python/GIL, authentication and complete byte validation included")
        if rate is not None:
            report.update(
                requested_operations_per_second=rate,
                pacing_missed_period_operations=sum(row[4] for row in rows),
                pacing_max_lateness_ns=max(row[5] for row in rows),
                measurement="absolute start schedule; Python/GIL, authentication and full byte validation inside operation latency",
            )
        if expected:
            report["expected_exchange"] = expected
        if observations is not None:
            report["measured_wire_by_worker"] = [o.wire for o in observations]
        if group_starts:
            verified_groups = overlapping_groups = 0
            for index in range(args.operations // args.concurrency):
                starts = [o.first_sends[index] for o in observations]
                if all(starts):
                    verified_groups += 1
                    earliest_finish = min(o.final_receives[index] for o in observations)
                    if args.concurrency > 1 and max(starts) < earliest_finish:
                        overlapping_groups += 1
            report.update(
                start_group_width=args.concurrency,
                verified_groups=verified_groups,
                overlapping_verified_groups=overlapping_groups,
                verified_by_worker=[len(row[0]) for row in rows],
                worker_endpoint_ports=[w.socket.getsockname()[1] for w in workers],
                client_process_cpu_time_ns=client_cpu,
            )
        return report
    finally:
        for worker in workers:
            worker.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "mode", "security", "credentials"):
        parser.add_argument("--" + name, required=True)
    for name in ("port", "bytes", "concurrency", "operations", "warmup", "timeout-ms", "sequence"):
        parser.add_argument("--" + name, type=int, required=True)
    parser.add_argument("--rate", type=int)
    parser.add_argument("--expect-exchange", choices=("piggyback", "separate-con"),
                        help="require the selected wire shape on every warmup and timed CON block; "
                             "separate-con requires the matching empty ACK before the verified response")
    parser.add_argument("--group-starts", action="store_true",
                        help="give all CON workers the same absolute start slot and report overlap and wire counts")
    args = parser.parse_args()
    if args.mode not in ("con", "non") or args.security not in ("unprotected", SECURITY):
        parser.error("unsupported mode/security")
    result = run(args)
    print(json.dumps(result, allow_nan=False))
    return int(bool(result["failed"] or result["warmup_failed"]))


if __name__ == "__main__":
    raise SystemExit(main())
