"""Matched plaintext/OSCORE external UDP driver using independent aiocoap crypto.

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

import aiocoap
from aiocoap.message import Direction
from context import Context, SECURITY


class DriverError(Exception):
    pass


def check_body(message, offset, size, etag, requested_block=None):
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
    if etag is not None and current != etag:
        raise ValueError("changed representation ETag")
    body = message.payload
    if not body or offset + len(body) > size or any(v != (offset + i) % 251 for i, v in enumerate(body)):
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


class Worker:
    def __init__(self, args, number, context, crypto_lock):
        self.args, self.number = args, number
        self.context, self.crypto_lock = context, crypto_lock
        self.mid = 0
        self.retired = []
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

    def exchange(self, sequence):
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
        block = (0, False, 6) if self.args.bytes > 1024 else None
        while True:
            mid = self.mid
            self.mid += 1
            request = aiocoap.Message(code=aiocoap.GET, uri_path=("bench",), block2=block)
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
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("complete representation deadline")
                self.socket.settimeout(remaining)
                wire = self.socket.recv(65535)
                response = aiocoap.Message.decode(wire)
                if wire == bytes([0x60, 0, mid >> 8, mid & 255]):
                    if self.args.mode != "con":
                        raise ValueError("ACK for NON request")
                    continue
                if response.code == aiocoap.EMPTY:
                    raise ValueError("malformed empty control")
                if response.token != token:
                    continue
                if response.mtype == aiocoap.RST or (response.mtype == aiocoap.ACK and self.args.mode != "con"):
                    raise ValueError("response type")
                if response.mtype == aiocoap.ACK and response.mid != mid:
                    continue
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
                offset, block, etag = check_body(plain, offset, self.args.bytes, etag, block)
                # A separate CON response is acknowledged only after authentication.
                if response.mtype == aiocoap.CON:
                    ack = aiocoap.Message(code=aiocoap.EMPTY)
                    ack.mtype, ack.mid = aiocoap.ACK, response.mid
                    self.socket.send(ack.encode())
                break
            if block is None:
                return time.perf_counter_ns() - start


def run(args):
    if args.host != "127.0.0.1":
        raise ValueError("benchmark credentials and sockets are loopback only")
    for value, low, high in ((args.port, 1, 65535), (args.bytes, 1, 1048576), (args.concurrency, 1, 128),
                             (args.operations, 1, 200000), (args.warmup, 0, 10000), (args.timeout_ms, 1, 60000),
                             (args.sequence, 0, 1 << 36)):
        if not low <= value <= high:
            raise ValueError("driver bounds")
    per_endpoint = 65536 // ((args.bytes + 15) // 16)
    reserved = sum(max(1, (args.operations // args.concurrency + (i < args.operations % args.concurrency)
                          + args.warmup + per_endpoint - 1) // per_endpoint) for i in range(args.concurrency))
    if reserved > 1024:
        raise ValueError("driver endpoint reservation exceeds 1024")
    context = Context(args.credentials, sequence=args.sequence) if args.security == SECURITY else None
    lock = threading.Lock()
    workers = [Worker(args, i, context, lock) for i in range(args.concurrency)]
    barrier = threading.Barrier(args.concurrency + 1)

    def work(worker):
        warmup_failed, failures, latencies, reasons = 0, 0, [], {}
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
        for _ in range(count):
            try:
                latencies.append(worker.exchange(sequence))
            except Exception as error:
                failures += 1
                label = type(error).__name__
                reasons[label] = reasons.get(label, 0) + 1
            sequence += 1
        return latencies, failures, warmup_failed, reasons

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = [pool.submit(work, worker) for worker in workers]
            barrier.wait()
            start = time.perf_counter_ns()
            barrier.wait()
            rows = [future.result() for future in futures]
            elapsed = time.perf_counter_ns() - start
        latencies = [n for row in rows for n in row[0]]
        failed, warmup_failed = sum(row[1] for row in rows), sum(row[2] for row in rows)
        reasons = {}
        for row in rows:
            for key, value in row[3].items():
                reasons[key] = reasons.get(key, 0) + value
        return dict(schema="coaptic-load/1", protocol="coap", security=args.security, mode=args.mode,
                    concurrency=args.concurrency, warmup=args.warmup, attempted=args.operations,
                    completed=len(latencies), failed=failed, warmup_failed=warmup_failed, driver_failures=reasons.get("DriverError", 0),
                    endpoint_rotations=sum(len(w.retired) for w in workers), verified_bytes=len(latencies) * args.bytes,
                    elapsed_ns=elapsed, latencies_ns=latencies, failure_types=reasons, clock="time.perf_counter_ns",
                    measurement="closed-loop; Python/GIL, authentication and complete byte validation included")
    finally:
        for worker in workers:
            worker.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "mode", "security", "credentials"):
        parser.add_argument("--" + name, required=True)
    for name in ("port", "bytes", "concurrency", "operations", "warmup", "timeout-ms", "sequence"):
        parser.add_argument("--" + name, type=int, required=True)
    args = parser.parse_args()
    if args.mode not in ("con", "non") or args.security not in ("plaintext", SECURITY):
        parser.error("unsupported mode/security")
    result = run(args)
    print(json.dumps(result, allow_nan=False))
    return int(bool(result["failed"] or result["warmup_failed"]))


if __name__ == "__main__":
    raise SystemExit(main())
