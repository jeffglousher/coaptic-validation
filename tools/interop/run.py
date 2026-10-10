import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from source_identity import source_identity

#!/usr/bin/env python3
"""Process interop runner. Cases live in capabilities.json."""
import argparse
import hashlib
import json
import math
import platform
import queue
import select
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from capabilities import load_manifest, evaluate

SCHEMA = "coaptic-peer/2"
BODY = b"core-test-payload"
LARGE = bytes(i % 251 for i in range(2000))
UPLOAD_4K = bytes(i % 251 for i in range(4096))


def port(family="ipv4"):
    with socket.socket(socket.AF_INET6 if family == "ipv6" else socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("::1" if family == "ipv6" else "127.0.0.1", 0))
        return sock.getsockname()[1]


def ipv6_probe(number):
    # Independent, hand-written CON GET /test proves the server is reachable
    # at ::1. A peer silently falling back to IPv4 cannot satisfy this probe.
    wire = b"\x41\x01\x76\x60\x8d\xb4test"
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind(("::1", 0))
        sock.settimeout(2)
        sock.sendto(wire, ("::1", number))
        reply, sender = sock.recvfrom(4096)
    if sender[0] != "::1" or sender[1] != number or reply[:5] != b"\x61\x45\x76\x60\x8d" or not reply.endswith(b"\xff" + BODY):
        raise AssertionError("IPv6 server probe response mismatch")
    return {"sender": sender, "request_hex": wire.hex(), "response_hex": reply.hex()}


def command(exe, role, transport, number, key="sesame", path="test", method="GET", timeout=6000, family="ipv4", payload=b"", sequence=None, qblock1=False, qblock2=False, observe=False, echo=False, replay=None, jsonpatch=False):
    result = [str(exe), role, transport, str(number), key, path, method, str(timeout), family, payload.hex()]
    if sequence is not None or qblock1 or qblock2 or observe or echo or replay is not None or jsonpatch:
        result.append("0" if sequence is None else str(sequence))
    if qblock1:
        result.append("qblock1")
    if qblock2:
        result.append("qblock2")
    if observe:
        result.append("observe")
    if echo:
        result.append("echo")
    if replay is not None:
        left, bits = replay
        result.append(f"replay:{left}:{bits}")
    if jsonpatch:
        result.append("jsonpatch")
    return result


def decode(line):
    if len(line) > 65536:
        raise RuntimeError("oversize peer event")
    value = json.loads(line)
    if value.get("schema") != SCHEMA:
        raise RuntimeError("peer schema mismatch")
    return value


class Server:
    def __init__(self, exe, transport, number=None, family="ipv4", echo=False, sequence=None, replay=None):
        self.number = number or port(family)
        self.stderr = tempfile.TemporaryFile()
        start = time.perf_counter_ns()
        self.proc = subprocess.Popen(
            command(exe, "server", transport, self.number, family=family, echo=echo, sequence=sequence, replay=replay),
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=self.stderr)
        events = queue.Queue(maxsize=1)
        def read_ready():
            try:
                events.put(self.proc.stdout.readline(65537))
            except Exception as error:
                events.put(error)
        self.reader = threading.Thread(target=read_ready, daemon=True)
        self.reader.start()
        try:
            line = events.get(timeout=8)
            if isinstance(line, Exception):
                raise line
            self.ready = decode(line)
            if self.ready.get("event") != "ready" or self.ready.get("port") != self.number or self.ready.get("transport") != transport:
                raise RuntimeError(f"server did not become ready: {self.ready}")
            if self.proc.poll() is not None:
                raise RuntimeError("server exited during readiness")
            self.startup_ms = (time.perf_counter_ns() - start) / 1_000_000
        except Exception:
            self.close()
            raise

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)
        self.reader.join(timeout=1)
        self.proc.stdout.close()
        self.stderr.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def request(exe, transport, number, **kwargs):
    start = time.perf_counter_ns()
    timeout = kwargs.get("timeout", 6000)
    try:
        result = subprocess.run(command(exe, "client", transport, number, **kwargs),
                                capture_output=True, timeout=timeout / 1000 + 4)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("peer exceeded process deadline (not a valid protocol timeout)") from error
    host_ns = time.perf_counter_ns() - start
    if len(result.stdout) > 65536:
        raise RuntimeError("oversize peer output")
    lines = result.stdout.splitlines()
    if len(lines) != 1:
        raise RuntimeError(f"expected one peer event, exit={result.returncode}, stderr={result.stderr[-2000:]!r}, stdout={result.stdout[:1000]!r}")
    event = decode(lines[0])
    event["host_total_ns"] = host_ns
    event["host_total_us"] = host_ns / 1000
    if result.returncode == 0:
        if event.get("event") != "response":
            raise RuntimeError("successful process without response")
        validate_timing(event)
    elif event.get("event") != "error":
        raise RuntimeError(f"peer crashed or contradicted response: {event}")
    event["exit_code"] = result.returncode
    return event


def expect_refusal(event, *, handshake=False):
    words = ("timeout", "timed out", "deadline", "elapsed")
    if handshake:
        words += ("handshake", "decrypt", "alert")
    if type(event.get("exit_code")) is not int or event["exit_code"] != 1 or event.get("event") != "error" or not any(
            word in event.get("message", "").lower() for word in words):
        raise AssertionError(f"not a bounded protocol refusal/timeout: {event}")


def validate_timing(event):
    # Reject bools, NaN, fractions, missing/old timing and malformed clock data.
    elapsed = event.get("elapsed_ns")
    clock = event.get("clock")
    if type(elapsed) is not int or not 0 <= elapsed <= 60_000_000_000:
        raise RuntimeError("invalid request nanosecond timing")
    if not isinstance(clock, dict) or not isinstance(clock.get("name"), str) or not clock["name"]:
        raise RuntimeError("missing request clock metadata")
    if "resolution_ns" not in clock:
        raise RuntimeError("missing clock resolution (null means unknown)")
    resolution = clock["resolution_ns"]
    if resolution is not None and (type(resolution) is not int or resolution <= 0):
        raise RuntimeError("invalid clock resolution")
    return elapsed


def expect(event, code=69, payload=BODY):
    if event["exit_code"] != 0 or event.get("code") != code:
        raise AssertionError(f"expected code {code}: {event}")
    if payload is not None and bytes.fromhex(event.get("payload_hex", "")) != payload:
        raise AssertionError(f"incorrect response body: {event}")


def packet_token(packet):
    if len(packet) < 4 or packet[0] >> 6 != 1 or (packet[0] & 15) > 8:
        return b""
    length = packet[0] & 15
    return packet[4:4 + length]


def shrink_qblock2_szx(packet, szx=4):
    """Ask the server for 256-byte blocks so one loss is a gap, not a missing tail."""
    if len(packet) < 5 or packet[0] >> 6 != 1 or (packet[0] & 15) > 8 or not 0 <= szx <= 6:
        return packet
    out = bytearray(packet)
    index = 4 + (out[0] & 15)
    number = 0
    while index < len(out) and out[index] != 0xFF:
        delta_nibble = out[index] >> 4
        length_nibble = out[index] & 15
        index += 1
        if delta_nibble == 15 or length_nibble == 15 or index > len(out):
            return packet
        delta, length = delta_nibble, length_nibble
        if delta_nibble == 13:
            if index >= len(out):
                return packet
            delta = out[index] + 13
            index += 1
        elif delta_nibble == 14:
            if index + 2 > len(out):
                return packet
            delta = int.from_bytes(out[index:index + 2], "big") + 269
            index += 2
        if length_nibble == 13:
            if index >= len(out):
                return packet
            length = out[index] + 13
            index += 1
        elif length_nibble == 14:
            if index + 2 > len(out):
                return packet
            length = int.from_bytes(out[index:index + 2], "big") + 269
            index += 2
        if index + length > len(out):
            return packet
        number += delta
        if number == 31 and length == 1:
            out[index] = (out[index] & 0xF8) | szx
        index += length
    return bytes(out)


def qblock2_content_num(packet):
    """NUM of a 2.05 that carries one Q-Block2 payload, else None."""
    if len(packet) < 5 or packet[0] >> 6 != 1 or packet[1] != 69:
        return None
    try:
        values = decoded_options(packet).get(31, [])
        if len(values) != 1 or not coap_payload(packet):
            return None
        num, _, _ = block1_fields(values[0])
    except (AssertionError, IndexError, ValueError):
        return None
    return num


def qblock2_requests_num(packet, num):
    if len(packet) < 5 or packet[0] >> 6 != 1 or packet[1] != 1:
        return False
    try:
        values = decoded_options(packet).get(31, [])
        return any(
            (got := block1_fields(value))[0] == num and not got[1] for value in values
        )
    except (AssertionError, IndexError, ValueError):
        return False


class Proxy:
    """One-client UDP relay, deterministic first-packet faults, bounded trace."""
    def __init__(self, dest, mode, family="ipv4", qblock2_szx=None):
        if family not in ("ipv4", "ipv6"):
            raise ValueError("unsupported proxy address family")
        address_family = socket.AF_INET6 if family == "ipv6" else socket.AF_INET
        address = "::1" if family == "ipv6" else "127.0.0.1"
        self.front = socket.socket(address_family, socket.SOCK_DGRAM)
        self.back = socket.socket(address_family, socket.SOCK_DGRAM)
        for endpoint in (self.front, self.back):
            if family == "ipv6":
                endpoint.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            endpoint.bind((address, 0))
        self.number = self.front.getsockname()[1]
        self.dest = (address, dest, 0, 0) if family == "ipv6" else (address, dest)
        self.mode, self.trace, self.error = mode, [], None
        self.qblock2_szx = qblock2_szx
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        client = None
        dropped = duplicated = False
        large_tokens = set()
        held_num = None
        release_held = False
        held_q0 = None
        q0_released = False
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([self.front, self.back], [], [], .02)
                for sock in ready:
                    try:
                        data, source = sock.recvfrom(65536)
                    except ConnectionResetError:
                        # Windows reports late ICMP port-unreachable when a
                        # one-shot client exits after the first duplicate reply.
                        if self.mode in ("duplicate-request", "dtls-reconnect", "drop-qblock2", "reorder-qblock2") and sock is self.front:
                            continue
                        raise
                    incoming = sock is self.front
                    if not incoming and source != self.dest:
                        raise RuntimeError("unexpected proxy upstream")
                    action = "forward"
                    if incoming:
                        if client is not None and source != client and self.mode != "dtls-reconnect":
                            raise RuntimeError("multiple clients in single-request fault proxy")
                        client = source
                    if self.mode == "corrupt-request" and incoming:
                        if not data:
                            raise RuntimeError("cannot corrupt an empty datagram")
                        action = "corrupt"
                    elif self.mode == "blackhole":
                        action = "drop"
                    elif self.mode == "drop-reply" and not incoming and not dropped:
                        action, dropped = "drop", True
                    elif self.mode == "delay-reply" and not incoming and not dropped:
                        action, dropped = "delay", True
                    elif self.mode == "duplicate-request" and incoming and not duplicated:
                        action, duplicated = "duplicate", True
                    elif self.mode == "drop-qblock2":
                        # Shrink the /large size hint, then drop block 1 until the client asks for it.
                        # Block 0 still arrives, so Size2 is seen. The probe token is left alone.
                        token = packet_token(data)
                        if incoming:
                            try:
                                if data[1:2] == b"\x01" and b"large" in decoded_options(data).get(11, []):
                                    large_tokens.add(token)
                            except (AssertionError, IndexError):
                                pass
                            if held_num is not None and qblock2_requests_num(data, held_num):
                                release_held = True
                        elif not release_held:
                            num = qblock2_content_num(data)
                            if num == 1 and token in large_tokens:
                                action = "drop"
                                held_num = num
                    elif self.mode == "reorder-qblock2":
                        # Hold /large Q-Block2 NUM 0 until a later payload of that transfer is forwarded.
                        token = packet_token(data)
                        if incoming:
                            try:
                                if data[1:2] == b"\x01" and b"large" in decoded_options(data).get(11, []):
                                    large_tokens.add(token)
                            except (AssertionError, IndexError):
                                pass
                        elif not q0_released and held_q0 is None and token in large_tokens and qblock2_content_num(data) == 0:
                            action = "hold"
                            held_q0 = data
                    if len(self.trace) >= (8192 if self.mode == "dtls-reconnect" else 256):
                        raise RuntimeError("proxy trace limit exceeded")
                    forwarded = data[:-1] + bytes([data[-1] ^ 0x80]) if action == "corrupt" else data
                    if self.mode == "drop-qblock2" and incoming and action == "forward" and packet_token(data) in large_tokens:
                        forwarded = shrink_qblock2_szx(data)
                    elif self.qblock2_szx is not None and incoming and action == "forward":
                        try:
                            if len(data) > 1 and data[1] == 1 and b"large" in decoded_options(data).get(11, []):
                                forwarded = shrink_qblock2_szx(data, self.qblock2_szx)
                        except (AssertionError, IndexError):
                            pass
                    self.trace.append({"direction": "request" if incoming else "response",
                                       "action": action, "hex": data.hex(), "forwarded_hex": forwarded.hex()})
                    if action == "delay":
                        time.sleep(0.25)
                    if action not in ("drop", "hold"):
                        target = self.back if incoming else self.front
                        address = self.dest if incoming else client
                        target.sendto(forwarded, address)
                        if action == "duplicate":
                            target.sendto(forwarded, address)
                        if (self.mode == "reorder-qblock2" and not incoming and held_q0 is not None
                                and packet_token(data) in large_tokens
                                and (later := qblock2_content_num(data)) is not None and later > 0):
                            self.trace.append({"direction": "response", "action": "release",
                                               "hex": held_q0.hex(), "forwarded_hex": held_q0.hex()})
                            target.sendto(held_q0, client)
                            held_q0 = None
                            q0_released = True
        except Exception as error:
            self.error = str(error)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=1)
        self.front.close()
        self.back.close()
        if self.thread.is_alive() or self.error:
            raise RuntimeError(f"proxy failed: {self.error}")


def delayed_reply(client, server):
    """Hold the first UDP response for 250 ms. The client still accepts /test."""
    with Server(server, "udp") as service:
        with Proxy(service.number, "delay-reply") as relay:
            event = request(client, "udp", relay.number, path="test")
        expect(event, 69, BODY)
        delayed = [row for row in relay.trace if row["action"] == "delay"]
        if len(delayed) != 1:
            raise AssertionError(f"response was not held once: {relay.trace}")
        if event["elapsed_ns"] < 150_000_000:
            raise AssertionError(f"held response arrived too quickly: {event['elapsed_ns']}")
    return {"delayed": 1, "elapsed_ns": event["elapsed_ns"]}


def expect_identical_requests(trace, require_repeat=False):
    requests = [row["hex"] for row in trace if row["direction"] == "request"]
    if len(requests) < (2 if require_repeat else 1) or len(set(requests)) != 1:
        raise AssertionError("missing or changed retransmitted request bytes")


def summary(samples):
    ordered = sorted(samples)
    return {"n": len(samples), "min": min(samples), "mean": statistics.mean(samples),
            "p50": ordered[math.ceil(.5 * len(samples)) - 1],
            "p95": ordered[math.ceil(.95 * len(samples)) - 1],
            "p99": ordered[math.ceil(.99 * len(samples)) - 1], "max": max(samples)}


def measure_requests(iterations, request_fn):
    samples, host, failures = [], [], []
    clock = None
    started = time.perf_counter_ns()
    for index in range(iterations):
        try:
            event = request_fn()
            expect(event)
            validate_timing(event)
            if type(event.get("host_total_ns")) is not int or event["host_total_ns"] < 0:
                raise RuntimeError("invalid host timing")
            if clock is not None and event["clock"] != clock:
                raise RuntimeError("request clock changed within benchmark")
            clock = event["clock"]
            samples.append(event["elapsed_ns"])
            host.append(event["host_total_ns"])
        except Exception as error:
            failures.append({"sample_index": index, "error": str(error)})
            break  # No retries or successful-sample substitution.
    wall_ns = time.perf_counter_ns() - started
    result = {"clock": clock, "requested_samples": iterations,
              "samples_ns": {"request": samples, "host_total": host},
              "failures": len(failures), "sample_failures": failures}
    if samples:
        result.update({"request_ns": summary(samples), "host_total_ns": summary(host),
                       "request_us": summary([n / 1000 for n in samples]),
                       "host_total_us": summary([n / 1000 for n in host])})
    if not failures:
        result["serial_host_requests_per_second"] = iterations * 1e9 / wall_ns
    return result


def replay_envelope(data):
    if len(data) < 5 or data[0] >> 6 != 1 or not 1 <= data[0] & 15 <= 8 or len(data) <= 4 + (data[0] & 15):
        raise AssertionError("missing token-bearing protected request bytes")
    replay = bytearray(data)
    replay[2] ^= 0x40
    replay[4] ^= 0x80
    return bytes(replay)


def oscore_fault_workflow(client, server):
    with Server(server, "oscore") as service:
        with Proxy(service.number, "dtls-reconnect") as relay:
            accepted = request(client, "oscore", relay.number, sequence=0, path="counter", method="POST")
            expect(accepted, 68, b"")
            expect(request(client, "oscore", service.number, sequence=10, path="counter"), 69, b"1")
            requests = [bytes.fromhex(row["hex"]) for row in relay.trace if row["direction"] == "request"]
            # Echo may cause one earlier challenged request. Replay the last
            # application request that actually produced the accepted POST.
            captured = next(wire for wire in reversed(requests) if len(wire) > 1 and wire[1] != 0)
            # RFC 8613 leaves outer MID/Token outside integrity protection.
            # Change both; preserve every option/ciphertext byte. Keep the
            # first relay bound so a new socket cannot reuse its source port.
            replay = replay_envelope(captured)
            accepted_source = relay.back.getsockname()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("127.0.0.1", 0))
                replay_source = sock.getsockname()
                if replay_source == accepted_source:
                    raise AssertionError("replay did not change source endpoint")
                sock.settimeout(.5)
                if sock.sendto(replay, ("127.0.0.1", service.number)) != len(replay):
                    raise AssertionError("replay datagram was not completely sent")
                try:
                    replay_reply = sock.recvfrom(4096)[0].hex()
                except socket.timeout:
                    replay_reply = None
        expect(request(client, "oscore", service.number, sequence=20, path="counter"), 69, b"1")
        # A forged far-future request cannot advance the recipient window.
        with Proxy(service.number, "corrupt-request") as corrupted:
            refused = request(client, "oscore", corrupted.number, sequence=1000,
                              path="counter", method="POST", timeout=500)
        expect_refusal(refused)
        if not any(row["action"] == "corrupt" and row["hex"] != row["forwarded_hex"] for row in corrupted.trace):
            raise AssertionError("authenticated corruption was not exercised")
        expect(request(client, "oscore", service.number, sequence=30, path="counter"), 69, b"1")
        expect(request(client, "oscore", service.number, sequence=1000, path="counter", method="POST"), 68, b"")
        final = request(client, "oscore", service.number, sequence=1100, path="counter")
        expect(final, 69, b"2")
        return {"accepted_trace": relay.trace, "accepted_source": accepted_source, "replay_source": replay_source, "replayed_hex": replay.hex(), "replay_reply_hex": replay_reply,
                "corrupted_trace": corrupted.trace, "refused": refused, "final": final}


def oscore_block2_workflow(client, server):
    evidence = []
    for mode in ("dtls-reconnect", "drop-reply", "duplicate-request"):
        with Server(server, "oscore") as service:
            # Complete any B.1.2 Echo challenge before the faulted transfer.
            expect(request(client, "oscore", service.number, sequence=0))
            with Proxy(service.number, mode) as relay:
                result = request(client, "oscore", relay.number, sequence=100,
                                 path="large", timeout=6500)
            expect(result, 69, LARGE)
            requests = [row for row in relay.trace if row["direction"] == "request"]
            if len(requests) < 2:
                raise AssertionError("large transfer did not exercise follow-up datagrams")
            if mode != "dtls-reconnect" and not any(row["action"] != "forward" for row in relay.trace):
                raise AssertionError("requested transfer fault was not exercised")
            refused = request(client, "oscore", service.number, sequence=1000,
                              path="large", key="incorrect", timeout=500)
            expect_refusal(refused)
            recovered = request(client, "oscore", service.number, sequence=1100, path="large")
            expect(recovered, 69, LARGE)
            evidence.append({"mode": mode, "result": result, "trace": relay.trace,
                             "wrong_key_refusal": refused, "recovered": recovered})
    return {"transfers": evidence, "expected_length": len(LARGE),
            "expected_sha256": hashlib.sha256(LARGE).hexdigest()}


def upload_workflow(client, server, transport="udp", family="ipv4"):
    """Exact Block1 bodies and one wrong byte, across one fresh server process."""
    changed = bytearray(LARGE)
    changed[-1] ^= 1

    def direct(**kwargs):
        if family != "ipv6":
            return request(client, transport, service.number, family=family, path="upload",
                           timeout=6500, **kwargs)
        with Proxy(service.number, "dtls-reconnect", family=family) as relay:
            result = request(client, transport, relay.number, family=family, path="upload",
                             timeout=6500, **kwargs)
        if not any(row["direction"] == "request" for row in relay.trace):
            raise AssertionError("no IPv6 request datagrams")
        return result

    def traced(payload):
        with Proxy(service.number, "dtls-reconnect", family=family) as relay:
            result = request(client, transport, relay.number, family=family, path="upload",
                             method="POST", payload=payload, timeout=6500)
            count = sum(row["direction"] == "request" for row in relay.trace)
        return result, count

    with Server(server, transport, family=family) as service:
        created, first_requests = traced(LARGE)
        expect(created, 65, b"")
        if first_requests < 2:
            raise AssertionError(f"2000-byte upload used {first_requests} request datagrams")
        expect(direct(), 69, b"1:1")
        refused = direct(method="POST", payload=bytes(changed))
        expect(refused, 128, b"")
        expect(direct(), 69, b"1:2")
        wide, wide_requests = traced(UPLOAD_4K)
        expect(wide, 65, b"")
        if wide_requests < 2:
            raise AssertionError(f"4096-byte upload used {wide_requests} request datagrams")
        readback = direct()
        expect(readback, 69, b"2:3")
        return {"transport": transport, "family": family,
                "lengths": [len(LARGE), len(UPLOAD_4K)],
                "sha256": {"2000": hashlib.sha256(LARGE).hexdigest(),
                           "4096": hashlib.sha256(UPLOAD_4K).hexdigest()},
                "request_datagrams": {"2000": first_requests, "4096": wide_requests},
                "wrong_byte": refused, "readback": readback}


CONTINUE = 95
INCOMPLETE = 136
TOO_LARGE = 141


def coap_option(delta, value):
    """One CoAP option. Delta and length use the RFC 7252 extended nibble form."""
    def field(n):
        if n < 13:
            return n, b""
        if n < 269:
            return 13, bytes([n - 13])
        if n < 65805:
            return 14, (n - 269).to_bytes(2, "big")
        raise ValueError("CoAP option field does not fit")
    delta_nibble, delta_ext = field(delta)
    length_nibble, length_ext = field(len(value))
    return bytes([(delta_nibble << 4) | length_nibble]) + delta_ext + length_ext + value


def coap_options(items):
    encoded = bytearray()
    previous = 0
    for number, value in items:
        if number < previous:
            raise ValueError("CoAP options are not in ascending order")
        encoded += coap_option(number - previous, value)
        previous = number
    return bytes(encoded)


def block1_value(num, more, szx):
    if not 0 <= num < 16 or not 0 <= szx <= 6:
        raise ValueError("Block1 value is outside the one-byte encoding")
    return bytes([(num << 4) | ((1 if more else 0) << 3) | szx])


def coap_message(code, mid, token, options, payload=b"", *, non=False):
    if not 0 < len(token) <= 8 or not 0 <= mid <= 0xFFFF or not 0 <= code <= 0xFF:
        raise ValueError("invalid CoAP header field")
    message = bytes([(0x50 if non else 0x40) | len(token), code, mid >> 8, mid & 0xFF]) + token + coap_options(options)
    if payload:
        message += b"\xff" + payload
    return message


def coap_payload(packet):
    if len(packet) < 4 or packet[0] >> 6 != 1 or (packet[0] & 15) > 8:
        raise AssertionError("not a CoAP datagram")
    index = 4 + (packet[0] & 15)
    while index < len(packet):
        if packet[index] == 0xFF:
            return packet[index + 1:]
        delta_nibble = packet[index] >> 4
        length_nibble = packet[index] & 15
        index += 1
        if delta_nibble == 15 or length_nibble == 15:
            raise AssertionError("malformed CoAP option")
        if delta_nibble == 13:
            delta_nibble = packet[index] + 13
            index += 1
        elif delta_nibble == 14:
            delta_nibble = int.from_bytes(packet[index:index + 2], "big") + 269
            index += 2
        if length_nibble == 13:
            length_nibble = packet[index] + 13
            index += 1
        elif length_nibble == 14:
            length_nibble = int.from_bytes(packet[index:index + 2], "big") + 269
            index += 2
        index += length_nibble
    return b""


def coap_roundtrip(sock, address, packet, timeout=2):
    """Send from one bound socket so Block1 identity stays on that endpoint."""
    sock.settimeout(timeout)
    if sock.sendto(packet, address) != len(packet):
        raise AssertionError("CoAP probe was not completely sent")
    try:
        data, sender = sock.recvfrom(4096)
    except (socket.timeout, ConnectionResetError) as error:
        raise AssertionError(f"no CoAP reply: {error}") from error
    if (sender[0], sender[1]) != address or ((data[0] >> 4) & 3) != 2:
        raise AssertionError(f"unexpected CoAP acknowledgement from {sender}")
    return data


def coap_exchange(sock, address, packet, timeout=2):
    data = coap_roundtrip(sock, address, packet, timeout)
    return data[1], coap_payload(data)


def decoded_options(packet):
    if len(packet) < 4 or packet[0] >> 6 != 1 or (packet[0] & 15) > 8:
        raise AssertionError("not a CoAP datagram")
    index = 4 + (packet[0] & 15)
    number = 0
    found = {}
    while index < len(packet) and packet[index] != 0xFF:
        delta_nibble = packet[index] >> 4
        length_nibble = packet[index] & 15
        index += 1
        if delta_nibble == 15 or length_nibble == 15 or index > len(packet):
            raise AssertionError("malformed CoAP option")
        delta, length = delta_nibble, length_nibble
        if delta_nibble == 13:
            delta = packet[index] + 13
            index += 1
        elif delta_nibble == 14:
            delta = int.from_bytes(packet[index:index + 2], "big") + 269
            index += 2
        if length_nibble == 13:
            length = packet[index] + 13
            index += 1
        elif length_nibble == 14:
            length = int.from_bytes(packet[index:index + 2], "big") + 269
            index += 2
        if index + length > len(packet):
            raise AssertionError("CoAP option exceeds the datagram")
        number += delta
        found.setdefault(number, []).append(packet[index:index + length])
        index += length
    return found


def block1_fields(value):
    if len(value) not in (1, 2, 3):
        raise AssertionError(f"Block1 length {len(value)} is outside 1..3")
    raw = int.from_bytes(value, "big")
    return raw >> 4, bool(raw & 8), raw & 7


def upload_block(mid, token, num, more, szx, payload, size1=None):
    options = [(11, b"upload"), (12, bytes([42])), (27, block1_value(num, more, szx))]
    if size1 is not None:
        encoded = size1.to_bytes(4, "big").lstrip(b"\x00") or b"\x00"
        options.append((60, encoded))
    return coap_message(2, mid, token, options, payload)


def block1_fault_workflow(server):
    """Independent Block1 refusals. The handler must stay cold."""
    pattern = bytes(i % 251 for i in range(1024))
    small = pattern[:64]

    def session(check):
        with Server(server, "udp") as service:
            address = ("127.0.0.1", service.number)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0))
            state = {"token": 1, "mid": 1}

            def fresh(token=None):
                state["mid"] = state["mid"] % 0xFFFF + 1
                if token is None:
                    state["token"] = state["token"] % 255 + 1
                    token = bytes([state["token"]])
                return state["mid"], token

            def post(token, num, more, szx, payload, size1=None):
                mid, _ = fresh(token)
                code, _ = coap_exchange(
                    sock, address, upload_block(mid, token, num, more, szx, payload, size1))
                return code

            def counts():
                mid, token = fresh()
                code, body = coap_exchange(
                    sock, address, coap_message(1, mid, token, [(11, b"upload")]))
                return code, body

            try:
                return check(post, counts)
            finally:
                sock.close()

    def ordered(post, counts):
        token = bytes([9])
        if post(token, 0, True, 2, small, size1=1) != CONTINUE:
            raise AssertionError("Size1 did not leave an unfinished block at 2.31")
        if counts() != (69, b"0:0"):
            raise AssertionError("Size1 completed or invoked the upload handler")
        if post(token, 0, True, 2, small) != CONTINUE:
            raise AssertionError("duplicate Block1 NUM was not replayed as 2.31")
        if post(token, 1, True, 2, small) != CONTINUE:
            raise AssertionError("duplicate Block1 NUM reset the transfer")
        if post(token, 3, True, 2, small) != INCOMPLETE:
            raise AssertionError("Block1 gap was not 4.08")
        if counts() != (69, b"0:0"):
            raise AssertionError("gap or duplicate invoked the upload handler")
        mismatched = bytes([10])
        if post(mismatched, 0, True, 2, small) != CONTINUE:
            raise AssertionError("initial SZX was refused")
        if post(mismatched, 1, True, 6, pattern) != INCOMPLETE:
            raise AssertionError("changed SZX was not 4.08")
        return counts()

    def overflow(post, counts):
        token = bytes([11])
        for num in range(4):
            if post(token, num, True, 6, pattern) != CONTINUE:
                raise AssertionError(f"block {num} of a 4096-byte body was refused early")
        if post(token, 4, True, 6, pattern) != TOO_LARGE:
            raise AssertionError("body past 4096 bytes was not 4.13")
        final = counts()
        if final != (69, b"0:0"):
            raise AssertionError(f"upload handler ran during refusal: {final}")
        return final

    session(ordered)
    final = session(overflow)
    return {"codes": {"continue": CONTINUE, "incomplete": INCOMPLETE, "too_large": TOO_LARGE},
            "body_limit": 4096, "final": {"code": final[0], "payload": final[1].decode()}}


def smaller_block_upload(server):
    """Client starts at 256-byte blocks and keeps that size through completion."""
    szx = 4
    size = 1 << (szx + 4)
    body = LARGE
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            offset = num = 0
            mid = 1
            while offset < len(body):
                chunk = body[offset:offset + size]
                more = offset + len(chunk) < len(body)
                mid += 1
                reply = coap_roundtrip(
                    sock, address, upload_block(mid, b"\x21", num, more, szx, chunk))
                echoed = decoded_options(reply).get(27, [])
                if more:
                    if len(echoed) != 1:
                        raise AssertionError(f"block {num} did not echo Block1: {echoed!r}")
                    echoed_num, _, echoed_szx = block1_fields(echoed[0])
                    if (echoed_num, echoed_szx) != (num, szx):
                        raise AssertionError(f"block {num} was not kept at SZX {szx}: {echoed!r}")
                elif len(echoed) == 1:
                    echoed_num, _, echoed_szx = block1_fields(echoed[0])
                    if (echoed_num, echoed_szx) != (num, szx):
                        raise AssertionError(f"final block echo changed size: {echoed!r}")
                elif echoed:
                    raise AssertionError(f"final block had repeated Block1: {echoed!r}")
                if reply[1] != (CONTINUE if more else 65):
                    raise AssertionError(f"block {num} returned {reply[1]}")
                offset += len(chunk)
                num += 1
            if num < 3:
                raise AssertionError(f"256-byte blocks did not split the body: {num}")
            code, counts = coap_exchange(
                sock, address, coap_message(1, mid + 1, b"\x22", [(11, b"upload")]))
        finally:
            sock.close()
    if (code, counts) != (69, b"1:1"):
        raise AssertionError(f"smaller blocks did not create the body once: {code} {counts!r}")
    return {"szx": szx, "block_bytes": size, "blocks": num, "length": len(body),
            "readback": counts.decode()}


def scaled_smaller_block(server):
    """RFC 7959 Figure 9 against one server: 64-byte block 0, then 16-byte block 4."""
    first = bytes(i % 251 for i in range(64))
    tail = bytes((64 + i) % 251 for i in range(16))
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            opened = coap_roundtrip(sock, address, upload_block(2, b"\x31", 0, True, 2, first))
            if opened[1] != CONTINUE:
                raise AssertionError(f"first 64-byte block returned {opened[1]}")
            skipped = coap_roundtrip(sock, address, upload_block(3, b"\x31", 1, True, 0, tail))
            if skipped[1] != INCOMPLETE:
                raise AssertionError(f"unaligned smaller block returned {skipped[1]}")
            code, counts = coap_exchange(
                sock, address, coap_message(1, 5, b"\x32", [(11, b"upload")]))
            if (code, counts) != (69, b"0:0"):
                raise AssertionError(f"unaligned block reached the handler: {code} {counts!r}")
            finished = coap_roundtrip(sock, address, upload_block(4, b"\x31", 4, False, 0, tail))
            if finished[1] != 128:
                raise AssertionError(f"scaled block did not reach the length check: {finished[1]}")
            code, counts = coap_exchange(
                sock, address, coap_message(1, 6, b"\x33", [(11, b"upload")]))
        finally:
            sock.close()
    if (code, counts) != (69, b"0:1"):
        raise AssertionError(f"scaled body was not delivered once: {code} {counts!r}")
    return {"first_bytes": 64, "next_num": 4, "next_bytes": 16, "readback": counts.decode()}


def qblock1_message(mid, token, num, more, szx, payload, size1, tag, non=False):
    encoded = size1.to_bytes(4, "big").lstrip(b"\x00") or b"\x00"
    options = [(11, b"upload"), (12, bytes([42])), (19, block1_value(num, more, szx)), (60, encoded)]
    if tag is not None:
        options.append((292, tag))
    return coap_message(2, mid, token, options, payload, non=non)


def await_datagram(sock, address, timeout):
    sock.settimeout(timeout)
    try:
        data, sender = sock.recvfrom(4096)
    except (socket.timeout, ConnectionResetError) as error:
        raise AssertionError(f"no CoAP reply: {error}") from error
    if (sender[0], sender[1]) != address or data[0] >> 6 != 1:
        raise AssertionError(f"unexpected datagram from {sender}")
    return data


def qblock1_upload(server):
    """One Coaptic Q-Block1 upload. Recovery and other peers stay out of this proof."""
    body = LARGE
    first, rest = body[:1024], body[1024:]
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            def post(mid, token, num, more, szx, payload, size1, tag):
                return coap_roundtrip(
                    sock, address, qblock1_message(mid, token, num, more, szx, payload, size1, tag))

            def counts(mid, token):
                return coap_exchange(
                    sock, address, coap_message(1, mid, token, [(11, b"upload")]))

            missing = post(2, b"\x41", 0, True, 6, first, len(body), None)
            if missing[1] != 128:
                raise AssertionError(f"missing Request-Tag returned {missing[1]}")
            if counts(3, b"\x51") != (69, b"0:0"):
                raise AssertionError("missing Request-Tag reached the upload handler")
            opened = post(4, b"\x42", 0, True, 6, first, len(body), b"a")
            if opened[1] != 0 or (opened[0] & 15) != 0 or len(opened) != 4:
                raise AssertionError(f"incomplete Q-Block1 was not an empty ACK: {opened!r}")
            changed = post(5, b"\x42", 1, False, 2, rest[:64], len(body), b"a")
            if changed[1] != INCOMPLETE:
                raise AssertionError(f"changed Q-Block1 size returned {changed[1]}")
            if counts(6, b"\x52") != (69, b"0:0"):
                raise AssertionError("changed Q-Block1 size reached the upload handler")
            if post(7, b"\x43", 0, True, 6, first, len(body), b"b")[1] != 0:
                raise AssertionError("exact Q-Block1 payload 0 was not acknowledged")
            created = post(8, b"\x43", 1, False, 6, rest, len(body), b"b")
            if created[1] != 65:
                raise AssertionError(f"exact Q-Block1 body returned {created[1]}")
            code, readback = counts(9, b"\x53")
        finally:
            sock.close()
    if (code, readback) != (69, b"1:1"):
        raise AssertionError(f"Q-Block1 body was not created once: {code} {readback!r}")
    return {"blocks": 2, "block_bytes": 1024, "length": len(body), "readback": readback.decode()}


def qblock1_missing(server):
    """A skipped NON Q-Block1 number is reported, then that payload is delivered once."""
    token = b"\x61"
    first = bytes(i % 251 for i in range(16))
    middle = bytes((16 + i) % 251 for i in range(16))
    tail = bytes((32 + i) % 251 for i in range(8))
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            def send(mid, num, more, payload):
                packet = qblock1_message(mid, token, num, more, 0, payload, 40, b"h", non=True)
                if sock.sendto(packet, address) != len(packet):
                    raise AssertionError("Q-Block1 probe was not completely sent")

            send(2, 0, True, first)
            send(3, 2, False, tail)
            report = await_datagram(sock, address, 6)
            if ((report[0] >> 4) & 3) != 1 or report[1] != INCOMPLETE or (report[0] & 15) != 1:
                raise AssertionError(f"hole was not a NON 4.08: {report!r}")
            if report[4:5] != token:
                raise AssertionError(f"4.08 token was not the request token: {report!r}")
            if decoded_options(report).get(12) != [bytes([1, 16])]:
                raise AssertionError("4.08 content format was not missing-blocks")
            if coap_payload(report) != b"\x01":
                raise AssertionError(f"4.08 did not name block 1: {coap_payload(report)!r}")
            if coap_exchange(sock, address, coap_message(1, 4, b"\x62", [(11, b"upload")])) != (69, b"0:0"):
                raise AssertionError("missing Q-Block1 payload reached the handler")
            filled = coap_roundtrip(
                sock, address, qblock1_message(5, token, 1, True, 0, middle, 40, b"h"))
            if filled[1] != 128:
                raise AssertionError(f"filled hole returned {filled[1]}")
            code, readback = coap_exchange(
                sock, address, coap_message(1, 6, b"\x63", [(11, b"upload")]))
        finally:
            sock.close()
    if (code, readback) != (69, b"0:1"):
        raise AssertionError(f"filled hole was not delivered once: {code} {readback!r}")
    return {"missing": 1, "reported_format": 272, "length": 40, "readback": readback.decode()}


def qblock1_window(server):
    """Ten NON Q-Block1 payloads draw one 2.31. The next payload is delivered once."""
    token = b"\x71"
    size1 = 168
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            def send_non(mid, num, payload, more):
                packet = qblock1_message(mid, token, num, more, 0, payload, size1, b"w", non=True)
                if sock.sendto(packet, address) != len(packet):
                    raise AssertionError("Q-Block1 probe was not completely sent")

            for num in range(9):
                send_non(2 + num, num, bytes((num * 16 + i) % 251 for i in range(16)), True)
            sock.settimeout(0.3)
            try:
                early, _sender = sock.recvfrom(4096)
            except socket.timeout:
                early = None
            if early is not None:
                raise AssertionError(f"Continue arrived before payload 9: {early!r}")
            send_non(11, 9, bytes((9 * 16 + i) % 251 for i in range(16)), True)
            continued = await_datagram(sock, address, 2)
            if ((continued[0] >> 4) & 3) != 1 or continued[1] != CONTINUE or (continued[0] & 15) != 1:
                raise AssertionError(f"full window was not a NON 2.31: {continued!r}")
            if continued[4:5] != token:
                raise AssertionError(f"2.31 token was not the request token: {continued!r}")
            if decoded_options(continued).get(19) != [b"\x98"]:
                raise AssertionError("2.31 did not echo Q-Block1 NUM 9, M=1, SZX 0")
            if coap_exchange(sock, address, coap_message(1, 12, b"\x72", [(11, b"upload")])) != (69, b"0:0"):
                raise AssertionError("the completed window reached the handler")
            finished = coap_roundtrip(
                sock, address,
                qblock1_message(13, token, 10, False, 0, bytes((160 + i) % 251 for i in range(8)), size1, b"w"))
            if finished[1] != 128:
                raise AssertionError(f"payload after the window returned {finished[1]}")
            code, readback = coap_exchange(
                sock, address, coap_message(1, 14, b"\x73", [(11, b"upload")]))
        finally:
            sock.close()
    if (code, readback) != (69, b"0:1"):
        raise AssertionError(f"payload after the window was not delivered once: {code} {readback!r}")
    return {"window": 10, "continue_num": 9, "length": size1, "readback": readback.decode()}


def oscore_qblock1_upload(client, server):
    """Protected Q-Block1 creates. libcoap has no Q-Block peer in this suite."""
    changed = bytearray(LARGE)
    changed[-1] ^= 1
    with Server(server, "oscore") as service:
        created = request(client, "oscore", service.number, sequence=0, path="upload", method="POST",
                          payload=LARGE, timeout=6500, qblock1=True)
        expect(created, 65, b"")
        expect(request(client, "oscore", service.number, sequence=100, path="upload"), 69, b"1:1")
        expect(request(client, "oscore", service.number, sequence=200, path="upload", method="POST",
                       payload=bytes(changed), timeout=6500, qblock1=True), 128, b"")
        expect(request(client, "oscore", service.number, sequence=300, path="upload"), 69, b"1:2")
        expect(request(client, "oscore", service.number, sequence=400, path="upload", method="POST",
                       payload=UPLOAD_4K, timeout=6500, qblock1=True), 65, b"")
        readback = request(client, "oscore", service.number, sequence=500, path="upload")
        expect(readback, 69, b"2:3")
        refused = request(client, "oscore", service.number, sequence=1000, path="upload", method="POST",
                          payload=LARGE, key="incorrect", timeout=500, qblock1=True)
        expect_refusal(refused)
        preserved = request(client, "oscore", service.number, sequence=1100, path="upload")
        expect(preserved, 69, b"2:3")
    return {"readback": preserved, "wrong_key": refused}


def oscore_qblock1_faults(client, server):
    """Lost first reply and a duplicated request during one protected Q-Block1 upload."""
    evidence = []
    for mode in ("dtls-reconnect", "drop-reply", "duplicate-request"):
        with Server(server, "oscore") as service:
            with Proxy(service.number, mode) as relay:
                created = request(client, "oscore", relay.number, sequence=100, path="upload",
                                  method="POST", payload=LARGE, timeout=6500, qblock1=True)
            expect(created, 65, b"")
            requests = [row for row in relay.trace if row["direction"] == "request"]
            if len(requests) < 2:
                raise AssertionError("protected Q-Block1 upload did not send a follow-up")
            if mode != "dtls-reconnect" and not any(row["action"] != "forward" for row in relay.trace):
                raise AssertionError("requested Q-Block1 fault was not exercised")
            expect(request(client, "oscore", service.number, sequence=200, path="upload"), 69, b"1:1")
            refused = request(client, "oscore", service.number, sequence=1000, path="upload",
                              method="POST", payload=LARGE, key="incorrect", timeout=500, qblock1=True)
            expect_refusal(refused)
            preserved = request(client, "oscore", service.number, sequence=1100, path="upload")
            expect(preserved, 69, b"1:1")
            evidence.append({"mode": mode, "requests": len(requests)})
    return {"transfers": evidence}


def no_response_counter(server):
    """NON POST with No-Response 2.xx still increments the counter and sends nothing."""
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            def counts(mid, token):
                return coap_exchange(
                    sock, address, coap_message(1, mid, token, [(11, b"counter")]))

            if counts(2, b"\x81") != (69, b"0"):
                raise AssertionError("counter did not start at 0")
            suppressed = coap_message(2, 3, b"\x82", [(11, b"counter"), (258, b"\x02")], non=True)
            if sock.sendto(suppressed, address) != len(suppressed):
                raise AssertionError("No-Response POST was not completely sent")
            sock.settimeout(0.3)
            try:
                early, _sender = sock.recvfrom(4096)
            except socket.timeout:
                early = None
            if early is not None:
                raise AssertionError(f"suppressed 2.04 was sent: {early!r}")
            if counts(4, b"\x83") != (69, b"1"):
                raise AssertionError("suppressed POST did not increment the counter")
            visible = coap_roundtrip(sock, address, coap_message(2, 5, b"\x84", [(11, b"counter")]))
            if visible[1] != 68:
                raise AssertionError(f"visible POST returned {visible[1]}")
            code, body = counts(6, b"\x85")
        finally:
            sock.close()
    if (code, body) != (69, b"2"):
        raise AssertionError(f"counter did not reach 2: {code} {body!r}")
    return {"readback": body.decode()}


def concurrent_counter(server, first, second):
    """Two clients POST /counter at once. The following GET is 2."""
    with Server(server, "udp") as service:
        replies = []
        errors = []

        def post(exe):
            try:
                replies.append(request(exe, "udp", service.number, path="counter", method="POST"))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=post, args=(exe,)) for exe in (first, second)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        if errors:
            raise errors[0]
        for reply in replies:
            expect(reply, 68, b"")
        readback = request(first, "udp", service.number, path="counter")
        expect(readback, 69, b"2")
    return {"posts": len(replies), "readback": "2"}


def no_response_not_found(server):
    """NON GET /missing with No-Response 4.xx sends nothing. Without it, the code is 4.04."""
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            visible = coap_roundtrip(
                sock, address, coap_message(1, 2, b"\x91", [(11, b"missing")]))
            if visible[1] != 132:
                raise AssertionError(f"missing path returned {visible[1]}")
            suppressed = coap_message(1, 3, b"\x92", [(11, b"missing"), (258, bytes([8]))], non=True)
            if sock.sendto(suppressed, address) != len(suppressed):
                raise AssertionError("No-Response GET was not completely sent")
            sock.settimeout(0.3)
            try:
                early, _sender = sock.recvfrom(4096)
            except socket.timeout:
                early = None
            if early is not None:
                raise AssertionError(f"suppressed 4.04 was sent: {early!r}")
        finally:
            sock.close()
    return {"visible": 132}


def discovery(server):
    """GET /.well-known/core lists the registered routes."""
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            reply = coap_roundtrip(
                sock, address,
                coap_message(1, 2, b"\x93", [(11, b".well-known"), (11, b"core")]))
        finally:
            sock.close()
    if reply[1] != 69:
        raise AssertionError(f"discovery returned {reply[1]}")
    if decoded_options(reply).get(12) != [bytes([40])]:
        raise AssertionError("discovery content format was not link-format")
    body = coap_payload(reply).decode()
    for path in ("/test", "/large", "/counter", "/upload", "/methods", "/separate", "/fail", "/cond"):
        if f"<{path}>" not in body:
            raise AssertionError(f"discovery omitted {path}: {body}")
    if ".well-known" in body:
        raise AssertionError(f"discovery listed itself: {body}")
    return {"links": body}


def separate_response(server):
    """GET /separate is an empty ACK, then a confirmable 2.05."""
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            request = coap_message(1, 0x21, b"\xa1", [(11, b"separate")])
            if sock.sendto(request, address) != len(request):
                raise AssertionError("separate GET was not completely sent")
            ack = await_datagram(sock, address, 2)
            if len(ack) != 4 or ack[1] != 0 or ((ack[0] >> 4) & 3) != 2 or int.from_bytes(ack[2:4], "big") != 0x21:
                raise AssertionError(f"separate response did not start with an empty ACK: {ack!r}")
            con = await_datagram(sock, address, 2)
            if ((con[0] >> 4) & 3) != 0 or con[1] != 69 or coap_payload(con) != b"separate-payload":
                raise AssertionError(f"separate CON was not 2.05 separate-payload: {con!r}")
            if con[2:4] == request[2:4] or con[4:4 + (con[0] & 15)] != b"\xa1":
                raise AssertionError("separate response MID/Token binding mismatch")
            mid = int.from_bytes(con[2:4], "big")
            empty = bytes([0x60, 0, mid >> 8, mid & 0xFF])
            if sock.sendto(empty, address) != len(empty):
                raise AssertionError("ACK of the separate CON was not completely sent")
        finally:
            sock.close()
    return {"ack_mid": 0x21, "payload": "separate-payload"}


def no_response_internal(server):
    """GET /fail is 5.00. NON with No-Response 5.xx sends nothing."""
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            visible = coap_roundtrip(
                sock, address, coap_message(1, 2, b"\x9a", [(11, b"fail")]))
            if visible[1] != 160:
                raise AssertionError(f"/fail returned {visible[1]}")
            suppressed = coap_message(1, 3, b"\x9b", [(11, b"fail"), (258, bytes([16]))], non=True)
            if sock.sendto(suppressed, address) != len(suppressed):
                raise AssertionError("No-Response GET was not completely sent")
            sock.settimeout(0.3)
            try:
                early, _sender = sock.recvfrom(4096)
            except socket.timeout:
                early = None
            if early is not None:
                raise AssertionError(f"suppressed 5.00 was sent: {early!r}")
        finally:
            sock.close()
    return {"visible": 160}


def observe_counter(server):
    """RFC 7641 against /counter: register, two notifications, deregister, then RST cancel.

    A NON notification stays outstanding for 3 s (section 4.5.1), so the
    second notification may arrive after that hold.
    """
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        watcher = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        writer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        watcher.bind(("127.0.0.1", 0))
        writer.bind(("127.0.0.1", 0))
        mids = iter(range(0x40, 0x100))
        try:
            def observe_value(packet):
                values = decoded_options(packet).get(6, [])
                if len(values) != 1:
                    raise AssertionError(f"expected one Observe option: {values!r}")
                return int.from_bytes(values[0], "big")

            def register(token):
                reply = coap_roundtrip(
                    watcher, address, coap_message(1, next(mids), token, [(6, b""), (11, b"counter")]))
                if reply[1] != 69 or reply[4:4 + len(token)] != token:
                    raise AssertionError(f"registration was not 2.05 on the token: {reply!r}")
                return observe_value(reply), coap_payload(reply)

            def post():
                if coap_roundtrip(writer, address,
                                  coap_message(2, next(mids), b"\xb0", [(11, b"counter")]))[1] != 68:
                    raise AssertionError("counter POST was not 2.04")

            def notification(token):
                note = await_datagram(watcher, address, 5)
                kind = (note[0] >> 4) & 3
                if kind not in (0, 1) or note[1] != 69 or note[4:4 + len(token)] != token:
                    raise AssertionError(f"not a 2.05 notification on the token: {note!r}")
                if kind == 0:
                    watcher.sendto(bytes([0x60, 0]) + note[2:4], address)
                return note, observe_value(note), coap_payload(note)

            def silent():
                watcher.settimeout(0.5)
                try:
                    stray, _sender = watcher.recvfrom(4096)
                except socket.timeout:
                    return
                raise AssertionError(f"notification after cancel: {stray!r}")

            first_seq, first_body = register(b"\xb1")
            if first_body != b"0":
                raise AssertionError(f"registration body was {first_body!r}")
            post()
            _, second_seq, second_body = notification(b"\xb1")
            post()
            _, third_seq, third_body = notification(b"\xb1")
            if (second_body, third_body) != (b"1", b"2"):
                raise AssertionError(f"notification bodies were {second_body!r} {third_body!r}")
            if not first_seq < second_seq < third_seq:
                raise AssertionError(f"Observe did not increase: {first_seq} {second_seq} {third_seq}")

            leave = coap_roundtrip(
                watcher, address, coap_message(1, next(mids), b"\xb1", [(6, b"\x01"), (11, b"counter")]))
            if leave[1] != 69 or 6 in decoded_options(leave):
                raise AssertionError(f"deregistration was not a plain 2.05: {leave!r}")
            post()
            silent()

            register(b"\xb2")
            post()
            note, _, body = notification(b"\xb2")
            if body != b"4":
                raise AssertionError(f"notification after re-register was {body!r}")
            watcher.sendto(bytes([0x70, 0]) + note[2:4], address)
            post()
            silent()

            code, value = coap_exchange(writer, address, coap_message(1, next(mids), b"\xb3", [(11, b"counter")]))
        finally:
            watcher.close()
            writer.close()
    if (code, value) != (69, b"5"):
        raise AssertionError(f"counter did not reach 5: {code} {value!r}")
    return {"observe": [first_seq, second_seq, third_seq], "final": value.decode()}


def observe_client(client, server, writer):
    """The client observes /counter through a relay and prints three bodies."""
    def wait_responses(relay, count, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if sum(row["direction"] == "response" for row in relay.trace) >= count:
                return
            time.sleep(0.02)
        raise AssertionError(f"relay saw fewer than {count} responses")

    with Server(server, "udp") as service:
        with Proxy(service.number, "dtls-reconnect") as relay:
            proc = subprocess.Popen(
                command(client, "client", "udp", relay.number, path="counter", timeout=15000, observe=True),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                wait_responses(relay, 1, 8)
                expect(request(writer, "udp", service.number, path="counter", method="POST"), 68, b"")
                wait_responses(relay, 2, 8)
                expect(request(writer, "udp", service.number, path="counter", method="POST"), 68, b"")
                out, err = proc.communicate(timeout=20)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
            trace = relay.trace
    lines = out.splitlines()
    if len(lines) != 1:
        raise RuntimeError(f"expected one observe event: {out[:400]!r} {err[-400:]!r}")
    event = decode(lines[0])
    event["exit_code"] = proc.returncode
    expect(event, 69, b"0,1,2")
    return {"responses": sum(row["direction"] == "response" for row in trace), "bodies": "0,1,2"}


def observe_protected(client, server, writer, transport, ready=1):
    """Observe /counter over OSCORE or DTLS. Two POSTs produce bodies 0, 1 and 2."""
    def wait_responses(relay, count, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if sum(row["direction"] == "response" for row in relay.trace) >= count:
                return
            time.sleep(0.02)
        raise AssertionError(f"relay saw fewer than {count} responses")

    def dtls_app_data(relay):
        return sum(row["direction"] == "response" and row["hex"].startswith("17") for row in relay.trace)

    def wait_dtls(relay, count, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if dtls_app_data(relay) >= count:
                return
            time.sleep(0.02)
        raise AssertionError(f"relay saw fewer than {count} DTLS application records")

    with Server(server, transport) as service:
        with Proxy(service.number, "dtls-reconnect") as relay:
            proc = subprocess.Popen(
                command(client, "client", transport, relay.number, path="counter", timeout=15000, observe=True),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                if transport == "dtls":
                    wait_dtls(relay, ready, 12)
                else:
                    wait_responses(relay, ready, 12)
                expect(request(writer, transport, service.number, path="counter", method="POST",
                               sequence=100 if transport == "oscore" else None), 68, b"")
                if transport == "dtls":
                    wait_dtls(relay, ready + 1, 8)
                else:
                    wait_responses(relay, ready + 1, 8)
                expect(request(writer, transport, service.number, path="counter", method="POST",
                               sequence=200 if transport == "oscore" else None), 68, b"")
                out, err = proc.communicate(timeout=20)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
            trace = relay.trace
    lines = out.splitlines()
    if len(lines) != 1:
        raise RuntimeError(f"expected one observe event: {out[:400]!r} {err[-400:]!r}")
    event = decode(lines[0])
    event["exit_code"] = proc.returncode
    expect(event, 69, b"0,1,2")
    return {"transport": transport, "responses": sum(row["direction"] == "response" for row in trace), "bodies": "0,1,2"}


def oscore_server_echo(client, server):
    """The Coaptic server challenges the first OSCORE request. The retry is the one that changes state."""
    with Server(server, "oscore", echo=True) as service:
        posted = request(client, "oscore", service.number, sequence=0, path="counter", method="POST")
        expect(posted, 68, b"")
        if posted.get("echo_retries") != 1:
            raise AssertionError(f"server Echo was not retried once: {posted}")
        readback = request(client, "oscore", service.number, sequence=100, path="counter")
        expect(readback, 69, b"1")
        if readback.get("echo_retries") != 1:
            raise AssertionError(f"readback was not challenged: {readback}")
    return {"echo_retries": 1, "readback": "1"}


def oscore_replay_restore(client, server):
    """RFC 8613 section 7.5: a restarted server restores the recipient window and the next sender sequence.

    Accepting client sequence 0 marks bit 0 of a fresh window. The next process
    starts at sender sequence 1 with that checkpoint. Sequence 0 is refused.
    Sequence 1 is accepted.
    """
    with Server(server, "oscore") as service:
        expect(request(client, "oscore", service.number, sequence=0, path="counter"), 69, b"0")
    with Server(server, "oscore", sequence=1, replay=(0, 1)) as service:
        refused = request(client, "oscore", service.number, sequence=0, path="counter", timeout=500)
        expect_refusal(refused)
        expect(request(client, "oscore", service.number, sequence=1, path="counter"), 69, b"0")
    return {"restored": "0:1", "sender_seq": 1, "refused_sequence": 0}


def concurrent_oscore_servers(client, server):
    """Two OSCORE server processes stay up together. Each process is one App and one replay window.

    Client sequence 0 is accepted by both. Repeating sequence 0 is refused by each
    window, and sequence 1 is then accepted by both.
    """
    with Server(server, "oscore") as left, Server(server, "oscore") as right:
        if left.number == right.number or left.proc.pid == right.proc.pid:
            raise AssertionError("OSCORE servers did not start as two processes")
        if left.proc.poll() is not None or right.proc.poll() is not None:
            raise AssertionError("an OSCORE server exited before the exchanges")
        replies = []
        errors = []

        def exchange(service):
            try:
                replies.append(request(client, "oscore", service.number, sequence=0, path="counter"))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=exchange, args=(service,)) for service in (left, right)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        if errors:
            raise errors[0]
        if len(replies) != 2:
            raise AssertionError(f"expected two OSCORE responses, got {len(replies)}")
        for reply in replies:
            expect(reply, 69, b"0")
        if left.proc.poll() is not None or right.proc.poll() is not None:
            raise AssertionError("an OSCORE server exited during sequence 0")
        for service in (left, right):
            expect_refusal(request(
                client, "oscore", service.number, sequence=0, path="counter", timeout=500))
        for service in (left, right):
            expect(request(client, "oscore", service.number, sequence=1, path="counter"), 69, b"0")
        if left.proc.poll() is not None or right.proc.poll() is not None:
            raise AssertionError("an OSCORE server exited during sequence 1")
        return {
            "ports": [left.number, right.number],
            "pids": [left.proc.pid, right.proc.pid],
            "sequence0": "2.05,2.05",
            "replay_sequence0": "refused,refused",
            "sequence1": "2.05,2.05",
        }


def observe_values(client, server, writer):
    """The client observes /counter. PUT replaces the representation; the client prints 0,1,2."""
    def wait_responses(relay, count, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if sum(row["direction"] == "response" for row in relay.trace) >= count:
                return
            time.sleep(0.02)
        raise AssertionError(f"relay saw fewer than {count} responses")

    with Server(server, "udp") as service:
        expect(request(writer, "udp", service.number, path="counter", method="PUT", payload=b"0"), 68, b"")
        with Proxy(service.number, "dtls-reconnect") as relay:
            proc = subprocess.Popen(
                command(client, "client", "udp", relay.number, path="counter", timeout=15000, observe=True),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                wait_responses(relay, 1, 8)
                expect(request(writer, "udp", service.number, path="counter", method="PUT", payload=b"1"), 68, b"")
                wait_responses(relay, 2, 8)
                expect(request(writer, "udp", service.number, path="counter", method="PUT", payload=b"2"), 68, b"")
                out, err = proc.communicate(timeout=20)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
            trace = relay.trace
    lines = out.splitlines()
    if len(lines) != 1:
        raise RuntimeError(f"expected one observe event: {out[:400]!r} {err[-400:]!r}")
    event = decode(lines[0])
    event["exit_code"] = proc.returncode
    expect(event, 69, b"0,1,2")
    return {"responses": sum(row["direction"] == "response" for row in trace), "bodies": "0,1,2"}


def merge_patch(client, server):
    """RFC 8132 merge-patch on /patch. Content-format 52 replaces or deletes the one decimal member."""
    with Server(server, "udp") as service:
        expect(request(client, "udp", service.number, path="patch"), 69, b'{"n":0}')
        expect(request(client, "udp", service.number, path="patch", method="PATCH",
                       payload=b'{"n":1}'), 68, b"")
        expect(request(client, "udp", service.number, path="patch"), 69, b'{"n":1}')
        address = ("127.0.0.1", service.number)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            refused = coap_roundtrip(sock, address, coap_message(
                6, 0x71, b"\xc3", [(11, b"patch"), (12, bytes([42]))], b'{"n":2}'))
            if refused[1] != 143:
                raise AssertionError(f"octet-stream PATCH returned {refused[1]}")
            shown = coap_roundtrip(sock, address, coap_message(1, 0x72, b"\xc4", [(11, b"patch")]))
            if shown[1] != 69 or coap_payload(shown) != b'{"n":1}':
                raise AssertionError(f"GET /patch returned {shown[1]} {coap_payload(shown)!r}")
            formats = decoded_options(shown).get(12, [])
            if formats != [bytes([50])]:
                raise AssertionError(f"GET /patch content-format was {formats!r}")
        expect(request(client, "udp", service.number, path="patch", method="PATCH",
                       payload=b'{"n":null}'), 68, b"")
        expect(request(client, "udp", service.number, path="patch"), 132, b"")
    return {"replaced": "1", "deleted": True, "refused_format": 42}


def json_patch(client, server):
    """RFC 8132 JSON Patch on /patch. Content-format 51 may replace or remove /n."""
    replace = b'[{"op":"replace","path":"/n","value":3}]'
    remove = b'[{"op":"remove","path":"/n"}]'
    with Server(server, "udp") as service:
        expect(request(client, "udp", service.number, path="patch"), 69, b'{"n":0}')
        expect(request(client, "udp", service.number, path="patch", method="PATCH",
                       payload=replace, jsonpatch=True), 68, b"")
        expect(request(client, "udp", service.number, path="patch"), 69, b'{"n":3}')
        address = ("127.0.0.1", service.number)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            refused = coap_roundtrip(sock, address, coap_message(
                6, 0x81, b"\xc5", [(11, b"patch"), (12, bytes([51]))], b'{"n":1}'))
            if refused[1] != 128:
                raise AssertionError(f"merge document at content-format 51 returned {refused[1]}")
            shown = coap_roundtrip(sock, address, coap_message(1, 0x82, b"\xc6", [(11, b"patch")]))
            if shown[1] != 69 or coap_payload(shown) != b'{"n":3}':
                raise AssertionError(f"GET /patch returned {shown[1]} {coap_payload(shown)!r}")
        expect(request(client, "udp", service.number, path="patch", method="PATCH",
                       payload=remove, jsonpatch=True), 68, b"")
        expect(request(client, "udp", service.number, path="patch"), 132, b"")
        expect(request(client, "udp", service.number, path="patch", method="PATCH",
                       payload=replace, jsonpatch=True), 132, b"")
    return {"replaced": "3", "removed": True}


def conditional_workflow(server):
    """RFC 7252 section 5.10.8 on /cond. A failed condition is 4.12 and changes nothing."""
    IF_MATCH, ETAG, IF_NONE_MATCH = 1, 4, 5
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        mids = iter(range(0x60, 0x100))
        steps = []
        try:
            def send(code, conditions=(), payload=b""):
                options = sorted(list(conditions) + [(11, b"cond")])
                reply = coap_roundtrip(sock, address,
                                       coap_message(code, next(mids), b"\xc1", options, payload))
                return reply[1], coap_payload(reply), decoded_options(reply).get(ETAG, [])

            def step(label, code, conditions, payload, want):
                got = send(code, conditions, payload)[0]
                steps.append((label, got))
                if got != want:
                    raise AssertionError(f"{label} returned {got}, expected {want}")

            def read(want_body, want_etag):
                got = send(1)
                if want_body is None:
                    if got[0] != 132:
                        raise AssertionError(f"GET /cond returned {got[0]}, expected 4.04")
                elif got[:2] != (69, want_body) or got[2] != [want_etag]:
                    raise AssertionError(f"GET /cond returned {got!r}")

            read(None, None)
            step("PUT If-Match empty on a missing resource", 3, [(IF_MATCH, b"")], b"a", 140)
            read(None, None)
            step("PUT If-None-Match on a missing resource", 3, [(IF_NONE_MATCH, b"")], b"a", 65)
            step("PUT If-None-Match on an existing resource", 3, [(IF_NONE_MATCH, b"")], b"b", 140)
            read(b"a", b"\x01")
            step("PUT If-Match with a stale ETag", 3, [(IF_MATCH, b"\x09")], b"c", 140)
            read(b"a", b"\x01")
            step("PUT If-Match with the current ETag", 3, [(IF_MATCH, b"\x01")], b"c", 68)
            read(b"c", b"\x02")
            step("DELETE If-Match with the old ETag", 4, [(IF_MATCH, b"\x01")], b"", 140)
            read(b"c", b"\x02")
            step("DELETE If-Match with the current ETag", 4, [(IF_MATCH, b"\x02")], b"", 66)
            read(None, None)
        finally:
            sock.close()
    return {"steps": steps}


def separate_client(client, server, timeout=6000):
    """The client reads /separate through a relay: empty ACK, then a confirmable 2.05 it acknowledges."""
    with Server(server, "udp") as service:
        with Proxy(service.number, "dtls-reconnect") as relay:
            result = request(client, "udp", relay.number, path="separate", timeout=timeout)
        trace = relay.trace
    expect(result, 69, b"separate-payload")
    return grade_separate_trace(trace)


def grade_separate_trace(trace):
    def packet(row):
        wire = bytes.fromhex(row["hex"])
        if len(wire) < 4 or wire[0] >> 6 != 1 or (wire[0] & 15) > 8 or len(wire) < 4 + (wire[0] & 15):
            raise AssertionError("malformed separate-response trace packet")
        return wire
    responses = [packet(row) for row in trace if row["direction"] == "response"]
    requests = [packet(row) for row in trace if row["direction"] == "request"]
    registrations = [p for p in requests if len(p) >= 4 and p[1] == 1 and (p[0] >> 4) & 3 == 0]
    if not registrations:
        raise AssertionError("no confirmable request")
    registration = registrations[0]
    if not responses or len(responses[0]) != 4 or responses[0][1] != 0 or (responses[0][0] >> 4) & 3 != 2:
        raise AssertionError(f"first response was not an empty ACK: {responses[:1]!r}")
    if responses[0][2:4] != registration[2:4]:
        raise AssertionError("empty ACK did not bind the request MID")
    later = [p for p in responses[1:] if (p[0] >> 4) & 3 == 0 and p[1] == 69]
    if not later:
        raise AssertionError("no confirmable 2.05 followed the empty ACK")
    token = registration[4:4 + (registration[0] & 15)]
    response = later[0]
    if response[2:4] == registration[2:4] or response[4:4 + (response[0] & 15)] != token:
        raise AssertionError("separate response MID/Token binding mismatch")
    if coap_payload(response) != b"separate-payload":
        raise AssertionError("separate response payload mismatch")
    acked = later[0][2:4]
    if not any(len(p) == 4 and p[1] == 0 and (p[0] >> 4) & 3 == 2 and p[2:4] == acked for p in requests):
        raise AssertionError("the client did not acknowledge the separate response")
    return {"responses": len(responses), "requests": len(requests), "trace": trace}


def qblock2_interop(client, server):
    """Q-Block2 GET of the 2000-byte pattern through a relay. The body is reassembled from the wire."""
    with Server(server, "udp") as service:
        with Proxy(service.number, "dtls-reconnect") as relay:
            result = request(client, "udp", relay.number, path="large", timeout=12000, qblock2=True)
        trace = relay.trace
    expect(result, 69, LARGE)
    requests = [bytes.fromhex(row["hex"]) for row in trace if row["direction"] == "request"]
    responses = [bytes.fromhex(row["hex"]) for row in trace if row["direction"] == "response"]
    downloads = []
    for packet in requests:
        if len(packet) <= 4 or packet[0] >> 6 != 1 or packet[1] != 1:
            continue
        if b"large" in decoded_options(packet).get(11, []):
            downloads.append(packet)
    if not downloads or any(31 not in decoded_options(packet) for packet in downloads):
        raise AssertionError("the download did not use Q-Block2 on every /large GET")
    if any(23 in decoded_options(packet) for packet in downloads):
        raise AssertionError("the download fell back to Block2")

    def token_of(packet):
        length = packet[0] & 15
        return packet[4:4 + length]

    # libcoap's Q-Block probe is a separate GET /.well-known/core. Its token is not an application token.
    large_tokens = {token_of(packet) for packet in downloads}
    blocks = []
    for packet in responses:
        if len(packet) <= 4 or packet[1] != 69 or token_of(packet) not in large_tokens:
            continue
        options = decoded_options(packet)
        if 23 in options:
            raise AssertionError("a response used Block2")
        if 31 in options:
            blocks.append(packet)
    if len(blocks) < 2:
        raise AssertionError("the 2000-byte body was not split across Q-Block2 responses")
    parts = {}
    etag = szx = None
    for packet in blocks:
        values = decoded_options(packet).get(31, [])
        if len(values) != 1:
            raise AssertionError(f"Q-Block2 count was {len(values)}")
        num, more, this_szx = block1_fields(values[0])
        if szx is None:
            szx = this_szx
        elif szx != this_szx:
            raise AssertionError(f"Q-Block2 SZX changed from {szx} to {this_szx}")
        payload = coap_payload(packet)
        size = 1 << (szx + 4)
        if more and len(payload) != size or not more and len(payload) > size:
            raise AssertionError(f"block {num} length {len(payload)} does not match SZX {szx}")
        previous = parts.get(num)
        if previous is not None and previous != payload:
            raise AssertionError(f"duplicate Q-Block2 {num} differed")
        parts[num] = payload
        tags = decoded_options(packet).get(4, [])
        if len(tags) != 1 or not tags[0]:
            raise AssertionError(f"block {num} had no ETag")
        if etag is None:
            etag = tags[0]
        elif etag != tags[0]:
            raise AssertionError("Q-Block2 responses did not share one ETag")
    if not parts or sorted(parts) != list(range(max(parts) + 1)):
        raise AssertionError(f"Q-Block2 numbers are not contiguous: {sorted(parts)}")
    if b"".join(parts[i] for i in range(max(parts) + 1)) != LARGE:
        raise AssertionError("wire Q-Block2 payloads are not the 2000-byte pattern")
    if "peer-coaptic" in Path(server).name:
        acks = [p for p in responses if len(p) == 4 and p[1] == 0 and (p[0] >> 4) & 3 == 2]
        if not acks:
            raise AssertionError("confirmable Q-Block2 did not get an empty ACK")
        if any((p[0] >> 4) & 3 != 1 for p in blocks):
            raise AssertionError("Q-Block2 payload was piggybacked on an ACK")
    return {"gets": len(downloads), "blocks": len(blocks), "szx": szx, "length": len(LARGE)}


def qblock2_reorder(client, server):
    """RFC 9177: deliver Q-Block2 NUM 1 before NUM 0. The body is still the 2000-byte pattern."""
    with Server(server, "udp") as service:
        with Proxy(service.number, "reorder-qblock2") as relay:
            result = request(client, "udp", relay.number, path="large", timeout=12000, qblock2=True)
        trace = relay.trace
    expect(result, 69, LARGE)
    large = set()
    for row in trace:
        if row["direction"] != "request":
            continue
        packet = bytes.fromhex(row["hex"])
        try:
            if packet[1:2] == b"\x01" and b"large" in decoded_options(packet).get(11, []):
                large.add(packet_token(packet))
        except (AssertionError, IndexError):
            pass
    nums = []
    for row in trace:
        if row["direction"] != "response" or row["action"] == "hold":
            continue
        packet = bytes.fromhex(row["forwarded_hex"])
        if packet_token(packet) not in large:
            continue
        num = qblock2_content_num(packet)
        if num is not None:
            nums.append(num)
    if not nums or nums[0] != 1 or 0 not in nums[1:]:
        raise AssertionError(f"Q-Block2 was not delivered 1 then 0: {nums}")
    return {"order": nums}


def qblock2_missing(client, server):
    """Drop one later Q-Block2 payload. The client asks for that block and the body completes."""
    with Server(server, "udp") as service:
        with Proxy(service.number, "drop-qblock2") as relay:
            result = request(client, "udp", relay.number, path="large", timeout=20000, qblock2=True)
        trace = relay.trace
    expect(result, 69, LARGE)
    dropped = [row for row in trace if row["action"] == "drop"]
    nums = []
    for row in dropped:
        num = qblock2_content_num(bytes.fromhex(row["hex"]))
        if num != 1:
            raise AssertionError(f"dropped datagram was not Q-Block2 block 1: {row['hex']}")
        nums.append(num)
    if len(set(nums)) != 1:
        raise AssertionError(f"dropped Q-Block2 numbers were {nums}")
    missing = nums[0]
    downloads = []
    for row in trace:
        if row["direction"] != "request":
            continue
        packet = bytes.fromhex(row["hex"])
        if len(packet) > 4 and packet[1] == 1 and b"large" in decoded_options(packet).get(11, []):
            downloads.append(packet)
    if not downloads or any(31 not in decoded_options(packet) for packet in downloads):
        raise AssertionError("the download did not use Q-Block2 on every /large GET")
    if any(23 in decoded_options(packet) for packet in downloads):
        raise AssertionError("the download fell back to Block2")
    large_tokens = {packet_token(packet) for packet in downloads}
    recovers = []
    recover_at = None
    for index, row in enumerate(trace):
        if row["direction"] != "request":
            continue
        packet = bytes.fromhex(row["hex"])
        if packet_token(packet) not in large_tokens or not qblock2_requests_num(packet, missing):
            continue
        parsed = [block1_fields(value) for value in decoded_options(packet).get(31, [])]
        recovers.append(parsed)
        if recover_at is None:
            recover_at = index
    if not recovers or recover_at is None:
        raise AssertionError(f"client did not request missing Q-Block2 {missing}")
    for parsed in recovers:
        asked = [num for num, _, _ in parsed]
        if asked != [missing]:
            raise AssertionError(f"recovery asked for {asked}")
        if any(more for _, more, _ in parsed):
            raise AssertionError("recovery set the M bit")
    drop_at = next(i for i, row in enumerate(trace) if row["action"] == "drop")
    if drop_at > recover_at:
        raise AssertionError("recovery request was not after the dropped payload")
    if not any(
        qblock2_content_num(bytes.fromhex(row["hex"])) not in (None, 0, missing)
        and packet_token(bytes.fromhex(row["hex"])) in large_tokens
        for row in trace[:recover_at]
        if row["direction"] == "response" and row["action"] != "drop"
    ):
        raise AssertionError("no higher Q-Block2 block arrived before the recovery request")
    parts = {}
    etag = None
    resent = False
    for index, row in enumerate(trace):
        if row["direction"] != "response" or row["action"] == "drop":
            continue
        packet = bytes.fromhex(row["hex"])
        if packet_token(packet) not in large_tokens or packet[1:2] != b"\x45":
            continue
        if 23 in decoded_options(packet):
            raise AssertionError("a response used Block2")
        values = decoded_options(packet).get(31, [])
        if len(values) != 1:
            continue
        num, _, _ = block1_fields(values[0])
        payload = coap_payload(packet)
        previous = parts.get(num)
        if previous is not None and previous != payload:
            raise AssertionError(f"duplicate Q-Block2 {num} differed")
        parts[num] = payload
        tags = decoded_options(packet).get(4, [])
        if len(tags) != 1 or not tags[0]:
            raise AssertionError(f"block {num} had no ETag")
        if etag is None:
            etag = tags[0]
        elif etag != tags[0]:
            raise AssertionError("Q-Block2 responses did not share one ETag")
        if num == missing and index > recover_at:
            resent = True
    if not resent:
        raise AssertionError("the missing block was not delivered after the recovery request")
    if sorted(parts) != list(range(max(parts) + 1)):
        raise AssertionError(f"Q-Block2 numbers are not contiguous: {sorted(parts)}")
    if b"".join(parts[i] for i in range(max(parts) + 1)) != LARGE:
        raise AssertionError("forwarded Q-Block2 payloads are not the 2000-byte pattern")
    if "peer-coaptic" in Path(server).name:
        acks = [bytes.fromhex(row["hex"]) for row in trace
                if row["direction"] == "response" and row["action"] == "forward"]
        if not any(len(p) == 4 and p[1] == 0 and (p[0] >> 4) & 3 == 2 for p in acks):
            raise AssertionError("confirmable Q-Block2 did not get an empty ACK")
    return {"missing": missing, "drops": len(dropped), "length": len(LARGE)}


def qblock2_window(client, server):
    """RFC 9177 section 4.4: a full window of 10 is confirmed with Q-Block2 NUM 10, M=1."""
    with Server(server, "udp") as service:
        with Proxy(service.number, "dtls-reconnect", qblock2_szx=3) as relay:
            result = request(client, "udp", relay.number, path="large", timeout=20000, qblock2=True)
        trace = relay.trace
    expect(result, 69, LARGE)
    downloads = []
    for row in trace:
        if row["direction"] != "request":
            continue
        packet = bytes.fromhex(row["hex"])
        if len(packet) > 4 and packet[1] == 1 and b"large" in decoded_options(packet).get(11, []):
            downloads.append((row, packet))
    if not downloads or any(31 not in decoded_options(packet) for _, packet in downloads):
        raise AssertionError("the download did not use Q-Block2 on every /large GET")
    if any(23 in decoded_options(packet) for _, packet in downloads):
        raise AssertionError("the download fell back to Block2")
    continues = []
    continue_at = None
    for index, row in enumerate(trace):
        if row["direction"] != "request":
            continue
        packet = bytes.fromhex(row["hex"])
        if len(packet) <= 4 or packet[1] != 1 or b"large" not in decoded_options(packet).get(11, []):
            continue
        parsed = [block1_fields(value) for value in decoded_options(packet).get(31, [])]
        if any(num == 10 and more for num, more, _ in parsed):
            continues.append(parsed)
            if continue_at is None:
                continue_at = index
    if not continues or continue_at is None:
        raise AssertionError("the client did not send Continue at Q-Block2 NUM 10")
    for parsed in continues:
        if parsed != [(10, True, 3)]:
            raise AssertionError(f"Continue was {parsed}")
    large_tokens = {packet_token(packet) for _, packet in downloads}
    before = 0
    for row in trace[:continue_at]:
        if row["direction"] != "response":
            continue
        packet = bytes.fromhex(row["hex"])
        num = qblock2_content_num(packet)
        if num is not None and packet_token(packet) in large_tokens:
            before += 1
    if before < 10:
        raise AssertionError(f"only {before} Q-Block2 payloads arrived before Continue")
    parts = {}
    etag = None
    for row in trace:
        if row["direction"] != "response":
            continue
        packet = bytes.fromhex(row["hex"])
        if packet_token(packet) not in large_tokens or len(packet) < 2 or packet[1] != 69:
            continue
        values = decoded_options(packet).get(31, [])
        if len(values) != 1:
            continue
        num, _, szx = block1_fields(values[0])
        if szx != 3:
            raise AssertionError(f"block {num} SZX was {szx}")
        payload = coap_payload(packet)
        previous = parts.get(num)
        if previous is not None and previous != payload:
            raise AssertionError(f"duplicate Q-Block2 {num} differed")
        parts[num] = payload
        tags = decoded_options(packet).get(4, [])
        if len(tags) != 1 or not tags[0]:
            raise AssertionError(f"block {num} had no ETag")
        if etag is None:
            etag = tags[0]
        elif etag != tags[0]:
            raise AssertionError("Q-Block2 responses did not share one ETag")
    if 10 not in parts:
        raise AssertionError("block 10 was not delivered after Continue")
    if sorted(parts) != list(range(max(parts) + 1)):
        raise AssertionError(f"Q-Block2 numbers are not contiguous: {sorted(parts)}")
    if b"".join(parts[i] for i in range(max(parts) + 1)) != LARGE:
        raise AssertionError("forwarded Q-Block2 payloads are not the 2000-byte pattern")
    if "peer-coaptic" in Path(server).name:
        acks = [bytes.fromhex(row["hex"]) for row in trace if row["direction"] == "response"]
        if not any(len(p) == 4 and p[1] == 0 and (p[0] >> 4) & 3 == 2 for p in acks):
            raise AssertionError("confirmable Q-Block2 did not get an empty ACK")
    return {"continue_num": 10, "blocks": len(parts), "length": len(LARGE)}


def qblock1_interop(client, server):
    """Q-Block1 POST of the 2000-byte pattern through a relay, then readback 1:1."""
    with Server(server, "udp") as service:
        with Proxy(service.number, "dtls-reconnect") as relay:
            created = request(client, "udp", relay.number, path="upload", method="POST",
                              payload=LARGE, timeout=12000, qblock1=True)
        requests = [bytes.fromhex(row["hex"]) for row in relay.trace if row["direction"] == "request"]
        expect(created, 65, b"")
        readback = request(client, "udp", service.number, path="upload")
        expect(readback, 69, b"1:1")
    uploads = [packet for packet in requests if len(packet) > 1 and packet[1] == 2]
    if len(uploads) < 2 or any(19 not in decoded_options(packet) for packet in uploads):
        raise AssertionError("the upload did not use Q-Block1 on every POST datagram")
    if any(27 in decoded_options(packet) for packet in uploads):
        raise AssertionError("the upload fell back to Block1")
    return {"post_datagrams": len(uploads), "readback": "1:1"}


def empty_request_tag(server):
    """A missing Request-Tag is 4.00. An empty Request-Tag is accepted and the handler runs once."""
    payload = bytes(range(16))
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            def post(mid, token, tag):
                return coap_roundtrip(
                    sock, address, qblock1_message(mid, token, 0, False, 0, payload, 16, tag))

            def counts(mid, token):
                return coap_exchange(
                    sock, address, coap_message(1, mid, token, [(11, b"upload")]))

            missing = post(2, b"\x96", None)
            if missing[1] != 128:
                raise AssertionError(f"missing Request-Tag returned {missing[1]}")
            if counts(3, b"\x97") != (69, b"0:0"):
                raise AssertionError("missing Request-Tag reached the handler")
            accepted = post(4, b"\x98", b"")
            if accepted[1] != 128:
                raise AssertionError(f"empty Request-Tag returned {accepted[1]}")
            code, readback = counts(5, b"\x99")
        finally:
            sock.close()
    if (code, readback) != (69, b"0:1"):
        raise AssertionError(f"empty Request-Tag was not delivered once: {code} {readback!r}")
    return {"readback": readback.decode()}


def problem_details_mix(server):
    """Block1 and Q-Block1 in one packet are 4.02 problem details. The handler stays cold."""
    block = block1_value(0, True, 0)
    payload = bytes(range(16))
    options = [
        (11, b"upload"),
        (12, bytes([42])),
        (19, block),
        (27, block),
        (60, bytes([16])),
        (292, b"m"),
    ]
    with Server(server, "udp") as service:
        address = ("127.0.0.1", service.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            reply = coap_roundtrip(sock, address, coap_message(2, 2, b"\x94", options, payload))
            if reply[1] != 130:
                raise AssertionError(f"mixed Block and Q-Block returned {reply[1]}")
            if decoded_options(reply).get(12) != [bytes([1, 1])]:
                raise AssertionError("4.02 content format was not problem details")
            if not coap_payload(reply):
                raise AssertionError("4.02 problem details body was empty")
            code, counts = coap_exchange(
                sock, address, coap_message(1, 3, b"\x95", [(11, b"upload")]))
        finally:
            sock.close()
    if (code, counts) != (69, b"0:0"):
        raise AssertionError(f"mixed options reached the handler: {code} {counts!r}")
    return {"code": 130, "readback": counts.decode()}


def oscore_upload_workflow(client, server):
    """Exact protected uploads. Each fresh client process has its own sender sequence."""
    changed = bytearray(LARGE)
    changed[-1] ^= 1
    with Server(server, "oscore") as service:
        expect(request(client, "oscore", service.number, sequence=0))
        created = request(client, "oscore", service.number, sequence=100, path="upload",
                          method="POST", payload=LARGE, timeout=6500)
        expect(created, 65, b"")
        expect(request(client, "oscore", service.number, sequence=200, path="upload"), 69, b"1:1")
        expect(request(client, "oscore", service.number, sequence=300, path="upload", method="POST",
                       payload=bytes(changed), timeout=6500), 128, b"")
        expect(request(client, "oscore", service.number, sequence=400, path="upload"), 69, b"1:2")
        expect(request(client, "oscore", service.number, sequence=500, path="upload", method="POST",
                       payload=UPLOAD_4K, timeout=6500), 65, b"")
        readback = request(client, "oscore", service.number, sequence=700, path="upload")
        expect(readback, 69, b"2:3")
        refused = request(client, "oscore", service.number, sequence=1000, path="upload",
                          method="POST", payload=LARGE, key="incorrect", timeout=500)
        expect_refusal(refused)
        preserved = request(client, "oscore", service.number, sequence=1100, path="upload")
        expect(preserved, 69, b"2:3")
        return {"sha256": {"2000": hashlib.sha256(LARGE).hexdigest(),
                           "4096": hashlib.sha256(UPLOAD_4K).hexdigest()},
                "wrong_key": refused, "readback": readback}


def oscore_upload_fault_workflow(client, server):
    """Lost first reply and duplicated request during one protected Block1 upload."""
    evidence = []
    for mode in ("dtls-reconnect", "drop-reply", "duplicate-request"):
        with Server(server, "oscore") as service:
            expect(request(client, "oscore", service.number, sequence=0))
            with Proxy(service.number, mode) as relay:
                created = request(client, "oscore", relay.number, sequence=100, path="upload",
                                  method="POST", payload=LARGE, timeout=6500)
            expect(created, 65, b"")
            requests = [row for row in relay.trace if row["direction"] == "request"]
            if len(requests) < 2:
                raise AssertionError("protected upload did not exercise follow-up datagrams")
            if mode != "dtls-reconnect" and not any(row["action"] != "forward" for row in relay.trace):
                raise AssertionError("requested upload fault was not exercised")
            expect(request(client, "oscore", service.number, sequence=200, path="upload"), 69, b"1:1")
            refused = request(client, "oscore", service.number, sequence=1000, path="upload",
                              method="POST", payload=LARGE, key="incorrect", timeout=500)
            expect_refusal(refused)
            preserved = request(client, "oscore", service.number, sequence=1100, path="upload")
            expect(preserved, 69, b"1:1")
            evidence.append({"mode": mode, "created": created, "trace": relay.trace,
                             "wrong_key_refusal": refused, "preserved": preserved})
    return {"expected_length": len(LARGE), "expected_sha256": hashlib.sha256(LARGE).hexdigest(),
            "transfers": evidence}


def ipv6_dtls_request(client, number, traces, **kwargs):
    # Each session has a fresh server-visible endpoint; IPv6-only sockets
    # prevent a fixture silently falling back to IPv4 from satisfying the case.
    with Proxy(number, "dtls-reconnect", family="ipv6") as relay:
        result = request(client, "dtls", relay.number, family="ipv6", **kwargs)
    if not any(row["direction"] == "request" for row in relay.trace):
        raise AssertionError("no IPv6 request datagrams")
    traces.append(relay.trace)
    return result


def method_workflow(client, server, transport="udp", family="ipv4"):
    """Literal byte/state oracles; private binary patch syntax, no JSON Patch claim."""
    steps = [
        ("GET", b"", 132, b""),
        ("PUT", b"alpha", 65, b""), ("GET", b"", 69, b"alpha"),
        ("PUT", b"a", 68, b""), ("GET", b"", 69, b"a"),
        ("POST", b"b", 68, b""), ("GET", b"", 69, b"ab"),
        ("PATCH", b"+c", 68, b""), ("GET", b"", 69, b"abc"),
        ("PATCH", b"+c", 68, b""), ("GET", b"", 69, b"abcc"),
        ("IPATCH", b"=final", 68, b""), ("GET", b"", 69, b"final"),
        ("IPATCH", b"=final", 68, b""), ("GET", b"", 69, b"final"),
        ("FETCH", b"value", 69, b"final"),
        ("FETCH", b"wrong", 128, None), ("GET", b"", 69, b"final"),
        ("PATCH", b"wrong", 128, None), ("GET", b"", 69, b"final"),
        ("IPATCH", b"wrong", 128, None), ("GET", b"", 69, b"final"),
        ("PUT", b"x" * 65, 141, None), ("GET", b"", 69, b"final"),
        ("POST", b"x" * 60, 141, None), ("GET", b"", 69, b"final"),
        ("DELETE", b"", 66, b""), ("GET", b"", 132, None),
        ("DELETE", b"", 132, None),
    ]
    evidence, traces = [], []
    with Server(server, transport, family=family) as service:
        probe = ipv6_probe(service.number) if family == "ipv6" and transport == "udp" else None
        def exchange(**kwargs):
            if family == "ipv6" and transport == "dtls":
                return ipv6_dtls_request(client, service.number, traces, **kwargs)
            return request(client, transport, service.number, family=family, **kwargs)
        refusal = None
        for index, (method, payload, code, body) in enumerate(steps):
            if transport == "dtls" and index == 2:
                # A refused replacement must leave the accepted PUT intact.
                refusal = exchange(path="methods",
                                  method="PUT", payload=b"poison", key="incorrect", timeout=1500)
                expect_refusal(refusal, handshake=True)
            result = exchange(path="methods", method=method, payload=payload)
            expect(result, code, body)
            evidence.append({"method": method, "request_hex": payload.hex(), "expected_code": code,
                             "expected_payload_hex": None if body is None else body.hex(), "response": result})
    return {"steps": evidence, "transport": transport, "address_family": family,
            "ipv6_socket_probe": probe, "ipv6_dtls_traces": traces, "wrong_key_result": refusal, "state_limit_bytes": 64, "patch_format": "fixture octet-stream: PATCH +suffix; IPATCH =replacement"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--libcoap-oscore-unavailable", action="store_true", help="Explicitly exclude C-peer OSCORE for this build")
    parser.add_argument("--coaptic", required=True, type=Path)
    parser.add_argument("--coap-rs", required=True, type=Path)
    parser.add_argument("--libcoap", required=True, type=Path)
    parser.add_argument("--libcoap-udp-only", action="store_true", help="Explicit local build limitation, recorded in results; CI requires DTLS")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--build-note", default="")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 10000:
        parser.error("iterations must be 1..10000")
    peers = {"coaptic": args.coaptic.resolve(), "coap-rs": args.coap_rs.resolve(), "libcoap": args.libcoap.resolve()}
    manifest, manifest_hash = load_manifest()
    report = {"schema": "coaptic-process-interop/2", "platform": platform.platform(),
              **source_identity(),
              "iterations": args.iterations, "build_note": args.build_note, "timing_scope": "request_us excludes process startup; host_total_us includes it",
              "host_clock": {"name": time.get_clock_info("perf_counter").implementation, "resolution_ns": math.ceil(time.get_clock_info("perf_counter").resolution * 1e9)},
              "libcoap_source": "851533c3cf63d16984d370ce39d586ecb3694971",
              "limitations": [],
              "executables": {n: {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for n,p in peers.items()},
              "capability_manifest": {"path": "tools/interop/capabilities.json", "sha256": manifest_hash},
              "cases": [], "benchmarks": []}
    if args.libcoap_udp_only:
        report["limitations"].append("libcoap DTLS and OSCORE excluded")

    def case(name, function):
        try:
            detail = function()
            report["cases"].append({"name": name, "passed": True, "evidence": detail})
            print(f"PASS {name}", flush=True)
        except Exception as error:
            report["cases"].append({"name": name, "passed": False, "error": str(error)})
            print(f"FAIL {name}: {error}", flush=True)

    for client, server in [("coaptic", "coaptic"), ("coaptic", "libcoap"), ("libcoap", "coaptic")]:
        if (args.libcoap_udp_only or args.libcoap_oscore_unavailable) and "libcoap" in (client, server):
            continue
        def oscore_state(client=client, server=server):
            with Server(peers[server], "oscore") as service:
                traces, results = [], []
                sequence = 0
                def exchange(**kwargs):
                    nonlocal sequence
                    with Proxy(service.number, "dtls-reconnect") as relay:
                        result = request(peers[client], "oscore", relay.number, sequence=sequence, **kwargs)
                    sequence += 100
                    if not relay.trace:
                        raise AssertionError("OSCORE exchange had no wire evidence")
                    traces.append(relay.trace)
                    results.append(result)
                    return result
                initial = exchange()
                expect(initial)
                if client == "coaptic" and server == "libcoap" and initial.get("echo_retries") != 1:
                    raise AssertionError("libcoap authenticated Echo challenge was not exercised exactly once")
                expect(exchange(path="methods", method="PUT", payload=b"alpha"), 65, b"")
                refused = exchange(path="methods", method="PUT", payload=b"poison", key="incorrect", timeout=1500)
                expect_refusal(refused)
                expect(exchange(path="methods"), 69, b"alpha")
                plain = request(peers[client], "udp", service.number, path="methods", method="PUT", payload=b"poison")
                expect(plain, 129, None)
                expect(exchange(path="methods"), 69, b"alpha")
                return {"server": service.ready, "traces": traces, "results": results, "plaintext_refusal": plain,
                        "fixture_context": "RFC 8613 C.1; client sequences 0,100,200,300,400"}
        case(f"oscore-state:{client}->{server}", oscore_state)

    for client, server in [("coaptic", "coaptic"), ("coaptic", "libcoap"), ("libcoap", "coaptic")]:
        if (args.libcoap_udp_only or args.libcoap_oscore_unavailable) and "libcoap" in (client, server):
            continue
        case(f"oscore-faults:{client}->{server}",
             lambda client=client, server=server: oscore_fault_workflow(peers[client], peers[server]))
        case(f"oscore-block2:{client}->{server}",
             lambda client=client, server=server: oscore_block2_workflow(peers[client], peers[server]))

    for transport in ("udp", "dtls"):
        pairs = [("coaptic", "coaptic"), ("coaptic", "coap-rs"), ("coap-rs", "coaptic"), ("coaptic", "libcoap"), ("libcoap", "coaptic")]
        for client, server in pairs:
            if transport == "dtls" and args.libcoap_udp_only and "libcoap" in (client, server):
                continue
            label = f"{transport}:{client}->{server}"
            def matrix(client=client, server=server, transport=transport, label=label):
                with Server(peers[server], transport) as service:
                    # Warm-up is an actual request; JSON readiness alone does not prove service health.
                    expect(request(peers[client], transport, service.number))
                    expect(request(peers[client], transport, service.number, path="missing"), 132, None)
                    expect(request(peers[client], transport, service.number, path="large"), 69, LARGE)
                    measured = measure_requests(args.iterations,
                        lambda: request(peers[client], transport, service.number))
                    report["benchmarks"].append({"pair": label, "server": service.ready,
                        "startup_ms": service.startup_ms, **measured})
                    if measured["failures"]:
                        raise AssertionError(f"request measurement failed: {measured['sample_failures']}")
                    if transport == "dtls":
                        refused = request(peers[client], transport, service.number, key="incorrect", timeout=1500)
                        expect_refusal(refused, handshake=True)
                        # A failed handshake must not destroy availability.
                        expect(request(peers[client], transport, service.number))
                    return {"server": service.ready}
            case(label, matrix)

    for transport, family, label in (("udp", "ipv4", "methods-udp"),
                                     ("dtls", "ipv4", "methods-dtls"),
                                     ("udp", "ipv6", "methods-ipv6-udp"),
                                     ("dtls", "ipv6", "methods-ipv6-dtls")):
        for client, server in [("coaptic", "coaptic"), ("coaptic", "coap-rs"), ("coap-rs", "coaptic"), ("coaptic", "libcoap"), ("libcoap", "coaptic")]:
            if transport == "dtls" and args.libcoap_udp_only and "libcoap" in (client, server):
                continue
            case(f"{label}:{client}->{server}",
                 lambda client=client, server=server, transport=transport, family=family:
                 method_workflow(peers[client], peers[server], transport, family))

    for client, server in [("coaptic", "coaptic"), ("coaptic", "coap-rs"), ("coap-rs", "coaptic"), ("coaptic", "libcoap"), ("libcoap", "coaptic")]:
        def ipv6_matrix(client=client, server=server):
            with Server(peers[server], "udp", family="ipv6") as service:
                probe = ipv6_probe(service.number)
                expect(request(peers[client], "udp", service.number, family="ipv6"))
                expect(request(peers[client], "udp", service.number, family="ipv6", path="missing"), 132, None)
                expect(request(peers[client], "udp", service.number, family="ipv6", path="large"), 69, LARGE)
                expect(request(peers[client], "udp", service.number, family="ipv6"))
                return {"server": service.ready, "address": "::1", "ipv6_socket_probe": probe}
        case(f"ipv6-udp:{client}->{server}", ipv6_matrix)

    for client, server in [("coaptic", "coaptic"), ("coaptic", "coap-rs"), ("coap-rs", "coaptic"), ("coaptic", "libcoap"), ("libcoap", "coaptic")]:
        if args.libcoap_udp_only and "libcoap" in (client, server):
            continue
        def ipv6_dtls(client=client, server=server):
            with Server(peers[server], "dtls", family="ipv6") as service:
                traces = []
                def exchange(**kwargs):
                    return ipv6_dtls_request(peers[client], service.number, traces, **kwargs)
                expect(exchange())
                expect(exchange(path="missing"), 132, None)
                expect(exchange(path="large"), 69, LARGE)
                refused = exchange(key="incorrect", timeout=1500)
                expect_refusal(refused, handshake=True)
                expect(exchange())
                return {"server": service.ready, "address": "::1", "relay_family": "AF_INET6",
                        "ipv6_only": True, "traces": traces, "wrong_key_result": refused}
        case(f"ipv6-dtls:{client}->{server}", ipv6_dtls)

    for transport, family, label in (("udp", "ipv4", "upload-udp"),
                                     ("dtls", "ipv4", "upload-dtls"),
                                     ("udp", "ipv6", "upload-ipv6-udp"),
                                     ("dtls", "ipv6", "upload-ipv6-dtls")):
        for client, server in [("coaptic", "coaptic"), ("coaptic", "coap-rs"), ("coap-rs", "coaptic"),
                               ("coaptic", "libcoap"), ("libcoap", "coaptic")]:
            if transport == "dtls" and args.libcoap_udp_only and "libcoap" in (client, server):
                continue
            case(f"{label}:{client}->{server}",
                 lambda client=client, server=server, transport=transport, family=family:
                 upload_workflow(peers[client], peers[server], transport, family))

    case("block1-faults:coaptic", lambda: block1_fault_workflow(peers["coaptic"]))
    case("block1-scaled:coaptic", lambda: scaled_smaller_block(peers["coaptic"]))
    case("qblock1-upload:coaptic", lambda: qblock1_upload(peers["coaptic"]))
    case("qblock1-missing:coaptic", lambda: qblock1_missing(peers["coaptic"]))
    case("qblock1-window:coaptic", lambda: qblock1_window(peers["coaptic"]))
    case("oscore-qblock1:coaptic", lambda: oscore_qblock1_upload(peers["coaptic"], peers["coaptic"]))
    case("oscore-qblock1-faults:coaptic", lambda: oscore_qblock1_faults(peers["coaptic"], peers["coaptic"]))
    case("no-response:coaptic", lambda: no_response_counter(peers["coaptic"]))
    case("no-response-4:coaptic", lambda: no_response_not_found(peers["coaptic"]))
    case("discovery:coaptic", lambda: discovery(peers["coaptic"]))
    case("separate:coaptic", lambda: separate_response(peers["coaptic"]))
    case("separate:coap-rs", lambda: separate_response(peers["coap-rs"]))
    case("separate-client:coaptic->coap-rs", lambda: separate_client(peers["coaptic"], peers["coap-rs"]))
    case("no-response-5:coaptic", lambda: no_response_internal(peers["coaptic"]))
    case("observe:coaptic", lambda: observe_counter(peers["coaptic"]))
    case("conditional:coaptic", lambda: conditional_workflow(peers["coaptic"]))
    case("conditional:libcoap", lambda: conditional_workflow(peers["libcoap"]))
    case("merge-patch:coaptic->coaptic",
         lambda: merge_patch(peers["coaptic"], peers["coaptic"]))
    case("merge-patch:coaptic->libcoap",
         lambda: merge_patch(peers["coaptic"], peers["libcoap"]))
    case("merge-patch:libcoap->coaptic",
         lambda: merge_patch(peers["libcoap"], peers["coaptic"]))
    case("merge-patch:coaptic->coap-rs",
         lambda: merge_patch(peers["coaptic"], peers["coap-rs"]))
    case("json-patch:coaptic->coaptic",
         lambda: json_patch(peers["coaptic"], peers["coaptic"]))
    case("json-patch:coaptic->libcoap",
         lambda: json_patch(peers["coaptic"], peers["libcoap"]))
    case("json-patch:libcoap->coaptic",
         lambda: json_patch(peers["libcoap"], peers["coaptic"]))
    case("json-patch:coaptic->coap-rs",
         lambda: json_patch(peers["coaptic"], peers["coap-rs"]))
    for client_name in ("coaptic", "coap-rs", "libcoap"):
        case(f"separate-client:{client_name}->coaptic",
             lambda client_name=client_name: separate_client(peers[client_name], peers["coaptic"]))
    case("separate-client:coaptic->libcoap",
         lambda: separate_client(peers["coaptic"], peers["libcoap"], timeout=8000))
    for client, server in [("coaptic", "coaptic"), ("coaptic", "libcoap"), ("libcoap", "coaptic")]:
        case(f"qblock1-interop:{client}->{server}",
             lambda client=client, server=server: qblock1_interop(peers[client], peers[server]))
    for client, server in [("coaptic", "coaptic"), ("coaptic", "libcoap"), ("libcoap", "coaptic")]:
        case(f"qblock2-interop:{client}->{server}",
             lambda client=client, server=server: qblock2_interop(peers[client], peers[server]))
    for client, server in [("coaptic", "coaptic"), ("libcoap", "coaptic")]:
        case(f"qblock2-missing:{client}->{server}",
             lambda client=client, server=server: qblock2_missing(peers[client], peers[server]))
    case("qblock2-reorder:coaptic->coaptic",
         lambda: qblock2_reorder(peers["coaptic"], peers["coaptic"]))
    for client, server in [("coaptic", "coaptic"), ("coaptic", "libcoap"), ("libcoap", "coaptic")]:
        case(f"qblock2-window:{client}->{server}",
             lambda client=client, server=server: qblock2_window(peers[client], peers[server]))
    for server_name in ("coaptic", "libcoap"):
        case(f"observe-client:coaptic->{server_name}",
             lambda server_name=server_name: observe_client(peers["coaptic"], peers[server_name], peers["coaptic"]))
    case("observe-client:libcoap->coaptic",
         lambda: observe_client(peers["libcoap"], peers["coaptic"], peers["coaptic"]))
    case("observe-client:coaptic->coap-rs",
         lambda: observe_values(peers["coaptic"], peers["coap-rs"], peers["coaptic"]))
    case("observe-oscore:coaptic->coaptic",
         lambda: observe_protected(peers["coaptic"], peers["coaptic"], peers["coaptic"], "oscore"))
    if not (args.libcoap_udp_only or args.libcoap_oscore_unavailable):
        case("observe-oscore:coaptic->libcoap",
             lambda: observe_protected(peers["coaptic"], peers["libcoap"], peers["coaptic"], "oscore", ready=2))
        case("observe-oscore:libcoap->coaptic",
             lambda: observe_protected(peers["libcoap"], peers["coaptic"], peers["coaptic"], "oscore"))
    case("observe-dtls:coaptic->coaptic",
         lambda: observe_protected(peers["coaptic"], peers["coaptic"], peers["coaptic"], "dtls"))
    if not args.libcoap_udp_only:
        case("observe-dtls:coaptic->libcoap",
             lambda: observe_protected(peers["coaptic"], peers["libcoap"], peers["coaptic"], "dtls"))
        case("observe-dtls:libcoap->coaptic",
             lambda: observe_protected(peers["libcoap"], peers["coaptic"], peers["coaptic"], "dtls"))
    case("oscore-echo:coaptic->coaptic",
         lambda: oscore_server_echo(peers["coaptic"], peers["coaptic"]))
    case("oscore-replay-restore:coaptic",
         lambda: oscore_replay_restore(peers["coaptic"], peers["coaptic"]))
    case("concurrent-oscore:coaptic",
         lambda: concurrent_oscore_servers(peers["coaptic"], peers["coaptic"]))
    case("empty-request-tag:coaptic", lambda: empty_request_tag(peers["coaptic"]))
    case("problem-details:coaptic", lambda: problem_details_mix(peers["coaptic"]))
    case("concurrent-counter:coaptic",
         lambda: concurrent_counter(peers["coaptic"], peers["coaptic"], peers["coap-rs"]))
    case("concurrent-counter:coap-rs",
         lambda: concurrent_counter(peers["coap-rs"], peers["coap-rs"], peers["coaptic"]))
    for server_name in ("coaptic", "coap-rs", "libcoap"):
        case(f"block1-szx:{server_name}",
             lambda server_name=server_name: smaller_block_upload(peers[server_name]))

    for client, server in [("coaptic", "coaptic"), ("coaptic", "libcoap"), ("libcoap", "coaptic")]:
        if (args.libcoap_udp_only or args.libcoap_oscore_unavailable) and "libcoap" in (client, server):
            continue
        case(f"oscore-upload:{client}->{server}",
             lambda client=client, server=server: oscore_upload_workflow(peers[client], peers[server]))
        case(f"oscore-upload-faults:{client}->{server}",
             lambda client=client, server=server: oscore_upload_fault_workflow(peers[client], peers[server]))

    # The relay preserves one server-visible UDP endpoint across fresh clients.
    for server in ("coaptic", "coap-rs"):
        for client in peers:
            if client == "libcoap" and args.libcoap_udp_only:
                continue
            def reconnect(server=server, client=client):
                with Server(peers[server], "dtls") as service:
                    with Proxy(service.number, "dtls-reconnect") as relay:
                        for _ in range(3):
                            expect(request(peers[client], "dtls", relay.number))
                        refused = request(peers[client], "dtls", relay.number, key="incorrect", timeout=1500)
                        expect_refusal(refused, handshake=True)
                        expect(request(peers[client], "dtls", relay.number))
                        endpoint = relay.back.getsockname()
                return {"server_endpoint": endpoint, "successful_connections": 4,
                        "wrong_key_result": refused, "trace": relay.trace}
            case(f"dtls-reconnect:{client}->{server}", reconnect)
        def churn(server=server):
            with Server(peers[server], "dtls") as service:
                with Proxy(service.number, "dtls-reconnect") as relay:
                    for _ in range(140):
                        expect(request(peers["coaptic"], "dtls", relay.number, path="counter", method="POST"), 68, b"")
                    expect(request(peers["coaptic"], "dtls", relay.number, path="counter"), 69, b"140")
                    endpoint = relay.back.getsockname()
            return {"server_endpoint": endpoint, "connections": 141, "trace": relay.trace}
        case(f"dtls-churn:coaptic->{server}", churn)

    if not args.libcoap_udp_only:
        def c_server_reconnect():
            with Server(peers["libcoap"], "dtls") as service:
                with Proxy(service.number, "dtls-reconnect") as relay:
                    for _ in range(140):
                        expect(request(peers["coaptic"], "dtls", relay.number, path="counter", method="POST"), 68, b"")
                    expect(request(peers["coaptic"], "dtls", relay.number, path="counter"), 69, b"140")
                    endpoint = relay.back.getsockname()
                    alerts = sum(row["direction"] == "request" and row["hex"].startswith("15") for row in relay.trace)
                    if alerts < 141:
                        raise AssertionError(f"missing terminal client records: {alerts}")
            return {"server_endpoint": endpoint, "connections": 141, "client_alert_records": alerts,
                    "trace": relay.trace}
        case("dtls-clean-reconnect:coaptic->libcoap", c_server_reconnect)

    # Exercise both Coaptic roles against independent peer implementations.
    for client, server in [(name, "coaptic") for name in peers] + [("coaptic", "coap-rs"), ("coaptic", "libcoap")]:
        label = client if server == "coaptic" else f"{client}->{server}"
        for mode in ("drop-reply", "duplicate-request", "blackhole"):
            def fault(client=client, server=server, mode=mode):
                with Server(peers[server], "udp") as service:
                    with Proxy(service.number, mode) as relay:
                        idempotent = server != "coaptic"
                        event = request(peers[client], "udp", relay.number,
                                        path=("methods" if idempotent else "counter") if mode != "blackhole" else "test",
                                        method=("PUT" if idempotent else "POST") if mode != "blackhole" else "GET",
                                        payload=b"once" if idempotent and mode != "blackhole" else b"",
                                        timeout=6500 if mode != "blackhole" else 500)
                    if mode == "blackhole":
                        expect_refusal(event)
                    else:
                        if idempotent:
                            # A cached Created or a reprocessed Changed are valid
                            # PUT outcomes. Neither proves server deduplication.
                            if event.get("code") not in (65, 68):
                                raise AssertionError("PUT did not create or replace the resource")
                            expect(event, event["code"], b"")
                            readback = request(peers[client], "udp", service.number, path="methods")
                            expect(readback, 69, b"once")
                        else:
                            expect(event, 68, b"")
                            readback = request(peers[client], "udp", service.number, path="counter")
                            expect(readback, 69, b"1")
                        expect_identical_requests(relay.trace, require_repeat=mode == "drop-reply")
                    if not relay.trace or not any(x["action"] != "forward" for x in relay.trace):
                        raise AssertionError("fault was not exercised")
                    return {"trace": relay.trace, "result": event,
                            "readback": None if mode == "blackhole" else readback,
                            "effect_oracle": "idempotent PUT state" if idempotent else "single POST effect"}
            case(f"reliability:{label}->{mode}", fault)
        def restart(client=client, server=server):
            number = port()
            with Server(peers[server], "udp", number) as service:
                expect(request(peers[client], "udp", service.number))
                expect(request(peers[client], "udp", service.number, path="counter", method="POST"), 68, b"")
            with Server(peers[server], "udp", number) as service:
                expect(request(peers[client], "udp", service.number))
                expect(request(peers[client], "udp", service.number, path="counter"), 69, b"0")
            return {"port": number, "note": "fresh in-memory fixture after process restart; no durability claim"}
        case(f"reliability:{label}->restart", restart)
    for client_name in ("coaptic", "coap-rs", "libcoap"):
        case(f"delay-reply:{client_name}->coaptic",
             lambda client_name=client_name: delayed_reply(peers[client_name], peers["coaptic"]))
    report["coverage"] = evaluate(manifest, report["cases"],
        libcoap_dtls=not args.libcoap_udp_only, libcoap_oscore=not (args.libcoap_udp_only or args.libcoap_oscore_unavailable), system=platform.system().lower())
    report["passed"] = report["coverage"]["complete"]
    report["failures"] = len(report["coverage"]["problems"])
    for problem in report["coverage"]["problems"]:
        print(f"FAIL coverage: {problem}", flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
