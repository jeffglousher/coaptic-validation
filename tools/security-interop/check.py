"""Quick independent OSCORE checks; no release-conformance or performance claim.

Run with Python containing aiocoap[oscore]==0.4.16 and pass --server to the
release fixture built from Cargo.toml in this directory. Fresh test credentials
are provisioned once per execution and deleted before the report is emitted.
Only verdicts, public runtime versions, counts and timing are persisted.
"""

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import logging
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time

import aiocoap
from aiocoap.transports.oscore import OSCOREAddress


class Capture(asyncio.DatagramProtocol):
    def __init__(self, server, protected):
        self.server = server
        self.client = None
        self.requests = []
        self.responses = []
        self.errors = []
        self.protected = protected

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        message = aiocoap.Message.decode(data)
        if peer == self.server:
            if message.code != aiocoap.EMPTY:
                if self.protected and message.opt.oscore is None:
                    self.errors.append("application response lacked OSCORE")
                self.responses.append(data)
            if self.client is not None:
                self.transport.sendto(data, self.client)
        else:
            if message.code != aiocoap.EMPTY:
                if self.protected and message.opt.oscore is None:
                    self.errors.append("application request lacked OSCORE")
                self.requests.append(data)
            self.client = peer
            self.transport.sendto(data, self.server)


def pattern(size):
    return bytes(index % 251 for index in range(size))


async def reject(server, packet):
    responses = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        sock.bind(("127.0.0.1", 0))
        loop = asyncio.get_running_loop()
        await loop.sock_sendto(sock, packet, server)
        deadline = loop.time() + 0.25
        while True:
            try:
                data, peer = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 2048), deadline - loop.time()
                )
            except TimeoutError:
                return responses
            decoded = aiocoap.Message.decode(data)
            if peer != server or decoded.code not in (
                aiocoap.EMPTY, aiocoap.UNAUTHORIZED, aiocoap.BAD_REQUEST, aiocoap.BAD_OPTION
            ):
                raise AssertionError("negative request produced an unexpected response")
            responses.append(str(decoded.code))
    finally:
        sock.close()


async def checks(server, directory, results, protected):
    loop = asyncio.get_running_loop()
    transport, capture = await loop.create_datagram_endpoint(
        lambda: Capture(server, protected), local_addr=("127.0.0.1", 0)
    )
    port = transport.get_extra_info("sockname")[1]
    base = f"coap://127.0.0.1:{port}"
    context = await aiocoap.Context.create_client_context(transports=["oscore", "simple6"] if protected else ["simple6"])
    if protected:
        context.client_credentials.load_from_dict(
            {f"{base}/*": {"oscore": {"basedir": directory}}}
        )
    try:
        for label, method, path, payload, want_code, want_payload, tagged in [
            ("GET", aiocoap.GET, "small", b"", aiocoap.CONTENT, pattern(64), False),
            ("Block2 GET", aiocoap.GET, "large", b"", aiocoap.CONTENT, pattern(2000), False),
            ("explicit Request-Tag Block1 PUT", aiocoap.PUT, "large", pattern(2000), aiocoap.CHANGED, b"accepted", True),
            ("explicit Request-Tag Block1 POST", aiocoap.POST, "small", pattern(2000), aiocoap.CHANGED, b"accepted", True),
            ("native untagged Block1 PUT", aiocoap.PUT, "large", pattern(2000), aiocoap.CHANGED, b"accepted", False),
            ("native untagged Block1 POST", aiocoap.POST, "small", pattern(2000), aiocoap.CHANGED, b"accepted", False),
        ]:
            started = time.perf_counter_ns()
            first_packet = len(capture.requests)
            request = aiocoap.Message(code=method, uri=f"{base}/{path}", payload=payload)
            if payload:
                request.opt.content_format = 42
            if tagged:
                request.opt.request_tag = (secrets.token_bytes(8),)
            try:
                response = await asyncio.wait_for(context.request(request).response, 4)
                if protected and not isinstance(response.remote, OSCOREAddress):
                    raise AssertionError("response was not authenticated by OSCORE transport")
                if (response.code, response.payload, response.opt.content_format) != (
                    want_code, want_payload, 42
                ):
                    raise AssertionError(f"code={response.code}, bytes={len(response.payload)}, format={response.opt.content_format}")
                if label == "Block2 GET" and response.opt.etags != (b"fixture",):
                    raise AssertionError("Block2 representation ETag changed or missing")
                result = {"case": label, "status": "PASS"}
            except Exception as error:
                result = {"case": label, "status": "FAIL", "error_type": type(error).__name__}
                if isinstance(error, AssertionError):
                    result["error"] = str(error)
            result["elapsed_ns"] = time.perf_counter_ns() - started
            packets = [aiocoap.Message.decode(packet) for packet in capture.requests[first_packet:]]
            result["request_datagrams"] = len(packets)
            result["distinct_request_tokens"] = len({packet.token for packet in packets})
            if not protected:
                result["blocks"] = [
                    {"number": packet.opt.block1.block_number, "more": packet.opt.block1.more, "bytes": len(packet.payload), "tagged": bool(packet.opt.request_tag)}
                    for packet in packets if packet.opt.block1 is not None
                ]
            results.append(result)
        observation = context.request(aiocoap.Message(code=aiocoap.GET, uri=f"{base}/observe", observe=0))
        try:
            initial = await asyncio.wait_for(observation.response, 4)
            if (initial.code, initial.payload, initial.opt.content_format) != (aiocoap.CONTENT, b"initial", 42):
                raise AssertionError("Observe registration failed")
            if initial.opt.observe is None or (protected and not isinstance(initial.remote, OSCOREAddress)):
                raise AssertionError("Observe registration not protected")
            update = await asyncio.wait_for(anext(observation.observation.__aiter__()), 4)
            if (update.code, update.payload, update.opt.content_format) != (aiocoap.CONTENT, b"notification", 42):
                raise AssertionError("Observe notification failed")
            if update.opt.observe is None or (protected and not isinstance(update.remote, OSCOREAddress)):
                raise AssertionError("Observe notification not protected")
            results.append({"case": "Observe registration and notification", "status": "PASS"})
        finally:
            observation.observation.cancel()
        if not protected:
            return len(capture.requests), len(capture.responses)
        plaintext = aiocoap.Message(code=aiocoap.GET)
        plaintext.mtype, plaintext.mid, plaintext.token = aiocoap.CON, 0xFE00, b"neg"
        plaintext.opt.uri_path = ("small",)
        responses = await reject(server, plaintext.encode())
        results.append({"case": "plaintext request rejected", "status": "PASS", "response_codes": responses})
        replay = bytearray(capture.requests[0])
        replay[2:4] = b"\xfe\x01"
        responses = await reject(server, bytes(replay))
        results.append({"case": "replayed Partial IV with fresh MID and endpoint rejected", "status": "PASS", "response_codes": responses})
        credential = next(iter(context.client_credentials.values()))
        fresh = aiocoap.Message(code=aiocoap.GET)
        fresh.mtype, fresh.mid, fresh.token = aiocoap.CON, 0xFE02, b"bad"
        fresh.opt.uri_path = ("small",)
        encrypted, _ = credential.protect(fresh)
        encrypted.mtype, encrypted.mid, encrypted.token = fresh.mtype, fresh.mid, fresh.token
        corrupted = bytearray(encrypted.encode())
        corrupted[-1] ^= 1
        responses = await reject(server, bytes(corrupted))
        results.append({"case": "corrupted ciphertext rejected", "status": "PASS", "response_codes": responses})
        if capture.errors:
            raise AssertionError("wire protection check failed")
        health = await asyncio.wait_for(
            context.request(aiocoap.Message(code=aiocoap.GET, uri=f"{base}/small")).response, 4
        )
        if not isinstance(health.remote, OSCOREAddress) or (
            health.code, health.payload, health.opt.content_format
        ) != (aiocoap.CONTENT, pattern(64), 42):
            raise AssertionError("authenticated health check after negative probes failed")
        results.append({"case": "authenticated health check after negative probes", "status": "PASS"})
        return len(capture.requests), len(capture.responses)
    finally:
        await context.shutdown()
        for credential in context.client_credentials.values():
            credential.lockfile.release()
            credential.lockfile = None
            del credential.sender_key
            del credential.recipient_key
        context.client_credentials.clear()
        transport.close()


async def run(binary, protected):
    secret, salt = secrets.token_bytes(16), secrets.token_bytes(8)
    process = subprocess.Popen([str(binary)] + ([] if protected else ["--plaintext"]), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    results = []
    try:
        process.stdin.write(secret + salt)
        process.stdin.close()
        endpoint = await asyncio.wait_for(asyncio.to_thread(process.stdout.readline), 8)
        host, port = endpoint.decode("ascii").strip().split(":")
        with tempfile.TemporaryDirectory(prefix="coaptic-oscore-") as directory:
            filename = Path(directory) / "secret.json"
            descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump({"secret_hex": secret.hex(), "salt_hex": salt.hex(), "sender-id_hex": "", "recipient-id_hex": "01"}, stream)
            requests, responses = await checks((host, int(port)), directory, results, protected)
        return {
            "schema": 1,
            "status": "FAIL" if any(result["status"] == "FAIL" for result in results) else "PASS",
            "peer": "aiocoap",
            "versions": {name: importlib.metadata.version(name) for name in ("aiocoap", "cryptography", "cbor2", "filelock")},
            "server_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "transport": "real loopback IPv4 UDP with capturing forwarder",
            "security": "pairwise OSCORE AES-CCM-16-64-128 / HKDF-SHA-256; fresh per-run provisioning" if protected else "explicit plaintext diagnostic control",
            "request_datagrams": requests,
            "response_datagrams": responses,
            "cases": results,
            "not_tested": ["reverse client/server direction", "Observe cancellation on wire", "restart recovery", "EDHOC", "Group OSCORE", "DTLS", "formal conformance", "performance ranking"],
        }
    except Exception as error:
        results.append({"case": "runner completion", "status": "FAIL", "error_type": type(error).__name__})
        return {"schema": 1, "status": "FAIL", "cases": results, "error_type": type(error).__name__}
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)
        process.stdout.close()
        process.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--plaintext", action="store_true", help="Run explicit plaintext diagnostic control")
    arguments = parser.parse_args()
    if arguments.output.exists():
        parser.error("output already exists; choose a new report path")
    logging.disable(logging.CRITICAL)
    started = time.perf_counter_ns()
    try:
        report = asyncio.run(run(arguments.server.resolve(), not arguments.plaintext))
    except Exception as error:
        report = {"schema": 1, "status": "FAIL", "error_type": type(error).__name__}
    report["elapsed_ns"] = time.perf_counter_ns() - started
    with arguments.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
