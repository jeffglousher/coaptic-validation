import argparse
import asyncio
import hashlib
from importlib.metadata import version
import ipaddress
import json
import logging
from pathlib import Path
import random
import re
import secrets
import socket
import sys
import time

import aiocoap
from build_source import verify_report_source


async def qualify(args):
    if sys.flags.optimize:
        raise ValueError("qualification requires enabled assertions")
    if version("aiocoap") != "0.4.16":
        raise ValueError("use aiocoap==0.4.16")
    address = ipaddress.ip_address(args.host)
    if address.version != 4 or address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("hardware qualification refuses loopback")
    build = json.loads(args.build.read_text(encoding="utf-8"))
    verify_report_source(build, args.expected_library_revision, args.expected_suite_revision)
    if build.get("schema") != "coaptic-esphome-network-build/1" or build.get("build_passed") is not True:
        raise ValueError("a successful build report is required")
    image = args.build.parent / "firmware.factory.bin"
    if hashlib.sha256(image.read_bytes()).hexdigest() != build["firmware.factory.bin_sha256"]:
        raise ValueError("firmware identity mismatch")
    report = {"schema": "coaptic-network-runtime/1", "peer": "aiocoap", "peer_version": version("aiocoap"),
              "host": args.host, "port": args.port, "run_id": build["run_id"],
              **{key: build[key] for key in ["source", "suite_source", "dirty", "suite_dirty", "suite_locks"]},
              "firmware_sha256": build["firmware.factory.bin_sha256"],
              "runtime_passed": False, "cases": [],
              "scope": "independent client over IPv4 UDP; OSCORE, actuators and durable state excluded"}
    context = await aiocoap.Context.create_client_context(transports=["simple6"])
    base = f"coap://{args.host}:{args.port}/"

    async def exchange(path, *, code=aiocoap.GET, payload=b"", mtype=aiocoap.CON):
        tuning = aiocoap.Reliable if mtype == aiocoap.CON else aiocoap.Unreliable
        message = aiocoap.Message(code=code, uri=base + path, payload=payload, transport_tuning=tuning())
        return await asyncio.wait_for(context.request(message).response, 10)

    async def case(name, operation):
        started = time.monotonic()
        entry = {"name": name, "passed": False}
        report["cases"].append(entry)
        await operation()
        entry.update(passed=True, elapsed_ms=round((time.monotonic() - started) * 1000, 3))
        print("PASS " + name, flush=True)

    async def identity():
        response = await exchange("identity")
        assert response.code == aiocoap.CONTENT and response.payload.decode("ascii") == build["run_id"]

    async def non():
        response = await exchange("test", mtype=aiocoap.NON)
        assert response.code == aiocoap.CONTENT and response.payload == b"coaptic"

    async def echo():
        payload = bytes(range(96))
        response = await exchange("echo", code=aiocoap.POST, payload=payload)
        assert response.code == aiocoap.CONTENT and response.payload == payload
        response = await exchange("echo", code=aiocoap.POST, payload=bytes(range(129)))
        assert response.code == aiocoap.REQUEST_ENTITY_TOO_LARGE

    async def upload():
        body = bytes(range(256)) * 7
        checksum = 0
        for byte in body:
            checksum = (((checksum << 5) | (checksum >> 27)) & 0xFFFFFFFF) ^ byte
        response = await exchange("upload", code=aiocoap.POST, payload=body)
        assert response.code == aiocoap.CONTENT, (str(response.code), response.payload.hex(), response.opt.block1)
        assert response.payload == len(body).to_bytes(4, "big") + checksum.to_bytes(4, "big"), response.payload.hex()

    async def download():
        response = await exchange("large")
        assert response.code == aiocoap.CONTENT and response.payload == b"\x5a" * 2000

    async def discovery():
        response = await exchange(".well-known/core")
        assert response.code == aiocoap.CONTENT
        for name in ["identity", "test", "echo", "upload", "large", "ticks"]:
            assert ("</" + name + ">").encode() in response.payload
        assert (await exchange("missing")).code == aiocoap.NOT_FOUND
        assert (await exchange("test", code=aiocoap.POST)).code == aiocoap.METHOD_NOT_ALLOWED

    async def observe():
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            channel.connect((args.host, args.port))
            channel.setblocking(False)
            mid = secrets.randbelow(65536)

            async def receive():
                packet = await asyncio.wait_for(loop.sock_recv(channel, 2048), 5)
                response = aiocoap.Message.decode(packet)
                if response.mtype == aiocoap.CON:
                    ack = aiocoap.Message(code=aiocoap.EMPTY)
                    ack.mtype, ack.mid = aiocoap.ACK, response.mid
                    await loop.sock_sendall(channel, ack.encode())
                return response

            for round_number in range(3):
                token = secrets.token_bytes(8)
                request = aiocoap.Message(code=aiocoap.GET, uri=base + "ticks", observe=0)
                request.mtype, request.mid, request.token = aiocoap.CON, mid, token
                mid = (mid + 1) % 65536
                await loop.sock_sendall(channel, request.encode())
                values, sequences = [], []
                for _ in range(6 if round_number == 0 else 2):
                    response = await receive()
                    assert response.code == aiocoap.CONTENT and response.token == token
                    assert response.opt.observe is not None and len(response.payload) == 4
                    values.append(int.from_bytes(response.payload, "big"))
                    sequences.append(response.opt.observe)
                assert all(b > a for a, b in zip(values, values[1:]))
                assert all(0 < (b - a) % (1 << 24) < (1 << 23) for a, b in zip(sequences, sequences[1:]))
                cancel = aiocoap.Message(code=aiocoap.GET, uri=base + "ticks", observe=1)
                cancel.mtype, cancel.mid, cancel.token = aiocoap.CON, mid, token
                mid = (mid + 1) % 65536
                await loop.sock_sendall(channel, cancel.encode())
                response = await receive()
                assert response.token == token and response.code == aiocoap.CONTENT and response.opt.observe is None
                try:
                    await asyncio.wait_for(loop.sock_recv(channel, 2048), 3.5)
                except TimeoutError:
                    pass
                else:
                    raise AssertionError("notification received after Observe cancellation")
        await identity()

    async def malformed():
        generator = random.Random(20261004)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            for size in range(1, 65):
                channel.sendto(b"\x00" + generator.randbytes(size), (args.host, args.port))
                await asyncio.sleep(0.02)
            channel.sendto(b"\xff" * 1400, (args.host, args.port))
            await asyncio.sleep(0.1)
            channel.sendto(b"\xff" * 4096, (args.host, args.port))
            await asyncio.sleep(0.1)
        await asyncio.sleep(1)
        await identity()

    async def repeat():
        for _ in range(args.iterations):
            response = await exchange("test")
            assert response.code == aiocoap.CONTENT and response.payload == b"coaptic"

    try:
        for name, operation in [("firmware_identity", identity), ("non_confirmable_get", non),
                                ("binary_echo_and_size_refusal", echo), ("block1_upload", upload),
                                ("block2_download", download), ("discovery_and_errors", discovery),
                                ("observe_and_cancel_reuse", lambda: asyncio.wait_for(observe(), 45)),
                                ("malformed_and_oversized_recovery", malformed),
                                (f"repeated_get_{args.iterations}", repeat)]:
            await case(name, operation)
        report["runtime_passed"] = True
        if args.capture:
            await asyncio.sleep(6)
            raw = args.capture.read_bytes()
            samples = [json.loads(match) for match in re.findall(rb"COAPTIC_NETWORK (\{[^\r\n]+\})", raw)]
            matching = [sample for sample in samples if sample["run_id"] == build["run_id"]]
            if not matching or b"COAPTIC_NETWORK_FAIL" in raw or b"COAPTIC_NETWORK_STOPPED" in raw:
                raise ValueError("missing live device evidence or stopped service")
            latest = matching[-1]
            assert 0 < latest["stack_high_water_bytes"] < latest["stack_capacity_bytes"]
            assert latest["rx"] >= args.iterations + 65 and latest["tx"] >= args.iterations
            assert latest["dropped"] >= 1
            report["device"] = latest
            report["console_bytes"] = len(raw)
            report["console_prefix_sha256"] = hashlib.sha256(raw).hexdigest()
    except Exception as error:
        report["runtime_passed"] = False
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        await context.shutdown()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=5683)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--expected-library-revision", required=True)
    parser.add_argument("--expected-suite-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    if not 1 <= args.iterations <= 10000:
        parser.error("iterations must be 1..10000")
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1..65535")
    asyncio.run(qualify(args))


if __name__ == "__main__":
    main()
