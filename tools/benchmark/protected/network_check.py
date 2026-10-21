"""Focused real UDP refusal/recovery checks; run with --server native fixture."""
import argparse
import pathlib
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

import aiocoap
from aiocoap.message import Direction
from context import Context, SECURITY
from load import Worker, check_body


def check(server, aiocoap_server=False):
    with tempfile.TemporaryDirectory() as directory:
        credentials = pathlib.Path(directory) / "credentials"
        credentials.write_bytes(secrets.token_bytes(24))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        if aiocoap_server:
            command = [sys.executable, str(pathlib.Path(__file__).with_name("aiocoap_server.py")),
                       "--host", "127.0.0.1", "--port", str(port), "--bytes", "2000", "--credentials", str(credentials)]
        else:
            command = [str(pathlib.Path(server).resolve()), "coaptic", "127.0.0.1", str(port), "2000", "1472", str(credentials)]
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(command, stdout=output, stderr=output)
            args = SimpleNamespace(host="127.0.0.1", port=port, bytes=2000, timeout_ms=1000, mode="con")
            context = Context(credentials)
            worker = Worker(args, 0, context, threading.Lock())
            try:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        worker.exchange(1)
                        break
                    except (OSError, ValueError):
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise AssertionError("protected fixture not ready")
                        time.sleep(.02)
                # Use a fresh endpoint/MID for each hostile request, avoiding
                # duplicate-cache effects. Only fixed verdicts are retained.
                request = aiocoap.Message(code=aiocoap.GET, uri_path=("bench",))
                request.mtype, request.mid, request.token = aiocoap.CON, 500, b"negative"
                valid, binding = context.protect(request)
                valid.mtype, valid.mid, valid.token = request.mtype, request.mid, request.token
                packet = valid.encode()
                wrong = pathlib.Path(directory) / "wrong"
                wrong.write_bytes(secrets.token_bytes(24))
                # Fresh sequence: isolate wrong-key refusal from replay refusal.
                wrong_context = Context(wrong, sequence=context.sender_sequence_number)
                wrong_packet, _ = wrong_context.protect(request)
                wrong_packet.mtype, wrong_packet.mid, wrong_packet.token = request.mtype, request.mid, request.token
                tampered = packet[:-1] + bytes([packet[-1] ^ 1])

                def refuse(wire):
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.bind(("127.0.0.1", 0))
                        sock.connect((args.host, port))
                        until = time.monotonic() + .15
                        sock.send(wire)
                        while True:
                            remaining = until - time.monotonic()
                            if remaining <= 0:
                                return
                            sock.settimeout(remaining)
                            try:
                                received = aiocoap.Message.decode(sock.recv(65535))
                            except TimeoutError:
                                return
                            if received.code not in (aiocoap.EMPTY, aiocoap.BAD_REQUEST, aiocoap.UNAUTHORIZED, aiocoap.BAD_OPTION):
                                raise AssertionError("hostile request produced application response")

                refuse(request.encode())
                refuse(wrong_packet.encode())
                refuse(tampered)
                # Authenticate the exact packet once, then resend from another
                # endpoint: a legitimate same-endpoint retry could hit dedup.
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.bind(("127.0.0.1", 0))
                    sock.connect((args.host, port))
                    sock.settimeout(1)
                    sock.send(packet)
                    while True:
                        response = aiocoap.Message.decode(sock.recv(65535))
                        if response.code != aiocoap.EMPTY:
                            assert response.opt.oscore is not None
                            response.direction = Direction.INCOMING
                            plain, _ = context.unprotect(response, binding)
                            check_body(plain, 0, 2000, None)
                            break
                refuse(packet)
                worker.exchange(2)
                print(("aiocoap" if aiocoap_server else "coaptic") + ": protected Block2, unprotected/wrong-key/tamper/replay refusal and fresh recovery PASS")
            finally:
                worker.close()
                process.kill()
                process.wait(timeout=3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    args = parser.parse_args()
    check(args.server)
    check(args.server, aiocoap_server=True)
