"""Finite native-client success, refusal and fresh recovery over real UDP."""
import argparse
import json
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time


def run_client(client, port, size, security, credentials=None):
    command = [str(Path(client).resolve()), str(port), str(size), "2", "0", "200",
               "spin", security]
    if credentials is not None:
        command.append(str(credentials))
    return subprocess.run(command, capture_output=True, text=True, timeout=5)


def raw_representation(client, corrupt):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(2)
        errors = []
        def serve():
            try:
                for _ in range(2):
                    wire, peer = sock.recvfrom(1473)
                    token = wire[4:4 + (wire[0] & 15)]
                    body = bytearray(range(64))
                    if corrupt:
                        body[-1] ^= 1
                    header = bytes([0x60 | len(token), 69]) + wire[2:4] + token
                    # ETag4 then Content-Format12; independent wire encoding.
                    response = header + b"\x47fixture\x81\x2a\xff" + body
                    sock.sendto(response, peer)
                    if corrupt:
                        return
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            result = run_client(client, sock.getsockname()[1], 64, "plaintext")
        finally:
            thread.join(timeout=3)
        if thread.is_alive() or errors:
            raise RuntimeError("independent raw fixture failed")
        if corrupt:
            if result.returncode == 0 or "mismatch" not in result.stderr:
                raise RuntimeError("corrupt representation counted complete")
        elif result.returncode or json.loads(result.stdout)["completed"] != 2:
            raise RuntimeError("independent raw representation failed")


def check(server, client):
    raw_representation(client, False)
    raw_representation(client, True)
    raw_representation(client, False)
    with tempfile.TemporaryDirectory(prefix="coaptic-native-check-") as directory:
        correct = Path(directory) / "correct"
        wrong = Path(directory) / "wrong"
        correct.write_bytes(secrets.token_bytes(24))
        wrong.write_bytes(secrets.token_bytes(24))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        command = [str(Path(server).resolve()), "coaptic-reusable", "127.0.0.1",
                   str(port), "2000", "1472", str(correct)]
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen(command, stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError("protected server startup failed")
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                        try:
                            probe.bind(("127.0.0.1", port))
                        except OSError:
                            break
                    time.sleep(.01)
                else:
                    raise RuntimeError("protected server bind deadline")
                for security, credential in (("plaintext", None), ("oscore", wrong)):
                    result = run_client(client, port, 2000, security, credential)
                    if result.returncode == 0:
                        raise RuntimeError("refused security profile counted complete")
                # First valid traffic: no reset/reuse of a used key+sender nonce.
                result = run_client(client, port, 2000, "oscore", correct)
                if result.returncode:
                    raise RuntimeError("fresh authenticated recovery failed")
                report = json.loads(result.stdout)
                if report["completed"] != 2 or report["received_datagrams"] < 4:
                    raise RuntimeError("incomplete protected Block2 report")
            finally:
                process.terminate()
                process.wait(timeout=5)
    print("native client: independent exact body, corrupt refusal/recovery, "
          "plaintext/wrong-key refusal and fresh protected Block2 PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    args = parser.parse_args()
    check(args.server, args.client)
