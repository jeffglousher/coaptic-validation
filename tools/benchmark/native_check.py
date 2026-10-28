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
from native_profiles import PROFILE_SIZES, dimensions, validate_profile
from native_diagnostic import server_resources, validate_report


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
            result = run_client(client, sock.getsockname()[1], 64, "unprotected")
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
    """Common proof uses Mio's passive startup ledger with host-control capacities.

    This replaces the reusable fixture: probing its live port by binding could
    steal the port before the server binds. Representation/security checks stay
    at 2000 bytes with 1472-byte RX datagrams.
    """
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
        command = [str(Path(server).resolve()), "coaptic-mio", "127.0.0.1",
                   str(port), "2000", "1472", str(correct),
                   "--resource-profile", "host-control"]
        path = Path(directory) / "server.log"
        with path.open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=log)
            primary_error = None
            try:
                server_resources(path, "coaptic-mio", deadline=time.monotonic() + 5,
                                 server=process, resource_profile="host-control",
                                 size=2000, security="oscore", rx_bytes=1472)
                for security, credential in (("unprotected", None), ("oscore", wrong)):
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
            except BaseException as error:
                primary_error = error
                try:
                    log.flush()
                    with path.open("rb") as reader:
                        raw = reader.read(4096)
                    print("RAW SERVER STARTUP/FAILURE: " + raw.decode("utf-8", errors="replace"),
                          flush=True)
                finally:
                    raise error
            finally:
                cleanup_errors = []
                try:
                    if process.poll() is None:
                        process.terminate()
                except BaseException as error:
                    cleanup_errors.append(error)
                try:
                    process.wait(timeout=5)
                except BaseException as error:
                    cleanup_errors.append(error)
                if cleanup_errors:
                    failure = primary_error if primary_error is not None else cleanup_errors.pop(0)
                    for error in cleanup_errors:
                        failure.add_note("native server cleanup: " + type(error).__name__
                                         + ": " + str(error)[:512])
                    if primary_error is None:
                        raise failure
    print("native client: independent exact body, corrupt refusal/recovery, "
          "unprotected/wrong-key refusal and fresh protected Block2 PASS")


def check_profile(server, client, profile, size):
    """Real executable/route checks; each process initializes its declared BODY.

    Fresh process-lifetime keys per cell. Wrong-key traffic cannot consume the
    valid sender sequence; the valid protected client is run exactly once.
    """
    validate_profile(profile, "coaptic-mio", size)
    rx_bytes = dimensions(profile, size)["rx_datagram_bytes"]
    for security in ("unprotected", "oscore"):
        with tempfile.TemporaryDirectory(prefix="coaptic-profile-check-") as directory:
            correct, wrong = Path(directory) / "correct", Path(directory) / "wrong"
            correct.write_bytes(secrets.token_bytes(24))
            wrong.write_bytes(secrets.token_bytes(24))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
                reserve.bind(("127.0.0.1", 0))
                port = reserve.getsockname()[1]
            command = [str(Path(server).resolve()), "coaptic-mio", "127.0.0.1", str(port), str(size), str(rx_bytes)]
            if security == "oscore":
                command.append(str(correct))
            command += ["--resource-profile", profile]
            path = Path(directory) / "server.log"
            with path.open("wb") as log:
                process = subprocess.Popen(command, stdout=log, stderr=log)
                try:
                    ledger = server_resources(path, "coaptic-mio", deadline=time.monotonic() + 5,
                                              server=process, resource_profile=profile,
                                              size=size, security=security, rx_bytes=rx_bytes)
                    # Exact +1 guard refusal followed by a fresh complete operation.
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as oversized:
                        oversized.sendto(b"\xff" * (rx_bytes + 1), ("127.0.0.1", port))
                    if security == "oscore":
                        for mode, key in (("unprotected", None), ("oscore", wrong)):
                            refused = run_client(client, port, size, mode, key)
                            failure = json.loads(refused.stdout)
                            expected = ("complete representation/status/format/ETag mismatch"
                                        if mode == "unprotected" else "complete operation deadline")
                            if (refused.returncode != 1 or failure.get("completed") != 0
                                    or failure.get("failure") != expected):
                                raise RuntimeError("unexpected security refusal: " + str(failure.get("failure")))
                    else:
                        refused = run_client(client, port, size - 1, security)
                        failure = json.loads(refused.stdout)
                        if (refused.returncode != 1 or failure.get("completed") != 0
                                or failure.get("failure") not in
                                ("output", "complete representation/status/format/ETag mismatch")):
                            raise RuntimeError("wrong declared representation counted complete")
                    result = run_client(client, port, size, security, correct if security == "oscore" else None)
                    if result.returncode:
                        raise RuntimeError("profile complete/recovery failed: " + result.stderr[:512])
                    report = json.loads(result.stdout)
                    validate_report(report, size, 2, "spin", security)
                    if process.poll() is not None:
                        raise RuntimeError("server exited during profile proof")
                    print(json.dumps(dict(profile=profile, security=security, size=size,
                                          completed=report["completed"], ledger=ledger,
                                          oversized_bytes=rx_bytes + 1,
                                          expected_client_refusals=2 if security == "oscore" else 1)))
                except BaseException:
                    log.flush()
                    print("RAW SERVER STARTUP/FAILURE: " + path.read_bytes()[:4096].decode("utf-8", errors="replace"),
                          flush=True)
                    raise
                finally:
                    if process.poll() is None:
                        process.terminate()
                    process.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--resource-profile", choices=tuple(PROFILE_SIZES))
    parser.add_argument("--bytes", type=int)
    args = parser.parse_args()
    if args.resource_profile is not None:
        check_profile(args.server, args.client, args.resource_profile, args.bytes)
    elif args.bytes is not None:
        parser.error("--bytes requires --resource-profile")
    else:
        check(args.server, args.client)
