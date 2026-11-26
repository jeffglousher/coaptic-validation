"""Verify unprotected small and Block2 GET wire shapes on an existing ESP qualification server."""
import argparse
import ipaddress
import json
import re
import secrets
import socket
import time
from pathlib import Path

import aiocoap as coap


def empty_ack(mid):
    return bytes((0x60, 0)) + mid.to_bytes(2, "big")


def read(sock, path, expected, separate, token, mid):
    """Return one verified operation and the next request MID. No retransmission."""
    rows = []
    started = time.perf_counter_ns()
    for offset in range(0, len(expected), 1024):
        request = coap.Message(code=coap.GET, uri_path=(path,))
        request.mtype, request.mid, request.token = coap.CON, mid, token
        if path != "identity":
            request.opt.uri_query = ("ack=1" if separate else "ack=0",)
        if path == "large":
            request.opt.block2 = (offset // 1024, False, 6)
        wire = request.encode()
        sock.send(wire)
        lengths = [len(wire)]
        wire = sock.recv(1500)
        if separate:
            if wire != empty_ack(mid):
                raise ValueError("missing or malformed request ACK")
            lengths.append(len(wire))
            wire = sock.recv(1500)
        response = coap.Message.decode(wire)
        if (response.mtype != (coap.CON if separate else coap.ACK)
                or (not separate and response.mid != mid) or response.token != token
                or response.code != coap.CONTENT):
            raise ValueError("unexpected response type, MID, token or code")
        expected_options = [4, 23] if path == "large" else []
        if [int(o.number) for o in response.opt.option_list()] != expected_options:
            raise ValueError("unexpected response options")
        chunk = expected[offset:offset + 1024]
        if path == "large" and (response.opt.etags != (b"large-v1",)
                or response.opt.block2 != (offset // 1024, offset + len(chunk) < len(expected), 6)):
            raise ValueError("Block2 position, size or ETag mismatch")
        if response.payload != chunk:
            raise ValueError("representation mismatch")
        lengths.append(len(wire))
        if separate:
            ack = empty_ack(response.mid)
            sock.send(ack)
            lengths.append(len(ack))
        rows.append(dict(request_mid=mid, response_mid=response.mid, wire_bytes=lengths))
        mid = (mid + 1) % 65536
    return dict(path=path, exchange="separate-con" if separate else "piggyback",
                verified_bytes=len(expected), elapsed_ns=time.perf_counter_ns()-started,
                blocks=rows), mid


def campaign(sock, run_id, rounds):
    mid = secrets.randbits(16)
    prefix = secrets.token_bytes(4)
    sequence = 0
    operations = []

    def get(path, body, separate):
        nonlocal mid, sequence
        sequence += 1
        token = prefix + sequence.to_bytes(2, "big")
        row, mid = read(sock, path, body, separate, token, mid)
        return row

    get("identity", run_id.encode("ascii"), False)
    for index in range(rounds):
        for separate in ((False, True) if index % 2 == 0 else (True, False)):
            for path, body in (("test", b"coaptic"), ("large", b"Z" * 2000)):
                operations.append(get(path, body, separate))
    get("identity", run_id.encode("ascii"), False)
    return dict(run_id=run_id, security="unprotected", verified=len(operations),
                identity_checks=2, operations=operations)


def match_wire(reference, result):
    """Compare verified block sizes and every datagram length across two service images."""
    def shapes(report):
        if not isinstance(report, dict):
            raise ValueError("invalid peer report")
        ops = report["operations"]
        if (report["security"] != "unprotected" or report["identity_checks"] != 2
                or report["verified"] != len(ops) or not ops):
            raise ValueError("incomplete unprotected peer report")
        return [(op["path"], op["exchange"], op["verified_bytes"],
                 [block["wire_bytes"] for block in op["blocks"]]) for op in ops]

    if shapes(reference) != shapes(result):
        raise ValueError("peer exchange counts or datagram lengths differ")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", type=ipaddress.IPv4Address)
    parser.add_argument("run_id", help="32 lowercase hexadecimal firmware identity bytes")
    parser.add_argument("--port", type=int, default=5683)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--match", type=Path, help="require the wire shapes and lengths in an earlier peer report")
    args = parser.parse_args()
    if (not any(args.address in ipaddress.IPv4Network(net) for net in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"))
            or not 1 <= args.port <= 65535 or not 1 <= args.rounds <= 32
            or not re.fullmatch("[a-f0-9]{32}", args.run_id)):
        parser.error("expected a private or loopback peer, valid port, run ID and 1–32 rounds")
    reference = json.loads(args.match.read_bytes()) if args.match else None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((str(args.address), args.port))
        sock.settimeout(2)
        result = campaign(sock, args.run_id, args.rounds)
    if args.match:
        match_wire(reference, result)
        result["matched_peer_run_id"] = reference["run_id"]
    print(json.dumps(result))


if __name__ == "__main__":
    main()
