"""Live loss/refusal regression for the unprotected libcoap handler control."""
import argparse
import json
import socket
import subprocess
import time

import aiocoap
from load import check_body


def selected_block(sock, number, request_mid, response_mids, *, drop_ack=False):
    token = b"retry"
    block = (number, False, 6)
    request = aiocoap.Message(code=aiocoap.GET, uri_path=("bench",), block2=block)
    request.mid, request.mtype, request.token = request_mid, aiocoap.CON, token
    sock.send(request.encode())
    sock.settimeout(1)
    if sock.recv(2048) != bytes((0x60, 0)) + request_mid.to_bytes(2, "big"):
        raise ValueError("missing request ACK")
    wire = sock.recv(2048)
    reply = aiocoap.Message.decode(wire)
    if reply.mtype != aiocoap.CON or reply.token != token or reply.mid in response_mids:
        raise ValueError("wrong separate response type, token or repeated response MID")
    response_mids.add(reply.mid)
    if number == 4:
        if reply.code != aiocoap.BAD_REQUEST:
            raise ValueError("out-of-range Block2 accepted")
    else:
        check_body(reply, number * 1024, 4096, (b"fixture",), block, fixture=True)
        if reply.opt.size2 != 4096:
            raise ValueError("incorrect Size2 on the selected range")
    if drop_ack:
        # The first response was fully verified. Withhold its ACK, then accept
        # only its byte-identical retransmission on the same connected socket.
        sock.settimeout(6)
        if sock.recv(2048) != wire:
            raise ValueError("separate response retransmission changed")
    sock.send(bytes((0x60, 0)) + reply.mid.to_bytes(2, "big"))
    return len(wire)


def check(server):
    with socket.socket(type=socket.SOCK_DGRAM) as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    process = subprocess.Popen([server, "127.0.0.1", str(port), "4096", "--fixture-etag",
                                "--handler-response", "separate-con"], stdout=subprocess.DEVNULL)
    try:
        # A bind probe consumes no request or pending response before the test.
        for _ in range(100):
            if process.poll() is not None:
                raise ValueError("fixture exited before readiness")
            with socket.socket(type=socket.SOCK_DGRAM) as probe:
                try:
                    probe.bind(("127.0.0.1", port))
                except OSError:
                    break
            time.sleep(.01)
        else:
            raise TimeoutError("fixture bind deadline")
        with socket.socket(type=socket.SOCK_DGRAM) as sock:
            sock.connect(("127.0.0.1", port))
            response_mids = set()
            retried_bytes = selected_block(sock, 3, 180, response_mids, drop_ack=True)
            selected_block(sock, 4, 181, response_mids)
            for number in range(4):
                selected_block(sock, number, 182 + number, response_mids)
        return dict(retransmitted_block=3, identical_response_bytes=retried_bytes,
                    refused_block=4, verified_blocks_after_refusal=4)
    finally:
        process.terminate()
        process.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    print(json.dumps(check(parser.parse_args().server)))
