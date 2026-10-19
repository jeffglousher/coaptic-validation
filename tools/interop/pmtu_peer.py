"""Linux host socket PMTU witness; no App MTU adaptation is implied."""
import argparse
import errno
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import struct
import time

import aiocoap

BODY = b"coaptic-scoped-addressing"
CONSTANTS = {"IPV6_MTU_DISCOVER": 23, "IPV6_MTU": 24, "IPV6_RECVERR": 25,
             "IPV6_PMTUDISC_DO": 2, "SO_EE_ORIGIN_ICMP6": 3}
ERROR = struct.Struct("=IBBBBII")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def installed_headers():
    paths = [Path("/usr/include/linux/in6.h"), Path("/usr/include/linux/errqueue.h")]
    texts = [path.read_text() for path in paths]
    joined = "\n".join(texts)
    for name, value in CONSTANTS.items():
        require(re.search(r"^#define\s+" + name + r"\s+" + str(value) + r"\b", joined, re.M),
                "installed Linux UAPI constant differs: " + name)
    require(ERROR.size == 16, "unexpected native fixed-width error layout")
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def grade_error(row, original, remote, router):
    require(row["level"] == socket.IPPROTO_IPV6 and row["type"] == CONSTANTS["IPV6_RECVERR"],
            "wrong error control message")
    data = bytes.fromhex(row["control_hex"])
    require(len(data) >= 44, "missing extended error/offender")
    number, origin, kind, code, _, mtu, _ = ERROR.unpack_from(data)
    require((number, origin, kind, code, mtu) == (errno.EMSGSIZE, 3, 2, 0, 1280),
            "not the expected ICMPv6 Packet Too Big")
    require(struct.unpack_from("=H", data, 16)[0] == socket.AF_INET6, "wrong offender family")
    require(socket.inet_ntop(socket.AF_INET6, data[24:40]) == router, "wrong ICMP sender")
    require(tuple(row["destination"]) == tuple(remote), "wrong original destination")
    quoted = bytes.fromhex(row["quoted_hex"])
    require(len(quoted) >= 32 and original.startswith(quoted), "error does not quote this probe")
    require(not row["flags"] & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "truncated error receipt")
    return {"errno": number, "origin": origin, "icmp_type": kind, "icmp_code": code,
            "mtu": mtu, "offender": router, "quoted_bytes": len(quoted)}


def run(args, report):
    report["headers"] = installed_headers()
    local = (str(ipaddress.IPv6Address(args.local)), 0, 0, 0)
    remote = (str(ipaddress.IPv6Address(args.remote)), args.port, 0, 0)
    router = str(ipaddress.IPv6Address(args.router))
    original = secrets.token_bytes(32) + b"p" * (1400 - 32)
    report.update(probe_hex=original.hex(), remote=remote,
                  claim="host Linux UDP PMTU/error queue; no Coaptic adaptation claim")
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind(local)
        sock.connect(remote)
        sock.setsockopt(socket.IPPROTO_IPV6, CONSTANTS["IPV6_RECVERR"], 1)
        sock.setsockopt(socket.IPPROTO_IPV6, CONSTANTS["IPV6_MTU_DISCOVER"], 2)
        report["local"] = sock.getsockname()
        report["mtu_before"] = sock.getsockopt(socket.IPPROTO_IPV6, CONSTANTS["IPV6_MTU"])
        require(report["mtu_before"] == 1500, "fresh topology must begin with 1500-byte path estimate")
        require(sock.send(original) == len(original), "initial probe not submitted")
        deadline = time.monotonic() + 3
        row = None
        while time.monotonic() < deadline:
            try:
                quoted, controls, flags, destination = sock.recvmsg(2048, 256, socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            require(len(controls) == 1, "ambiguous error controls")
            level, kind, control = controls[0]
            row = {"quoted_hex": quoted.hex(), "level": level, "type": kind,
                   "control_hex": control.hex(), "flags": flags, "destination": destination}
            report["error_queue"] = row
            report["validated_error"] = grade_error(row, original, remote, router)
            break
        require(row is not None, "no actual ICMPv6 PTB receipt")
        report["mtu_after"] = sock.getsockopt(socket.IPPROTO_IPV6, CONSTANTS["IPV6_MTU"])
        require(report["mtu_after"] == 1280, "kernel did not retain discovered MTU")
        try:
            sock.send(original)
        except OSError as error:
            report["subsequent_send_errno"] = error.errno
            require(error.errno == errno.EMSGSIZE, "wrong subsequent socket refusal")
        else:
            raise ValueError("oversized subsequent send unexpectedly succeeded")
        # The local EMSGSIZE can enqueue a second receipt. Drain only this
        # owned socket, with a fixed bound, before the fresh application call.
        report["drained"] = []
        for _ in range(4):
            try:
                item = sock.recvmsg(2048, 256, socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT)
                report["drained"].append({"quoted_hex":item[0].hex(), "flags":item[2]})
            except BlockingIOError:
                break
        else:
            raise ValueError("unexpected error queue volume")
        request = aiocoap.Message(code=aiocoap.GET, mtype=aiocoap.CON,
                                  mid=secrets.randbelow(65536), token=secrets.token_bytes(8))
        request.opt.uri_path = ("test",)
        wire = request.encode()
        sock.settimeout(2)
        sock.send(wire)
        reply = sock.recv(1153)
        report["fresh"] = {"request_hex":wire.hex(), "response_hex":reply.hex()}
        message = aiocoap.Message.decode(reply)
        require(message.mtype == aiocoap.ACK and message.mid == request.mid
                and message.token == request.token and message.code == aiocoap.CONTENT
                and message.payload == BODY, "fresh ordinary CoAP operation failed")
    report["status"] = "passed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("local", "remote", "router"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--port", type=int, default=56830)
    args = parser.parse_args()
    report = {"implementation":"aiocoap-codec/python-UDP", "status":"failed"}
    try:
        run(args, report)
    except Exception as error:
        report["error"] = repr(error)
    print(json.dumps(report), flush=True)
    return report["status"] != "passed"


if __name__ == "__main__":
    raise SystemExit(main())
