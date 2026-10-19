"""Independent finite UDP peer for explicit IPv6 bind/remote scope identities."""
import argparse
import ipaddress
import json
import secrets
import socket
import time

import aiocoap

BODY = b"coaptic-scoped-addressing"
PACKET_LIMIT = 1152


def endpoint(host, port, scope, remote=False):
    value = ipaddress.ip_address(host)
    if not isinstance(value, ipaddress.IPv6Address) or "%" in host:
        raise ValueError("numeric IPv6 host and separate numeric scope required")
    if value.is_link_local and scope == 0:
        raise ValueError("link-local endpoint needs nonzero scope")
    if not 0 <= scope <= 0xffffffff or not 0 <= port <= 65535 or remote and port == 0:
        raise ValueError("invalid endpoint")
    return str(value), port, 0, scope


def emit(**value):
    print(json.dumps(value), flush=True)


def run(args):
    local = endpoint(args.bind_host, args.bind_port, args.bind_scope)
    remote = endpoint(args.remote_host, args.remote_port, args.remote_scope, True) if args.role == "client" else None
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(local)
        sock.settimeout(args.timeout)
        emit(event="ready", local=sock.getsockname(), remote=remote, implementation="aiocoap-codec/python-UDP",
             security="unprotected", receive_capacity=PACKET_LIMIT + 1)
        if remote:
            request = aiocoap.Message(code=aiocoap.GET, mtype=aiocoap.CON,
                                      mid=secrets.randbelow(65536), token=secrets.token_bytes(8))
            request.opt.uri_path = ("test",)
            wire = request.encode()
            emit(event="send-attempt", peer=remote, hex=wire.hex())
            sock.sendto(wire, remote)
        deadline = time.monotonic() + args.timeout
        for _ in range(16):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded fixture deadline")
            sock.settimeout(remaining)
            wire, peer = sock.recvfrom(PACKET_LIMIT + 1)
            if len(wire) > PACKET_LIMIT:
                raise ValueError("oversized datagram")
            emit(event="receive", peer=peer, hex=wire.hex())
            message = aiocoap.Message.decode(wire)
            if remote:
                if peer != remote or message.mid != request.mid or message.token != request.token:
                    raise ValueError("response endpoint/operation identity mismatch")
                if message.mtype != aiocoap.ACK or message.code != aiocoap.CONTENT or message.payload != BODY:
                    raise ValueError("wrong application response")
                emit(event="complete", code=int(message.code), hex=message.payload.hex())
                return
            if message.mtype != aiocoap.CON or message.code != aiocoap.GET or message.opt.uri_path != ("test",) or message.payload:
                raise ValueError("wrong application request")
            reply = aiocoap.Message(code=aiocoap.CONTENT, mtype=aiocoap.ACK, mid=message.mid,
                                    token=message.token, payload=BODY)
            wire = reply.encode()
            emit(event="send-attempt", peer=peer, hex=wire.hex())
            sock.sendto(wire, peer)
            if args.once:
                return
        raise ValueError("fixture packet limit exceeded")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("client", "server"))
    parser.add_argument("--bind-host", required=True)
    parser.add_argument("--bind-port", type=int, required=True)
    parser.add_argument("--bind-scope", type=int, default=0)
    parser.add_argument("--remote-host")
    parser.add_argument("--remote-port", type=int, default=0)
    parser.add_argument("--remote-scope", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not 0.1 <= args.timeout <= 30 or args.role == "client" and args.remote_host is None:
        parser.error("bounded timeout and explicit client remote required")
    try:
        run(args)
        return 0
    except (OSError, ValueError) as error:
        emit(event="error", error_type=type(error).__name__, message=str(error),
             errno=getattr(error, "errno", None), winerror=getattr(error, "winerror", None))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
