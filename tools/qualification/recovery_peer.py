"""Finite unprotected installed-fixture selectors; never provisions security state.

Use only against the source-bound qualification image. OSCORE campaigns use the
durable native client separately; these results cannot establish protected cells.
"""
import argparse
import json
import secrets
import socket
import sys
import time

import aiocoap


class Peer:
    def __init__(self, channel, host, port):
        self.channel = channel
        self.base = f"coap://{host}:{port}/"
        self.mid = secrets.randbelow(65536)

    def request(self, path, code=aiocoap.GET, payload=b"", token=None, observe=None):
        packet = aiocoap.Message(code=code, uri=self.base + path, payload=payload)
        packet.mtype, packet.mid = aiocoap.CON, self.mid
        self.mid = (self.mid + 1) % 65536
        packet.token = secrets.token_bytes(8) if token is None else token
        if observe is not None:
            packet.opt.observe = observe
        return packet

    def exchange(self, packet):
        deadline = time.monotonic() + 5
        self.channel.settimeout(5)
        self.channel.send(packet.encode())
        for _ in range(128):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self.channel.settimeout(remaining)
            reply = aiocoap.Message.decode(self.channel.recv(1153))
            if reply.mtype == aiocoap.CON:
                ack = aiocoap.Message(code=aiocoap.EMPTY)
                ack.mtype, ack.mid = aiocoap.ACK, reply.mid
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("response acknowledgment deadline exhausted")
                self.channel.settimeout(remaining)
                self.channel.send(ack.encode())
            if time.monotonic() >= deadline:
                raise TimeoutError("exchange deadline exhausted")
            if reply.mtype == aiocoap.ACK and reply.mid != packet.mid:
                continue
            # Notifications already queued before cancellation share its token.
            # Acknowledge them, but require a non-Observe cancellation response.
            if packet.opt.observe == 1 and reply.opt.observe is not None:
                continue
            if reply.token == packet.token and reply.code.is_response():
                return reply
        raise TimeoutError("finite response deadline or packet budget exhausted")

    def count(self):
        reply = self.exchange(self.request("effects"))
        assert reply.code == aiocoap.CONTENT and len(reply.payload) == 4
        return int.from_bytes(reply.payload, "big")


def duplicate_effects(peer):
    before = peer.count()
    packet = peer.request("echo", aiocoap.POST, b"finite duplicate effect")
    first = peer.exchange(packet)
    second = peer.exchange(packet)  # Same socket, MID, token and complete wire.
    assert first.code == second.code == aiocoap.CONTENT
    assert first.payload == second.payload == packet.payload
    after = peer.count()
    assert (after - before) % (1 << 32) == 1
    return {"before": before, "after": after, "identical_requests": 2}


def observe_capacity(peer):
    tokens = [secrets.token_bytes(8) for _ in range(3)]
    try:
        for token in tokens[:2]:
            reply = peer.exchange(peer.request("ticks", token=token, observe=0))
            assert reply.code == aiocoap.CONTENT and reply.opt.observe is not None
        refused = peer.exchange(peer.request("ticks", token=tokens[2], observe=0))
        # RFC 7641 registration refusal returns the representation without Observe.
        assert refused.code == aiocoap.CONTENT and refused.opt.observe is None
        cancelled = peer.exchange(peer.request("ticks", token=tokens[0], observe=1))
        assert cancelled.code == aiocoap.CONTENT and cancelled.opt.observe is None
        reused = peer.exchange(peer.request("ticks", token=tokens[2], observe=0))
        assert reused.code == aiocoap.CONTENT and reused.opt.observe is not None
        return {"capacity": 2, "third_registration_refused": True, "released_slot_reused": True}
    finally:
        # Best-effort bounded teardown; failures remain failures in the receipt.
        primary = sys.exception()
        failures = []
        for token in tokens:
            try:
                reply = peer.exchange(peer.request("ticks", token=token, observe=1))
                assert reply.code == aiocoap.CONTENT and reply.opt.observe is None
            except Exception as error:
                failures.append(type(error).__name__ + ": " + str(error))
        if failures:
            detail = "Observe teardown: " + "; ".join(failures)
            if primary is not None:
                primary.add_note(detail)
            else:
                raise RuntimeError(detail)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=5683)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--case", choices=["duplicate-effects", "observe-capacity"], required=True)
    args = parser.parse_args()
    result = {"schema": "coaptic-device-recovery/1", "security": "unprotected",
              "case": args.case, "run_id": args.run_id, "passed": False}
    with open(args.output, "x", encoding="utf-8") as report:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
                channel.connect((args.host, args.port))
                peer = Peer(channel, args.host, args.port)
                identity = peer.exchange(peer.request("identity"))
                assert identity.code == aiocoap.CONTENT and identity.payload == args.run_id.encode("ascii")
                result["observations"] = (duplicate_effects if args.case == "duplicate-effects" else observe_capacity)(peer)
                result["passed"] = True
        except BaseException as error:
            result["error"] = type(error).__name__ + ": " + str(error)
            result["notes"] = getattr(error, "__notes__", [])
            raise
        finally:
            json.dump(result, report, indent=2)
            report.write("\n")


if __name__ == "__main__":
    main()
