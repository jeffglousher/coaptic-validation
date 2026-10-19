"""Finite UDP relay: lose one reply, inject malformed/unmatched input, recover."""
import argparse
import json
import selectors
import socket
import time


def require(condition, message):
    if not condition:
        raise ValueError(message)


def emit(**value):
    print(json.dumps(value), flush=True)


def grade(rows):
    requests = [row for row in rows if row["event"] == "request"]
    responses = [row for row in rows if row["event"] == "response"]
    injections = [row for row in rows if row["event"] == "inject"]
    require(len(requests) == 3 and len(responses) == 3 and len(injections) == 2,
            "schedule count differs")
    require(requests[0]["hex"] == requests[1]["hex"] and requests[0]["peer"] == requests[1]["peer"],
            "retransmission changed bytes or owner")
    require(requests[2]["hex"] != requests[0]["hex"], "fresh request reused old bytes")
    require([row["action"] for row in responses] == ["drop", "forward", "forward"],
            "first reply loss not exercised")
    require(injections[0]["hex"] == "00", "malformed injection differs")
    initial = bytes.fromhex(responses[0]["hex"])
    changed = bytearray(initial)
    require(initial[0] & 15 == 8 and len(initial) >= 12, "expected compact eight-byte token")
    changed[4] ^= 1
    require(injections[1]["hex"] == changed.hex(), "unmatched reply mutation differs")
    for request, response in zip(requests, responses):
        req, reply = bytes.fromhex(request["hex"]), bytes.fromhex(response["hex"])
        require(req[:2] == b"H\x01" and reply[:2] == b"hE", "expected CON GET and ACK Content")
        require(req[2:12] == reply[2:12], "response MID/token mismatch")
    return {"dropped_replies":1, "malformed_injections":1, "unmatched_token_injections":1,
            "identical_retransmission":True, "fresh_exchange":True}


def run(args):
    remote = (args.remote, 56830, 0, 0)
    rows = []
    def record(row):
        require(len(rows) < 16, "finite relay trace exhausted")
        rows.append(row)
        emit(**row)
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as front, \
         socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as back, selectors.DefaultSelector() as selector:
        front.bind((args.front,56831,0,0))
        back.bind((args.back,0,0,0))
        selector.register(front,selectors.EVENT_READ,"front")
        selector.register(back,selectors.EVENT_READ,"back")
        emit(event="ready",front=front.getsockname(),back=back.getsockname(),remote=remote)
        client, first, replies = None, None, 0
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            for key, _ in selector.select(min(0.1,max(0,deadline-time.monotonic()))):
                wire, peer = key.fileobj.recvfrom(1153)
                require(len(wire) <= 1152, "oversized relay datagram")
                require(len(rows) < 16, "finite relay trace exhausted")
                if key.data == "front":
                    if first is None:
                        first = wire
                    if replies < 2 and client is not None:
                        require(peer == client and wire == first, "outstanding exchange changed")
                    client = peer
                    record(dict(event="request",peer=peer,hex=wire.hex(),action="forward"))
                    back.sendto(wire,remote)
                else:
                    require(peer == remote and client is not None, "unexpected server/owner")
                    replies += 1
                    record(dict(event="response",peer=peer,hex=wire.hex(),action="drop" if replies == 1 else "forward"))
                    if replies == 1:
                        require(wire[0] & 15 == 8 and len(wire) >= 12, "expected compact response token")
                        changed = bytearray(wire)
                        changed[4] ^= 1
                        for malformed in (b"\x00",bytes(changed)):
                            front.sendto(malformed,client)
                            record(dict(event="inject",peer=client,hex=malformed.hex()))
                    else:
                        front.sendto(wire,client)
                    if replies == 3:
                        result = grade(rows)
                        emit(event="complete",trace=rows,result=result)
                        return
        raise ValueError("bounded compound relay deadline")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("front","back","remote"):
        parser.add_argument("--"+option,required=True)
    args = parser.parse_args()
    try:
        run(args)
        return 0
    except Exception as error:
        emit(event="error",message=repr(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
