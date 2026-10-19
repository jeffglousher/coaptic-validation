"""Finite same-endpoint selected Observe controls, independent Python wire client."""
import socket
import time

from run import coap_message, coap_payload, decoded_options, packet_token


def require(value, message):
    if not value:
        raise AssertionError(message)


class Channel:
    def __init__(self, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.peer = ("127.0.0.1", port)
        self.trace = []
        self.mid = 12000

    def record(self, direction, wire):
        require(len(self.trace) < 192 and len(wire) <= 1472, "control trace/datagram bound")
        self.trace.append({"direction": direction, "hex": wire.hex(),
                           "local": list(self.socket.getsockname()), "peer": list(self.peer),
                           "time_ns": time.perf_counter_ns()})

    def send(self, code, token, options, payload=b""):
        self.mid += 1
        wire = coap_message(code, self.mid, token, sorted(options), payload)
        self.record("send", wire)
        require(self.socket.sendto(wire, self.peer) == len(wire), "incomplete control send")
        return wire

    def receive(self, timeout=2):
        self.socket.settimeout(timeout)
        wire, source = self.socket.recvfrom(1473)
        require(source == self.peer and 4 <= len(wire) <= 1472, "foreign/truncated control reply")
        self.record("receive", wire)
        if (wire[0] >> 4) & 3 == 0:
            ack = b"\x60\x00" + wire[2:4]
            self.record("send", ack)
            require(self.socket.sendto(ack, self.peer) == 4, "incomplete ACK")
        return wire

    def response(self, request, code=None, timeout=3):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            wire = self.receive(max(.001, end - time.monotonic()))
            if wire[1] == 0:
                continue
            require(packet_token(wire) == packet_token(request), "unexpected response owner")
            if (wire[0] >> 4) & 3 == 2:
                require(wire[2:4] == request[2:4], "wrong piggyback MID")
            if code is not None:
                require(wire[1] == code, "unexpected response code")
            return wire
        raise AssertionError("control response deadline")

    def quiet(self, forbidden, duration=.3):
        end = time.monotonic() + duration
        while time.monotonic() < end:
            try:
                wire = self.receive(max(.001, end - time.monotonic()))
            except socket.timeout:
                return
            require(packet_token(wire) not in forbidden, "cancelled selection still notified")


def grade_changed_selection(wire, strict_refusal):
    options = decoded_options(wire)
    require(6 not in options, "changed selection retained Observe")
    if strict_refusal:
        require(wire[1] == 128, "core changed-selection refusal changed")
        return {"behavior": "retained-selection-refused", "code": 128}
    require(wire[1] == 69 and coap_payload(wire) == b"m" * 32,
            "native independent right read changed bytes/code")
    require(options.get(23) == [b"\x19"], "native right read changed NUM1/M/SZX")
    require(options.get(12) == [b""], "native right read changed Content-Format")
    require(4 not in options or options[4] == [b"\x03"], "native right read changed ETag")
    # The lifecycle must still prove the original left observer survives.
    return {"behavior": "independent-right-read", "code": 69,
            "etag_hex": [v.hex() for v in options.get(4, [])], "block2": 25}


def selected_lifecycle(port, selection, captures=None, strict_refusal=True):
    """One origin, two retained selectors, invalid replacement, exact cancel/fresh.

    The Python client is a distinct control peer, not a claim that a native CLI
    exposes its own cancellation API. Its source/endpoint/bytes are all retained.
    """
    require(selection in ("query", "fetch"), "unknown selected lifecycle")
    channel = Channel(port)
    if captures is not None:
        captures.append(channel.trace)
    method = 1 if selection == "query" else 5

    def options(pick, observe):
        value = [(6, b"" if observe == 0 else b"\x01"), (11, b"obs-selected")]
        if selection == "query":
            value.append((15, b"pick=" + pick))
        else:
            value.append((12, b"*"))
        return value

    def send(pick, token, observe=0):
        return channel.send(method, token, options(pick, observe), pick if method == 5 else b"")

    def representation(wire, expected, observed=True):
        require(wire[1] == 69 and coap_payload(wire) == expected * 96, "wrong complete selected bytes")
        require((6 in decoded_options(wire)) == observed, "registration/cancellation Observe mismatch")

    try:
        for pick, token, body in ((b"left", b"left", b"a"), (b"right", b"rght", b"m")):
            representation(channel.response(send(pick, token), 69), body)
        # Malformed selector reuses the first relation's exact endpoint/token.
        bad = channel.response(send(b"invalid", b"left"))
        require(bad[1] >= 128 and 6 not in decoded_options(bad), "invalid selector accepted")
        # Re-registration establishes the explicit owner after a terminal error;
        # no assumption that an error leaves that prior relation alive.
        representation(channel.response(send(b"left", b"left"), 69), b"a")
        # Core refuses a changed retained selector. Native may answer a separate
        # right read; neither may change the original left Observe relation.
        changed_options = [item for item in options(b"right", 0) if item[0] != 6]
        changed_options.append((23, b"\x11"))
        changed = channel.send(method, b"left", changed_options, b"right" if method == 5 else b"")
        followup = channel.response(changed)
        changed_result = grade_changed_selection(followup, strict_refusal)
        post = channel.send(2, b"post", [(11, b"obs-selected")])
        # RFC7641 same-endpoint NON spacing is 3s; allow the second owner
        # to become due without relaxing response/refusal or Q-window deadlines.
        got = set()
        while len(got) < 3:
            wire = channel.receive(timeout=4)
            token = packet_token(wire)
            require(token not in got, "duplicate selected progress")
            if token == b"post":
                require(wire[1] == 68 and wire[2:4] == post[2:4], "mutation ACK mismatch")
            else:
                require(token in (b"left", b"rght"), "foreign notification")
                representation(wire, b"b" if token == b"left" else b"n")
            got.add(token)
        representation(channel.response(send(b"left", b"left", 1), 69), b"b", False)
        post = channel.send(2, b"next", [(11, b"obs-selected")])
        got = set()
        while len(got) < 2:
            wire = channel.receive(timeout=4)
            token = packet_token(wire)
            require(token not in got and token in (b"next", b"rght"), "retired/foreign notification")
            if token == b"next":
                require(wire[1] == 68 and wire[2:4] == post[2:4], "fresh mutation ACK mismatch")
            else:
                representation(wire, b"o")
            got.add(token)
        channel.quiet({b"left"})
        representation(channel.response(send(b"left", b"fresh"), 69), b"c")
        return {"peer": "independent Python wire control", "selection": selection,
                "changed_selection": changed_result, "trace": channel.trace, "passed": True}
    finally:
        channel.socket.close()


def q_initial_representation(channel, token):
    """M1 requests a complete representation, unlike single-block M0."""
    pending = channel.send(1, token, [(6, b""), (11, b"obs-q"), (31, b"\x09")])
    chunks = []
    sequence = None
    etag = None
    train_kind = None
    while len(chunks) < 22:
        wire = channel.receive()
        kind = (wire[0] >> 4) & 3
        if wire[1] == 0:
            require(wire == b"\x60\x00" + pending[2:4], "Q initial foreign empty control")
            continue
        require(packet_token(wire) == token and wire[1] == 69 and kind in (0, 1, 2),
                "Q initial owner/code/type changed")
        if kind == 2:
            require(wire[2:4] == pending[2:4], "Q initial ACK MID changed")
        if kind != 2:
            if train_kind is None:
                train_kind = kind
            require(kind == train_kind, "Q initial changed CON/NON train")
        options = decoded_options(wire)
        require(len(options.get(31, [])) == 1, "Q initial block missing")
        block = int.from_bytes(options[31][0], "big")
        index = block >> 4
        require(index == len(chunks) and block & 7 == 1 and bool(block & 8) == (index < 21),
                "Q initial NUM/M/SZX changed")
        require(coap_payload(wire) == b"a" * 32 and options.get(28) == [b"\x02\xc0"],
                "Q initial bytes/Size2 changed")
        if not chunks:
            require(len(options.get(6, [])) == 1 and len(options.get(4, [])) == 1 and
                    1 <= len(options[4][0]) <= 8, "Q initial epoch/ETag missing or invalid")
            sequence, etag = options[6], options[4]
        require(options.get(4) == etag and options.get(6) == sequence,
                "Q initial representation identity changed")
        chunks.append(coap_payload(wire))
        # ACKing each CON drives its train. Only a NON window needs a pull.
        if kind == 1 and len(chunks) in (10, 20):
            value = (len(chunks) << 4) | 9
            encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
            pending = channel.send(1, token, [(11, b"obs-q"), (31, encoded)])
    require(b"".join(chunks) == b"a" * 704, "Q initial body incomplete")
    return sequence[0], etag


def q_recovery_lifecycle(port, captures=None):
    """Exact retained final-window recovery and next epoch, Python wire client."""
    channel = Channel(port)
    if captures is not None:
        captures.append(channel.trace)
    token = b"qobs"
    try:
        initial_sequence, _ = q_initial_representation(channel, token)

        def epoch(number, letter):
            post = channel.send(2, b"post", [(11, b"obs-q")])
            accepted = False
            chunks = {}
            sequence = None
            etag = None
            while len(chunks) < 22 or not accepted:
                # Initial NON delivery can hold this endpoint for 3s. Once a
                # CON train starts, keep the ordinary per-block deadline.
                wire = channel.receive(timeout=4 if not chunks else 2)
                if packet_token(wire) == b"post":
                    require(not accepted and wire[1] == 68 and wire[2:4] == post[2:4], "Q mutation ACK")
                    accepted = True
                    continue
                require(packet_token(wire) == token and wire[1] == 69 and (wire[0] >> 4) & 3 == 0,
                        "Q CON owner/type changed")
                options = decoded_options(wire)
                require(len(options.get(31, [])) == 1 and len(options.get(6, [])) == 1,
                        "Q notification lacks block/epoch")
                value = int.from_bytes(options[31][0], "big")
                index = value >> 4
                require(index == len(chunks) and value & 7 == 1 and bool(value & 8) == (index < 21),
                        "Q ACK progression skipped/changed block")
                require(coap_payload(wire) == letter * 32 and options.get(28) == [b"\x02\xc0"],
                        "Q body/Size2 changed")
                current_sequence = options[6][0]
                current_etag = options.get(4)
                require(current_etag is not None and len(current_etag) == 1 and
                        1 <= len(current_etag[0]) <= 8, "Q epoch has invalid ETag")
                if sequence is None:
                    sequence, etag = current_sequence, current_etag
                require(sequence == current_sequence and etag == current_etag, "Q epoch mixed representations")
                chunks[index] = coap_payload(wire)
            require(b"".join(chunks.values()) == letter * 704, "incomplete Q representation")
            return sequence, etag

        first_sequence, etag = epoch(1, b"b")
        delta = (int.from_bytes(first_sequence, "big") - int.from_bytes(initial_sequence, "big")) % (1 << 24)
        require(0 < delta < 1 << 23, "Q first notification did not advance")
        # NUM20 and21 occupy one configured10-block MAX_PAYLOADS_SET. No Observe
        # on missing-block requests or replies. This checks retained bytes, not
        # an invented immediate packet-loss timer policy.
        # ETag is a cache validator, not a request identity: including it may
        # legitimately produce 2.03 without the missing bytes (RFC9177?4.4).
        missing = channel.send(1, token, [(11, b"obs-q"),
                                         (31, b"\x01\x41"), (31, b"\x01\x51")])
        recovered = set()
        while len(recovered) < 2:
            wire = channel.receive()
            require(packet_token(wire) == token and wire[1] == 69, "Q recovery owner/code changed")
            options = decoded_options(wire)
            require(6 not in options and options.get(4) == etag, "Q recovery changed epoch identity")
            require(len(options.get(31, [])) == 1, "Q recovery missing block")
            block = int.from_bytes(options[31][0], "big")
            index = block >> 4
            require(index in (20, 21) and index not in recovered and block & 7 == 1 and
                    bool(block & 8) == (index < 21) and options.get(28) == [b"\x02\xc0"] and
                    coap_payload(wire) == b"b" * 32, "Q recovery escaped selected set")
            recovered.add(index)
        channel.quiet({token})
        next_sequence, _ = epoch(2, b"c")
        delta = (int.from_bytes(next_sequence, "big") - int.from_bytes(first_sequence, "big")) % (1 << 24)
        require(0 < delta < 1 << 23, "Q next epoch did not advance")
        cancel = channel.send(1, token, [(6, b"\x01"), (11, b"obs-q")])
        reply = channel.response(cancel, 69)
        require(6 not in decoded_options(reply), "Q cancellation retained registration")
        fresh = channel.send(1, b"frsh", [(11, b"test")])
        require(coap_payload(channel.response(fresh, 69)) == b"core-test-payload", "Q fresh recovery failed")
        return {"peer": "independent Python wire control", "max_payloads": 10,
                "body_bytes": 704, "trace": channel.trace, "passed": True}
    finally:
        channel.socket.close()
