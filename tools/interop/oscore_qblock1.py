"""Finite fixture-key OSCORE Q-Block1 evidence, authenticated with aiocoap.

This is an offline oracle and existing-process campaign, not a security provider.
The key material is the public RFC 8613 C.1 fixture used by both peer programs.
"""
import importlib.metadata
import json

import aiocoap
from aiocoap import oscore
from aiocoap.message import Direction


class FixtureContext(oscore.CanProtect, oscore.CanUnprotect, oscore.SecurityContextUtils):
    def __init__(self, *, server, wrong_key=False, sequence=0):
        self.alg_aead = oscore.algorithms["AES-CCM-16-64-128"]
        self.hashfun = oscore.hashfunctions["sha256"]
        self.sender_id, self.recipient_id = (b"\x01", b"") if server else (b"", b"\x01")
        self.id_context = None
        self.sender_sequence_number = sequence
        self.echo_recovery = None
        self.recipient_replay_window = oscore.ReplayWindow(64, lambda: None)
        self.recipient_replay_window.initialize_empty()
        secret = bytes([0xFE if wrong_key else 1, *range(2, 17)])
        self.derive_keys(bytes.fromhex("9e7ca92223786340"), secret)

    def post_seqnoincrease(self):
        pass


def require(ok, reason):
    if not ok:
        raise AssertionError(reason)


def incoming(wire):
    message = aiocoap.Message.decode(wire)
    message.direction = Direction.INCOMING
    return message


def request_plain(wire, *, wrong_key=False):
    # Fresh decoding contexts are intentional for offline retransmission traces.
    # The grader separately requires exact ciphertext for a repeated MID/PIV.
    try:
        return FixtureContext(server=True, wrong_key=wrong_key).unprotect(incoming(wire))
    except Exception as error:
        raise AssertionError("request authentication failed") from error


def response_plain(wire, request):
    try:
        _, binding = request_plain(request)
        return FixtureContext(server=False).unprotect(incoming(wire), binding)[0]
    except Exception as error:
        raise AssertionError("response authentication/request binding failed") from error


def final_response(wire, trace):
    """Relay classifier: drop only an authenticated Created reply, never an ACK."""
    from run import packet_token
    if len(wire) < 5 or wire[1] == 0:
        return False
    candidates = [bytes.fromhex(row["hex"]) for row in trace
                  if row["direction"] == "request" and row["action"] == "forward"
                  and len(bytes.fromhex(row["hex"])) > 4]
    require(candidates, "protected reply without a request")
    request = candidates[-1]
    require((wire[0] >> 4) & 3 == 0 and packet_token(wire) == packet_token(request),
            "protected reply owner mismatch")
    return int(response_plain(wire, request).code) == 65


def _counts(event):
    from run import expect
    expect(event, 69, None)
    raw = bytes.fromhex(event["payload_hex"])
    require(len(raw) <= 16 and raw.count(b":") == 1, "invalid effect readback")
    fields = raw.split(b":")
    require(all(x.isdigit() for x in fields), "invalid effect counters")
    return tuple(map(int, fields))


def _endpoint(value, family):
    require(family in ("ipv4", "ipv6"), "unsupported protected address family")
    ipv6 = family == "ipv6"
    require(isinstance(value, (list, tuple)) and len(value) == (4 if ipv6 else 2)
            and value[0] == ("::1" if ipv6 else "127.0.0.1")
            and type(value[1]) is int and 0 < value[1] < 65536
            and (not ipv6 or all(type(part) is int and part == 0 for part in value[2:])),
            "not exact loopback endpoint with zero flow/scope")
    return tuple(value)


def _relay_endpoints(relay, family):
    import socket
    endpoints = {"front": list(relay.front.getsockname()), "back": list(relay.back.getsockname()),
                 "server": list(relay.dest)}
    if family == "ipv6":
        endpoints["family"] = "AF_INET6" if relay.front.family == relay.back.family == socket.AF_INET6 else "wrong"
        endpoints["v6only"] = [sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY)
                               for sock in (relay.front, relay.back)]
    return endpoints


def grade(trace, result, endpoints, before, after, mode, *, family="ipv4"):
    from run import LARGE, decoded_options, packet_token, block1_fields, coap_payload, expect, expect_refusal
    require(mode in ("baseline", "drop-request", "drop-once", "drop-permanent", "wrong-key"), "unknown schedule")
    wrong = mode == "wrong-key"
    timeout = mode in ("drop-permanent", "wrong-key")
    if timeout:
        expect_refusal(result)
    else:
        expect(result, 65, b"")
    prior, current = _counts(before), _counts(after)
    require(prior[0] == prior[1], "unexpected prior handler count")
    require(current == tuple(n + int(not wrong) for n in prior), "handler effect mismatch")
    require(1 <= len(trace) <= 256, "trace outside finite bound")

    require(family in ("ipv4", "ipv6"), "unsupported protected address family")
    if family == "ipv6":
        only = endpoints.get("v6only")
        require(endpoints.get("family") == "AF_INET6" and isinstance(only, list)
                and len(only) == 2 and all(type(value) is int and value == 1 for value in only),
                "relay sockets not proven IPv6-only")
    def endpoint(value):
        return _endpoint(value, family)

    front, back, server = (endpoint(endpoints[k]) for k in ("front", "back", "server"))
    client = endpoint(trace[0]["source"])
    require(len({front, back, server, client}) == 4, "overlapping endpoint owners")
    unique, pivs = {}, set()
    body = bytearray()
    latest = None
    acknowledged = True
    token = szx = None
    previous_time = -1
    request_retries = dropped = final_forwarded = final_seen = 0
    retry_intervals = []
    lost_request = None
    lost_request_at = None
    request_loss_retries = 0
    response_wire = None
    response_first_at = None
    response_retries = client_acks = 0
    decryption_refusals = 0
    first_time = {}
    for row in trace:
        direction, action = row["direction"], row["action"]
        require(direction in ("request", "response") and action in ("forward", "drop"),
                "unsupported trace action")
        expected = (client, server, back) if direction == "request" else (server, client, front)
        require(tuple(endpoint(row[k]) for k in ("source", "destination", "relay")) == expected,
                "trace endpoint owner mismatch")
        at = row["time_ns"]
        require(type(at) is int and at >= 0 and at >= previous_time, "unordered capture time")
        previous_time = at
        require(at - trace[0]["time_ns"] <= 8_000_000_000, "capture exceeds bounded request interval")
        require(row["forwarded_hex"] == row["hex"], "relay modified bytes")
        wire = bytes.fromhex(row["hex"])
        require(4 <= len(wire) <= 4096 and wire[0] >> 6 == 1 and wire[0] & 15 <= 8,
                "malformed bounded CoAP packet")
        if direction == "request":
            if wire[1] == 0:
                require(response_wire is not None and final_forwarded == 1 and client_acks == 0
                        and wire == b"\x60\x00" + response_wire[2:4] and action == "forward",
                        "missing or wrong separate-response ACK ownership")
                client_acks += 1
                continue
            if action == "drop":
                require(mode == "drop-request" and lost_request is None and latest is None,
                        "unexpected request loss")
                request_plain(wire)  # The relay loss is an intact authenticated request.
                lost_request, lost_request_at = wire, at
                continue
            if lost_request is not None and latest is None:
                require(wire == lost_request and at - lost_request_at >= 1_950_000_000,
                        "lost request did not retry exact bytes after its RTO")
                request_loss_retries += 1
            require(action == "forward" and (wire[0] >> 4) & 3 == 0 and wire[1] == 2,
                    "request not forwarded CON POST")
            require(not final_forwarded, "request after completed response")
            if wire in unique:
                require(wire == latest and not acknowledged, "retry changed or settled request ownership")
                request_retries += 1
                interval = at - first_time[wire]
                require(interval >= 1_950_000_000, "request retry before original RTO")
                retry_intervals.append(interval)
                continue
            require(acknowledged, "new CON before previous exact-owner ACK")
            require(wire[2:4] not in {old[2:4] for old in unique}, "MID reused with changed ciphertext")
            outer = decoded_options(wire)
            require(set(outer) == {9} and len(outer[9]) == 1, "unexpected outer options")
            if wrong:
                try:
                    request_plain(wire)
                except AssertionError:
                    pass
                else:
                    raise AssertionError("wrong-key request authenticated with correct key")
            plain, binding = request_plain(wire, wrong_key=wrong)
            piv = bytes(binding.partial_iv)
            require(piv not in pivs, "PIV reused for different request bytes")
            pivs.add(piv)
            options = {}
            for option in plain.opt.option_list():
                options.setdefault(int(option.number), []).append(option.encode())
            require(int(plain.code) == 2 and set(options) == {11, 12, 19, 60, 292}
                    and options[11] == [b"upload"] and options[12] == [b"*"]
                    and options[60] == [b"\x07\xd0"] and options[292] == [b"upload-1"]
                    and len(options[19]) == 1, "authenticated inner Q-Block1/options mismatch")
            num, more, current_szx = block1_fields(options[19][0])
            require(0 <= current_szx <= 6, "invalid inner block size")
            size = 1 << (current_szx + 4)
            require(num * size == len(body) and (szx is None or szx == current_szx),
                    "inner block gap/reorder/size change")
            expected_body = LARGE[len(body):len(body) + size]
            require(plain.payload == expected_body and bool(more) == (len(body) + len(expected_body) < len(LARGE)),
                    "inner complete-body slice mismatch")
            require(token is None or token == packet_token(wire), "upload token changed")
            require(packet_token(wire), "missing upload token")
            token, szx = packet_token(wire), current_szx
            body.extend(plain.payload)
            unique[wire], first_time[wire], latest = num, at, wire
            acknowledged = False
        else:
            require(latest is not None, "response without a forwarded request")
            if wrong:
                # RFC8613 section8.2 step6 permits an unprotected Bad Request.
                # This pinned fixture emits exactly this diagnostic; it is not
                # authentication or an ACK that advances the protected upload.
                require(decryption_refusals == 0 and action == "forward"
                        and (wire[0] >> 4) & 3 == 2 and wire[1] == 128
                        and wire[2:4] == latest[2:4] and packet_token(wire) == token
                        and decoded_options(wire) == {14: [b""]}
                        and coap_payload(wire) == b"Decryption failed",
                        "unexpected unauthenticated rejection response")
                decryption_refusals += 1
                continue
            if wire[1] == 0:
                require(wire == b"\x60\x00" + latest[2:4] and action == "forward",
                        "invalid or dropped exact-owner empty ACK")
                acknowledged = True
                continue
            require(acknowledged and (wire[0] >> 4) & 3 == 0
                    and packet_token(wire) == token and set(decoded_options(wire)) == {9},
                    "separate response type/token/protection or request settlement mismatch")
            # RFC 7252 sections 4.4/4.5 scope MIDs by sender endpoint.
            # A separate server response may reuse a numeric client-request MID.
            plain = response_plain(wire, latest)
            require(int(plain.code) == 65 and plain.payload == b"", "wrong authenticated Created")
            require(bytes(body) == LARGE, "Created before exact complete body")
            if response_wire is None:
                response_wire, response_first_at = wire, at
            else:
                require(wire == response_wire and dropped and not final_forwarded
                        and at - response_first_at >= 1_950_000_000,
                        "separate response retry changed bytes/ownership or preceded RTO")
                response_retries += 1
            final_seen += 1
            if action == "drop":
                dropped += 1
            else:
                final_forwarded += 1
    if wrong:
        require(len(unique) == 1 and len(body) < len(LARGE) and not final_seen
                and decryption_refusals == 1,
                "wrong-key request advanced upload")
    else:
        require(bytes(body) == LARGE and len(unique) >= 2 and final_seen >= 1,
                "missing authenticated fragmented upload completion")
    require(client_acks == (0 if timeout else 1), "separate response ACK absent or unexpected")
    if mode in ("baseline", "drop-request"):
        require(dropped == 0 and final_forwarded == 1, "baseline delivery mismatch")
        require(request_loss_retries == int(mode == "drop-request"), "request loss/recovery not exercised")
    elif mode == "drop-once":
        require(dropped == 1 and final_forwarded == 1 and response_retries >= 1,
                "one-loss recovery not exercised")
    elif mode == "drop-permanent":
        require(dropped >= 2 and final_forwarded == 0 and response_retries >= 1,
                "permanent loss/timeout not exercised")
    return {"authenticated_inner_blocks": len(unique), "body_bytes_observed": len(body),
            "exact_request_retries": request_retries, "request_loss_retries": request_loss_retries, "exact_response_retries": response_retries,
            "exact_client_acks": client_acks, "unprotected_decryption_refusals": decryption_refusals, "retry_intervals_ns": retry_intervals,
            "dropped_authenticated_created": dropped, "effect_before": prior, "effect_after": current,
            "client_outcome": "timeout; independently observed one application effect" if mode == "drop-permanent"
                              else "wrong-key refusal" if wrong else "complete Created",
            "decoder": "aiocoap " + importlib.metadata.version("aiocoap")}


MODES = ("baseline", "drop-request", "drop-once", "drop-permanent", "wrong-key", "baseline")


def campaign_review(record, *, family="ipv4"):
    """Reauthenticate six captured uploads, exact outcomes and fresh same-server recovery."""
    from run import expect_refusal
    require(record.get("family") == family, "campaign address family changed")
    ready = record["server_ready"]
    require(ready.get("transport") == "oscore", "server not protected")
    server = _endpoint(("::1", ready["port"], 0, 0) if family == "ipv6"
                       else ("127.0.0.1", ready["port"]), family)
    schedules = record["schedules"]
    require(len(schedules) == len(MODES), "incomplete six-schedule campaign")
    bindings, first_bindings = set(), []
    effects = (0, 0)
    for index, (case, mode) in enumerate(zip(schedules, MODES)):
        sequence = 200 + index * 300
        require(case["mode"] == mode and type(case["sequence_start"]) is int
                and case["sequence_start"] == sequence, "changed campaign order/sequence")
        require(_endpoint(case["endpoints"]["server"], family) == server, "server changed during recovery")
        result, trace = case["result"], case["trace"]
        proof = grade(trace, result, case["endpoints"], case["before"], case["after"], mode, family=family)
        require(json.dumps(proof, sort_keys=True) == json.dumps(case["proof"], sort_keys=True),
                "retained proof differs from actual trace")
        require(_counts(case["before"]) == effects, "effect history changed between schedules")
        effects = _counts(case["after"])
        host_ns = result.get("host_total_ns")
        require(type(host_ns) is int and 0 <= host_ns <= 10_500_000_000
                and trace[-1]["time_ns"] - trace[0]["time_ns"] <= host_ns,
                "missing bounded host duration or trace exceeds process lifetime")
        if mode in ("drop-permanent", "wrong-key"):
            expect_refusal(result)
            require(result.get("message") == "request timed out" and "code" not in result
                    and not result.get("payload_hex"), "not exact protocol timeout without response")
            require(host_ns >= (650_000_000 if mode == "wrong-key" else 6_450_000_000), "premature timeout")
        seen = set()
        for row in trace:
            wire = bytes.fromhex(row["hex"])
            if row["direction"] != "request" or wire[1] == 0 or wire in seen:
                continue
            _, binding = request_plain(wire, wrong_key=mode == "wrong-key")
            piv = bytes(binding.partial_iv)
            require(piv not in bindings, "request PIV reused between uploads")
            value = int.from_bytes(piv, "big")
            # A full-body sizing attempt may consume a PIV before Block1 fallback.
            # Bind actual upload requests to the caller's disjoint finite range.
            require(sequence <= value < sequence + 100, "request outside reserved upload sequence range")
            if not seen:
                first_bindings.append(value)
            bindings.add(piv)
            seen.add(wire)
    require(effects == (5, 5) and _counts(record["final_readback"]) == effects,
            "final independent effect readback differs")
    return {"same_server": list(server), "schedules": list(MODES), "fresh_upload_bindings": first_bindings,
            "distinct_request_pivs": len(bindings), "final_effect": list(effects),
            "fresh_recovery_body_bytes": schedules[-1]["proof"]["body_bytes_observed"],
            "scope": f"finite {family} loopback CON Q-Block1; no durable effects, enrollment, routed or sustained availability qualification"}


def workflow(client, server, *, family="ipv4", record=None, patch=None):
    from run import LARGE, Proxy, Server, request
    require(family in ("ipv4", "ipv6"), "unsupported protected address family")
    if record is None:
        record = {}
    record.update(family=family, schedules=[], complete=False,
                  limits=f"finite {family} loopback fixture; no enrollment or sustained availability",
                  libcoap_source="851533c3cf63d16984d370ce39d586ecb3694971")
    sequence = 0
    with Server(server, "oscore", family=family) as service:
        record["server_ready"] = service.ready
        if patch is not None:
            require(service.ready.get("libcoap_patch_sha256") == patch["patch_sha256"],
                    "server binary does not identify expected dependency patch")
        def exchange(**kwargs):
            nonlocal sequence
            sequence += 100
            return request(client, "oscore", kwargs.pop("port", service.number), sequence=sequence,
                           family=family, **kwargs)

        for mode, fault in zip(MODES, ("pass", "drop-oscore-request-once", "drop-oscore-final-once",
                                       "drop-oscore-final-permanent", "pass", "pass")):
            current = {"mode": mode, "sequence_start": sequence + 200}
            record["schedules"].append(current)
            current["before"] = exchange(path="upload")
            relay = Proxy(service.number, fault, family=family)
            try:
                with relay:
                    current["endpoints"] = _relay_endpoints(relay, family)
                    current["result"] = exchange(port=relay.number, path="upload", method="POST", payload=LARGE,
                                                  timeout=6500 if mode != "wrong-key" else 700,
                                                  qblock1=True, key="incorrect" if mode == "wrong-key" else "sesame")
                current["after"] = exchange(path="upload")
                current["trace"] = relay.trace
                current["proof"] = grade(relay.trace, current["result"], current["endpoints"],
                                          current["before"], current["after"], mode, family=family)
            except (AssertionError, RuntimeError) as error:
                # The relay context has joined before retaining its final trace.
                current["trace"] = relay.trace
                raise AssertionError(json.dumps({"error": str(error), "completed": record["schedules"][:-1],
                                                 "failed": current})) from error
        record["final_readback"] = exchange(path="upload")
    record["proof"] = campaign_review(record, family=family)
    record["complete"] = True
    return record


def main():
    import argparse
    import hashlib
    import platform
    from pathlib import Path
    from run import source_identity
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coaptic", required=True, type=Path)
    parser.add_argument("--libcoap", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--family", choices=("ipv4", "ipv6"), default="ipv4")
    parser.add_argument("--libcoap-patch-manifest", required=True, type=Path)
    args = parser.parse_args()
    peers = {"coaptic": args.coaptic.resolve(), "libcoap": args.libcoap.resolve()}
    patch = json.loads(args.libcoap_patch_manifest.read_text(encoding="utf-8"))
    report = {"schema": "coaptic-protected-qblock1-campaign/1", **source_identity(),
              "family": args.family, "platform": platform.platform(), "libcoap_patch": patch, "qualification_complete": False,
              "executables": {name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                              for name, path in peers.items()}, "campaign": {}}
    try:
        workflow(peers["coaptic"], peers["libcoap"], family=args.family, record=report["campaign"], patch=patch)
        report["qualification_complete"] = True
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"qualification_complete": report["qualification_complete"], "report": str(args.output)}))
    return 0 if report["qualification_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
