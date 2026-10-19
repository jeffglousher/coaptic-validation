"""Characterize duplicate side effects in named alternative-server fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import time

from run import (BODY, Server, Proxy, request, expect, decoded_options,
                 coap_payload, packet_token)
from source_identity import source_identity, SUITE


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def grade_exchange(trace, method, path, code, body, duplicate=False):
    require(0 < len(trace) <= 256, "missing or excessive capture")
    requests = [row for row in trace if row["direction"] == "request"]
    replies = [row for row in trace if row["direction"] == "response"]
    require(len(requests) == 1, "unexpected client retransmission or extra operation")
    require(len(replies) == (2 if duplicate else 1), "wrong number of server responses")
    first = requests[0]
    packet = bytes.fromhex(first["hex"])
    require(packet[0] >> 6 == 1 and (packet[0] >> 4) & 3 == 0 and packet[1] == method,
            "wrong CON request")
    require(decoded_options(packet) == {11: [path]} and not coap_payload(packet),
            "wrong request target/options/body")
    require(first["action"] == ("duplicate" if duplicate else "forward"), "duplicate schedule not exercised")
    client, server = first["source"], first["destination"]
    relays, previous = {}, 0
    for row in trace:
        direction = row["direction"]
        require(direction in ("request", "response"), "unknown direction")
        for endpoint in (row["source"], row["destination"], row["relay"]):
            require(isinstance(endpoint, list) and len(endpoint) == 2 and endpoint[0] == "127.0.0.1"
                    and type(endpoint[1]) is int and 0 < endpoint[1] <= 65535, "wrong endpoint")
        require(row["source"] == (client if direction == "request" else server), "wrong sender")
        require(row["destination"] == (server if direction == "request" else client), "wrong receiver")
        require(row["hex"] == row["forwarded_hex"], "relay changed datagram bytes")
        require(row["time_ns"] >= previous, "capture clock regressed")
        previous = row["time_ns"]
        require(relays.setdefault(direction, row["relay"]) == row["relay"], "relay owner changed")
        if direction == "response":
            require(row["action"] == "forward", "response was changed or suppressed")
            reply = bytes.fromhex(row["hex"])
            require(reply[0] >> 6 == 1 and (reply[0] >> 4) & 3 == 2, "expected piggyback ACK")
            require(reply[2:4] == packet[2:4] and packet_token(reply) == packet_token(packet), "reply operation mismatch")
            require(reply[1] == code and coap_payload(reply) == body, "wrong response effect/body")
    require(len({tuple(client), tuple(server), *(tuple(item) for item in relays.values())}) == 4,
            "capture owners are not distinct")
    return {"server_peer": relays["request"], "mid": int.from_bytes(packet[2:4], "big"),
            "token": packet_token(packet).hex(), "request_hex": packet.hex(),
            "relay_sends": 2 if duplicate else 1}


def grade(record):
    checks = record["exchanges"]
    require(len(checks) == 6, "missing schedule phase")
    specs = ((1, b"counter", 69, b"0", False), (2, b"counter", 68, b"", True),
             (1, b"counter", 69, b"2", False), (2, b"counter", 68, b"", False),
             (1, b"counter", 69, b"3", False), (1, b"test", 69, BODY, False))
    identities = []
    for exchange, spec in zip(checks, specs):
        expect(exchange["result"], spec[2], spec[3])
        identities.append(grade_exchange(exchange["trace"], *spec))
    duplicate, fresh = identities[1], identities[3]
    require((duplicate["server_peer"], duplicate["mid"], duplicate["token"]) !=
            (fresh["server_peer"], fresh["mid"], fresh["token"]), "fresh POST reused the duplicate operation")
    require(duplicate["request_hex"] != fresh["request_hex"], "fresh POST did not use new wire identity")
    destinations = {tuple(exchange["trace"][0]["destination"]) for exchange in checks}
    require(len(destinations) == 1, "counter phases used different servers")
    return {"duplicate_effects": 2, "counter_after_fresh_post": 3,
            "fresh_get": True, "duplicate_suppression": "not present in this fixture execution",
            "claim": "characterization only; not a deduplication or whole-library RFC conformance pass",
            "duplicate_operation": duplicate, "fresh_operation": fresh}


def characterize(client, server, name):
    record = {"server": name, "exchanges": []}
    try:
        with Server(server, "udp") as service:
            record["ready"] = service.ready
            for path, method, mode in (("counter", "GET", "profiles"),
                                       ("counter", "POST", "duplicate-request"),
                                       ("counter", "GET", "profiles"),
                                       ("counter", "POST", "profiles"),
                                       ("counter", "GET", "profiles"),
                                       ("test", "GET", "profiles")):
                with Proxy(service.number, mode) as relay:
                    exchange = {"trace": relay.trace, "method": method, "path": path}
                    record["exchanges"].append(exchange)
                    exchange["result"] = request(client, "udp", relay.number, path=path, method=method)
                    if mode == "duplicate-request":
                        deadline = time.monotonic() + 1
                        while len([row for row in relay.trace if row["direction"] == "response"]) < 2:
                            require(time.monotonic() < deadline, "missing duplicate response")
                            require(not relay.error, "relay failed")
                            time.sleep(0.005)
            record["observed"] = grade(record)
            record["status"] = "characterized"
    except Exception as error:
        record["status"], record["error"] = "failed", repr(error)
    return record


def binaries(args, current):
    build = json.loads(args.build_record.read_text(encoding="utf-8"))
    require(not build["dirty"] and not build["suite_dirty"], "binary build record is dirty")
    peers = {"coap-rs": args.coap_rs, "libcoap": args.libcoap}
    for name, path in peers.items():
        require(hashlib.sha256(path.read_bytes()).hexdigest() == build["executables"][name]["sha256"], "binary hash changed since recorded build")
    # Reusing an identified peer is valid only while its fixture contract is unchanged.
    paths = ("crates/peer-coap-rs/src/main.rs", "crates/peer-coap-rs/Cargo.toml",
             "tools/interop/support.rs", "tools/interop/separate_listener.rs",
             "tools/interop/coap_dtls.rs", "tools/interop/dtls_listener.rs",
             "tools/interop/libcoap/peer.c", "tools/interop/libcoap/CMakeLists.txt")
    contracts = {}
    for path in paths:
        previous = subprocess.check_output(["git", "-C", str(SUITE), "show", build["suite_source"] + ":" + path])
        present = subprocess.check_output(["git", "-C", str(SUITE), "show", current["suite_source"] + ":" + path])
        require(previous == present, "peer contract changed; rebuild required: " + path)
        contracts[path] = hashlib.sha256(present).hexdigest()
    return {"build_record": build, "build_record_sha256": hashlib.sha256(args.build_record.read_bytes()).hexdigest(),
            "unchanged_fixture_contracts": contracts,
            "meaning": "Original exact binary/source pair reused; not rebuilt against the current core"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("coap-rs", "libcoap", "build-record", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    current = source_identity()
    require(not current["dirty"] and not current["suite_dirty"], "runner source must be clean")
    report = {"schema": "coaptic-alternative-duplicate-characterization/1", "runner_source": current,
              "platform": platform.platform(), "security": "unprotected", "address_family": "ipv4-loopback",
              "binary_provenance": binaries(args, current), "cases": [],
              "scope": "Named counter fixtures only; no protocol deduplication PASS or upstream whole-library claim"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def save():
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for name, server in (("coap-rs", args.coap_rs), ("libcoap", args.libcoap)):
        report["cases"].append(characterize(args.coap_rs, server, name))
        save()
    require(source_identity() == current, "runner sources changed during capture")
    report["characterized"] = sum(row["status"] == "characterized" for row in report["cases"])
    report["failed"] = len(report["cases"]) - report["characterized"]
    save()
    print(json.dumps({key: report[key] for key in ("characterized", "failed")}))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
