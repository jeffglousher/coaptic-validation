"""Authenticated independent Q-Block2 baseline; loss qualification is separate."""
from oscore_qblock1 import request_plain, response_plain, require, incoming
from aiocoap import oscore


def baseline_grade(trace, result, endpoints):
    from run import LARGE, decoded_options, block1_fields, packet_token, expect
    expect(result, 69, LARGE)
    require(1 <= len(trace) <= 256, "baseline trace outside bound")
    def endpoint(value):
        require(isinstance(value, (list, tuple)) and len(value) == 2
                and value[0] == "127.0.0.1" and type(value[1]) is int
                and 0 < value[1] < 65536, "not exact IPv4 loopback endpoint")
        return tuple(value)
    front, back, server = (endpoint(endpoints[k]) for k in ("front", "back", "server"))
    client = endpoint(trace[0]["source"])
    require(len({front, back, server, client}) == 4, "overlapping endpoint owners")
    latest = None
    request_pending = False
    server_pending = None
    token = etag = None
    request_mids, response_mids, pivs, response_pivs = set(), set(), set(), set()
    body = bytearray()
    forms = []
    previous = -1
    for row in trace:
        direction = row["direction"]
        require(direction in ("request", "response") and row["action"] == "forward",
                "baseline requires forwarded packets")
        actual = tuple(endpoint(row[k]) for k in ("source", "destination", "relay"))
        require(actual == ((client, server, back) if direction == "request" else (server, client, front)),
                "endpoint ownership mismatch")
        at = row["time_ns"]
        require(type(at) is int and at >= 0 and at >= previous
                and at - trace[0]["time_ns"] <= 8_000_000_000, "invalid baseline time")
        previous = at
        require(row["hex"] == row["forwarded_hex"], "relay changed protected bytes")
        wire = bytes.fromhex(row["hex"])
        require(4 <= len(wire) <= 4096 and wire[0] >> 6 == 1
                and wire[0] & 15 <= 8, "invalid bounded packet")
        mid, ty = wire[2:4], (wire[0] >> 4) & 3
        if direction == "request":
            if wire[1] == 0:
                require(server_pending is not None and wire == b"\x60\x00" + server_pending,
                        "client ACK does not own outstanding server CON")
                server_pending = None
                continue
            require(not request_pending and server_pending is None and ty == 0 and wire[1] == 2
                    and mid not in request_mids and set(decoded_options(wire)) == {9},
                    "unexpected protected request ownership")
            plain, binding = request_plain(wire)
            options = {}
            for option in plain.opt.option_list():
                options.setdefault(int(option.number), []).append(option.encode())
            require(int(plain.code) == 1 and plain.payload == b"" and set(options) == {11, 31}
                    and options[11] == [b"large"] and len(options[31]) == 1,
                    "authenticated request is not Q-Block2 GET")
            num, more, szx = block1_fields(options[31][0])
            require(szx == 6 and num * 1024 == len(body) and (latest is not None or more),
                    "request does not select current SZX1024 body range")
            require(token is None or token == packet_token(wire), "request token changed")
            require(packet_token(wire) and bytes(binding.partial_iv) not in pivs, "missing token or reused PIV")
            token = packet_token(wire)
            pivs.add(bytes(binding.partial_iv))
            request_mids.add(mid)
            latest, request_pending = wire, True
            continue
        require(latest is not None, "response without active request")
        if wire[1] == 0:
            require(request_pending and wire == b"\x60\x00" + latest[2:4],
                    "empty ACK owner mismatch")
            request_pending = False
            forms.append("empty request ACK")
            continue
        require(wire[1] == 68 and packet_token(wire) == token and set(decoded_options(wire)) == {9},
                "response token/protection mismatch")
        if ty == 2:
            require(request_pending and mid == latest[2:4], "piggybacked response owner mismatch")
            request_pending = False
            forms.append("piggybacked content")
        else:
            require(ty == 0 and not request_pending and server_pending is None
                    and mid not in response_mids and mid not in request_mids,
                    "separate CON violates owner/NSTART")
            server_pending = mid
            response_mids.add(mid)
            forms.append("separate CON content")
        plain = response_plain(wire, latest)
        # Authentication first; parse the explicit sender PIV with the pinned decoder.
        _, _, cose, _ = oscore.CanUnprotect._extract_encrypted0(incoming(wire))
        piv = cose.get(oscore.COSE_PIV)
        require(isinstance(piv, bytes) and 1 <= len(piv) <= 5 and piv not in response_pivs,
                "distinct Q responses require distinct explicit server PIVs")
        response_pivs.add(piv)
        options = {}
        for option in plain.opt.option_list():
            options.setdefault(int(option.number), []).append(option.encode())
        require(int(plain.code) == 69 and set(options) <= {4, 12, 14, 28, 31}
                and len(options.get(31, [])) == 1 and options.get(12) == [b"*"]
                and options.get(28) == [b"\x07\xd0"] and len(options.get(4, [])) == 1,
                "authenticated representation options mismatch")
        tag = options[4][0]
        require(1 <= len(tag) <= 8 and (etag is None or tag == etag), "missing or changed ETag")
        etag = tag
        num, more, szx = block1_fields(options[31][0])
        require(szx == 6 and num * 1024 == len(body) and num in (0, 1)
                and more == (num == 0) and plain.payload == LARGE[num * 1024:(num + 1) * 1024],
                "authenticated Q-Block2 body mismatch")
        body.extend(plain.payload)
    require(bytes(body) == LARGE and not request_pending and server_pending is None,
            "incomplete body or unsettled CON")
    return {"body_bytes": len(body), "etag_hex": etag.hex(), "response_forms": forms,
            "request_count": len(request_mids), "server_pivs": sorted(p.hex() for p in response_pivs), "scope": "baseline only; loss/refusal/recovery not yet qualified"}


def baseline(client, server, record, patch=None):
    from run import Proxy, Server, request, expect
    with Server(server, "oscore") as service:
        if patch is not None:
            record["server_ready"] = service.ready
            require(service.ready.get("libcoap_patch_sha256") == patch["patch_sha256"],
                    "server binary does not identify the expected dependency patch")
        record["setup"] = request(client, "oscore", service.number, sequence=0)
        expect(record["setup"])
        relay = Proxy(service.number, "pass")
        try:
            with relay:
                record["endpoints"] = {"front": relay.front.getsockname(), "back": relay.back.getsockname(), "server": relay.dest}
                record["result"] = request(client, "oscore", relay.number, path="large", sequence=100, timeout=6500, qblock2=True)
        finally:
            record["trace"] = relay.trace
        record["proof"] = baseline_grade(record["trace"], record["result"], record["endpoints"])


def main():
    import argparse
    import hashlib
    import json
    import platform
    from pathlib import Path
    # Importing run makes the common tools identity module available.
    from run import source_identity
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coaptic", required=True, type=Path)
    parser.add_argument("--libcoap", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--libcoap-patch-manifest", type=Path)
    args = parser.parse_args()
    peers = {"coaptic": args.coaptic.resolve(), "libcoap": args.libcoap.resolve()}
    patch = (json.loads(args.libcoap_patch_manifest.read_text(encoding="utf-8"))
             if args.libcoap_patch_manifest else None)
    report = {"libcoap_patch": patch, "schema": "coaptic-protected-qblock2-baseline/1", **source_identity(),
              "platform": platform.platform(), "qualification_complete": False,
              "scope": "baseline observation only; loss/refusal/recovery remain unqualified",
              "libcoap_source": "851533c3cf63d16984d370ce39d586ecb3694971",
              "executables": {name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                              for name, path in peers.items()}, "baseline": {}}
    try:
        baseline(peers["coaptic"], peers["libcoap"], report["baseline"], patch)
        report["baseline_passed"] = True
    except Exception as error:
        report["baseline_passed"] = False
        report["error"] = f"{type(error).__name__}: {error}"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes((json.dumps(report, indent=2) + "\n").encode("utf-8"))
    print(json.dumps({"baseline_passed": report["baseline_passed"],
                      "qualification_complete": False, "report": str(args.output)}))
    return 0 if report["baseline_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
