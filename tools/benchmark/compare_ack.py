"""Verify CON reads against the native Coaptic and libcoap fixtures on loopback."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from campaign import run_cell

DRIVER = Path(__file__).with_name("protected") / "load.py"
OSCORE = "OSCORE-AES-CCM-16-64-128"


def check_peer(executable, peer, security, size, shape, operations):
    address = ["{host}", "{port}", "{bytes}"]
    if peer in ("libcoap", "libcoap-handler"):
        server = [str(executable), *address]
        if security == OSCORE:
            server += ["oscore", "{credentials}"]
        server.append("--fixture-etag")
        if peer == "libcoap-handler":
            server.extend(["--handler-response", shape])
    else:
        server = [str(executable), "coaptic-async", *address, "1472"]
        if security == OSCORE:
            server.append("{credentials}")
        if shape == "separate-con":
            server.append("--separate-con")
    driver = [sys.executable, "-B", str(DRIVER)]
    for key in ("host", "port", "bytes", "concurrency", "operations", "warmup",
                "timeout_ms", "mode", "security", "credentials", "sequence"):
        driver.extend(["--" + key.replace("_", "-"), "{" + key + "}"])
    driver.extend(["--expect-exchange", shape])
    case = dict(id=f"{peer}-{security}-{size}-{shape}", protocol="coap", security=security,
                bytes=size, concurrency=1, operations=operations, warmup=4, timeout_ms=1000, mode="con")
    row = run_cell(dict(server=server, driver=driver), case)
    report = row.get("sample", {})
    if (report.get("completed") != operations or report.get("failed") != 0
            or report.get("warmup_failed") != 0 or report.get("verified_bytes") != size * operations):
        raise ValueError(f"{case['id']}: incomplete run: {row.get('error') or report.get('failure_types')}")
    requests = operations * ((size + 1023) // 1024)
    separate = requests if shape == "separate-con" else 0
    expected = dict(data_requests=requests, received_datagrams=requests + separate,
                    matching_empty_acks=separate, piggybacked_responses=requests - separate,
                    separate_con_responses=separate, separate_non_responses=0, sent_response_acks=separate)
    if report["measured_wire_by_worker"] != [expected]:
        raise ValueError(f"{case['id']}: measured datagrams {report['measured_wire_by_worker']}")
    return dict(case=case["id"], verified_reads=operations, verified_bytes=size * operations,
                exchange=shape, wire=expected, readiness_echo_challenges=row["readiness"]["bootstrap_echo_challenges"],
                driver_echo_challenges=report["bootstrap_echo_challenges"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coaptic", type=Path, required=True)
    parser.add_argument("--libcoap", type=Path, required=True)
    parser.add_argument("--operations", type=int, default=32)
    parser.add_argument("--unprotected-handler", action="store_true",
                        help="also compare both unprotected response styles with libcoap application-managed Block2")
    args = parser.parse_args()
    if not 1 <= args.operations <= 10000:
        parser.error("operations must be 1..10000")
    binaries = {peer: getattr(args, peer).resolve(strict=True) for peer in ("coaptic", "libcoap")}
    hashes = {}
    for peer, path in binaries.items():
        with path.open("rb") as stream:
            hashes[peer] = hashlib.file_digest(stream, "sha256").hexdigest()
    rows = []
    for size in (64, 4096):
        for security in ("unprotected", OSCORE):
            shape = "separate-con" if security == OSCORE else "piggyback"
            for peer, path in binaries.items():
                rows.append(check_peer(path, peer, security, size, shape, args.operations))
            if args.unprotected_handler and security == "unprotected":
                rows.append(check_peer(binaries["coaptic"], "coaptic", security, size, "separate-con", args.operations))
                for handler_shape in ("piggyback", "separate-con"):
                    rows.append(check_peer(binaries["libcoap"], "libcoap-handler", security, size, handler_shape, args.operations))
            if security == OSCORE:
                rows.append(check_peer(binaries["coaptic"], "coaptic", security, size, "piggyback", args.operations))
    result = dict(schema="coaptic-libcoap-ack/1", binaries=hashes, runs=rows)
    if args.unprotected_handler:
        command = [sys.executable, "-B", str(DRIVER.with_name("verify_ack_retry.py")),
                   "--server", str(binaries["libcoap"])]
        result["libcoap_handler_recovery"] = json.loads(subprocess.check_output(command, text=True, timeout=20))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
