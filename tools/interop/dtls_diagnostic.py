#!/usr/bin/env python3
"""One IPv4 fixture exchange; no policy/cipher changes or retry campaign."""
import argparse
import hashlib
import json
from pathlib import Path

from run import Server, expect, request, source_identity

REASONS = {
    "no shared cipher", "no ciphers available", "unsupported protocol",
    "no suitable signature algorithm", "bad record mac", "decryption failed",
    "psk identity not found", "insufficient security", "handshake failure",
    "unclassified-suppressed",
}
DESCRIPTIONS = {
    "handshake failure", "insufficient security", "protocol version",
    "bad record mac", "decrypt error", "unknown PSK identity", "close notify",
    "unclassified-suppressed",
}


def integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def parse_observations(data):
    """Retain only the fixed C diagnostic grammar; reject extra/raw text."""
    if not isinstance(data, bytes) or len(data) > 8192:
        raise ValueError("diagnostic byte bound")
    lines = data.splitlines()
    if len(lines) > 33:
        raise ValueError("diagnostic row bound")
    rows = []
    for index, line in enumerate(lines):
        if len(line) > 512:
            raise ValueError("diagnostic line bound")
        def unique(pairs):
            obj = {}
            for key, value in pairs:
                if key in obj:
                    raise ValueError("duplicate diagnostic key")
                obj[key] = value
            return obj
        row = json.loads(line, object_pairs_hook=unique)
        if not isinstance(row, dict):
            raise ValueError("diagnostic object required")
        kind = row.get("diagnostic")
        valid = False
        if kind == "reason":
            valid = set(row) == {"diagnostic", "reason"} and row["reason"] in REASONS
        elif kind == "alert":
            valid = (set(row) == {"diagnostic", "direction", "description"}
                     and row["direction"] in {"read", "write", "unknown"}
                     and row["description"] in DESCRIPTIONS)
        elif kind == "session":
            valid = (set(row) == {"diagnostic", "event", "security_level"}
                     and row["event"] in {"dtls-error", "dtls-connected", "server-session-new"}
                     and (row["security_level"] is None or integer(row["security_level"], 5)))
        elif kind == "backend":
            valid = (set(row) == {"diagnostic", "library", "runtime_version", "built_version"}
                     and integer(row["library"], 5)
                     and integer(row["runtime_version"], 2**64 - 1)
                     and integer(row["built_version"], 2**64 - 1))
        elif kind == "backend-unavailable":
            valid = set(row) == {"diagnostic"}
        elif kind == "overflow":
            valid = set(row) == {"diagnostic"} and index == 32 and index == len(lines) - 1
        if not valid or (index >= 32 and kind != "overflow"):
            raise ValueError("unrecognized diagnostic record")
        rows.append(row)
    return rows


def fingerprint(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return {"path": str(path), "sha256": digest.hexdigest()}


def diagnose(coaptic, libcoap):
    report = {
        "schema": "coaptic-dtls-diagnostic/1",
        "case": "dtls:coaptic->libcoap", "address_family": "ipv4",
        "transactions_attempted": 0, "passed": False, "exchange_passed": False,
        "failure_kind": None, "observations": [],
        "diagnostics_complete": False, "cleanup_settled": False,
        "contract": {
            "request_timeout_ms": 6000, "request": "GET /test",
            "rust_cipher": "TLS_PSK_WITH_AES_128_CCM_8",
            "policy_override": False, "cipher_override": False,
            "notes": "Fixed fixture credentials unchanged; no key or packet output. "
                     "Warning categories are allowlisted observations, not cause proof. "
                     "A null or absent security level means unobserved. "
                     "This one transaction does not replace the failed interop campaign.",
        },
    }
    server = None
    try:
        server = Server(libcoap, "dtls", diagnostics=True)
        with server:
            report["transactions_attempted"] = 1
            event = request(coaptic, "dtls", server.number)
            expect(event)
            report["exchange_passed"] = True
    except Exception as error:
        # Fixed categories only: exception/peer text may contain external data.
        report["failure_kind"] = "response-refused" if isinstance(error, AssertionError) else "supervisor-error"
    if server is not None:
        report["cleanup_settled"] = (server.proc.poll() is not None
            and not server.reader.is_alive() and not server.stderr_reader.is_alive())
    if server is not None and server.diagnostic_stderr is not None:
        try:
            report["observations"] = parse_observations(server.diagnostic_stderr)
            report["diagnostics_complete"] = server.diagnostic_stderr_complete and bool(report["observations"]) and not any(
                row["diagnostic"] == "overflow" for row in report["observations"])
        except (ValueError, TypeError, UnicodeError):
            report["diagnostic_error"] = "invalid-or-oversize-backend-diagnostics"
    report["passed"] = report["exchange_passed"] and report["cleanup_settled"] and report["diagnostics_complete"]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coaptic", type=Path, required=True)
    parser.add_argument("--libcoap", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("diagnostic output must be new")
    peers = {name: path.resolve(strict=True) for name, path in
             (("coaptic", args.coaptic), ("libcoap", args.libcoap))}
    report = {**source_identity(), "executables": {
        name: fingerprint(path) for name, path in peers.items()},
        "libcoap_source": "851533c3cf63d16984d370ce39d586ecb3694971"}
    report.update(diagnose(**peers))
    payload = (json.dumps(report, indent=2, allow_nan=False) + "\n").encode("utf-8")
    if len(payload) > 32768:
        raise ValueError("diagnostic report byte bound")
    with args.output.open("xb") as stream:
        stream.write(payload)
    return 0 if report["passed"] and report["cleanup_settled"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
