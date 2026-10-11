"""Offline finite UDP refusal grading; no network, provisioning or device operations."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import tarfile

LENGTHS = (1153, 2047, 2048, 4096)
COUNTERS = ("rx", "tx", "dropped", "polls", "idle_waits", "scheduler_yields", "wait_errors")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value):
    require(type(value) is int and 0 <= value < 2**63, "invalid bounded integer")
    return value


def digest(value, length=64):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value), "invalid source/hash identity")
    return value


def grade(host, capture, manifest, artifacts):
    require(manifest.get("schema") == "coaptic-raw-udp-provenance/1", "provenance schema")
    firmware, tool, installation = (manifest[key] for key in ("firmware", "host", "installation"))
    for identity in (firmware, tool):
        digest(identity["core_revision"], 40)
        digest(identity["suite_revision"], 40)
    # Expected attribution is independent of the files being graded. Source labels
    # alone are insufficient: retained build/install records and artifact bytes match.
    for key, expected in manifest["artifact_sha256"].items():
        require(artifacts["hashes"].get(key) == digest(expected), "artifact hash mismatch")
    require(set(manifest["artifact_sha256"]) == {"host_build", "firmware_preparation", "component_archive", "installation"}, "artifact manifest incomplete")
    hb, fb, prep, receipt = (artifacts[key] for key in ("host_build", "firmware_build", "firmware_preparation", "receipt"))
    for identity, build in ((tool, hb), (firmware, fb)):
        require(build["source"] == identity["core_revision"] and build["suite_source"] == identity["suite_revision"], "build source mismatch")
        require(build["dirty"] is False and build["suite_dirty"] is False, "dirty build attribution")
    require(prep["source"] == firmware["core_revision"] and prep["suite_source"] == firmware["suite_revision"], "firmware preparation source mismatch")
    require(hb["binary_sha256"] == artifacts["host_binary_sha256"] == tool["binary_sha256"], "host binary mismatch")
    require(prep["archive_sha256"] == fb["archive_sha256"] == artifacts["static_archive_sha256"], "firmware static archive mismatch")
    require(artifacts["ota_sha256"] == firmware["ota_sha256"] == receipt["ota_sha256"], "OTA image mismatch")
    require(receipt["exit_code"] == 0 and receipt["mode"] == "protected" and receipt["run_id"] == firmware["run_id"], "installation receipt refusal")
    require(receipt["observed_at_ms"] == installation["installed_at_ms"], "installation receipt timing")
    require(any(image["run_id"] == firmware["run_id"] and image["firmware.ota.bin_sha256"] == firmware["ota_sha256"] and image["build_passed"] is True for image in prep["images"].values()), "built image/run binding")
    run = digest(firmware["run_id"], 32)
    image = digest(firmware["ota_sha256"])
    digest(tool["binary_sha256"])
    require(digest(manifest["capture_tool_sha256"]) == artifacts["capture_tool_sha256"], "capture tool mismatch")
    require(digest(installation["receipt_sha256"]) == artifacts["hashes"]["installation"], "installation receipt hash")
    require(number(firmware["mode"]) == number(installation["mode"]) == 1, "protected service mode required")
    require(installation["upload_success"] is True and installation["ota_sha256"] == image
            and installation["run_id"] == run, "installed image binding")
    require(len(host) == 278, "incomplete or extra campaign events")
    begin, complete = host[0], host[-1]
    require(begin["event"] == "begin" and begin["schema"] == "coaptic-raw-udp/1" and begin["clock"] == "host_utc", "host schema")
    require(begin["run_id"] == run and begin["binary_sha256"] == tool["binary_sha256"], "host provenance mismatch")
    require(begin["peer"] == manifest["peer"], "wrong endpoint")
    address, port = begin["peer"].rsplit(":", 1)
    require(ipaddress.ip_address(address).version == 4 and 1 <= int(port) <= 65535, "IPv4 endpoint required")
    start, end = number(begin["start_ms"]), number(complete["end_ms"])
    require(number(installation["installed_at_ms"]) <= start < end <= start + 120_000, "campaign timing")
    require(complete["event"] == "complete" and complete["packet_count"] == 256
            and complete["device_qualified"] is False, "missing bounded host completion")
    index, previous, prior_tick = 1, start, None
    for phase in range(5):
        if phase:
            length = LENGTHS[phase - 1]
            expected_hash = hashlib.sha256(bytes([0xA5]) * length).hexdigest()
            last_packet = None
            for packet in range(64):
                event = host[index]
                index += 1
                at = number(event["at_ms"])
                require(event["event"] == "packet" and number(event["group"]) == phase - 1
                        and number(event["index"]) == packet and event["length"] == length
                        and event["sha256"] == expected_hash, "raw packet identity/count/bytes")
                require(previous <= at <= end, "raw packet ordering")
                if last_packet is not None:
                    require(1 <= at - last_packet <= 500, "raw pacing bound")
                previous = last_packet = at
        for path in ("identity", "large", "echo", "ticks"):
            event = host[index]
            index += 1
            require(event["event"] == "control" and number(event["phase"]) == phase
                    and event["path"] == path and event["code"] == 69, "protected control identity")
            first, last = number(event["start_ms"]), number(event["end_ms"])
            require(previous <= first <= last <= end and last - first <= 6000, "control timing")
            previous = last
            require(type(event["body_hex"]) is str and re.fullmatch(r"(?:[0-9a-f]{2})*", event["body_hex"]), "control encoding")
            body = bytes.fromhex(event["body_hex"])
            if path == "ticks":
                require(len(body) == 4, "complete timer body")
                tick = int.from_bytes(body, "big")
                require(prior_tick is None or tick > prior_tick, "authenticated timer did not progress")
                prior_tick = tick
            else:
                expected = run.encode() if path == "identity" else bytes([0x5A]) * (2000 if path == "large" else 128)
                require(body == expected, "incomplete or changed protected body")
    require(index == len(host) - 1, "event accounting")
    require(2 <= len(capture) <= 2000, "capture bound")
    require(capture[0]["event"] == "capture_begin" and capture[-1]["event"] == "capture_end", "complete API capture required")
    require(capture[0]["clock"] == "host_utc_receipt" and capture[0]["transport"] == "encrypted_esphome_api"
            and capture[0]["device_ipv4"] == address, "capture clock/transport/endpoint attribution")
    require(number(capture[0]["at_ms"]) <= start and number(capture[-1]["at_ms"]) >= end, "capture must bracket campaign")
    rows, observed = [], number(capture[0]["at_ms"])
    for event in capture[1:-1]:
        require(event["event"] == "log", "unexpected capture event")
        at = number(event["at_ms"])
        require(observed <= at <= number(capture[-1]["at_ms"]), "capture time regression")
        observed = at
        message = event["message"]
        require(isinstance(message, str) and len(message) <= 8192, "log bound")
        require(not any(marker in message for marker in ("COAPTIC_NETWORK_STOPPED", "COAPTIC_NETWORK_FAIL", "COAPTIC_NETWORK_READY", "COAPTIC_TELEMETRY_COMPLETE", "ESP-ROM:", "rst:")), "stop/failure/restart or wrong mode")
        if "COAPTIC_NETWORK {" not in message:
            continue
        row = json.loads(message.split("COAPTIC_NETWORK ", 1)[1])
        require(row["run_id"] == run, "device run mismatch")
        for key in COUNTERS:
            number(row[key])
        require(0 <= number(row["stack_high_water_bytes"]) <= number(row["stack_capacity_bytes"]), "stack observation bound")
        if rows:
            require(all(row[k] >= rows[-1][1][k] for k in COUNTERS), "counter reset/regression")
        rows.append((at, row))
    before = [row for at, row in rows if start - 10_000 <= at <= start]
    after = [row for at, row in rows if end <= at <= end + 10_000]
    require(before and after, "fresh counter samples must bracket host work")
    first, last = before[-1], after[0]
    delta = {key: last[key] - first[key] for key in COUNTERS}
    require(delta["dropped"] == 256, "actual raw drop accounting incomplete or contaminated")
    require(delta["rx"] >= 281 and delta["tx"] >= 25, "device receipt/control accounting")
    require(delta["polls"] >= 281 and delta["idle_waits"] > 0 and delta["wait_errors"] == 0, "poll/idle progress or wait error")
    return {"schema": "coaptic-raw-udp-grade/1", "passed": True, "packet_count": 256,
            "packet_bytes": sum(LENGTHS) * 64, "counter_delta": delta,
            "provenance": manifest, "duration_ms": end - start,
            "limitations": ["Finite source-bound campaign, not sustained availability or delivery fairness.",
                            "Image attribution uses supplied installation receipt plus authenticated run identity; not hardware attestation.",
                            "Requires isolated reserved-device campaign; unrelated oversized traffic invalidates exact drop accounting.",
                            "Synthetic fixtures validate the grader only and do not qualify hardware."]}


def load_lines(path):
    require(Path(path).stat().st_size <= 1_000_000, "input byte bound")
    raw = Path(path).read_bytes()
    return [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()], hashlib.sha256(raw).hexdigest()


def load_artifacts(args):
    hashes, records = {}, {}
    for key in ("host_build", "firmware_preparation", "installation"):
        require(getattr(args, key).stat().st_size <= 1_000_000, "record byte bound")
        raw = getattr(args, key).read_bytes()
        hashes[key] = hashlib.sha256(raw).hexdigest()
        records[key] = json.loads(raw)
    require(args.component_archive.stat().st_size <= 16_000_000, "component archive bound")
    raw = args.component_archive.read_bytes()
    hashes["component_archive"] = hashlib.sha256(raw).hexdigest()
    with tarfile.open(args.component_archive, "r:gz") as archive:
        def member(name):
            info = archive.getmember("components/coaptic_network/lib/" + name)
            require(info.isfile() and info.size <= 16_000_000, "archive member bound")
            return archive.extractfile(info).read()
        build = json.loads(member("build.json"))
        static_hash = hashlib.sha256(member("libcoaptic_esphome_probe.a")).hexdigest()
    byte_hashes = {}
    for key in ("host_binary", "ota", "capture_tool"):
        path = getattr(args, key)
        require(path.stat().st_size <= 16_000_000, "binary byte bound")
        byte_hashes[key + "_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"hashes": hashes, "host_build": records["host_build"],
            "firmware_preparation": records["firmware_preparation"],
            "firmware_build": build, "receipt": records["installation"],
            "static_archive_sha256": static_hash, **byte_hashes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "capture", "manifest", "output", "host-build", "firmware-preparation", "component-archive", "installation", "host-binary", "ota", "capture-tool"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    report = {"schema": "coaptic-raw-udp-grade/1", "passed": False}
    try:
        host, host_hash = load_lines(args.host)
        capture, capture_hash = load_lines(args.capture)
        require(args.manifest.stat().st_size <= 32_000, "manifest bound")
        raw = args.manifest.read_bytes()
        report = grade(host, capture, json.loads(raw), load_artifacts(args))
        report["input_sha256"] = {"host": host_hash, "capture": capture_hash, "manifest": hashlib.sha256(raw).hexdigest()}
    except (OSError, ValueError, KeyError, TypeError, IndexError, tarfile.TarError) as error:
        report["error"] = str(error)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
