import hashlib
import json
import unittest
import io
import gzip
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace

from raw_udp import grade, load_artifacts, archive_proofs, LENGTHS, MAX_EXPANDED_ARCHIVE, MAX_ARCHIVE_HEADERS


def fixture():
    h = lambda text: hashlib.sha256(text.encode()).hexdigest()
    run, core, suite = "a" * 32, "b" * 40, "c" * 40
    image, binary, static = h("image"), h("binary"), h("static")
    hashes = {k: h(k) for k in ("host_build", "firmware_preparation", "component_archive", "installation")}
    firmware = {"core_revision": core, "suite_revision": suite, "run_id": run, "mode": 1, "ota_sha256": image}
    tool = {"core_revision": core, "suite_revision": suite, "binary_sha256": binary}
    install = {"mode": 1, "upload_success": True, "run_id": run, "ota_sha256": image, "installed_at_ms": 100, "receipt_sha256": hashes["installation"]}
    manifest = {"schema": "coaptic-raw-udp-provenance/1", "firmware": firmware, "host": tool, "installation": install,
                "peer": "192.0.2.2:5683", "capture_tool_sha256": h("capture"), "artifact_sha256": hashes.copy()}
    build = {"source": core, "suite_source": suite, "dirty": False, "suite_dirty": False}
    artifacts = {"hashes": hashes, "host_build": {**build, "binary_sha256": binary},
                 "firmware_build": {**build, "archive_sha256": static},
                 "firmware_preparation": {"source": core, "suite_source": suite, "archive_sha256": static,
                     "images": {"protected": {"run_id": run, "firmware.ota.bin_sha256": image, "build_passed": True}}},
                 "receipt": {"exit_code": 0, "mode": "protected", "run_id": run, "ota_sha256": image, "observed_at_ms": 100},
                 "host_binary_sha256": binary, "ota_sha256": image, "static_archive_sha256": static, "capture_tool_sha256": h("capture")}
    now = 100000
    host = [{"event": "begin", "schema": "coaptic-raw-udp/1", "clock": "host_utc", "peer": manifest["peer"], "run_id": run, "start_ms": now, "binary_sha256": binary}]
    for phase in range(5):
        if phase:
            now += 300
            length = LENGTHS[phase - 1]
            for index in range(64):
                now += 2
                host.append({"event": "packet", "group": phase - 1, "index": index, "length": length, "at_ms": now,
                             "sha256": hashlib.sha256(bytes([0xA5]) * length).hexdigest()})
        for path in ("identity", "large", "echo", "ticks"):
            body = run.encode() if path == "identity" else ((100 + phase).to_bytes(4, "big") if path == "ticks" else bytes([0x5A]) * (2000 if path == "large" else 128))
            host.append({"event": "control", "phase": phase, "path": path, "start_ms": now, "end_ms": now + 10, "code": 69, "body_hex": body.hex()})
            now += 10
    host.append({"event": "complete", "end_ms": now + 1, "packet_count": 256, "device_qualified": False})
    first = {"run_id": run, "rx": 10, "tx": 10, "dropped": 0, "polls": 10, "idle_waits": 10,
             "scheduler_yields": 0, "wait_errors": 0, "stack_high_water_bytes": 76000, "stack_capacity_bytes": 98304}
    last = {**first, "rx": 291, "tx": 35, "dropped": 256, "polls": 500, "idle_waits": 20}
    capture = [{"event": "capture_begin", "at_ms": 99000, "clock": "host_utc_receipt", "transport": "encrypted_esphome_api", "device_ipv4": "192.0.2.2"},
               {"event": "log", "at_ms": 99900, "message": "COAPTIC_NETWORK " + json.dumps(first)},
               {"event": "log", "at_ms": now + 100, "message": "COAPTIC_NETWORK " + json.dumps(last)},
               {"event": "capture_end", "at_ms": now + 200}]
    return host, capture, manifest, artifacts


class RawUdpGraderTests(unittest.TestCase):
    def test_synthetic_success_is_explicitly_not_hardware_evidence(self):
        report = grade(*fixture())
        self.assertTrue(report["passed"])
        self.assertEqual(report["packet_bytes"], sum(LENGTHS) * 64)
        self.assertEqual(report["counter_delta"]["dropped"], 256)
        self.assertIn("Synthetic", " ".join(report["limitations"]))

    def test_host_mutations_refuse(self):
        mutations = [
            lambda h: h.pop(5),
            lambda h: h[0].update(peer="192.0.2.3:5683"),
            lambda h: h[0].update(run_id="d" * 32),
            lambda h: h[0].update(binary_sha256="d" * 64),
            lambda h: h[-1].update(packet_count=255),
            lambda h: h[-1].update(device_qualified=True),
            lambda h: h[-1].update(end_ms=h[0]["start_ms"] + 120001),
            lambda h: h[5].update(length=1152),
            lambda h: h[5].update(index=1),
            lambda h: h[5].update(group=1),
            lambda h: h[5].update(sha256="d" * 64),
            lambda h: h[6].update(at_ms=h[5]["at_ms"]),
            lambda h: h[2].update(body_hex="5a" * 1999),
            lambda h: h[3].update(body_hex="5a" * 127),
            lambda h: h[1].update(code=128),
            lambda h: h[72].update(body_hex=h[4]["body_hex"]),
        ]
        for mutate in mutations:
            data = fixture()
            mutate(data[0])
            with self.subTest(mutation=mutations.index(mutate)), self.assertRaises(ValueError):
                grade(*data)

    def test_counter_and_capture_refusals(self):
        for key, value in (("dropped", 255), ("dropped", 257), ("rx", 290), ("tx", 34), ("polls", 10), ("idle_waits", 10), ("wait_errors", 1), ("scheduler_yields", -1), ("run_id", "d" * 32)):
            data = fixture()
            row = json.loads(data[1][2]["message"].split(" ", 1)[1])
            row[key] = value
            data[1][2]["message"] = "COAPTIC_NETWORK " + json.dumps(row)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                grade(*data)
        for change in (lambda c: c.pop(1), lambda c: c[1].update(at_ms=100001),
                       lambda c: c[-1].update(event="log"),
                       lambda c: c[0].update(clock="device_ticks"),
                       lambda c: c[0].update(transport="plaintext"),
                       lambda c: c[0].update(device_ipv4="192.0.2.3"),
                       lambda c: c[2].update(message="COAPTIC_NETWORK_STOPPED result=1"),
                       lambda c: c[2].update(message="COAPTIC_NETWORK_READY run_id=a mode=1"),
                       lambda c: c[2].update(message="ESP-ROM: restart")):
            data = fixture()
            change(data[1])
            with self.assertRaises(ValueError):
                grade(*data)

    def test_retained_artifact_bytes_and_records_are_cross_checked(self):
        host, capture, manifest, expected = fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {key: root / key for key in ("host_build", "firmware_preparation", "installation", "component_archive", "host_binary", "ota", "capture_tool")}
            for key, value in (("host_build", expected["host_build"]), ("firmware_preparation", expected["firmware_preparation"]), ("installation", expected["receipt"])):
                paths[key].write_text(json.dumps(value), encoding="utf-8")
            for key, value in (("host_binary", b"binary"), ("ota", b"image"), ("capture_tool", b"capture")):
                paths[key].write_bytes(value)
            with tarfile.open(paths["component_archive"], "w:gz") as archive:
                for name, value in (("build.json", json.dumps(expected["firmware_build"]).encode()), ("libcoaptic_esphome_probe.a", b"static")):
                    member = tarfile.TarInfo("components/coaptic_network/lib/" + name)
                    member.size = len(value)
                    archive.addfile(member, io.BytesIO(value))
            manifest["artifact_sha256"] = {key: hashlib.sha256(paths[key].read_bytes()).hexdigest() for key in manifest["artifact_sha256"]}
            manifest["installation"]["receipt_sha256"] = manifest["artifact_sha256"]["installation"]
            args = SimpleNamespace(**paths)
            self.assertTrue(grade(host, capture, manifest, load_artifacts(args))["passed"])
            for key in ("host_binary", "ota", "capture_tool"):
                original = paths[key].read_bytes()
                paths[key].write_bytes(b"changed artifact")
                with self.subTest(artifact=key), self.assertRaises(ValueError):
                    grade(host, capture, manifest, load_artifacts(args))
                paths[key].write_bytes(original)
            paths["host_build"].write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                grade(host, capture, manifest, load_artifacts(args))

    def test_archive_expansion_headers_duplicate_and_link_refuse(self):
        def packed(entries):
            out = io.BytesIO()
            with tarfile.open(fileobj=out, mode="w:gz") as archive:
                for name, value, link in entries:
                    item = tarfile.TarInfo(name)
                    if link:
                        item.type = tarfile.SYMTYPE
                        item.linkname = "somewhere"
                    else:
                        item.size = len(value)
                    archive.addfile(item, None if link else io.BytesIO(value))
            return out.getvalue()
        proof = [("components/coaptic_network/lib/build.json", b"{}", False),
                 ("components/coaptic_network/lib/libcoaptic_esphome_probe.a", b"static", False)]
        self.assertEqual(archive_proofs(packed(proof))[0], {})
        for entries in (proof + [proof[0]], proof + [("link", b"", True)],
                        proof + [(str(index), b"", False) for index in range(MAX_ARCHIVE_HEADERS)]):
            with self.assertRaises(ValueError):
                archive_proofs(packed(entries))
        # Tiny compressed input with expansion just above the explicit bound.
        out = io.BytesIO()
        with gzip.GzipFile(fileobj=out, mode="wb") as stream:
            for _ in range(MAX_EXPANDED_ARCHIVE // 65536 + 1):
                stream.write(bytes(65536))
        self.assertLess(len(out.getvalue()), 100000)
        with self.assertRaisesRegex(ValueError, "expanded component archive bound"):
            archive_proofs(out.getvalue())

    def test_provenance_changes_refuse(self):
        mutations = [lambda m,a: m["firmware"].update(mode=3),
                     lambda m,a: m["firmware"].update(core_revision="d" * 40),
                     lambda m,a: m["host"].update(suite_revision="d" * 40),
                     lambda m,a: m["firmware"].update(ota_sha256="d" * 64),
                     lambda m,a: a.update(host_binary_sha256="d" * 64),
                     lambda m,a: a.update(static_archive_sha256="d" * 64),
                     lambda m,a: a.update(capture_tool_sha256="d" * 64),
                     lambda m,a: a["receipt"].update(exit_code=1),
                     lambda m,a: a["receipt"].update(observed_at_ms=101),
                     lambda m,a: a["host_build"].update(dirty=True),
                     lambda m,a: a["firmware_preparation"].update(images={}),
                     lambda m,a: m["artifact_sha256"].pop("installation")]
        for change in mutations:
            data = fixture()
            change(data[2],data[3])
            with self.assertRaises(ValueError):
                grade(*data)


if __name__ == "__main__":
    unittest.main()
