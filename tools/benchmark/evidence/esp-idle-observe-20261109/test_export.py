"""Tiny synthetic privacy/integrity/gate counterexamples; no measurement input reads."""
import copy
import gzip
import json
import unittest
import common as c
import verify
import portable_host


def lookup():
    result = {}
    for name, value in [("H", .9), ("C1", 1.0), ("C2", 1.05)]:
        for client in ["sync", "async"]:
            for path in ["identity", "test", "large"]:
                result[name, client, path] = {"name": name, "median_ms": value, "boot_medians_ms": [value, value]}
    return result


class Tests(unittest.TestCase):
    def test_positive_host_gate_and_failed_round(self):
        self.assertTrue(c.host_decision(True, 1.05, [1.04, 1.05, 1.06]))
        self.assertFalse(c.host_decision(True, 1.05, [1.04, 1.05, 1.0]))
        self.assertFalse(c.host_decision(True, 1.02, [1.02, 1.02, 1.02]))
        self.assertFalse(c.host_decision(False, 1.2, [1.2] * 3))

    def test_promising_is_computed_and_can_be_true(self):
        self.assertTrue(c.wifi_decision("H", ["C1", "C2"], lookup(), True)["promising"])

    def test_one_bad_wifi_cell_cannot_hide_in_mean(self):
        values = lookup()
        values["H", "sync", "identity"]["median_ms"] = 1.05
        result = c.wifi_decision("H", ["C1", "C2"], values, True)
        self.assertLess(result["strict_best_C_geometric_median_ratio"], .97)
        self.assertFalse(result["promising"])

    def test_bad_boot_prevents_promotion(self):
        values = lookup()
        for key, value in values.items():
            if key[0] == "H":
                value["boot_medians_ms"] = [1.05, .75]
        self.assertFalse(c.wifi_decision("H", ["C1", "C2"], values, True)["promising"])

    def test_resource_or_stability_failure_prevents_promotion(self):
        self.assertFalse(c.wifi_decision("H", ["C1", "C2"], lookup(), False)["promising"])

    def test_strongest_of_both_C_controls_matters(self):
        values = lookup()
        for key, value in values.items():
            if key[0] == "C2":
                value.update(median_ms=.85, boot_medians_ms=[.85, .85])
        self.assertFalse(c.wifi_decision("H", ["C1", "C2"], values, True)["promising"])

    def test_host_whitelist_drops_identity_and_keeps_every_latency(self):
        value = {"sample": {"latencies_ns": [100, 101], "elapsed_ns": 300, "credential": "PRIVATE_SENTINEL"}, "server_stdout": json.dumps({"schema": "example", "app_including_adapter_bytes": 24, "run_id": "PRIVATE_SENTINEL"}), "server_stderr": "", "loaded": {"after": {"memory": {"private": 100}, "processes": [{"pid": 42, "name": "PRIVATE_SENTINEL"}]}}, "resource_samples": [{"at": 500.0, "snapshot": {"memory": {"private": 100}, "processes": [{"pid": 42, "name": "PRIVATE_SENTINEL"}]}}], "operator_path": "PRIVATE_SENTINEL"}
        result = c.host_result(value)
        self.assertEqual(result["sample"]["latencies_ns"], [100, 101])
        self.assertNotIn(b"PRIVATE_SENTINEL", c.encoded(result))
        self.assertNotIn(b'"pid"', c.encoded(result))

    def test_operation_whitelist_excludes_run_id_and_keeps_failures(self):
        value = {"passed": False, "elapsed_ns": 120, "run_id": "PRIVATE_SENTINEL", "operator_path": "PRIVATE_SENTINEL", "events": [[2, 0, 0, 5, 12], [2, 0, 0, 5, 12]]}
        result = c.operation(value)
        self.assertFalse(result["passed"])
        self.assertEqual(result["request_send_ids"], [12, 12])
        self.assertNotIn(b"PRIVATE_SENTINEL", c.encoded(result))

    def test_compressed_and_raw_integrity_are_checked(self):
        raw = c.encoded({"latencies_ns": [1, 2, 3]})
        packed = gzip.compress(raw, mtime=0)
        expected = {"sha256": c.sha(packed), "raw_sha256": c.sha(raw), "raw_bytes": len(raw)}
        self.assertEqual(c.unpack(packed, expected), raw)
        expected["raw_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            c.unpack(packed, expected)

    def test_private_values_and_path_escape_are_refused(self):
        self.assertTrue(c.private(b'C:/Users/private/state'))
        self.assertTrue(c.private(('.'.join(['192', '168', '234', '56'])).encode()))
        self.assertTrue(c.private((':'.join(['ab'] * 6)).encode()))
        for path in ['../outside.gz', '/outside.gz', 'C:/outside.gz']:
            with self.assertRaises(ValueError):
                c.relative(path)

    def test_source_normalization_keeps_one_addition_and_three_overrides(self):
        old = {"f" + str(i) + ".rs": "0" * 64 for i in range(679)}
        new = dict(old)
        overrides = []
        for i in range(3):
            name = "f" + str(i) + ".rs"
            new[name] = "1" * 64
            overrides.append({"normalized": name, "original_sha256": old[name], "effective_sha256": new[name]})
        new["new.rs"] = "2" * 64
        value = {"original_normalized": old, "effective": new, "explicit_staged_overrides": overrides, "explicit_staged_additions": [{"normalized": "new.rs", "original_sha256": None, "effective_sha256": "2" * 64}]}
        self.assertEqual(verify.source_map({"effective_inputs": value})["unchanged"], 676)
        new["f10.rs"] = "3" * 64
        with self.assertRaises(ValueError):
            verify.source_map({"effective_inputs": value})

    def test_empty_host_records_withhold_all_acceptance(self):
        cases = [dict(bytes=b, concurrency=n, operations=4096 if b <= 1024 else 512 if b == 16384 else 256, warmup=2, timeout_ms=2000, mode="con", protocol="coap", security="unprotected") for b in [64, 1024, 16384, 65536] for n in [1, 16, 64]]
        peers = []
        for name in portable_host.PEERS:
            arguments = ["{host}", "{port}", "{bytes}"] if name == "libcoap" else ["coaptic-mio" if name.endswith("Mio") else "coaptic-async", "{host}", "{port}", "{bytes}", "1472"]
            peers.append({"id": name, "server": ["server"] + arguments, "driver": ["driver", "{host}", "{port}", "{bytes}", "{concurrency}", "{operations}", "{warmup}", "{timeout_ms}", "{mode}"]})
        method = {"candidate": c.H, "baseline": c.BASE, "cases": cases, "peers": peers, "rounds": 3, "seed": 20261107, "schedule": portable_host.schedule(portable_host.PEERS, cases, 20261107), "limits": {"phase_seconds": 480, "driver_seconds": 30, "private_bytes": 268435456}, "acceptance": {"aggregate_goodput_ratio_minimum": 1.03, "every_round_geometric_goodput_ratio_strict_minimum": 1.0, "complete_cells": 180, "verified_operations": 403200, "all_capacity_and_failure_gates": True}, "binary_sha256": {"libcoap": "a" * 64}}
        report = portable_host.analyze_records(method, [], False)
        self.assertEqual(report["completed"], 0)
        self.assertTrue(all(not d["host_gate_passed"] for d in report["decisions"]))

    def test_qualification_cannot_be_imported_as_speed(self):
        with self.assertRaises(ValueError):
            verify.startup_grade({"candidate": c.H, "runtime": c.RUNTIME, "performance_operations_imported": 1, "profiles": []})


    def native_boot(self):
        return {"mode": "sync", "settle_seconds": 30.0, "configuration": {"sdk": {"ESP_DEFAULT_CPU_FREQ_MHZ": 240, "ESP32S3_INSTRUCTION_CACHE_SIZE": 32768, "ESP32S3_ICACHE_ASSOCIATED_WAYS": 8, "ESP32S3_INSTRUCTION_CACHE_LINE_SIZE": 32}, "task_stack_reserved_bytes": 98304, "task_priority": 1, "task_core": -1}}

    def test_exported_cpu_frequency_must_match_frozen_clock(self):
        boot = self.native_boot()
        self.assertTrue(c.native_policy(boot, {"post_ota_settle_s": 30}))
        boot["configuration"]["sdk"]["ESP_DEFAULT_CPU_FREQ_MHZ"] = 160
        self.assertFalse(c.native_policy(boot, {"post_ota_settle_s": 30}))

    def test_exported_cache_geometry_is_checked(self):
        for key, value in [("ESP32S3_INSTRUCTION_CACHE_SIZE", 16384), ("ESP32S3_ICACHE_ASSOCIATED_WAYS", 4), ("ESP32S3_INSTRUCTION_CACHE_LINE_SIZE", 16)]:
            boot = self.native_boot()
            boot["configuration"]["sdk"][key] = value
            self.assertFalse(c.native_policy(boot, {"post_ota_settle_s": 30}))

    def test_exported_task_policy_and_stack_are_checked(self):
        for key, value in [("task_core", 0), ("task_priority", 2), ("task_stack_reserved_bytes", 65536)]:
            boot = self.native_boot()
            boot["configuration"][key] = value
            self.assertFalse(c.native_policy(boot, {"post_ota_settle_s": 30}))

    def test_exported_settling_guard_is_checked(self):
        boot = self.native_boot()
        boot["settle_seconds"] = 29.99
        self.assertFalse(c.native_policy(boot, {"post_ota_settle_s": 30}))


if __name__ == "__main__":
    unittest.main()
