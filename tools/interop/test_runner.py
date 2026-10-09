"""Exercise wire fault injection and fail-closed result validation."""
import socket
import unittest
from unittest.mock import patch
from run import (Proxy, decode, expect, summary, validate_timing, measure_requests, method_workflow,
                  expect_identical_requests, ipv6_dtls_request, replay_envelope, coap_message,
                  upload_block, coap_payload, block1_value, decoded_options, block1_fields)


class RunnerTests(unittest.TestCase):
    def test_wrong_schema_is_not_accepted(self):
        with self.assertRaises(RuntimeError):
            decode('{"schema":"other","event":"response"}')

    def test_payload_mismatch_is_not_success(self):
        with self.assertRaises(AssertionError):
            expect({"exit_code":0,"code":69,"payload_hex":"00"})
        with self.assertRaises(AssertionError):
            expect({"exit_code":1,"code":69,"payload_hex":""})

    def test_method_workflow_rejects_success_without_resource_effect(self):
        # A peer claims Created but the readback did not retain the write.
        with patch("run.Server") as server, patch("run.request") as request:
            server.return_value.__enter__.return_value.number = 1234
            request.side_effect = [
                {"exit_code": 0, "code": 132, "payload_hex": ""},
                {"exit_code": 0, "code": 65, "payload_hex": ""},
                {"exit_code": 0, "code": 69, "payload_hex": ""},
            ]
            with self.assertRaises(AssertionError):
                method_workflow("client", "server")
            self.assertEqual(request.call_count, 3)

    def test_method_workflow_requires_ipv6_probe_before_mutations(self):
        with patch("run.Server") as server, patch("run.request") as request, patch("run.ipv6_probe") as probe:
            server.return_value.__enter__.return_value.number = 1234
            probe.side_effect = AssertionError("IPv6 unavailable")
            with self.assertRaises(AssertionError):
                method_workflow("client", "server", "udp", "ipv6")
            server.assert_called_once_with("server", "udp", family="ipv6")
            probe.assert_called_once_with(1234)
            request.assert_not_called()

    def test_ipv6_dtls_requires_real_request_datagrams(self):
        with patch("run.Proxy") as proxy, patch("run.request") as request:
            proxy.return_value.__enter__.return_value.trace = []
            with self.assertRaises(AssertionError):
                ipv6_dtls_request("client", 1234, [])
            proxy.assert_called_once_with(1234, "dtls-reconnect", family="ipv6")
            self.assertEqual(request.call_args.kwargs["family"], "ipv6")

    def test_ipv6_dtls_methods_use_relay_and_refuse_wrong_key_success(self):
        with patch("run.Server") as server, patch("run.ipv6_dtls_request") as exchange, patch("run.ipv6_probe") as probe:
            server.return_value.__enter__.return_value.number = 1234
            exchange.side_effect = [
                {"exit_code": 0, "code": 132, "payload_hex": ""},
                {"exit_code": 0, "code": 65, "payload_hex": ""},
                {"exit_code": 0, "code": 68, "payload_hex": ""},
            ]
            with self.assertRaises(AssertionError):
                method_workflow("client", "server", "dtls", "ipv6")
            probe.assert_not_called()
            self.assertEqual(exchange.call_count, 3)
            self.assertEqual(exchange.call_args.kwargs["key"], "incorrect")
            self.assertEqual(exchange.call_args.kwargs["method"], "PUT")

    def test_method_workflow_rejects_wrong_key_success(self):
        with patch("run.Server") as server, patch("run.request") as request:
            server.return_value.__enter__.return_value.number = 1234
            request.side_effect = [
                {"exit_code": 0, "code": 132, "payload_hex": ""},
                {"exit_code": 0, "code": 65, "payload_hex": ""},
                {"exit_code": 0, "code": 68, "payload_hex": ""},
            ]
            with self.assertRaises(AssertionError):
                method_workflow("client", "server", "dtls")
            server.assert_called_once_with("server", "dtls", family="ipv4")
            self.assertEqual(request.call_args.args, ("client", "dtls", 1234))
            self.assertEqual(request.call_args.kwargs["key"], "incorrect")
            self.assertEqual(request.call_args.kwargs["method"], "PUT")
            self.assertEqual(request.call_count, 3)

    def test_nearest_rank_percentiles(self):
        self.assertEqual(summary([4,1,3,2])["p50"], 2)
        self.assertEqual(summary([4,1,3,2])["p99"], 4)

    def test_nanosecond_evidence_preserves_sub_microsecond_samples(self):
        event = {"elapsed_ns": 1234567, "clock": {"name": "CLOCK_MONOTONIC", "resolution_ns": 1}}
        self.assertEqual(validate_timing(event), 1234567)
        self.assertEqual(summary([1234567,1234568])["mean"], 1234567.5)
        event["clock"]["resolution_ns"] = None
        self.assertEqual(validate_timing(event), 1234567)

    def test_invalid_timing_cannot_pass(self):
        for elapsed in (None, True, -1, 1.5, float("nan"), float("inf"), 60_000_000_001):
            with self.subTest(elapsed=elapsed), self.assertRaises(RuntimeError):
                validate_timing({"elapsed_ns": elapsed, "clock": {"name":"test", "resolution_ns":1}})
        for clock in (None, {}, {"name":"test"}, {"name":"test", "resolution_ns":0},
                      {"name":"test", "resolution_ns":True}):
            with self.subTest(clock=clock), self.assertRaises(RuntimeError):
                validate_timing({"elapsed_ns": 123, "clock": clock})
        with self.assertRaises(RuntimeError):
            decode('{"schema":"coaptic-peer/1","event":"response","elapsed_us":1000}')

    def test_failed_run_retains_samples_without_retrying(self):
        events = iter([
            {"exit_code":0, "code":69, "payload_hex":b"core-test-payload".hex(),
             "elapsed_ns":1234567, "host_total_ns":2000001,
             "clock":{"name":"test", "resolution_ns":1}},
            {"exit_code":1, "event":"error", "message":"deadline has elapsed"},
        ])
        result = measure_requests(100, lambda: next(events))
        self.assertEqual(result["samples_ns"]["request"], [1234567])
        self.assertEqual(result["failures"], 1)
        self.assertEqual(result["sample_failures"][0]["sample_index"], 1)
        self.assertEqual(result["request_ns"]["n"], 1)
        self.assertNotIn("serial_host_requests_per_second", result)

    def test_first_sample_failure_is_not_an_empty_success(self):
        result = measure_requests(100, lambda: {"exit_code":1})
        self.assertEqual(result["failures"], 1)
        self.assertEqual(result["samples_ns"]["request"], [])
        self.assertNotIn("request_ns", result)

    def test_retransmission_requires_exact_wire_identity(self):
        one = {"direction": "request", "hex": "41031234aa"}
        expect_identical_requests([one, one], require_repeat=True)
        for trace in ([], [one], [one, {"direction": "request", "hex": "41031235aa"}]):
            with self.assertRaises(AssertionError):
                expect_identical_requests(trace, require_repeat=True)

    def test_ipv6_relay_preserves_bytes_in_both_directions(self):
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
            server.bind(("::1", 0))
            server.settimeout(1)
            client.settimeout(1)
            with Proxy(server.getsockname()[1], "dtls-reconnect", family="ipv6") as proxy:
                for endpoint in (proxy.front, proxy.back):
                    self.assertEqual(endpoint.family, socket.AF_INET6)
                    self.assertEqual(endpoint.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY), 1)
                client.sendto(b"request\x00", ("::1", proxy.number))
                data, address = server.recvfrom(100)
                self.assertEqual(data, b"request\x00")
                self.assertEqual(address[0], "::1")
                server.sendto(b"reply\xff", address)
                self.assertEqual(client.recvfrom(100)[0], b"reply\xff")
            self.assertEqual([row["direction"] for row in proxy.trace], ["request", "response"])

    def test_proxy_refuses_unknown_address_family(self):
        with self.assertRaises(ValueError):
            Proxy(1234, "dtls-reconnect", family="invented")

    def test_replay_changes_routing_identity_but_preserves_ciphertext(self):
        original = b"\x41\x02\x12\x34\xa1\x91\x01\xffciphertext-tag"
        replay = replay_envelope(original)
        self.assertNotEqual(replay[2:4], original[2:4])
        self.assertNotEqual(replay[4:5], original[4:5])
        self.assertEqual(replay[:2], original[:2])
        self.assertEqual(replay[5:], original[5:])
        for malformed in (b"", b"\x40\x02\x12\x34", b"\x49\x02\x12\x34long-token"):
            with self.assertRaises(AssertionError):
                replay_envelope(malformed)

    def test_corruption_changes_actual_forwarded_datagram(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            server.bind(("127.0.0.1", 0))
            server.settimeout(1)
            with Proxy(server.getsockname()[1], "corrupt-request") as relay:
                for payload in (b"tag\x00", b"tag\xff"):
                    client.sendto(payload, ("127.0.0.1", relay.number))
                    observed = server.recvfrom(100)[0]
                    self.assertEqual(observed, payload[:-1] + bytes([payload[-1] ^ 0x80]))
            self.assertEqual(len(relay.trace), 2)
            self.assertTrue(all(row["action"] == "corrupt" and row["hex"] != row["forwarded_hex"] for row in relay.trace))

    def test_duplicate_and_drop_are_real_datagrams(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            server.bind(("127.0.0.1",0))
            server.settimeout(1)
            client.settimeout(1)
            with Proxy(server.getsockname()[1], "duplicate-request") as proxy:
                client.sendto(b"request",("127.0.0.1",proxy.number))
                one, address=server.recvfrom(100)
                two, again=server.recvfrom(100)
                self.assertEqual((one,address),(two,again))
                server.sendto(b"reply",address)
                self.assertEqual(client.recvfrom(100)[0], b"reply")
            self.assertEqual(proxy.trace[0]["action"],"duplicate")
            with Proxy(server.getsockname()[1], "drop-reply") as proxy:
                client.sendto(b"request",("127.0.0.1",proxy.number))
                _,address=server.recvfrom(100)
                server.sendto(b"drop",address)
                server.sendto(b"keep",address)
                self.assertEqual(client.recvfrom(100)[0],b"keep")
            self.assertEqual(sum(e["action"]=="drop" for e in proxy.trace),1)

    def test_upload_block_encodes_ordered_options_and_one_byte_block1(self):
        self.assertEqual(block1_value(0, True, 6), b"\x0e")
        self.assertEqual(block1_value(2, True, 2), bytes([(2 << 4) | (1 << 3) | 2]))
        message = upload_block(0x1234, b"\x09", 0, True, 2, b"A" * 64, size1=1)
        self.assertEqual(message[:4], bytes([0x41, 0x02, 0x12, 0x34]))
        self.assertEqual(message[4:5], b"\x09")
        self.assertIn(b"upload", message)
        self.assertEqual(coap_payload(message), b"A" * 64)
        parsed = coap_message(1, 7, b"\x01", [(11, b"upload")])
        self.assertEqual(coap_payload(parsed), b"")
        small = upload_block(3, b"\x21", 7, False, 4, b"Z")
        self.assertEqual(block1_fields(decoded_options(small)[27][0]), (7, False, 4))


if __name__ == "__main__":
    unittest.main()
