"""Common native proof contracts; no native executables or live sockets."""
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import MagicMock, Mock, call, patch

import native_check


def startup_line():
    # Host-control's existing Mio ledger, 2000-byte body / 1472-byte RX.
    record = dict(
        schema="coaptic-native-mio-resources/1", server_kind="coaptic-mio",
        udp_scratch_bytes=2049, adapter_inline_bytes=2100,
        app_including_adapter_bytes=10000, poll_inline_bytes=8,
        events_inline_bytes=24, event_capacity=8, worker_threads=0,
        pending_kernel_operations=0, runtime_heap_bytes=None,
        runtime_stack_bytes=None, kernel_bytes=None, nesting="adapter inside App",
        limits="inline/requested only", resource_profile="host-control",
        storage="allocated", routes=1, populated_routes=1, calls=4, deferred=0,
        associations=1, security_requests=4, blockwise=True, rx_slots=4, tx_slots=4,
        rx_datagram_bytes=1472, tx_datagram_bytes=1472, dedup=8, observe=4,
        rx_body_slots=1, tx_body_slots=2, rx_body_bytes=2048, tx_body_bytes=2048,
        representation_bytes=2000, representation_heap_bytes=2000,
        app_requested_heap_bytes=20000, security="oscore",
        allocator_overhead_bytes=None, initialization_stack_bytes=None,
        events_heap_bytes=None)
    return json.dumps(record).encode() + b"\n"


class CommonProofTests(unittest.TestCase):
    def setUp(self):
        self.clock = 10.0
        self.launched = False
        self.log = None
        self.line = startup_line()
        self.on_sleep = None
        self.process = Mock()
        self.process.poll.return_value = None
        self.process.wait.return_value = 0
        self.reserve = MagicMock()
        self.reserve.__enter__.return_value = self.reserve
        self.reserve.getsockname.return_value = ("127.0.0.1", 45678)
        self.reserve.bind.side_effect = self.bind_reservation
        self.output = io.StringIO()

        def patched(name, **kwargs):
            replacement = patch(name, **kwargs)
            self.addCleanup(replacement.stop)
            return replacement.start()

        # Fail closed: the sole socket is an ephemeral reservation before Popen.
        # A regression to bind probes after launch fails even if bind would win.
        self.sockets = patched("native_check.socket.socket", side_effect=self.socket)
        self.raw = patched("native_check.raw_representation")
        self.launch = patched("native_check.subprocess.Popen", side_effect=self.popen)
        patched("native_check.subprocess.run", side_effect=AssertionError("native run forbidden"))
        self.client = patched("native_check.run_client", side_effect=[
            self.result(1), self.result(1), self.result(0, completed=2, received_datagrams=4)])
        self.ready = patched("native_check.server_resources", wraps=native_check.server_resources)
        patched("native_check.time.monotonic", side_effect=lambda: self.clock)
        self.sleep = patched("native_check.time.sleep", side_effect=self.advance)
        patched("sys.stdout", new=self.output)

    @staticmethod
    def result(code, **report):
        return subprocess.CompletedProcess([], code, json.dumps(report), "client failure")

    def socket(self, *args):
        self.assertFalse(self.launched, "active socket probe after server launch")
        self.assertEqual(args, (native_check.socket.AF_INET, native_check.socket.SOCK_DGRAM))
        return self.reserve

    def bind_reservation(self, address):
        self.assertFalse(self.launched, "bind probe can steal server port")
        self.assertEqual(address, ("127.0.0.1", 0))

    def popen(self, command, **kwargs):
        self.launched = True
        self.assertEqual(self.reserve.__exit__.call_count, 1)
        self.command = command
        self.log = kwargs["stdout"]
        self.assertIs(kwargs["stderr"], self.log)
        self.log.write(self.line)
        self.log.flush()
        return self.process

    def advance(self, seconds):
        self.assertGreater(seconds, 0)
        self.assertLessEqual(seconds, .01)
        self.client.assert_not_called()
        self.clock += seconds
        if self.on_sleep is not None:
            self.on_sleep()

    def check(self):
        native_check.check("server", "client")

    def assert_waited(self):
        self.process.wait.assert_called_once_with(timeout=5)
        self.assertTrue(self.log.closed)
        self.assertFalse(Path(self.log.name).exists())

    def test_passive_readiness_then_refusals_and_fresh_complete_block2(self):
        self.line = self.line[:-1]

        def finish_line():
            self.assertEqual(self.log.tell(), len(self.line))
            self.log.write(b"\n")
            self.log.flush()

        self.on_sleep = finish_line
        self.check()
        self.raw.assert_has_calls([call("client", False), call("client", True), call("client", False)])
        self.assertEqual(self.raw.call_count, 3)
        self.assertEqual(self.command[:6], [str(Path("server").resolve()), "coaptic-mio",
                                           "127.0.0.1", "45678", "2000", "1472"])
        self.assertEqual(self.command[7:], ["--resource-profile", "host-control"])
        self.assertEqual(self.ready.call_args.args, (Path(self.log.name), "coaptic-mio"))
        self.assertEqual(self.ready.call_args.kwargs, dict(deadline=15.0, server=self.process,
            resource_profile="host-control", size=2000, security="oscore", rx_bytes=1472))
        self.sleep.assert_called_once_with(.01)
        self.sockets.assert_called_once()
        self.reserve.bind.assert_called_once_with(("127.0.0.1", 0))
        calls = self.client.call_args_list
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0], call("client", 45678, 2000, "unprotected", None))
        self.assertEqual(calls[1].args[:4], ("client", 45678, 2000, "oscore"))
        self.assertEqual(calls[2], call("client", 45678, 2000, "oscore", Path(self.command[6])))
        self.assertNotEqual(calls[1].args[4], calls[2].args[4])
        self.process.terminate.assert_called_once()
        self.assert_waited()
        self.assertIn("fresh protected Block2 PASS", self.output.getvalue())

    def test_exited_server_retains_raw_stderr_and_is_waited(self):
        self.line = b"bind refused\xff"
        self.process.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, "server exited before complete startup ledger"):
            self.check()
        self.client.assert_not_called()
        self.process.terminate.assert_not_called()
        self.assert_waited()
        self.assertEqual(self.output.getvalue(), "RAW SERVER STARTUP/FAILURE: bind refused\ufffd\n")

    def test_partial_ledger_deadline_never_releases_clients(self):
        self.line = self.line[:-1]
        self.on_sleep = lambda: setattr(self, "clock", 15.0)
        with self.assertRaisesRegex(TimeoutError, "startup ledger deadline"):
            self.check()
        self.client.assert_not_called()
        self.assertIn(self.line.decode(), self.output.getvalue())
        self.assert_waited()

    def test_oversized_startup_output_is_bounded_and_primary_is_preserved(self):
        self.line = b"stderr\xff" + b"x" * 5000
        primary = ValueError("server startup ledger exceeded allowance")
        self.ready.side_effect = primary
        with self.assertRaises(ValueError) as caught:
            self.check()
        self.assertIs(caught.exception, primary)
        self.client.assert_not_called()
        self.assertEqual(self.output.getvalue(), "RAW SERVER STARTUP/FAILURE: " +
                         self.line[:4096].decode("utf-8", errors="replace") + "\n")
        self.assert_waited()

    def test_mismatched_profile_ledger_rejected_before_clients(self):
        record = json.loads(self.line)
        record["calls"] = 1
        self.line = json.dumps(record).encode() + b"\n"
        with self.assertRaisesRegex(ValueError, "mismatched Mio profile ledger: calls"):
            self.check()
        self.client.assert_not_called()
        self.assert_waited()

    def test_primary_client_error_survives_terminate_and_wait_failures(self):
        primary = KeyboardInterrupt("primary client failure")
        self.client.side_effect = primary
        self.process.terminate.side_effect = OSError("terminate failed")
        self.process.wait.side_effect = subprocess.TimeoutExpired("server", 5)
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.check()
        self.assertIs(caught.exception, primary)
        self.assertIn(self.line.decode(), self.output.getvalue())
        self.assertTrue(any("terminate failed" in note for note in primary.__notes__))
        self.assertTrue(any("TimeoutExpired" in note for note in primary.__notes__))
        self.assert_waited()

    def test_cleanup_failure_after_success_propagates_and_waits(self):
        primary = OSError("terminate failed")
        self.process.terminate.side_effect = primary
        with self.assertRaises(OSError) as caught:
            self.check()
        self.assertIs(caught.exception, primary)
        self.assert_waited()
        self.assertNotIn("PASS", self.output.getvalue())

    def test_unprotected_success_is_rejected(self):
        self.client.side_effect = [self.result(0)]
        with self.assertRaisesRegex(RuntimeError, "refused security profile counted complete"):
            self.check()
        self.assertEqual(self.client.call_count, 1)
        self.assert_waited()

    def test_wrong_key_success_is_rejected(self):
        self.client.side_effect = [self.result(1), self.result(0)]
        with self.assertRaisesRegex(RuntimeError, "refused security profile counted complete"):
            self.check()
        self.assertEqual(self.client.call_count, 2)
        self.assert_waited()

    def test_failed_fresh_authenticated_recovery_is_rejected(self):
        self.client.side_effect = [self.result(1), self.result(1), self.result(1)]
        with self.assertRaisesRegex(RuntimeError, "fresh authenticated recovery failed"):
            self.check()
        self.assert_waited()

    def test_incomplete_representation_is_rejected(self):
        self.client.side_effect = [self.result(1), self.result(1),
                                   self.result(0, completed=1, received_datagrams=4)]
        with self.assertRaisesRegex(RuntimeError, "incomplete protected Block2 report"):
            self.check()
        self.assert_waited()

    def test_datagram_only_report_cannot_claim_complete_block2(self):
        self.client.side_effect = [self.result(1), self.result(1),
                                   self.result(0, completed=2, received_datagrams=3)]
        with self.assertRaisesRegex(RuntimeError, "incomplete protected Block2 report"):
            self.check()
        self.assert_waited()


if __name__ == "__main__":
    unittest.main()
