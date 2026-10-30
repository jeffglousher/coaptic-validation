"""No native execution: fixed diagnostic grammar and one-exchange custody."""
import io
import json
import unittest
from unittest.mock import Mock, patch

from dtls_diagnostic import diagnose, parse_observations
from run import Server


def wire(*rows):
    return b"".join(json.dumps(row).encode() + b"\n" for row in rows)


BACKEND = {"diagnostic": "backend", "library": 2, "runtime_version": 0x30500050, "built_version": 0x30500050}
REASON = {"diagnostic": "reason", "reason": "no shared cipher"}
POLICY = {"diagnostic": "session", "event": "dtls-error", "security_level": 2}


class DtlsDiagnosticTests(unittest.TestCase):
    def test_allowlisted_observations_preserve_unknown_policy(self):
        unknown = {**POLICY, "security_level": None}
        alert = {"diagnostic": "alert", "direction": "write", "description": "handshake failure"}
        self.assertEqual(parse_observations(wire(BACKEND, unknown, REASON, alert)), [BACKEND, unknown, REASON, alert])

    def test_raw_secret_text_and_extra_fields_are_rejected(self):
        for data in [b"PSK=do-not-retain\n", wire({**REASON, "raw": "private"}),
                     wire({**REASON, "reason": "unrecognized private value"}),
                     wire({"diagnostic": "packet", "hex": "deadbeef"}),
                     b'{"diagnostic":"reason","reason":"no shared cipher","reason":"bad record mac"}\n']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_observations(data)

    def test_bounds_and_scalar_types(self):
        for data in [b"x" * 8193, b" " * 513, wire(*([REASON] * 34)),
                     wire({**POLICY, "security_level": True}), wire({**POLICY, "security_level": 6}),
                     wire({**BACKEND, "runtime_version": -1}), wire({**BACKEND, "built_version": 2**64}),
                     wire({"diagnostic": "overflow"}), b"[]\n"]:
            with self.subTest(data=data[:100]), self.assertRaises(ValueError):
                parse_observations(data)
        self.assertEqual(len(parse_observations(wire(*([REASON] * 32)))), 32)
        rows = [REASON] * 32 + [{"diagnostic": "overflow"}]
        self.assertEqual(parse_observations(wire(*rows)), rows)

    def server(self):
        server = Mock()
        server.__enter__ = Mock(return_value=server)
        server.__exit__ = Mock(return_value=False)
        server.number = 12345
        server.proc.poll.return_value = -15
        server.reader.is_alive.return_value = False
        server.stderr_reader.is_alive.return_value = False
        server.diagnostic_stderr = wire(BACKEND, POLICY, REASON)
        server.diagnostic_stderr_complete = True
        return server

    def test_refusal_retains_observations_and_runs_only_one_unchanged_request(self):
        server = self.server()
        event = {"exit_code": 1, "event": "error", "message": "Alert is Fatal or Close Notify"}
        with patch("dtls_diagnostic.Server", return_value=server) as constructor, patch(
                "dtls_diagnostic.request", return_value=event) as request:
            report = diagnose("rust", "c")
        constructor.assert_called_once_with("c", "dtls", diagnostics=True)
        request.assert_called_once_with("rust", "dtls", 12345)
        self.assertEqual(report["transactions_attempted"], 1)
        self.assertFalse(report["passed"])
        self.assertEqual(report["failure_kind"], "response-refused")
        self.assertTrue(report["diagnostics_complete"])
        self.assertTrue(report["cleanup_settled"])
        self.assertEqual(report["observations"], [BACKEND, POLICY, REASON])

    def test_success_requires_real_response_payload_and_complete_cleanup(self):
        event = {"exit_code": 0, "code": 69, "payload_hex": b"core-test-payload".hex()}
        for malformed, alive, complete in [(False, False, True), (True, False, True),
                                           (False, True, True), (False, False, False)]:
            server = self.server()
            server.stderr_reader.is_alive.return_value = alive
            server.diagnostic_stderr_complete = complete
            response = {**event, "payload_hex": "00"} if malformed else event
            with patch("dtls_diagnostic.Server", return_value=server), patch(
                    "dtls_diagnostic.request", return_value=response):
                report = diagnose("rust", "c")
            self.assertEqual(report["passed"], not malformed and not alive and complete)

    def test_unknown_raw_stderr_is_discarded_even_when_exchange_succeeds(self):
        server = self.server()
        server.diagnostic_stderr = b"do-not-retain-this-secret"
        with patch("dtls_diagnostic.Server", return_value=server), patch(
                "dtls_diagnostic.request", return_value={"exit_code": 0, "code": 69,
                                                       "payload_hex": b"core-test-payload".hex()}):
            report = diagnose("rust", "c")
        self.assertTrue(report["exchange_passed"])
        self.assertFalse(report["passed"])
        self.assertEqual(report["observations"], [])
        self.assertNotIn("do-not-retain", json.dumps(report))

    def test_readiness_failure_never_retries_or_claims_cleanup(self):
        with patch("dtls_diagnostic.Server", side_effect=RuntimeError("external-secret")), patch(
                "dtls_diagnostic.request") as request:
            report = diagnose("rust", "c")
        request.assert_not_called()
        self.assertFalse(report["passed"])
        self.assertFalse(report["cleanup_settled"])
        self.assertEqual(report["transactions_attempted"], 0)
        self.assertNotIn("external-secret", json.dumps(report))

    def test_diagnostic_server_drains_without_disk_spool_and_stops_owned_process(self):
        proc = Mock()
        ready = b'{"schema":"coaptic-peer/2","event":"ready","port":12345,"transport":"dtls"}\n'
        proc.stdout = io.BytesIO(ready)
        proc.stderr = io.BytesIO(b"x" * 20000)
        proc.poll.side_effect = [None, None, -15]
        with patch("run.subprocess.Popen", return_value=proc) as popen, patch(
                "run.tempfile.TemporaryFile") as temporary:
            server = Server("c", "dtls", number=12345, diagnostics=True)
            server.close()
        temporary.assert_not_called()
        self.assertEqual(popen.call_args.kwargs["env"]["COAPTIC_DTLS_DIAGNOSTICS"], "1")
        self.assertEqual(len(server.diagnostic_stderr), 8193)
        self.assertTrue(server.diagnostic_stderr_complete)
        self.assertFalse(server.stderr_reader.is_alive())
        proc.terminate.assert_called_once()
        proc.wait.assert_called_once_with(timeout=2)


if __name__ == "__main__":
    unittest.main()
