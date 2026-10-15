"""Focused authentication and complete-body failure checks for the matched driver."""
import secrets
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "protected"))
import aiocoap
from aiocoap.message import Direction
from context import Context
from load import DriverError, Worker, body_matches, check_body, run
import aiocoap_server


class ProtectedTests(unittest.TestCase):
    def test_fixture_comparison_all_period_phases_and_datagram_bounds(self):
        for offset in range(251):
            for length in (1, 250, 251, 252, 1024):
                body = bytes((offset + i) % 251 for i in range(length))
                self.assertTrue(body_matches(body, offset))
                self.assertTrue(body_matches(body, offset + 251 * 4000))
        for offset in (0, 1, 250):
            body = bytes((offset + i) % 251 for i in range(65535))
            self.assertTrue(body_matches(body, offset))
            self.assertFalse(body_matches(body + b"x", offset))
        self.assertFalse(body_matches(b"", 0))
        self.assertFalse(body_matches(b"\xfa", -1))

    def test_fixture_comparison_refuses_each_changed_byte_and_recovers(self):
        offset = 65024
        valid = bytes((offset + i) % 251 for i in range(1024))
        for position in range(len(valid)):
            changed = bytearray(valid)
            changed[position] ^= 1
            self.assertFalse(body_matches(bytes(changed), offset))
        self.assertTrue(body_matches(valid, offset))

    def test_uvloop_selection_runs_the_requested_backend(self):
        backend = Mock()
        with patch.dict(sys.modules, uvloop=backend), patch.object(aiocoap_server, "serve", new=Mock(return_value="fixture")):
            with patch.object(sys, "argv", ["fixture", "--host", "127.0.0.1", "--port", "1234", "--bytes", "64", "--uvloop"]):
                aiocoap_server.main()
        backend.run.assert_called_once_with("fixture")

    def test_control_packets_and_unprotected_response_refusal(self):
        for mode, protected, control, success in (
                ("con", False, bytes([0x60, 0, 0, 0]), True),
                ("non", False, bytes([0x60, 0, 0, 0]), False),
                ("con", False, bytes([0x60, 0, 0, 0, 255, 1]), False),
                ("con", True, None, False)):
            with self.subTest(mode=mode, protected=protected, control=control):
                response = aiocoap.Message(code=aiocoap.CONTENT, payload=bytes(range(64)), content_format=42)
                response.mid, response.mtype, response.token = 0, aiocoap.NON, (1).to_bytes(8, "big")
                sock = Mock()
                sock.recv.side_effect = ([control] if control is not None else []) + [response.encode()]
                args = SimpleNamespace(host="127.0.0.1", port=1, bytes=64, timeout_ms=1000, mode=mode)
                context = Context(self.credentials) if protected else None
                with patch("load.socket.socket", return_value=sock):
                    worker = Worker(args, 0, context, threading.Lock())
                    if success:
                        self.assertGreater(worker.exchange(1), 0)
                    else:
                        with self.assertRaises(ValueError):
                            worker.exchange(1)

    def test_failure_accounting_includes_warmup_and_driver_failures(self):
        args = SimpleNamespace(host="127.0.0.1", port=1, bytes=64, concurrency=1, operations=2,
                               warmup=1, timeout_ms=1000, sequence=0, mode="con", security="plaintext")
        with patch.object(Worker, "exchange", side_effect=[ValueError("warmup"), DriverError("rotation"), 100]):
            result = run(args)
        self.assertEqual((result["attempted"], result["completed"], result["failed"], result["warmup_failed"],
                          result["driver_failures"], result["verified_bytes"]), (2, 1, 1, 1, 1, 64))

    def test_shared_sender_dispatch_holds_sequence_lock_through_udp_send(self):
        crypto_lock = threading.Lock()
        sock = Mock()
        def sent(_):
            self.assertTrue(crypto_lock.locked(), "sequence was reserved before unsequenced local dispatch")
        sock.send.side_effect = sent
        sock.recv.side_effect = TimeoutError()
        args = SimpleNamespace(host="127.0.0.1", port=1, bytes=64, timeout_ms=1000, mode="con")
        with patch.object(Worker, "new_socket", return_value=sock):
            worker = Worker(args, 0, Context(self.credentials), crypto_lock)
            with self.assertRaises(TimeoutError):
                worker.exchange(1)
        self.assertFalse(crypto_lock.locked(), "send/receive failure retained the shared sender lock")

    def test_matched_replay_retention_accepts_31_behind_and_refuses_32(self):
        server = Context(self.credentials, server=True)
        recent, _ = self.request(Context(self.credentials, sequence=32))
        server.unprotect(recent)
        too_old, _ = self.request(Context(self.credentials, sequence=0))
        with self.assertRaises(aiocoap.oscore.ReplayError):
            server.unprotect(too_old)
        retained, _ = self.request(Context(self.credentials, sequence=1))
        self.assertEqual(server.unprotect(retained)[0].code, aiocoap.GET)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.credentials = Path(self.directory.name) / "credentials"
        self.credentials.write_bytes(secrets.token_bytes(24))

    def request(self, client):
        request = aiocoap.Message(code=aiocoap.GET, uri_path=("bench",))
        request.mtype, request.mid, request.token = aiocoap.CON, 1, b"12345678"
        wire, binding = client.protect(request)
        wire.mid, wire.mtype, wire.token = request.mid, request.mtype, request.token
        decoded = aiocoap.Message.decode(wire.encode())
        decoded.direction = Direction.INCOMING
        return decoded, binding

    def test_authenticated_request_response_and_replay_refusal(self):
        client, server = Context(self.credentials), Context(self.credentials, server=True)
        request, binding = self.request(client)
        plain, response_binding = server.unprotect(request)
        self.assertEqual(plain.code, aiocoap.GET)
        with self.assertRaises(Exception):
            server.unprotect(request)
        response = aiocoap.Message(code=aiocoap.CONTENT, payload=bytes(range(64)), content_format=42)
        protected, _ = server.protect(response, response_binding)
        protected.mid, protected.mtype, protected.token = 1, aiocoap.ACK, b"12345678"
        incoming = aiocoap.Message.decode(protected.encode())
        incoming.direction = Direction.INCOMING
        verified, _ = client.unprotect(incoming, binding)
        self.assertEqual(check_body(verified, 0, 64, None)[0], 64)

    def test_tamper_wrong_key_and_fresh_valid_recovery(self):
        client, server = Context(self.credentials), Context(self.credentials, server=True)
        request, _ = self.request(client)
        changed = request.copy()
        changed.payload = changed.payload[:-1] + bytes([changed.payload[-1] ^ 1])
        with self.assertRaises(Exception):
            server.unprotect(changed)
        wrong = Path(self.directory.name) / "wrong"
        wrong.write_bytes(secrets.token_bytes(24))
        wrong_request, _ = self.request(Context(wrong))
        with self.assertRaises(Exception):
            server.unprotect(wrong_request)
        # Authentication failures must not consume the valid sequence.
        self.assertEqual(server.unprotect(request)[0].code, aiocoap.GET)

    def test_response_bound_to_request(self):
        client, server = Context(self.credentials), Context(self.credentials, server=True)
        request, _ = self.request(client)
        _, binding = server.unprotect(request)
        protected, _ = server.protect(aiocoap.Message(code=aiocoap.CONTENT, payload=b"body"), binding)
        protected.mid, protected.mtype, protected.token = 1, aiocoap.ACK, b"12345678"
        incoming = aiocoap.Message.decode(protected.encode())
        incoming.direction = Direction.INCOMING
        _, unrelated = self.request(client)
        with self.assertRaises(Exception):
            client.unprotect(incoming, unrelated)

    def test_complete_blockwise_and_hostile_representations(self):
        first = aiocoap.Message(code=aiocoap.CONTENT, payload=bytes(i % 251 for i in range(1024)),
                                content_format=42, etag=b"fixture", block2=(0, True, 6))
        offset, block, etag = check_body(first, 0, 2000, None)
        self.assertEqual((offset, block), (1024, (1, False, 6)))
        final = aiocoap.Message(code=aiocoap.CONTENT, payload=bytes(i % 251 for i in range(1024, 2000)),
                                content_format=42, etag=b"fixture", block2=(1, False, 6))
        self.assertEqual(check_body(final, offset, 2000, etag)[0], 2000)
        for change in (dict(code=aiocoap.UNAUTHORIZED), dict(content_format=0), dict(payload=b"bad"),
                       dict(etag=b"changed"), dict(block2=(0, False, 6)), dict(block2=(1, True, 6)), dict(block2=None)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                check_body(final.copy(**change), offset, 2000, etag)
        with self.assertRaisesRegex(ValueError, "size increased"):
            check_body(final, offset, 2000, etag, (2, False, 5))

    def test_credentials_length_refused(self):
        self.credentials.write_bytes(b"short")
        with self.assertRaises(ValueError):
            Context(self.credentials)


if __name__ == "__main__":
    unittest.main()
