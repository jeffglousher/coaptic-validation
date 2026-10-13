"""Focused authentication and complete-body failure checks for the matched driver."""
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "protected"))
import aiocoap
from aiocoap.message import Direction
from context import Context
from load import check_body


class ProtectedTests(unittest.TestCase):
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
                       dict(etag=b"changed"), dict(block2=(0, False, 6)), dict(block2=(1, True, 6))):
            with self.subTest(change=change), self.assertRaises(ValueError):
                check_body(final.copy(**change), offset, 2000, etag)

    def test_credentials_length_refused(self):
        self.credentials.write_bytes(b"short")
        with self.assertRaises(ValueError):
            Context(self.credentials)


if __name__ == "__main__":
    unittest.main()
