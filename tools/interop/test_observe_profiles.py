"""Offline counterexamples for the added independent evidence oracles."""
import unittest

import aiocoap
from oscore_qblock1 import FixtureContext
from protected_tokens import grade, incoming, plain_request, plain_response


def wire(message, token, mid, kind):
    if len(token) <= 12:
        prefix = bytes([0x40 | kind << 4 | len(token), int(message.code)]) + mid.to_bytes(2, "big")
    else:
        prefix = bytes([0x40 | kind << 4 | 13, int(message.code)]) + mid.to_bytes(2, "big") + bytes([len(token) - 13])
    return prefix + token + message.opt.encode() + (b"\xff" + message.payload if message.payload else b"")


class ExtendedProtectedOracle(unittest.TestCase):
    def fixture(self, length=32, code=68):
        token = bytes(range(length))
        request = aiocoap.Message(code=aiocoap.POST, payload=b"effect")
        request.opt.uri_path = ("counter",)
        protected, _ = FixtureContext(server=False).protect(request)
        sent = wire(protected, token, 123, 0)
        plain, binding = plain_request(sent)
        self.assertEqual(plain.payload, b"effect")
        reply = aiocoap.Message(code=code)
        protected_reply, _ = FixtureContext(server=True).protect(reply, binding)
        received = wire(protected_reply, token, 123, 2)
        return sent, received

    def test_full_extended_token_reaches_independent_crypto(self):
        for length in (32, 64):
            sent, received = self.fixture(length)
            self.assertEqual(incoming(sent).token, bytes(range(length)))
            self.assertEqual(int(plain_response(received, sent).code), 68)

    def test_ciphertext_mutation_is_rejected(self):
        sent, _ = self.fixture()
        with self.assertRaises(Exception):
            plain_request(sent[:-1] + bytes([sent[-1] ^ 1]))

    def test_full_token_and_mid_correlation_cannot_be_shortened(self):
        sent, received = self.fixture()
        trace = [dict(direction="request", hex=sent.hex(), forwarded_hex=sent.hex(), action="forward"),
                 dict(direction="response", hex=received.hex(), forwarded_hex=received.hex(), action="forward")]
        for index, row in enumerate(trace):
            row.update(source=["127.0.0.1", 1000 if index == 0 else 2000],
                       destination=["127.0.0.1", 2000 if index == 0 else 1000],
                       relay=["127.0.0.1", 3000 if index == 0 else 4000], time_ns=index)
        grade(trace, 32)
        for offset in (2, 5 + 31):
            changed = bytearray(received)
            changed[offset] ^= 1
            trace[1]["hex"] = trace[1]["forwarded_hex"] = changed.hex()
            with self.assertRaises(AssertionError):
                grade(trace, 32)


if __name__ == "__main__":
    unittest.main()
