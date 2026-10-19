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


class SelectedFollowupOracle(unittest.TestCase):
    def test_native_independent_read_keeps_exact_identity(self):
        from run import coap_message
        from observe_controls import grade_changed_selection
        options = [(12, b""), (23, b"\x19")]
        response = coap_message(69, 1, b"left", options, b"m" * 32)
        self.assertEqual(grade_changed_selection(response, False)["behavior"], "independent-right-read")
        for changed, body in (([(12, b""), (23, b"\x09")], b"m" * 32),
                              ([(6, b""), *options], b"m" * 32),
                              ([(4, b"\x02"), *options], b"m" * 32),
                              (options, b"a" * 32)):
            with self.assertRaises(AssertionError):
                grade_changed_selection(coap_message(69, 1, b"left", changed, body), False)
        with self.assertRaises(AssertionError):
            grade_changed_selection(response, True)

    def test_core_refusal_remains_required(self):
        from run import coap_message
        from observe_controls import grade_changed_selection
        response = coap_message(128, 1, b"left", [])
        self.assertEqual(grade_changed_selection(response, True)["code"], 128)
        with self.assertRaises(AssertionError):
            grade_changed_selection(response, False)


class ObserveFixtureDiagnostics(unittest.TestCase):
    def test_fetch_continuation_requires_original_selection(self):
        from profiles import grade_fetch_continuation
        from run import coap_message
        options = [(11, b"obs-selected"), (12, b"*"), (23, b"\x11")]
        grade_fetch_continuation(coap_message(5, 2, b"new", options, b"left"))
        for opts, body in ((options, b""), (options, b"right"),
                           ([(11, b"test"), *options[1:]], b"left"),
                           ([options[0], (12, b""), options[2]], b"left")):
            with self.assertRaises(AssertionError):
                grade_fetch_continuation(coap_message(5, 2, b"new", opts, body))

    def test_failed_server_diagnostic_survives_cleanup(self):
        import tempfile
        from types import SimpleNamespace
        from profiles import EvidenceServer, ACTIVE_COMMANDS
        service = object.__new__(EvidenceServer)
        service.stderr = tempfile.TemporaryFile()
        service.stderr.write(b"Q notification: bounded failure")
        service.proc = SimpleNamespace(args=["peer", "server"], poll=lambda: 1)
        closed = []
        service.close = lambda: (closed.append(True), service.stderr.close())
        before = len(ACTIVE_COMMANDS)
        try:
            with self.assertRaisesRegex(RuntimeError, "original"):
                with service:
                    raise RuntimeError("original")
            self.assertEqual(closed, [True])
            self.assertEqual(ACTIVE_COMMANDS[-1]["exit_code_before_cleanup"], 1)
            self.assertIn("bounded failure", ACTIVE_COMMANDS[-1]["stderr"])
        finally:
            del ACTIVE_COMMANDS[before:]


class QInitialControl(unittest.TestCase):
    def channel(self, kind, corrupt=None):
        from run import coap_message
        class FakeChannel:
            def __init__(self):
                self.sent = []
                self.index = 0
            def send(self, code, token, options):
                self.sent.append(options)
                return coap_message(code, len(self.sent), token, options)
            def receive(self):
                index = self.index
                self.index += 1
                block = (index << 4) | (9 if index < 21 else 1)
                opts = [(4, b"one"), (6, b"\x02"), (28, b"\x02\xc0"),
                        (31, block.to_bytes((block.bit_length() + 7) // 8, "big"))]
                if corrupt and index == 10:
                    opts = corrupt(opts)
                wire = coap_message(69, index + 100, b"qobs", opts, b"a" * 32)
                return bytes([(wire[0] & 0xcf) | (kind << 4)]) + wire[1:]
        return FakeChannel()

    def test_con_train_acks_need_no_window_pull(self):
        from observe_controls import q_initial_representation
        channel = self.channel(0)
        q_initial_representation(channel, b"qobs")
        self.assertEqual(len(channel.sent), 1)

    def test_non_windows_request_exact_next_set(self):
        from observe_controls import q_initial_representation
        channel = self.channel(1)
        q_initial_representation(channel, b"qobs")
        self.assertEqual([options[-1] for options in channel.sent],
                         [(31, b"\x09"), (31, b"\xa9"), (31, b"\x01\x49")])

    def test_initial_metadata_change_is_not_accepted(self):
        from observe_controls import q_initial_representation
        for mutate in (lambda opts: [(n, b"two" if n == 4 else v) for n, v in opts],
                       lambda opts: [(n, v) for n, v in opts if n != 28]):
            with self.assertRaises(AssertionError):
                q_initial_representation(self.channel(0, mutate), b"qobs")


if __name__ == "__main__":
    unittest.main()
