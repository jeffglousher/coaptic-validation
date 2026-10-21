"""Offline counterexamples for the added independent evidence oracles."""
from contextlib import contextmanager
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
    @contextmanager
    def child_server(self, body):
        from pathlib import Path
        import sys
        import tempfile
        from unittest.mock import patch
        from profiles import EvidenceServer
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"
            script = ('import os, sys, time\n'
                      'os.write(1, b\'{"schema":"coaptic-peer/2","event":"ready",'
                      '"port":1234,"transport":"udp"}\\n\')\n'
                      'deadline = time.monotonic() + 10\n'
                      'while not os.path.exists(sys.argv[1]):\n'
                      '    if time.monotonic() > deadline: raise SystemExit(2)\n'
                      '    time.sleep(0.001)\n' + body)
            with patch("run.command", return_value=[sys.executable, "-c", script, str(release)]):
                with EvidenceServer("unused", "udp", number=1234) as service:
                    release.touch()
                    yield service

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
        from profiles import ACTIVE_COMMANDS
        fatal = b'{"schema":"coaptic-peer/2","event":"error","message":"UDP failure"}\n\xff'
        body = (f'os.write(1, {fatal!r})\n'
                'os.write(2, b"Q notification: bounded failure")\n'
                'raise SystemExit(1)\n')
        before = len(ACTIVE_COMMANDS)
        try:
            with self.assertRaisesRegex(RuntimeError, "original"):
                with self.child_server(body) as service:
                    self.assertEqual(service.proc.wait(timeout=5), 1)
                    raise RuntimeError("original")
            self.assertTrue(service.proc.stdout.closed)
            self.assertTrue(service.stderr.closed)
            self.assertFalse(service.reader.is_alive())
            failure = ACTIVE_COMMANDS[-1]
            self.assertEqual(failure["exit_code_before_cleanup"], 1)
            self.assertIn("bounded failure", failure["stderr"])
            self.assertIn("UDP failure", failure["stdout_after_ready"])
            self.assertEqual(bytes.fromhex(failure["stdout_after_ready_hex"]), fatal)
            self.assertFalse(failure["stdout_after_ready_truncated"])
            self.assertTrue(failure["stdout_after_ready_complete"])
            self.assertIsNone(failure["stdout_after_ready_error"])
        finally:
            del ACTIVE_COMMANDS[before:]

    def test_verbose_server_drains_beyond_bound_without_changing_success(self):
        from profiles import ACTIVE_COMMANDS
        before = len(ACTIVE_COMMANDS)
        body = ('sys.stdout.buffer.write(b"x" * 262144)\n'
                'sys.stdout.buffer.flush()\n')
        with self.child_server(body) as service:
            self.assertEqual(service.proc.wait(timeout=5), 0)
        self.assertEqual(len(ACTIVE_COMMANDS), before)
        self.assertEqual(service.stdout_after_ready, b"x" * 65536)
        self.assertTrue(service.stdout_after_ready_truncated)
        self.assertTrue(service.stdout_after_ready_complete)
        self.assertIsNone(service.stdout_after_ready_error)
        self.assertTrue(service.proc.stdout.closed)
        self.assertTrue(service.stderr.closed)
        self.assertFalse(service.reader.is_alive())


class QInitialControl(unittest.TestCase):
    def channel(self, kind, corrupt=None, initial_corrupt=None, switch_kind=False):
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
                if initial_corrupt and index == 0:
                    opts = initial_corrupt(opts)
                wire = coap_message(69, index + 100, b"qobs", opts, b"a" * 32)
                actual_kind = 1 - kind if switch_kind and index == 10 else kind
                return bytes([(wire[0] & 0xcf) | (actual_kind << 4)]) + wire[1:]
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
        for mutate in (lambda opts: [(n, b"" if n == 4 else v) for n, v in opts],
                       lambda opts: [opts[0], *opts]):
            with self.assertRaises(AssertionError):
                q_initial_representation(self.channel(0, initial_corrupt=mutate), b"qobs")
        with self.assertRaises(AssertionError):
            q_initial_representation(self.channel(0, switch_kind=True), b"qobs")


class QPacketClassification(unittest.TestCase):
    def packet(self, index, *, observe=True, body=b"b", token=b"qobs", kind=0, mid=None):
        from run import coap_message
        block = (index << 4) | (9 if index < 21 else 1)
        options = [(4, b"two")]
        if observe:
            options.append((6, b"\x02"))
        options += [(28, b"\x02\xc0"), (31, block.to_bytes((block.bit_length()+7)//8, "big"))]
        packet = coap_message(69, index + 100 if mid is None else mid, token, options, body * 32)
        return bytes([(packet[0] & 0xcf) | (kind << 4)]) + packet[1:]

    def test_owned_cancel_is_not_a_notification(self):
        from profiles import grade_q_notification_epoch
        from run import coap_message
        packets = [self.packet(index) for index in range(22)]
        requests = [b"\x60\x00" + packet[2:4] for packet in packets]
        cancel = coap_message(1, 400, b"qobs", [(6, b"\x01"), (11, b"obs-q"), (31, b"\x09")], non=True)
        extra = self.packet(0, observe=False, kind=1)
        grade_q_notification_epoch(packets + [extra], requests + [cancel], b"qobs", 704, 22)
        for extras, sent in (([extra], requests),
                             ([self.packet(0, observe=False, kind=1, token=b"other")], requests + [cancel]),
                             ([self.packet(1, observe=False, kind=1)], requests + [cancel]),
                             ([self.packet(0, observe=False, kind=2, mid=401)], requests + [cancel]),
                             ([extra], requests[1:] + [cancel])):
            with self.assertRaises(AssertionError):
                grade_q_notification_epoch(packets + extras, sent, b"qobs", 704, 22)
        with self.assertRaises(AssertionError):
            grade_q_notification_epoch([self.packet(0, kind=1), *packets[1:]], requests, b"qobs", 704, 22)

    def test_exact_recovery_duplicates_are_accepted(self):
        from observe_controls import grade_q_recovery
        from run import coap_message
        request = coap_message(1, 400, b"qobs", [(11, b"obs-q"), (31, b"\x01\x41"), (31, b"\x01\x51")])
        duplicate = self.packet(21, observe=False)
        for packet in (duplicate, duplicate, self.packet(20, observe=False),
                       self.packet(21, observe=False, kind=2, mid=400)):
            self.assertIn(grade_q_recovery(packet, request, [b"two"]), (20, 21))
        self.assertIsNone(grade_q_recovery(b"\x60\x00\x01\x90", request, [b"two"]))
        for packet in (self.packet(21, observe=False, body=b"x"), self.packet(19, observe=False),
                       self.packet(21), self.packet(21, observe=False, token=b"other"),
                       self.packet(21, observe=False, kind=2, mid=401),
                       duplicate.replace(b"two", b"bad"),
                       duplicate.replace(b"\x02\xc0", b"\x02\xc1")):
            with self.assertRaises(AssertionError):
                grade_q_recovery(packet, request, [b"two"])


if __name__ == "__main__":
    unittest.main()
