"""Focused authentication and complete-body failure checks for the matched driver."""
import secrets
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "protected"))
import aiocoap
from aiocoap.message import Direction
from context import Context
from load import DriverError, GroupObservation, Worker, body_matches, check_body, run
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
                               warmup=1, timeout_ms=1000, sequence=0, mode="con", security="unprotected")
        with patch.object(Worker, "bootstrap") as bootstrap, patch.object(
                Worker, "exchange", side_effect=[ValueError("warmup"), DriverError("rotation"), 100]):
            result = run(args)
        bootstrap.assert_called_once()
        self.assertEqual((result["attempted"], result["completed"], result["failed"], result["warmup_failed"],
                          result["driver_failures"], result["verified_bytes"]), (2, 1, 1, 1, 1, 64))
        self.assertNotIn("requested_operations_per_second", result)
        self.assertNotIn("start_group_width", result)

    def test_paced_workers_share_one_schedule_and_count_every_missed_period(self):
        args = SimpleNamespace(host="127.0.0.1", port=1, bytes=64, concurrency=2, operations=5,
                               warmup=0, timeout_ms=1000, sequence=0, mode="con",
                               security="unprotected", rate=400)
        period = 2_500_000
        with patch.object(Worker, "bootstrap"), patch.object(Worker, "exchange", return_value=100):
            with patch("load.wait_for_slot", side_effect=lambda due: due + period) as wait:
                result = run(args)
        due = sorted(call.args[0] for call in wait.call_args_list)
        self.assertEqual([value - due[0] for value in due], [0, period, 2 * period, 3 * period, 4 * period])
        self.assertEqual(result["completed"], 5)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["requested_operations_per_second"], 400)
        self.assertEqual(result["pacing_missed_period_operations"], 5)
        self.assertEqual(result["pacing_max_lateness_ns"], period)

    def test_group_starts_require_paced_con_and_complete_groups(self):
        args = dict(host="127.0.0.1", port=1, bytes=64, concurrency=2, operations=6,
                    warmup=0, timeout_ms=1000, sequence=0, mode="con",
                    security="unprotected", rate=400, group_starts=True)
        with patch("load.Worker") as worker:
            for overrides in (dict(rate=None), dict(mode="non"), dict(operations=5)):
                with self.subTest(overrides=overrides):
                    with self.assertRaisesRegex(ValueError, "paced CON and complete groups"):
                        run(SimpleNamespace(**(args | overrides)))
        worker.assert_not_called()

    def test_group_schedule_keeps_failed_and_just_touching_intervals_distinct(self):
        args = SimpleNamespace(host="127.0.0.1", port=1, bytes=64, concurrency=2, operations=6,
                               warmup=0, timeout_ms=1000, sequence=0, mode="con",
                               security="unprotected", rate=400, group_starts=True)
        epoch = 1000
        period = 5_000_000
        # Two verified groups, but only the first pair overlaps.
        intervals = ((100, 200), (150, 210), (230, 300), None, (400, 450), (450, 500))

        def exchange(worker, sequence, *, observation):
            interval = intervals[(sequence - 1) * 2 + worker.number]
            if interval is None:
                raise DriverError("group member failed")
            first, last = interval
            observation.first_send_ns = epoch + first
            observation.final_receive_ns = epoch + last
            return last - first

        with patch.object(Worker, "bootstrap"), patch.object(Worker, "exchange", new=exchange):
            with patch("load.wait_for_slot", side_effect=lambda due: due + period) as wait:
                with patch("load.time.perf_counter_ns", return_value=epoch):
                    result = run(args)
        self.assertEqual(sorted(call.args[0] - epoch for call in wait.call_args_list),
                         [0, 0, period, period, 2 * period, 2 * period])
        self.assertEqual(result["pacing_missed_period_operations"], 6)
        self.assertEqual(result["pacing_max_lateness_ns"], period)
        self.assertEqual(result["verified_by_worker"], [3, 2])
        self.assertEqual(len(set(result["worker_endpoint_ports"])), 2)
        self.assertEqual(result["verified_groups"], 2)
        self.assertEqual(result["overlapping_verified_groups"], 1)
        self.assertEqual(result["failed"], 1)

    def test_group_wire_counts_distinguish_confirmed_response_shapes(self):
        for response_type in (aiocoap.ACK, aiocoap.CON):
            with self.subTest(response_type=response_type):
                separate = response_type == aiocoap.CON
                reply = aiocoap.Message(code=aiocoap.CONTENT, content_format=42,
                                        payload=bytes(range(64)))
                reply.mid, reply.mtype, reply.token = int(separate), response_type, (1).to_bytes(8, "big")
                empty_ack = bytes([0x60, 0, 0, 0])
                sock = Mock()
                sock.recv.side_effect = ([empty_ack] if separate else []) + [reply.encode()]
                args = SimpleNamespace(host="127.0.0.1", port=1, bytes=64, timeout_ms=1000, mode="con")
                with patch.object(Worker, "new_socket", return_value=sock):
                    worker = Worker(args, 0, None, threading.Lock())
                    observation = GroupObservation(1)
                    epoch = time.perf_counter_ns()
                    worker.exchange(1, observation=observation)
                    observation.record_verified(0, epoch)
                self.assertLessEqual(observation.first_sends[0], observation.final_receives[0])
                self.assertEqual(observation.wire, dict(
                    data_requests=1, received_datagrams=1 + separate,
                    matching_empty_acks=int(separate), piggybacked_responses=int(not separate),
                    separate_con_responses=int(separate), separate_non_responses=0,
                    sent_response_acks=int(separate),
                ))

    def test_matched_exchange_requires_each_canonical_ack_and_verified_block(self):
        token = (1).to_bytes(8, "big")
        def response(kind, mid, num, **changes):
            block = aiocoap.Message(code=aiocoap.CONTENT, content_format=42, etag=b"fixture",
                                    block2=(num, num == 0, 0),
                                    payload=bytes(range(num * 16, (num + 1) * 16)))
            block.mtype, block.mid, block.token = kind, mid, token
            return block.copy(**changes).encode()

        ack0, ack1 = bytes([0x60, 0, 0, 0]), bytes([0x60, 0, 0, 1])
        con0, con1 = response(aiocoap.CON, 100, 0), response(aiocoap.CON, 101, 1)
        pig0, pig1 = response(aiocoap.ACK, 0, 0), response(aiocoap.ACK, 1, 1)
        cases = [
            ("separate-con", [ack0, con0, ack1, con1], True, [100, 101]),
            ("piggyback", [pig0, pig1], True, []),
            ("separate-con", [ack0, con0, pig1], False, [100]),
            ("separate-con", [ack0, con0, con1], False, [100]),
            ("separate-con", [ack0, con0, ack1, response(aiocoap.CON, 100, 1)], False, [100]),
            ("separate-con", [ack0, response(aiocoap.CON, 100, 0, etag=b"wrong")], False, []),
            ("separate-con", [ack0, response(aiocoap.CON, 100, 0, size2=31)], False, []),
            ("separate-con", [ack0, response(aiocoap.CON, 100, 0, size2=32), ack1, con1], True, [100, 101]),
            ("separate-con", [ack0, ack0, con0, con1], False, []),
            ("separate-con", [ack1, con0], False, []),
            ("separate-con", [ack0 + b"\xffx", con0], False, []),
            ("separate-con", [ack0, response(aiocoap.CON, 100, 0, token=b"x")], False, []),
            ("separate-con", [ack0, response(aiocoap.CON, 100, 0, payload=b"x")], False, []),
            ("piggyback", [ack0, con0], False, []),
            ("piggyback", [con0], False, []),
            ("piggyback", [response(aiocoap.ACK, 1, 0)], False, []),
        ]
        for shape, packets, valid, ack_mids in cases:
            with self.subTest(shape=shape, packets=packets):
                sock = Mock()
                sock.recv.side_effect = packets
                args = SimpleNamespace(bytes=32, mode="con", timeout_ms=1000, expect_exchange=shape)
                with patch.object(Worker, "new_socket", return_value=sock):
                    worker = Worker(args, 0, None, threading.Lock())
                    if valid:
                        self.assertGreater(worker.exchange(1), 0)
                    else:
                        with self.assertRaises(ValueError):
                            worker.exchange(1)
                controls = [call.args[0] for call in sock.send.call_args_list if call.args[0][0] == 0x60]
                self.assertEqual(controls, [bytes([0x60, 0, 0, mid]) for mid in ack_mids])

    def echo_worker(self, responses, *, tamper=False):
        server = Context(self.credentials, server=True)
        pending, requests = [], []
        sock = Mock()
        def send(wire):
            incoming = aiocoap.Message.decode(wire)
            incoming.direction = Direction.INCOMING
            request, binding = server.unprotect(incoming)
            requests.append(request)
            response = responses[len(requests) - 1]
            protected, _ = server.protect(response, binding)
            protected.mid, protected.mtype, protected.token = incoming.mid, aiocoap.ACK, incoming.token
            if tamper:
                protected.payload = protected.payload[:-1] + bytes([protected.payload[-1] ^ 1])
            pending.append(protected.encode())
        sock.send.side_effect = send
        sock.recv.side_effect = lambda _: pending.pop(0)
        args = SimpleNamespace(host="127.0.0.1", port=1, bytes=64, timeout_ms=1000, mode="con")
        with patch.object(Worker, "new_socket", return_value=sock):
            worker = Worker(args, 0, Context(self.credentials), threading.Lock())
        self.addCleanup(worker.close)
        return worker, requests

    def test_authenticated_echo_bootstrap_retries_once_and_verifies_complete_body(self):
        challenge = aiocoap.Message(code=aiocoap.UNAUTHORIZED, echo=b"nonce123")
        body = aiocoap.Message(code=aiocoap.CONTENT, payload=bytes(range(64)), content_format=42)
        worker, requests = self.echo_worker([challenge, body])
        worker.bootstrap()
        self.assertEqual([r.opt.echo for r in requests], [None, b"nonce123"])
        self.assertEqual(worker.bootstrap_echo_challenges, 1)
        self.assertEqual(worker.mid, 2)

    def test_echo_is_not_a_timed_success_and_setup_failures_are_not_filtered(self):
        challenge = aiocoap.Message(code=aiocoap.UNAUTHORIZED, echo=b"nonce123")
        worker, requests = self.echo_worker([challenge])
        with self.assertRaisesRegex(ValueError, "Echo challenge"):
            worker.exchange(1)
        self.assertEqual(len(requests), 1)
        self.assertEqual(worker.bootstrap_echo_challenges, 0)
        args = SimpleNamespace(host="127.0.0.1", port=1, bytes=64, concurrency=1, operations=1,
                               warmup=0, timeout_ms=1000, sequence=0, mode="con", security="unprotected")
        with patch.object(Worker, "bootstrap", side_effect=ValueError("setup")), patch.object(Worker, "exchange") as exchange:
            with self.assertRaisesRegex(ValueError, "setup"):
                run(args)
        exchange.assert_not_called()

    def test_repeated_malformed_or_unauthenticated_echo_cannot_initialize(self):
        challenge = aiocoap.Message(code=aiocoap.UNAUTHORIZED, echo=b"nonce123")
        worker, requests = self.echo_worker([challenge, challenge])
        with self.assertRaisesRegex(ValueError, "Echo challenge"):
            worker.bootstrap()
        self.assertEqual((len(requests), worker.bootstrap_echo_challenges), (2, 1))
        for response in (challenge.copy(echo=b""), challenge.copy(echo=b"x" * 41),
                         challenge.copy(payload=b"unexpected"), challenge.copy(content_format=42)):
            with self.subTest(response=response):
                worker, requests = self.echo_worker([response])
                with self.assertRaises(ValueError):
                    worker.bootstrap()
                self.assertEqual(len(requests), 1)
                self.assertEqual(worker.bootstrap_echo_challenges, 0)
        worker, requests = self.echo_worker([challenge], tamper=True)
        with self.assertRaises(Exception):
            worker.bootstrap()
        self.assertEqual((len(requests), worker.bootstrap_echo_challenges), (1, 0))

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
