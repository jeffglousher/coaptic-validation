import hashlib
import json
from pathlib import Path
import socket
import tempfile
import unittest

import packet_trace as trace


class PacketTraceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        (self.directory / 'synthetic-credentials.bin').write_bytes(bytes(range(24)))
        self.coap, self.Direction, self.Context, _ = trace.dependencies()

    def tearDown(self):
        self.temp.cleanup()

    def frames(self, protected=False, size=64, mode='con', bootstrap=False, echo=False):
        coap = self.coap
        sender = self.Context(self.directory / 'synthetic-credentials.bin', sequence=1 << 32)
        responder = self.Context(self.directory / 'synthetic-credentials.bin', server=True)
        frames = []
        mid = 100
        for operation in range(5 if bootstrap else 4):
            for offset in range(0, size, 1024):
                block = (offset // 1024, False, 6) if size > 1024 else None
                request = coap.Message(code=coap.GET, uri_path=('bench',), block2=block)
                request.mtype = coap.CON if mode == 'con' else coap.NON
                request.mid, request.token = mid, operation.to_bytes(8, "big") if bootstrap else bytes([operation + 1])
                binding = None
                if protected:
                    outgoing, binding = sender.protect(request)
                    outgoing.mid, outgoing.mtype, outgoing.token = request.mid, request.mtype, request.token
                else:
                    outgoing = request
                frames.append((dict(direction='request', client=['127.0.0.1', 5600]), outgoing.encode()))
                if echo and operation == 0 and offset == 0:
                    outgoing.direction = self.Direction.INCOMING
                    _, challenge_binding = responder.unprotect(outgoing)
                    challenge = coap.Message(code=coap.UNAUTHORIZED, echo=b'fresh123')
                    challenge, _ = responder.protect(challenge, challenge_binding)
                    challenge.mid, challenge.token = mid, request.token
                    challenge.mtype = coap.ACK if mode == 'con' else coap.NON
                    frames.append((dict(direction='response', client=['127.0.0.1', 5600]), challenge.encode()))
                    request.opt.echo = b'fresh123'
                    mid += 1
                    request.mid = mid
                    outgoing, binding = sender.protect(request)
                    outgoing.mid, outgoing.mtype, outgoing.token = mid, request.mtype, request.token
                    frames.append((dict(direction='request', client=['127.0.0.1', 5600]), outgoing.encode()))

                response = coap.Message(code=coap.CONTENT, content_format=42,
                    payload=bytes(i % 251 for i in range(offset, min(offset + 1024, size))))
                if size > 1024:
                    response.opt.block2 = (offset // 1024, offset + 1024 < size, 6)
                    response.opt.etags = (b'one',)
                response.mid = mid if mode == 'con' else mid + 1000
                response.mtype = coap.ACK if mode == 'con' else coap.NON
                response.token = request.token
                if protected:
                    outgoing.direction = self.Direction.INCOMING
                    _, server_binding = responder.unprotect(outgoing)
                    reply, _ = responder.protect(response, server_binding)
                    reply.mid, reply.mtype, reply.token = response.mid, response.mtype, response.token
                else:
                    reply = response
                frames.append((dict(direction='response', client=['127.0.0.1', 5600]), reply.encode()))
                mid += 1
        return frames

    def case(self, protected=False, size=64, mode='con'):
        return dict(security=trace.SECURITY if protected else 'unprotected', bytes=size,
                    operations=3, warmup=1, concurrency=1, mode=mode)

    def test_complete_plain_and_authenticated_blockwise(self):
        for protected in (False, True):
            for size in (64, 65536):
                for mode in ('con', 'non'):
                    with self.subTest(protected=protected, size=size, mode=mode):
                        result = trace.grade_coap(self.directory, self.case(protected, size, mode), self.frames(protected, size, mode))
                        self.assertEqual(result['completed_including_warmup'], 4)
                        self.assertEqual(result['authenticated'], protected)

    def test_authenticated_echo_bootstrap_is_control_not_body(self):
        case = dict(self.case(True), bootstrap_completed=1, bootstrap_echo_challenges=1)
        frames = self.frames(True, bootstrap=True, echo=True)
        result = trace.grade_coap(self.directory, case, frames)
        self.assertEqual(result['completed_including_warmup'], 5)
        self.assertEqual(result['authenticated_echo_challenges'], 1)
        with self.assertRaises(ValueError):
            trace.grade_coap(self.directory, dict(case, bootstrap_echo_challenges=0), frames)
        row, wire = frames[1]
        frames[1] = row, wire[:-1] + bytes([wire[-1] ^ 1])
        with self.assertRaises(Exception):
            trace.grade_coap(self.directory, case, frames)

    def test_partial_and_tampered_authenticated_refused(self):
        for protected in (False, True):
            frames = self.frames(protected, 2048)
            with self.assertRaises(ValueError):
                trace.grade_coap(self.directory, self.case(protected, 2048), frames[:-1])
            row, wire = frames[1]
            frames[1] = row, wire[:-1] + bytes([wire[-1] ^ 1])
            with self.assertRaises(Exception):
                trace.grade_coap(self.directory, self.case(protected, 2048), frames)

    def test_identity_status_format_etag_and_block_refused(self):
        for field in ('token', 'mid', 'status', 'format', 'etag', 'block'):
            frames = self.frames(False, 2048)
            row, wire = frames[3]
            msg = self.coap.Message.decode(wire)
            if field == 'token': msg.token = b'foreign'
            if field == 'mid': msg.mid += 1
            if field == 'status': msg.code = self.coap.BAD_REQUEST
            if field == 'format': msg.opt.content_format = 0
            if field == 'etag': msg.opt.etags = (b'changed',)
            if field == 'block': msg.opt.block2 = (0, False, 6)
            msg.direction = self.Direction.OUTGOING
            frames[3] = row, msg.encode()
            with self.subTest(field=field), self.assertRaises(ValueError):
                trace.grade_coap(self.directory, self.case(False, 2048), frames)

    def test_pcap_roundtrip_and_truncation_even_with_updated_hash(self):
        writer = trace.Writer(self.directory)
        for row, wire in self.frames():
            writer.record(wire, row['direction'], row['client'], ('127.0.0.1', 1), ('127.0.0.1', 2))
        writer.close()
        receipt = dict(frames=writer.count, hashes={name: trace.campaign.digest(self.directory / name) for name in ('datagrams.pcap', 'frames.jsonl')})
        self.assertEqual(len(list(trace.records(self.directory, receipt))), 8)
        path = self.directory / 'datagrams.pcap'
        path.write_bytes(path.read_bytes()[:-1])
        receipt['hashes'][path.name] = trace.campaign.digest(path)
        with self.assertRaises(ValueError): list(trace.records(self.directory, receipt))

    def test_relay_preserves_received_payloads(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            server.bind(('127.0.0.1', 0)); server.settimeout(1); client.settimeout(1)
            with trace.Relay(self.directory, server.getsockname()) as relay:
                client.sendto(b'actual UDP bytes', relay.address)
                data, source = server.recvfrom(100)
                self.assertEqual(data, b'actual UDP bytes')
                server.sendto(b'actual response bytes', source)
                self.assertEqual(client.recvfrom(100)[0], b'actual response bytes')
            self.assertIsNone(relay.error)
            self.assertEqual(relay.writer.count, 2)

    def test_missing_whole_operation_and_replay_refused(self):
        frames = self.frames(True)
        with self.assertRaises(ValueError):
            trace.grade_coap(self.directory, self.case(True), frames[:-2])
        with self.assertRaises(Exception):
            trace.grade_coap(self.directory, self.case(True), frames[:2] + frames)

    def test_separate_response_requires_request_ack_even_if_reordered(self):
        frames = self.frames()
        row, wire = frames[1]
        response = self.coap.Message.decode(wire)
        request_mid = response.mid
        response.mtype, response.mid = self.coap.NON, 900
        response.direction = self.Direction.OUTGOING
        frames[1] = row, response.encode()
        with self.assertRaises(ValueError):
            trace.grade_coap(self.directory, self.case(), frames)
        ack = bytes([0x60, 0, request_mid >> 8, request_mid & 255])
        frames.insert(2, (row, ack))
        self.assertEqual(trace.grade_coap(self.directory, self.case(), frames)['completed_including_warmup'], 4)
        frames.insert(3, (row, ack))
        with self.assertRaises(ValueError):
            trace.grade_coap(self.directory, self.case(), frames)

    def test_writer_refuses_caps_without_writing_partial_record(self):
        writer = trace.Writer(self.directory)
        writer.count = trace.MAX_FRAMES
        with self.assertRaises(ValueError):
            writer.record(b'x', 'request', ('127.0.0.1', 1), ('127.0.0.1', 2), ('127.0.0.1', 3))
        writer.count = 0
        writer.size = trace.MAX_BYTES
        with self.assertRaises(ValueError):
            writer.record(b'x', 'request', ('127.0.0.1', 1), ('127.0.0.1', 2), ('127.0.0.1', 3))
        writer.close()
        self.assertEqual((self.directory / 'datagrams.pcap').read_bytes(), trace.HEADER)

    def test_dtls_only_framing_and_truncation(self):
        record = bytes.fromhex('17fefd00010000000000000008') + b'ciphered'
        frames = [(dict(direction=d), record) for d in ('request', 'response')]
        self.assertFalse(trace.grade_dtls(frames)['authenticated'])
        with self.assertRaises(ValueError): trace.grade_dtls([(dict(direction='request'), record[:-1])])


if __name__ == '__main__':
    unittest.main()


