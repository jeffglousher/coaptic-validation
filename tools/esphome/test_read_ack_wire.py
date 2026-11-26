"""Wire-shape and complete-body checks for both ESP benchmark response modes."""
import unittest
from unittest.mock import Mock

import aiocoap as coap

from read_ack_wire import empty_ack, match_wire, read


class ReadWireTests(unittest.TestCase):
    def setUp(self):
        self.token = b"coap"
        self.body = b"Z" * 2000

    def reply(self, index, separate, **changes):
        body = self.body[1024*index:1024*(index+1)]
        m = coap.Message(code=coap.CONTENT, etag=b"large-v1", payload=body,
                         block2=(index, index == 0, 6))
        m.mtype = coap.CON if separate else coap.ACK
        m.mid = (123 if separate else 10) + index
        m.token = self.token
        return m.copy(**changes).encode()

    def test_blockwise_full_exchange_and_client_acks(self):
        for separate in (False, True):
            with self.subTest(separate=separate):
                sock = Mock()
                datagrams = []
                for i in range(2):
                    if separate:
                        datagrams.append(empty_ack(10+i))
                    datagrams.append(self.reply(i, separate))
                sock.recv.side_effect = datagrams
                row, mid = read(sock, "large", self.body, separate, self.token, 10)
                self.assertEqual((mid, row["verified_bytes"]), (12, 2000))
                sent = [v.args[0] for v in sock.send.call_args_list]
                if separate:
                    self.assertEqual(sent[1::2], [b"\x60\0\0\x7b", b"\x60\0\0\x7c"])
                for i, wire in enumerate(sent[::2] if separate else sent):
                    m = coap.Message.decode(wire)
                    self.assertEqual(m.opt.uri_query, ("ack=1" if separate else "ack=0",))
                    self.assertEqual(m.opt.block2, (i, False, 6))
                    self.assertEqual(len(row["blocks"][i]["wire_bytes"]), 4 if separate else 2)

    def test_refuse_missing_duplicate_wrong_or_unverified_datagram_before_ack(self):
        ack, content = empty_ack(10), self.reply(0, True)
        variants = [[content], [ack, ack], [empty_ack(11)], [ack, self.reply(0, False)],
                    [ack, self.reply(0, True, token=b"x")], [ack, self.reply(0, True, payload=b"x")],
                    [ack, self.reply(0, True, block2=(1, True, 6))],
                    [ack, self.reply(0, True, etag=b"changed")]]
        for received in variants:
            with self.subTest(received=received):
                sock = Mock()
                sock.recv.side_effect = received
                with self.assertRaises(ValueError):
                    read(sock, "large", self.body, True, self.token, 10)
                self.assertEqual(sock.send.call_count, 1)

    def test_second_block_requires_its_own_ack_and_valid_next_read_is_accepted(self):
        sock = Mock()
        first = [empty_ack(10), self.reply(0, True)]
        sock.recv.side_effect = first + [self.reply(1, True)]
        with self.assertRaisesRegex(ValueError, "request ACK"):
            read(sock, "large", self.body, True, self.token, 10)
        sent = [v.args[0] for v in sock.send.call_args_list]
        self.assertEqual([wire for wire in sent if len(wire) == 4], [empty_ack(123)])
        sock.recv.side_effect = [self.reply(0, False, mid=12), self.reply(1, False, mid=13)]
        row, _ = read(sock, "large", self.body, False, self.token, 12)
        self.assertEqual(row["verified_bytes"], 2000)

    def test_cross_peer_comparison_includes_both_ack_lengths(self):
        def report(ack_length, mid):
            return dict(security="unprotected", identity_checks=2, verified=1,
                        operations=[dict(path="test", exchange="separate-con", verified_bytes=7,
                                         blocks=[dict(request_mid=mid, response_mid=mid+1,
                                                      wire_bytes=[21, 4, 18, ack_length])])])
        match_wire(report(4, 1), report(4, 300))
        with self.assertRaisesRegex(ValueError, "datagram lengths"):
            match_wire(report(4, 1), report(5, 300))

    def test_piggyback_requires_request_mid(self):
        sock = Mock()
        sock.recv.side_effect = [self.reply(0, False, mid=9)]
        with self.assertRaises(ValueError):
            read(sock, "large", self.body, False, self.token, 10)


if __name__ == "__main__":
    unittest.main()
