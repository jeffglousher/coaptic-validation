import unittest

import aiocoap

from recovery_peer import Peer


class CancellationRaceTests(unittest.TestCase):
    def test_queued_notification_and_old_ack_cannot_complete_cancellation(self):
        token = b"relation"
        notification = aiocoap.Message(code=aiocoap.CONTENT, payload=b"tick", observe=4)
        notification.mtype, notification.mid, notification.token = aiocoap.CON, 70, token
        old_ack = aiocoap.Message(code=aiocoap.CONTENT, payload=b"old")
        old_ack.mtype, old_ack.mid, old_ack.token = aiocoap.ACK, 71, token
        cancelled = aiocoap.Message(code=aiocoap.CONTENT, payload=b"cancelled")
        cancelled.mtype, cancelled.mid, cancelled.token = aiocoap.ACK, 72, token

        class Channel:
            def __init__(self):
                self.packets = [p.encode() for p in (notification, old_ack, cancelled)]
                self.sent = []

            def send(self, packet):
                self.sent.append(aiocoap.Message.decode(packet))

            def settimeout(self, _):
                pass

            def recv(self, _):
                return self.packets.pop(0)

        channel = Channel()
        peer = Peer(channel, "127.0.0.1", 5683)
        peer.mid = 72
        response = peer.exchange(peer.request("ticks", token=token, observe=1))
        self.assertEqual(response.payload, b"cancelled")
        self.assertEqual(len(channel.sent), 2)
        self.assertEqual(channel.sent[1].mtype, aiocoap.ACK)
        self.assertEqual(channel.sent[1].mid, notification.mid)


if __name__ == "__main__":
    unittest.main()
