import copy
import errno
import socket
import struct
import unittest

from pmtu_peer import grade_error


class PmtuOracle(unittest.TestCase):
    def receipt(self):
        original = bytes(range(32)) + b"p" * 1368
        remote = ["fd42:c0a:2::2", 56830, 0, 0]
        router = "fd42:c0a:1::1"
        control = struct.pack("=IBBBBII", errno.EMSGSIZE, 3, 2, 0, 0, 1280, 0)
        control += struct.pack("=H", socket.AF_INET6) + bytes(6)
        control += socket.inet_pton(socket.AF_INET6, router) + bytes(4)
        return original, remote, router, dict(level=socket.IPPROTO_IPV6, type=25,
            control_hex=control.hex(), destination=remote, quoted_hex=original[:1000].hex(), flags=0)

    def test_exact_quote_destination_offender_and_mtu(self):
        original, remote, router, row = self.receipt()
        self.assertEqual(grade_error(row, original, remote, router)["mtu"], 1280)

    def test_false_error_evidence_is_refused(self):
        original, remote, router, good = self.receipt()
        for mutation in ("quote", "destination", "offender", "origin", "type", "mtu", "truncation"):
            row = copy.deepcopy(good)
            control = bytearray.fromhex(row["control_hex"])
            if mutation == "quote":
                row["quoted_hex"] = b"unrelated".hex()
            elif mutation == "destination":
                row["destination"][1] += 1
            elif mutation == "offender":
                control[39] ^= 1
            elif mutation == "origin":
                control[4] = 1
            elif mutation == "type":
                control[5] = 1
            elif mutation == "mtu":
                struct.pack_into("=I", control, 8, 1500)
            else:
                row["flags"] = socket.MSG_CTRUNC
            row["control_hex"] = control.hex()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                grade_error(row, original, remote, router)


if __name__ == "__main__":
    unittest.main()
