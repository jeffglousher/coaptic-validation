import copy
import unittest

from compound_relay import grade


class CompoundOracle(unittest.TestCase):
    def trace(self):
        request = bytes.fromhex("480112340102030405060708b474657374")
        response = bytes.fromhex("684512340102030405060708ff") + b"coaptic-scoped-addressing"
        fresh_request = bytearray(request)
        fresh_response = bytearray(response)
        fresh_request[3] += 1
        fresh_response[3] += 1
        changed = bytearray(response)
        changed[4] ^= 1
        peer = ["fd42:c0a:1::2",20000,0,0]
        return [dict(event="request",hex=request.hex(),peer=peer),
                dict(event="response",hex=response.hex(),action="drop"),
                dict(event="inject",hex="00"),dict(event="inject",hex=changed.hex()),
                dict(event="request",hex=request.hex(),peer=peer),
                dict(event="response",hex=response.hex(),action="forward"),
                dict(event="request",hex=fresh_request.hex(),peer=peer),
                dict(event="response",hex=fresh_response.hex(),action="forward")]

    def test_exact_compound_schedule(self):
        self.assertTrue(grade(self.trace())["fresh_exchange"])

    def test_omitted_loss_malformed_or_wrong_identity_refused(self):
        for mutation in ("loss","malformed","identity","fresh"):
            rows = copy.deepcopy(self.trace())
            if mutation == "loss":
                rows[1]["action"] = "forward"
            elif mutation == "malformed":
                rows.pop(2)
            elif mutation == "identity":
                rows[4]["peer"][1] += 1
                # deepcopy preserves the shared fixture owner list; give the
                # retransmission a separate changed owner for this mutation.
                rows[4]["peer"] = ["fd42:c0a:1::3",20001,0,0]
            else:
                rows[6]["hex"] = rows[0]["hex"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                grade(rows)


if __name__ == "__main__":
    unittest.main()
