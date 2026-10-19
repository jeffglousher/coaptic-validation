"""Refusal mutations for the finite independent option fixture's wire grading."""
import unittest

import aiocoap
from aiocoap.optiontypes import OpaqueOption

from edhoc_options import control, extra, options, silence, bootstrap_request


class Grading(unittest.IsolatedAsyncioTestCase):
    def test_exact_control_rejects_every_nonempty_or_wrong_owner_field(self):
        for kind in (aiocoap.ACK, aiocoap.RST):
            for field, value in (("mtype", aiocoap.NON), ("code", aiocoap.BAD_OPTION),
                                 ("mid", 10), ("token", b"changed"), ("payload", b"x"),
                                 ("option", b"x")):
                message = aiocoap.Message(code=aiocoap.EMPTY)
                message.mtype, message.mid = kind, 9
                control(message, kind, 9)
                if field == "option":
                    message.opt.add_option(OpaqueOption(2048, value))
                else:
                    setattr(message, field, value)
                with self.subTest(kind=kind, field=field), self.assertRaises(ValueError):
                    control(message, kind, 9)

    def test_elective_wire_retains_required_metadata_and_changed_bytes(self):
        original = extra(bootstrap_request(b"native-message", 1, 9, b"t"))
        changed = extra(bootstrap_request(b"native-message", 1, 9, b"t"), changed=True)
        decoded = aiocoap.Message.decode(original.encode())
        self.assertEqual(options(decoded), [(0, b""), (10, b"before"),
                         (11, b".well-known"), (11, b"edhoc"), (12, b"A"), (12, b"\x7f"),
                         (14, b""), (14, b"\x01"), (2048, b"after")])
        self.assertEqual(decoded.payload, b"\xf5native-message")
        self.assertNotEqual(original.encode(), changed.encode())
        self.assertEqual((original.mid, original.token, original.payload),
                         (changed.mid, changed.token, changed.payload))

    async def test_strict_silence_rejects_even_empty_or_error_responses(self):
        class Wire:
            def __init__(self, value):
                self.value = value
            async def receive(self, *_):
                if self.value is None:
                    raise TimeoutError
                return b"wire", self.value
        await silence(Wire(None), None, "quiet")
        for code in (aiocoap.EMPTY, aiocoap.BAD_OPTION, aiocoap.CHANGED):
            with self.subTest(code=code), self.assertRaises(ValueError):
                await silence(Wire(aiocoap.Message(code=code)), None, "not quiet")


if __name__ == "__main__":
    unittest.main()
