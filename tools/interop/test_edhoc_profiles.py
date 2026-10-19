import copy
import unittest

import blake3
from edhoc import DOMAIN, credential, derive
from edhoc_profiles import VECTORS, validate_profile


def completions(role, suite, ead):
    secret, salt = bytes(range(16)), bytes(range(8))
    peer_role = "responder" if role == "initiator" else "initiator"
    sender, recipient = (b"\x01", b"\x00") if role == "initiator" else (b"\x00", b"\x01")
    common = {"method": 3, "suite": suite, "message4": True,
              "exports": [{"label": label, "context": bytes(range(256))[:context].hex(),
                           "length": length, "hex": bytes(length).hex()} for label, context, length in VECTORS]}
    core = dict(common, complete=True, sender_id=sender.hex(), recipient_id=recipient.hex(),
                sender_key=derive(secret, salt, sender, "Key", 16).hex(),
                recipient_key=derive(secret, salt, recipient, "Key", 16).hex(),
                common_iv=derive(secret, salt, b"", "IV", 13).hex(),
                principal=blake3.blake3(credential(peer_role), derive_key_context=DOMAIN).hexdigest())
    native = copy.deepcopy(dict(common, master_secret=secret.hex(), master_salt=salt.hex(),
                                sender_id=recipient.hex(), recipient_id=sender.hex(),
                                peer_credential=credential(role).hex(), local_credential=credential(peer_role).hex()))
    for result, current in ((core, role), (native, peer_role)):
        result["ead_received"] = ([0, 3, 0, 3] if current == "initiator" else [3, 0, 3, 0]) if ead else [0] * 4
        result["ead_authenticated"] = (10 if current == "initiator" else 4) if ead else 0
    return core, native


class ProfileOracle(unittest.TestCase):
    def test_selected_profiles(self):
        for role in ("initiator", "responder"):
            for suite in (2, 3):
                for ead in (False, True):
                    validate_profile(*completions(role, suite, ead), role, suite, ead)

    def test_exporter_value_or_request_mismatch_refused(self):
        for field, replacement in (("hex", "01" * 16), ("context", "00"), ("label", 32769), ("length", 15)):
            core, native = completions("initiator", 3, True)
            native["exports"][0][field] = replacement
            with self.assertRaises(ValueError):
                validate_profile(core, native, "initiator", 3, True)

    def test_ead_missing_or_unauthenticated_stage_refused(self):
        for field, replacement in (("ead_received", [0, 3, 0, 2]), ("ead_authenticated", 2)):
            core, native = completions("initiator", 2, True)
            core[field] = replacement
            with self.assertRaises(ValueError):
                validate_profile(core, native, "initiator", 2, True)


if __name__ == "__main__":
    unittest.main()
