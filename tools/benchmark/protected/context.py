"""Process-lifetime benchmark OSCORE context; no provisioning or persistence API."""
from pathlib import Path
from aiocoap import oscore

SECURITY = "OSCORE-AES-CCM-16-64-128"
REPLAY_WINDOW = 32


class Context(oscore.CanProtect, oscore.CanUnprotect, oscore.SecurityContextUtils):
    def __init__(self, credentials, *, server=False, sequence=0):
        with Path(credentials).open("rb") as stream:
            material = stream.read(25)
        if len(material) != 24:
            raise ValueError("expected 24-byte ephemeral benchmark credentials")
        self.alg_aead = oscore.algorithms["AES-CCM-16-64-128"]
        self.hashfun = oscore.hashfunctions["sha256"]
        self.sender_id, self.recipient_id = (b"\x01", b"") if server else (b"", b"\x01")
        self.id_context = None
        self.sender_sequence_number = sequence
        self.echo_recovery = None
        self.authenticated_claims = ["ephemeral-benchmark"]
        self.recipient_replay_window = oscore.ReplayWindow(REPLAY_WINDOW, lambda: None)
        self.recipient_replay_window.initialize_empty()
        self.derive_keys(material[16:], material[:16])

    def post_seqnoincrease(self):
        pass
