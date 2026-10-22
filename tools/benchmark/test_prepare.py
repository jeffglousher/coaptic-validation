import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare import add_dtls_peers, validate_coaptic_receive_capacity


class DtlsPreparationTests(unittest.TestCase):
    def test_bare_udp_refuses_oversized_receive_capacity_before_build(self):
        with self.assertRaisesRegex(ValueError, "coaptic-reusable"):
            validate_coaptic_receive_capacity(["coaptic", "coaptic-reusable"], 2048)
        validate_coaptic_receive_capacity(["coaptic"], 1472)
        validate_coaptic_receive_capacity(["coaptic-reusable"], 2048)

    def peer(self, name, capabilities=None):
        return {"id": name, "protocol": "coap", "security": "unprotected",
                "server": [name, "{host}", "{port}", "{bytes}"], "driver": ["udp-driver"],
                "identity": {"security_capabilities": capabilities or {"oscore": False, "dtls": False},
                             "coaptic_capacities": {"rx_datagram_bytes": 1472} if name.startswith("coaptic") else None}}

    def test_native_endpoints_and_adapters_remain_explicit_separate_stratum(self):
        peers = [self.peer(name, {"oscore": True, "dtls": True})
                 for name in ("coaptic", "coaptic-reusable", "coap-rs", "go-coap", "libcoap", "coap-lite-codec", "aiocoap")]
        unsupported = []
        add_dtls_peers(peers, unsupported, Path("rust"), Path("go"), ["independent-dtls-driver"])
        protected = [p for p in peers if p["security"].startswith("DTLS")]
        self.assertEqual({p["id"] for p in protected}, {"coaptic-dtls", "coap-rs-dtls", "go-coap-dtls", "libcoap-dtls"})
        self.assertEqual({p["peer"] for p in unsupported}, {"coap-lite-codec", "aiocoap"})
        self.assertTrue(all(p["driver"] == ["independent-dtls-driver"] for p in protected))
        self.assertIn("test-only", next(p for p in protected if p["id"] == "coaptic-dtls")["identity"]["security_integration"])
        self.assertEqual(next(p for p in protected if p["id"] == "libcoap-dtls")["server"][-2:], ["dtls", "{credentials}"])

    def test_no_crypto_build_does_not_become_a_protected_result(self):
        peers = [self.peer("libcoap"), self.peer("coaptic-reusable")]
        unsupported = []
        add_dtls_peers(peers, unsupported, Path("rust"), Path("go"), ["dtls-driver"])
        self.assertEqual([p["id"] for p in peers if p["security"].startswith("DTLS")], ["coaptic-dtls"])
        self.assertEqual([p["peer"] for p in unsupported], ["libcoap"])

    def test_dtls_reports_its_fixed_receive_capacity(self):
        peer = self.peer("coaptic")
        peer["identity"]["coaptic_capacities"] = {"rx_datagram_bytes": 2048}
        peers = [peer]
        add_dtls_peers(peers, [], Path("rust"), Path("go"), ["dtls-driver"])
        dtls = next(p for p in peers if p["id"] == "coaptic-dtls")
        self.assertEqual(dtls["identity"]["coaptic_capacities"]["rx_datagram_bytes"], 1472)
        self.assertEqual(dtls["identity"]["coaptic_transport"]["reusable_scratch_bytes"], 1473)
        self.assertEqual(peer["identity"]["coaptic_capacities"]["rx_datagram_bytes"], 2048)


if __name__ == "__main__":
    unittest.main()
