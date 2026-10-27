"""Exact preset ledgers and bounded independent endpoint selection."""
import unittest

from native_profiles import PROFILE_SIZES, dimensions, validate_concurrency, validate_profile


class NativeProfileTests(unittest.TestCase):
    def test_supported_sizes_are_exact(self):
        self.assertEqual(PROFILE_SIZES, {
            "host-control": (64, 1024, 65536),
            "small-device": (32,),
            "small-blockwise": (64, 1024, 4096),
            "small-observe": (4096,),
            "device-fixed": (64, 1024, 4096),
            "gateway-fixed": (64, 1024, 8192),
            "service-datagram": (64, 1024),
            "service-fixed": (64, 1024, 16384),
            "service-allocated": (64, 1024, 16384),
        })
        for profile, sizes in PROFILE_SIZES.items():
            for size in (0, 32, 64, 1024, 4096, 8192, 16384, 65536, True, "64", 64.0):
                with self.subTest(profile=profile, size=size):
                    if type(size) is int and size in sizes:
                        validate_profile(profile, "coaptic-mio", size)
                    else:
                        with self.assertRaises(ValueError):
                            validate_profile(profile, "coaptic-mio", size)

    def test_all_preset_dimensions_match_exact_public_capacities(self):
        # routes, Calls, deferred, datagram slots/bytes, dedup, Observe, body slots/bytes
        presets = {
            "small-device": (4, 1, 0, 2, 1152, 4, 2, 0, 0),
            "small-blockwise": (4, 1, 0, 2, 1152, 4, 2, 1, 4096),
            "small-observe": (4, 1, 0, 2, 1152, 4, 1, 1, 4096),
            "device-fixed": (8, 4, 2, 4, 1472, 8, 4, 2, 4096),
            "gateway-fixed": (16, 4, 4, 8, 1472, 16, 8, 2, 8192),
            "service-datagram": (32, 4, 8, 32, 1472, 64, 32, 0, 0),
            "service-fixed": (32, 4, 8, 32, 1472, 64, 32, 4, 16384),
            "service-allocated": (32, 4, 8, 32, 1472, 64, 32, 4, 16384),
        }
        for profile, (routes, calls, deferred, slots, datagram, dedup, observe, bodies, body_bytes) in presets.items():
            for size in PROFILE_SIZES[profile]:
                expected = dict(resource_profile=profile,
                    storage="allocated" if profile == "service-allocated" else "fixed",
                    routes=routes, populated_routes=1, calls=calls, deferred=deferred,
                    associations=1, security_requests=4, blockwise=bodies != 0,
                    rx_slots=slots, tx_slots=slots, rx_datagram_bytes=datagram,
                    tx_datagram_bytes=datagram, dedup=dedup, observe=observe,
                    rx_body_slots=bodies, tx_body_slots=bodies,
                    rx_body_bytes=body_bytes, tx_body_bytes=body_bytes,
                    representation_bytes=size,
                    representation_heap_bytes=0 if profile == "small-device" else size)
                with self.subTest(profile=profile, size=size):
                    self.assertEqual(dimensions(profile, size), expected)
                    self.assertEqual(dimensions(profile, size, rx_bytes=2048), expected)

    def test_host_ledger_and_size_dependent_overlap_guard_stay_unchanged(self):
        expected = dict(resource_profile="host-control", storage="allocated", routes=1,
            populated_routes=1, calls=4, deferred=0, associations=1, security_requests=4,
            blockwise=True, rx_slots=4, tx_slots=4, rx_datagram_bytes=2048,
            tx_datagram_bytes=1472, dedup=8, observe=4, rx_body_slots=1, tx_body_slots=2,
            rx_body_bytes=65536, tx_body_bytes=65536, representation_bytes=65536,
            representation_heap_bytes=65536)
        self.assertEqual(dimensions("host-control", 65536, rx_bytes=2048), expected)
        self.assertEqual(dimensions("host-control", 1025)["rx_body_bytes"], 2048)
        for size, limit in ((64, 4), (1024, 4), (65536, 2)):
            for concurrency in (2, 3, 4):
                if concurrency <= limit:
                    validate_profile("host-control", "coaptic-mio", size,
                                     concurrency=concurrency, independent_endpoints=True)
                else:
                    with self.assertRaises(ValueError):
                        validate_profile("host-control", "coaptic-mio", size,
                                         concurrency=concurrency, independent_endpoints=True)

    def test_independent_concurrency_is_bounded_by_each_profile(self):
        limits = {"small-device": 1, "small-blockwise": 1, "small-observe": 1,
                  "device-fixed": 2, "gateway-fixed": 2, "service-datagram": 4,
                  "service-fixed": 4, "service-allocated": 4}
        for profile, limit in limits.items():
            for size in PROFILE_SIZES[profile]:
                for security in (None, "unprotected", "oscore"):
                    for concurrency in (1, 2, 3, 4):
                        selected = dict(concurrency=concurrency, security=security,
                                        independent_endpoints=concurrency > 1)
                        with self.subTest(profile=profile, size=size, **selected):
                            if concurrency <= limit:
                                validate_profile(profile, "coaptic-mio", size, **selected)
                            else:
                                with self.assertRaises(ValueError):
                                    validate_profile(profile, "coaptic-mio", size, **selected)

    def test_representative_guards_keep_mio_security_and_endpoint_nstart(self):
        invalid = [dict(kind="coaptic-ready"), dict(kind="coaptic-mio-direct"),
                   dict(security="dtls"), dict(security="unknown"),
                   dict(message_type="non"), dict(admission_diagnostics=True),
                   dict(concurrency=2), dict(concurrency=4),
                   dict(independent_endpoints=True),
                   dict(concurrency=2, independent_endpoints=True, message_type="non")]
        for profile, sizes in PROFILE_SIZES.items():
            if profile == "host-control":
                continue
            for changes in invalid:
                selected = dict(kind="coaptic-mio") | changes
                with self.subTest(profile=profile, changes=changes), self.assertRaises(ValueError):
                    validate_profile(profile, size=sizes[0], **selected)
        for concurrency in (True, 0, 5, 2.0, "2"):
            with self.subTest(concurrency=concurrency), self.assertRaises(ValueError):
                validate_concurrency(concurrency, "con", True)
        for independent in (1, "yes", None):
            with self.subTest(independent=independent), self.assertRaises(ValueError):
                validate_concurrency(2, "con", independent)
        for kind in ("coaptic-ready", "coaptic-mio-direct"):
            with self.assertRaises(ValueError):
                validate_profile("host-control", kind, 64, concurrency=2, independent_endpoints=True)
        for function, args in ((dimensions, ("unknown", 64)),
                               (validate_profile, ("unknown", "coaptic-mio", 64))):
            with self.assertRaises(ValueError):
                function(*args)


if __name__ == "__main__":
    unittest.main()
