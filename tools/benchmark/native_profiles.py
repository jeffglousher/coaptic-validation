"""Exact native fixture selections; no runtime or measurement policy."""

PROFILE_SIZES = {
    "host-control": (64, 1024, 65536),
    "small-device": (32,),
    "small-blockwise": (64, 1024, 4096),
    "small-observe": (4096,),
    "device-fixed": (64, 1024, 4096),
    "gateway-fixed": (64, 1024, 8192),
    "service-datagram": (64, 1024),
    "service-fixed": (64, 1024, 16384),
    "service-allocated": (64, 1024, 16384),
}


def validate_concurrency(concurrency, message_type, independent_endpoints=False):
    if (type(concurrency) is not int or not 1 <= concurrency <= 4
            or message_type not in ("con", "non") or type(independent_endpoints) is not bool
            or (independent_endpoints and (concurrency == 1 or message_type != "con"))
            or (concurrency > 1 and message_type == "con" and not independent_endpoints)):
        raise ValueError("concurrency bounds 1..4; per-endpoint NSTART=1; C2..4 CON requires actual independent endpoints")


def validate_profile(profile, kind, size, *, concurrency=1, message_type="con",
                     security=None, admission_diagnostics=False, independent_endpoints=False):
    if profile not in PROFILE_SIZES:
        raise ValueError("unknown resource profile")
    if security is not None and security not in ("unprotected", "oscore"):
        raise ValueError("unsupported profile security")
    validate_concurrency(concurrency, message_type, independent_endpoints)
    if type(size) is not int or size not in PROFILE_SIZES[profile]:
        raise ValueError("unsupported resource profile representation")
    if independent_endpoints:
        if (kind != "coaptic-mio" or admission_diagnostics or profile.startswith("small-")
                or (profile in ("device-fixed", "gateway-fixed") and concurrency > 2)
                or (profile == "host-control" and size > 1024 and concurrency > 2)):
            raise ValueError("independent CON requires Mio and actual server capacity (device2/gateway2/host2/service4)")
    if profile != "host-control":
        if (kind != "coaptic-mio" or (concurrency != 1 and not independent_endpoints)
                or message_type != "con" or admission_diagnostics):
            raise ValueError("representative profiles require same Mio, bounded independent CON and no admission diagnostics")


def dimensions(profile, size, rx_bytes=None):
    if profile not in PROFILE_SIZES:
        raise ValueError("unknown resource profile")
    small = profile.startswith("small-")
    device = profile == "device-fixed"
    gateway = profile == "gateway-fixed"
    service = profile.startswith("service-")
    blockwise = profile not in ("small-device", "service-datagram")
    body_bytes = (4096 if small or device else 8192 if gateway else 16384 if service
                  else ((size + 1023) // 1024) * 1024)
    slots = 2 if small else 8 if gateway else 32 if service else 4
    body_slots = 1 if small else 4 if service else 2
    return dict(resource_profile=profile,
                storage="allocated" if profile in ("host-control", "service-allocated") else "fixed",
                routes=4 if small else 8 if device else 16 if gateway else 32 if service else 1,
                populated_routes=1,
                calls=1 if small else 4, deferred=2 if device else 4 if gateway else 8 if service else 0,
                associations=1, security_requests=4, blockwise=blockwise,
                rx_slots=slots, tx_slots=slots,
                rx_datagram_bytes=1152 if small else (rx_bytes or 1472) if profile == "host-control" else 1472,
                tx_datagram_bytes=1152 if small else 1472,
                dedup=4 if small else 16 if gateway else 64 if service else 8,
                observe=1 if profile == "small-observe" else 2 if small else 8 if gateway else 32 if service else 4,
                rx_body_slots=0 if not blockwise else 1 if profile == "host-control" else body_slots,
                tx_body_slots=body_slots if blockwise else 0,
                rx_body_bytes=body_bytes if blockwise else 0,
                tx_body_bytes=body_bytes if blockwise else 0,
                representation_bytes=size,
                representation_heap_bytes=0 if profile == "small-device" else size)
