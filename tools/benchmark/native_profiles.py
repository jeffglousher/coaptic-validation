"""Exact native fixture selections; no runtime or measurement policy."""

PROFILE_SIZES = {
    "host-control": (64, 1024, 65536),
    "small-device": (32,),
    "small-blockwise": (64, 1024, 4096),
    "service-fixed": (64, 1024, 16384),
    "service-allocated": (64, 1024, 16384),
}


def validate_profile(profile, kind, size, *, concurrency=1, message_type="con",
                     security=None, admission_diagnostics=False):
    if profile not in PROFILE_SIZES:
        raise ValueError("unknown resource profile")
    if security is not None and security not in ("unprotected", "oscore"):
        raise ValueError("unsupported profile security")
    if profile != "host-control":
        if (kind != "coaptic-mio" or type(concurrency) is not int or concurrency != 1
                or message_type != "con" or admission_diagnostics):
            raise ValueError("representative profiles require same Mio, C1 CON and no admission diagnostics")
    if type(size) is not int or size not in PROFILE_SIZES[profile]:
        raise ValueError("unsupported resource profile representation")


def dimensions(profile, size, rx_bytes=None):
    if profile not in PROFILE_SIZES:
        raise ValueError("unknown resource profile")
    small = profile.startswith("small-")
    service = profile.startswith("service-")
    blockwise = profile != "small-device"
    body_bytes = 4096 if small else 16384 if service else ((size + 1023) // 1024) * 1024
    return dict(resource_profile=profile, storage="fixed" if small or profile == "service-fixed" else "allocated",
                routes=4 if small else 32 if service else 1, populated_routes=1,
                calls=1 if small else 4, deferred=8 if service else 0,
                associations=1, security_requests=4, blockwise=blockwise,
                rx_slots=2 if small else 32 if service else 4,
                tx_slots=2 if small else 32 if service else 4,
                rx_datagram_bytes=1152 if small else rx_bytes or 1472,
                tx_datagram_bytes=1152 if small else 1472,
                dedup=4 if small else 64 if service else 8,
                observe=2 if small else 32 if service else 4,
                rx_body_slots=0 if not blockwise else 1 if small or not service else 4,
                tx_body_slots=0 if not blockwise else 1 if small else 4 if service else 2,
                rx_body_bytes=body_bytes if blockwise else 0,
                tx_body_bytes=body_bytes if blockwise else 0,
                representation_bytes=size,
                representation_heap_bytes=0 if profile == "small-device" else size)
