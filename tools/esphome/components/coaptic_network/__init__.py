from pathlib import Path
import hashlib
import json
import re
import ipaddress

import esphome.codegen as cg
from esphome.components import esp32
from esphome.components.esp32.const import VARIANT_ESP32C3, VARIANT_ESP32C6, VARIANT_ESP32S3
import esphome.config_validation as cv
import esphome.final_validate as fv
from esphome.const import CONF_ID
from esphome.core import CORE

DEPENDENCIES = ["esp32", "logger", "wifi"]
CONFLICTS_WITH = ["coaptic_probe"]
namespace = cg.esphome_ns.namespace("coaptic_network")
CoapticNetwork = namespace.class_("CoapticNetwork", cg.Component)


def run_id(value):
    value = cv.string(value)
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise cv.Invalid("run_id must be 32 lowercase hexadecimal characters")
    return value


def native_toolchain(config):
    if not CORE.using_toolchain_esp_idf:
        raise cv.Invalid("Coaptic sockets require the native esp-idf toolchain")
    return config


def source_revision(value):
    value = cv.string(value)
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise cv.Invalid("expected source revisions must be full lowercase commit SHAs")
    return value


def fixed_hex(length):
    def validate(value):
        value = cv.string(value)
        if not re.fullmatch(r"[0-9a-f]{%d}" % (length * 2), value):
            raise cv.Invalid("OSCORE values require exact lowercase hexadecimal lengths")
        return value
    return validate


def validate_security(config):
    if sum([bool(config.get("oscore")), config["allow_plaintext"], "pairing" in config]) != 1:
        raise cv.Invalid("select protected oscore, privileged pairing or explicit allow_plaintext; exactly one is required")
    if "oscore" in config and config["oscore"]["sender_id"] == config["oscore"]["recipient_id"]:
        raise cv.Invalid("OSCORE Sender and Recipient IDs must differ")
    if "telemetry" in config:
        if "oscore" not in config or config["oscore"]["provision_only"]:
            raise cv.Invalid("telemetry requires existing protected OSCORE state")
    if "legacy_custody_permit" in config and "pairing" not in config:
        raise cv.Invalid("legacy custody migration requires privileged pairing and reviewed provenance")
    return config


def peer_address(value):
    try:
        address = ipaddress.IPv4Address(cv.string(value))
    except ipaddress.AddressValueError as error:
        raise cv.Invalid("telemetry peer must be an IPv4 address") from error
    if address.is_unspecified or int(address) >> 24 >= 224:
        raise cv.Invalid("telemetry requires one unicast peer")
    return str(address)


def bounded_payload(value):
    value = cv.string(value)
    if len(value) > 2048 or len(value) % 2 or not re.fullmatch(r"[0-9a-f]*", value):
        raise cv.Invalid("telemetry payload must be 0..1024 bytes of lowercase hexadecimal")
    return value


def validate_runtime(config):
    if config["rust_runtime"] == "bundled":
        if esp32.get_esp32_variant() != VARIANT_ESP32S3:
            raise cv.Invalid("bundled Rust is prepared only for ESP32-S3")
        root = Path(__file__).resolve().parent / "lib"
        try:
            report = json.loads((root / "build.json").read_text())
            if any(key not in config for key in ["expected_library_revision", "expected_suite_revision"]):
                raise cv.Invalid("bundled Rust requires both expected source revisions")
            if (report.get("schema") not in {"coaptic-esphome-archive/2", "coaptic-esphome-archive/3"} or
                    report.get("source") != config["expected_library_revision"] or
                    report.get("suite_source") != config["expected_suite_revision"] or
                    report.get("dirty") is not False or report.get("suite_dirty") is not False):
                raise cv.Invalid("Coaptic Rust archive source provenance mismatch")
            locks = report.get("suite_locks")
            expected_locks = {"Cargo.lock", "tools/benchmark/native/Cargo.lock", "tools/security-interop/Cargo.lock",
                              "tools/security-profile/Cargo.lock", "tools/esphome/rust/Cargo.lock",
                              "tools/qualification/esp32/Cargo.lock"}
            if report["schema"] == "coaptic-esphome-archive/3":
                expected_locks.add("tools/durable-host/Cargo.lock")
            if (not isinstance(locks, dict) or set(locks) != expected_locks or
                    any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                        for value in locks.values())):
                raise cv.Invalid("Coaptic Rust archive lockfile provenance mismatch")
            if (report["target"] != "xtensa-esp32s3-none-elf" or
                    report["features"] != ["network", "standalone"] +
                    (["oscore"] if "oscore" in config or "pairing" in config else []) +
                    (["telemetry"] if "telemetry" in config else []) +
                    (["pairing"] if "pairing" in config else []) +
                    (["async-network"] if config["async_network"] else [])):
                raise cv.Invalid("Coaptic Rust archive target or features mismatch")
            if hashlib.sha256((root / "libcoaptic_esphome_probe.a").read_bytes()).hexdigest() != report["archive_sha256"]:
                raise cv.Invalid("Coaptic Rust archive checksum mismatch")
        except (OSError, KeyError, ValueError) as error:
            raise cv.Invalid(f"Coaptic Rust archive is unavailable: {error}") from error
    return config


CONFIG_SCHEMA = cv.All(
    cv.Schema({
        cv.GenerateID(): cv.declare_id(CoapticNetwork),
        cv.Required("run_id"): run_id,
        cv.Required("qualification_only"): cv.All(cv.boolean, cv.one_of(True)),
        cv.Optional("rust_runtime", default="source"): cv.one_of("source", "bundled", "external"),
        cv.Optional("async_network", default=False): cv.boolean,
        cv.Optional("resource_qualification", default=False): cv.boolean,
        cv.Optional("legacy_custody_permit"): fixed_hex(136),
        cv.Optional("expected_library_revision"): source_revision,
        cv.Optional("expected_suite_revision"): source_revision,
        cv.Optional("allow_plaintext", default=False): cv.boolean,
        cv.Optional("pairing"): cv.Schema({
            cv.Required("privileged_usb"): cv.All(cv.boolean, cv.one_of(True)),
        }),
        cv.Optional("oscore"): cv.Schema({
            cv.Required("master_secret"): fixed_hex(32),
            cv.Required("master_salt"): fixed_hex(16),
            cv.Required("context_id"): fixed_hex(16),
            cv.Optional("sender_id", default=1): cv.int_range(min=0, max=255),
            cv.Optional("recipient_id", default=2): cv.int_range(min=0, max=255),
            cv.Optional("provision_only", default=False): cv.boolean,
        }),
        cv.Optional("port", default=5683): cv.int_range(min=1, max=65535),
        cv.Optional("telemetry"): cv.Schema({
            cv.Required("principal_public_key"): fixed_hex(33),
            cv.Required("principal_kid"): cv.int_range(min=0, max=255),
            cv.Required("resource"): fixed_hex(32),
            cv.Required("peer_address"): peer_address,
            cv.Optional("peer_port", default=5683): cv.int_range(min=1, max=65535),
            cv.Optional("timeout_ms", default=30000): cv.int_range(min=1, max=300000),
            # Presence selects offline first provisioning; remove for transmission.
            cv.Optional("provision_pending"): cv.Schema({
                cv.Required("operation_id"): fixed_hex(16),
                cv.Required("payload_hex"): bounded_payload,
                cv.Optional("content_format"): cv.int_range(min=0, max=65535),
            }),
        }),
    }).extend(cv.COMPONENT_SCHEMA),
    cv.only_on_esp32,
    cv.only_with_framework("esp-idf"),
    esp32.only_on_variant(supported=[VARIANT_ESP32C3, VARIANT_ESP32C6, VARIANT_ESP32S3]),
    native_toolchain,
    validate_security,
    validate_runtime,
)


def validate_pairing_console(config):
    if "pairing" in config:
        logger = fv.full_config.get()["logger"]
        if logger.get("hardware_uart") == "USB_SERIAL_JTAG" and logger["baud_rate"] != 0:
            raise cv.Invalid("pairing needs exclusive USB: set logger baud_rate to 0 or use another UART")
    return config


FINAL_VALIDATE_SCHEMA = validate_pairing_console


async def to_code(config):
    component = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(component, config)
    cg.add(component.set_run_id(config["run_id"]))
    cg.add(component.set_port(config["port"]))
    if config["resource_qualification"]:
        esp32.add_idf_sdkconfig_option("CONFIG_FREERTOS_USE_TRACE_FACILITY", True)
        cg.add_define("COAPTIC_RESOURCE_QUALIFICATION")
    if "legacy_custody_permit" in config:
        cg.add_define("COAPTIC_LEGACY_CUSTODY")
        cg.add(component.set_legacy_custody_permit(config["legacy_custody_permit"]))
    if config["async_network"]:
        esp32.add_idf_sdkconfig_option("CONFIG_VFS_SUPPORT_SELECT", True)
        if "pairing" in config:
            esp32.add_idf_sdkconfig_option("CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG", True)
        cg.add_define("COAPTIC_ASYNC_NETWORK")
    if "pairing" in config:
        cg.add(component.set_pairing())
        cg.add_define("COAPTIC_PAIRING")
    if "oscore" in config:
        security = config["oscore"]
        cg.add(component.set_oscore(security["master_secret"], security["master_salt"],
                                    security["context_id"], security["sender_id"],
                                    security["recipient_id"], security["provision_only"]))
    if "telemetry" in config:
        telemetry = config["telemetry"]
        pending = telemetry.get("provision_pending", {})
        cg.add(component.set_telemetry(telemetry["principal_public_key"], telemetry["principal_kid"],
                                      telemetry["resource"], int(ipaddress.IPv4Address(telemetry["peer_address"])),
                                      telemetry["peer_port"], telemetry["timeout_ms"],
                                      pending.get("operation_id", ""), pending.get("content_format", -1),
                                      pending.get("payload_hex", "")))
    if config["rust_runtime"] == "external":
        return
    if config["rust_runtime"] == "bundled":
        root = Path(__file__).resolve().parent
        archive = root / "lib" / "libcoaptic_esphome_probe.a"
        esp32.add_idf_component(name="coaptic_rust_network", path=str(root / "coaptic_rust_network"))
        cg.add_cmake_arg("COAPTIC_RUST_ARCHIVE", archive.as_posix())
        return
    root = Path(__file__).resolve().parents[2]
    rust_component = root / "coaptic_rust_probe"
    esp32.add_idf_component(name="coaptic_rust_probe", path=str(rust_component))
    cg.add_cmake_arg("COAPTIC_RUST_MANIFEST", str(root / "rust" / "Cargo.toml"))
    cg.add_cmake_arg("COAPTIC_NETWORK", "ON")
    cg.add_cmake_arg("COAPTIC_ASYNC_NETWORK", "ON" if config["async_network"] else "OFF")
    cg.add_cmake_arg("COAPTIC_OSCORE", "ON" if "oscore" in config or "pairing" in config else "OFF")
    cg.add_cmake_arg("COAPTIC_PAIRING", "ON" if "pairing" in config else "OFF")
    cg.add_cmake_arg("COAPTIC_TELEMETRY", "ON" if "telemetry" in config else "OFF")
