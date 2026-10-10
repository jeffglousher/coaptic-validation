from pathlib import Path
import hashlib
import json
import re

import esphome.codegen as cg
from esphome.components import esp32
from esphome.components.esp32.const import VARIANT_ESP32C3, VARIANT_ESP32C6, VARIANT_ESP32S3
import esphome.config_validation as cv
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
    if bool(config.get("oscore")) == config["allow_plaintext"]:
        raise cv.Invalid("select protected oscore or explicit allow_plaintext, never both")
    if "oscore" in config and config["oscore"]["sender_id"] == config["oscore"]["recipient_id"]:
        raise cv.Invalid("OSCORE Sender and Recipient IDs must differ")
    return config


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
                    report["features"] != ["network", "standalone"] + (["oscore"] if "oscore" in config else [])):
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
        cv.Optional("expected_library_revision"): source_revision,
        cv.Optional("expected_suite_revision"): source_revision,
        cv.Optional("allow_plaintext", default=False): cv.boolean,
        cv.Optional("oscore"): cv.Schema({
            cv.Required("master_secret"): fixed_hex(32),
            cv.Required("master_salt"): fixed_hex(16),
            cv.Required("context_id"): fixed_hex(16),
            cv.Optional("sender_id", default=1): cv.int_range(min=0, max=255),
            cv.Optional("recipient_id", default=2): cv.int_range(min=0, max=255),
            cv.Optional("provision_only", default=False): cv.boolean,
        }),
        cv.Optional("port", default=5683): cv.int_range(min=1, max=65535),
    }).extend(cv.COMPONENT_SCHEMA),
    cv.only_on_esp32,
    cv.only_with_framework("esp-idf"),
    esp32.only_on_variant(supported=[VARIANT_ESP32C3, VARIANT_ESP32C6, VARIANT_ESP32S3]),
    native_toolchain,
    validate_security,
    validate_runtime,
)


async def to_code(config):
    component = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(component, config)
    cg.add(component.set_run_id(config["run_id"]))
    cg.add(component.set_port(config["port"]))
    if "oscore" in config:
        security = config["oscore"]
        cg.add(component.set_oscore(security["master_secret"], security["master_salt"],
                                    security["context_id"], security["sender_id"],
                                    security["recipient_id"], security["provision_only"]))
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
    cg.add_cmake_arg("COAPTIC_OSCORE", "ON" if "oscore" in config else "OFF")
