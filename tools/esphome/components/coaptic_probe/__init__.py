from pathlib import Path
import re

import esphome.codegen as cg
from esphome.components import esp32
from esphome.components.esp32.const import VARIANT_ESP32C3, VARIANT_ESP32C6, VARIANT_ESP32S3
import esphome.config_validation as cv
from esphome.const import CONF_ID
from esphome.core import CORE

DEPENDENCIES = ["esp32", "logger"]

namespace = cg.esphome_ns.namespace("coaptic_probe")
CoapticProbe = namespace.class_("CoapticProbe", cg.Component)


def validate_run_id(value):
    value = cv.string(value)
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise cv.Invalid("run_id must be 32 lowercase hexadecimal characters")
    return value


def native_toolchain(config):
    if not CORE.using_toolchain_esp_idf:
        raise cv.Invalid("Coaptic qualification requires the native esp-idf toolchain")
    return config


CONFIG_SCHEMA = cv.All(
    cv.Schema({
        cv.GenerateID(): cv.declare_id(CoapticProbe),
        cv.Required("run_id"): validate_run_id,
        cv.Optional("oscore", default=False): cv.boolean,
    }).extend(cv.COMPONENT_SCHEMA),
    cv.only_on_esp32,
    cv.only_with_framework("esp-idf"),
    esp32.only_on_variant(supported=[VARIANT_ESP32C3, VARIANT_ESP32C6, VARIANT_ESP32S3]),
    native_toolchain,
)


async def to_code(config):
    component = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(component, config)
    cg.add(component.set_run_id(config["run_id"]))
    root = Path(__file__).resolve().parents[2]
    rust_component = root / "coaptic_rust_probe"
    esp32.add_idf_component(name="coaptic_rust_probe", path=str(rust_component))
    cg.add_cmake_arg("COAPTIC_RUST_MANIFEST", str(root / "rust" / "Cargo.toml"))
    cg.add_cmake_arg("COAPTIC_OSCORE", "ON" if config["oscore"] else "OFF")
