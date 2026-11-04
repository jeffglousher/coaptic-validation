"""Finite unprotected libcoap client using the existing ESPHome/IDF shell."""
import ipaddress
from pathlib import Path
import re

import esphome.codegen as cg
from esphome.components import esp32
from esphome.components.esp32.const import VARIANT_ESP32S3
import esphome.config_validation as cv
from esphome.const import CONF_ID
from esphome.core import CORE

DEPENDENCIES = ["esp32", "logger", "wifi"]
CONFLICTS_WITH = ["coaptic_probe", "coaptic_network"]
namespace = cg.esphome_ns.namespace("libcoap_benchmark")
LibcoapBenchmark = namespace.class_("LibcoapBenchmark", cg.Component)


def identity(value):
    value = cv.string(value)
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise cv.Invalid("identity must be exactly 32 lowercase hexadecimal characters")
    return value


def private_peer(value):
    try:
        address = ipaddress.IPv4Address(cv.string(value))
    except ipaddress.AddressValueError as error:
        raise cv.Invalid("peer_address must be an IPv4 address") from error
    if not any(address in ipaddress.IPv4Network(network)
               for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
        raise cv.Invalid("peer_address requires an explicit private IPv4 host")
    return str(address)


def native_toolchain(config):
    if not CORE.using_toolchain_esp_idf:
        raise cv.Invalid("libcoap benchmark requires the native esp-idf toolchain")
    if esp32.idf_version() != cv.Version(5, 5, 5):
        raise cv.Invalid("this benchmark fixture is pinned to ESP-IDF 5.5.5")
    return config


CONFIG_SCHEMA = cv.All(
    cv.Schema({
        cv.GenerateID(): cv.declare_id(LibcoapBenchmark),
        cv.Required("qualification_only"): cv.All(cv.boolean, cv.one_of(True)),
        cv.Required("allow_unprotected"): cv.All(cv.boolean, cv.one_of(True)),
        cv.Required("run_id"): identity,
        cv.Required("server_run_id"): identity,
        cv.Required("peer_address"): private_peer,
        cv.Optional("peer_port", default=5683): cv.int_range(min=1, max=65535),
        cv.Optional("start_delay_ms", default=30000): cv.int_range(min=0, max=120000),
    }).extend(cv.COMPONENT_SCHEMA),
    cv.only_on_esp32,
    cv.only_with_framework("esp-idf"),
    esp32.only_on_variant(supported=[VARIANT_ESP32S3]),
    native_toolchain,
)


async def to_code(config):
    component = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(component, config)
    cg.add(component.set_run_id(config["run_id"]))
    cg.add(component.set_server_run_id(config["server_run_id"]))
    cg.add(component.set_peer_address(int(ipaddress.IPv4Address(config["peer_address"]))))
    cg.add(component.set_peer_port(config["peer_port"]))
    cg.add(component.set_start_delay_ms(config["start_delay_ms"]))
    # Public REQUIRES on the local manifest component exposes libcoap's headers
    # to ESPHome's main component without replacing EXTRA_COMPONENT_DIRS.
    esp32.add_idf_component(name="coaptic_libcoap_benchmark",
                            path=str(Path(__file__).resolve().parent / "idf_component"))
    for name, value in {
        "CONFIG_COAP_CLIENT_SUPPORT": True,
        "CONFIG_COAP_SERVER_SUPPORT": False,
        "CONFIG_COAP_MBEDTLS_PSK": False,
        "CONFIG_COAP_MBEDTLS_PKI": False,
        "CONFIG_COAP_OSCORE_SUPPORT": False,
        "CONFIG_COAP_TCP_SUPPORT": False,
        "CONFIG_COAP_WEBSOCKETS": False,
        "CONFIG_COAP_DEBUGGING": False,
    }.items():
        esp32.add_idf_sdkconfig_option(name, value)
