//! TD identifiers from vendored CoAP#4 YAML (same files as `tests/plugtest`).
//!
//! Do not invent TD identifiers. Extraction is a line scan for `TD_…:` keys.

/// In-scope CORE TDs from `base.yml`.
pub const CORE: &[&str] = &[
    "TD_COAP_CORE_01",
    "TD_COAP_CORE_02",
    "TD_COAP_CORE_03",
    "TD_COAP_CORE_04",
    "TD_COAP_CORE_05",
    "TD_COAP_CORE_06",
    "TD_COAP_CORE_07",
    "TD_COAP_CORE_08",
    "TD_COAP_CORE_09",
    "TD_COAP_CORE_10",
    "TD_COAP_CORE_11",
    "TD_COAP_CORE_12",
    "TD_COAP_CORE_13",
    "TD_COAP_CORE_14",
    "TD_COAP_CORE_15",
    "TD_COAP_CORE_16",
    "TD_COAP_CORE_17",
    "TD_COAP_CORE_18",
    "TD_COAP_CORE_19",
    "TD_COAP_CORE_20",
    "TD_COAP_CORE_21",
    "TD_COAP_CORE_22",
    "TD_COAP_CORE_23",
    "TD_COAP_CORE_31",
];

/// In-scope Block TDs from `block.yml`.
pub const BLOCK: &[&str] = &[
    "TD_COAP_BLOCK_01",
    "TD_COAP_BLOCK_02",
    "TD_COAP_BLOCK_03",
    "TD_COAP_BLOCK_04",
    "TD_COAP_BLOCK_05",
    "TD_COAP_BLOCK_06",
];

/// In-scope Observe TDs from `block.yml`. There is no `TD_COAP_OBS_03`.
pub const OBS: &[&str] = &[
    "TD_COAP_OBS_01",
    "TD_COAP_OBS_02",
    "TD_COAP_OBS_04",
    "TD_COAP_OBS_05",
    "TD_COAP_OBS_06",
    "TD_COAP_OBS_07",
    "TD_COAP_OBS_08",
    "TD_COAP_OBS_09",
    "TD_COAP_OBS_10",
    "TD_COAP_OBS_11",
    "TD_COAP_OBS_12",
    "TD_COAP_OBS_13",
    "TD_COAP_OBS_14",
];

/// In-scope Link TDs from `link.yml`.
pub const LINK: &[&str] = &[
    "TD_COAP_LINK_01",
    "TD_COAP_LINK_02",
    "TD_COAP_LINK_03",
    "TD_COAP_LINK_04",
    "TD_COAP_LINK_05",
    "TD_COAP_LINK_06",
    "TD_COAP_LINK_07",
    "TD_COAP_LINK_08",
    "TD_COAP_LINK_09",
];

/// DTLS TDs from `dtls.yml`. Run in this harness (`dtls` feature).
pub const DTLS: &[&str] = &[
    "TD_COAP_DTLS_01",
    "TD_COAP_DTLS_02",
    "TD_COAP_DTLS_03",
    "TD_COAP_DTLS_04",
    "TD_COAP_DTLS_05",
    "TD_COAP_DTLS_06",
    "TD_COAP_DTLS_07",
];

const BASE_YML: &str = include_str!("../../../tests/plugtest/td-coap4/base.yml");
const BLOCK_YML: &str = include_str!("../../../tests/plugtest/td-coap4/block.yml");
const LINK_YML: &str = include_str!("../../../tests/plugtest/td-coap4/link.yml");
const DTLS_YML: &str = include_str!("../../../tests/plugtest/td-coap4/dtls.yml");
const LOWPAN_YML: &str = include_str!("../../../tests/plugtest/td-coap4/6lowpan.yml");

/// Keys that look like `TD_…:` at the start of a YAML line.
#[must_use]
pub fn extract_td_ids(yaml: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    for line in yaml.lines() {
        let line = line.trim();
        if let Some(id) = line.strip_prefix("TD_") {
            if let Some(name) = id.strip_suffix(':') {
                ids.push(line.strip_suffix(':').unwrap_or(name));
            }
        }
    }
    ids
}

fn assert_list(name: &str, yaml: &str, listed: &[&str]) {
    let found = extract_td_ids(yaml);
    assert_eq!(
        found, listed,
        "{name}: hand-maintained TD list must match vendored YAML keys (do not invent ids)"
    );
}

/// Fail if a hand-maintained list drifts from the vendored YAML.
pub fn assert_ids_match_yaml() {
    assert_list("base.yml CORE", BASE_YML, CORE);
    let block_yml_ids = extract_td_ids(BLOCK_YML);
    let mut expected = Vec::from(BLOCK);
    expected.extend_from_slice(OBS);
    assert_eq!(
        block_yml_ids, expected,
        "block.yml: BLOCK then OBS keys, no invented TD_COAP_OBS_03"
    );
    assert_list("link.yml", LINK_YML, LINK);
    assert_list("dtls.yml", DTLS_YML, DTLS);
    let lowpan = extract_td_ids(LOWPAN_YML);
    assert!(
        lowpan.iter().all(|id| id.starts_with("TD_6LoWPAN_")),
        "6lowpan.yml keys must stay TD_6LoWPAN_* (found {lowpan:?})"
    );
    assert!(!lowpan.is_empty(), "6lowpan.yml must contain TD keys");
}

/// Skip reason. `None` means this harness implements the TD.
///
/// The App harness reports unimplemented scenario steps explicitly (#199).
/// Engine tests and process smoke tests have separate coverage contracts.
#[must_use]
pub fn skip_reason(id: &str) -> Option<&'static str> {
    if id.starts_with("TD_6LoWPAN_") {
        return Some("future/backlog: 6LoWPAN (contributor opportunity)");
    }
    if id.starts_with("TD_COAP_DTLS_") && !cfg!(feature = "dtls") {
        return Some("enable crate feature dtls (harness webrtc-dtls adapter)");
    }
    match id {
        "TD_COAP_OBS_01" => Some(
            "coverage gap #199: server notifications stay NON until the 24-hour confirm point; this TD requires CON notifications",
        ),
        "TD_COAP_DTLS_02" => Some(
            "coverage gap #199: prescribed decrypt_error alert is not visible as a plaintext fatal alert",
        ),
        "TD_COAP_DTLS_03" => {
            Some("coverage gap #199: dtls handshake loss of each flight packet is not implemented")
        }
        "TD_COAP_DTLS_04" | "TD_COAP_DTLS_05" | "TD_COAP_DTLS_06" | "TD_COAP_DTLS_07" => Some(
            "coverage gap #199: DTLS backend has no RFC 7250 raw public key; an X.509 run is a different test",
        ),
        _ if OBS.contains(&id) && id != "TD_COAP_OBS_02" => Some(
            "coverage gap #199: Observe cancel, Max-Age, re-registration, restart, loss, or large notifications are not qualified; coap-rs does not collect notifications",
        ),
        _ => None,
    }
}

/// Vendored `TD_6LoWPAN_*` keys.
#[must_use]
pub fn lowpan_ids() -> Vec<&'static str> {
    extract_td_ids(LOWPAN_YML)
}
