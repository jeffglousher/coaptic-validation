//! In-scope ETSI CoAP#4 plugtest harness (in-memory Engine pair).
//!
//! Two [`coaptic::storage::Engine`]s exchange datagram bytes (no sockets, no
//! DTLS). This is **not** an App SUT: App proof is `crates/coaptic-plugtest`
//! (`cargo test -p coaptic-plugtest`, plus `--features dtls`).
//! TD identifiers come from `tests/plugtest/td-coap4/*.yml` — this file
//! does not invent ids. In-memory `dtls` is skipped (no sockets; see
//! `crates/coaptic-plugtest --features dtls`). The future/backlog
//! `6lowpan` suite is skipped with a reason. Observe Max-Age / client-OFF TDs run on the colocated
//! `ObserveInterest` lifetime (no seventh area).
//!
//! ```text
//! cargo test --test plugtest
//! cargo test --test plugtest catalog
//! cargo test --test plugtest td_coap_core
//! cargo test --test plugtest td_coap_block
//! cargo test --test plugtest td_coap_obs
//! cargo test --test plugtest td_coap_link
//! cargo test --test plugtest inventory -- --nocapture
//! ```
//!
//! Tracking: <https://github.com/jeffglousher/coaptic/issues/49>,
//! <https://github.com/jeffglousher/coaptic/issues/56>.

#![allow(clippy::too_many_lines)]

#[path = "plugtest/catalog.rs"]
mod catalog;
mod harness;

#[path = "plugtest/block.rs"]
mod block;
#[path = "plugtest/core.rs"]
mod core;
#[path = "plugtest/link.rs"]
mod link;
#[path = "plugtest/obs.rs"]
mod obs;

/// Vendored YAML keys match the hand-maintained lists (no invented TDs).
#[test]
fn catalog_matches_vendored_yaml() {
    catalog::assert_ids_match_yaml();
}

#[test]
fn td_coap_core_all() {
    for id in catalog::CORE {
        match catalog::skip_reason(id) {
            Some(reason) => panic!("{id} is CORE and must run (skip={reason})"),
            None => core::run(id),
        }
    }
}

#[test]
fn td_coap_block_all() {
    for id in catalog::BLOCK {
        match catalog::skip_reason(id) {
            Some(reason) => panic!("{id} is BLOCK and must run (skip={reason})"),
            None => block::run(id),
        }
    }
}

#[test]
fn td_coap_obs_all() {
    for id in catalog::OBS {
        match catalog::skip_reason(id) {
            Some(reason) => eprintln!("skip {id}: {reason}"),
            None => obs::run(id),
        }
    }
}

#[test]
fn td_coap_link_all() {
    for id in catalog::LINK {
        match catalog::skip_reason(id) {
            Some(reason) => panic!("{id} is LINK and must run (skip={reason})"),
            None => link::run(id),
        }
    }
}

#[test]
fn deferred_dtls_skipped() {
    for id in catalog::DTLS {
        let reason = catalog::skip_reason(id).expect("DTLS must skip");
        assert!(reason.contains("DTLS"), "{id}: {reason}");
    }
}

#[test]
fn backlog_6lowpan_skipped() {
    let yaml = include_str!("plugtest/td-coap4/6lowpan.yml");
    for id in catalog::extract_td_ids(yaml) {
        let reason = catalog::skip_reason(id).unwrap_or_else(|| panic!("{id} must skip"));
        assert!(reason.contains("6LoWPAN"), "{id}: {reason}");
        assert!(
            reason.contains("future/backlog"),
            "{id}: skip reason must say future/backlog ({reason})"
        );
    }
}

/// Inventory printed for humans (`cargo test --test plugtest inventory -- --nocapture`).
#[test]
fn inventory() {
    catalog::assert_ids_match_yaml();
    let mut ran = 0usize;
    let mut skipped = 0usize;
    let mut lines = Vec::new();
    for (suite, ids) in [
        ("CORE", catalog::CORE),
        ("BLOCK", catalog::BLOCK),
        ("OBS", catalog::OBS),
        ("LINK", catalog::LINK),
        ("DTLS", catalog::DTLS),
    ] {
        for id in ids {
            match catalog::skip_reason(id) {
                Some(reason) => {
                    skipped += 1;
                    lines.push(format!("SKIP  {suite} {id}  ({reason})"));
                }
                None => {
                    ran += 1;
                    lines.push(format!("RUN   {suite} {id}"));
                }
            }
        }
    }
    let lowpan = catalog::extract_td_ids(include_str!("plugtest/td-coap4/6lowpan.yml"));
    skipped += lowpan.len();
    lines.push(format!(
        "SKIP  6LOWPAN {} TDs (future/backlog: 6LoWPAN (contributor opportunity))",
        lowpan.len()
    ));
    eprintln!(
        "plugtest inventory: {ran} run, {skipped} skip\n{}",
        lines.join("\n")
    );
    assert!(ran >= 24 + 6 + 13 + 9, "CORE+BLOCK+OBS+LINK must all run");
}
