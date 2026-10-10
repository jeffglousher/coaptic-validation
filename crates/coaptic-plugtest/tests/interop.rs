//! Multi-impl plugtest + pcap grade (`cargo test -p coaptic-plugtest`).

use coaptic_plugtest::catalog;
use coaptic_plugtest::grade::Catalog;
use coaptic_plugtest::runner::{self, Pair};

#[test]
fn catalog_matches_vendored_yaml() {
    catalog::assert_ids_match_yaml();
}

#[test]
fn golden_catalog_parses_and_covers_tds() {
    let cat = Catalog::load().expect("expectations/catalog.json");
    for id in catalog::CORE
        .iter()
        .chain(catalog::BLOCK)
        .chain(catalog::OBS)
        .chain(catalog::LINK)
        .chain(catalog::DTLS)
    {
        assert!(cat.tds.contains_key(*id), "golden file missing {id}");
    }
}

#[test]
fn core_goldens_do_not_blanket_allow_extra() {
    let cat = Catalog::load().expect("expectations/catalog.json");
    for id in catalog::CORE {
        let td = cat.tds.get(*id).expect(id);
        assert!(
            !td.allow_extra,
            "{id}: CORE must not set allow_extra without a per-TD reason"
        );
    }
}

#[test]
fn out_of_scope_6lowpan_scenarios_are_explicitly_skipped() {
    for id in catalog::lowpan_ids() {
        let reason = catalog::skip_reason(id).expect("6LoWPAN must skip");
        assert!(reason.contains("6LoWPAN"), "{id}: {reason}");
        assert!(
            reason.contains("outside the accepted 0.0.10"),
            "{id}: {reason}"
        );
    }
}

#[test]
fn unqualified_scenarios_cannot_report_pass() {
    for id in catalog::CORE
        .iter()
        .chain(catalog::BLOCK)
        .chain(catalog::OBS)
        .chain(catalog::LINK)
        .chain(catalog::DTLS)
    {
        if let Some(reason) = catalog::skip_reason(id) {
            for result in runner::run_suite(&[*id], &runner::default_pairs()) {
                assert_eq!(
                    result.error.as_deref(),
                    Some(format!("SKIP: {reason}").as_str()),
                    "{id}"
                );
                assert!(result.capture.snapshot().is_empty());
            }
        }
    }
    assert_eq!(
        catalog::skip_reason("TD_COAP_DTLS_01").is_none(),
        cfg!(feature = "dtls")
    );
    assert!(catalog::skip_reason("TD_COAP_DTLS_04").is_some());
}

fn assert_suite(name: &str, ids: &[&str], pairs: &[Pair]) {
    let results = runner::run_suite(ids, pairs);
    let mut failed = Vec::new();
    for r in &results {
        match &r.error {
            Some(e) if e.starts_with("SKIP:") => {
                eprintln!("SKIP  {name} {} {}  ({e})", r.id, r.pair.label());
            }
            Some(e) => {
                eprintln!("FAIL  {name} {} {}  {e}", r.id, r.pair.label());
                failed.push(format!("{} {}: {e}", r.id, r.pair.label()));
            }
            None => {
                eprintln!("PASS  {name} {} {}", r.id, r.pair.label());
            }
        }
    }
    assert!(failed.is_empty(), "{name} failures:\n{}", failed.join("\n"));
}

/// Base GETs must grade green on mixed + same-impl coaptic (success criterion 1).
#[test]
fn td_core_01_pcap_green() {
    assert_suite("CORE_01", &["TD_COAP_CORE_01"], &runner::default_pairs());
}

#[test]
fn td_coap_core() {
    assert_suite("CORE", catalog::CORE, &runner::default_pairs());
}

#[test]
fn td_coap_block() {
    assert_suite("BLOCK", catalog::BLOCK, &runner::default_pairs());
}

#[test]
fn td_coap_link() {
    assert_suite("LINK", catalog::LINK, &runner::default_pairs());
}

#[test]
fn td_coap_obs() {
    assert_suite("OBS", catalog::OBS, &runner::default_pairs());
}

#[test]
fn non_observe_notifications_reach_each_client_backend() {
    for client in ["coaptic", "coap-rs"] {
        let result = runner::run_td(
            "TD_COAP_OBS_02",
            runner::Pair {
                client,
                server: "coaptic",
            },
        );
        if let Some(directory) = std::env::var_os("COAPTIC_OBSERVE_CAPTURE_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            result
                .capture
                .write_pcap(
                    std::fs::File::create(directory.join(format!("obs-02-{client}.pcap"))).unwrap(),
                )
                .unwrap();
        }
        assert!(result.error.is_none(), "{client}: {:?}", result.error);
        assert!(!result.capture.snapshot().is_empty());
    }
}

#[test]
#[cfg(feature = "dtls")]
fn td_coap_dtls() {
    assert_suite("DTLS", catalog::DTLS, &runner::default_pairs());
}

#[test]
fn inventory() {
    catalog::assert_ids_match_yaml();
    let mut ran = 0usize;
    let mut skipped = 0usize;
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
                    eprintln!("SKIP  {suite} {id}  ({reason})");
                }
                None => {
                    ran += 1;
                    eprintln!("RUN   {suite} {id}");
                }
            }
        }
    }
    let lowpan = catalog::lowpan_ids();
    skipped += lowpan.len();
    eprintln!(
        "SKIP  6LOWPAN {} TDs (future/backlog: 6LoWPAN (contributor opportunity))",
        lowpan.len()
    );
    eprintln!("interop inventory: {ran} run, {skipped} skip");
    assert_eq!(
        ran + skipped,
        88,
        "every vendored scenario is accounted for"
    );
    assert!(
        ran >= 19,
        "qualified basic CORE scenarios must remain runnable"
    );
}
