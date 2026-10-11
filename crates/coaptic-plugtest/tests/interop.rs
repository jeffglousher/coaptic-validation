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
        reject_incomplete_observe_loop(&result.capture);
    }
}

fn reject_incomplete_observe_loop(capture: &coaptic_plugtest::pcap::Capture) {
    use coaptic::message::{Code, Message, Opt, Type, decode, encode, encode_uint};
    use coaptic_plugtest::pcap::Capture;
    let packets = capture.snapshot();
    let last = packets
        .iter()
        .filter_map(|p| decode(&p.bytes).ok())
        .filter_map(|p| p.observe().and_then(Result::ok))
        .max()
        .unwrap();
    let catalog = Catalog::load().unwrap();
    for fault in ["missing", "token", "sequence", "payload", "format"] {
        let changed = Capture::new();
        for packet in &packets {
            let parsed = decode(&packet.bytes).unwrap();
            let mut bytes = packet.bytes.clone();
            if parsed.code() == Code::CONTENT && parsed.observe() == Some(Ok(last)) {
                match fault {
                    "missing" => continue,
                    "token" => bytes[4] ^= 1,
                    "payload" => *bytes.last_mut().unwrap() ^= 1,
                    "sequence" | "format" => {
                        let sequence = encode_uint(if fault == "sequence" { 0 } else { last });
                        let format = encode_uint(if fault == "format" { 42 } else { 0 });
                        let options = [Opt::observe(&sequence), Opt::content_format(&format)];
                        let message =
                            Message::new(Type::NonConfirmable, Code::CONTENT, parsed.message_id())
                                .with_token(parsed.token())
                                .with_options(&options)
                                .with_payload(parsed.payload());
                        let mut buffer = [0; 128];
                        let length = encode(&message, &mut buffer).unwrap();
                        bytes = buffer[..length].to_vec();
                    }
                    _ => unreachable!(),
                }
            }
            changed.push(packet.src, packet.dst, &bytes, packet.decrypted);
        }
        assert!(
            catalog.grade("TD_COAP_OBS_02", &changed).is_err(),
            "accepted {fault} final notification"
        );
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

#[test]
fn confirmable_observe_notifications_reach_each_client_backend() {
    use coaptic::message::{Code, Message, Opt, Type, decode, encode, encode_uint};
    use coaptic_plugtest::pcap::Capture;
    let catalog = Catalog::load().unwrap();
    for client in ["coaptic", "coap-rs"] {
        let result = runner::run_td(
            "TD_COAP_OBS_01",
            Pair {
                client,
                server: "coaptic",
            },
        );
        assert!(result.error.is_none(), "{client}: {:?}", result.error);
        let packets = result.capture.snapshot();
        let last = packets
            .iter()
            .filter_map(|p| decode(&p.bytes).ok())
            .filter_map(|p| p.observe().and_then(Result::ok))
            .max()
            .unwrap();
        let last_mid = packets
            .iter()
            .find_map(|p| {
                let p = decode(&p.bytes).ok()?;
                (p.ty() == Type::Confirmable
                    && p.code() == Code::CONTENT
                    && p.observe() == Some(Ok(last)))
                .then_some(p.message_id())
            })
            .unwrap();
        for fault in [
            "missing-notification",
            "non-notification",
            "token",
            "sequence",
            "payload",
            "format",
            "missing-ack",
            "ack-mid",
            "ack-endpoint",
            "registration-path",
            "registration-endpoint",
            "initial-body",
        ] {
            let changed = Capture::new();
            for packet in &packets {
                let p = decode(&packet.bytes).unwrap();
                let mut bytes = packet.bytes.clone();
                let mut src = packet.src;
                if p.code() == Code::CONTENT && p.observe() == Some(Ok(last)) {
                    match fault {
                        "missing-notification" => continue,
                        "non-notification" => bytes[0] |= 0x10,
                        "token" => bytes[4] ^= 1,
                        "payload" => *bytes.last_mut().unwrap() ^= 1,
                        "sequence" | "format" => {
                            let seq = encode_uint(if fault == "sequence" { 0 } else { last });
                            let format = encode_uint(if fault == "format" { 42 } else { 0 });
                            let opts = [Opt::observe(&seq), Opt::content_format(&format)];
                            let message =
                                Message::new(Type::Confirmable, Code::CONTENT, p.message_id())
                                    .with_token(p.token())
                                    .with_options(&opts)
                                    .with_payload(p.payload());
                            let mut buf = [0; 128];
                            let n = encode(&message, &mut buf).unwrap();
                            bytes = buf[..n].to_vec();
                        }
                        _ => {}
                    }
                }
                if p.is_empty_ack() && p.message_id() == last_mid {
                    match fault {
                        "missing-ack" => continue,
                        "ack-mid" => bytes[3] ^= 1,
                        "ack-endpoint" => src = packet.dst,
                        _ => {}
                    }
                }
                if p.code() == Code::GET {
                    if fault == "registration-path" {
                        let opts = [Opt::observe_register(), Opt::uri_path("wrong")];
                        let message = Message::new(Type::Confirmable, Code::GET, p.message_id())
                            .with_token(p.token())
                            .with_options(&opts);
                        let mut buf = [0; 128];
                        let n = encode(&message, &mut buf).unwrap();
                        bytes = buf[..n].to_vec();
                    } else if fault == "registration-endpoint" {
                        src = packet.dst;
                    }
                }
                if fault == "initial-body"
                    && p.ty() == Type::Acknowledgement
                    && p.code() == Code::CONTENT
                {
                    *bytes.last_mut().unwrap() ^= 1;
                }
                changed.push(src, packet.dst, &bytes, packet.decrypted);
            }
            assert!(
                catalog.grade("TD_COAP_OBS_01", &changed).is_err(),
                "{client}: accepted {fault}"
            );
        }
        if let Some(directory) = std::env::var_os("COAPTIC_OBSERVE_CAPTURE_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            result
                .capture
                .write_pcap(
                    std::fs::File::create(directory.join(format!("obs-01-{client}.pcap"))).unwrap(),
                )
                .unwrap();
        }
    }
    let reverse = runner::run_td(
        "TD_COAP_OBS_01",
        Pair {
            client: "coaptic",
            server: "coap-rs",
        },
    );
    assert!(reverse.error.as_deref().unwrap().starts_with("SKIP:"));
}

#[test]
fn observe_client_restart_resets_on_same_endpoint_and_recovers() {
    use coaptic::message::{Code, Type, decode};
    use coaptic_plugtest::pcap::Capture;
    let catalog = Catalog::load().unwrap();
    let result = runner::run_td(
        "TD_COAP_OBS_06",
        Pair {
            client: "coaptic",
            server: "coaptic",
        },
    );
    assert!(result.error.is_none(), "{:?}", result.error);
    let packets = result.capture.snapshot();
    let reset_mid = packets
        .iter()
        .find_map(|packet| {
            let p = decode(&packet.bytes).ok()?;
            (p.ty() == Type::Reset).then_some(p.message_id())
        })
        .unwrap();
    for fault in [
        "missing-rst",
        "rst-mid",
        "rst-endpoint",
        "ack-instead-rst",
        "missing-rejected-con",
        "non-instead-con",
        "rejected-body",
        "rejected-token",
        "rejected-endpoint",
        "registration-body",
        "missing-recovery",
        "extra-traffic",
    ] {
        let changed = Capture::new();
        let mut registrations = std::collections::HashSet::new();
        let mut recovery_token = None;
        for packet in &packets {
            let p = decode(&packet.bytes).unwrap();
            if p.code() == Code::GET {
                registrations.insert(p.token());
                if registrations.len() == 2 {
                    recovery_token = Some(p.token());
                }
            }
            let mut bytes = packet.bytes.clone();
            let mut src = packet.src;
            if p.ty() == Type::Reset {
                match fault {
                    "missing-rst" => continue,
                    "rst-mid" => bytes[3] ^= 1,
                    "rst-endpoint" => src = packet.dst,
                    "ack-instead-rst" => bytes[0] = (bytes[0] & !0x30) | 0x20,
                    _ => {}
                }
            }
            if p.ty() == Type::Confirmable
                && p.code() == Code::CONTENT
                && p.message_id() == reset_mid
            {
                match fault {
                    "missing-rejected-con" => continue,
                    "non-instead-con" => bytes[0] |= 0x10,
                    "rejected-body" => *bytes.last_mut().unwrap() ^= 1,
                    "rejected-token" => bytes[4] ^= 1,
                    "rejected-endpoint" => src = packet.dst,
                    _ => {}
                }
            }
            if fault == "registration-body"
                && p.ty() == Type::Acknowledgement
                && p.code() == Code::CONTENT
            {
                *bytes.last_mut().unwrap() ^= 1;
            }
            if fault == "missing-recovery" && recovery_token == Some(p.token()) {
                continue;
            }
            changed.push(src, packet.dst, &bytes, packet.decrypted);
        }
        if fault == "extra-traffic" {
            let packet = &packets[0];
            let mut bytes = packet.bytes.clone();
            bytes[3] ^= 0x80;
            changed.push(packet.src, packet.dst, &bytes, packet.decrypted);
        }
        assert!(
            catalog.grade("TD_COAP_OBS_06", &changed).is_err(),
            "accepted {fault}"
        );
    }
    if let Some(directory) = std::env::var_os("COAPTIC_OBSERVE_CAPTURE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        result
            .capture
            .write_pcap(std::fs::File::create(directory.join("obs-06-coaptic.pcap")).unwrap())
            .unwrap();
    }
    for pair in [
        Pair {
            client: "coap-rs",
            server: "coaptic",
        },
        Pair {
            client: "coaptic",
            server: "coap-rs",
        },
    ] {
        let unsupported = runner::run_td("TD_COAP_OBS_06", pair);
        assert!(unsupported.error.as_deref().unwrap().starts_with("SKIP:"));
    }
}

#[test]
fn same_owner_get_preserves_observation_and_explicit_cancel_stops_it() {
    use coaptic::message::{Code, Message, MessageId, Opt, Type, decode, encode};
    use coaptic_plugtest::pcap::Capture;
    let catalog = Catalog::load().unwrap();
    for id in ["TD_COAP_OBS_10", "TD_COAP_OBS_12"] {
        let result = runner::run_td(
            id,
            Pair {
                client: "coaptic",
                server: "coaptic",
            },
        );
        assert!(result.error.is_none(), "{id}: {:?}", result.error);
        let packets = result.capture.snapshot();
        let mut unique = packets.clone();
        let mut seen = std::collections::HashSet::new();
        unique.sort_by_key(|p| p.t_ns);
        unique.retain(|p| seen.insert((p.src, p.dst, p.bytes.clone())));
        for fault in [
            "request-path",
            "request-endpoint",
            "request-mid",
            "request-token",
            "request-observe",
            "missing-request",
            "reply-mid",
            "reply-token",
            "reply-endpoint",
            "reply-body",
            "reply-observe",
            "missing-continuation",
            "continuation-body",
            "continuation-token",
            "continuation-sequence",
            "extra-traffic",
        ] {
            let changed = Capture::new();
            for packet in &packets {
                let index = unique
                    .iter()
                    .position(|p| {
                        p.src == packet.src && p.dst == packet.dst && p.bytes == packet.bytes
                    })
                    .unwrap();
                let parsed = decode(&packet.bytes).unwrap();
                let mut bytes = packet.bytes.clone();
                let mut src = packet.src;
                if index == 6 {
                    match fault {
                        "missing-request" => continue,
                        "request-endpoint" => src = packet.dst,
                        "request-token" => {
                            let registration = decode(&unique[0].bytes).unwrap();
                            if id == "TD_COAP_OBS_10" {
                                bytes[4..4 + registration.token().len()]
                                    .copy_from_slice(registration.token().as_bytes());
                            } else {
                                bytes[4] ^= 1;
                            }
                        }
                        "request-mid" | "request-path" | "request-observe" => {
                            let mut opts = Vec::new();
                            if fault == "request-observe" {
                                opts.push(Opt::observe_register());
                            } else if id == "TD_COAP_OBS_12" {
                                opts.push(Opt::observe_deregister());
                            }
                            opts.push(Opt::uri_path(if fault == "request-path" {
                                "test"
                            } else {
                                "obs"
                            }));
                            let mid = if fault == "request-mid" {
                                decode(&unique[0].bytes).unwrap().message_id()
                            } else {
                                parsed.message_id()
                            };
                            let message = Message::new(Type::Confirmable, Code::GET, mid)
                                .with_token(parsed.token())
                                .with_options(&opts);
                            let mut buf = [0; 128];
                            let n = encode(&message, &mut buf).unwrap();
                            bytes = buf[..n].to_vec();
                        }
                        _ => {}
                    }
                }
                if index == 7 {
                    match fault {
                        "reply-mid" => bytes[3] ^= 1,
                        "reply-token" => bytes[4] ^= 1,
                        "reply-endpoint" => src = packet.dst,
                        "reply-body" => *bytes.last_mut().unwrap() ^= 1,
                        "reply-observe" => {
                            let format = coaptic::message::encode_uint(0);
                            let opts = [Opt::observe_register(), Opt::content_format(&format)];
                            let msg = Message::new(
                                Type::Acknowledgement,
                                Code::CONTENT,
                                parsed.message_id(),
                            )
                            .with_token(parsed.token())
                            .with_options(&opts)
                            .with_payload(parsed.payload());
                            let mut buf = [0; 128];
                            let n = encode(&msg, &mut buf).unwrap();
                            bytes = buf[..n].to_vec();
                        }
                        _ => {}
                    }
                }
                if index >= 8 && fault == "missing-continuation" {
                    continue;
                }
                if index >= 8 && parsed.code() == Code::CONTENT && fault == "continuation-body" {
                    *bytes.last_mut().unwrap() ^= 1;
                }
                if index >= 8 && parsed.code() == Code::CONTENT {
                    if fault == "continuation-token" {
                        bytes[4] ^= 1;
                    }
                    if fault == "continuation-sequence" {
                        let seq = coaptic::message::encode_uint(1);
                        let format = coaptic::message::encode_uint(0);
                        let opts = [Opt::observe(&seq), Opt::content_format(&format)];
                        let msg = Message::new(parsed.ty(), parsed.code(), parsed.message_id())
                            .with_token(parsed.token())
                            .with_options(&opts)
                            .with_payload(parsed.payload());
                        let mut buf = [0; 128];
                        let n = encode(&msg, &mut buf).unwrap();
                        bytes = buf[..n].to_vec();
                    }
                }
                changed.push(src, packet.dst, &bytes, packet.decrypted);
            }
            if fault == "extra-traffic" {
                let packet = &unique[0];
                let msg = Message::new(Type::Reset, Code::EMPTY, MessageId::new(0x1234));
                let mut buf = [0; 4];
                let n = encode(&msg, &mut buf).unwrap();
                changed.push(packet.src, packet.dst, &buf[..n], false);
            }
            assert!(
                catalog.grade(id, &changed).is_err(),
                "{id}: accepted {fault}"
            );
        }
        if let Some(directory) = std::env::var_os("COAPTIC_OBSERVE_CAPTURE_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            result
                .capture
                .write_pcap(
                    std::fs::File::create(directory.join(format!("{id}-coaptic.pcap"))).unwrap(),
                )
                .unwrap();
        }
        for pair in [
            Pair {
                client: "coap-rs",
                server: "coaptic",
            },
            Pair {
                client: "coaptic",
                server: "coap-rs",
            },
        ] {
            assert!(
                runner::run_td(id, pair)
                    .error
                    .as_deref()
                    .unwrap()
                    .starts_with("SKIP:")
            );
        }
    }
}

#[test]
fn observed_resource_updates_are_delivered_and_read_back() {
    use coaptic::message::{Code, Message, Opt, Type, decode, encode, encode_uint};
    use coaptic_plugtest::pcap::Capture;
    let catalog = Catalog::load().unwrap();
    let result = runner::run_td(
        "TD_COAP_OBS_09",
        Pair {
            client: "coaptic",
            server: "coaptic",
        },
    );
    assert!(result.error.is_none(), "{:?}", result.error);
    let packets = result.capture.snapshot();
    let mut unique = packets.clone();
    let mut seen = std::collections::HashSet::new();
    unique.sort_by_key(|p| p.t_ns);
    unique.retain(|p| seen.insert((p.src, p.dst, p.bytes.clone())));
    for fault in [
        "notification-body",
        "notification-token",
        "notification-format",
        "notification-sequence",
        "non-notification",
        "missing-notification",
        "ack-mid",
        "ack-endpoint",
        "request-path",
        "request-token",
        "request-observe",
        "reply-body",
        "reply-format",
        "reply-token",
        "reply-endpoint",
        "missing-readback",
    ] {
        let changed = Capture::new();
        for packet in &packets {
            let index = unique
                .iter()
                .position(|p| p.src == packet.src && p.dst == packet.dst && p.bytes == packet.bytes)
                .unwrap();
            let p = decode(&packet.bytes).unwrap();
            let mut bytes = packet.bytes.clone();
            let mut src = packet.src;
            if index == 6 {
                match fault {
                    "notification-body" => *bytes.last_mut().unwrap() ^= 1,
                    "notification-token" => bytes[4] ^= 1,
                    "non-notification" => bytes[0] |= 0x10,
                    "missing-notification" => continue,
                    "notification-format" | "notification-sequence" => {
                        let seq = encode_uint(if fault == "notification-sequence" {
                            1
                        } else {
                            p.observe().unwrap().unwrap()
                        });
                        let format = encode_uint(if fault == "notification-format" {
                            42
                        } else {
                            0
                        });
                        let opts = [Opt::observe(&seq), Opt::content_format(&format)];
                        let msg = Message::new(Type::Confirmable, Code::CONTENT, p.message_id())
                            .with_token(p.token())
                            .with_options(&opts)
                            .with_payload(p.payload());
                        let mut buf = [0; 128];
                        let n = encode(&msg, &mut buf).unwrap();
                        bytes = buf[..n].to_vec();
                    }
                    _ => {}
                }
            }
            if index == 7 {
                if fault == "ack-mid" {
                    bytes[3] ^= 1;
                }
                if fault == "ack-endpoint" {
                    src = packet.dst;
                }
            }
            if index == 8 {
                if fault == "request-token" {
                    let token = decode(&unique[0].bytes).unwrap().token();
                    bytes[4..4 + token.len()].copy_from_slice(token.as_bytes());
                }
                if matches!(fault, "request-path" | "request-observe") {
                    let mut opts = Vec::new();
                    if fault == "request-observe" {
                        opts.push(Opt::observe_register());
                    }
                    opts.push(Opt::uri_path(if fault == "request-path" {
                        "test"
                    } else {
                        "obs"
                    }));
                    let msg = Message::new(Type::Confirmable, Code::GET, p.message_id())
                        .with_token(p.token())
                        .with_options(&opts);
                    let mut buf = [0; 128];
                    let n = encode(&msg, &mut buf).unwrap();
                    bytes = buf[..n].to_vec();
                }
            }
            if index == 9 {
                match fault {
                    "reply-body" => *bytes.last_mut().unwrap() ^= 1,
                    "reply-token" => bytes[4] ^= 1,
                    "reply-endpoint" => src = packet.dst,
                    "missing-readback" => continue,
                    "reply-format" => {
                        let format = encode_uint(42);
                        let opts = [Opt::content_format(&format)];
                        let msg =
                            Message::new(Type::Acknowledgement, Code::CONTENT, p.message_id())
                                .with_token(p.token())
                                .with_options(&opts)
                                .with_payload(p.payload());
                        let mut buf = [0; 128];
                        let n = encode(&msg, &mut buf).unwrap();
                        bytes = buf[..n].to_vec();
                    }
                    _ => {}
                }
            }
            changed.push(src, packet.dst, &bytes, packet.decrypted);
        }
        assert!(
            catalog.grade("TD_COAP_OBS_09", &changed).is_err(),
            "accepted {fault}"
        );
    }
    if let Some(directory) = std::env::var_os("COAPTIC_OBSERVE_CAPTURE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        result
            .capture
            .write_pcap(std::fs::File::create(directory.join("obs-09-coaptic.pcap")).unwrap())
            .unwrap();
    }
    for pair in [
        Pair {
            client: "coap-rs",
            server: "coaptic",
        },
        Pair {
            client: "coaptic",
            server: "coap-rs",
        },
    ] {
        assert!(
            runner::run_td("TD_COAP_OBS_09", pair)
                .error
                .as_deref()
                .unwrap()
                .starts_with("SKIP:")
        );
    }
}
