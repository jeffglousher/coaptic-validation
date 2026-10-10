//! Run one TD against a client/server peer pair and grade the pcap.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use coaptic::message::{Code, Type};

use crate::catalog;
use crate::grade::Catalog;
use crate::pcap::Capture;
use crate::peer::{ClientRequest, Peer, PeerError};
use crate::site;

/// Which implementations sit on each side.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pair {
    /// Client backend name (`coaptic`, `coap-rs`).
    pub client: &'static str,
    /// Server backend name.
    pub server: &'static str,
}

impl Pair {
    /// Label for logs (`coaptic→coap-rs`).
    #[must_use]
    pub fn label(self) -> String {
        format!("{}→{}", self.client, self.server)
    }
}

/// Useful role matrix: mixed interop plus same-impl coaptic.
#[must_use]
pub fn default_pairs() -> Vec<Pair> {
    vec![
        Pair {
            client: "coap-rs",
            server: "coaptic",
        },
        Pair {
            client: "coaptic",
            server: "coap-rs",
        },
        Pair {
            client: "coaptic",
            server: "coaptic",
        },
    ]
}

/// Construct a named peer.
pub fn peer_by_name(name: &str) -> Result<Box<dyn Peer>, PeerError> {
    match name {
        "coaptic" => Ok(Box::new(crate::coaptic::CoapticPeer::new())),
        "coap-rs" => Ok(Box::new(crate::coap_rs::CoapRsPeer::new())),
        other => Err(PeerError(format!(
            "unknown peer {other:?} (extension point: implement crate::peer::Peer)"
        ))),
    }
}

/// Outcome of one TD × pair.
#[derive(Debug)]
pub struct TdResult {
    /// TD identifier.
    pub id: String,
    /// Role pair.
    pub pair: Pair,
    /// `None` if the run and grade succeeded.
    pub error: Option<String>,
    /// Merged capture (for debugging / PCAP dump).
    pub capture: Capture,
}

/// One TD at a time: plugtest site state is process-global, and parallel
/// `cargo test` workers would otherwise interleave `site::reset`.
pub(crate) fn harness_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Run `id` on `pair` and grade against the golden catalog.
pub fn run_td(id: &str, pair: Pair) -> TdResult {
    let _guard = harness_lock();
    if let Some(reason) = catalog::skip_reason(id) {
        return TdResult {
            id: id.to_owned(),
            pair,
            error: Some(format!("SKIP: {reason}")),
            capture: Capture::new(),
        };
    }
    let mut server = match peer_by_name(pair.server) {
        Ok(p) => p,
        Err(e) => {
            return TdResult {
                id: id.to_owned(),
                pair,
                error: Some(e.0),
                capture: Capture::new(),
            };
        }
    };
    let mut client = match peer_by_name(pair.client) {
        Ok(p) => p,
        Err(e) => {
            return TdResult {
                id: id.to_owned(),
                pair,
                error: Some(e.0),
                capture: Capture::new(),
            };
        }
    };
    let addr = match server.start_server() {
        Ok(a) => a,
        Err(e) => {
            return TdResult {
                id: id.to_owned(),
                pair,
                error: Some(format!("start_server: {e}")),
                capture: Capture::new(),
            };
        }
    };
    let run = drive_td(id, addr, client.as_mut(), server.as_mut());
    // coap-rs ACKs a separate CON before `send` returns, on its own socket.
    // The coaptic server records that ACK on a later poll. Wait until the
    // empty ACK is in the server log so the snapshot is the whole exchange.
    if matches!(
        id,
        "TD_COAP_CORE_09" | "TD_COAP_CORE_11" | "TD_COAP_CORE_16"
    ) {
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            if exchange_has_response_ack(&client.take_capture(), &server.take_capture()) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    let capture = Capture::new();
    capture.extend_from(&client.take_capture());
    capture.extend_from(&server.take_capture());
    server.stop_server();
    let error = match run {
        Ok(()) => match Catalog::load().and_then(|c| c.grade(id, &capture)) {
            Ok(()) => None,
            Err(e) => Some(format!("grade: {e}")),
        },
        Err(e) => Some(e.0),
    };
    TdResult {
        id: id.to_owned(),
        pair,
        error,
        capture,
    }
}

/// True when some datagram is an empty ACK of a CON 2.05.
fn exchange_has_response_ack(client: &Capture, server: &Capture) -> bool {
    let mut packets = client.snapshot();
    packets.extend(server.snapshot());
    let response_mid = packets.iter().find_map(|packet| {
        let bytes = packet.bytes.as_slice();
        (bytes.len() >= 4 && (bytes[0] >> 4) == 0x04 && bytes[1] == 0x45)
            .then_some(u16::from_be_bytes([bytes[2], bytes[3]]))
    });
    let Some(mid) = response_mid else {
        return false;
    };
    packets.iter().any(|packet| {
        let bytes = packet.bytes.as_slice();
        bytes.len() == 4
            && bytes[0] == 0x60
            && bytes[1] == 0
            && u16::from_be_bytes([bytes[2], bytes[3]]) == mid
    })
}

fn drive_td(
    id: &str,
    dest: SocketAddr,
    client: &mut dyn Peer,
    server: &mut dyn Peer,
) -> Result<(), PeerError> {
    match id {
        "TD_COAP_CORE_01" => basic(client, dest, ClientRequest::get(&["test"]), Code::CONTENT),
        "TD_COAP_CORE_02" => basic(
            client,
            dest,
            ClientRequest::request(Code::DELETE, &["test"]),
            Code::DELETED,
        ),
        "TD_COAP_CORE_03" => {
            let mut r = ClientRequest::request(Code::PUT, &["test"]);
            r.payload = site::TEST_BODY.to_vec();
            r.content_format = Some(0);
            basic(client, dest, r, Code::CHANGED)
        }
        "TD_COAP_CORE_04" | "TD_COAP_CORE_18" | "TD_COAP_CORE_19" => {
            let mut r = ClientRequest::request(Code::POST, &["test"]);
            r.payload = site::TEST_BODY.to_vec();
            r.content_format = Some(0);
            let got = client.send_request(dest, &r)?;
            expect_codes(id, got.code, &[Code::CREATED, Code::CHANGED])?;
            Ok(())
        }
        "TD_COAP_CORE_05" => {
            let mut r = ClientRequest::get(&["test"]);
            r.ty = Type::NonConfirmable;
            basic(client, dest, r, Code::CONTENT)
        }
        "TD_COAP_CORE_06" => {
            let mut r = ClientRequest::request(Code::DELETE, &["test"]);
            r.ty = Type::NonConfirmable;
            basic(client, dest, r, Code::DELETED)
        }
        "TD_COAP_CORE_07" => {
            let mut r = ClientRequest::request(Code::PUT, &["test"]);
            r.ty = Type::NonConfirmable;
            r.payload = site::TEST_BODY.to_vec();
            r.content_format = Some(0);
            basic(client, dest, r, Code::CHANGED)
        }
        "TD_COAP_CORE_08" => {
            let mut r = ClientRequest::request(Code::POST, &["test"]);
            r.ty = Type::NonConfirmable;
            r.payload = site::TEST_BODY.to_vec();
            r.content_format = Some(0);
            let got = client.send_request(dest, &r)?;
            expect_codes(id, got.code, &[Code::CREATED, Code::CHANGED])
        }
        "TD_COAP_CORE_09" | "TD_COAP_CORE_11" | "TD_COAP_CORE_17" => {
            separate_get(client, dest, id, Duration::from_secs(3))
        }
        "TD_COAP_CORE_10" => {
            let mut r = ClientRequest::get(&["test"]);
            r.token_len = Some(4);
            basic(client, dest, r, Code::CONTENT)
        }
        "TD_COAP_CORE_12" => {
            let mut r = ClientRequest::get(&["test"]);
            r.token_len = Some(0);
            basic(client, dest, r, Code::CONTENT)
        }
        "TD_COAP_CORE_13" => basic(
            client,
            dest,
            ClientRequest::get(&["seg1", "seg2", "seg3"]),
            Code::CONTENT,
        ),
        "TD_COAP_CORE_14" => {
            let mut r = ClientRequest::get(&["query"]);
            r.query = vec!["first=1".into(), "second=2".into(), "third=3".into()];
            basic(client, dest, r, Code::CONTENT)
        }
        "TD_COAP_CORE_15" => {
            let _loss = crate::pcap::RequestLoss::arm(1);
            let mut r = ClientRequest::get(&["test"]);
            r.timeout = Duration::from_secs(8);
            let got = client.send_request(dest, &r)?;
            expect_codes(id, got.code, &[Code::CONTENT])?;
            if got.payload != site::TEST_BODY {
                return Err(PeerError("CORE_15 payload".into()));
            }
            Ok(())
        }
        "TD_COAP_CORE_16" => {
            let _loss = crate::pcap::RequestLoss::arm(1);
            separate_get(client, dest, id, Duration::from_secs(8))
        }
        "TD_COAP_CORE_20" => {
            let mut r = ClientRequest::get(&["test"]);
            r.accept = Some(0);
            basic(client, dest, r, Code::CONTENT)
        }
        "TD_COAP_CORE_21" => {
            let first = client.send_request(dest, &ClientRequest::get(&["validate"]))?;
            expect_codes(id, first.code, &[Code::CONTENT])?;
            if first.etag.is_empty() {
                return Err(PeerError("CORE_21 expected ETag".into()));
            }
            let mut r = ClientRequest::get(&["validate"]);
            r.etag = first.etag;
            let second = client.send_request(dest, &r)?;
            expect_codes(id, second.code, &[Code::VALID])
        }
        "TD_COAP_CORE_22" => {
            let mut ok = ClientRequest::request(Code::PUT, &["validate"]);
            ok.payload = site::TEST_BODY.to_vec();
            ok.if_match = vec![b"etag1".to_vec()];
            let got = client.send_request(dest, &ok)?;
            expect_codes(id, got.code, &[Code::CHANGED])?;
            let mut bad = ClientRequest::request(Code::PUT, &["validate"]);
            bad.if_match = vec![b"wrong".to_vec()];
            let got = client.send_request(dest, &bad)?;
            expect_codes(id, got.code, &[Code::PRECONDITION_FAILED])
        }
        "TD_COAP_CORE_23" => {
            let mut r = ClientRequest::request(Code::PUT, &["validate"]);
            r.if_none_match = true;
            let got = client.send_request(dest, &r)?;
            expect_codes(id, got.code, &[Code::PRECONDITION_FAILED])
        }
        "TD_COAP_CORE_31" => {
            let got = client.send_request(dest, &ClientRequest::ping())?;
            if !got.rst {
                return Err(PeerError(format!(
                    "CORE_31 expected RST, got {} {}",
                    got.ty, got.code
                )));
            }
            Ok(())
        }
        "TD_COAP_BLOCK_01" => block2(client, dest, true, 64),
        "TD_COAP_BLOCK_02" => block2(client, dest, false, 1024),
        "TD_COAP_BLOCK_03" => block1(client, dest, Code::PUT, &["large-update"], Code::CHANGED),
        "TD_COAP_BLOCK_04" => block1(client, dest, Code::POST, &["large-create"], Code::CREATED),
        "TD_COAP_BLOCK_05" => block1(client, dest, Code::POST, &["large-post"], Code::CHANGED),
        "TD_COAP_BLOCK_06" => block2(client, dest, true, 16),
        "TD_COAP_LINK_01" => link(client, dest, &[]),
        "TD_COAP_LINK_02" => link(client, dest, &["rt=Type1"]),
        "TD_COAP_LINK_03" => link(client, dest, &["rt=*"]),
        "TD_COAP_LINK_04" => link(client, dest, &["rt=Type2"]),
        "TD_COAP_LINK_05" => link(client, dest, &["if=If*"]),
        "TD_COAP_LINK_06" => link(client, dest, &["sz=*"]),
        "TD_COAP_LINK_07" => link(client, dest, &["href=/link1"]),
        "TD_COAP_LINK_08" => link(client, dest, &["href=/link*"]),
        "TD_COAP_LINK_09" => {
            link(client, dest, &[])?;
            let got = client.send_request(dest, &ClientRequest::get(&["path"]))?;
            expect_codes(id, got.code, &[Code::CONTENT])?;
            let target = check_hierarchy_payload(
                got.content_format,
                got.body.as_deref().unwrap_or(&got.payload),
            )?;
            let path: Vec<&str> = target.trim_start_matches('/').split('/').collect();
            let sub = client.send_request(dest, &ClientRequest::get(&path))?;
            expect_codes(id, sub.code, &[Code::CONTENT])?;
            if sub.payload != site::PATH_SUB1 {
                return Err(PeerError("LINK_09 /path/sub1 payload".into()));
            }
            Ok(())
        }
        id if id.starts_with("TD_COAP_OBS_") => observe(id, dest, client, server),
        id if id.starts_with("TD_COAP_DTLS_") => Err(PeerError(format!(
            "{id}: drive via runner::run_dtls (feature dtls)"
        ))),
        other => Err(PeerError(format!("no driver for {other}"))),
    }
}

fn basic(
    client: &mut dyn Peer,
    dest: SocketAddr,
    req: ClientRequest,
    want: Code,
) -> Result<(), PeerError> {
    let got = client.send_request(dest, &req)?;
    expect_codes("basic", got.code, &[want])
}

fn expect_codes(id: &str, got: Code, want: &[Code]) -> Result<(), PeerError> {
    if want.contains(&got) {
        Ok(())
    } else {
        Err(PeerError(format!(
            "{id}: got {got}, expected one of {want:?}"
        )))
    }
}

fn separate_get(
    client: &mut dyn Peer,
    dest: SocketAddr,
    id: &str,
    timeout: Duration,
) -> Result<(), PeerError> {
    let mut r = ClientRequest::get(&["separate"]);
    r.timeout = timeout;
    if id == "TD_COAP_CORE_17" {
        r.ty = Type::NonConfirmable;
    }
    r.token_len = Some(if id == "TD_COAP_CORE_11" { 8 } else { 4 });
    let got = client.send_request(dest, &r)?;
    expect_codes(id, got.code, &[Code::CONTENT])?;
    if got.payload != site::SEP_BODY {
        return Err(PeerError(format!(
            "{id}: payload {:?}",
            String::from_utf8_lossy(&got.payload)
        )));
    }
    Ok(())
}

fn block2(
    client: &mut dyn Peer,
    dest: SocketAddr,
    early: bool,
    size: u16,
) -> Result<(), PeerError> {
    let mut r = ClientRequest::get(&["large"]);
    if early {
        r.block2 = Some((0, false, size));
    }
    r.timeout = Duration::from_secs(20);
    let got = client.send_request(dest, &r)?;
    expect_codes("block2", got.code, &[Code::CONTENT])?;
    let body = got.body.as_deref().unwrap_or(&got.payload);
    let expect = site::large_body();
    if body != expect {
        return Err(PeerError(format!(
            "block2 assembled {} bytes, want {}",
            body.len(),
            expect.len()
        )));
    }
    Ok(())
}

fn block1(
    client: &mut dyn Peer,
    dest: SocketAddr,
    method: Code,
    path: &[&str],
    want: Code,
) -> Result<(), PeerError> {
    let mut r = ClientRequest::request(method, path);
    r.payload = site::large_body();
    r.content_format = Some(0);
    r.timeout = Duration::from_secs(20);
    let got = client.send_request(dest, &r)?;
    expect_codes("block1", got.code, &[want])?;
    if path == ["large-update"] {
        let stored = site::large_update().ok_or("BLOCK_03 stored no updated resource")?;
        if stored != r.payload {
            return Err(PeerError(format!(
                "BLOCK_03 application effect stored {} bytes, sent {}",
                stored.len(),
                r.payload.len()
            )));
        }
    }
    if path == ["large-post"] {
        let body = got.body.as_deref().unwrap_or(&got.payload);
        if body != r.payload {
            return Err(PeerError(format!(
                "BLOCK_05 response representation {} bytes, sent {}",
                body.len(),
                r.payload.len()
            )));
        }
    }
    Ok(())
}

fn link(client: &mut dyn Peer, dest: SocketAddr, query: &[&str]) -> Result<(), PeerError> {
    let mut r = ClientRequest::get(&[".well-known", "core"]);
    r.query = query.iter().map(|s| (*s).to_owned()).collect();
    // Request bounded blocks so the full catalog is not a truncated inline snapshot.
    r.block2 = Some((0, false, 64));
    let got = client.send_request(dest, &r)?;
    expect_codes("link", got.code, &[Code::CONTENT])?;
    // Independent expected membership: do not reuse the server's filter.
    let indices: &[usize] = match query {
        [] => &[0, 1, 2, 3, 4, 5],
        ["rt=Type1"] => &[0, 2],
        ["rt=*"] => &[0, 1, 2, 3],
        ["rt=Type2"] => &[0, 1],
        ["if=If*"] => &[0, 1],
        ["sz=*"] => &[0, 5],
        ["href=/link1"] => &[1],
        ["href=/link*"] => &[1, 2, 3],
        _ => return Err(PeerError("link: unknown expected query".into())),
    };
    check_link_payload(
        got.content_format,
        got.body.as_deref().unwrap_or(&got.payload),
        indices,
    )
}

fn check_hierarchy_payload(format: Option<u16>, payload: &[u8]) -> Result<&str, PeerError> {
    if format != Some(40) {
        return Err(PeerError(
            "LINK_09: missing/incorrect child link content-format".into(),
        ));
    }
    let text = std::str::from_utf8(payload).map_err(|e| PeerError(e.to_string()))?;
    let mut children: Vec<&str> = text.split(',').collect();
    children.sort_unstable();
    if children != ["</path/sub1>", "</path/sub2>"] {
        return Err(PeerError(
            "LINK_09: missing, extra, duplicate or malformed child links".into(),
        ));
    }
    // Select the next request from the verified received representation.
    Ok(children[0]
        .strip_prefix('<')
        .unwrap()
        .strip_suffix('>')
        .unwrap())
}

fn check_link_payload(
    format: Option<u16>,
    payload: &[u8],
    indices: &[usize],
) -> Result<(), PeerError> {
    if format != Some(40) {
        return Err(PeerError(
            "link: missing or incorrect application/link-format".into(),
        ));
    }
    let text = std::str::from_utf8(payload).map_err(|e| PeerError(e.to_string()))?;
    let mut actual: Vec<&str> = text.split(',').collect();
    let mut expected: Vec<&str> = indices.iter().map(|i| site::LINK_CATALOG[*i]).collect();
    actual.sort_unstable();
    expected.sort_unstable();
    if actual != expected {
        return Err(PeerError(format!(
            "link: expected {expected:?}, received {actual:?}"
        )));
    }
    Ok(())
}

fn observe(
    id: &str,
    dest: SocketAddr,
    client: &mut dyn Peer,
    server: &mut dyn Peer,
) -> Result<(), PeerError> {
    if id == "TD_COAP_OBS_02" {
        return observe_non(dest, client, server);
    }
    let path: &[&str] = &["obs"];
    let mut reg = ClientRequest::get(path);
    reg.observe = Some(0);
    let first = client.send_request(dest, &reg)?;
    expect_codes(id, first.code, &[Code::CONTENT])?;
    match id {
        "TD_COAP_OBS_07" => {
            let del = client.send_request(dest, &ClientRequest::request(Code::DELETE, path))?;
            expect_codes(id, del.code, &[Code::DELETED])
        }
        "TD_COAP_OBS_10" => {
            let _ = client.send_request(dest, &ClientRequest::get(path))?;
            server.notify(path, site::OBS_BODY_2)?;
            thread::sleep(Duration::from_millis(80));
            Ok(())
        }
        "TD_COAP_OBS_12" => {
            let mut off = ClientRequest::get(path);
            off.observe = Some(1);
            let _ = client.send_request(dest, &off)?;
            Ok(())
        }
        "TD_COAP_OBS_08" => {
            // Format-change: server drops the interest (App/engine). A notify is optional.
            Ok(())
        }
        _ => {
            server.notify(path, site::OBS_BODY_2)?;
            thread::sleep(Duration::from_millis(80));
            Ok(())
        }
    }
}

fn observe_non(
    dest: SocketAddr,
    client: &mut dyn Peer,
    server: &mut dyn Peer,
) -> Result<(), PeerError> {
    if server.name() != "coaptic" {
        return Err(PeerError(
            "SKIP: coverage gap #199: coap-rs server wrapper does not emit NON notifications"
                .into(),
        ));
    }
    let mut reg = ClientRequest::get(&["obs-non"]);
    reg.ty = Type::NonConfirmable;
    reg.observe = Some(0);
    reg.timeout = Duration::from_secs(3);
    let first = client.begin_observe(dest, &reg)?;
    expect_codes("TD_COAP_OBS_02", first.code, &[Code::CONTENT])?;
    if first.ty != Type::NonConfirmable || first.payload != site::OBS_BODY {
        return Err(PeerError("OBS_02 initial NON notification".into()));
    }
    if first.content_format != Some(0) {
        return Err(PeerError("OBS_02 initial content-format".into()));
    }
    let mut previous = first
        .observe
        .ok_or_else(|| PeerError("OBS_02 missing initial Observe sequence".into()))?;
    // The vendored TD repeats its notification steps. Require two later state
    // changes; registration plus a single update does not exercise that loop.
    for payload in [site::OBS_BODY_2, site::OBS_BODY] {
        // Respect the server's NON congestion hold before the next periodic
        // change. A one-shot notify during that hold may legitimately send zero.
        thread::sleep(Duration::from_millis(
            u64::from(coaptic::message::ObserveTransmission::NON_TIMEOUT_MS) + 20,
        ));
        server.notify(&["obs-non"], payload)?;
        let next = client.take_notification(Duration::from_secs(3))?;
        expect_codes("TD_COAP_OBS_02", next.code, &[Code::CONTENT])?;
        if next.ty != Type::NonConfirmable || next.payload != payload {
            return Err(PeerError("OBS_02 next NON notification".into()));
        }
        let sequence = next
            .observe
            .ok_or_else(|| PeerError("OBS_02 missing Observe sequence".into()))?;
        let delta = sequence.wrapping_sub(previous) & 0x00ff_ffff;
        if !(1..0x0080_0000).contains(&delta) {
            return Err(PeerError(format!(
                "OBS_02 sequence {previous} then {sequence}"
            )));
        }
        if next.content_format != first.content_format {
            return Err(PeerError("OBS_02 content-format".into()));
        }
        previous = sequence;
    }
    Ok(())
}

/// Run every in-scope TD on `pairs`. DTLS TDs need `feature = "dtls"`.
pub fn run_suite(ids: &[&str], pairs: &[Pair]) -> Vec<TdResult> {
    let mut out = Vec::new();
    for id in ids {
        if id.starts_with("TD_COAP_DTLS_") {
            #[cfg(feature = "dtls")]
            {
                out.extend(crate::dtls::run_dtls_pairs(id, pairs));
            }
            #[cfg(not(feature = "dtls"))]
            {
                for pair in pairs {
                    out.push(TdResult {
                        id: (*id).to_owned(),
                        pair: *pair,
                        error: Some(format!(
                            "SKIP: {}",
                            catalog::skip_reason(id).unwrap_or("dtls feature")
                        )),
                        capture: Capture::new(),
                    });
                }
            }
            continue;
        }
        for pair in pairs {
            out.push(run_td(id, *pair));
        }
    }
    out
}

#[cfg(test)]
mod link_grade_tests {
    use super::*;

    #[test]
    fn hierarchy_refuses_partial_duplicate_extra_and_wrong_format() {
        let valid = b"</path/sub1>,</path/sub2>";
        assert_eq!(
            check_hierarchy_payload(Some(40), valid).unwrap(),
            "/path/sub1"
        );
        for format in [None, Some(0), Some(50)] {
            assert!(check_hierarchy_payload(format, valid).is_err());
        }
        for invalid in [
            "",
            "</path/sub1>",
            "</path/sub1>,</path/sub1>",
            "</path/sub1>,</path/sub2>,</other>",
            "</path/sub1>,</path/sub2",
        ] {
            assert!(check_hierarchy_payload(Some(40), invalid.as_bytes()).is_err());
        }
    }

    #[test]
    fn exact_discovery_refuses_missing_extra_duplicate_and_truncated_links() {
        let valid = site::LINK_CATALOG[1];
        check_link_payload(Some(40), valid.as_bytes(), &[1]).unwrap();
        for format in [None, Some(0), Some(50)] {
            assert!(check_link_payload(format, valid.as_bytes(), &[1]).is_err());
        }
        for invalid in [
            String::new(),
            valid[..valid.len() - 1].to_owned(),
            format!("{valid},{valid}"),
            format!("{valid},{}", site::LINK_CATALOG[3]),
        ] {
            assert!(check_link_payload(Some(40), invalid.as_bytes(), &[1]).is_err());
        }
    }
}
