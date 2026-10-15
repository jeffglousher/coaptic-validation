//! In-memory Engine-pair drivers for `TD_COAP_LINK_*` (RFC 6690).
//!
//! Link-format catalog and filtering live in the harness application, not
//! in Engine. The two Engines exchange the GET / `.well-known/core` bytes.

use coaptic::message::{Opt, Type};
use coaptic::{Code, ContentFormat};

use crate::harness::{Pair, path_is, uri_query};

const CATALOG: &[&str] = &[
    "</test>;rt=\"Type1 Type2\";if=\"If1\";sz=123",
    "</link1>;rt=\"Type2 Type3\";if=\"If2\"",
    "</link2>;rt=\"Type1 Type3\";if=\"foo\"",
    "</link3>;rt=\"\"",
    "</path>;ct=40",
    "</large>;sz=1024",
];

const PATH_SUB: &str = "</path/sub1>,</path/sub2>";
const PATH_SUB1_BODY: &[u8] = b"/path/sub1";

pub fn run(id: &str) {
    match id {
        "TD_COAP_LINK_01" => link_01_all(),
        "TD_COAP_LINK_02" => link_filter("rt=Type1", |l| l.contains("Type1")),
        "TD_COAP_LINK_03" => link_filter("rt=*", |l| l.contains("rt=")),
        "TD_COAP_LINK_04" => link_filter("rt=Type2", |l| l.contains("Type2")),
        "TD_COAP_LINK_05" => link_filter("if=If*", |l| l.contains("if=\"If")),
        "TD_COAP_LINK_06" => link_filter("sz=*", |l| l.contains("sz=")),
        "TD_COAP_LINK_07" => link_filter("href=/link1", |l| l.starts_with("</link1>")),
        "TD_COAP_LINK_08" => link_filter("href=/link*", |l| l.contains("</link")),
        "TD_COAP_LINK_09" => link_09_hierarchy(),
        other => panic!("unknown LINK id {other}"),
    }
}

fn well_known(pair: &mut Pair, query: &[Opt<'_>]) -> String {
    let token = Pair::client_token(2);
    let (tx, mid) = pair.client_request(
        Type::Confirmable,
        Code::GET,
        token,
        &[".well-known", "core"],
        query,
        &[],
    );
    let rx = pair.exchange_client(tx);
    let parsed = pair.server.decode_rx(rx).expect("decode");
    assert!(path_is(parsed, &[".well-known", "core"]));
    let qs = uri_query(parsed);
    let payload = filter_catalog(&qs);
    let cf = ContentFormat::LINK_FORMAT.encode();
    let extra = [Opt::content_format(&cf)];
    let stx = pair.server_reply(
        Type::Acknowledgement,
        Code::CONTENT,
        mid,
        token,
        &extra,
        payload.as_bytes(),
    );
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    let got = pair.client.decode_rx(crx).expect("client decode");
    assert_eq!(got.code(), Code::CONTENT);
    assert_eq!(
        got.content_format().expect("cf").expect("val"),
        ContentFormat::LINK_FORMAT
    );
    let body = String::from_utf8(got.payload().to_vec()).expect("link-format utf8");
    pair.client.match_response_rx(crx).ok();
    pair.client.release_rx(crx).ok();
    body
}

fn filter_catalog(queries: &[String]) -> String {
    if queries.is_empty() {
        return CATALOG.join(",");
    }
    CATALOG
        .iter()
        .filter(|link| queries.iter().all(|q| link_matches(link, q)))
        .copied()
        .collect::<Vec<_>>()
        .join(",")
}

fn link_matches(link: &str, query: &str) -> bool {
    let Some((key, value)) = query.split_once('=') else {
        return false;
    };
    match key {
        "href" => href_match(link, value),
        "rt" => attr_match(link, "rt", value),
        "if" => attr_match(link, "if", value),
        "sz" => {
            if value == "*" {
                link.contains("sz=")
            } else {
                link.contains(&format!("sz={value}"))
            }
        }
        _ => false,
    }
}

fn href_match(link: &str, value: &str) -> bool {
    let href = link
        .split('>')
        .next()
        .and_then(|s| s.strip_prefix('<'))
        .unwrap_or("");
    if let Some(prefix) = value.strip_suffix('*') {
        href.starts_with(prefix)
    } else {
        href == value
    }
}

fn attr_match(link: &str, attr: &str, value: &str) -> bool {
    let needle = format!("{attr}=");
    let Some(start) = link.find(&needle) else {
        return false;
    };
    if value == "*" {
        return true;
    }
    let rest = &link[start + needle.len()..];
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    let end = rest.find('"').unwrap_or(rest.len());
    let listed = &rest[..end];
    if let Some(prefix) = value.strip_suffix('*') {
        listed.split_whitespace().any(|t| t.starts_with(prefix))
    } else {
        listed.split_whitespace().any(|t| t == value)
    }
}

fn link_01_all() {
    let mut pair = Pair::new();
    let body = well_known(&mut pair, &[]);
    assert_eq!(body, CATALOG.join(","));
}

fn link_filter(query: &str, pred: impl Fn(&str) -> bool) {
    let mut pair = Pair::new();
    let q = Opt::uri_query(query);
    let body = well_known(&mut pair, &[q]);
    for part in body.split(',').filter(|s| !s.is_empty()) {
        assert!(pred(part), "filter {query} kept unexpected {part}");
    }
    for link in CATALOG {
        if pred(link) {
            assert!(
                body.contains(link.split(';').next().unwrap_or(link)),
                "filter {query} missing {link}"
            );
        }
    }
}

fn link_09_hierarchy() {
    let mut pair = Pair::new();
    let body = well_known(&mut pair, &[]);
    assert!(body.split(',').any(|link| link == "</path>;ct=40"));
    let token = Pair::client_token(2);
    let cf = ContentFormat::LINK_FORMAT.encode();
    let extra = [Opt::content_format(&cf)];
    let (tx, mid) = pair.client_request(Type::Confirmable, Code::GET, token, &["path"], &[], &[]);
    let rx = pair.exchange_client(tx);
    let stx = pair.server_reply(
        Type::Acknowledgement,
        Code::CONTENT,
        mid,
        token,
        &extra,
        PATH_SUB.as_bytes(),
    );
    pair.server.release_rx(rx).ok();
    let crx = pair.exchange_server(stx);
    let response = pair.client.decode_rx(crx).expect("path");
    assert_eq!(response.code(), Code::CONTENT);
    assert_eq!(
        response.content_format().unwrap().unwrap(),
        ContentFormat::LINK_FORMAT
    );
    assert_eq!(response.payload(), PATH_SUB.as_bytes());
    pair.client.match_response_rx(crx).ok();
    pair.client.release_rx(crx).ok();

    let token2 = Pair::client_token(3);
    let (tx2, mid2) = pair.client_request(
        Type::Confirmable,
        Code::GET,
        token2,
        &["path", "sub1"],
        &[],
        &[],
    );
    let rx2 = pair.exchange_client(tx2);
    let stx2 = pair.server_reply(
        Type::Acknowledgement,
        Code::CONTENT,
        mid2,
        token2,
        &[],
        PATH_SUB1_BODY,
    );
    pair.server.release_rx(rx2).ok();
    let crx2 = pair.exchange_server(stx2);
    let response = pair.client.decode_rx(crx2).expect("sub1");
    assert_eq!(response.code(), Code::CONTENT);
    assert_eq!(response.payload(), PATH_SUB1_BODY);
    pair.client.match_response_rx(crx2).ok();
    pair.client.release_rx(crx2).ok();
}
