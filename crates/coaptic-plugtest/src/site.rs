//! Plugtest resource catalog shared by both peer backends.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

use coaptic::app::MethodRouter;
use coaptic::message::Precondition;
use coaptic::{Code, ContentFormat, Request, Response, get, post, put};

/// Text body for `/test` GET.
pub const TEST_BODY: &[u8] = b"core-test-payload";
/// Second representation of the CORE20 resource.
pub const XML_BODY: &[u8] = b"<value>core-test-payload</value>";
pub(crate) const UPDATE_BODY: &[u8] = b"atomic-update-one";
pub(crate) const CONCURRENT_BODY: &[u8] = b"concurrent-update-two";
pub(crate) const REFUSED_BODY: &[u8] = b"refused-update-three";
/// Body for `/separate`.
pub const SEP_BODY: &[u8] = b"separate-payload";
/// Body for `/secure` (DTLS TDs).
pub const SECURE_BODY: &[u8] = b"secure-payload";
/// First Observe representation.
pub const OBS_BODY: &[u8] = b"obs-0";
/// Later Observe representation.
pub const OBS_BODY_2: &[u8] = b"obs-1";
const fn observe_large_bytes(version: u8) -> [u8; 2000] {
    let mut bytes = [0; 2000];
    let mut i = 0;
    while i < bytes.len() {
        bytes[i] = ((i + version as usize * 17) % 251) as u8;
        i += 1;
    }
    bytes
}
static OBS_LARGE_0: [u8; 2000] = observe_large_bytes(0);
static OBS_LARGE_1: [u8; 2000] = observe_large_bytes(1);
static OBS_LARGE_2: [u8; 2000] = observe_large_bytes(2);
static OBS_LARGE_VERSION: AtomicU8 = AtomicU8::new(0);
/// Fixed large representation and its stable version ETag.
#[must_use]
pub fn observe_large(version: u8) -> Option<(&'static [u8], &'static [u8])> {
    match version {
        0 => Some((&OBS_LARGE_0, b"L0")),
        1 => Some((&OBS_LARGE_1, b"L1")),
        2 => Some((&OBS_LARGE_2, b"L2")),
        _ => None,
    }
}
pub(crate) fn commit_observe_large(version: u8) {
    OBS_LARGE_VERSION.store(version, Ordering::SeqCst);
}
pub(crate) fn observe_large_response() -> Response<'static> {
    let (body, etag) =
        observe_large(OBS_LARGE_VERSION.load(Ordering::SeqCst)).expect("bounded version");
    Response::content(body)
        .content_format(ContentFormat::TEXT_PLAIN)
        .etag(etag)
        .max_age(5)
}
fn get_obs_large(_: Request<'_>) -> Response<'static> {
    observe_large_response()
}

static OBS_PUMPING_VERSION: AtomicU8 = AtomicU8::new(0);
/// Finite variable-size representation and stable ETag.
#[must_use]
pub fn observe_pumping(version: u8) -> Option<(&'static [u8], &'static [u8])> {
    match version {
        0 => Some((&OBS_LARGE_0[..32], b"P0")),
        1 => Some((&OBS_LARGE_1, b"P1")),
        2 => Some((&OBS_LARGE_2[..64], b"P2")),
        _ => None,
    }
}
pub(crate) fn commit_observe_pumping(version: u8) {
    OBS_PUMPING_VERSION.store(version, Ordering::SeqCst);
}
pub(crate) fn observe_pumping_response() -> Response<'static> {
    let (body, etag) =
        observe_pumping(OBS_PUMPING_VERSION.load(Ordering::SeqCst)).expect("bounded version");
    Response::content(body)
        .content_format(ContentFormat::TEXT_PLAIN)
        .etag(etag)
        .max_age(5)
}
fn get_obs_pumping(_: Request<'_>) -> Response<'static> {
    observe_pumping_response()
}

/// `/path/sub1` payload.
pub const PATH_SUB1: &[u8] = b"/path/sub1";
/// `/path` link-format children.
pub const PATH_LINKS: &str = "</path/sub1>,</path/sub2>";
/// Large Block2 / Block1 body (bigger than a Default datagram).
pub const LARGE_LEN: usize = 2000;
/// Patterned large body (same rule as the in-crate harness).
#[must_use]
pub fn large_body() -> Vec<u8> {
    (0..LARGE_LEN).map(|i| (i % 251) as u8).collect()
}

/// RFC 6690 catalog used by LINK TDs (same strings as `tests/plugtest/link.rs`).
pub const LINK_CATALOG: &[&str] = &[
    "</test>;rt=\"Type1 Type2\";if=\"If1\";sz=123",
    "</link1>;rt=\"Type2 Type3\";if=\"If2\"",
    "</link2>;rt=\"Type1 Type3\";if=\"foo\"",
    "</link3>;rt=\"\"",
    "</path>;ct=40",
    "</large>;sz=1024",
];

static VALIDATE_BODY: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
static VALIDATE_ETAG: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
static LARGE_UPDATE: OnceLock<Mutex<Option<Vec<u8>>>> = OnceLock::new();
static TEST_EXISTS: AtomicBool = AtomicBool::new(true);
static OBS_SEQ: AtomicU32 = AtomicU32::new(0);
// Serialized TD ownership is enforced by runner::harness_lock. Zero preserves
// the original fixed snapshot fixture; 1/2 select the two updated representations.
static OBS_REPRESENTATION: AtomicU8 = AtomicU8::new(0);
static OBS_STATE: AtomicU8 = AtomicU8::new(0);

pub(crate) fn set_observed_state(state: u8) {
    OBS_STATE.store(state, Ordering::SeqCst);
    if state == 0 {
        OBS_REPRESENTATION.store(0, Ordering::SeqCst);
    }
}

pub(crate) fn observed_response() -> Response<'static> {
    match OBS_STATE.load(Ordering::SeqCst) {
        1 => Response::not_found(),
        2 => Response::content(OBS_BODY_2).content_format(ContentFormat::OCTET_STREAM),
        _ => Response::content(current_observe_body()).content_format(ContentFormat::TEXT_PLAIN),
    }
}

pub(crate) fn observe_update_body(payload: &[u8]) -> Option<&'static [u8]> {
    if payload == OBS_BODY {
        Some(OBS_BODY)
    } else if payload == OBS_BODY_2 {
        Some(OBS_BODY_2)
    } else {
        None
    }
}

pub(crate) fn commit_observe_update(body: &'static [u8]) {
    OBS_REPRESENTATION.store(if body == OBS_BODY_2 { 1 } else { 2 }, Ordering::SeqCst);
}

fn current_observe_body() -> &'static [u8] {
    if OBS_REPRESENTATION.load(Ordering::SeqCst) == 1 {
        OBS_BODY_2
    } else {
        OBS_BODY
    }
}

fn validate_body() -> &'static Mutex<Vec<u8>> {
    VALIDATE_BODY.get_or_init(|| Mutex::new(TEST_BODY.to_vec()))
}

fn validate_etag() -> &'static Mutex<Vec<u8>> {
    VALIDATE_ETAG.get_or_init(|| Mutex::new(b"etag1".to_vec()))
}

pub(crate) fn validation_snapshot() -> (Vec<u8>, Vec<u8>) {
    (
        validate_body().lock().unwrap().clone(),
        validate_etag().lock().unwrap().clone(),
    )
}

pub(crate) fn validation_update(body: &[u8]) {
    *validate_body().lock().unwrap() = body.to_vec();
    let mut etag = validate_etag().lock().unwrap();
    // One bounded revision byte is sufficient for this finite per-TD fixture.
    let revision = etag.last().copied().unwrap_or(0).wrapping_add(1);
    *etag = vec![revision];
}

fn created_body() -> &'static Mutex<Option<Vec<u8>>> {
    static BODY: OnceLock<Mutex<Option<Vec<u8>>>> = OnceLock::new();
    BODY.get_or_init(|| Mutex::new(None))
}

pub(crate) fn create_once(body: &[u8]) -> bool {
    let mut saved = created_body().lock().unwrap();
    if saved.is_some() {
        return false;
    }
    *saved = Some(body.to_vec());
    true
}

pub(crate) fn created_snapshot() -> Option<Vec<u8>> {
    created_body().lock().unwrap().clone()
}

fn large_update_slot() -> &'static Mutex<Option<Vec<u8>>> {
    LARGE_UPDATE.get_or_init(|| Mutex::new(None))
}

/// Body stored by the last completed PUT `/large-update`.
#[must_use]
pub fn large_update() -> Option<Vec<u8>> {
    large_update_slot().lock().expect("large-update").clone()
}

/// Record the assembled PUT `/large-update` body (the TD's application effect).
pub fn set_large_update(body: &[u8]) {
    *large_update_slot().lock().expect("large-update") = Some(body.to_vec());
}

/// Reset per-TD resource state.
pub fn reset() {
    *created_body().lock().unwrap() = None;
    *validate_body().lock().expect("body") = TEST_BODY.to_vec();
    *validate_etag().lock().expect("etag") = b"etag1".to_vec();
    *large_update_slot().lock().expect("large-update") = None;
    TEST_EXISTS.store(true, Ordering::SeqCst);
    OBS_SEQ.store(0, Ordering::SeqCst);
    OBS_LARGE_VERSION.store(0, Ordering::SeqCst);
    OBS_PUMPING_VERSION.store(0, Ordering::SeqCst);
    OBS_STATE.store(0, Ordering::SeqCst);
    OBS_REPRESENTATION.store(0, Ordering::SeqCst);
}

fn get_test(_req: Request<'_>) -> Response<'static> {
    if !TEST_EXISTS.load(Ordering::SeqCst) {
        return Response::not_found();
    }
    Response::content(TEST_BODY).content_format(ContentFormat::TEXT_PLAIN)
}

fn put_test(req: Request<'_>) -> Response<'static> {
    TEST_EXISTS.store(true, Ordering::SeqCst);
    let _ = req.payload();
    Response::changed()
}

fn post_test(_req: Request<'_>) -> Response<'static> {
    TEST_EXISTS.store(true, Ordering::SeqCst);
    Response::created()
        .location_path("location1")
        .location_path("location2")
        .location_path("location3")
        .location_query("first=1")
        .location_query("second=2")
}

fn delete_test(_req: Request<'_>) -> Response<'static> {
    TEST_EXISTS.store(false, Ordering::SeqCst);
    Response::deleted()
}

fn get_separate(_req: Request<'_>) -> Response<'static> {
    Response::content(SEP_BODY)
        .content_format(ContentFormat::TEXT_PLAIN)
        .separate()
}

fn get_query(_req: Request<'_>) -> Response<'static> {
    Response::content(TEST_BODY).content_format(ContentFormat::TEXT_PLAIN)
}

fn get_seg(_req: Request<'_>) -> Response<'static> {
    Response::content(TEST_BODY).content_format(ContentFormat::TEXT_PLAIN)
}

fn get_validate(req: Request<'_>) -> Response<'static> {
    let etag = validate_etag().lock().expect("etag").clone();
    let body = validate_body().lock().expect("body").clone();
    let tags: Vec<Vec<u8>> = req.etag().map(|t| t.to_vec()).collect();
    if tags.iter().any(|t| t == &etag) {
        return Response::valid().etag(&etag);
    }
    let mut r = Response::content_copy(&body)
        .content_format(ContentFormat::TEXT_PLAIN)
        .etag(&etag);
    if req.accept().is_some() {
        r = r.content_format(ContentFormat::TEXT_PLAIN);
    }
    r
}

fn put_validate(req: Request<'_>) -> Response<'static> {
    let etag = validate_etag().lock().expect("etag").clone();
    let exists = true;
    match req.precondition(exists, Some(etag.as_slice())) {
        Precondition::Unconditional | Precondition::Satisfied => {
            validation_update(req.payload());
            Response::changed()
        }
        Precondition::FailedIfMatch | Precondition::FailedIfNoneMatch => {
            Response::precondition_failed()
        }
    }
}

fn get_multi_format(req: Request<'_>) -> Response<'static> {
    match req.accept() {
        Some(Ok(ContentFormat::XML)) => {
            Response::content(XML_BODY).content_format(ContentFormat::XML)
        }
        None | Some(Ok(ContentFormat::TEXT_PLAIN)) => {
            Response::content(TEST_BODY).content_format(ContentFormat::TEXT_PLAIN)
        }
        _ => Response::new(Code::NOT_ACCEPTABLE),
    }
}

fn put_create(req: Request<'_>) -> Response<'static> {
    if !req.if_none_match() || !create_once(req.payload()) {
        Response::precondition_failed()
    } else {
        Response::created()
    }
}

fn get_create(_: Request<'_>) -> Response<'static> {
    match created_snapshot() {
        Some(body) => Response::content_copy(&body).content_format(ContentFormat::TEXT_PLAIN),
        None => Response::not_found(),
    }
}

fn get_large(_req: Request<'_>) -> Response<'static> {
    // 'static leak once — Default TX body is 4096; 2000 must Block2.
    static LARGE: OnceLock<Vec<u8>> = OnceLock::new();
    let body = LARGE.get_or_init(large_body);
    // Response::content wants 'static; copy into a leaked box for the handler.
    // The harness is a test crate; this is once per process.
    static LEAK: OnceLock<&'static [u8]> = OnceLock::new();
    let slice = *LEAK.get_or_init(|| body.clone().leak());
    Response::content(slice).content_format(ContentFormat::TEXT_PLAIN)
}

fn put_large(req: Request<'_>) -> Response<'static> {
    let body = req.body().unwrap_or(req.payload());
    set_large_update(body);
    Response::changed()
}

fn post_large_create(req: Request<'_>) -> Response<'static> {
    let _ = req.body().or(Some(req.payload()));
    Response::created()
        .location_path("large-create")
        .location_path("ps")
}

fn post_large_post(req: Request<'_>) -> Response<'static> {
    let _ = req.body().or(Some(req.payload()));
    static LEAK: OnceLock<&'static [u8]> = OnceLock::new();
    let slice = *LEAK.get_or_init(|| large_body().leak());
    Response::new(Code::CHANGED)
        .with_static(slice)
        .content_format(ContentFormat::TEXT_PLAIN)
}

fn get_obs(_req: Request<'_>) -> Response<'static> {
    if OBS_STATE.load(Ordering::SeqCst) == 1 {
        return Response::not_found();
    }
    observed_response().observe(0).max_age(5)
}

fn obs_snapshot() -> Response<'static> {
    if OBS_STATE.load(Ordering::SeqCst) != 0 {
        return observed_response();
    }
    let body = if OBS_REPRESENTATION.load(Ordering::SeqCst) == 0 {
        OBS_BODY_2
    } else {
        current_observe_body()
    };
    Response::content(body)
        .content_format(ContentFormat::TEXT_PLAIN)
        .observe(OBS_SEQ.fetch_add(1, Ordering::SeqCst).saturating_add(1))
}

fn delete_obs(_req: Request<'_>) -> Response<'static> {
    set_observed_state(1);
    Response::deleted()
}

fn get_link1(_req: Request<'_>) -> Response<'static> {
    Response::content(b"link1")
}

fn get_path(_req: Request<'_>) -> Response<'static> {
    Response::content(PATH_LINKS.as_bytes()).content_format(ContentFormat::LINK_FORMAT)
}

fn get_path_sub1(_req: Request<'_>) -> Response<'static> {
    Response::content(PATH_SUB1)
}

fn get_path_sub2(_req: Request<'_>) -> Response<'static> {
    Response::content(b"/path/sub2")
}

fn get_secure(_req: Request<'_>) -> Response<'static> {
    Response::content(SECURE_BODY).content_format(ContentFormat::TEXT_PLAIN)
}

fn well_known(req: Request<'_>) -> Response<'static> {
    let queries: Vec<String> = req
        .uri_query()
        .filter_map(|s| s.ok().map(str::to_owned))
        .collect();
    static FULL_CATALOG: OnceLock<String> = OnceLock::new();
    if queries.is_empty() {
        return Response::content(
            FULL_CATALOG
                .get_or_init(|| LINK_CATALOG.join(","))
                .as_bytes(),
        )
        .content_format(ContentFormat::LINK_FORMAT);
    }
    // Stable, finite fixture storage allows large filtered catalogs to use
    // normal Block2 assembly instead of silently clipping the inline payload.
    const FILTERS: [&str; 8] = [
        "rt=Type1",
        "rt=*",
        "rt=Type2",
        "if=If*",
        "sz=*",
        "href=/link1",
        "href=/link*",
        "rt=",
    ];
    static FILTERED: OnceLock<[String; 8]> = OnceLock::new();
    if queries.len() == 1 {
        if let Some(index) = FILTERS.iter().position(|q| *q == queries[0]) {
            let catalogs =
                FILTERED.get_or_init(|| FILTERS.map(|q| filter_catalog(&[q.to_owned()])));
            return Response::content(catalogs[index].as_bytes())
                .content_format(ContentFormat::LINK_FORMAT);
        }
    }
    let payload = filter_catalog(&queries);
    let response =
        Response::content_copy(payload.as_bytes()).content_format(ContentFormat::LINK_FORMAT);
    if response.payload_truncated() {
        Response::new(Code::REQUEST_ENTITY_TOO_LARGE)
    } else {
        response
    }
}

/// Filter [`LINK_CATALOG`] by RFC 6690 query keys (`rt`, `if`, `sz`, `href`).
#[must_use]
pub fn filter_catalog(queries: &[String]) -> String {
    if queries.is_empty() {
        return LINK_CATALOG.join(",");
    }
    LINK_CATALOG
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
    if value.is_empty() {
        return listed.is_empty();
    }
    if let Some(prefix) = value.strip_suffix('*') {
        listed.split_whitespace().any(|t| t.starts_with(prefix))
    } else {
        listed.split_whitespace().any(|t| t == value)
    }
}

/// Method router table for the coaptic App server (24 slots).
pub fn routers() -> [(&'static str, MethodRouter); 21] {
    [
        (
            "test",
            get(get_test)
                .put(put_test)
                .post(post_test)
                .delete(delete_test),
        ),
        ("separate", get(get_separate)),
        ("query", get(get_query)),
        ("validate", get(get_validate).put(put_validate)),
        ("multi-format", get(get_multi_format)),
        ("create1", get(get_create).put(put_create)),
        ("seg1/seg2/seg3", get(get_seg)),
        ("large", get(get_large)),
        ("large-update", put(put_large)),
        ("large-create", post(post_large_create)),
        ("large-post", post(post_large_post)),
        ("obs", get(get_obs).delete(delete_obs).observe(obs_snapshot)),
        ("obs-non", get(get_obs).observe(obs_snapshot)),
        (
            "obs-pumping",
            get(get_obs_pumping).observe(observe_pumping_response),
        ),
        (
            "obs-large",
            get(get_obs_large).observe(observe_large_response),
        ),
        ("link1", get(get_link1)),
        ("link2", get(get_link1)),
        ("link3", get(get_link1)),
        ("path", get(get_path)),
        ("path/sub1", get(get_path_sub1)),
        ("path/sub2", get(get_path_sub2)),
    ]
}

/// Extra routes that do not fit the array above.
pub fn extra_routers() -> [(&'static str, MethodRouter); 2] {
    [
        (".well-known/core", get(well_known)),
        ("secure", get(get_secure)),
    ]
}
