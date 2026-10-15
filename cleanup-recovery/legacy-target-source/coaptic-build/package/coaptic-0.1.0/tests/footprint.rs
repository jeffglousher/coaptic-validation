//! RAM locks for Default / Constrained App vs Memory (#93 / PERF-00).
//!
//! `.block_wise::<false>()` must not pay `WithBodies` padding or the
//! client Block2 assembled hold (`RESPONSE_BODY`). Host `usize=8`
//! magnitudes at `06a39cd`: Memory Default 13416, WithBodies 30312
//! (Δ16896), App-with-enum 33600.

use core::mem::size_of;

use coaptic::Response;
use coaptic::app::{
    App, DEFAULT_ROUTES, LINK_FORMAT_PER_ROUTE, LinkFormatScratch, RESPONSE_BODY,
    link_format_capacity,
};
use coaptic::profiles;
use coaptic::storage::{Memory, MemoryLayout, WithBodies};

/// Block-wise App may pay the assembled hold on top of Memory body pools.
/// Padding to `App`'s alignment stays well under 64 bytes.
const ASSEMBLED_HOLD_PAD: usize = 64;

// Four live requests now retain up to 256 URI-query bytes, eight lengths,
// and metadata each. Account explicitly for this bounded protocol state;
// the remaining overhead must still be smaller than an assembled body.
const RETAINED_QUERY_BUDGET: usize = 4 * (256 + 16 + 16);
// Four pending/completed headers and one borrowed-reply hold. The hold also
// retains an inline payload and endpoint; no assembled-body buffer is hidden here.
const RETAINED_RESPONSE_BUDGET: usize = 5 * coaptic::app::RESPONSE_OPTION_BYTES + 192;

// Exact cancellation retains a canonical request for each of the four Calls.
// Includes length/Option alignment; this is protocol metadata, not body pools.
const OBSERVE_REQUEST_BUDGET: usize = 4 * (coaptic::app::OBSERVE_REQUEST_BYTES + 16);

// Two 9-byte optional tags and If-None-Match per Call, with alignment.
const RETAINED_CONDITIONS_BUDGET: usize = 4 * 24;
// Four three-state Observe format values, including potential alignment.
const OBSERVE_FORMAT_BUDGET: usize = 4 * 8;

fn assert_datagram_omits_assembled(
    datagram_app: usize,
    block_wise_app: usize,
    datagram_mem: usize,
    block_wise_mem: usize,
) {
    assert!(
        datagram_mem < block_wise_mem,
        "Memory body pools must add RAM ({datagram_mem} !< {block_wise_mem})"
    );
    assert!(
        datagram_app.saturating_sub(OBSERVE_REQUEST_BUDGET) < block_wise_mem,
        "datagram App ({datagram_app}), excluding explicit cancellation metadata, must not include WithBodies Memory ({block_wise_mem})"
    );
    let overhead = datagram_app.saturating_sub(datagram_mem);
    assert!(
        overhead
            < RESPONSE_BODY
                + RETAINED_QUERY_BUDGET
                + RETAINED_RESPONSE_BUDGET
                + OBSERVE_REQUEST_BUDGET
                + RETAINED_CONDITIONS_BUDGET
                + OBSERVE_FORMAT_BUDGET,
        "datagram App must not carry an assembled body beyond its bounded query/response/cancellation/condition metadata (App {datagram_app}, Memory {datagram_mem}, overhead {overhead})"
    );
    let mem_delta = block_wise_mem - datagram_mem;
    let app_delta = block_wise_app - datagram_app;
    assert!(
        app_delta >= mem_delta + RESPONSE_BODY,
        "block-wise App must include assembled hold beyond Memory body pools (App Δ {app_delta}, Memory Δ {mem_delta})"
    );
    let extra = app_delta - mem_delta;
    assert!(
        extra <= RESPONSE_BODY + ASSEMBLED_HOLD_PAD,
        "assembled hold extra {extra} exceeds RESPONSE_BODY + pad"
    );
}

#[test]
fn datagram_app_does_not_include_body_pools() {
    type Datagram = App<profiles::Default, ()>;
    type BlockWise = App<profiles::Default, (), DEFAULT_ROUTES, true>;

    let datagram_app = size_of::<Datagram>();
    let block_wise_app = size_of::<BlockWise>();
    let datagram_mem = size_of::<Memory<profiles::Default>>();
    let block_wise_mem = size_of::<Memory<profiles::Default, WithBodies<profiles::Default>>>();

    assert_datagram_omits_assembled(datagram_app, block_wise_app, datagram_mem, block_wise_mem);
}

#[test]
fn constrained_datagram_app_omits_body_pools() {
    type Datagram = App<profiles::Constrained, ()>;
    type BlockWise = App<profiles::Constrained, (), DEFAULT_ROUTES, true>;

    let datagram_app = size_of::<Datagram>();
    let block_wise_app = size_of::<BlockWise>();
    let datagram_mem = size_of::<Memory<profiles::Constrained>>();
    let block_wise_mem =
        size_of::<Memory<profiles::Constrained, WithBodies<profiles::Constrained>>>();

    assert_datagram_omits_assembled(datagram_app, block_wise_app, datagram_mem, block_wise_mem);
}

#[test]
fn memory_layout_selects_store() {
    fn assert_store<P: MemoryLayout<B>, const B: bool>() {}
    assert_store::<profiles::Default, false>();
    assert_store::<profiles::Default, true>();
    assert_eq!(
        size_of::<<profiles::Default as MemoryLayout<false>>::Store>(),
        size_of::<Memory<profiles::Default>>()
    );
    assert_eq!(
        size_of::<<profiles::Default as MemoryLayout<true>>::Store>(),
        size_of::<Memory<profiles::Default, WithBodies<profiles::Default>>>()
    );
}

#[test]
fn response_is_not_a_4kib_copy() {
    let n = size_of::<Response<'static>>();
    assert!(
        n < 768,
        "Response must not own [u8;4096] (got {n}; ~520 with inline 128 + location slices)"
    );
}

/// `/.well-known/core` catalog is poll stack ([`LinkFormatScratch`]), not a
/// field of [`App`] / [`Response`]. Default N=8 is ~192 bytes, not 4096.
#[test]
fn well_known_core_scratch_is_not_4kib() {
    const CAP: usize = link_format_capacity::<DEFAULT_ROUTES>();
    const _: () = assert!(CAP == DEFAULT_ROUTES * LINK_FORMAT_PER_ROUTE);
    const _: () = assert!(CAP == 192);

    let n = size_of::<LinkFormatScratch<DEFAULT_ROUTES>>();
    assert!(n >= CAP, "scratch {n} must hold catalog capacity {CAP}");
    assert!(
        n < RESPONSE_BODY / 8,
        "N={DEFAULT_ROUTES} scratch {n} should be ~{CAP}, not RESPONSE_BODY={RESPONSE_BODY}"
    );

    let floor = size_of::<LinkFormatScratch<1>>();
    assert!(
        floor >= 128,
        "N=1 scratch {floor} must hold the 128-byte floor"
    );
    assert!(floor < 256, "N=1 scratch {floor} should be ~128, not 4KiB");

    let n16 = size_of::<LinkFormatScratch<16>>();
    assert!(n16 >= link_format_capacity::<16>());
    assert!(
        n16 < RESPONSE_BODY / 4,
        "N=16 scratch {n16} should be ~384, not 4KiB"
    );
}

#[test]
fn block_request_identity_sidecar_has_an_explicit_bound() {
    use coaptic::storage::BlockTransfer;
    let bytes = size_of::<BlockTransfer>();
    println!(
        "BlockTransfer sidecar: {bytes} bytes; request identity budget: {}",
        BlockTransfer::REQUEST_IDENTITY_BYTES
    );
    assert!(bytes <= BlockTransfer::REQUEST_IDENTITY_BYTES + 192);
}

#[cfg(feature = "oscore")]
#[test]
fn protected_recovery_reference_has_a_fixed_sidecar_budget() {
    let bytes = size_of::<Option<(coaptic::message::Token, coaptic::oscore::RequestRef)>>();
    println!("protected recovery reference: {bytes} bytes per body sidecar");
    assert!(bytes <= 24);
}

#[test]
fn observe_format_retention_has_a_small_explicit_bound() {
    assert!(size_of::<Option<Option<coaptic::message::ContentFormat>>>() <= 4);
}

#[cfg(feature = "oscore")]
#[test]
fn observe_and_download_security_bindings_remain_bounded() {
    let bytes = size_of::<coaptic::oscore::SecurityContext>();
    println!("SecurityContext with four registration/download pairs: {bytes} bytes");
    assert!(size_of::<Option<coaptic::oscore::RequestRef>>() <= 16);
    assert!(
        bytes <= 512,
        "pairwise context exceeded its explicit binding budget: {bytes}"
    );
}
