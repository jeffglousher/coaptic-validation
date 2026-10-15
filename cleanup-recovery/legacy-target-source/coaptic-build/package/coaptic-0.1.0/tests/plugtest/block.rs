//! In-memory Engine-pair drivers for `TD_COAP_BLOCK_*` (classic Block, RFC 7959).

use coaptic::message::{BlockValue, Message, MessageId, Opt, OptionsBuilder, Token, Type};
use coaptic::storage::SlotId;
use coaptic::{Code, ContentFormat};

use crate::harness::{
    Pair, block_at, block_key, block_slice, code_continue, path_is, patterned_body,
};

const LARGE: usize = 320;
const SZX64: u16 = 64;
const SZX16: u16 = 16;

pub fn run(id: &str) {
    match id {
        "TD_COAP_BLOCK_01" => block2_early(SZX64, LARGE),
        "TD_COAP_BLOCK_02" => block2_late(SZX64, LARGE),
        "TD_COAP_BLOCK_03" => block1_put(SZX64, LARGE),
        "TD_COAP_BLOCK_04" => block1_post(SZX64, LARGE, false),
        "TD_COAP_BLOCK_05" => block1_post(SZX64, LARGE, true),
        "TD_COAP_BLOCK_06" => block2_early(SZX16, 80),
        other => panic!("unknown BLOCK id {other}"),
    }
}

fn block2_early(size: u16, body_len: usize) {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let want = patterned_body(body_len);
    let szx = BlockValue::from_size(0, false, size).expect("szx").szx();
    let first = block_at(0, false, size).encode();
    let extra = [Opt::block2(&first)];
    let (tx, _mid) =
        pair.client_request(Type::Confirmable, Code::GET, token, &["large"], &extra, &[]);
    let rx = pair.exchange_client(tx);
    let parsed = pair.server.decode_rx(rx).expect("decode GET");
    assert!(path_is(parsed, &["large"]));
    assert_eq!(parsed.block2().expect("Block2").expect("val").num(), 0);
    let key = block_key(token, pair.client_ep);
    let body_id = pair
        .server
        .start_block2(key, &want, szx)
        .expect("start Block2");
    let assembled = assemble_block2_to_client(&mut pair, body_id, token, rx, &want, size);
    assert_eq!(assembled, want);
}

fn block2_late(size: u16, body_len: usize) {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let want = patterned_body(body_len);
    let szx = BlockValue::from_size(0, false, size).expect("szx").szx();
    let (tx, _mid) = pair.client_request(Type::Confirmable, Code::GET, token, &["large"], &[], &[]);
    let rx = pair.exchange_client(tx);
    let parsed = pair.server.decode_rx(rx).expect("decode GET");
    assert!(
        parsed.block2().is_none(),
        "late negotiation: no Block2 on GET"
    );
    let key = block_key(token, pair.client_ep);
    let body_id = pair
        .server
        .start_block2(key, &want, szx)
        .expect("start Block2");
    let assembled = assemble_block2_to_client(&mut pair, body_id, token, rx, &want, size);
    assert_eq!(assembled, want);
}

fn assemble_block2_to_client(
    pair: &mut Pair,
    body_id: SlotId,
    token: Token,
    first_rx: SlotId,
    want: &[u8],
    size: u16,
) -> Vec<u8> {
    pair.server.release_rx(first_rx).ok();
    let blocks = want.len().div_ceil(usize::from(size)) as u32;
    for num in 0..blocks {
        let stx = pair.server.acquire_tx().expect("server TX");
        let issued = pair
            .server
            .encode_block2_tx(
                body_id,
                stx,
                Type::Acknowledgement,
                Code::CONTENT,
                pair.server_ids.next(),
            )
            .expect("encode Block2");
        let crx = pair.exchange_server(stx);
        let progress = pair
            .client
            .apply_block2_rx(crx)
            .unwrap_or_else(|e| panic!("apply Block2 NUM={num}: {e:?}"));
        let parsed = pair.client.decode_rx(crx).expect("client decode");
        assert_eq!(parsed.token(), token);
        assert_eq!(parsed.payload(), block_slice(want, num, size));
        assert_eq!(issued.block().num(), num);
        pair.client.release_rx(crx).ok();
        if progress.complete() {
            return pair
                .client
                .rx_body_payload(progress.id())
                .expect("complete body")
                .to_vec();
        }
        let next = block_at(num + 1, false, size).encode();
        let extra = [Opt::block2(&next)];
        let (tx, _) =
            pair.client_request(Type::Confirmable, Code::GET, token, &["large"], &extra, &[]);
        let rx = pair.exchange_client(tx);
        pair.server.release_rx(rx).ok();
    }
    panic!("Block2 transfer did not complete");
}

fn block1_put(size: u16, body_len: usize) {
    block1_request(
        size,
        body_len,
        Code::PUT,
        &["large-update"],
        Code::CHANGED,
        false,
    );
}

fn block1_post(size: u16, body_len: usize, two_way: bool) {
    block1_request(
        size,
        body_len,
        Code::POST,
        if two_way {
            &["large-post"]
        } else {
            &["large-create"]
        },
        if two_way {
            Code::CHANGED
        } else {
            Code::CREATED
        },
        two_way,
    );
}

fn block1_request(
    size: u16,
    body_len: usize,
    method: Code,
    path: &[&str],
    final_code: Code,
    two_way: bool,
) {
    let mut pair = Pair::new();
    let token = Pair::client_token(4);
    let want = patterned_body(body_len);
    let szx = BlockValue::from_size(0, false, size).expect("szx").szx();
    let key = block_key(token, pair.server_ep);
    let body_id = pair
        .client
        .start_block1(key, &want, szx)
        .expect("start Block1");
    let blocks = want.len().div_ceil(usize::from(size)) as u32;
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let mut last_complete = false;
    let mut last_id = None;
    for num in 0..blocks {
        let tx = pair.client.acquire_tx().expect("client TX");
        let issued = pair
            .client
            .encode_block1_tx(
                body_id,
                tx,
                Type::Confirmable,
                method,
                pair.client_ids.next(),
            )
            .expect("encode Block1");
        let (mid, blk, payload) = {
            let parsed = pair.client.decode_tx(tx).expect("decode issued");
            let mid = parsed.message_id();
            let blk = parsed.block1().expect("Block1").expect("val").encode();
            let payload = parsed.payload().to_vec();
            (mid, blk, payload)
        };
        let mut opts = OptionsBuilder::<8>::new();
        for seg in path {
            opts.push(Opt::uri_path(seg)).ok();
        }
        opts.push(Opt::content_format(&cf)).ok();
        opts.push(Opt::block1(&blk)).ok();
        let msg = Message::new(Type::Confirmable, method, mid)
            .with_token(token)
            .with_options(opts.as_slice())
            .with_payload(&payload);
        pair.client
            .encode_tx(tx, &msg)
            .expect("re-encode with path");
        pair.client.set_tx_endpoint(tx, pair.server_ep).ok();
        pair.client.record_request(tx, pair.server_ep).ok();
        let _ = pair
            .client
            .record_pending_con(tx, pair.server_ep, mid, pair.now_ms, 0);
        let rx = pair.exchange_client(tx);
        let progress = pair
            .server
            .apply_block1_rx(rx)
            .unwrap_or_else(|e| panic!("apply Block1 NUM={num}: {e:?}"));
        assert_eq!(issued.block().num(), num);
        let mid = pair.server.decode_rx(rx).expect("mid").message_id();
        let resp_code = if progress.complete() {
            final_code
        } else {
            code_continue()
        };
        let echo = block_at(num, !progress.complete(), size).encode();
        let extra = [Opt::block1(&echo)];
        let stx = pair.server_reply(Type::Acknowledgement, resp_code, mid, token, &extra, &[]);
        pair.server.release_rx(rx).ok();
        let crx = pair.exchange_server(stx);
        assert!(pair.client.match_response_rx(crx).expect("match").is_some());
        pair.client.release_rx(crx).ok();
        last_complete = progress.complete();
        last_id = Some(progress.id());
    }
    assert!(last_complete);
    if let Some(id) = last_id {
        assert_eq!(pair.server.rx_body_payload(id), Some(want.as_slice()));
    }
    if two_way {
        let resp_body = patterned_body(body_len);
        let assembled = pull_block2(&mut pair, token, &resp_body, size, path);
        assert_eq!(assembled, resp_body);
    }
}

fn pull_block2(pair: &mut Pair, token: Token, want: &[u8], size: u16, path: &[&str]) -> Vec<u8> {
    let blocks = want.len().div_ceil(usize::from(size)) as u32;
    let szx = BlockValue::from_size(0, false, size).expect("szx").szx();
    let key = block_key(token, pair.client_ep);
    let body_id = pair
        .server
        .start_block2(key, want, szx)
        .expect("start Block2");
    for num in 0..blocks {
        let stx = pair.server.acquire_tx().expect("TX");
        pair.server
            .encode_block2_tx(
                body_id,
                stx,
                Type::Acknowledgement,
                Code::CHANGED,
                MessageId::new(0xB200 + num as u16),
            )
            .expect("encode");
        let crx = pair.exchange_server(stx);
        let progress = pair.client.apply_block2_rx(crx).expect("apply");
        pair.client.release_rx(crx).ok();
        if progress.complete() {
            return pair
                .client
                .rx_body_payload(progress.id())
                .expect("body")
                .to_vec();
        }
        let next = block_at(num + 1, false, size).encode();
        let extra = [Opt::block2(&next)];
        let (tx, _) = pair.client_request(Type::Confirmable, Code::POST, token, path, &extra, &[]);
        let rx = pair.exchange_client(tx);
        pair.server.release_rx(rx).ok();
    }
    panic!("two-way Block2 did not complete")
}
