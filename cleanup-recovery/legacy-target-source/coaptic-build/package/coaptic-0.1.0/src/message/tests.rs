//! Library unit tests for RFC 7252 decode/encode. Not plugtest.

use super::value::{
    BlockValue, ContentFormat, MAX_AGE_DEFAULT, OBSERVE_DEREGISTER, OBSERVE_REGISTER, as_str,
    encode_block, encode_observe, encode_uint,
};
use super::{
    Code, EncodedUint, Ids, Message, MessageId, Opt, OptionNumber, OptionsBuilder, Token,
    Transmission, Type, decode, encode,
};
use crate::error::{EncodeError, OptionsFull, ParseError, SlotMessageError, ValueError};
use crate::profiles;
use crate::storage::MemoryProfile;
use crate::storage::{EngineBuilder, Memory, SlotError, SlotId, SlotPool};

fn encode_to<'a>(msg: &Message<'_>, buf: &'a mut [u8]) -> &'a [u8] {
    let n = encode(msg, buf).expect("encode");
    &buf[..n]
}

fn assert_roundtrip(msg: &Message<'_>) {
    let mut buf = [0u8; 1024];
    let n = encode(msg, &mut buf).expect("encode");
    let parsed = decode(&buf[..n]).expect("decode");
    assert_eq!(parsed.ty(), msg.ty());
    assert_eq!(parsed.code(), msg.code());
    assert_eq!(parsed.message_id(), msg.message_id());
    assert_eq!(parsed.token(), msg.token());
    assert_eq!(parsed.payload(), msg.payload());

    let mut expected = msg.options().iter();
    for opt in parsed.options() {
        let want = expected.next().expect("decoded extra option");
        assert_eq!(opt.number(), want.number());
        assert_eq!(opt.value(), want.value());
    }
    assert!(expected.next().is_none());

    let mut again = [0u8; 1024];
    let n2 = parsed.encode(&mut again).expect("re-encode");
    assert_eq!(&buf[..n], &again[..n2]);
}

#[test]
fn roundtrip_get_uri_path() {
    let opts = [Opt::new(OptionNumber::URI_PATH, b"temp")];
    let token = Token::new(&[0x21]).expect("token");
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(0x1234))
        .with_token(token)
        .with_options(&opts);
    assert_roundtrip(&msg);

    let mut buf = [0u8; 32];
    let bytes = encode_to(&msg, &mut buf);
    // ver=1 T=CON TKL=1 code=GET mid=0x1234 token=0x21 Uri-Path "temp"
    assert_eq!(
        bytes,
        &[0x41, 0x01, 0x12, 0x34, 0x21, 0xb4, b't', b'e', b'm', b'p']
    );
}

#[test]
fn roundtrip_post_with_payload() {
    let opts = [Opt::new(OptionNumber::CONTENT_FORMAT, &[])];
    let msg = Message::new(Type::NonConfirmable, Code::POST, MessageId::new(0x0001))
        .with_options(&opts)
        .with_payload(b"hi");
    assert_roundtrip(&msg);
    assert!(msg.code().is_request());
}

#[test]
fn roundtrip_empty_ack() {
    let msg = Message::empty_ack(MessageId::new(0x00ab));
    assert_roundtrip(&msg);
    let mut buf = [0u8; 8];
    assert_eq!(encode_to(&msg, &mut buf), &[0x60, 0x00, 0x00, 0xab]);
}

#[test]
fn roundtrip_empty_rst() {
    let msg = Message::empty_rst(MessageId::new(7));
    assert_roundtrip(&msg);
}

#[test]
fn empty_ack_rst_constructors_wire_bytes() {
    let mut buf = [0u8; 8];
    let ack = crate::message::empty_ack(MessageId::new(0x00ab));
    assert_eq!(ack.ty(), Type::Acknowledgement);
    assert!(ack.code().is_empty());
    assert_eq!(encode_to(&ack, &mut buf), &[0x60, 0x00, 0x00, 0xab]);
    let parsed = decode(&[0x60, 0x00, 0x00, 0xab]).expect("ack");
    assert!(parsed.is_empty_ack());
    assert!(parsed.is_empty_ack_or_rst());
    assert!(!parsed.is_empty_rst());

    let rst = crate::message::empty_rst(MessageId::new(7));
    assert_eq!(rst.ty(), Type::Reset);
    assert_eq!(encode_to(&rst, &mut buf), &[0x70, 0x00, 0x00, 0x07]);
    let parsed = decode(&[0x70, 0x00, 0x00, 0x07]).expect("rst");
    assert!(parsed.is_empty_rst());
    assert!(parsed.is_empty_ack_or_rst());
    assert!(!parsed.is_empty_ack());

    let get = Message::new(Type::Confirmable, Code::GET, MessageId::new(1));
    let n = encode(&get, &mut buf).expect("get");
    let parsed = decode(&buf[..n]).expect("get decode");
    assert!(!parsed.is_empty_ack_or_rst());
    assert!(!parsed.is_empty());
}

#[test]
fn roundtrip_extended_delta_and_length() {
    let thirteen = [b'x'; 13];
    let opts = [
        Opt::new(OptionNumber::URI_PATH, &thirteen),
        Opt::new(OptionNumber::SIZE1, &[0x10]),
        Opt::new(OptionNumber::new(269), b"z"),
    ];
    let msg = Message::new(Type::Confirmable, Code::PUT, MessageId::new(9)).with_options(&opts);
    assert_roundtrip(&msg);
}

#[test]
fn roundtrip_repeatable_uri_path() {
    let opts = [
        Opt::new(OptionNumber::URI_PATH, b"a"),
        Opt::new(OptionNumber::URI_PATH, b"b"),
    ];
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(1)).with_options(&opts);
    assert_roundtrip(&msg);
}

#[test]
fn payload_ff_inside_option_value_is_not_marker() {
    let opts = [Opt::new(OptionNumber::URI_PATH, &[0xff])];
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(2)).with_options(&opts);
    assert_roundtrip(&msg);
}

#[test]
fn reject_truncated_header() {
    assert_eq!(
        decode(&[0x40, 0x01, 0x00]),
        Err(ParseError::TruncatedHeader)
    );
    assert_eq!(decode(&[]), Err(ParseError::TruncatedHeader));
}

#[test]
fn reject_unsupported_version() {
    assert_eq!(
        decode(&[0x00, 0x01, 0x00, 0x01]),
        Err(ParseError::UnsupportedVersion)
    );
    assert_eq!(
        decode(&[0x80, 0x01, 0x00, 0x01]),
        Err(ParseError::UnsupportedVersion)
    );
}

#[test]
fn reject_bad_tkl() {
    // TKL 9, enough following bytes that only TKL is wrong.
    let mut buf = [0u8; 16];
    buf[0] = 0x49;
    buf[1] = 0x01;
    assert_eq!(decode(&buf), Err(ParseError::BadTokenLength));
}

#[test]
fn reject_truncated_token() {
    // TKL 2 but only one byte after the header.
    assert_eq!(
        decode(&[0x42, 0x01, 0x00, 0x01, 0xaa]),
        Err(ParseError::TruncatedToken)
    );
}

#[test]
fn accept_tkl_8() {
    let token = Token::new(&[1, 2, 3, 4, 5, 6, 7, 8]).expect("8-byte token");
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(1)).with_token(token);
    assert_roundtrip(&msg);
}

#[test]
fn reject_token_new_too_long() {
    assert!(Token::new(&[0; 9]).is_none());
}

#[test]
fn token_from_checked_is_infallible() {
    let t = Token::from_checked(&[1, 2, 3]);
    assert_eq!(t.as_bytes(), &[1, 2, 3]);
    let t8 = Token::from_checked(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(t8.len(), 8);
    let truncated = Token::from_checked(&[0; 9]);
    assert_eq!(truncated.len(), 8);
    assert_eq!(truncated.as_bytes(), &[0; 8]);
    assert_eq!(Token::from_checked(&[]), Token::EMPTY);
}

#[test]
fn ids_request_skeleton_roundtrip() {
    let mut ids = Ids::new(0x1234);
    let token = Token::mint(1, &[0x21]).expect("token");
    let msg = ids.con(Code::GET, token);
    assert_roundtrip(&msg);
    let mut buf = [0u8; 16];
    let bytes = encode_to(&msg, &mut buf);
    assert_eq!(bytes, &[0x41, 0x01, 0x12, 0x34, 0x21]);
    assert_eq!(ids.peek(), MessageId::new(0x1235));

    let non = Message::non(Code::POST, MessageId::new(1), Token::EMPTY);
    assert_roundtrip(&non);
    assert_eq!(MessageId::new(u16::MAX).wrapping_add(1), MessageId::new(0));
}

#[test]
fn reject_option_value_overflow() {
    // delta=11 length=4 but only two value bytes.
    assert_eq!(
        decode(&[0x40, 0x01, 0x00, 0x01, 0xb4, b'a', b'b']),
        Err(ParseError::TruncatedOption)
    );
}

#[test]
fn reject_option_number_overflow() {
    // Delta 14 + 0xFFFF => 269 + 65535, which does not fit in u16.
    assert_eq!(
        decode(&[0x40, 0x01, 0x00, 0x01, 0xe0, 0xff, 0xff]),
        Err(ParseError::OptionNumberOverflow)
    );
}

#[test]
fn reject_reserved_option_delta() {
    assert_eq!(
        decode(&[0x40, 0x01, 0x00, 0x01, 0xf0]),
        Err(ParseError::ReservedOptionDelta)
    );
}

#[test]
fn reject_reserved_option_length() {
    assert_eq!(
        decode(&[0x40, 0x01, 0x00, 0x01, 0x0f]),
        Err(ParseError::ReservedOptionLength)
    );
}

#[test]
fn reject_truncated_extended_delta() {
    assert_eq!(
        decode(&[0x40, 0x01, 0x00, 0x01, 0xd0]),
        Err(ParseError::TruncatedOption)
    );
}

#[test]
fn reject_payload_marker_without_payload() {
    assert_eq!(
        decode(&[0x40, 0x01, 0x00, 0x01, 0xff]),
        Err(ParseError::PayloadMarkerWithoutPayload)
    );
}

#[test]
fn reject_empty_message_with_extra_bytes() {
    assert_eq!(
        decode(&[0x60, 0x00, 0x00, 0x01, 0x00]),
        Err(ParseError::EmptyMessageNotEmpty)
    );
}

#[test]
fn reject_empty_message_with_token() {
    assert_eq!(
        decode(&[0x61, 0x00, 0x00, 0x01, 0xaa]),
        Err(ParseError::EmptyMessageNotEmpty)
    );
}

#[test]
fn encode_empty_with_payload_fails() {
    let msg =
        Message::new(Type::Acknowledgement, Code::EMPTY, MessageId::new(1)).with_payload(b"x");
    let mut buf = [0u8; 16];
    assert_eq!(
        encode(&msg, &mut buf),
        Err(EncodeError::EmptyMessageNotEmpty)
    );
}

#[test]
fn encode_options_must_ascend() {
    let opts = [
        Opt::new(OptionNumber::URI_PATH, b"a"),
        Opt::new(OptionNumber::IF_MATCH, b""),
    ];
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(1)).with_options(&opts);
    let mut buf = [0u8; 32];
    assert_eq!(
        encode(&msg, &mut buf),
        Err(EncodeError::OptionsNotAscending)
    );
}

#[test]
fn encode_buffer_too_small() {
    let msg = Message::new(Type::Acknowledgement, Code::EMPTY, MessageId::new(1));
    let mut buf = [0u8; 3];
    assert_eq!(encode(&msg, &mut buf), Err(EncodeError::BufferTooSmall));
}

#[test]
fn encode_options_full_is_distinct_from_not_ascending() {
    assert_ne!(EncodeError::OptionsFull, EncodeError::OptionsNotAscending);
}

#[test]
fn unrecognized_critical_is_structured_not_policy() {
    // Block2 is critical and not in RFC 7252 Table 4.
    // Decode accepts it as opaque; check_rfc7252_options reports it.
    let opts = [Opt::new(OptionNumber::BLOCK2, &[0x02])];
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(3)).with_options(&opts);
    let mut buf = [0u8; 32];
    let bytes = encode_to(&msg, &mut buf);
    let parsed = decode(bytes).expect("opaque parse");
    assert!(!OptionNumber::BLOCK2.is_rfc7252());
    assert!(OptionNumber::BLOCK2.is_critical());
    assert!(OptionNumber::BLOCK2.is_known());
    assert_eq!(parsed.unrecognized_critical(), Some(OptionNumber::BLOCK2));
    assert_eq!(parsed.unknown_critical(), None);
    assert_eq!(
        parsed.check_rfc7252_options(),
        Err(ParseError::UnrecognizedCritical(OptionNumber::BLOCK2))
    );

    // Observe (6) is elective and not in RFC 7252 Table 4; not reported.
    let opts = [Opt::observe_register()];
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(4)).with_options(&opts);
    let bytes = encode_to(&msg, &mut buf);
    let parsed = decode(bytes).expect("opaque parse");
    assert!(!OptionNumber::OBSERVE.is_rfc7252());
    assert!(!OptionNumber::OBSERVE.is_critical());
    assert!(OptionNumber::OBSERVE.is_known());
    assert_eq!(parsed.unrecognized_critical(), None);
    assert_eq!(parsed.unknown_critical(), None);
    parsed.check_rfc7252_options().expect("elective Observe");
    parsed.check_rfc7252_formats().expect("not Table 4");

    // IANA experimental 65001 is odd ⇒ critical and not in the known stack.
    let opts = [Opt::new(OptionNumber::new(65001), &[])];
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(5)).with_options(&opts);
    let bytes = encode_to(&msg, &mut buf);
    let parsed = decode(bytes).expect("opaque parse");
    assert!(OptionNumber::new(65001).is_critical());
    assert!(!OptionNumber::new(65001).is_known());
    assert_eq!(
        parsed.unrecognized_critical(),
        Some(OptionNumber::new(65001))
    );
    assert_eq!(parsed.unknown_critical(), Some(OptionNumber::new(65001)));
    // 65000 is even ⇒ elective; decode accepts it, neither check reports it.
    let opts = [Opt::new(OptionNumber::new(65000), &[])];
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(6)).with_options(&opts);
    let bytes = encode_to(&msg, &mut buf);
    let parsed = decode(bytes).expect("opaque parse");
    assert!(!OptionNumber::new(65000).is_critical());
    assert!(!OptionNumber::new(65000).is_known());
    assert_eq!(parsed.unrecognized_critical(), None);
    assert_eq!(parsed.unknown_critical(), None);
}

#[test]
fn code_helpers() {
    assert!(Code::GET.is_request());
    assert!(!Code::GET.is_response());
    assert!(Code::CONTENT.is_success());
    assert!(Code::NOT_FOUND.is_client_error());
    assert!(Code::INTERNAL_SERVER_ERROR.is_server_error());
    assert!(Code::CONTENT.is_response());
    assert_eq!(Code::from_class_detail(2, 5), Some(Code::CONTENT));
    assert_eq!(Code::from_class_detail(2, 31), Some(Code::CONTINUE));
    assert_eq!(
        Code::from_class_detail(4, 8),
        Some(Code::REQUEST_ENTITY_INCOMPLETE)
    );
    assert!(Code::CONTINUE.is_success());
    assert!(Code::REQUEST_ENTITY_INCOMPLETE.is_client_error());
    assert_eq!(
        crate::message::ObserveTransmission::CONFIRM_INTERVAL_MS,
        24 * 60 * 60 * 1_000
    );
    assert_eq!(crate::message::ObserveTransmission::NON_TIMEOUT_MS, 3_000);
    assert_eq!(
        crate::message::QBlockTransmission::NON_TIMEOUT_MS,
        crate::message::Transmission::ACK_TIMEOUT_MS
    );
    assert_eq!(
        crate::message::QBlockTransmission::NON_RECEIVE_TIMEOUT_MS,
        4_000
    );
    assert_eq!(
        crate::message::QBlockTransmission::NON_MAX_RETRANSMIT,
        crate::message::Transmission::MAX_RETRANSMIT
    );
    assert_eq!((Code::GET.class(), Code::GET.detail()), (0, 1));
    assert_eq!(Type::Confirmable.to_bits(), 0);
    assert_eq!(Type::from_bits(2), Some(Type::Acknowledgement));
    assert!(Code::FETCH.is_request());
    assert!(Code::FETCH.is_safe());
    assert!(Code::FETCH.is_idempotent());
    assert!(Code::PATCH.is_request());
    assert!(!Code::PATCH.is_safe());
    assert!(!Code::PATCH.is_idempotent());
    assert!(Code::IPATCH.is_request());
    assert!(!Code::IPATCH.is_safe());
    assert!(Code::IPATCH.is_idempotent());
    assert!(Code::PUT.is_idempotent());
    assert!(!Code::PUT.is_safe());
    assert!(Code::DELETE.is_idempotent());
    assert!(!Code::POST.is_safe());
    assert!(!Code::POST.is_idempotent());
    assert!(!Code::CONTENT.is_safe());
    assert!(!Code::CONTENT.is_idempotent());
    assert_eq!(Code::from_class_detail(0, 5), Some(Code::FETCH));
    assert_eq!(Code::from_class_detail(0, 6), Some(Code::PATCH));
    assert_eq!(Code::from_class_detail(0, 7), Some(Code::IPATCH));
    assert_eq!(Code::from_class_detail(4, 9), Some(Code::CONFLICT));
    assert_eq!(
        Code::from_class_detail(4, 22),
        Some(Code::UNPROCESSABLE_ENTITY)
    );
    assert_eq!(Code::from_class_detail(5, 8), Some(Code::HOP_LIMIT_REACHED));
    assert!(Code::CONFLICT.is_client_error());
    assert!(Code::UNPROCESSABLE_ENTITY.is_client_error());
    assert!(Code::HOP_LIMIT_REACHED.is_server_error());
}

#[test]
fn decode_from_datagram_pool_slot() {
    let mut engine = EngineBuilder::new()
        .profile::<profiles::Default>()
        .block_wise(false)
        .build(Memory::<profiles::Default>::new())
        .expect("storage build");

    let id = engine.acquire_rx().expect("rx slot");
    let opts = [Opt::new(OptionNumber::URI_PATH, b"slot")];
    let msg =
        Message::new(Type::Confirmable, Code::GET, MessageId::new(0x2222)).with_options(&opts);

    let n = {
        let slot = engine
            .storage_mut()
            .rx_datagram_mut()
            .payload_mut(id)
            .expect("occupied");
        encode(&msg, slot).expect("encode into slot")
    };
    engine
        .storage_mut()
        .rx_datagram_mut()
        .set_len(id, n)
        .expect("set_len");

    let bytes = engine.storage().rx_datagram().payload(id).expect("filled");
    let parsed = decode(bytes).expect("decode slot bytes");
    assert_eq!(parsed.code(), Code::GET);
    assert_eq!(parsed.message_id(), MessageId::new(0x2222));
    let opt = parsed.options().next().expect("Uri-Path");
    assert_eq!(opt.number(), OptionNumber::URI_PATH);
    assert_eq!(opt.value(), b"slot");
    assert!(engine.storage().rx_datagram().slot_count() >= 1);
}

#[test]
fn default_datagram_slot_is_1472() {
    assert_eq!(profiles::Default::RX_DATAGRAM_BYTES, 1472);
}

fn parse_opts(opts: &[Opt<'_>]) -> (usize, [u8; 256]) {
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(1)).with_options(opts);
    let mut buf = [0u8; 256];
    let n = encode(&msg, &mut buf).expect("encode");
    (n, buf)
}

#[test]
fn observe_option_roundtrip_register_deregister_and_sequence() {
    let register = [Opt::observe_register()];
    let (n, buf) = parse_opts(&register);
    let parsed = decode(&buf[..n]).expect("register decode");
    assert_eq!(parsed.observe(), Some(Ok(OBSERVE_REGISTER)));
    assert!(parsed.is_observe_register());
    assert!(!parsed.is_observe_deregister());
    parsed.check_rfc7252_options().expect("elective");
    parsed.check_rfc7252_formats().expect("not Table 4");

    let mut again = [0u8; 256];
    let n2 = parsed.encode(&mut again).expect("re-encode");
    assert_eq!(&buf[..n], &again[..n2]);

    let deregister = [Opt::observe_deregister()];
    let (n, buf) = parse_opts(&deregister);
    let parsed = decode(&buf[..n]).expect("deregister decode");
    assert_eq!(parsed.observe(), Some(Ok(OBSERVE_DEREGISTER)));
    assert!(parsed.is_observe_deregister());
    assert!(!parsed.is_observe_register());

    let seq = encode_observe(0x010203);
    let notify = [Opt::observe(&seq)];
    let msg =
        Message::new(Type::Confirmable, Code::CONTENT, MessageId::new(1)).with_options(&notify);
    let mut buf = [0u8; 256];
    let n = encode(&msg, &mut buf).expect("encode notify");
    let parsed = decode(&buf[..n]).expect("notify decode");
    assert_eq!(parsed.observe(), Some(Ok(0x010203)));
    assert!(!parsed.is_observe_register());
    assert!(!parsed.is_observe_deregister());

    let zero_seq = encode_observe(0);
    let notify0 = [Opt::observe(&zero_seq)];
    let msg =
        Message::new(Type::NonConfirmable, Code::CONTENT, MessageId::new(2)).with_options(&notify0);
    let n = encode(&msg, &mut buf).expect("encode seq 0");
    let parsed = decode(&buf[..n]).expect("seq 0");
    assert_eq!(parsed.observe(), Some(Ok(0)));
    assert!(!parsed.is_observe_register());
}

#[test]
fn fetch_observe_register_and_deregister() {
    let register = [Opt::observe_register()];
    let msg =
        Message::new(Type::Confirmable, Code::FETCH, MessageId::new(1)).with_options(&register);
    let mut buf = [0u8; 256];
    let n = encode(&msg, &mut buf).expect("encode");
    let parsed = decode(&buf[..n]).expect("decode");
    assert!(parsed.is_observe_register());
    assert!(!parsed.is_observe_deregister());

    let deregister = [Opt::observe_deregister()];
    let msg =
        Message::new(Type::Confirmable, Code::FETCH, MessageId::new(2)).with_options(&deregister);
    let n = encode(&msg, &mut buf).expect("encode");
    let parsed = decode(&buf[..n]).expect("decode");
    assert!(parsed.is_observe_deregister());
    assert!(!parsed.is_observe_register());

    let msg =
        Message::new(Type::Confirmable, Code::POST, MessageId::new(3)).with_options(&register);
    let n = encode(&msg, &mut buf).expect("encode");
    let parsed = decode(&buf[..n]).expect("decode");
    assert!(!parsed.is_observe_register());
}

#[test]
fn block_options_roundtrip_szx_more_and_qblock() {
    let block2 = encode_block(BlockValue::from_size(0, true, 1024).expect("szx 6"));
    let block1 = encode_block(BlockValue::new(2, false, 3).expect("szx 3"));
    let size2 = encode_uint(4096);
    let q1 = encode_block(BlockValue::new(1, true, 0).expect("q1"));
    let q2a = encode_block(BlockValue::new(0, true, 2).expect("q2a"));
    let q2b = encode_block(BlockValue::new(1, false, 2).expect("q2b"));
    let opts = [
        Opt::uri_path("large"),
        Opt::q_block1(&q1),
        Opt::block2(&block2),
        Opt::block1(&block1),
        Opt::size2(&size2),
        Opt::q_block2(&q2a),
        Opt::q_block2(&q2b),
    ];
    let (n, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..n]).expect("decode");

    assert_eq!(
        parsed.block2(),
        Some(Ok(BlockValue::from_size(0, true, 1024).expect("want 1024")))
    );
    assert_eq!(
        parsed.block1(),
        Some(Ok(BlockValue::new(2, false, 3).expect("want 128")))
    );
    assert_eq!(parsed.size2(), Some(Ok(4096)));
    assert_eq!(
        parsed.q_block1(),
        Some(Ok(BlockValue::new(1, true, 0).expect("q1")))
    );
    let q2: [BlockValue; 2] = {
        let mut out = [BlockValue::new(0, false, 0).expect("z"); 2];
        let mut i = 0;
        for v in parsed.q_block2() {
            out[i] = v.expect("q2");
            i += 1;
        }
        assert_eq!(i, 2);
        out
    };
    assert_eq!(q2[0], BlockValue::new(0, true, 2).expect("q2a"));
    assert_eq!(q2[1], BlockValue::new(1, false, 2).expect("q2b"));
    assert_eq!(parsed.uri_path().next(), Some(Ok("large")));

    parsed.check_rfc7252_formats().expect("not Table 4");
    assert_eq!(
        parsed.check_rfc7252_options(),
        Err(ParseError::UnrecognizedCritical(OptionNumber::Q_BLOCK1))
    );

    let mut again = [0u8; 256];
    let n2 = parsed.encode(&mut again).expect("re-encode");
    assert_eq!(&buf[..n], &again[..n2]);
}

#[test]
fn block_options_builder_sorts_with_table4() {
    let blk = encode_block(BlockValue::new(0, false, 6).expect("1024"));
    let size2 = encode_uint(2048);
    let mut opts = OptionsBuilder::<4>::new();
    opts.push(Opt::size2(&size2)).expect("size2");
    opts.push(Opt::uri_path("b")).expect("path");
    opts.push(Opt::block2(&blk)).expect("block2");
    opts.push(Opt::size1(&size2)).expect("size1");

    let numbers: [OptionNumber; 4] = [
        opts.as_slice()[0].number(),
        opts.as_slice()[1].number(),
        opts.as_slice()[2].number(),
        opts.as_slice()[3].number(),
    ];
    assert_eq!(
        numbers,
        [
            OptionNumber::URI_PATH,
            OptionNumber::BLOCK2,
            OptionNumber::SIZE2,
            OptionNumber::SIZE1,
        ]
    );

    let msg =
        Message::new(Type::Confirmable, Code::GET, MessageId::new(1)).with_options(opts.as_slice());
    assert_roundtrip(&msg);
}

#[test]
fn helpers_roundtrip_uri_path_segments() {
    let opts = [Opt::uri_path("sensors"), Opt::uri_path("temp")];
    let (n, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..n]).expect("decode");
    let mut got = ["", ""];
    let mut i = 0;
    for seg in parsed.uri_path() {
        got[i] = seg.expect("utf-8");
        i += 1;
    }
    assert_eq!(&got[..i], &["sensors", "temp"]);
    parsed.check_rfc7252_formats().expect("formats");
}

#[test]
fn helpers_content_format_examples() {
    for (cf, raw) in [
        (ContentFormat::TEXT_PLAIN, &[] as &[u8]),
        (ContentFormat::LINK_FORMAT, &[40u8] as &[u8]),
        (ContentFormat::JSON, &[50u8] as &[u8]),
        (ContentFormat::OCTET_STREAM, &[42u8] as &[u8]),
        (ContentFormat::PROBLEM_DETAILS, &[1u8, 1] as &[u8]),
        (ContentFormat::MISSING_BLOCKS, &[1u8, 16] as &[u8]),
    ] {
        let encoded = cf.encode();
        assert_eq!(encoded.as_bytes(), raw);
        let opts = [Opt::content_format(&encoded)];
        let (n, buf) = parse_opts(&opts);
        let parsed = decode(&buf[..n]).expect("decode");
        assert_eq!(parsed.content_format(), Some(Ok(cf)));
        parsed.check_rfc7252_formats().expect("formats");
    }
}

#[test]
fn empty_vs_missing_if_none_match_and_max_age() {
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(1));
    let (n, buf) = {
        let mut buf = [0u8; 32];
        let n = encode(&msg, &mut buf).expect("encode");
        (n, buf)
    };
    let parsed = decode(&buf[..n]).expect("decode");
    assert!(!parsed.if_none_match());
    assert!(parsed.max_age().is_none());
    assert_eq!(MAX_AGE_DEFAULT, 60);

    let zero = encode_uint(0);
    let opts = [Opt::if_none_match(), Opt::max_age(&zero)];
    let (n, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..n]).expect("decode");
    assert!(parsed.if_none_match());
    assert_eq!(parsed.max_age(), Some(Ok(0)));
    let inm = parsed
        .get_option(OptionNumber::IF_NONE_MATCH)
        .expect("present");
    assert!(inm.is_empty_value());
    parsed.check_rfc7252_formats().expect("formats");
}

#[test]
fn uint_helpers_uri_port_accept_size1() {
    let port = encode_uint(5683);
    let accept = ContentFormat::JSON.encode();
    let size = encode_uint(4096);
    let opts = [
        Opt::uri_port(&port),
        Opt::accept(&accept),
        Opt::size1(&size),
    ];
    let (n, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..n]).expect("decode");
    assert_eq!(parsed.uri_port(), Some(Ok(5683)));
    assert_eq!(parsed.accept(), Some(Ok(ContentFormat::JSON)));
    assert_eq!(parsed.size1(), Some(Ok(4096)));
}

#[test]
fn uint_helpers_size2() {
    let size = encode_uint(0);
    let opts = [Opt::size2(&size)];
    let (n, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..n]).expect("decode");
    assert_eq!(parsed.size2(), Some(Ok(0)));
    assert!(!OptionNumber::SIZE2.is_rfc7252());
    parsed.check_rfc7252_options().expect("elective Size2");
    parsed.check_rfc7252_formats().expect("not Table 4");
}

#[test]
fn opaque_if_match_and_etag() {
    let opts = [Opt::if_match(b""), Opt::etag(b"abc")];
    let (n, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..n]).expect("decode");
    let matches: [&[u8]; 1] = {
        let mut out = [&b""[..]; 1];
        let mut i = 0;
        for v in parsed.if_match() {
            out[i] = v;
            i += 1;
        }
        assert_eq!(i, 1);
        out
    };
    assert_eq!(matches[0], b"");
    let tags: [&[u8]; 1] = {
        let mut out = [&b""[..]; 1];
        let mut i = 0;
        for v in parsed.etag() {
            out[i] = v;
            i += 1;
        }
        assert_eq!(i, 1);
        out
    };
    assert_eq!(tags[0], b"abc");
    parsed.check_rfc7252_formats().expect("formats");
}

#[test]
fn request_tag_is_opaque_and_not_rfc7252() {
    let opts = [Opt::request_tag(b"rt1"), Opt::request_tag(&[])];
    let (n, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..n]).expect("decode");
    let tags: [&[u8]; 2] = {
        let mut out = [&b""[..]; 2];
        let mut i = 0;
        for v in parsed.request_tag() {
            out[i] = v;
            i += 1;
        }
        assert_eq!(i, 2);
        out
    };
    assert_eq!(tags[0], b"rt1");
    assert_eq!(tags[1], b"");
    assert!(!OptionNumber::REQUEST_TAG.is_rfc7252());
    parsed
        .check_rfc7252_options()
        .expect("elective Request-Tag");
    parsed.check_rfc7252_formats().expect("not Table 4");
}

#[test]
fn echo_is_opaque_and_not_rfc7252() {
    let opts = [Opt::echo(b"fresh")];
    let (n, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..n]).expect("decode");
    assert_eq!(parsed.echo(), Some(&b"fresh"[..]));
    assert!(!OptionNumber::ECHO.is_rfc7252());
    assert!(!OptionNumber::ECHO.is_critical());
    assert!(OptionNumber::ECHO.is_no_cache_key());
    parsed.check_rfc7252_options().expect("elective Echo");
    parsed.check_rfc7252_formats().expect("not Table 4");

    let empty = [Opt::echo(b"")];
    let (n, buf) = parse_opts(&empty);
    let parsed = decode(&buf[..n]).expect("wire decode");
    assert_eq!(parsed.echo(), Some(&b""[..]));
    assert_eq!(
        crate::message::Echo::from_message(&parsed),
        Err(ValueError::EchoLength)
    );

    let long = [0u8; 40];
    let opts = [Opt::echo(&long)];
    let (n, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..n]).expect("40");
    assert_eq!(parsed.echo(), Some(&long[..]));
    assert_eq!(
        crate::message::Echo::from_message(&parsed)
            .expect("ok")
            .expect("present")
            .as_slice(),
        &long
    );

    let size = encode_uint(8);
    let after_size1 = [Opt::size1(&size), Opt::echo(b"ab")];
    let (n, buf) = parse_opts(&after_size1);
    let parsed = decode(&buf[..n]).expect("delta");
    assert_eq!(parsed.size1(), Some(Ok(8)));
    assert_eq!(parsed.echo(), Some(&b"ab"[..]));
}

#[test]
fn string_helpers_host_query_location_proxy() {
    let opts = [
        Opt::uri_host("example.com"),
        Opt::location_path("loc"),
        Opt::uri_path("a"),
        Opt::uri_query("k=v"),
        Opt::location_query("q=1"),
        Opt::proxy_uri("coap://example.com/x"),
        Opt::proxy_scheme("coap"),
    ];
    let (n, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..n]).expect("decode");
    assert_eq!(parsed.uri_host(), Some(Ok("example.com")));
    assert_eq!(parsed.uri_query().next(), Some(Ok("k=v")));
    assert_eq!(parsed.location_path().next(), Some(Ok("loc")));
    assert_eq!(parsed.location_query().next(), Some(Ok("q=1")));
    assert_eq!(parsed.proxy_uri(), Some(Ok("coap://example.com/x")));
    assert_eq!(parsed.proxy_scheme(), Some(Ok("coap")));
}

#[test]
fn reject_bad_utf8_on_string_helpers() {
    let opts = [Opt::new(OptionNumber::URI_PATH, &[0xff, 0xfe])];
    let (n, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..n]).expect("opaque decode still works");
    assert_eq!(parsed.uri_path().next(), Some(Err(ValueError::InvalidUtf8)));
    assert_eq!(as_str(&[0xff]), Err(ValueError::InvalidUtf8));
}

#[test]
fn format_check_rejects_known_wrong_format_not_policy() {
    let bad_path = [Opt::new(OptionNumber::URI_PATH, &[0xff])];
    let (n, buf) = parse_opts(&bad_path);
    let parsed = decode(&buf[..n]).expect("opaque decode");
    parsed.check_rfc7252_options().expect("known option");
    assert_eq!(
        parsed.check_rfc7252_formats(),
        Err(ParseError::BadOptionFormat(OptionNumber::URI_PATH))
    );

    let long_cf = [Opt::new(OptionNumber::CONTENT_FORMAT, &[0, 0, 50])];
    let (n, buf) = parse_opts(&long_cf);
    let parsed = decode(&buf[..n]).expect("opaque decode");
    assert_eq!(parsed.content_format(), Some(Ok(ContentFormat::JSON)));
    assert_eq!(
        parsed.check_rfc7252_formats(),
        Err(ParseError::BadOptionFormat(OptionNumber::CONTENT_FORMAT))
    );

    let nonempty_inm = [Opt::new(OptionNumber::IF_NONE_MATCH, b"x")];
    let (n, buf) = parse_opts(&nonempty_inm);
    let parsed = decode(&buf[..n]).expect("opaque decode");
    assert!(parsed.if_none_match());
    assert_eq!(
        parsed.check_rfc7252_formats(),
        Err(ParseError::BadOptionFormat(OptionNumber::IF_NONE_MATCH))
    );

    let empty_etag = [Opt::etag(b"")];
    let (n, buf) = parse_opts(&empty_etag);
    let parsed = decode(&buf[..n]).expect("opaque decode");
    assert_eq!(
        parsed.check_rfc7252_formats(),
        Err(ParseError::BadOptionFormat(OptionNumber::ETAG))
    );

    let empty_host = [Opt::uri_host("")];
    let (n, buf) = parse_opts(&empty_host);
    let parsed = decode(&buf[..n]).expect("opaque decode");
    assert_eq!(
        parsed.check_rfc7252_formats(),
        Err(ParseError::BadOptionFormat(OptionNumber::URI_HOST))
    );
}

#[test]
fn format_check_ignores_unknown_and_accepts_leading_zero_uint() {
    let padded = EncodedUint::new(50);
    assert_eq!(padded.as_bytes(), &[50]);
    let opts = [
        Opt::new(OptionNumber::CONTENT_FORMAT, &[0, 50]),
        Opt::new(OptionNumber::new(23), &[0x02]),
    ];
    let (n, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..n]).expect("decode");
    parsed.check_rfc7252_formats().expect("length 2 is legal");
    assert_eq!(
        parsed.check_rfc7252_options(),
        Err(ParseError::UnrecognizedCritical(OptionNumber::new(23)))
    );
}

#[test]
fn generic_format_constructors_and_opt_accessors() {
    let n = encode_uint(14);
    let opts = [
        Opt::opaque(OptionNumber::ETAG, b"tag"),
        Opt::empty(OptionNumber::IF_NONE_MATCH),
        Opt::string(OptionNumber::URI_PATH, "x"),
        Opt::uint(OptionNumber::MAX_AGE, &n),
    ];
    let (len, buf) = parse_opts(&opts);
    let parsed = decode(&buf[..len]).expect("decode");
    let path = parsed.get_option(OptionNumber::URI_PATH).expect("path");
    assert_eq!(path.as_str(), Ok("x"));
    let age = parsed.get_option(OptionNumber::MAX_AGE).expect("age");
    assert_eq!(age.as_uint(), Ok(14));
    parsed.check_rfc7252_formats().expect("formats");
}

#[test]
fn helpers_compose_with_engine_datagram_slot() {
    let mut engine = EngineBuilder::new()
        .profile::<profiles::Default>()
        .block_wise(false)
        .build(Memory::<profiles::Default>::new())
        .expect("storage build");

    let id = engine.acquire_rx().expect("rx slot");
    let cf = ContentFormat::JSON.encode();
    let mut opts = OptionsBuilder::<2>::new();
    opts.push(Opt::content_format(&cf)).expect("cf");
    opts.push(Opt::uri_path("slot")).expect("path");
    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(0x3333))
        .with_options(opts.as_slice());

    engine.encode_rx(id, &msg).expect("encode into rx slot");
    let parsed = engine.decode_rx(id).expect("decode slot bytes");
    assert_eq!(parsed.uri_path().next(), Some(Ok("slot")));
    assert_eq!(parsed.content_format(), Some(Ok(ContentFormat::JSON)));
    parsed.check_rfc7252_options().expect("known options");
    parsed.check_rfc7252_formats().expect("formats");
}

#[test]
fn options_builder_out_of_order_roundtrip() {
    let cf = ContentFormat::TEXT_PLAIN.encode();
    let mut opts = OptionsBuilder::<4>::new();
    opts.push(Opt::uri_query("q=1")).expect("query");
    opts.push(Opt::uri_path("sensors")).expect("seg0");
    opts.push(Opt::content_format(&cf)).expect("cf");
    opts.push(Opt::uri_path("temp")).expect("seg1");

    assert_eq!(
        [
            opts.as_slice()[0].number(),
            opts.as_slice()[1].number(),
            opts.as_slice()[2].number(),
            opts.as_slice()[3].number(),
        ],
        [
            OptionNumber::URI_PATH,
            OptionNumber::URI_PATH,
            OptionNumber::CONTENT_FORMAT,
            OptionNumber::URI_QUERY,
        ]
    );
    assert_eq!(opts.as_slice()[0].as_str(), Ok("sensors"));
    assert_eq!(opts.as_slice()[1].as_str(), Ok("temp"));

    let msg = Message::new(Type::Confirmable, Code::GET, MessageId::new(0x42))
        .with_options(opts.as_slice());
    assert_roundtrip(&msg);

    let mut buf = [0u8; 64];
    let n = encode(&msg, &mut buf).expect("encode");
    let parsed = decode(&buf[..n]).expect("decode");
    let mut path = parsed.uri_path();
    assert_eq!(path.next(), Some(Ok("sensors")));
    assert_eq!(path.next(), Some(Ok("temp")));
    assert_eq!(parsed.content_format(), Some(Ok(ContentFormat::TEXT_PLAIN)));
    assert_eq!(parsed.uri_query().next(), Some(Ok("q=1")));
}

#[test]
fn options_builder_capacity_full() {
    let mut opts = OptionsBuilder::<2>::new();
    opts.push(Opt::uri_path("a")).expect("a");
    opts.push(Opt::uri_path("b")).expect("b");
    assert_eq!(opts.push(Opt::uri_path("c")).err(), Some(OptionsFull));
}

#[test]
fn encode_tx_slot_and_decode_back() {
    let mut engine = EngineBuilder::new()
        .profile::<profiles::Default>()
        .block_wise(false)
        .build(Memory::<profiles::Default>::new())
        .expect("storage build");

    let id = engine.acquire_tx().expect("tx slot");
    let cf = ContentFormat::JSON.encode();
    let mut opts = OptionsBuilder::<3>::new();
    opts.push(Opt::content_format(&cf)).expect("cf");
    opts.push(Opt::uri_path("temp")).expect("path");
    let token = Token::new(&[0xaa, 0xbb]).expect("token");
    let msg = Message::new(Type::NonConfirmable, Code::PUT, MessageId::new(0x1111))
        .with_token(token)
        .with_options(opts.as_slice())
        .with_payload(b"{}");

    let n = engine.encode_tx(id, &msg).expect("encode tx");
    assert!(n > 4);
    assert_eq!(
        engine
            .storage()
            .tx_datagram()
            .payload(id)
            .expect("len")
            .len(),
        n
    );

    let parsed = engine.decode_tx(id).expect("decode tx");
    assert_eq!(parsed.ty(), Type::NonConfirmable);
    assert_eq!(parsed.code(), Code::PUT);
    assert_eq!(parsed.message_id(), MessageId::new(0x1111));
    assert_eq!(parsed.token(), token);
    assert_eq!(parsed.payload(), b"{}");
    assert_eq!(parsed.uri_path().next(), Some(Ok("temp")));
    assert_eq!(parsed.content_format(), Some(Ok(ContentFormat::JSON)));
    parsed.check_rfc7252_formats().expect("formats");
}

#[test]
fn slot_glue_rejects_free_slot() {
    let mut engine = EngineBuilder::new()
        .profile::<profiles::Default>()
        .block_wise(false)
        .build(Memory::<profiles::Default>::new())
        .expect("storage build");

    let id = SlotId::from_index(0);
    assert_eq!(
        engine.decode_rx(id).unwrap_err(),
        SlotMessageError::Slot(SlotError::NotOccupied)
    );
    let msg = Message::new(Type::Acknowledgement, Code::EMPTY, MessageId::new(1));
    assert_eq!(
        engine.encode_tx(id, &msg).unwrap_err(),
        SlotMessageError::Slot(SlotError::NotOccupied)
    );
}

#[test]
fn transmission_initial_timeout_clamps_jitter() {
    assert_eq!(
        Transmission::initial_timeout_ms(0),
        Transmission::ACK_TIMEOUT_MS
    );
    assert_eq!(
        Transmission::initial_timeout_ms(500),
        Transmission::ACK_TIMEOUT_MS + 500
    );
    assert_eq!(
        Transmission::initial_timeout_ms(Transmission::ACK_RANDOM_SPAN_MS),
        Transmission::ACK_TIMEOUT_MS + Transmission::ACK_RANDOM_SPAN_MS
    );
    assert_eq!(
        Transmission::initial_timeout_ms(Transmission::ACK_RANDOM_SPAN_MS + 1),
        Transmission::ACK_TIMEOUT_MS + Transmission::ACK_RANDOM_SPAN_MS
    );
    assert_eq!(
        Transmission::ACK_RANDOM_SPAN_MS,
        Transmission::ACK_TIMEOUT_MS / u32::from(Transmission::ACK_RANDOM_FACTOR_DEN)
            * u32::from(Transmission::ACK_RANDOM_FACTOR_NUM - Transmission::ACK_RANDOM_FACTOR_DEN)
    );
}
