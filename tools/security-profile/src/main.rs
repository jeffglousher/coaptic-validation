//! Socket-free OSCORE work probe; not an end-to-end throughput benchmark.
//!
//! Fresh per-process secrets are provisioned outside timing. Each iteration
//! validates a complete protected GET/response with a fresh request sequence.
//! Context setup, outer parsing, body validation and sample storage are outside
//! the recorded phases. Protection includes inner/outer encoding, copying and
//! AEAD; opening includes authentication, inner parsing and replay work. These
//! phases do not isolate AES alone and must not be added to socket diagnostics
//! from another workload as if they formed one measured latency distribution.
#![forbid(unsafe_code)]

use coaptic::message::{EncodedUint, Message, MessageId, Opt, Token, Type, decode, encode};
use coaptic::oscore::{DeriveParams, SecurityContext};
use coaptic::{Code, ContentFormat};
use std::{env, hint::black_box, time::Instant};

fn context(secret: &[u8], salt: &[u8], sender: &[u8], recipient: &[u8]) -> SecurityContext {
    SecurityContext::derive(DeriveParams {
        master_secret: secret,
        master_salt: salt,
        sender_id: sender,
        recipient_id: recipient,
        id_context: &[],
    })
    .expect("valid fresh fixture context")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: coaptic-security-profile BODY_BYTES OPERATIONS".into());
    }
    let bytes: usize = args[1].parse()?;
    let operations: usize = args[2].parse()?;
    if ![64, 1024].contains(&bytes) || !(1..=60_000).contains(&operations) {
        return Err("body must be 64 or 1024 bytes; operations must be 1..=60000".into());
    }
    let mut secret = [0u8; 16];
    let mut salt = [0u8; 8];
    getrandom::fill(&mut secret).map_err(|error| error.to_string())?;
    getrandom::fill(&mut salt).map_err(|error| error.to_string())?;
    let started = Instant::now();
    let mut client = context(&secret, &salt, &[0], &[1]);
    let mut server = context(&secret, &salt, &[1], &[0]);
    let derive_ns = started.elapsed().as_nanos();
    let body: Vec<_> = (0..bytes).map(|index| (index % 251) as u8).collect();
    let path = [Opt::uri_path("bench")];
    let format = EncodedUint::new(ContentFormat::OCTET_STREAM.get() as u32);
    let response_options = [Opt::etag(b"fixture"), Opt::content_format(&format)];
    let mut plain_wire = [0u8; 1472];
    let mut request_wire = [0u8; 1472];
    let mut opened_request = [0u8; 1472];
    let mut response_wire = [0u8; 1472];
    let mut opened_response = [0u8; 1472];
    let mut times: [Vec<u64>; 5] = std::array::from_fn(|_| Vec::with_capacity(operations));
    for index in 0..operations + 128 {
        let token_bytes = (index as u64).to_be_bytes();
        let token = Token::new(&token_bytes).expect("eight-byte token");
        let id = MessageId::new(index as u16);
        let request = Message::new(Type::Confirmable, Code::GET, id)
            .with_token(token)
            .with_options(&path);
        let response = Message::new(Type::Acknowledgement, Code::CONTENT, id)
            .with_token(token)
            .with_options(&response_options)
            .with_payload(&body);

        let started = Instant::now();
        let plain_len = encode(black_box(&response), black_box(&mut plain_wire))
            .expect("plain fixture encoding");
        let encode_ns = started.elapsed().as_nanos() as u64;
        assert_eq!(decode(&plain_wire[..plain_len]).unwrap().payload(), body);

        let started = Instant::now();
        let request_len = client
            .protect_request(black_box(&request), black_box(&mut request_wire))
            .expect("request protection");
        let seal_request_ns = started.elapsed().as_nanos() as u64;
        let protected_request =
            decode(&request_wire[..request_len]).expect("protected outer request");
        assert!(protected_request.oscore().is_some());

        let started = Instant::now();
        let (inner_request, binding) = server
            .unprotect_request(
                black_box(&protected_request),
                black_box(&mut opened_request),
            )
            .expect("authenticated fresh request");
        let open_request_ns = started.elapsed().as_nanos() as u64;
        assert_eq!(inner_request.code(), Code::GET);
        assert_eq!(inner_request.token(), token);
        assert_eq!(inner_request.message_id(), id);
        assert_eq!(
            inner_request.uri_path().collect::<Vec<_>>(),
            vec![Ok("bench")]
        );
        assert!(inner_request.payload().is_empty());

        let started = Instant::now();
        let response_len = server
            .protect_response(black_box(&response), binding, black_box(&mut response_wire))
            .expect("one response per fresh request binding");
        let seal_response_ns = started.elapsed().as_nanos() as u64;
        let protected_response =
            decode(&response_wire[..response_len]).expect("protected outer response");
        assert!(protected_response.oscore().is_some());
        let client_binding = client.lookup(token).expect("retained request binding");

        let started = Instant::now();
        let inner_response = client
            .unprotect_response(
                black_box(&protected_response),
                client_binding,
                black_box(&mut opened_response),
            )
            .expect("authenticated bound response");
        let open_response_ns = started.elapsed().as_nanos() as u64;
        assert_eq!(inner_response.code(), Code::CONTENT);
        assert_eq!(inner_response.token(), token);
        assert_eq!(inner_response.message_id(), id);
        assert_eq!(
            inner_response.content_format(),
            Some(Ok(ContentFormat::OCTET_STREAM))
        );
        assert_eq!(inner_response.payload(), body);
        assert_eq!(
            inner_response.etag().collect::<Vec<_>>(),
            vec![b"fixture".as_slice()]
        );
        assert_eq!(client.take(token), Some(client_binding));
        if index >= 128 {
            for (samples, time) in times.iter_mut().zip([
                encode_ns,
                seal_request_ns,
                open_request_ns,
                seal_response_ns,
                open_response_ns,
            ]) {
                samples.push(time);
            }
        }
    }
    for (phase, samples) in [
        "plain_response_encode",
        "request_protect",
        "request_open",
        "response_protect",
        "response_open",
    ]
    .into_iter()
    .zip(times)
    {
        println!(
            "{{\"schema\":\"coaptic-security-work/1\",\"body_bytes\":{bytes},\"operations\":{operations},\"phase\":\"{phase}\",\"two_context_derive_ns\":{derive_ns},\"latencies_ns\":[{}]}}",
            samples
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    Ok(())
}
