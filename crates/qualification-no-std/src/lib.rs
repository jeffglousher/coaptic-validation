//! Bounded code-generation and finite runtime probes for platform qualification.
//! Cross builds prove code generation. Runtime results require executing the
//! probe and retaining source, image identity and platform stack evidence.
#![no_std]
#![forbid(unsafe_code)]

use coaptic::storage::DatagramIo;
use coaptic::{App, Endpoint, Request, Response, get, profiles};

struct ProbeIo<'a> {
    incoming: Option<&'a [u8]>,
}
impl DatagramIo for ProbeIo<'_> {
    type Error = ();
    fn recv(&mut self, bytes: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        let Some(packet) = self.incoming.take() else {
            return Ok(None);
        };
        if packet.len() > bytes.len() {
            return Err(());
        }
        bytes[..packet.len()].copy_from_slice(packet);
        Ok(Some((packet.len(), Endpoint::v4([192, 0, 2, 1], 5683))))
    }
    fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        Ok(bytes.len())
    }
}

/// Generates concrete bounded App code for the selected target. The transport
/// discards traffic; returning true would not establish network interoperability.
#[must_use]
pub fn protocol_codegen_probe(input: &[u8], _master_secret: &[u8]) -> bool {
    fn value(_: Request<'_>) -> Response<'static> {
        Response::content(b"probe")
    }
    let builder = App::profile::<profiles::Constrained>()
        .deterministic_for_tests()
        .block_wise::<true>()
        .route("probe", get(value));
    #[cfg(feature = "oscore")]
    let builder = {
        let Ok(context) = coaptic::oscore::SecurityContext::derive(coaptic::oscore::DeriveParams {
            master_secret: _master_secret,
            master_salt: &[],
            sender_id: &[1],
            recipient_id: &[2],
            id_context: &[],
        }) else {
            return false;
        };
        builder.oscore(context)
    };
    #[cfg(not(feature = "oscore"))]
    let builder = builder.allow_plaintext();
    let Ok(mut app) = builder.bind(ProbeIo {
        incoming: Some(input),
    }) else {
        return false;
    };
    let Ok(call) = app
        .get("probe")
        .to(Endpoint::v4([192, 0, 2, 1], 5683))
        .send(0)
    else {
        return false;
    };
    app.poll(1).is_ok() && app.cancel(call)
}

struct LoopIo {
    packets: [[u8; 1152]; 4],
    lengths: [usize; 4],
    head: usize,
    count: usize,
}

impl DatagramIo for LoopIo {
    type Error = ();
    fn recv(&mut self, bytes: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        if self.count == 0 {
            return Ok(None);
        }
        let index = self.head;
        let size = self.lengths[index];
        if size > bytes.len() {
            return Err(());
        }
        bytes[..size].copy_from_slice(&self.packets[index][..size]);
        self.head = (self.head + 1) % 4;
        self.count -= 1;
        Ok(Some((size, Endpoint::v4([192, 0, 2, 1], 5683))))
    }
    fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        if self.count == 4 || bytes.len() > 1152 {
            return Err(());
        }
        let index = (self.head + self.count) % 4;
        self.packets[index][..bytes.len()].copy_from_slice(bytes);
        self.lengths[index] = bytes.len();
        self.count += 1;
        Ok(bytes.len())
    }
}

/// Runs 64 bounded App block downloads and cancellations with exact body checks.
///
/// Executes without an allocator, sockets or a platform runtime. A board launcher
/// must retain the compiler, image, result and stack measurement. This loopback
/// campaign does not establish radio, entropy or persistent-storage integration.
#[inline(never)]
#[must_use]
pub fn protocol_runtime_probe() -> Result<(), &'static str> {
    const BODY: [u8; 2000] = [0x5a; 2000];
    fn large(_: Request<'_>) -> Response<'static> {
        Response::content(&BODY)
    }
    let Ok(mut app) = App::profile::<profiles::Constrained>()
        .deterministic_for_tests()
        .allow_plaintext()
        .block_wise::<true>()
        .route("large", get(large))
        .bind(LoopIo {
            packets: [[0; 1152]; 4],
            lengths: [0; 4],
            head: 0,
            count: 0,
        })
    else {
        return Err("bind");
    };
    let peer = Endpoint::v4([192, 0, 2, 1], 5683);
    for round in 0..64 {
        let now = round * 300_000;
        if app.poll(now).is_err() {
            return Err("epoch cleanup");
        }
        let Ok(call) = app.get("large").to(peer).deadline(now + 20).send(now) else {
            return Err("download send");
        };
        let mut complete = false;
        for tick in 0..16 {
            if app.poll(now + tick).is_err() {
                return Err("download poll");
            }
            if let Some(response) = app.take_response(call) {
                let Ok(response) = response else {
                    return Err("download terminal failure");
                };
                if response.code() != coaptic::Code::CONTENT || response.body() != Some(&BODY[..]) {
                    return Err("download body");
                }
                complete = true;
                break;
            }
        }
        if !complete {
            return Err("download incomplete");
        }
        let Ok(cancelled) = app.get("large").to(peer).send(now + 16) else {
            return Err("cancellation send");
        };
        if !app.cancel(cancelled)
            || !matches!(
                app.take_response(cancelled),
                Some(Err(coaptic::CallFailure::Cancelled))
            )
        {
            return Err("cancellation result");
        }
        if app.poll(now + 17).is_err() || app.engine_mut().rx_occupied() != 0 {
            return Err("cancellation cleanup");
        }
    }
    #[cfg(feature = "oscore")]
    {
        use coaptic::message::{Code, Message, MessageId, Type, decode};
        use coaptic::oscore::{DeriveParams, SecurityContext};
        let parameters = DeriveParams {
            master_secret: b"device qualification fixture",
            master_salt: &[],
            sender_id: &[1],
            recipient_id: &[2],
            id_context: &[],
        };
        let Ok(mut sender) = SecurityContext::derive(parameters) else {
            return Err("sender derive");
        };
        let Ok(mut recipient) = SecurityContext::derive(DeriveParams {
            sender_id: &[2],
            recipient_id: &[1],
            ..parameters
        }) else {
            return Err("recipient derive");
        };
        for index in 0..64 {
            let plain = Message::new(Type::Confirmable, Code::GET, MessageId::new(index));
            let mut wire = [0u8; 1280];
            let Ok(size) = sender.protect_request(&plain, &mut wire) else {
                return Err("protect");
            };
            let Ok(protected) = decode(&wire[..size]) else {
                return Err("decode protected");
            };
            let mut scratch = [0u8; 1280];
            if recipient
                .unprotect_request(&protected, &mut scratch)
                .is_err()
                || recipient
                    .unprotect_request(&protected, &mut scratch)
                    .is_ok()
            {
                return Err("authentication or replay");
            }
        }
    }
    Ok(())
}
