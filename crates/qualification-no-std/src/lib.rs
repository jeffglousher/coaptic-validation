//! Compile/code-generation probe, not a runtime or device qualification.
//! Instantiates App, bounded block storage, client/server dispatch and optional
//! OSCORE on each target without linking a platform runtime or allocator.
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
