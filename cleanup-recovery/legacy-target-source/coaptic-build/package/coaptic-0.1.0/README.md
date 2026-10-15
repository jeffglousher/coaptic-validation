# coaptic

[![CI](https://github.com/jeffglousher/coaptic/actions/workflows/ci.yml/badge.svg)](https://github.com/jeffglousher/coaptic/actions/workflows/ci.yml)

A bounded `no_std` CoAP engine with an approachable `App` face. Slots and tables sit under the hood; there is no global App State.

Not on crates.io yet (publish parked — [#132](https://github.com/jeffglousher/coaptic/issues/132)). Until then:

```toml
[dependencies]
coaptic = { git = "https://github.com/jeffglousher/coaptic" }
getrandom = "0.3" # host example; embedded callers provide their own secure source
```

## Quick start

The public API is documented in rustdoc (`cargo doc --open`). `App` owns bounded protocol state; you supply I/O, time and application data.

```rust
use coaptic::{App, Request, Response, get, profiles};

fn get_temp(_req: Request<'_>) -> Response<'static> {
    Response::content(b"21.5")
}

let mut app = App::profile::<profiles::Default>()
    .randomness(|bytes| getrandom::fill(bytes).is_ok())
    .block_wise::<true>()
    .route("sensors/temp", get(get_temp))
    .bind(io)?;
app.poll(now_ms)?;

let call = app.get("sensors/temp").to(peer).send(now_ms)?;
app.poll(now_ms)?;
let response = app.take_response(call);
```

`.route` / `app.get` also accept `&["sensors", "temp"]`. Handlers are `fn(Request<'_>) -> Response`. You own the socket (`storage::DatagramIo`), the clock, the destination of a client request, and any domain data that outlives a request. Supply secure entropy for eight-byte Tokens, a randomized initial Message ID and CON retry jitter. The library does not call an OS RNG; deterministic mode is explicitly for tests.

Optional `oscore` provides pairwise AES-CCM protection with caller-owned security
contexts. See rustdoc for Observe, block-wise transfers and security APIs.
DTLS adapters live in test harnesses and independent peer executables; the library
does not own a DTLS stack.

## Operational limits

- App holds four live client requests, including Observe subscriptions and
  unread completed replies; profile resources may impose lower limits.
  Exhaustion returns `Error::Saturated` rather than evicting a request.
- One pairwise OSCORE context per App, with four live Token bindings. Use
  separate Apps for independent peers or key epochs; replacing a context
  does not migrate live exchanges or subscriptions. Timed Q-Block gap
  recovery with OSCORE returns `Error::Unsupported` without sending plaintext.
- `.block_wise::<true>()` uses 4 KiB per body slot even for Constrained:
  8 KiB of RX/TX bodies for Constrained, 16 KiB for Default, plus a 4 KiB
  assembled client-body hold and bookkeeping. Datagram-only mode omits these.
- Unknown critical response options reject the response; unknown elective
  options are retained in bounded response metadata without interpretation. A rejected CON response gets RST, while a matching
  piggybacked ACK stops request retransmission without completing the Call.

## Features

Default is `no_std` with no allocator. Optional `alloc` and `std` (`std` implies `alloc`). Optional `oscore` pulls RustCrypto `aes` / `ccm` / `hkdf` / `sha2` (AES-CCM-16-64-128 only; not a COSE crate). Without `oscore` the library crate has zero dependencies.

## Examples and testing

```bash
cargo run --example coap_server --features std
```

- [Contributor checks](https://github.com/jeffglousher/coaptic/blob/main/CONTRIBUTING.md): toolchain, CI and packaging.
- [App harness and dogfood](https://github.com/jeffglousher/coaptic/blob/main/crates/coaptic-plugtest/README.md): mixed-stack UDP workflows, Observe and OSCORE coverage, baseline comparisons.
- [Independent process tests](https://github.com/jeffglousher/coaptic/blob/main/tools/interop/README.md): Coaptic, coap-rs and libcoap over UDP/DTLS, fault injection and timing methodology.

The in-crate `cargo test --test plugtest` exchanges Engine bytes without sockets.
The linked harnesses exercise App and real loopback transports. Their guides
separate tested behavior from untested capabilities and performance claims.

## Project

API reference: `cargo doc --open`. Protocol copies: `knowledge/rfcs/` in the
repository. Planning and remaining capabilities live in
[GitHub Issues / project](https://github.com/users/jeffglousher/projects/2).

Licensed MIT OR Apache-2.0.
