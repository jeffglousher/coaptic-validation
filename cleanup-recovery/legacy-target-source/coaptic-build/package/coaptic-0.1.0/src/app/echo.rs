//! Caller-owned Echo issuance and verification.

use crate::error::ValueError;
use crate::message::Echo;
use crate::storage::Endpoint;

/// Inputs to an explicit server Echo policy, after message protection checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EchoCheck {
    /// The received Echo, preserving absence and malformed-value errors.
    pub echo: Result<Option<Echo>, ValueError>,
    /// Transport peer; include the address, port and IPv6 scope in bindings.
    pub peer: Endpoint,
    /// Caller monotonic clock used for this poll.
    pub now_ms: u64,
    /// True when App verified an Inner OSCORE request in its attached context.
    /// This does not describe security supplied by an external transport.
    pub oscore_protected: bool,
}

/// Result of caller-owned Echo issuance/verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EchoDecision {
    /// Continue to bounded body processing and the application handler.
    Accept,
    /// Return 4.01 with this opaque challenge, without processing the request.
    Challenge(Echo),
    /// Return 4.01 without a challenge, without processing the request.
    /// Use when verification/issuance is unavailable; do not fail open.
    Reject,
}

/// Server Echo policy called before body assembly or handler side effects.
///
/// Install with [`super::AppBuilder::echo_policy`] or [`super::App::echo_policy`].
/// The caller owns challenge state, entropy, keys, expiry, endpoint/security-
/// association binding, reboot behavior and verification. Use a bounded issued-
/// value cache or a reviewed authenticated construction (RFC 9175 Appendix A).
/// A timestamp comparison alone is not verification of a server-issued value.
///
/// Request freshness additionally requires integrity-protected messages under
/// RFC 9175 section 2.3. OSCORE verification is indicated by `oscore_protected`;
/// for an external DTLS transport, the caller must establish that guarantee.
/// Plaintext address-reachability challenges are a distinct RFC 9175 use case.
/// The core does not supply a key, OS RNG, global cache or automatic verifier.
/// The callback must finish in bounded time and must not re-enter this App.
///
/// Duplicate CON requests may receive their cached response before this policy
/// is called; this preserves retransmission behavior without repeating effects.
pub type EchoPolicy = fn(EchoCheck) -> EchoDecision;
