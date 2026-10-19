#![no_std]
//! Observation only: no authentication, checksum validation, admission or packet changes.
pub const MAX_COAP: usize = 256;
pub const MAX_FRAME: usize = 14 + 60 + 8 + MAX_COAP;
pub const COUNTERS: u32 = 5;
pub const TOTAL: u32 = 4;
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Uninspected = 0,
    Oversized = 1,
    MalformedCoap = 2,
    CoapSyntax = 3,
}

#[inline(always)]
fn be16(bytes: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes([
        *bytes.get(at)?,
        *bytes.get(at + 1)?,
    ])))
}

/// Borrow the complete linear UDP payload. Unsupported envelopes remain uninspected.
#[inline(always)]
fn udp(frame: &[u8]) -> Option<&[u8]> {
    let kind = be16(frame, 12)?;
    let (start, end) = match kind {
        0x0800 => {
            let version_ihl = *frame.get(14)?;
            let ihl = usize::from(version_ihl & 15) * 4;
            if version_ihl >> 4 != 4 || ihl < 20 || *frame.get(23)? != 17 {
                return None;
            }
            // MF or nonzero offset: never classify fragments, even first fragments.
            if be16(frame, 20)? & 0x3fff != 0 {
                return None;
            }
            let len = be16(frame, 16)?;
            if len < ihl + 8 {
                return None;
            }
            (14 + ihl, 14 + len)
        }
        0x86dd => {
            if *frame.get(14)? >> 4 != 6 || *frame.get(20)? != 17 {
                return None;
            }
            let len = be16(frame, 18)?;
            if len < 8 {
                return None;
            }
            // Extension headers and jumbograms are not part of this pilot profile.
            (54, 54 + len)
        }
        _ => return None,
    };
    let ip = frame.get(..end)?;
    let src = be16(ip, start)?;
    let dst = be16(ip, start + 2)?;
    if src != 5683 && dst != 5683 {
        return None;
    }
    let len = be16(ip, start + 4)?;
    if len < 8 || start + len != end {
        return None;
    }
    ip.get(start + 8..end)
}

#[inline(always)]
pub fn classify(frame: &[u8]) -> Class {
    if frame.len() > MAX_FRAME {
        return Class::Uninspected;
    }
    let Some(payload) = udp(frame) else {
        return Class::Uninspected;
    };
    if payload.len() > MAX_COAP {
        return Class::Oversized;
    }
    match coaptic::message::extended::decode(payload) {
        Ok(_) => Class::CoapSyntax,
        Err(_) => Class::MalformedCoap,
    }
}
