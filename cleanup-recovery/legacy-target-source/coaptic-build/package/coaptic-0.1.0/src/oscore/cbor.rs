//! Minimal CBOR for OSCORE HKDF `info` and COSE AAD. Not a general decoder.

use super::Error;
use super::{AEAD_AES_CCM_16_64_128, OSCORE_VERSION};

/// `Enc_structure` prefix: `["Encrypt0", h'']` (11 bytes) before `external_aad`.
const ENC0_PREFIX: &[u8] = &[
    0x83, 0x68, b'E', b'n', b'c', b'r', b'y', b'p', b't', b'0', 0x40,
];

pub(crate) fn encode_info(
    out: &mut [u8],
    id: &[u8],
    id_context: Option<&[u8]>,
    label: &str,
    l: u8,
) -> Result<usize, Error> {
    let mut i = 0;
    push(out, &mut i, 0x85)?;
    put_bstr(out, &mut i, id)?;
    match id_context {
        None => push(out, &mut i, 0xf6)?,
        Some(ctx) => put_bstr(out, &mut i, ctx)?,
    }
    put_uint(out, &mut i, AEAD_AES_CCM_16_64_128 as u8)?;
    put_tstr(out, &mut i, label)?;
    put_uint(out, &mut i, l)?;
    Ok(i)
}

pub(crate) fn encode_aad(
    out: &mut [u8],
    request_kid: &[u8],
    request_piv: &[u8],
    class_i: &[u8],
) -> Result<usize, Error> {
    let mut aad_array = [0u8; 48];
    let mut i = 0;
    push(&mut aad_array, &mut i, 0x85)?;
    put_uint(&mut aad_array, &mut i, OSCORE_VERSION)?;
    push(&mut aad_array, &mut i, 0x81)?;
    put_uint(&mut aad_array, &mut i, AEAD_AES_CCM_16_64_128 as u8)?;
    put_bstr(&mut aad_array, &mut i, request_kid)?;
    put_bstr(&mut aad_array, &mut i, request_piv)?;
    put_bstr(&mut aad_array, &mut i, class_i)?;

    if out.len() < ENC0_PREFIX.len() {
        return Err(Error::BufferTooSmall);
    }
    out[..ENC0_PREFIX.len()].copy_from_slice(ENC0_PREFIX);
    let mut n = ENC0_PREFIX.len();
    put_bstr(out, &mut n, &aad_array[..i])?;
    Ok(n)
}

fn put_bstr(out: &mut [u8], i: &mut usize, value: &[u8]) -> Result<(), Error> {
    put_len(out, i, 0x40, value.len())?;
    push_slice(out, i, value)
}

fn put_tstr(out: &mut [u8], i: &mut usize, value: &str) -> Result<(), Error> {
    put_len(out, i, 0x60, value.len())?;
    push_slice(out, i, value.as_bytes())
}

fn put_len(out: &mut [u8], i: &mut usize, major: u8, len: usize) -> Result<(), Error> {
    if len <= 23 {
        push(out, i, major | (len as u8))
    } else if len <= 255 {
        push(out, i, major | 24)?;
        push(out, i, len as u8)
    } else {
        Err(Error::Id)
    }
}

fn put_uint(out: &mut [u8], i: &mut usize, n: u8) -> Result<(), Error> {
    if n <= 23 {
        push(out, i, n)
    } else {
        push(out, i, 0x18)?;
        push(out, i, n)
    }
}

fn push(out: &mut [u8], i: &mut usize, b: u8) -> Result<(), Error> {
    if *i >= out.len() {
        return Err(Error::BufferTooSmall);
    }
    out[*i] = b;
    *i += 1;
    Ok(())
}

fn push_slice(out: &mut [u8], i: &mut usize, bytes: &[u8]) -> Result<(), Error> {
    let end = i.checked_add(bytes.len()).ok_or(Error::BufferTooSmall)?;
    if end > out.len() {
        return Err(Error::BufferTooSmall);
    }
    out[*i..end].copy_from_slice(bytes);
    *i = end;
    Ok(())
}
