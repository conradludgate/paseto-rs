//! Constant-time base64url decoding.
//!
//! <https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#base64-encoding>.

// Code taken from base64ct.
// Licensed from the RustCrypto developers under Apache-2.0.
// <https://github.com/RustCrypto/formats/blob/master/base64ct/LICENSE-APACHE>
//
// Modified to allow encoding directly into a `fmt::Formatter`.
#![allow(unsafe_code)]

use alloc::vec::Vec;
use core::fmt;

use crate::PasetoError;

pub fn write_to_fmt(bytes: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    let mut tmp = [0; 4];

    let (chunks, rem) = bytes.as_chunks::<3>();
    for s in chunks {
        encode_3bytes(s, &mut tmp);
        // SAFETY: values written by `encode_3bytes` are valid one-byte UTF-8 chars
        f.write_str(unsafe { str::from_utf8_unchecked(&tmp) })?;
    }

    let last = encode_last(rem, &mut tmp);
    f.write_str(unsafe { str::from_utf8_unchecked(last) })
}

fn encode_last<'a>(bytes: &[u8], dst: &'a mut [u8; 4]) -> &'a [u8] {
    let tmp;
    let len = match *bytes {
        [] => {
            tmp = [0; 3];
            0
        }
        [a] => {
            tmp = [a, 0, 0];
            2
        }
        [a, b] => {
            tmp = [a, b, 0];
            3
        }
        [a, b, c, ..] => {
            tmp = [a, b, c];
            4
        }
    };

    encode_3bytes(&tmp, dst);
    &dst[..len]
}

pub fn decode<'a>(src: &str, dst: &'a mut [u8]) -> Result<&'a [u8], PasetoError> {
    let dlen = decoded_len(src.len());
    let dst = dst.get_mut(..dlen).ok_or(PasetoError::Base64DecodeError)?;

    decode_inner(src, dst)?;
    Ok(dst)
}

pub fn decode_vec(src: &str) -> Result<Vec<u8>, PasetoError> {
    let dlen = decoded_len(src.len());
    let mut dst = vec![0; dlen];

    decode_inner(src, &mut dst[..])?;
    Ok(dst)
}

fn decode_inner(src: &str, dst: &mut [u8]) -> Result<(), PasetoError> {
    let (src_chunks, src_rem) = src.as_bytes().as_chunks::<4>();
    let (dst_chunks, dst_rem) = dst.as_chunks_mut::<3>();

    let mut err = 0;
    for (s, d) in core::iter::zip(src_chunks, dst_chunks) {
        err |= decode_3bytes(s, d);
    }

    err |= !(src_rem.is_empty() || src_rem.len() >= 2) as i16;
    let mut tmp_out = [0u8; 3];
    let mut tmp_in = [b'A'; 4];
    tmp_in[..src_rem.len()].copy_from_slice(src_rem);
    err |= decode_3bytes(&tmp_in, &mut tmp_out);
    dst_rem.copy_from_slice(&tmp_out[..dst_rem.len()]);

    if err == 0 {
        validate_last_block(src.as_ref(), dst)?;
        Ok(())
    } else {
        Err(PasetoError::Base64DecodeError)
    }
}

/// Validate that the last block of the decoded data round-trips back to the
/// encoded data.
fn validate_last_block(encoded: &[u8], decoded: &[u8]) -> Result<(), PasetoError> {
    if encoded.is_empty() && decoded.is_empty() {
        return Ok(());
    }

    // TODO(tarcieri): explicitly checked/wrapped arithmetic
    #[allow(clippy::arithmetic_side_effects)]
    fn last_block_start(bytes: &[u8], block_size: usize) -> usize {
        (bytes.len().saturating_sub(1) / block_size) * block_size
    }

    let enc_block = encoded
        .get(last_block_start(encoded, 4)..)
        .ok_or(PasetoError::Base64DecodeError)?;

    let dec_block = decoded
        .get(last_block_start(decoded, 3)..)
        .ok_or(PasetoError::Base64DecodeError)?;

    // Round-trip encode the decoded block
    let mut buf = [0u8; 4];
    let bytes = encode_last(dec_block, &mut buf);

    // Non-short-circuiting comparison of padding
    // TODO(tarcieri): better constant-time mechanisms (e.g. `subtle`)?
    if bytes
        .iter()
        .zip(enc_block.iter())
        .fold(0, |acc, (a, b)| acc | (a ^ b))
        == 0
    {
        Ok(())
    } else {
        Err(PasetoError::Base64DecodeError)
    }
}

/// Get the length of the output from decoding the provided *unpadded*
/// Base64-encoded input.
///
/// Note that this function does not fully validate the Base64 is well-formed
/// and may return incorrect results for malformed Base64.
// TODO(tarcieri): explicitly checked/wrapped arithmetic
#[allow(clippy::arithmetic_side_effects)]
#[inline(always)]
pub(crate) fn decoded_len(input_len: usize) -> usize {
    // overflow-proof computation of `(3*n)/4`
    let k = input_len / 4;
    let l = input_len - 4 * k;
    3 * k + (3 * l) / 4
}

/// Decode 3 bytes of a Base64 message.
#[inline(always)]
fn decode_3bytes(src: &[u8; 4], dst: &mut [u8; 3]) -> i16 {
    let c0 = decode_6bits(src[0]);
    let c1 = decode_6bits(src[1]);
    let c2 = decode_6bits(src[2]);
    let c3 = decode_6bits(src[3]);

    dst[0] = ((c0 << 2) | (c1 >> 4)) as u8;
    dst[1] = ((c1 << 4) | (c2 >> 2)) as u8;
    dst[2] = ((c2 << 6) | c3) as u8;

    ((c0 | c1 | c2 | c3) >> 8) & 1
}

/// Decode 6-bits of a Base64 message.
fn decode_6bits(src: u8) -> i16 {
    let mut ret: i16 = -1;

    ret += ((((b'A' as i16 - 1) - src as i16) & (src as i16 - (b'Z' as i16 + 1))) >> 8)
        & (src as i16 + -64);

    ret += ((((b'a' as i16 - 1) - src as i16) & (src as i16 - (b'z' as i16 + 1))) >> 8)
        & (src as i16 + -70);

    ret += ((((b'0' as i16 - 1) - src as i16) & (src as i16 - (b'9' as i16 + 1))) >> 8)
        & (src as i16 + 5);

    ret += ((((b'-' as i16 - 1) - src as i16) & (src as i16 - (b'-' as i16 + 1))) >> 8) & 63;
    ret += ((((b'_' as i16 - 1) - src as i16) & (src as i16 - (b'_' as i16 + 1))) >> 8) & 64;

    ret
}

/// Encode 3-bytes of a Base64 message.
#[inline(always)]
fn encode_3bytes(src: &[u8; 3], dst: &mut [u8; 4]) {
    let b0 = src[0] as i16;
    let b1 = src[1] as i16;
    let b2 = src[2] as i16;

    dst[0] = encode_6bits(b0 >> 2);
    dst[1] = encode_6bits(((b0 << 4) | (b1 >> 4)) & 63);
    dst[2] = encode_6bits(((b1 << 2) | (b2 >> 6)) & 63);
    dst[3] = encode_6bits(b2 & 63);
}

/// Encode 6-bits of a Base64 message.
#[inline(always)]
fn encode_6bits(src: i16) -> u8 {
    let mut diff = src + b'A' as i16;

    diff += ((25 - src) >> 8) & 6;
    diff += ((51 - src) >> 8) & -75;
    diff += ((61 - src) >> 8) & -(b'-' as i16 - 0x20);
    diff += ((62 - src) >> 8) & (b'_' as i16 - b'-' as i16 - 1);

    diff as u8
}
