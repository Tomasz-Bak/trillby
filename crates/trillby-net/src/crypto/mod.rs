//! Zero-allocation #![no_std] Cryptographic Primitives:
//! - SHA-256 (RFC 6234)
//! - HMAC-SHA256 (RFC 2104)
//! - HKDF-SHA256 (RFC 5869)
//! - ChaCha20-Poly1305 AEAD (RFC 8439)
//!
//! One file per primitive; this module only re-exports the public surface
//! so callers keep using `crate::crypto::{sha256, hkdf_expand, ...}`.

mod aead;
mod chacha20;
mod hkdf;
mod hmac;
mod poly1305;
mod sha256;

pub use aead::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};
pub use chacha20::{chacha20_block, chacha20_xor};
pub use hkdf::{hkdf_expand, hkdf_extract};
pub use hmac::{hmac_sha256, HmacSha256};
pub use poly1305::Poly1305;
pub use sha256::{sha256, Sha256};

use core::sync::atomic::{compiler_fence, Ordering};

/// Constant-time slice equality comparison.
///
/// Length is treated as public. `black_box` stops LLVM from turning the
/// OR-accumulator into an early-exit loop.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff = core::hint::black_box(diff | (x ^ y));
    }
    core::hint::black_box(diff) == 0
}

/// Plain-old-data types for which the all-zero bit pattern is valid.
///
/// # Safety
/// Implementors must be `Copy`, contain no padding-sensitive invariants, and
/// accept all-zero bytes as a valid value.
pub(crate) unsafe trait Pod: Copy {}
unsafe impl Pod for u8 {}
unsafe impl Pod for u32 {}
unsafe impl Pod for u64 {}
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}

/// Best-effort secret wipe that the optimizer is not allowed to elide.
#[inline(never)]
pub(crate) fn wipe<T: Pod>(x: &mut T) {
    let p = x as *mut T as *mut u8;
    for i in 0..core::mem::size_of::<T>() {
        // SAFETY: `p..p+size_of::<T>()` is the exclusively borrowed `x`, and
        // `T: Pod` guarantees zero bytes are a valid `T`.
        unsafe { core::ptr::write_volatile(p.add(i), 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Parses whitespace/colon-separated hex into a fixed array (tests only).
#[cfg(test)]
pub(crate) fn hex<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let mut n = 0;
    let mut hi: Option<u8> = None;
    for c in s.bytes() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => continue,
        };
        match hi.take() {
            None => hi = Some(v),
            Some(h) => {
                out[n] = (h << 4) | v;
                n += 1;
            }
        }
    }
    assert!(n == N && hi.is_none(), "hex length mismatch");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_edge_cases() {
        assert!(constant_time_eq(&[], &[]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));

        // 1-bit flip at first byte
        let a = [0x42, 0x55, 0xaa];
        let mut b = a;
        b[0] ^= 0x01;
        assert!(!constant_time_eq(&a, &b));

        // 1-bit flip at middle byte
        let mut c = a;
        c[1] ^= 0x01;
        assert!(!constant_time_eq(&a, &c));

        // 1-bit flip at last byte
        let mut d = a;
        d[2] ^= 0x01;
        assert!(!constant_time_eq(&a, &d));
    }

    #[test]
    fn test_wipe_zeroes_memory() {
        let mut byte_buf = [0x5au8; 32];
        wipe(&mut byte_buf);
        assert_eq!(byte_buf, [0u8; 32]);

        let mut u32_buf = [0x12345678u32; 8];
        wipe(&mut u32_buf);
        assert_eq!(u32_buf, [0u32; 8]);
    }
}
