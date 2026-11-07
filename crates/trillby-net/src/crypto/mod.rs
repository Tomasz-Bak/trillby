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
pub use chacha20::{KEY_LEN, NONCE_LEN};
pub use hkdf::{hkdf_expand, hkdf_extract};
pub use hmac::hmac_sha256;
pub use poly1305::TAG_LEN;
pub use sha256::{sha256, DIGEST_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    BufferTooShort,
    CounterOverflow,
    OutputTooLong,
    AuthFailed,
}

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

#[derive(Clone, Copy)]
pub(crate) struct BlockBuffer<const N: usize> {
    pub(crate) buf: [u8; N],
    pub(crate) len: usize,
}

impl<const N: usize> BlockBuffer<N> {
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }

    pub(crate) fn absorb(&mut self, mut data: &[u8], mut process: impl FnMut(&[u8; N])) {
        if self.len > 0 {
            let needed = N - self.len;
            if data.len() < needed {
                self.buf[self.len..self.len + data.len()].copy_from_slice(data);
                self.len += data.len();
                return;
            }
            self.buf[self.len..].copy_from_slice(&data[..needed]);
            let block = self.buf;
            process(&block);
            self.len = 0;
            data = &data[needed..];
        }

        let mut blocks = data.chunks_exact(N);
        for b in &mut blocks {
            process(b.try_into().unwrap());
        }

        let rem = blocks.remainder();
        self.buf[..rem.len()].copy_from_slice(rem);
        self.len = rem.len();
    }

    pub(crate) fn pending(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub(crate) fn wipe(&mut self) {
        wipe(&mut self.buf);
        self.len = 0;
    }
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
pub(crate) const SUNSCREEN: &[u8; 114] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

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

    #[test]
    fn test_block_buffer_absorb_and_wipe() {
        let mut bb = BlockBuffer::<4>::new();
        let mut blocks = [[0u8; 4]; 4];
        let mut block_count = 0;

        // Absorbing less than a block leaves it in pending
        bb.absorb(&[1, 2], |b| {
            blocks[block_count] = *b;
            block_count += 1;
        });
        assert_eq!(block_count, 0);
        assert_eq!(bb.pending(), &[1, 2]);

        // Absorbing enough to complete the pending block plus full and partial blocks
        bb.absorb(&[3, 4, 5, 6, 7, 8, 9], |b| {
            blocks[block_count] = *b;
            block_count += 1;
        });
        assert_eq!(block_count, 2);
        assert_eq!(blocks[0], [1, 2, 3, 4]);
        assert_eq!(blocks[1], [5, 6, 7, 8]);
        assert_eq!(bb.pending(), &[9]);

        // Wipe clears both buffer and length
        bb.wipe();
        assert_eq!(bb.pending(), &[]);
        assert_eq!(bb.buf, [0u8; 4]);
    }
}
