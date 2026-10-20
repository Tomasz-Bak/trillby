//! HMAC-SHA256 (RFC 2104).

use super::sha256::{sha256, Sha256};
use super::wipe;

/// Incremental HMAC-SHA256.
///
/// `Copy` on purpose: key the MAC once, then copy the prepared state per
/// message (HKDF does this per output block) to skip re-hashing the pads.
#[derive(Clone, Copy)]
pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            let mut hashed = sha256(key);
            k[..32].copy_from_slice(&hashed);
            wipe(&mut hashed);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut pad = [0u8; 64];
        let mut inner = Sha256::new();
        let mut outer = Sha256::new();

        for (p, &b) in pad.iter_mut().zip(k.iter()) {
            *p = b ^ 0x36;
        }
        inner.update(&pad);
        for (p, &b) in pad.iter_mut().zip(k.iter()) {
            *p = b ^ 0x5c;
        }
        outer.update(&pad);

        wipe(&mut k);
        wipe(&mut pad);
        Self { inner, outer }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let mut inner_hash = self.inner.finalize();
        self.outer.update(&inner_hash);
        let tag = self.outer.finalize();
        wipe(&mut inner_hash);
        self.wipe();
        tag
    }

    /// Clears the keyed state. Needed because `Copy` types cannot impl `Drop`.
    pub(crate) fn wipe(&mut self) {
        self.inner.wipe();
        self.outer.wipe();
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new(key);
    mac.update(data);
    mac.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    #[test]
    fn test_hmac_sha256_vector() {
        // RFC 4231 Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha256(key, data);
        assert_eq!(
            mac,
            [
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
                0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
                0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
                0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
            ]
        );
    }

    #[test]
    fn test_hmac_sha256_long_key() {
        // RFC 4231 Test Case 6: 131-byte key forces the hash-the-key branch.
        let key = [0xaau8; 131];
        let mac = hmac_sha256(&key, b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(
            mac,
            hex::<32>("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn test_hmac_incremental_matches_oneshot() {
        let mut m = HmacSha256::new(b"Jefe");
        m.update(b"what do ya ");
        m.update(b"want for nothing?");
        assert_eq!(m.finalize(), hmac_sha256(b"Jefe", b"what do ya want for nothing?"));
    }
}
