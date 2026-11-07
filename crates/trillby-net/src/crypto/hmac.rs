//! HMAC-SHA256 (RFC 2104).

use super::sha256::{sha256, Sha256, BLOCK_LEN, DIGEST_LEN};
use super::wipe;

/// Incremental HMAC-SHA256.
///
/// `Clone`, not `Copy`: HKDF clones the keyed state per output block, and
/// every copy wipes itself on drop.
#[derive(Clone)]
pub(crate) struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            let mut hashed = sha256(key);
            k[..DIGEST_LEN].copy_from_slice(&hashed);
            wipe(&mut hashed);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut pad = [0u8; BLOCK_LEN];
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

    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let mut inner_hash = self.inner.finalize();
        self.outer.update(&inner_hash);
        let tag = self.outer.finalize();
        wipe(&mut inner_hash);
        tag
    }

    /// Clears the keyed state; called on drop.
    fn wipe(&mut self) {
        self.inner.wipe();
        self.outer.wipe();
    }
}

impl Drop for HmacSha256 {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut mac = HmacSha256::new(key);
    mac.update(data);
    mac.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    fn assert_hmac(key: &[u8], data: &[u8], expected: [u8; 32]) {
        assert_eq!(hmac_sha256(key, data), expected);
        let mut h = HmacSha256::new(key);
        for &b in data {
            h.update(&[b]);
        }
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn test_hmac_sha256_vector() {
        // RFC 4231 Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        assert_eq!(
            hmac_sha256(key, data),
            hex::<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn test_hmac_sha256_long_key() {
        // RFC 4231 Test Case 6: 131-byte key forces the hash-the-key branch.
        let key = [0xaau8; 131];
        assert_hmac(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            hex::<32>("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        );
    }

    #[test]
    fn test_hmac_incremental_matches_oneshot() {
        let mut m = HmacSha256::new(b"Jefe");
        m.update(b"what do ya ");
        m.update(b"want for nothing?");
        assert_eq!(m.finalize(), hmac_sha256(b"Jefe", b"what do ya want for nothing?"));
    }

    #[test]
    fn test_hmac_empty_key_and_exact_64_byte_block_key() {
        let data = b"Sample message for key boundary testing";

        // Empty key (key.len() == 0)
        let empty_key = b"";
        let expected_empty = hex::<32>("ecb335ed2eb8a5ffa590812283341f08b36fd6070a1e3476d19f68acdfcfbda3");
        assert_hmac(empty_key, data, expected_empty);

        // Exact 64-byte block key (key.len() == 64)
        let mut key64 = [0u8; 64];
        for i in 0..64 {
            key64[i] = i as u8;
        }
        let expected_64 = hex::<32>("f7208193d2b5d8bc02300f1f5c7398189eea7aef78ee1ac657f9aa58bede8451");
        assert_hmac(&key64, data, expected_64);
    }
}
