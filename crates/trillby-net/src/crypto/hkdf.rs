//! HKDF-SHA256 (RFC 5869).

use super::hmac::{hmac_sha256, HmacSha256};
use super::wipe;

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    // An empty salt is zero-padded by HMAC, matching RFC 5869's default.
    hmac_sha256(salt, ikm)
}

pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), ()> {
    if out.len() > 255 * 32 {
        return Err(());
    }

    // Key once; each block is a cheap copy of the prepared ipad/opad state.
    let mut keyed = HmacSha256::new(prk);
    let mut t = [0u8; 32];

    // `out.len() <= 255*32` bounds the chunk count to 255, so `i + 1` fits u8.
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let mut mac = keyed;
        if i > 0 {
            mac.update(&t);
        }
        mac.update(info);
        mac.update(&[(i + 1) as u8]);
        t = mac.finalize();
        chunk.copy_from_slice(&t[..chunk.len()]);
    }

    wipe(&mut t);
    keyed.wipe();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    #[test]
    fn test_hkdf_sha256_vector() {
        // RFC 5869 Test Case 1
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk,
            [
                0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
                0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
                0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
                0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
            ]
        );

        // Full 42 bytes: block 2 is the only path that chains T(1).
        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &info, &mut okm).unwrap();
        assert_eq!(
            okm,
            hex::<42>(
                "3cb25f25faacd57a90434f64d0362f2a\
                 2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865"
            )
        );
    }

    #[test]
    fn test_hkdf_max_length_no_overflow() {
        // 255 blocks used to overflow the u8 counter after the last block.
        let mut okm = [0u8; 255 * 32];
        assert!(hkdf_expand(&[7u8; 32], b"", &mut okm).is_ok());
        let mut too_long = [0u8; 255 * 32 + 1];
        assert!(hkdf_expand(&[7u8; 32], b"", &mut too_long).is_err());
    }
}
