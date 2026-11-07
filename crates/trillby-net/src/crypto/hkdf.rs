//! HKDF-SHA256 (RFC 5869).

use super::hmac::{hmac_sha256, HmacSha256};
use super::sha256::DIGEST_LEN;
use super::wipe;
use super::CryptoError;

const MAX_OUTPUT: usize = 255 * DIGEST_LEN;

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; DIGEST_LEN] {
    // An empty salt is zero-padded by HMAC, matching RFC 5869's default.
    hmac_sha256(salt, ikm)
}

pub fn hkdf_expand(prk: &[u8; DIGEST_LEN], info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    if out.len() > MAX_OUTPUT {
        return Err(CryptoError::OutputTooLong);
    }

    // Key once; each block is a clone of the prepared ipad/opad state.
    let keyed = HmacSha256::new(prk);
    let mut t = [0u8; DIGEST_LEN];

    // `out.len() <= MAX_OUTPUT` bounds the chunk count to 255, so `i + 1` fits u8.
    for (i, chunk) in out.chunks_mut(DIGEST_LEN).enumerate() {
        let mut mac = keyed.clone();
        if i > 0 {
            mac.update(&t);
        }
        mac.update(info);
        mac.update(&[(i + 1) as u8]);
        t = mac.finalize();
        chunk.copy_from_slice(&t[..chunk.len()]);
    }

    wipe(&mut t);
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
        let salt = hex::<13>("00 01 02 03 04 05 06 07 08 09 0a 0b 0c");
        let info = hex::<10>("f0 f1 f2 f3 f4 f5 f6 f7 f8 f9");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk,
            hex::<32>(
                "07 77 09 36 2c 2e 32 df 0d dc 3f 0d c4 7b ba 63 \
                 90 b6 c7 3b b5 0f 9c 31 22 ec 84 4a d7 c2 b3 e5"
            )
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
