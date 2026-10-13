//! ChaCha20-Poly1305 AEAD construction (RFC 8439).

use super::chacha20::{chacha20_block, chacha20_xor};
use super::constant_time_eq;
use super::poly1305::Poly1305;
use super::wipe;

pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext_and_tag: &mut [u8], // Last 16 bytes will receive the Poly1305 tag
) -> Result<(), ()> {
    if plaintext_and_tag.len() < 16 {
        return Err(());
    }
    let pt_len = plaintext_and_tag.len() - 16;

    // 1. Generate Poly1305 one-time key with block counter 0
    const ZERO_PAD: [u8; 16] = [0u8; 16];

    let mut poly_key_block = [0u8; 64];
    chacha20_block(key, nonce, 0, &mut poly_key_block);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    // 2. Encrypt plaintext in place (starting at counter 1)
    if chacha20_xor(key, nonce, 1, &mut plaintext_and_tag[..pt_len]).is_err() {
        wipe(&mut poly_key_block);
        wipe(&mut poly_key);
        return Err(());
    }

    // 3. Compute Poly1305 tag over AAD || pad || Ciphertext || pad || len(AAD) || len(Ciphertext)
    let mut poly = Poly1305::new(&poly_key);

    poly.update(aad);
    if aad.len() % 16 != 0 {
        poly.update(&ZERO_PAD[..16 - (aad.len() % 16)]);
    }

    poly.update(&plaintext_and_tag[..pt_len]);
    if pt_len % 16 != 0 {
        poly.update(&ZERO_PAD[..16 - (pt_len % 16)]);
    }

    poly.update(&(aad.len() as u64).to_le_bytes());
    poly.update(&(pt_len as u64).to_le_bytes());

    let tag = poly.finalize();
    plaintext_and_tag[pt_len..pt_len + 16].copy_from_slice(&tag);

    wipe(&mut poly_key_block);
    wipe(&mut poly_key);
    Ok(())
}

pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &mut [u8],
) -> Result<usize, ()> {
    const ZERO_PAD: [u8; 16] = [0u8; 16];

    if ciphertext_and_tag.len() < 16 {
        return Err(());
    }
    let ct_len = ciphertext_and_tag.len() - 16;

    // 1. Generate Poly1305 one-time key
    let mut poly_key_block = [0u8; 64];
    chacha20_block(key, nonce, 0, &mut poly_key_block);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    // 2. Verify MAC
    let mut poly = Poly1305::new(&poly_key);

    poly.update(aad);
    if aad.len() % 16 != 0 {
        poly.update(&ZERO_PAD[..16 - (aad.len() % 16)]);
    }

    poly.update(&ciphertext_and_tag[..ct_len]);
    if ct_len % 16 != 0 {
        poly.update(&ZERO_PAD[..16 - (ct_len % 16)]);
    }

    poly.update(&(aad.len() as u64).to_le_bytes());
    poly.update(&(ct_len as u64).to_le_bytes());

    let expected_tag = poly.finalize();
    let actual_tag = &ciphertext_and_tag[ct_len..ct_len + 16];

    let valid = constant_time_eq(&expected_tag, actual_tag);
    wipe(&mut poly_key_block);
    wipe(&mut poly_key);

    if !valid {
        return Err(());
    }

    // 3. Decrypt ciphertext in place
    chacha20_xor(key, nonce, 1, &mut ciphertext_and_tag[..ct_len])?;
    Ok(ct_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    #[test]
    fn test_chacha20_poly1305_rfc8439_2_8_2() {
        let key = hex::<32>(
            "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f \
             90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f",
        );
        let nonce = hex::<12>("07 00 00 00 40 41 42 43 44 45 46 47");
        let aad = hex::<12>("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

        let expected_ct = hex::<114>(
            "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2 \
             a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6 \
             3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b \
             1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36 \
             92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58 \
             fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc \
             3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b \
             61 16",
        );
        let expected_tag = hex::<16>("1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91");

        let mut buf = [0u8; 114 + 16];
        buf[..114].copy_from_slice(plaintext);

        // Encrypt test: verify actual ciphertext and tag against RFC 8439
        chacha20_poly1305_encrypt(&key, &nonce, &aad, &mut buf).unwrap();
        assert_eq!(&buf[..114], &expected_ct, "RFC 8439 2.8.2 ciphertext mismatch");
        assert_eq!(&buf[114..], &expected_tag, "RFC 8439 2.8.2 tag mismatch");

        // Decrypt test: verify decryption of the standard vector
        let pt_len = chacha20_poly1305_decrypt(&key, &nonce, &aad, &mut buf).unwrap();
        assert_eq!(pt_len, 114);
        assert_eq!(&buf[..pt_len], plaintext);
    }

    #[test]
    fn test_chacha20_poly1305_rfc8439_a_5_decrypt() {
        let key = hex::<32>(
            "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 \
             47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0",
        );
        let nonce = hex::<12>("00 00 00 00 01 02 03 04 05 06 07 08");
        let aad = hex::<12>("f3 33 88 86 00 00 00 00 00 00 4e 91");
        let ciphertext = hex::<265>(
            "64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd \
             5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2 \
             4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0 \
             bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf \
             33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81 \
             14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55 \
             97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38 \
             36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4 \
             b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9 \
             90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e \
             af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a \
             0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a \
             0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e \
             ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10 \
             49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30 \
             30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29 \
             a6 ad 5c b4 02 2b 02 70 9b",
        );
        let tag = hex::<16>("ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38");
        let expected_pt = hex::<265>(
            "49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20 \
             61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65 \
             6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20 \
             6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d \
             6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65 \
             20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63 \
             65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64 \
             20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65 \
             6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e \
             20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72 \
             69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65 \
             72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72 \
             65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61 \
             6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65 \
             6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20 \
             2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67 \
             72 65 73 73 2e 2f e2 80 9d",
        );

        let mut buf = [0u8; 265 + 16];
        buf[..265].copy_from_slice(&ciphertext);
        buf[265..].copy_from_slice(&tag);

        let pt_len = chacha20_poly1305_decrypt(&key, &nonce, &aad, &mut buf).unwrap();
        assert_eq!(pt_len, 265);
        assert_eq!(&buf[..pt_len], &expected_pt, "RFC 8439 A.5 decrypted plaintext mismatch");
    }

    #[test]
    fn test_chacha20_poly1305_round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x19u8; 12];
        let aad = b"HDR_SEQ_1001";
        let plaintext = b"TR_WORK_ORDER_OP_8829_PART_99";

        let mut buf = [0u8; 128];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let total_len = plaintext.len() + 16;

        chacha20_poly1305_encrypt(&key, &nonce, aad, &mut buf[..total_len]).unwrap();
        // Ciphertext is now encrypted and tagged
        assert_ne!(&buf[..plaintext.len()], plaintext);

        // Bit flip check in ciphertext
        let mut tampered = buf;
        tampered[2] ^= 0x01;
        assert!(chacha20_poly1305_decrypt(&key, &nonce, aad, &mut tampered[..total_len]).is_err());

        // Bit flip check in AAD
        assert!(chacha20_poly1305_decrypt(&key, &nonce, b"BAD_AAD", &mut buf[..total_len]).is_err());

        // Legitimate decryption
        let pt_len = chacha20_poly1305_decrypt(&key, &nonce, aad, &mut buf[..total_len]).unwrap();
        assert_eq!(&buf[..pt_len], plaintext);
    }

    #[test]
    fn test_chacha20_poly1305_empty_payload_and_aad() {
        let key = [0x55u8; 32];
        let nonce = [0x99u8; 12];
        let mut buf = [0u8; 16];

        // Empty plaintext, empty AAD: should produce 16-byte tag
        chacha20_poly1305_encrypt(&key, &nonce, b"", &mut buf).unwrap();
        assert_ne!(buf, [0u8; 16]);

        let pt_len = chacha20_poly1305_decrypt(&key, &nonce, b"", &mut buf).unwrap();
        assert_eq!(pt_len, 0);
    }
}
