//! ChaCha20 stream cipher (RFC 8439).

use super::wipe;

#[inline(always)]
fn chacha_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[inline(always)]
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn init_state(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    for (dst, src) in s[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *dst = le32(src);
    }
    s[12] = counter;
    for (dst, src) in s[13..16].iter_mut().zip(nonce.chunks_exact(4)) {
        *dst = le32(src);
    }
    s
}

fn block_from_state(state: &[u32; 16], out: &mut [u8; 64]) {
    let mut working = *state;

    for _ in 0..10 {
        // Column rounds
        chacha_quarter_round(&mut working, 0, 4, 8, 12);
        chacha_quarter_round(&mut working, 1, 5, 9, 13);
        chacha_quarter_round(&mut working, 2, 6, 10, 14);
        chacha_quarter_round(&mut working, 3, 7, 11, 15);

        // Diagonal rounds
        chacha_quarter_round(&mut working, 0, 5, 10, 15);
        chacha_quarter_round(&mut working, 1, 6, 11, 12);
        chacha_quarter_round(&mut working, 2, 7, 8, 13);
        chacha_quarter_round(&mut working, 3, 4, 9, 14);
    }

    for ((dst, w), s) in out.chunks_exact_mut(4).zip(working.iter()).zip(state.iter()) {
        dst.copy_from_slice(&w.wrapping_add(*s).to_le_bytes());
    }
    wipe(&mut working);
}

pub fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8; 64]) {
    let mut state = init_state(key, nonce, counter);
    block_from_state(&state, out);
    wipe(&mut state);
}

/// XORs the ChaCha20 keystream starting at block `counter` into `buf`.
///
/// Fails without touching `buf` if the 32-bit block counter would wrap,
/// since wrapping reuses keystream (catastrophic for a stream cipher).
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) -> Result<(), ()> {
    let blocks = (buf.len() as u64).div_ceil(64);
    if blocks > (1u64 << 32) - counter as u64 {
        return Err(());
    }

    let mut state = init_state(key, nonce, counter);
    let mut ks = [0u8; 64];

    for chunk in buf.chunks_mut(64) {
        block_from_state(&state, &mut ks);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
        // Wrap only ever happens after the final block (checked above).
        state[12] = state[12].wrapping_add(1);
    }

    wipe(&mut ks);
    wipe(&mut state);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    pub(crate) const SUNSCREEN: &[u8; 114] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

    #[test]
    fn test_chacha20_rfc8439_2_4_2() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = hex::<12>("00 00 00 00 00 00 00 4a 00 00 00 00");
        let mut buf = *SUNSCREEN;
        chacha20_xor(&key, &nonce, 1, &mut buf).unwrap();
        assert_eq!(
            buf,
            hex::<114>(
                "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
                 e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
                 f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
                 16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
                 07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
                 52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
                 5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
                 87 4d"
            )
        );
    }

    #[test]
    fn test_chacha20_counter_wrap_rejected() {
        let mut buf = [0u8; 65];
        // Two blocks starting at u32::MAX would wrap.
        assert!(chacha20_xor(&[0; 32], &[0; 12], u32::MAX, &mut buf).is_err());
        assert_eq!(buf, [0u8; 65], "buffer must be untouched on error");
        // One block at u32::MAX is the last legal block.
        assert!(chacha20_xor(&[0; 32], &[0; 12], u32::MAX, &mut buf[..64]).is_ok());
    }
}
