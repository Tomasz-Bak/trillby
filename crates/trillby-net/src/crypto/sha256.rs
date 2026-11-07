//! SHA-256 (RFC 6234).

use super::wipe;

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub(crate) const BLOCK_LEN: usize = 64;
pub const DIGEST_LEN: usize = 32;
const LEN_OFFSET: usize = BLOCK_LEN - 8;

#[derive(Clone, Copy)]
pub(crate) struct Sha256 {
    state: [u32; 8],
    buffer: super::BlockBuffer<BLOCK_LEN>,
    total_len: u64,
}

impl Sha256 {
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: super::BlockBuffer::new(),
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        self.buffer.absorb(data, |b| Self::process_block(&mut self.state, b));
    }

    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buffer.buf[self.buffer.len] = 0x80;
        self.buffer.buf[self.buffer.len + 1..].fill(0);

        if self.buffer.len >= LEN_OFFSET {
            Self::process_block(&mut self.state, &self.buffer.buf);
            self.buffer.buf.fill(0);
        }

        self.buffer.buf[LEN_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
        Self::process_block(&mut self.state, &self.buffer.buf);

        let mut out = [0u8; DIGEST_LEN];
        for (dst, &s) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            dst.copy_from_slice(&s.to_be_bytes());
        }
        self.wipe();
        out
    }

    /// Clears key-dependent state (e.g. HMAC pads absorbed into it).
    pub(crate) fn wipe(&mut self) {
        wipe(&mut self.state);
        self.buffer.wipe();
    }

    fn process_block(state: &mut [u32; 8], block: &[u8; BLOCK_LEN]) {
        // Rolling 16-word message schedule instead of a 256-byte w[64].
        let mut w = [0u32; 16];
        for (wi, b) in w.iter_mut().zip(block.chunks_exact(4)) {
            *wi = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

        for i in 0..64 {
            if i >= 16 {
                let w15 = w[(i + 1) & 15];
                let w2 = w[(i + 14) & 15];
                let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
                let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
                w[i & 15] = w[i & 15]
                    .wrapping_add(s0)
                    .wrapping_add(w[(i + 9) & 15])
                    .wrapping_add(s1);
            }

            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i & 15]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

pub fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    fn assert_sha256(input: &[u8], expected: [u8; 32]) {
        assert_eq!(sha256(input), expected);
        let mut s = Sha256::new();
        for &b in input {
            s.update(&[b]);
        }
        assert_eq!(s.finalize(), expected);
    }

    #[test]
    fn test_sha256_vector() {
        assert_eq!(
            sha256(b"abc"),
            hex::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn test_sha256_empty() {
        assert_sha256(
            b"",
            hex::<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        );
    }

    #[test]
    fn test_sha256_two_block_padding() {
        // 56-byte message: padding spills into a second block.
        assert_sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            hex::<32>("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        );
    }

    #[test]
    fn test_sha256_million_a_odd_chunks() {
        // Exercises the buffered path with chunk sizes coprime to 64.
        let chunk = [b'a'; 997];
        let mut h = Sha256::new();
        let mut left = 1_000_000usize;
        while left > 0 {
            let n = left.min(chunk.len());
            h.update(&chunk[..n]);
            left -= n;
        }
        assert_eq!(
            h.finalize(),
            hex::<32>("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    #[test]
    fn test_sha256_55_and_64_byte_block_boundaries() {
        // 55-byte input: 55 data bytes + 1 byte delimiter 0x80 + 8 bytes length = 64 bytes (exact single block)
        let input_55 = [b'A'; 55];
        let expected_55 = hex::<32>("8963cc0afd622cc7574ac2011f93a3059b3d65548a77542a1559e3d202e6ab00");
        assert_sha256(&input_55, expected_55);

        // 64-byte input: exactly fills the first block, spilling padding into a second block
        let input_64 = [b'A'; 64];
        let expected_64 = hex::<32>("d53eda7a637c99cc7fb566d96e9fa109bf15c478410a3f5eb4d4c4e26cd081f6");
        assert_sha256(&input_64, expected_64);
    }
}
