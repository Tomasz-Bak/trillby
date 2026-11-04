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

#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let needed = 64 - self.buf_len;
            if data.len() < needed {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buffer[self.buf_len..].copy_from_slice(&data[..needed]);
            Self::process_block(&mut self.state, &self.buffer);
            self.buf_len = 0;
            data = &data[needed..];
        }

        // Full blocks straight from the input, no staging copy.
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            Self::process_block(&mut self.state, block.try_into().unwrap());
        }

        let rem = blocks.remainder();
        self.buffer[..rem.len()].copy_from_slice(rem);
        self.buf_len = rem.len();
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buffer[self.buf_len] = 0x80;
        self.buffer[self.buf_len + 1..].fill(0);

        if self.buf_len >= 56 {
            Self::process_block(&mut self.state, &self.buffer);
            self.buffer.fill(0);
        }

        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());
        Self::process_block(&mut self.state, &self.buffer);

        let mut out = [0u8; 32];
        for (dst, &s) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            dst.copy_from_slice(&s.to_be_bytes());
        }
        self.wipe();
        out
    }

    /// Clears key-dependent state (e.g. HMAC pads absorbed into it).
    pub(crate) fn wipe(&mut self) {
        wipe(&mut self.state);
        wipe(&mut self.buffer);
    }

    fn process_block(state: &mut [u32; 8], block: &[u8; 64]) {
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

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    #[test]
    fn test_sha256_vector() {
        let hash = sha256(b"abc");
        assert_eq!(
            hash,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    #[test]
    fn test_sha256_empty() {
        assert_eq!(
            sha256(b""),
            hex::<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn test_sha256_two_block_padding() {
        // 56-byte message: padding spills into a second block.
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex::<32>("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
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
}
