//! Zero-allocation #![no_std] Cryptographic Primitives:
//! - SHA-256 (RFC 6234)
//! - HMAC-SHA256 (RFC 2104)
//! - HKDF-SHA256 (RFC 5869)
//! - ChaCha20-Poly1305 AEAD (RFC 8439)

/// Constant-time slice equality comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[inline(always)]
fn add_carry_u64(a: u64, b: u64, carry: bool) -> (u64, bool) {
    let (s1, c1) = a.overflowing_add(b);
    let (s2, c2) = s1.overflowing_add(carry as u64);
    (s2, c1 || c2)
}

// ===========================================================================
// SHA-256 (RFC 6234)
// ===========================================================================

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
        self.total_len += data.len() as u64;

        if self.buf_len > 0 {
            let needed = 64 - self.buf_len;
            if data.len() >= needed {
                self.buffer[self.buf_len..64].copy_from_slice(&data[..needed]);
                let block = self.buffer;
                Self::process_block(&mut self.state, &block);
                self.buf_len = 0;
                data = &data[needed..];
            } else {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            Self::process_block(&mut self.state, &block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            self.buffer[self.buf_len..64].fill(0);
            let block = self.buffer;
            Self::process_block(&mut self.state, &block);
            self.buf_len = 0;
        }

        self.buffer[self.buf_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        Self::process_block(&mut self.state, &block);

        let mut out = [0u8; 32];
        for (i, &s) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&s.to_be_bytes());
        }
        out
    }

    fn process_block(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
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

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

// ===========================================================================
// HMAC-SHA256 (RFC 2104)
// ===========================================================================

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_pad = [0u8; 64];
    if key.len() > 64 {
        let hashed_k = sha256(key);
        k_pad[..32].copy_from_slice(&hashed_k);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = k_pad[i] ^ 0x36;
        opad[i] = k_pad[i] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

// ===========================================================================
// HKDF-SHA256 (RFC 5869)
// ===========================================================================

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), ()> {
    if out.len() > 255 * 32 {
        return Err(());
    }

    let mut t = [0u8; 32];
    let mut t_len = 0;
    let mut counter = 1u8;
    let mut written = 0;

    while written < out.len() {
        let mut step = Sha256::new();
        let mut k_pad = [0u8; 64];
        k_pad[..32].copy_from_slice(prk);

        let mut ipad = [0u8; 64];
        let mut opad = [0u8; 64];
        for i in 0..64 {
            ipad[i] = k_pad[i] ^ 0x36;
            opad[i] = k_pad[i] ^ 0x5c;
        }

        step.update(&ipad);
        if t_len > 0 {
            step.update(&t);
        }
        step.update(info);
        step.update(&[counter]);
        let inner_hash = step.finalize();

        let mut outer = Sha256::new();
        outer.update(&opad);
        outer.update(&inner_hash);
        t = outer.finalize();
        t_len = 32;

        let to_copy = (out.len() - written).min(32);
        out[written..written + to_copy].copy_from_slice(&t[..to_copy]);
        written += to_copy;
        counter += 1;
    }

    Ok(())
}

// ===========================================================================
// ChaCha20 (RFC 8439)
// ===========================================================================

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

pub fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8; 64]) {
    let state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter,
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];

    let mut working = state;

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

    for i in 0..16 {
        let val = working[i].wrapping_add(state[i]);
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
}

pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], mut counter: u32, buf: &mut [u8]) {
    let mut block = [0u8; 64];
    let mut offset = 0;

    while offset < buf.len() {
        chacha20_block(key, nonce, counter, &mut block);
        let rem = buf.len() - offset;
        let to_xor = rem.min(64);
        for i in 0..to_xor {
            buf[offset + i] ^= block[i];
        }
        offset += to_xor;
        counter = counter.wrapping_add(1);
    }
}

// ===========================================================================
// Poly1305 (RFC 8439)
// ===========================================================================

pub struct Poly1305 {
    r0: u64,
    r1: u64,
    s0: u64,
    s1: u64,
    h0: u64,
    h1: u64,
    h2: u64,
    buffer: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[..16]);
        // Clamping r
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;

        let r0 = u64::from_le_bytes(r_bytes[0..8].try_into().unwrap());
        let r1 = u64::from_le_bytes(r_bytes[8..16].try_into().unwrap());

        let s0 = u64::from_le_bytes(key[16..24].try_into().unwrap());
        let s1 = u64::from_le_bytes(key[24..32].try_into().unwrap());

        Self {
            r0,
            r1,
            s0,
            s1,
            h0: 0,
            h1: 0,
            h2: 0,
            buffer: [0u8; 16],
            buf_len: 0,
        }
    }

    fn process_block(&mut self, block: &[u8]) {
        let mut padded = [0u8; 16];
        padded[..block.len()].copy_from_slice(block);

        let m0 = u64::from_le_bytes(padded[0..8].try_into().unwrap());
        let m1 = u64::from_le_bytes(padded[8..16].try_into().unwrap());

        // h += m
        let (h0, carry0) = self.h0.overflowing_add(m0);
        let (h1, carry1) = add_carry_u64(self.h1, m1, carry0);
        let h2 = self.h2 + 1 + (carry1 as u64);

        // h *= r (modulo 2^130 - 5)
        let r1_5 = self.r1.wrapping_mul(5);

        let d0 = (h0 as u128) * (self.r0 as u128) + (h1 as u128) * (r1_5 as u128);
        let d1 = (h0 as u128) * (self.r1 as u128) + (h1 as u128) * (self.r0 as u128);
        let d2 = (h2 as u128) * (self.r0 as u128);
        let d2_extra = (h2 as u128) * (r1_5 as u128);

        let c0 = (d0 >> 64) as u64;
        let l0 = d0 as u64;

        let d1_tot = d1 + (c0 as u128) + d2_extra;
        let c1 = (d1_tot >> 64) as u64;
        let l1 = d1_tot as u64;

        let d2_tot = d2 + (c1 as u128);
        let l2 = (d2_tot & 3) as u64;
        let c2 = (d2_tot >> 2) as u64;

        let (h0_final, c_fold) = l0.overflowing_add(c2.wrapping_mul(5));
        let (h1_final, c_fold2) = add_carry_u64(l1, 0, c_fold);
        let h2_final = l2 + (c_fold2 as u64);

        self.h0 = h0_final;
        self.h1 = h1_final;
        self.h2 = h2_final;
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let needed = 16 - self.buf_len;
            if data.len() >= needed {
                self.buffer[self.buf_len..16].copy_from_slice(&data[..needed]);
                let block = self.buffer;
                self.process_block(&block);
                self.buf_len = 0;
                data = &data[needed..];
            } else {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
        }

        while data.len() >= 16 {
            self.process_block(&data[..16]);
            data = &data[16..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            let rem = self.buf_len;
            let mut block = [0u8; 16];
            block[..rem].copy_from_slice(&self.buffer[..rem]);
            block[rem] = 0x01; // Append the 1-bit per RFC 8439
            self.process_block_final(&block);
        }

        // Full reduction modulo 2^130 - 5
        let mut h0 = self.h0;
        let mut h1 = self.h1;
        let mut h2 = self.h2;

        let q = h2 >> 2;
        h2 &= 3;
        let (h0_t, c0) = h0.overflowing_add(q.wrapping_mul(5));
        let (h1_t, c1) = add_carry_u64(h1, 0, c0);
        h2 += c1 as u64;

        // If h >= 2^130 - 5, subtract 2^130 - 5
        let (h0_sub, c0_sub) = h0_t.overflowing_add(5);
        let (h1_sub, c1_sub) = add_carry_u64(h1_t, 0, c0_sub);
        let h2_sub = h2.wrapping_add(c1_sub as u64);

        if (h2_sub >> 2) > 0 {
            h0 = h0_sub;
            h1 = h1_sub;
        } else {
            h0 = h0_t;
            h1 = h1_t;
        }

        // Add s (modulo 2^128)
        let (out0, c_s) = h0.overflowing_add(self.s0);
        let (out1, _) = add_carry_u64(h1, self.s1, c_s);

        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&out0.to_le_bytes());
        tag[8..16].copy_from_slice(&out1.to_le_bytes());
        tag
    }

    fn process_block_final(&mut self, block: &[u8; 16]) {
        let m0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let m1 = u64::from_le_bytes(block[8..16].try_into().unwrap());

        let (h0, carry0) = self.h0.overflowing_add(m0);
        let (h1, carry1) = add_carry_u64(self.h1, m1, carry0);
        let h2 = self.h2 + (carry1 as u64); // No +1 because the 1-bit is already inside block[rem]

        let r1_5 = self.r1.wrapping_mul(5);

        let d0 = (h0 as u128) * (self.r0 as u128) + (h1 as u128) * (r1_5 as u128);
        let d1 = (h0 as u128) * (self.r1 as u128) + (h1 as u128) * (self.r0 as u128);
        let d2 = (h2 as u128) * (self.r0 as u128);
        let d2_extra = (h2 as u128) * (r1_5 as u128);

        let c0 = (d0 >> 64) as u64;
        let l0 = d0 as u64;

        let d1_tot = d1 + (c0 as u128) + d2_extra;
        let c1 = (d1_tot >> 64) as u64;
        let l1 = d1_tot as u64;

        let d2_tot = d2 + (c1 as u128);
        let l2 = (d2_tot & 3) as u64;
        let c2 = (d2_tot >> 2) as u64;

        let (h0_final, c_fold) = l0.overflowing_add(c2.wrapping_mul(5));
        let (h1_final, c_fold2) = add_carry_u64(l1, 0, c_fold);
        let h2_final = l2 + (c_fold2 as u64);

        self.h0 = h0_final;
        self.h1 = h1_final;
        self.h2 = h2_final;
    }
}

// ===========================================================================
// ChaCha20-Poly1305 AEAD (RFC 8439)
// ===========================================================================

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
    let mut poly_key_block = [0u8; 64];
    chacha20_block(key, nonce, 0, &mut poly_key_block);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    // 2. Encrypt plaintext in place (starting at counter 1)
    chacha20_xor(key, nonce, 1, &mut plaintext_and_tag[..pt_len]);

    // 3. Compute Poly1305 tag over AAD || pad || Ciphertext || pad || len(AAD) || len(Ciphertext)
    let mut poly = Poly1305::new(&poly_key);

    poly.update(aad);
    if aad.len() % 16 != 0 {
        let pad = [0u8; 16];
        poly.update(&pad[..16 - (aad.len() % 16)]);
    }

    poly.update(&plaintext_and_tag[..pt_len]);
    if pt_len % 16 != 0 {
        let pad = [0u8; 16];
        poly.update(&pad[..16 - (pt_len % 16)]);
    }

    poly.update(&(aad.len() as u64).to_le_bytes());
    poly.update(&(pt_len as u64).to_le_bytes());

    let tag = poly.finalize();
    plaintext_and_tag[pt_len..pt_len + 16].copy_from_slice(&tag);
    Ok(())
}

pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &mut [u8],
) -> Result<usize, ()> {
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
        let pad = [0u8; 16];
        poly.update(&pad[..16 - (aad.len() % 16)]);
    }

    poly.update(&ciphertext_and_tag[..ct_len]);
    if ct_len % 16 != 0 {
        let pad = [0u8; 16];
        poly.update(&pad[..16 - (ct_len % 16)]);
    }

    poly.update(&(aad.len() as u64).to_le_bytes());
    poly.update(&(ct_len as u64).to_le_bytes());

    let expected_tag = poly.finalize();
    let actual_tag = &ciphertext_and_tag[ct_len..ct_len + 16];

    if !constant_time_eq(&expected_tag, actual_tag) {
        return Err(());
    }

    // 3. Decrypt ciphertext in place
    chacha20_xor(key, nonce, 1, &mut ciphertext_and_tag[..ct_len]);
    Ok(ct_len)
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &info, &mut okm).unwrap();
        assert_eq!(
            &okm[..16],
            &[
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
                0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a
            ]
        );
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
}
