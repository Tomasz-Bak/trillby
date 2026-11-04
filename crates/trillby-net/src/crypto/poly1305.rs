//! Poly1305 one-time authenticator (RFC 8439).
//!
//! Radix-2^64 representation: `h = h0 + h1·2^64 + h2·2^128` (h2 is tiny),
//! `r = r0 + r1·2^64`. Products are accumulated in `u128`.

use super::wipe;

#[inline(always)]
fn add_carry_u64(a: u64, b: u64, carry: bool) -> (u64, bool) {
    let (s1, c1) = a.overflowing_add(b);
    let (s2, c2) = s1.overflowing_add(carry as u64);
    (s2, c1 || c2)
}

pub struct Poly1305 {
    r0: u64,
    r1: u64,
    /// `5 * r1 / 4`, used to fold limbs at weight 2^128 and 2^192 back down.
    /// Exact because clamping clears the low 2 bits of r1.
    r1_5_4: u64,
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
        let r0 = u64::from_le_bytes(key[0..8].try_into().unwrap()) & 0x0fff_fffc_0fff_ffff;
        let r1 = u64::from_le_bytes(key[8..16].try_into().unwrap()) & 0x0fff_fffc_0fff_fffc;
        let s0 = u64::from_le_bytes(key[16..24].try_into().unwrap());
        let s1 = u64::from_le_bytes(key[24..32].try_into().unwrap());

        Self {
            r0,
            r1,
            r1_5_4: (r1 >> 2) * 5,
            s0,
            s1,
            h0: 0,
            h1: 0,
            h2: 0,
            buffer: [0u8; 16],
            buf_len: 0,
        }
    }

    /// `h = (h + m + hibit·2^128) · r  mod 2^130 - 5` (partially reduced).
    #[inline(always)]
    fn block(&mut self, m: &[u8; 16], hibit: u64) {
        let m0 = u64::from_le_bytes(m[0..8].try_into().unwrap());
        let m1 = u64::from_le_bytes(m[8..16].try_into().unwrap());

        let (h0, c) = self.h0.overflowing_add(m0);
        let (h1, c) = add_carry_u64(self.h1, m1, c);
        let h2 = self.h2 + c as u64 + hibit;

        let (r0, r1, rr) = (self.r0 as u128, self.r1 as u128, self.r1_5_4 as u128);
        let (h0, h1, h2) = (h0 as u128, h1 as u128, h2 as u128);

        // Bounds: r0,r1 < 2^60, rr < 2^61, h2 <= 6 → no u128 overflow.
        let d0 = h0 * r0 + h1 * rr;
        let d1 = h0 * r1 + h1 * r0 + h2 * rr + (d0 >> 64);
        let d2 = h2 * r0 + (d1 >> 64);

        // Fold bits >= 2^130 back in via 2^130 ≡ 5.
        let c2 = (d2 >> 2) as u64; // < 2^62, so c2·5 fits u64
        let (h0, c) = (d0 as u64).overflowing_add(c2 * 5);
        let (h1, c) = add_carry_u64(d1 as u64, 0, c);

        self.h0 = h0;
        self.h1 = h1;
        self.h2 = (d2 as u64 & 3) + c as u64;
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let needed = 16 - self.buf_len;
            if data.len() < needed {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buffer[self.buf_len..].copy_from_slice(&data[..needed]);
            let b = self.buffer;
            self.block(&b, 1);
            self.buf_len = 0;
            data = &data[needed..];
        }

        let mut blocks = data.chunks_exact(16);
        for b in &mut blocks {
            self.block(b.try_into().unwrap(), 1);
        }

        let rem = blocks.remainder();
        self.buffer[..rem.len()].copy_from_slice(rem);
        self.buf_len = rem.len();
    }

    pub fn finalize(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            let mut b = [0u8; 16];
            b[..self.buf_len].copy_from_slice(&self.buffer[..self.buf_len]);
            b[self.buf_len] = 0x01; // explicit 1-bit, so no implicit 2^128
            self.block(&b, 0);
            wipe(&mut b);
        }

        // Carry h2's excess above 2^130 back into h0.
        let q = self.h2 >> 2;
        let (h0, c) = self.h0.overflowing_add(q * 5);
        let (h1, c) = add_carry_u64(self.h1, 0, c);
        let h2 = (self.h2 & 3) + c as u64;

        // g = h + 5; if g >= 2^130 then h >= p and the result is g mod 2^130.
        let (g0, c) = h0.overflowing_add(5);
        let (g1, c) = add_carry_u64(h1, 0, c);
        let g2 = h2 + c as u64;

        // Constant-time select (no secret-dependent branch).
        let mask = 0u64.wrapping_sub(g2 >> 2);
        let h0 = h0 ^ (mask & (h0 ^ g0));
        let h1 = h1 ^ (mask & (h1 ^ g1));

        // tag = (h + s) mod 2^128
        let (t0, c) = h0.overflowing_add(self.s0);
        let (t1, _) = add_carry_u64(h1, self.s1, c);

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&t0.to_le_bytes());
        tag[8..].copy_from_slice(&t1.to_le_bytes());
        tag
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        wipe(&mut self.r0);
        wipe(&mut self.r1);
        wipe(&mut self.r1_5_4);
        wipe(&mut self.s0);
        wipe(&mut self.s1);
        wipe(&mut self.h0);
        wipe(&mut self.h1);
        wipe(&mut self.h2);
        wipe(&mut self.buffer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;

    fn mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
        let mut p = Poly1305::new(key);
        p.update(msg);
        p.finalize()
    }

    fn rs(r: &str, s: &str) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[..16].copy_from_slice(&hex::<16>(r));
        k[16..].copy_from_slice(&hex::<16>(s));
        k
    }

    #[test]
    fn test_poly1305_rfc8439_2_5_2() {
        let key = hex::<32>(
            "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:\
             01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b",
        );
        assert_eq!(
            mac(&key, b"Cryptographic Forum Research Group"),
            hex::<16>("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9")
        );
    }

    #[test]
    fn test_poly1305_streaming_matches_oneshot() {
        let key = hex::<32>(
            "85d6be7857556d337f4452fe42d506a8 0103808afb0db2fd4abff6af4149f51b",
        );
        let msg = b"Cryptographic Forum Research Group";
        let mut p = Poly1305::new(&key);
        for c in msg.chunks(3) {
            p.update(c);
        }
        assert_eq!(p.finalize(), mac(&key, msg));
    }

    // RFC 8439 Appendix A.3 edge cases for carries and final reduction.
    const ZERO: &str = "00000000000000000000000000000000";
    const ONES: &str = "ffffffffffffffffffffffffffffffff";
    const R1: &str = "01000000000000000000000000000000";
    const R2: &str = "02000000000000000000000000000000";

    #[test]
    fn test_poly1305_a3_5_not_fully_reduced() {
        assert_eq!(mac(&rs(R2, ZERO), &hex::<16>(ONES)), hex::<16>("03000000000000000000000000000000"));
    }

    #[test]
    fn test_poly1305_a3_6_s_overflow() {
        assert_eq!(mac(&rs(R2, ONES), &hex::<16>(R2)), hex::<16>("03000000000000000000000000000000"));
    }

    #[test]
    fn test_poly1305_a3_7_limb_carry() {
        let msg = hex::<48>(
            "ffffffffffffffffffffffffffffffff\
             f0ffffffffffffffffffffffffffffff\
             11000000000000000000000000000000",
        );
        assert_eq!(mac(&rs(R1, ZERO), &msg), hex::<16>("05000000000000000000000000000000"));
    }

    #[test]
    fn test_poly1305_a3_8_exactly_p() {
        let msg = hex::<48>(
            "ffffffffffffffffffffffffffffffff\
             fbfefefefefefefefefefefefefefefe\
             01010101010101010101010101010101",
        );
        assert_eq!(mac(&rs(R1, ZERO), &msg), hex::<16>(ZERO));
    }

    #[test]
    fn test_poly1305_a3_9_p_minus_1() {
        assert_eq!(
            mac(&rs(R2, ZERO), &hex::<16>("fdffffffffffffffffffffffffffffff")),
            hex::<16>("faffffffffffffffffffffffffffffff")
        );
    }

    #[test]
    fn test_poly1305_a3_10_11_131bit() {
        let r = "01000000000000000400000000000000";
        let msg = hex::<64>(
            "e33594d7505e43b90000000000000000\
             3394d7505e4379cd0100000000000000\
             00000000000000000000000000000000\
             01000000000000000000000000000000",
        );
        assert_eq!(mac(&rs(r, ZERO), &msg), hex::<16>("14000000000000005500000000000000"));
        assert_eq!(mac(&rs(r, ZERO), &msg[..48]), hex::<16>("13000000000000000000000000000000"));
    }
}
