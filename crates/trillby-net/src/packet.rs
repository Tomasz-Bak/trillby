//! Binary Packed Frame Layout & Zero-Allocation Payloads
//!
//! All integer fields are encoded as Little-Endian.
//! The 16-byte FrameHeader serves as the Associated Authenticated Data (AAD)
//! for ChaCha20-Poly1305.

use crate::crypto::{
    chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, constant_time_eq,
    hkdf_expand, hkdf_extract, hmac_sha256, sha256,
};

pub const FRAME_MAGIC: [u8; 2] = [0x54, 0x52]; // "TR"
pub const PROTOCOL_VERSION: u8 = 0x01;
pub const HEADER_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const HMAC_TAG_LEN: usize = 32;
pub const MAX_PAYLOAD_LEN: u16 = 240;
pub const MAX_FRAME_LEN: usize = HEADER_LEN + (MAX_PAYLOAD_LEN as usize); // 256 bytes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    InvalidMagic,
    UnsupportedVersion,
    UnknownMsgType,
    BufferTooShort,
    PayloadTooLarge,
    DecryptionFailed,
    AuthenticationFailed,
    InvalidPayload,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    HandshakeInit = 0x01,
    HandshakeResp = 0x02,
    Rekey         = 0x03,
    Heartbeat     = 0x10,
    Ack           = 0x11,
    AuthInit      = 0x20,
    AuthResp      = 0x21,
    Data          = 0x30,
}

impl TryFrom<u8> for MsgType {
    type Error = PacketError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x01 => Ok(MsgType::HandshakeInit),
            0x02 => Ok(MsgType::HandshakeResp),
            0x03 => Ok(MsgType::Rekey),
            0x10 => Ok(MsgType::Heartbeat),
            0x11 => Ok(MsgType::Ack),
            0x20 => Ok(MsgType::AuthInit),
            0x21 => Ok(MsgType::AuthResp),
            0x30 => Ok(MsgType::Data),
            _ => Err(PacketError::UnknownMsgType),
        }
    }
}

// ===========================================================================
// Zero-Allocation Sequential Byte Codec
// ===========================================================================

/// A zero-allocation, sequential byte writer over a mutable slice.
#[derive(Debug)]
pub struct ByteWriter<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> ByteWriter<'a> {
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    #[inline]
    pub fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    #[inline]
    pub fn write_u8(&mut self, val: u8) -> Result<(), PacketError> {
        if self.remaining() < 1 {
            return Err(PacketError::BufferTooShort);
        }
        self.buf[self.offset] = val;
        self.offset += 1;
        Ok(())
    }

    #[inline]
    pub fn write_i8(&mut self, val: i8) -> Result<(), PacketError> {
        self.write_u8(val as u8)
    }

    #[inline]
    pub fn write_u16_le(&mut self, val: u16) -> Result<(), PacketError> {
        self.write_bytes(&val.to_le_bytes())
    }

    #[inline]
    pub fn write_u32_le(&mut self, val: u32) -> Result<(), PacketError> {
        self.write_bytes(&val.to_le_bytes())
    }

    #[inline]
    pub fn write_u64_le(&mut self, val: u64) -> Result<(), PacketError> {
        self.write_bytes(&val.to_le_bytes())
    }

    #[inline]
    pub fn write_bytes(&mut self, src: &[u8]) -> Result<(), PacketError> {
        if self.remaining() < src.len() {
            return Err(PacketError::BufferTooShort);
        }
        self.buf[self.offset..self.offset + src.len()].copy_from_slice(src);
        self.offset += src.len();
        Ok(())
    }
}

/// A zero-allocation, sequential byte reader over an immutable slice.
#[derive(Debug)]
pub struct ByteReader<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    #[inline]
    pub fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    #[inline]
    pub fn read_u8(&mut self) -> Result<u8, PacketError> {
        if self.remaining() < 1 {
            return Err(PacketError::BufferTooShort);
        }
        let b = self.buf[self.offset];
        self.offset += 1;
        Ok(b)
    }

    #[inline]
    pub fn read_i8(&mut self) -> Result<i8, PacketError> {
        self.read_u8().map(|b| b as i8)
    }

    #[inline]
    pub fn read_u16_le(&mut self) -> Result<u16, PacketError> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    #[inline]
    pub fn read_u32_le(&mut self) -> Result<u32, PacketError> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    #[inline]
    pub fn read_u64_le(&mut self) -> Result<u64, PacketError> {
        let bytes = self.read_array::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    #[inline]
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], PacketError> {
        if self.remaining() < N {
            return Err(PacketError::BufferTooShort);
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&self.buf[self.offset..self.offset + N]);
        self.offset += N;
        Ok(arr)
    }

    #[inline]
    pub fn read_slice(&mut self, len: usize) -> Result<&'a [u8], PacketError> {
        if self.remaining() < len {
            return Err(PacketError::BufferTooShort);
        }
        let slice = &self.buf[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub msg_type: MsgType,
    pub session_id: u32,
    pub seq_num: u32,
    /// Length of ciphertext + 16-byte Poly1305 MAC tag
    pub payload_len: u16,
    pub flags: u16,
}

impl FrameHeader {
    pub fn new(msg_type: MsgType, session_id: u32, seq_num: u32, payload_len: u16) -> Self {
        Self {
            msg_type,
            session_id,
            seq_num,
            payload_len,
            flags: 0,
        }
    }

    pub fn encode(&self, out: &mut [u8; HEADER_LEN]) {
        let mut w = ByteWriter::new(out);
        let _ = w.write_bytes(&FRAME_MAGIC);
        let _ = w.write_u8(PROTOCOL_VERSION);
        let _ = w.write_u8(self.msg_type as u8);
        let _ = w.write_u32_le(self.session_id);
        let _ = w.write_u32_le(self.seq_num);
        let _ = w.write_u16_le(self.payload_len);
        let _ = w.write_u16_le(self.flags);
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < HEADER_LEN {
            return Err(PacketError::BufferTooShort);
        }
        let mut r = ByteReader::new(bytes);
        let magic = r.read_array::<2>()?;
        if magic != FRAME_MAGIC {
            return Err(PacketError::InvalidMagic);
        }
        let version = r.read_u8()?;
        if version != PROTOCOL_VERSION {
            return Err(PacketError::UnsupportedVersion);
        }
        let msg_type = MsgType::try_from(r.read_u8()?)?;
        let session_id = r.read_u32_le()?;
        let seq_num = r.read_u32_le()?;
        let payload_len = r.read_u16_le()?;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(PacketError::PayloadTooLarge);
        }
        let flags = r.read_u16_le()?;

        Ok(Self {
            msg_type,
            session_id,
            seq_num,
            payload_len,
            flags,
        })
    }

    /// Derive standard 12-byte AEAD nonce: [salt (4B) || session_id (4B) || seq_num (4B)]
    pub fn derive_nonce(&self, salt: &[u8; 4]) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        let mut w = ByteWriter::new(&mut nonce);
        let _ = w.write_bytes(salt);
        let _ = w.write_u32_le(self.session_id);
        let _ = w.write_u32_le(self.seq_num);
        nonce
    }
}

// ===========================================================================
// Specific Payloads
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeInitPayload {
    pub client_nonce: [u8; 32],
    pub device_uuid: [u8; 16],
}

impl HandshakeInitPayload {
    pub const LEN: usize = 48;

    pub fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        let mut w = ByteWriter::new(out);
        w.write_bytes(&self.client_nonce)?;
        w.write_bytes(&self.device_uuid)?;
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        let mut r = ByteReader::new(bytes);
        let client_nonce = r.read_array::<32>()?;
        let device_uuid = r.read_array::<16>()?;
        Ok(Self { client_nonce, device_uuid })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeRespPayload {
    pub server_nonce: [u8; 32],
    pub assigned_session_id: u32,
    pub session_salt: [u8; 4],
}

impl HandshakeRespPayload {
    pub const LEN: usize = 40;

    pub fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        let mut w = ByteWriter::new(out);
        w.write_bytes(&self.server_nonce)?;
        w.write_u32_le(self.assigned_session_id)?;
        w.write_bytes(&self.session_salt)?;
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        let mut r = ByteReader::new(bytes);
        let server_nonce = r.read_array::<32>()?;
        let assigned_session_id = r.read_u32_le()?;
        let session_salt = r.read_array::<4>()?;
        Ok(Self {
            server_nonce,
            assigned_session_id,
            session_salt,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthInitPayload {
    pub auth_data_len: u8,
    pub auth_data: [u8; 32],
    pub timestamp_ms: u64,
}

impl AuthInitPayload {
    pub const LEN: usize = 41; // 1 + 32 + 8

    pub fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        let mut w = ByteWriter::new(out);
        w.write_u8(self.auth_data_len)?;
        w.write_bytes(&self.auth_data)?;
        w.write_u64_le(self.timestamp_ms)?;
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        let mut r = ByteReader::new(bytes);
        let auth_data_len = r.read_u8()?;
        let auth_data = r.read_array::<32>()?;
        let timestamp_ms = r.read_u64_le()?;
        Ok(Self {
            auth_data_len,
            auth_data,
            timestamp_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRespPayload {
    pub status: u8,
    pub role: u8,
    pub session_ttl_s: u32,
}

impl AuthRespPayload {
    pub const LEN: usize = 6; // 1 + 1 + 4

    pub fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        let mut w = ByteWriter::new(out);
        w.write_u8(self.status)?;
        w.write_u8(self.role)?;
        w.write_u32_le(self.session_ttl_s)?;
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        let mut r = ByteReader::new(bytes);
        let status = r.read_u8()?;
        let role = r.read_u8()?;
        let session_ttl_s = r.read_u32_le()?;
        Ok(Self {
            status,
            role,
            session_ttl_s,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatPayload {
    pub battery_pct: u8,
    pub rssi: i8,
    pub pending_outbox: u16,
    pub uptime_s: u32,
}

impl HeartbeatPayload {
    pub const LEN: usize = 8; // 1 + 1 + 2 + 4

    pub fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        let mut w = ByteWriter::new(out);
        w.write_u8(self.battery_pct)?;
        w.write_i8(self.rssi)?;
        w.write_u16_le(self.pending_outbox)?;
        w.write_u32_le(self.uptime_s)?;
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        let mut r = ByteReader::new(bytes);
        let battery_pct = r.read_u8()?;
        let rssi = r.read_i8()?;
        let pending_outbox = r.read_u16_le()?;
        let uptime_s = r.read_u32_le()?;
        Ok(Self {
            battery_pct,
            rssi,
            pending_outbox,
            uptime_s,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckPayload {
    pub acked_seq: u32,
    pub status: u8,
}

impl AckPayload {
    pub const LEN: usize = 5;

    pub fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        let mut w = ByteWriter::new(out);
        w.write_u32_le(self.acked_seq)?;
        w.write_u8(self.status)?;
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        let mut r = ByteReader::new(bytes);
        let acked_seq = r.read_u32_le()?;
        let status = r.read_u8()?;
        Ok(Self { acked_seq, status })
    }
}

// ===========================================================================
// Key Derivation & Nonce Helpers
// ===========================================================================

pub const SESSION_KEY_INFO: &[u8] = b"TRILLBY_SESSION_KEY_V1";

/// Derive the symmetric session key using HKDF-SHA256 (RFC 5869):
/// PRK = HKDF-Extract(salt = client_nonce || server_nonce || session_salt, IKM = psk)
/// Key = HKDF-Expand(PRK, "TRILLBY_SESSION_KEY_V1", 32)
pub fn derive_session_key(
    psk: &[u8; 32],
    salt: &[u8; 4],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut nonce_salt = [0u8; 68];
    let mut w = ByteWriter::new(&mut nonce_salt);
    let _ = w.write_bytes(client_nonce);
    let _ = w.write_bytes(server_nonce);
    let _ = w.write_bytes(salt);

    let prk = hkdf_extract(&nonce_salt, psk);
    let mut key = [0u8; 32];
    let _ = hkdf_expand(&prk, SESSION_KEY_INFO, &mut key);
    key
}

/// Assemble and HMAC-authenticate an unencrypted handshake frame.
/// Returns total frame length (16-byte header + payload + 32-byte HMAC-SHA256 tag).
pub fn pack_and_authenticate_hmac(
    key: &[u8; 32],
    msg_type: MsgType,
    session_id: u32,
    seq_num: u32,
    payload: &[u8],
    frame_buf: &mut [u8],
) -> Result<usize, PacketError> {
    let payload_len = payload.len() + HMAC_TAG_LEN;
    let total_len = HEADER_LEN + payload_len;
    if total_len > frame_buf.len() || payload_len > (MAX_PAYLOAD_LEN as usize) {
        return Err(PacketError::PayloadTooLarge);
    }

    let header = FrameHeader::new(msg_type, session_id, seq_num, payload_len as u16);
    let mut header_bytes = [0u8; HEADER_LEN];
    header.encode(&mut header_bytes);

    frame_buf[..HEADER_LEN].copy_from_slice(&header_bytes);
    frame_buf[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);

    let tag = hmac_sha256(key, &frame_buf[..HEADER_LEN + payload.len()]);
    frame_buf[HEADER_LEN + payload.len()..total_len].copy_from_slice(&tag);

    Ok(total_len)
}

/// Verify HMAC-SHA256 authentication and unpack an unencrypted handshake frame.
/// Returns (FrameHeader, payload_slice).
pub fn verify_and_unpack_hmac<'a>(
    key: &[u8; 32],
    frame_buf: &'a [u8],
) -> Result<(FrameHeader, &'a [u8]), PacketError> {
    if frame_buf.len() < HEADER_LEN + HMAC_TAG_LEN {
        return Err(PacketError::BufferTooShort);
    }

    let header = FrameHeader::decode(&frame_buf[..HEADER_LEN])?;
    let expected_payload_len = header.payload_len as usize;
    if frame_buf.len() < HEADER_LEN + expected_payload_len || expected_payload_len < HMAC_TAG_LEN {
        return Err(PacketError::BufferTooShort);
    }

    let data_len = expected_payload_len - HMAC_TAG_LEN;
    let authenticated_len = HEADER_LEN + data_len;
    let expected_tag = hmac_sha256(key, &frame_buf[..authenticated_len]);
    let received_tag = &frame_buf[authenticated_len..HEADER_LEN + expected_payload_len];

    if !constant_time_eq(&expected_tag, received_tag) {
        return Err(PacketError::AuthenticationFailed);
    }

    Ok((header, &frame_buf[HEADER_LEN..authenticated_len]))
}

/// Generate a pseudo-random client nonce derived from PSK + device UUID + monotonic timestamp:
/// SHA-256(PSK || UUID || timestamp_ms)
pub fn generate_client_nonce(
    psk: &[u8; 32],
    device_uuid: &[u8; 16],
    timestamp_ms: u64,
) -> [u8; 32] {
    let mut prk_input = [0u8; 64];
    let mut w = ByteWriter::new(&mut prk_input);
    let _ = w.write_bytes(psk);
    let _ = w.write_bytes(device_uuid);
    let _ = w.write_u64_le(timestamp_ms);
    sha256(&prk_input)
}

// ===========================================================================
// Full Frame Serialization & In-Place AEAD Encryption
// ===========================================================================

/// Assemble and encrypt a packet frame into `frame_buf`.
/// Returns total frame length (16-byte header + ciphertext + 16-byte MAC tag).
pub fn pack_and_encrypt(
    key: &[u8; 32],
    salt: &[u8; 4],
    msg_type: MsgType,
    session_id: u32,
    seq_num: u32,
    plaintext: &[u8],
    frame_buf: &mut [u8],
) -> Result<usize, PacketError> {
    let payload_len = plaintext.len() + TAG_LEN;
    let total_len = HEADER_LEN + payload_len;
    if total_len > frame_buf.len() || payload_len > (MAX_PAYLOAD_LEN as usize) {
        return Err(PacketError::PayloadTooLarge);
    }

    let header = FrameHeader::new(msg_type, session_id, seq_num, payload_len as u16);
    let mut header_bytes = [0u8; HEADER_LEN];
    header.encode(&mut header_bytes);

    frame_buf[..HEADER_LEN].copy_from_slice(&header_bytes);
    frame_buf[HEADER_LEN..HEADER_LEN + plaintext.len()].copy_from_slice(plaintext);

    let nonce = header.derive_nonce(salt);
    let pt_and_tag = &mut frame_buf[HEADER_LEN..total_len];

    chacha20_poly1305_encrypt(key, &nonce, &header_bytes, pt_and_tag)
        .map_err(|_| PacketError::PayloadTooLarge)?;

    Ok(total_len)
}

/// Verify MAC and decrypt an incoming frame in place.
/// Returns (FrameHeader, plaintext_slice).
pub fn decrypt_and_unpack<'a>(
    key: &[u8; 32],
    salt: &[u8; 4],
    frame_buf: &'a mut [u8],
) -> Result<(FrameHeader, &'a [u8]), PacketError> {
    if frame_buf.len() < HEADER_LEN + TAG_LEN {
        return Err(PacketError::BufferTooShort);
    }

    let (header_slice, rest) = frame_buf.split_at_mut(HEADER_LEN);
    let header = FrameHeader::decode(header_slice)?;

    let expected_payload_len = header.payload_len as usize;
    if rest.len() < expected_payload_len || expected_payload_len < TAG_LEN {
        return Err(PacketError::BufferTooShort);
    }

    let nonce = header.derive_nonce(salt);
    let ct_and_tag = &mut rest[..expected_payload_len];

    let pt_len = chacha20_poly1305_decrypt(key, &nonce, header_slice, ct_and_tag)
        .map_err(|_| PacketError::DecryptionFailed)?;

    Ok((header, &rest[..pt_len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let hdr = FrameHeader::new(MsgType::Data, 0x12345678, 42, 64);
        let mut bytes = [0u8; HEADER_LEN];
        hdr.encode(&mut bytes);
        let decoded = FrameHeader::decode(&bytes).unwrap();
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn test_pack_and_encrypt_round_trip() {
        let key = [0x55u8; 32];
        let salt = [0x11, 0x22, 0x33, 0x44];
        let mut frame_buf = [0u8; 256];

        let plaintext = b"APPLICATION_LEVEL_PAYLOAD_BYTES";

        let total_frame_len = pack_and_encrypt(
            &key,
            &salt,
            MsgType::Data,
            100,
            1,
            plaintext,
            &mut frame_buf,
        ).unwrap();

        assert_eq!(total_frame_len, HEADER_LEN + plaintext.len() + TAG_LEN);

        // Decrypt
        let (hdr, decrypted_pt) = decrypt_and_unpack(
            &key,
            &salt,
            &mut frame_buf[..total_frame_len],
        ).unwrap();

        assert_eq!(hdr.msg_type, MsgType::Data);
        assert_eq!(hdr.seq_num, 1);
        assert_eq!(decrypted_pt, plaintext);
    }

    #[test]
    fn test_tampered_frame_rejected() {
        let key = [0x55u8; 32];
        let salt = [0x11, 0x22, 0x33, 0x44];
        let mut frame_buf = [0u8; 256];

        let pt = b"TOP_SECRET_PAYLOAD";
        let total_len = pack_and_encrypt(
            &key,
            &salt,
            MsgType::AuthInit,
            1,
            1,
            pt,
            &mut frame_buf,
        ).unwrap();

        // Tamper with sequence number in header (AAD)
        frame_buf[8] ^= 0x01;
        assert_eq!(
            decrypt_and_unpack(&key, &salt, &mut frame_buf[..total_len]),
            Err(PacketError::DecryptionFailed)
        );
    }

    #[test]
    fn test_byte_writer_reader_round_trip() {
        let mut buf = [0u8; 32];
        let written_len = {
            let mut w = ByteWriter::new(&mut buf);
            assert_eq!(w.offset(), 0);
            assert_eq!(w.remaining(), 32);

            w.write_u8(0xAA).unwrap();
            w.write_i8(-42).unwrap();
            w.write_u16_le(0xBEEF).unwrap();
            w.write_u32_le(0x12345678).unwrap();
            w.write_u64_le(0xDEADBEEFCAFE1234).unwrap();
            w.write_bytes(b"HELLO").unwrap();

            w.offset()
        };
        assert_eq!(written_len, 1 + 1 + 2 + 4 + 8 + 5);

        let mut r = ByteReader::new(&buf[..written_len]);
        assert_eq!(r.read_u8().unwrap(), 0xAA);
        assert_eq!(r.read_i8().unwrap(), -42);
        assert_eq!(r.read_u16_le().unwrap(), 0xBEEF);
        assert_eq!(r.read_u32_le().unwrap(), 0x12345678);
        assert_eq!(r.read_u64_le().unwrap(), 0xDEADBEEFCAFE1234);
        assert_eq!(r.read_slice(5).unwrap(), b"HELLO");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn test_byte_writer_overflow_and_reader_underflow() {
        let mut buf = [0u8; 3];
        let mut w = ByteWriter::new(&mut buf);
        w.write_u16_le(0x1234).unwrap();
        assert_eq!(w.write_u16_le(0x5678), Err(PacketError::BufferTooShort));

        let mut r = ByteReader::new(&buf[..2]);
        assert_eq!(r.read_u16_le().unwrap(), 0x1234);
        assert_eq!(r.read_u8(), Err(PacketError::BufferTooShort));
    }

    #[test]
    fn test_payloads_round_trip() {
        // HandshakeInitPayload
        let init = HandshakeInitPayload {
            client_nonce: [0x11u8; 32],
            device_uuid: [0x22u8; 16],
        };
        let mut init_buf = [0u8; HandshakeInitPayload::LEN];
        init.encode(&mut init_buf).unwrap();
        assert_eq!(HandshakeInitPayload::decode(&init_buf).unwrap(), init);

        // HandshakeRespPayload
        let resp = HandshakeRespPayload {
            server_nonce: [0x33u8; 32],
            assigned_session_id: 0x99887766,
            session_salt: [0x12, 0x34, 0x56, 0x78],
        };
        let mut resp_buf = [0u8; HandshakeRespPayload::LEN];
        resp.encode(&mut resp_buf).unwrap();
        assert_eq!(HandshakeRespPayload::decode(&resp_buf).unwrap(), resp);

        // AuthInitPayload
        let auth_init = AuthInitPayload {
            auth_data: [0x55u8; 32],
            auth_data_len: 16,
            timestamp_ms: 1728000000000,
        };
        let mut auth_init_buf = [0u8; AuthInitPayload::LEN];
        auth_init.encode(&mut auth_init_buf).unwrap();
        assert_eq!(AuthInitPayload::decode(&auth_init_buf).unwrap(), auth_init);

        // AuthRespPayload
        let auth_resp = AuthRespPayload {
            status: 0,
            role: 2,
            session_ttl_s: 3600,
        };
        let mut auth_resp_buf = [0u8; AuthRespPayload::LEN];
        auth_resp.encode(&mut auth_resp_buf).unwrap();
        assert_eq!(AuthRespPayload::decode(&auth_resp_buf).unwrap(), auth_resp);

        // HeartbeatPayload
        let hb = HeartbeatPayload {
            battery_pct: 88,
            rssi: -65,
            pending_outbox: 3,
            uptime_s: 3600,
        };
        let mut hb_buf = [0u8; HeartbeatPayload::LEN];
        hb.encode(&mut hb_buf).unwrap();
        assert_eq!(HeartbeatPayload::decode(&hb_buf).unwrap(), hb);

        // AckPayload
        let ack = AckPayload {
            acked_seq: 42,
            status: 0,
        };
        let mut ack_buf = [0u8; AckPayload::LEN];
        ack.encode(&mut ack_buf).unwrap();
        assert_eq!(AckPayload::decode(&ack_buf).unwrap(), ack);
    }

    #[test]
    fn test_derive_session_key_and_client_nonce() {
        let psk = [0x55u8; 32];
        let uuid = [0x77u8; 16];
        let nonce = generate_client_nonce(&psk, &uuid, 1000);
        assert_ne!(nonce, [0u8; 32]);

        let server_nonce = [0x88u8; 32];
        let salt = [1, 2, 3, 4];
        let key1 = derive_session_key(&psk, &salt, &nonce, &server_nonce);
        let key2 = derive_session_key(&psk, &salt, &nonce, &server_nonce);
        assert_eq!(key1, key2);
        assert_ne!(key1, [0u8; 32]);

        // Different PSK produces completely different session key
        let diff_psk = [0x56u8; 32];
        let diff_key = derive_session_key(&diff_psk, &salt, &nonce, &server_nonce);
        assert_ne!(key1, diff_key);
    }

    #[test]
    fn test_hmac_handshake_round_trip_and_tamper() {
        let key = [0x42u8; 32];
        let init = HandshakeInitPayload {
            client_nonce: [0x11u8; 32],
            device_uuid: [0x22u8; 16],
        };
        let mut pt_buf = [0u8; HandshakeInitPayload::LEN];
        init.encode(&mut pt_buf).unwrap();

        let mut frame_buf = [0u8; MAX_FRAME_LEN];
        let len = pack_and_authenticate_hmac(
            &key,
            MsgType::HandshakeInit,
            0,
            0,
            &pt_buf,
            &mut frame_buf,
        ).unwrap();

        let (hdr, payload) = verify_and_unpack_hmac(&key, &frame_buf[..len]).unwrap();
        assert_eq!(hdr.msg_type, MsgType::HandshakeInit);
        let decoded = HandshakeInitPayload::decode(payload).unwrap();
        assert_eq!(decoded, init);

        // Tampering with payload byte fails authentication
        let mut tampered = frame_buf;
        tampered[HEADER_LEN] ^= 0x01;
        assert_eq!(
            verify_and_unpack_hmac(&key, &tampered[..len]),
            Err(PacketError::AuthenticationFailed)
        );

        // Tampering with header byte fails authentication
        let mut tampered_hdr = frame_buf;
        tampered_hdr[4] ^= 0x01; // Change session_id field in header
        assert_eq!(
            verify_and_unpack_hmac(&key, &tampered_hdr[..len]),
            Err(PacketError::AuthenticationFailed)
        );

        // Tampering with HMAC tag fails authentication
        let mut tampered_tag = frame_buf;
        tampered_tag[len - 1] ^= 0x01;
        assert_eq!(
            verify_and_unpack_hmac(&key, &tampered_tag[..len]),
            Err(PacketError::AuthenticationFailed)
        );
    }
}
