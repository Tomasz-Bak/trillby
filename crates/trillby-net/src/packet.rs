//! Binary Packed Frame Layout & Zero-Allocation Payloads
//!
//! All integer fields are encoded as Little-Endian.
//! The 16-byte FrameHeader serves as the Associated Authenticated Data (AAD)
//! for ChaCha20-Poly1305.

use crate::crypto::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};

pub const FRAME_MAGIC: [u8; 2] = [0x54, 0x52]; // "TR"
pub const PROTOCOL_VERSION: u8 = 0x01;
pub const HEADER_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
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
    InvalidPayload,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    HandshakeInit = 0x01,
    HandshakeResp = 0x02,
    OperatorAuth = 0x10,
    WorkStart = 0x11,
    WorkPause = 0x12,
    WorkResume = 0x13,
    WorkFinish = 0x14,
    QaNote = 0x15,
    Heartbeat = 0x20,
    Ack = 0x30,
    Rekey = 0x40,
}

impl TryFrom<u8> for MsgType {
    type Error = PacketError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x01 => Ok(MsgType::HandshakeInit),
            0x02 => Ok(MsgType::HandshakeResp),
            0x10 => Ok(MsgType::OperatorAuth),
            0x11 => Ok(MsgType::WorkStart),
            0x12 => Ok(MsgType::WorkPause),
            0x13 => Ok(MsgType::WorkResume),
            0x14 => Ok(MsgType::WorkFinish),
            0x15 => Ok(MsgType::QaNote),
            0x20 => Ok(MsgType::Heartbeat),
            0x30 => Ok(MsgType::Ack),
            0x40 => Ok(MsgType::Rekey),
            _ => Err(PacketError::UnknownMsgType),
        }
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
        out[0] = FRAME_MAGIC[0];
        out[1] = FRAME_MAGIC[1];
        out[2] = PROTOCOL_VERSION;
        out[3] = self.msg_type as u8;
        out[4..8].copy_from_slice(&self.session_id.to_le_bytes());
        out[8..12].copy_from_slice(&self.seq_num.to_le_bytes());
        out[12..14].copy_from_slice(&self.payload_len.to_le_bytes());
        out[14..16].copy_from_slice(&self.flags.to_le_bytes());
    }

    pub fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self, PacketError> {
        if bytes[0] != FRAME_MAGIC[0] || bytes[1] != FRAME_MAGIC[1] {
            return Err(PacketError::InvalidMagic);
        }
        if bytes[2] != PROTOCOL_VERSION {
            return Err(PacketError::UnsupportedVersion);
        }
        let msg_type = MsgType::try_from(bytes[3])?;
        let session_id = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let seq_num = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let payload_len = u16::from_le_bytes(bytes[12..14].try_into().unwrap());
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(PacketError::PayloadTooLarge);
        }
        let flags = u16::from_le_bytes(bytes[14..16].try_into().unwrap());

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
        nonce[0..4].copy_from_slice(salt);
        nonce[4..8].copy_from_slice(&self.session_id.to_le_bytes());
        nonce[8..12].copy_from_slice(&self.seq_num.to_le_bytes());
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
        if out.len() < Self::LEN {
            return Err(PacketError::BufferTooShort);
        }
        out[0..32].copy_from_slice(&self.client_nonce);
        out[32..48].copy_from_slice(&self.device_uuid);
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < Self::LEN {
            return Err(PacketError::BufferTooShort);
        }
        let mut client_nonce = [0u8; 32];
        client_nonce.copy_from_slice(&bytes[0..32]);
        let mut device_uuid = [0u8; 16];
        device_uuid.copy_from_slice(&bytes[32..48]);
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
        if out.len() < Self::LEN {
            return Err(PacketError::BufferTooShort);
        }
        out[0..32].copy_from_slice(&self.server_nonce);
        out[32..36].copy_from_slice(&self.assigned_session_id.to_le_bytes());
        out[36..40].copy_from_slice(&self.session_salt);
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < Self::LEN {
            return Err(PacketError::BufferTooShort);
        }
        let mut server_nonce = [0u8; 32];
        server_nonce.copy_from_slice(&bytes[0..32]);
        let assigned_session_id = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let mut session_salt = [0u8; 4];
        session_salt.copy_from_slice(&bytes[36..40]);
        Ok(Self {
            server_nonce,
            assigned_session_id,
            session_salt,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorAuthPayload {
    pub card_id: [u8; 16],
    pub card_id_len: u8,
    pub timestamp_ms: u64,
}

impl OperatorAuthPayload {
    pub const LEN: usize = 25; // 1 + 16 + 8

    pub fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        if out.len() < Self::LEN {
            return Err(PacketError::BufferTooShort);
        }
        out[0] = self.card_id_len;
        out[1..17].copy_from_slice(&self.card_id);
        out[17..25].copy_from_slice(&self.timestamp_ms.to_le_bytes());
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < Self::LEN {
            return Err(PacketError::BufferTooShort);
        }
        let card_id_len = bytes[0];
        let mut card_id = [0u8; 16];
        card_id.copy_from_slice(&bytes[1..17]);
        let timestamp_ms = u64::from_le_bytes(bytes[17..25].try_into().unwrap());
        Ok(Self { card_id, card_id_len, timestamp_ms })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkStartPayload {
    pub work_order_len: u8,
    pub work_order_id: [u8; 32],
    pub operator_id_len: u8,
    pub operator_id: [u8; 16],
    pub timestamp_ms: u64,
}

impl WorkStartPayload {
    pub const LEN: usize = 58; // 1 + 32 + 1 + 16 + 8

    pub fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        if out.len() < Self::LEN {
            return Err(PacketError::BufferTooShort);
        }
        out[0] = self.work_order_len;
        out[1..33].copy_from_slice(&self.work_order_id);
        out[33] = self.operator_id_len;
        out[34..50].copy_from_slice(&self.operator_id);
        out[50..58].copy_from_slice(&self.timestamp_ms.to_le_bytes());
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < Self::LEN {
            return Err(PacketError::BufferTooShort);
        }
        let work_order_len = bytes[0];
        let mut work_order_id = [0u8; 32];
        work_order_id.copy_from_slice(&bytes[1..33]);
        let operator_id_len = bytes[33];
        let mut operator_id = [0u8; 16];
        operator_id.copy_from_slice(&bytes[34..50]);
        let timestamp_ms = u64::from_le_bytes(bytes[50..58].try_into().unwrap());
        Ok(Self {
            work_order_len,
            work_order_id,
            operator_id_len,
            operator_id,
            timestamp_ms,
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
        if out.len() < Self::LEN {
            return Err(PacketError::BufferTooShort);
        }
        out[0] = self.battery_pct;
        out[1] = self.rssi as u8;
        out[2..4].copy_from_slice(&self.pending_outbox.to_le_bytes());
        out[4..8].copy_from_slice(&self.uptime_s.to_le_bytes());
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < Self::LEN {
            return Err(PacketError::BufferTooShort);
        }
        let battery_pct = bytes[0];
        let rssi = bytes[1] as i8;
        let pending_outbox = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
        let uptime_s = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
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
        if out.len() < Self::LEN {
            return Err(PacketError::BufferTooShort);
        }
        out[0..4].copy_from_slice(&self.acked_seq.to_le_bytes());
        out[4] = self.status;
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < Self::LEN {
            return Err(PacketError::BufferTooShort);
        }
        let acked_seq = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let status = bytes[4];
        Ok(Self { acked_seq, status })
    }
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

    let mut header_bytes = [0u8; HEADER_LEN];
    header_bytes.copy_from_slice(&frame_buf[..HEADER_LEN]);
    let header = FrameHeader::decode(&header_bytes)?;

    let expected_total = HEADER_LEN + (header.payload_len as usize);
    if frame_buf.len() < expected_total || (header.payload_len as usize) < TAG_LEN {
        return Err(PacketError::BufferTooShort);
    }

    let nonce = header.derive_nonce(salt);
    let ct_and_tag = &mut frame_buf[HEADER_LEN..expected_total];

    let pt_len = chacha20_poly1305_decrypt(key, &nonce, &header_bytes, ct_and_tag)
        .map_err(|_| PacketError::DecryptionFailed)?;

    Ok((header, &frame_buf[HEADER_LEN..HEADER_LEN + pt_len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let hdr = FrameHeader::new(MsgType::WorkStart, 0x12345678, 42, 64);
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

        let mut work_order = [0u8; 32];
        work_order[..9].copy_from_slice(b"WO_9921_Q");
        let mut operator = [0u8; 16];
        operator[..7].copy_from_slice(b"OP_7741");

        let payload = WorkStartPayload {
            work_order_len: 9,
            work_order_id: work_order,
            operator_id_len: 7,
            operator_id: operator,
            timestamp_ms: 1728750000000,
        };

        let mut pt_buf = [0u8; 64];
        payload.encode(&mut pt_buf).unwrap();

        let total_frame_len = pack_and_encrypt(
            &key,
            &salt,
            MsgType::WorkStart,
            100,
            1,
            &pt_buf[..WorkStartPayload::LEN],
            &mut frame_buf,
        ).unwrap();

        assert_eq!(total_frame_len, HEADER_LEN + WorkStartPayload::LEN + TAG_LEN);

        // Decrypt
        let (hdr, decrypted_pt) = decrypt_and_unpack(
            &key,
            &salt,
            &mut frame_buf[..total_frame_len],
        ).unwrap();

        assert_eq!(hdr.msg_type, MsgType::WorkStart);
        assert_eq!(hdr.seq_num, 1);
        let decoded_payload = WorkStartPayload::decode(decrypted_pt).unwrap();
        assert_eq!(decoded_payload, payload);
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
            MsgType::OperatorAuth,
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
}
