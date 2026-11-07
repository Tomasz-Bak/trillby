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
pub use crate::crypto::TAG_LEN;
pub const HMAC_TAG_LEN: usize = crate::crypto::DIGEST_LEN;
pub const MAX_PAYLOAD_LEN: u16 = 240;
pub const MAX_FRAME_LEN: usize = HEADER_LEN + (MAX_PAYLOAD_LEN as usize); // 256 bytes
pub const OPERATOR_ID_CAP: usize = trillby_core::MAX_OPERATOR_ID_LEN;
pub const JOB_ID_CAP: usize = trillby_core::MAX_JOB_ID_LEN;

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
    SendFailed,
    NotOnline,
    EncryptionFailed,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    HandshakeInit = 0x01,
    HandshakeResp = 0x02,
    /// Reserved for future OTA rekeying; currently ignored by both peers.
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
    pub fn written(&self) -> &[u8] {
        &self.buf[..self.offset]
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

/// Which peer sealed an AEAD frame; mixed into the nonce so the two directions never share a keystream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction { ClientToServer, ServerToClient }

/// FrameHeader.flags bit 0: frame was sealed by the client.
pub const FLAG_CLIENT_TO_SERVER: u16 = 0x0001;
/// XORed into nonce byte 0 for client->server frames.
const C2S_NONCE_MASK: u8 = 0x80;


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

    pub fn direction(&self) -> Direction {
        if self.flags & FLAG_CLIENT_TO_SERVER != 0 {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        }
    }

    pub fn set_direction(&mut self, d: Direction) {
        match d {
            Direction::ClientToServer => self.flags |= FLAG_CLIENT_TO_SERVER,
            Direction::ServerToClient => self.flags &= !FLAG_CLIENT_TO_SERVER,
        }
    }

    pub fn is_direction(&self, d: Direction) -> bool {
        self.direction() == d
    }

    /// Derive standard 12-byte AEAD nonce: [salt ^ dir (4B) || session_id LE (4B) || seq_num LE (4B)], dir = 0x80 in byte 0 for client->server
    pub fn derive_nonce(&self, salt: &[u8; 4]) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        let mut w = ByteWriter::new(&mut nonce);
        let _ = w.write_bytes(salt);
        let _ = w.write_u32_le(self.session_id);
        let _ = w.write_u32_le(self.seq_num);
        if self.direction() == Direction::ClientToServer {
            nonce[0] ^= C2S_NONCE_MASK;
        }
        nonce
    }
}

// ===========================================================================
// Payloads
// ===========================================================================

pub trait Payload {
    const MSG_TYPE: MsgType;
    const LEN: usize;
    fn encode(&self, out: &mut [u8]) -> Result<(), PacketError>;
}

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
impl Payload for HandshakeInitPayload {
    const MSG_TYPE: MsgType = MsgType::HandshakeInit;
    const LEN: usize = Self::LEN;

    fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        Self::encode(self, out)
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
impl Payload for HandshakeRespPayload {
    const MSG_TYPE: MsgType = MsgType::HandshakeResp;
    const LEN: usize = Self::LEN;

    fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        Self::encode(self, out)
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthInitPayload {
    pub auth_data_len: u8,
    pub auth_data: [u8; OPERATOR_ID_CAP],
    pub timestamp_ms: u64,
}

fn truncated<const N: usize>(src: &[u8]) -> (u8, [u8; N]) {
    let len = src.len().min(N);
    let mut buf = [0u8; N];
    buf[..len].copy_from_slice(&src[..len]);
    (len as u8, buf)
}

impl AuthInitPayload {
    pub const LEN: usize = 1 + OPERATOR_ID_CAP + 8;

    pub fn new(auth_data: &[u8], timestamp_ms: u64) -> Self {
        let (auth_data_len, auth_data) = truncated(auth_data);
        Self {
            auth_data_len,
            auth_data,
            timestamp_ms,
        }
    }

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
        if (auth_data_len as usize) > OPERATOR_ID_CAP {
            return Err(PacketError::InvalidPayload);
        }
        let auth_data = r.read_array::<OPERATOR_ID_CAP>()?;
        let timestamp_ms = r.read_u64_le()?;
        Ok(Self {
            auth_data_len,
            auth_data,
            timestamp_ms,
        })
    }

    #[inline]
    pub fn auth_data_bytes(&self) -> &[u8] {
        let len = (self.auth_data_len as usize).min(self.auth_data.len());
        &self.auth_data[..len]
    }
}
impl Payload for AuthInitPayload {
    const MSG_TYPE: MsgType = MsgType::AuthInit;
    const LEN: usize = Self::LEN;

    fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        Self::encode(self, out)
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
impl Payload for AuthRespPayload {
    const MSG_TYPE: MsgType = MsgType::AuthResp;
    const LEN: usize = Self::LEN;

    fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        Self::encode(self, out)
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
impl Payload for HeartbeatPayload {
    const MSG_TYPE: MsgType = MsgType::Heartbeat;
    const LEN: usize = Self::LEN;

    fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        Self::encode(self, out)
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckPayload {
    pub acked_seq: u32,
    pub status: u8,
}

impl AckPayload {
    pub const LEN: usize = 5;
    pub const STATUS_OK: u8 = 0;

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
impl Payload for AckPayload {
    const MSG_TYPE: MsgType = MsgType::Ack;
    const LEN: usize = Self::LEN;

    fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        Self::encode(self, out)
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WorkEventKind {
    WorkStart = 0x01,
    WorkStop = 0x02,
    OperatorLogout = 0x03,
}

impl TryFrom<u8> for WorkEventKind {
    type Error = PacketError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x01 => Ok(WorkEventKind::WorkStart),
            0x02 => Ok(WorkEventKind::WorkStop),
            0x03 => Ok(WorkEventKind::OperatorLogout),
            _ => Err(PacketError::InvalidPayload),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkEventPayload {
    pub kind: WorkEventKind,
    pub operator_id_len: u8,
    pub operator_id: [u8; OPERATOR_ID_CAP],
    pub job_id_len: u8,
    pub job_id: [u8; JOB_ID_CAP],
    pub timestamp_ms: u64,
    pub duration_ms: u64,
}

impl WorkEventPayload {
    pub const LEN: usize = 1 + 1 + OPERATOR_ID_CAP + 1 + JOB_ID_CAP + 8 + 8;

    pub fn work_start(operator_id: &[u8], job_id: &[u8], timestamp_ms: u64) -> Self {
        let (operator_id_len, operator_id) = truncated(operator_id);
        let (job_id_len, job_id) = truncated(job_id);
        Self {
            kind: WorkEventKind::WorkStart,
            operator_id_len,
            operator_id,
            job_id_len,
            job_id,
            timestamp_ms,
            duration_ms: 0,
        }
    }

    pub fn work_stop(operator_id: &[u8], job_id: &[u8], timestamp_ms: u64, duration_ms: u64) -> Self {
        let (operator_id_len, operator_id) = truncated(operator_id);
        let (job_id_len, job_id) = truncated(job_id);
        Self {
            kind: WorkEventKind::WorkStop,
            operator_id_len,
            operator_id,
            job_id_len,
            job_id,
            timestamp_ms,
            duration_ms,
        }
    }

    pub fn operator_logout(operator_id: &[u8], timestamp_ms: u64) -> Self {
        let (operator_id_len, operator_id) = truncated(operator_id);
        Self {
            kind: WorkEventKind::OperatorLogout,
            operator_id_len,
            operator_id,
            job_id_len: 0,
            job_id: [0u8; JOB_ID_CAP],
            timestamp_ms,
            duration_ms: 0,
        }
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        let mut w = ByteWriter::new(out);
        w.write_u8(self.kind as u8)?;
        w.write_u8(self.operator_id_len)?;
        w.write_bytes(&self.operator_id)?;
        w.write_u8(self.job_id_len)?;
        w.write_bytes(&self.job_id)?;
        w.write_u64_le(self.timestamp_ms)?;
        w.write_u64_le(self.duration_ms)?;
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() != Self::LEN {
            return Err(PacketError::InvalidPayload);
        }
        let mut r = ByteReader::new(bytes);
        let kind = WorkEventKind::try_from(r.read_u8()?)?;
        let operator_id_len = r.read_u8()?;
        if (operator_id_len as usize) > OPERATOR_ID_CAP {
            return Err(PacketError::InvalidPayload);
        }
        let operator_id = r.read_array::<OPERATOR_ID_CAP>()?;
        let job_id_len = r.read_u8()?;
        if (job_id_len as usize) > JOB_ID_CAP {
            return Err(PacketError::InvalidPayload);
        }
        let job_id = r.read_array::<JOB_ID_CAP>()?;
        let timestamp_ms = r.read_u64_le()?;
        let duration_ms = r.read_u64_le()?;
        Ok(Self {
            kind,
            operator_id_len,
            operator_id,
            job_id_len,
            job_id,
            timestamp_ms,
            duration_ms,
        })
    }

    #[inline]
    pub fn operator_id_bytes(&self) -> &[u8] {
        let len = (self.operator_id_len as usize).min(self.operator_id.len());
        &self.operator_id[..len]
    }

    #[inline]
    pub fn job_id_bytes(&self) -> &[u8] {
        let len = (self.job_id_len as usize).min(self.job_id.len());
        &self.job_id[..len]
    }
}
impl Payload for WorkEventPayload {
    const MSG_TYPE: MsgType = MsgType::Data;
    const LEN: usize = Self::LEN;

    fn encode(&self, out: &mut [u8]) -> Result<(), PacketError> {
        Self::encode(self, out)
    }
}


// ===========================================================================
// Key Derivation & Nonce Helpers
// ===========================================================================

pub const SESSION_KEY_INFO: &[u8] = b"TRILLBY_SESSION_KEY_V1";
const KDF_SALT_LEN: usize = 32 + 32 + 4;

/// Derive the symmetric session key using HKDF-SHA256 (RFC 5869):
/// PRK = HKDF-Extract(salt = client_nonce || server_nonce || session_salt, IKM = psk)
/// Key = HKDF-Expand(PRK, "TRILLBY_SESSION_KEY_V1", 32)
pub fn derive_session_key(
    psk: &[u8; 32],
    salt: &[u8; 4],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut nonce_salt = [0u8; KDF_SALT_LEN];
    let mut w = ByteWriter::new(&mut nonce_salt);
    let _ = w.write_bytes(client_nonce);
    let _ = w.write_bytes(server_nonce);
    let _ = w.write_bytes(salt);

    let prk = hkdf_extract(&nonce_salt, psk);
    let mut key = [0u8; 32];
    let _ = hkdf_expand(&prk, SESSION_KEY_INFO, &mut key);
    key
}

fn write_frame_header(
    header: &FrameHeader,
    payload_len: usize,
    tag_len: usize,
    frame_buf: &mut [u8],
) -> Result<([u8; HEADER_LEN], usize), PacketError> {
    let full_payload_len = payload_len + tag_len;
    let total_len = HEADER_LEN + full_payload_len;
    if total_len > frame_buf.len() || full_payload_len > (MAX_PAYLOAD_LEN as usize) {
        return Err(PacketError::PayloadTooLarge);
    }
    let mut header_bytes = [0u8; HEADER_LEN];
    header.encode(&mut header_bytes);
    frame_buf[..HEADER_LEN].copy_from_slice(&header_bytes);
    Ok((header_bytes, total_len))
}

fn write_frame_prefix(
    header: &FrameHeader,
    payload: &[u8],
    tag_len: usize,
    frame_buf: &mut [u8],
) -> Result<([u8; HEADER_LEN], usize), PacketError> {
    let (header_bytes, total_len) = write_frame_header(header, payload.len(), tag_len, frame_buf)?;
    frame_buf[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);
    Ok((header_bytes, total_len))
}

fn split_frame(frame_buf: &[u8], tag_len: usize) -> Result<(FrameHeader, usize), PacketError> {
    if frame_buf.len() < HEADER_LEN + tag_len {
        return Err(PacketError::BufferTooShort);
    }
    let header = FrameHeader::decode(&frame_buf[..HEADER_LEN])?;
    let expected_payload_len = header.payload_len as usize;
    if frame_buf[HEADER_LEN..].len() < expected_payload_len || expected_payload_len < tag_len {
        return Err(PacketError::BufferTooShort);
    }
    Ok((header, expected_payload_len))
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
    let header = FrameHeader::new(
        msg_type,
        session_id,
        seq_num,
        (payload.len() + HMAC_TAG_LEN) as u16,
    );
    let (_, total_len) = write_frame_prefix(&header, payload, HMAC_TAG_LEN, frame_buf)?;

    let tag = hmac_sha256(key, &frame_buf[..HEADER_LEN + payload.len()]);
    frame_buf[HEADER_LEN + payload.len()..total_len].copy_from_slice(&tag);

    Ok(total_len)
}

/// Assemble and HMAC-authenticate an unencrypted handshake frame where the payload
/// is already written into `frame_buf[HEADER_LEN..HEADER_LEN + payload_len]`.
/// Returns total frame length (16-byte header + payload + 32-byte HMAC-SHA256 tag).
pub fn pack_and_authenticate_hmac_inplace(
    key: &[u8; 32],
    msg_type: MsgType,
    session_id: u32,
    seq_num: u32,
    payload_len: usize,
    frame_buf: &mut [u8],
) -> Result<usize, PacketError> {
    let header = FrameHeader::new(
        msg_type,
        session_id,
        seq_num,
        (payload_len + HMAC_TAG_LEN) as u16,
    );
    let (_, total_len) = write_frame_header(&header, payload_len, HMAC_TAG_LEN, frame_buf)?;

    let tag = hmac_sha256(key, &frame_buf[..HEADER_LEN + payload_len]);
    frame_buf[HEADER_LEN + payload_len..total_len].copy_from_slice(&tag);

    Ok(total_len)
}

/// Verify HMAC-SHA256 authentication and unpack an unencrypted handshake frame.
/// Returns (FrameHeader, payload_slice).
pub fn verify_and_unpack_hmac<'a>(
    key: &[u8; 32],
    frame_buf: &'a [u8],
) -> Result<(FrameHeader, &'a [u8]), PacketError> {
    let (header, expected_payload_len) = split_frame(frame_buf, HMAC_TAG_LEN)?;

    let data_len = expected_payload_len - HMAC_TAG_LEN;
    let authenticated_len = HEADER_LEN + data_len;
    let expected_tag = hmac_sha256(key, &frame_buf[..authenticated_len]);
    let received_tag = &frame_buf[authenticated_len..HEADER_LEN + expected_payload_len];

    if !constant_time_eq(&expected_tag, received_tag) {
        return Err(PacketError::AuthenticationFailed);
    }

    Ok((header, &frame_buf[HEADER_LEN..authenticated_len]))
}

const CLIENT_NONCE_INPUT_LEN: usize = 32 + 16 + 8 + 8; // 32 PSK + 16 UUID + 8 timestamp_ms + 8 pad = 64

/// Generate a pseudo-random client nonce derived from PSK + device UUID + monotonic timestamp:
/// SHA-256(PSK || UUID || timestamp_ms)
pub fn generate_client_nonce(
    psk: &[u8; 32],
    device_uuid: &[u8; 16],
    timestamp_ms: u64,
) -> [u8; 32] {
    let mut prk_input = [0u8; CLIENT_NONCE_INPUT_LEN];
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
/// `direction` sets `FLAG_CLIENT_TO_SERVER` in the (authenticated) header for
/// client->server frames, which also selects the direction-specific nonce.
/// Returns total frame length (16-byte header + ciphertext + 16-byte MAC tag).
pub fn pack_and_encrypt_directed(
    key: &[u8; 32],
    salt: &[u8; 4],
    direction: Direction,
    msg_type: MsgType,
    session_id: u32,
    seq_num: u32,
    plaintext: &[u8],
    frame_buf: &mut [u8],
) -> Result<usize, PacketError> {
    let mut header = FrameHeader::new(
        msg_type,
        session_id,
        seq_num,
        (plaintext.len() + TAG_LEN) as u16,
    );
    header.set_direction(direction);
    let (header_bytes, total_len) =
        write_frame_prefix(&header, plaintext, TAG_LEN, frame_buf)?;

    let nonce = header.derive_nonce(salt);
    let pt_and_tag = &mut frame_buf[HEADER_LEN..total_len];

    chacha20_poly1305_encrypt(key, &nonce, &header_bytes, pt_and_tag)
        .map_err(|_| PacketError::EncryptionFailed)?;

    Ok(total_len)
}

/// Seal a server->client frame.
pub fn pack_and_encrypt(
    key: &[u8; 32],
    salt: &[u8; 4],
    msg_type: MsgType,
    session_id: u32,
    seq_num: u32,
    plaintext: &[u8],
    frame_buf: &mut [u8],
) -> Result<usize, PacketError> {
    pack_and_encrypt_directed(
        key,
        salt,
        Direction::ServerToClient,
        msg_type,
        session_id,
        seq_num,
        plaintext,
        frame_buf,
    )
}

/// Verify MAC and decrypt an incoming frame in place.
/// Returns (FrameHeader, plaintext_slice).
pub fn decrypt_and_unpack<'a>(
    key: &[u8; 32],
    salt: &[u8; 4],
    frame_buf: &'a mut [u8],
) -> Result<(FrameHeader, &'a [u8]), PacketError> {
    let (header, expected_payload_len) = split_frame(frame_buf, TAG_LEN)?;

    let (header_slice, rest) = frame_buf.split_at_mut(HEADER_LEN);

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
    fn test_header_direction() {
        let mut hdr = FrameHeader::new(MsgType::Data, 7, 9, 0);
        hdr.set_direction(Direction::ClientToServer);
        let mut buf = [0u8; HEADER_LEN];
        hdr.encode(&mut buf);
        let decoded = FrameHeader::decode(&buf).unwrap();
        assert!(decoded.is_direction(Direction::ClientToServer));
        assert!(!decoded.is_direction(Direction::ServerToClient));
        let flags = u16::from_le_bytes([buf[HEADER_LEN - 2], buf[HEADER_LEN - 1]]);
        assert!((flags & FLAG_CLIENT_TO_SERVER) != 0);

        hdr.set_direction(Direction::ServerToClient);
        hdr.encode(&mut buf);
        let decoded2 = FrameHeader::decode(&buf).unwrap();
        assert!(decoded2.is_direction(Direction::ServerToClient));
        assert!(!decoded2.is_direction(Direction::ClientToServer));
        let flags2 = u16::from_le_bytes([buf[HEADER_LEN - 2], buf[HEADER_LEN - 1]]);
        assert_eq!(flags2 & FLAG_CLIENT_TO_SERVER, 0);
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

    #[test]
    fn test_hmac_handshake_inplace_round_trip() {
        let key = [0x42u8; 32];
        let init = HandshakeInitPayload {
            client_nonce: [0x11u8; 32],
            device_uuid: [0x22u8; 16],
        };

        let mut frame_buf = [0u8; MAX_FRAME_LEN];
        init.encode(&mut frame_buf[HEADER_LEN..HEADER_LEN + HandshakeInitPayload::LEN]).unwrap();
        let len = pack_and_authenticate_hmac_inplace(
            &key,
            MsgType::HandshakeInit,
            0,
            0,
            HandshakeInitPayload::LEN,
            &mut frame_buf,
        ).unwrap();

        let (hdr, payload) = verify_and_unpack_hmac(&key, &frame_buf[..len]).unwrap();
        assert_eq!(hdr.msg_type, MsgType::HandshakeInit);
        let decoded = HandshakeInitPayload::decode(payload).unwrap();
        assert_eq!(decoded, init);
    }

    #[test]
    fn test_work_event_payload_round_trip_and_clamping() {
        let start = WorkEventPayload::work_start(b"OP-0042", b"WO-55102", 123_456);
        assert_eq!(start.kind, WorkEventKind::WorkStart);
        assert_eq!(start.operator_id_len, 7);
        assert_eq!(&start.operator_id[..7], b"OP-0042");
        assert_eq!(start.job_id_len, 8);
        assert_eq!(&start.job_id[..8], b"WO-55102");
        assert_eq!(start.timestamp_ms, 123_456);
        assert_eq!(start.duration_ms, 0);

        let mut buf = [0u8; WorkEventPayload::LEN];
        start.encode(&mut buf).unwrap();
        assert_eq!(WorkEventPayload::decode(&buf).unwrap(), start);

        let stop = WorkEventPayload::work_stop(b"OP-0042", b"WO-55102", 223_456, 100_000);
        assert_eq!(stop.kind, WorkEventKind::WorkStop);
        assert_eq!(stop.duration_ms, 100_000);
        stop.encode(&mut buf).unwrap();
        assert_eq!(WorkEventPayload::decode(&buf).unwrap(), stop);

        let logout = WorkEventPayload::operator_logout(b"OP-0042", 250_000);
        assert_eq!(logout.kind, WorkEventKind::OperatorLogout);
        assert_eq!(logout.job_id_len, 0);
        assert_eq!(logout.duration_ms, 0);
        logout.encode(&mut buf).unwrap();
        assert_eq!(WorkEventPayload::decode(&buf).unwrap(), logout);

        // Over-length operator_id (> OPERATOR_ID_CAP) and job_id (> JOB_ID_CAP) are clamped
        let long_op = [b'A'; OPERATOR_ID_CAP + 8];
        let long_job = [b'B'; JOB_ID_CAP + 16];
        let clamped = WorkEventPayload::work_start(&long_op, &long_job, 999);
        assert_eq!(clamped.operator_id_len, OPERATOR_ID_CAP as u8);
        assert_eq!(clamped.operator_id, [b'A'; OPERATOR_ID_CAP]);
        assert_eq!(clamped.job_id_len, JOB_ID_CAP as u8);
        assert_eq!(clamped.job_id, [b'B'; JOB_ID_CAP]);
        clamped.encode(&mut buf).unwrap();
        assert_eq!(WorkEventPayload::decode(&buf).unwrap(), clamped);
        assert_eq!(start.operator_id_bytes(), b"OP-0042");
        assert_eq!(start.job_id_bytes(), b"WO-55102");
        assert_eq!(logout.operator_id_bytes(), b"OP-0042");
        assert_eq!(logout.job_id_bytes(), b"");
        assert_eq!(clamped.operator_id_bytes(), &[b'A'; OPERATOR_ID_CAP]);
        assert_eq!(clamped.job_id_bytes(), &[b'B'; JOB_ID_CAP]);
    }

    #[test]
    fn test_auth_init_payload_new_and_clamping() {
        let auth = AuthInitPayload::new(b"OP-0042", 123_456);
        assert_eq!(auth.auth_data_len, 7);
        assert_eq!(&auth.auth_data[..7], b"OP-0042");
        assert_eq!(&auth.auth_data[7..], &[0u8; 25]);
        assert_eq!(auth.timestamp_ms, 123_456);

        let long_auth = [b'X'; OPERATOR_ID_CAP + 13];
        let clamped = AuthInitPayload::new(&long_auth, 999);
        assert_eq!(clamped.auth_data_len, OPERATOR_ID_CAP as u8);
        assert_eq!(clamped.auth_data, [b'X'; OPERATOR_ID_CAP]);
        assert_eq!(clamped.timestamp_ms, 999);
        assert_eq!(auth.auth_data_bytes(), b"OP-0042");
        assert_eq!(clamped.auth_data_bytes(), &[b'X'; OPERATOR_ID_CAP]);
    }

    #[test]
    fn test_work_event_payload_validation_errors() {
        let valid = WorkEventPayload::work_start(b"OP-1", b"JOB-1", 1000);
        let mut buf = [0u8; WorkEventPayload::LEN];
        valid.encode(&mut buf).unwrap();

        // Buffer length mismatch on decode
        assert_eq!(
            WorkEventPayload::decode(&buf[..WorkEventPayload::LEN - 1]),
            Err(PacketError::InvalidPayload)
        );
        let mut oversized = [0u8; WorkEventPayload::LEN + 1];
        oversized[..WorkEventPayload::LEN].copy_from_slice(&buf);
        assert_eq!(
            WorkEventPayload::decode(&oversized),
            Err(PacketError::InvalidPayload)
        );

        // Unknown WorkEventKind discriminant
        let mut bad_kind = buf;
        bad_kind[0] = 0x00;
        assert_eq!(
            WorkEventPayload::decode(&bad_kind),
            Err(PacketError::InvalidPayload)
        );
        bad_kind[0] = 0x04;
        assert_eq!(
            WorkEventPayload::decode(&bad_kind),
            Err(PacketError::InvalidPayload)
        );

        // operator_id_len > OPERATOR_ID_CAP
        let mut bad_op_len = buf;
        bad_op_len[1] = (OPERATOR_ID_CAP + 1) as u8;
        assert_eq!(
            WorkEventPayload::decode(&bad_op_len),
            Err(PacketError::InvalidPayload)
        );

        // job_id_len > JOB_ID_CAP (offset 1 + 1 + OPERATOR_ID_CAP)
        let mut bad_job_len = buf;
        bad_job_len[1 + 1 + OPERATOR_ID_CAP] = (JOB_ID_CAP + 1) as u8;
        assert_eq!(
            WorkEventPayload::decode(&bad_job_len),
            Err(PacketError::InvalidPayload)
        );

        // BufferTooShort on encode
        let mut short_out = [0u8; WorkEventPayload::LEN - 1];
        assert_eq!(
            valid.encode(&mut short_out),
            Err(PacketError::BufferTooShort)
        );
    }

    #[test]
    fn test_frame_header_decode_all_error_variants() {
        let valid_hdr = FrameHeader::new(MsgType::Data, 1234, 5678, 100);
        let mut bytes = [0u8; HEADER_LEN];
        valid_hdr.encode(&mut bytes);

        // < 16 bytes
        assert_eq!(FrameHeader::decode(&bytes[..15]), Err(PacketError::BufferTooShort));

        // Bad magic
        let mut bad_magic = bytes;
        bad_magic[0] ^= 0xff;
        assert_eq!(FrameHeader::decode(&bad_magic), Err(PacketError::InvalidMagic));

        // Version 0 or 2
        let mut v0 = bytes;
        v0[2] = 0;
        assert_eq!(FrameHeader::decode(&v0), Err(PacketError::UnsupportedVersion));
        let mut v2 = bytes;
        v2[2] = 2;
        assert_eq!(FrameHeader::decode(&v2), Err(PacketError::UnsupportedVersion));

        // Unknown msg_type 0x00 / 0x99
        let mut unk0 = bytes;
        unk0[3] = 0x00;
        assert_eq!(FrameHeader::decode(&unk0), Err(PacketError::UnknownMsgType));
        let mut unk99 = bytes;
        unk99[3] = 0x99;
        assert_eq!(FrameHeader::decode(&unk99), Err(PacketError::UnknownMsgType));

        // payload_len = 241 (> MAX_PAYLOAD_LEN = 240)
        let mut large_payload = bytes;
        large_payload[12..14].copy_from_slice(&241u16.to_le_bytes());
        assert_eq!(FrameHeader::decode(&large_payload), Err(PacketError::PayloadTooLarge));
    }

    #[test]
    fn test_all_payloads_short_buffers_and_auth_init_length_validation() {
        // HandshakeInitPayload (LEN = 48)
        let init = HandshakeInitPayload {
            client_nonce: [0x11; 32],
            device_uuid: [0x22; 16],
        };
        let mut short_init = [0u8; HandshakeInitPayload::LEN - 1];
        assert_eq!(init.encode(&mut short_init), Err(PacketError::BufferTooShort));
        assert_eq!(HandshakeInitPayload::decode(&short_init), Err(PacketError::BufferTooShort));

        // HandshakeRespPayload (LEN = 40)
        let resp = HandshakeRespPayload {
            server_nonce: [0x33; 32],
            assigned_session_id: 100,
            session_salt: [1, 2, 3, 4],
        };
        let mut short_resp = [0u8; HandshakeRespPayload::LEN - 1];
        assert_eq!(resp.encode(&mut short_resp), Err(PacketError::BufferTooShort));
        assert_eq!(HandshakeRespPayload::decode(&short_resp), Err(PacketError::BufferTooShort));

        // AuthInitPayload (LEN = 41)
        let auth_init = AuthInitPayload {
            auth_data_len: 16,
            auth_data: [0x44; 32],
            timestamp_ms: 1000,
        };
        let mut short_auth_init = [0u8; AuthInitPayload::LEN - 1];
        assert_eq!(auth_init.encode(&mut short_auth_init), Err(PacketError::BufferTooShort));
        assert_eq!(AuthInitPayload::decode(&short_auth_init), Err(PacketError::BufferTooShort));

        // AuthRespPayload (LEN = 6)
        let auth_resp = AuthRespPayload {
            status: 0,
            role: 1,
            session_ttl_s: 3600,
        };
        let mut short_auth_resp = [0u8; AuthRespPayload::LEN - 1];
        assert_eq!(auth_resp.encode(&mut short_auth_resp), Err(PacketError::BufferTooShort));
        assert_eq!(AuthRespPayload::decode(&short_auth_resp), Err(PacketError::BufferTooShort));

        // HeartbeatPayload (LEN = 8)
        let hb = HeartbeatPayload {
            battery_pct: 95,
            rssi: -60,
            pending_outbox: 3,
            uptime_s: 500,
        };
        let mut short_hb = [0u8; HeartbeatPayload::LEN - 1];
        assert_eq!(hb.encode(&mut short_hb), Err(PacketError::BufferTooShort));
        assert_eq!(HeartbeatPayload::decode(&short_hb), Err(PacketError::BufferTooShort));

        // AckPayload (LEN = 5)
        let ack = AckPayload {
            acked_seq: 1,
            status: 0,
        };
        let mut short_ack = [0u8; AckPayload::LEN - 1];
        assert_eq!(ack.encode(&mut short_ack), Err(PacketError::BufferTooShort));
        assert_eq!(AckPayload::decode(&short_ack), Err(PacketError::BufferTooShort));

        // AuthInitPayload::decode with auth_data_len > 32 must return Err(PacketError::InvalidPayload)
        let mut valid_auth_buf = [0u8; AuthInitPayload::LEN];
        auth_init.encode(&mut valid_auth_buf).unwrap();

        let mut buf_33 = valid_auth_buf;
        buf_33[0] = (OPERATOR_ID_CAP + 1) as u8;
        assert_eq!(AuthInitPayload::decode(&buf_33), Err(PacketError::InvalidPayload));

        let mut buf_255 = valid_auth_buf;
        buf_255[0] = 255;
        assert_eq!(AuthInitPayload::decode(&buf_255), Err(PacketError::InvalidPayload));
    }

    #[test]
    fn test_hmac_and_aead_frame_boundary_and_mismatch_errors() {
        let key = [0x55u8; 32];
        let salt = [0x11, 0x22, 0x33, 0x44];
        let mut frame_buf = [0u8; MAX_FRAME_LEN];

        // 1. HMAC boundary:
        // Exact max payload: 208 bytes + 32 tag = 240 bytes payload (total 256 bytes) -> Ok(256)
        let payload_208 = [0xAAu8; 208];
        let res_208 = pack_and_authenticate_hmac(
            &key,
            MsgType::HandshakeInit,
            0,
            0,
            &payload_208,
            &mut frame_buf,
        );
        assert_eq!(res_208, Ok(MAX_FRAME_LEN));

        // 209 bytes payload -> 209 + 32 = 241 > MAX_PAYLOAD_LEN -> Err(PacketError::PayloadTooLarge)
        let payload_209 = [0xAAu8; 209];
        let res_209 = pack_and_authenticate_hmac(
            &key,
            MsgType::HandshakeInit,
            0,
            0,
            &payload_209,
            &mut frame_buf,
        );
        assert_eq!(res_209, Err(PacketError::PayloadTooLarge));

        // verify_and_unpack_hmac:
        // Truncated frame_buf (< HEADER_LEN + HMAC_TAG_LEN)
        assert_eq!(
            verify_and_unpack_hmac(&key, &frame_buf[..HEADER_LEN + HMAC_TAG_LEN - 1]),
            Err(PacketError::BufferTooShort)
        );
        // header.payload_len < HMAC_TAG_LEN (e.g. 31)
        let mut bad_len_frame = [0u8; HEADER_LEN + HMAC_TAG_LEN];
        let bad_hdr = FrameHeader::new(MsgType::HandshakeInit, 0, 0, (HMAC_TAG_LEN - 1) as u16);
        let mut hdr_bytes = [0u8; HEADER_LEN];
        bad_hdr.encode(&mut hdr_bytes);
        bad_len_frame[..HEADER_LEN].copy_from_slice(&hdr_bytes);
        assert_eq!(
            verify_and_unpack_hmac(&key, &bad_len_frame),
            Err(PacketError::BufferTooShort)
        );

        // 2. AEAD boundary:
        // Exact max plaintext: 224 bytes + 16 tag = 240 bytes payload (total 256 bytes) -> Ok(256)
        let pt_224 = [0xBBu8; 224];
        let res_224 = pack_and_encrypt(
            &key,
            &salt,
            MsgType::Data,
            1,
            1,
            &pt_224,
            &mut frame_buf,
        );
        assert_eq!(res_224, Ok(MAX_FRAME_LEN));

        // 225 bytes plaintext -> 225 + 16 = 241 > MAX_PAYLOAD_LEN -> Err(PacketError::PayloadTooLarge)
        let pt_225 = [0xBBu8; 225];
        let res_225 = pack_and_encrypt(
            &key,
            &salt,
            MsgType::Data,
            1,
            1,
            &pt_225,
            &mut frame_buf,
        );
        assert_eq!(res_225, Err(PacketError::PayloadTooLarge));

        // decrypt_and_unpack:
        let valid_frame = frame_buf;
        let mut wrong_salt_frame = valid_frame;
        let mut wrong_salt = salt;
        wrong_salt[0] ^= 1;
        assert_eq!(
            decrypt_and_unpack(&key, &wrong_salt, &mut wrong_salt_frame),
            Err(PacketError::DecryptionFailed)
        );

        let mut wrong_key_frame = valid_frame;
        let mut wrong_key = key;
        wrong_key[0] ^= 1;
        assert_eq!(
            decrypt_and_unpack(&wrong_key, &salt, &mut wrong_key_frame),
            Err(PacketError::DecryptionFailed)
        );

        // header.payload_len < TAG_LEN (e.g. 15)
        let mut short_payload_hdr_frame = [0u8; HEADER_LEN + TAG_LEN];
        let short_hdr = FrameHeader::new(MsgType::Data, 1, 1, (TAG_LEN - 1) as u16);
        let mut short_hdr_bytes = [0u8; HEADER_LEN];
        short_hdr.encode(&mut short_hdr_bytes);
        short_payload_hdr_frame[..HEADER_LEN].copy_from_slice(&short_hdr_bytes);
        assert_eq!(
            decrypt_and_unpack(&key, &salt, &mut short_payload_hdr_frame),
            Err(PacketError::BufferTooShort)
        );
    }

    #[test]
    fn test_derive_session_key_input_sensitivity() {
        let psk = [0x55u8; 32];
        let salt = [1, 2, 3, 4];
        let client_nonce = [0x11u8; 32];
        let server_nonce = [0x22u8; 32];

        let base_key = derive_session_key(&psk, &salt, &client_nonce, &server_nonce);
        assert_ne!(base_key, [0u8; 32]);

        // Flip 1 bit in psk
        let mut diff_psk = psk;
        diff_psk[0] ^= 0x01;
        assert_ne!(derive_session_key(&diff_psk, &salt, &client_nonce, &server_nonce), base_key);

        // Flip 1 bit in salt
        let mut diff_salt = salt;
        diff_salt[0] ^= 0x01;
        assert_ne!(derive_session_key(&psk, &diff_salt, &client_nonce, &server_nonce), base_key);

        // Flip 1 bit in client_nonce
        let mut diff_client_nonce = client_nonce;
        diff_client_nonce[0] ^= 0x01;
        assert_ne!(derive_session_key(&psk, &salt, &diff_client_nonce, &server_nonce), base_key);

        // Flip 1 bit in server_nonce
        let mut diff_server_nonce = server_nonce;
        diff_server_nonce[0] ^= 0x01;
        assert_ne!(derive_session_key(&psk, &salt, &client_nonce, &diff_server_nonce), base_key);
    }

}
