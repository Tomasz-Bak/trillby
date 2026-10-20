#![no_std]

#[cfg(test)]
extern crate std;

pub mod client;
pub mod crypto;
pub mod outbox;
pub mod packet;
pub mod posix;
pub mod provisioning;
pub mod server;

pub use client::{ClientState, NetClient};
pub use outbox::{Outbox, OutboxError};
pub use packet::{
    decrypt_and_unpack, derive_session_key, generate_client_nonce, pack_and_authenticate_hmac,
    pack_and_encrypt, verify_and_unpack_hmac, AckPayload, AuthInitPayload, AuthRespPayload,
    ByteReader, ByteWriter, FrameHeader, HandshakeInitPayload, HandshakeRespPayload,
    HeartbeatPayload, MsgType, PacketError, FRAME_MAGIC, HEADER_LEN, HMAC_TAG_LEN,
    MAX_FRAME_LEN, MAX_PAYLOAD_LEN, PROTOCOL_VERSION, SESSION_KEY_INFO, TAG_LEN,
};
pub use posix::{fill_random, monotonic_ms, PosixSocket};
pub use provisioning::{crc32_ieee, DeviceProvisioning, ProvisioningError};
pub use server::{NetServer, ServerEvent, ServerSession, ServerSessionState};
