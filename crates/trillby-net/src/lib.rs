#![no_std]

#[cfg(test)]
extern crate std;
#[cfg(test)]
extern crate self as trillby_net;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
pub(crate) mod test_support;

pub mod client;
pub mod crypto;
pub mod outbox;
pub mod framing;
pub mod packet;
pub mod posix;
pub mod provisioning;
pub mod server;

pub use client::{ClientState, NetClient};
pub use outbox::{Outbox, OutboxError};
pub use framing::{FrameAssembler, RecvOutcome, SessionCrypto};
pub use packet::{
    decrypt_and_unpack, derive_session_key, generate_client_nonce, pack_and_authenticate_hmac,
    pack_and_authenticate_hmac_inplace, pack_and_encrypt, pack_and_encrypt_directed,
    verify_and_unpack_hmac, AckPayload, AuthInitPayload, AuthRespPayload, ByteReader, ByteWriter,
    Direction, FrameHeader, HandshakeInitPayload, HandshakeRespPayload, HeartbeatPayload, MsgType,
    Payload, WorkEventKind, WorkEventPayload, FLAG_CLIENT_TO_SERVER, FRAME_MAGIC, HEADER_LEN, HMAC_TAG_LEN,
    MAX_FRAME_LEN, MAX_PAYLOAD_LEN, PROTOCOL_VERSION, SESSION_KEY_INFO, TAG_LEN,
};
pub use posix::{fill_random, monotonic_ms, PosixSocket};
pub use provisioning::{
    crc32_ieee, decode_hex, parse_registry_line, write_hex, write_registry_line,
    DeviceProvisioning, ProvisioningError, RegistryError, DEFAULT_PATH, DEFAULT_SERVER_PORT,
    DEV_DEVICE_UUID, DEV_PSK,
};
pub use server::{NetServer, ServerEvent, ServerSessionState};
