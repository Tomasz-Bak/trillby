#![no_std]

pub mod client;
pub mod crypto;
pub mod outbox;
pub mod packet;
pub mod posix;

pub use client::{ClientState, NetClient};
pub use outbox::{Outbox, OutboxError};
pub use packet::{
    derive_session_key, generate_client_nonce, AckPayload, ByteReader, ByteWriter, FrameHeader,
    HandshakeInitPayload, HandshakeRespPayload, HeartbeatPayload, MsgType, OperatorAuthPayload,
    PacketError, WorkStartPayload, SESSION_KEY_INFO,
};
pub use posix::{monotonic_ms, PosixSocket};
