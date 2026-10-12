#![no_std]

pub mod client;
pub mod crypto;
pub mod outbox;
pub mod packet;
pub mod posix;

pub use client::{ClientState, NetClient};
pub use outbox::{Outbox, OutboxError};
pub use packet::{
    FrameHeader, MsgType, PacketError,
    HandshakeInitPayload, HandshakeRespPayload,
    OperatorAuthPayload, WorkStartPayload, HeartbeatPayload, AckPayload,
};
pub use posix::{monotonic_ms, PosixSocket};
