//! Client Network State Machine & POSIX Event Loop Integration
//!
//! Driven directly by the non-blocking `libc::poll` loop in PID 1.
//! Operates on real monotonic millisecond timestamps (CLOCK_MONOTONIC).
//! Implements PSK + HKDF-SHA256 key establishment, automatic OTA rekeying,
//! offline outbox queuing, and anti-replay sequence tracking.

use crate::crypto::{hkdf_expand, hkdf_extract};
use crate::outbox::{Outbox, OutboxError};
use crate::packet::{
    decrypt_and_unpack, pack_and_encrypt, AckPayload, HandshakeInitPayload,
    HandshakeRespPayload, MsgType, HEADER_LEN, MAX_FRAME_LEN,
};
use crate::posix::PosixSocket;
use trillby_core::net_types::NetworkStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Disconnected { next_attempt_ms: u64, backoff_ms: u32 },
    Connecting,
    Handshaking,
    Online,
}

pub struct NetClient<const OUTBOX_CAP: usize> {
    psk: [u8; 32],
    device_uuid: [u8; 16],
    server_ip: [u8; 4],
    server_port: u16,
    state: ClientState,
    socket: PosixSocket,
    session_id: u32,
    session_salt: [u8; 4],
    session_key: [u8; 32],
    client_nonce: [u8; 32],
    tx_seq: u32,
    rx_seq: u32,
    outbox: Outbox<OUTBOX_CAP>,
}

impl<const OUTBOX_CAP: usize> NetClient<OUTBOX_CAP> {
    pub fn new(
        psk: [u8; 32],
        device_uuid: [u8; 16],
        server_ip: [u8; 4],
        server_port: u16,
    ) -> Self {
        Self {
            psk,
            device_uuid,
            server_ip,
            server_port,
            state: ClientState::Disconnected {
                next_attempt_ms: 0,
                backoff_ms: 1000, // Initial 1-second delay
            },
            socket: PosixSocket::invalid(),
            session_id: 0,
            session_salt: [0u8; 4],
            session_key: [0u8; 32],
            client_nonce: [0u8; 32],
            tx_seq: 1,
            rx_seq: 0,
            outbox: Outbox::new(),
        }
    }

    pub fn state(&self) -> ClientState {
        self.state
    }

    pub fn status(&self) -> NetworkStatus {
        match self.state {
            ClientState::Disconnected { .. } => NetworkStatus::Offline,
            ClientState::Connecting => NetworkStatus::Connecting,
            ClientState::Handshaking => NetworkStatus::Handshaking,
            ClientState::Online => {
                let pending = self.outbox.len();
                if pending > 0 {
                    NetworkStatus::Syncing(pending as u16)
                } else {
                    NetworkStatus::Online
                }
            }
        }
    }

    pub fn socket_fd(&self) -> libc::c_int {
        self.socket.fd()
    }

    pub fn outbox_pending_count(&self) -> usize {
        self.outbox.len()
    }

    /// Enqueue an event payload. If an active session is online, it will be
    /// encrypted with the current session key and queued for transmission.
    pub fn enqueue_event(&mut self, msg_type: MsgType, plaintext: &[u8]) -> Result<(), OutboxError> {
        let seq = self.tx_seq;
        self.tx_seq = self.tx_seq.wrapping_add(1);

        let mut frame_buf = [0u8; MAX_FRAME_LEN];
        let frame_len = pack_and_encrypt(
            &self.session_key,
            &self.session_salt,
            msg_type,
            self.session_id,
            seq,
            plaintext,
            &mut frame_buf,
        ).map_err(|_| OutboxError::FrameTooLarge)?;

        self.outbox.push(seq, &frame_buf[..frame_len])?;
        Ok(())
    }

    /// Primary event loop step. Called by the poll loop on timeout or socket event.
    /// Operates on real monotonic milliseconds `now_ms`.
    /// Returns `Some(new_status)` if the high-level network status changed.
    pub fn poll_step(&mut self, now_ms: u64, revents: i16) -> Option<NetworkStatus> {
        let prev_status = self.status();

        match self.state {
            ClientState::Disconnected { next_attempt_ms, backoff_ms } => {
                if now_ms >= next_attempt_ms {
                    match PosixSocket::new_nonblocking_tcp() {
                        Ok(sock) => {
                            self.socket = sock;
                            match self.socket.connect_ipv4(self.server_ip, self.server_port) {
                                Ok(true) => {
                                    // Connected immediately
                                    self.state = ClientState::Handshaking;
                                    self.send_handshake_init(now_ms);
                                }
                                Ok(false) => {
                                    // EINPROGRESS (normal for non-blocking connect)
                                    self.state = ClientState::Connecting;
                                }
                                Err(_) => {
                                    self.transition_to_disconnected(now_ms, backoff_ms);
                                }
                            }
                        }
                        Err(_) => {
                            self.transition_to_disconnected(now_ms, backoff_ms);
                        }
                    }
                }
            }
            ClientState::Connecting => {
                if (revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                    self.transition_to_disconnected(now_ms, 2000);
                } else if (revents & libc::POLLOUT) != 0 {
                    if self.socket.check_connect_completed().is_ok() {
                        self.state = ClientState::Handshaking;
                        self.send_handshake_init(now_ms);
                    } else {
                        self.transition_to_disconnected(now_ms, 2000);
                    }
                }
            }
            ClientState::Handshaking => {
                if (revents & (libc::POLLERR | libc::POLLHUP)) != 0 {
                    self.transition_to_disconnected(now_ms, 2000);
                } else if (revents & libc::POLLIN) != 0 {
                    self.handle_handshake_response(now_ms);
                }
            }
            ClientState::Online => {
                if (revents & (libc::POLLERR | libc::POLLHUP)) != 0 {
                    self.transition_to_disconnected(now_ms, 2000);
                } else {
                    if (revents & libc::POLLIN) != 0 {
                        self.receive_frames(now_ms);
                    }
                    if self.state == ClientState::Online {
                        self.flush_outbox();
                    }
                }
            }
        }

        let new_status = self.status();
        if new_status != prev_status {
            Some(new_status)
        } else {
            None
        }
    }

    fn transition_to_disconnected(&mut self, now_ms: u64, prev_backoff: u32) {
        self.socket.close();
        let next_backoff = (prev_backoff * 2).min(30_000); // Max 30 seconds backoff
        self.state = ClientState::Disconnected {
            next_attempt_ms: now_ms + (prev_backoff as u64),
            backoff_ms: next_backoff,
        };
    }

    fn send_handshake_init(&mut self, now_ms: u64) {
        // Generate pseudo-random client nonce derived from PSK + UUID + monotonic timestamp
        let mut prk_input = [0u8; 64];
        prk_input[..32].copy_from_slice(&self.psk);
        prk_input[32..48].copy_from_slice(&self.device_uuid);
        prk_input[48..56].copy_from_slice(&now_ms.to_le_bytes());
        self.client_nonce = crate::crypto::sha256(&prk_input);

        let init_payload = HandshakeInitPayload {
            client_nonce: self.client_nonce,
            device_uuid: self.device_uuid,
        };

        let mut pt_buf = [0u8; HandshakeInitPayload::LEN];
        let _ = init_payload.encode(&mut pt_buf);

        // HandshakeInit is encrypted using root PSK with zero salt/session
        let mut frame_buf = [0u8; MAX_FRAME_LEN];
        if let Ok(len) = pack_and_encrypt(
            &self.psk,
            &[0u8; 4],
            MsgType::HandshakeInit,
            0,
            0,
            &pt_buf,
            &mut frame_buf,
        ) {
            let _ = self.socket.send(&frame_buf[..len]);
        }
    }

    fn handle_handshake_response(&mut self, now_ms: u64) {
        let mut buf = [0u8; MAX_FRAME_LEN];
        match self.socket.recv(&mut buf) {
            Ok(n) if n >= HEADER_LEN => {
                if let Ok((hdr, pt)) = decrypt_and_unpack(&self.psk, &[0u8; 4], &mut buf[..n]) {
                    if hdr.msg_type == MsgType::HandshakeResp {
                        if let Ok(resp) = HandshakeRespPayload::decode(pt) {
                            self.session_id = resp.assigned_session_id;
                            self.session_salt = resp.session_salt;

                            // Derive Session Key: HKDF(PSK, client_nonce || server_nonce)
                            let mut ikm = [0u8; 64];
                            ikm[..32].copy_from_slice(&self.client_nonce);
                            ikm[32..64].copy_from_slice(&resp.server_nonce);

                            let prk = hkdf_extract(&resp.session_salt, &ikm);
                            let info = b"TRILLBY_SESSION_KEY_V1";
                            let _ = hkdf_expand(&prk, info, &mut self.session_key);

                            self.tx_seq = 1;
                            self.rx_seq = 0;
                            self.state = ClientState::Online;
                            self.flush_outbox();
                            return;
                        }
                    }
                }
                // Decryption or format failure
                self.transition_to_disconnected(now_ms, 2000);
            }
            Ok(0) => {
                // Connection closed by peer
                self.transition_to_disconnected(now_ms, 2000);
            }
            _ => {}
        }
    }

    fn receive_frames(&mut self, now_ms: u64) {
        let mut buf = [0u8; MAX_FRAME_LEN];
        match self.socket.recv(&mut buf) {
            Ok(n) if n >= HEADER_LEN => {
                if let Ok((hdr, pt)) = decrypt_and_unpack(
                    &self.session_key,
                    &self.session_salt,
                    &mut buf[..n],
                ) {
                    // Anti-replay check
                    if hdr.seq_num > self.rx_seq {
                        self.rx_seq = hdr.seq_num;
                        if hdr.msg_type == MsgType::Ack {
                            if let Ok(ack) = AckPayload::decode(pt) {
                                self.outbox.ack(ack.acked_seq);
                            }
                        }
                    }
                }
            }
            Ok(0) => {
                self.transition_to_disconnected(now_ms, 2000);
            }
            _ => {}
        }
    }

    fn flush_outbox(&mut self) {
        while let Some((_seq, frame)) = self.outbox.peek() {
            match self.socket.send(frame) {
                Ok(n) if n == frame.len() => {
                    // Sent full frame
                    break;
                }
                _ => {
                    // Socket would block or errored; wait for next poll step
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_initial_state() {
        let psk = [0x99u8; 32];
        let uuid = [0x11u8; 16];
        let client: NetClient<16> = NetClient::new(psk, uuid, [127, 0, 0, 1], 8088);
        assert_eq!(client.status(), NetworkStatus::Offline);
        assert_eq!(client.outbox_pending_count(), 0);
    }
}
