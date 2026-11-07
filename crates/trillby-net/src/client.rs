//! Client Network State Machine & POSIX Event Loop Integration
//!
//! Driven directly by the non-blocking `libc::poll` loop in PID 1.
//! Operates on real monotonic millisecond timestamps (CLOCK_MONOTONIC).
//! Implements PSK + HKDF-SHA256 key establishment,
//! offline outbox queuing, and anti-replay sequence tracking.

use crate::framing::{FrameAssembler, RecvOutcome, SessionCrypto, MAX_RECV_PER_STEP};
use crate::outbox::{Outbox, OutboxError};
use crate::packet::{
    derive_session_key, generate_client_nonce,
    pack_and_authenticate_hmac_inplace, verify_and_unpack_hmac,
    AckPayload, AuthInitPayload, Direction, HandshakeInitPayload,
    HandshakeRespPayload, MsgType, Payload, WorkEventPayload, HEADER_LEN, HMAC_TAG_LEN,
    MAX_FRAME_LEN, TAG_LEN,
};
use crate::posix::PosixSocket;
use trillby_core::net_types::NetworkStatus;

/// If the in-flight event is not ACKed within this window the link is presumed
/// dead (half-open TCP, wedged server) and is torn down; the event is resent on
/// the next session. TCP already guarantees delivery within a live connection,
/// so there is no in-session retransmission.
pub const ACK_TIMEOUT_MS: u64 = 10_000;


const INITIAL_BACKOFF_MS: u32 = 1_000;
const MAX_BACKOFF_MS: u32 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Disconnected { next_attempt_ms: u64, backoff_ms: u32 },
    Connecting,
    Handshaking,
    Online,
}

/// Outbox head that has been sealed and written to the current session.
#[derive(Debug, Clone, Copy)]
struct Inflight {
    seq: u32,
    sent_ms: u64,
}

pub struct NetClient<const OUTBOX_CAP: usize> {
    psk: [u8; 32],
    device_uuid: [u8; 16],
    server_ip: [u8; 4],
    server_port: u16,
    state: ClientState,
    socket: PosixSocket,
    client_nonce: [u8; 32],
    crypto: SessionCrypto,
    outbox: Outbox<OUTBOX_CAP>,
    inflight: Option<Inflight>,
    assembler: FrameAssembler,
    /// Delay applied to the next failure; doubles per failure, capped at MAX_BACKOFF_MS.
    backoff_ms: u32,
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
                backoff_ms: INITIAL_BACKOFF_MS,
            },
            socket: PosixSocket::invalid(),
            client_nonce: [0u8; 32],
            crypto: SessionCrypto::new(),
            outbox: Outbox::new(),
            inflight: None,
            assembler: FrameAssembler::new(),
            backoff_ms: INITIAL_BACKOFF_MS,
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

    /// Whether the poll loop should request `POLLOUT` for `socket_fd()`.
    ///
    /// True only while a connect is in progress or an outbox event is waiting
    /// to be written. Do NOT derive this from `outbox_pending_count() > 0`: a
    /// TCP socket is nearly always writable, so that would busy-spin the loop
    /// for the whole time an event is waiting on its ACK.
    pub fn wants_write(&self) -> bool {
        match self.state {
            ClientState::Connecting => true,
            ClientState::Online => self.inflight.is_none() && !self.outbox.is_empty(),
            _ => false,
        }
    }

    /// Returns the poll events mask to request for `socket_fd()`: always `POLLIN`,
    /// plus `POLLOUT` when [`wants_write`](Self::wants_write) is true.
    pub fn poll_events(&self) -> i16 {
        libc::POLLIN | if self.wants_write() { libc::POLLOUT } else { 0 }
    }

    /// Enqueue an application data payload (MsgType::Data) for transmission.
    pub fn send_data(&mut self, data: &[u8]) -> Result<(), OutboxError> {
        self.enqueue_event(MsgType::Data, data)
    }

    /// Enqueue a typed payload for transmission.
    pub fn send_payload<P: Payload>(&mut self, payload: &P) -> Result<(), OutboxError> {
        let mut buf = [0u8; crate::outbox::MAX_EVENT_LEN];
        if P::LEN > crate::outbox::MAX_EVENT_LEN {
            return Err(OutboxError::FrameTooLarge);
        }
        payload.encode(&mut buf[..P::LEN]).map_err(|_| OutboxError::FrameTooLarge)?;
        self.enqueue_event(P::MSG_TYPE, &buf[..P::LEN])
    }

    /// Enqueue a high-level session event translated to its protocol wire payload.
    pub fn send_session_event(
        &mut self,
        ev: &trillby_core::SessionEvent,
        now_ms: u64,
    ) -> Result<(), OutboxError> {
        match ev {
            trillby_core::SessionEvent::OperatorLogin { operator_id, .. } => {
                let payload = AuthInitPayload::new(operator_id.as_bytes(), now_ms);
                self.send_payload(&payload)
            }
            trillby_core::SessionEvent::OperatorLogout { operator_id, .. } => {
                let payload = WorkEventPayload::operator_logout(operator_id.as_bytes(), now_ms);
                self.send_payload(&payload)
            }
            trillby_core::SessionEvent::WorkStart {
                operator_id,
                job_id,
                ..
            } => {
                let payload = WorkEventPayload::work_start(
                    operator_id.as_bytes(),
                    job_id.as_bytes(),
                    now_ms,
                );
                self.send_payload(&payload)
            }
            trillby_core::SessionEvent::WorkStop {
                operator_id,
                job_id,
                duration_ms,
                ..
            } => {
                let payload = WorkEventPayload::work_stop(
                    operator_id.as_bytes(),
                    job_id.as_bytes(),
                    now_ms,
                    *duration_ms,
                );
                self.send_payload(&payload)
            }
        }
    }

    /// Enqueue an event payload (plaintext). It is sealed with whatever session
    /// is current at transmit time, so it is safe to enqueue while offline.
    pub fn enqueue_event(&mut self, msg_type: MsgType, plaintext: &[u8]) -> Result<(), OutboxError> {
        self.outbox.push(msg_type, plaintext)
    }

    /// Primary event loop step. Called by the poll loop on timeout or socket event.
    /// Operates on real monotonic milliseconds `now_ms`.
    /// Returns `Some(new_status)` if the high-level network status changed.
    pub fn poll_step(&mut self, now_ms: u64, revents: i16) -> Option<NetworkStatus> {
        self.poll_step_with(now_ms, revents, |_, _| {})
    }

    /// Event loop step with callback for incoming application data (MsgType::Data, MsgType::AuthResp).
    pub fn poll_step_with(
        &mut self,
        now_ms: u64,
        revents: i16,
        mut on_data: impl FnMut(MsgType, &[u8]),
    ) -> Option<NetworkStatus> {
        let prev_status = self.status();

        match self.state {
            ClientState::Disconnected { next_attempt_ms, .. } => {
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
                                    self.transition_to_disconnected(now_ms);
                                }
                            }
                        }
                        Err(_) => {
                            self.transition_to_disconnected(now_ms);
                        }
                    }
                }
            }
            ClientState::Connecting => {
                if (revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                    self.transition_to_disconnected(now_ms);
                } else if (revents & libc::POLLOUT) != 0 {
                    if self.socket.check_connect_completed().is_ok() {
                        self.state = ClientState::Handshaking;
                        self.send_handshake_init(now_ms);
                    } else {
                        self.transition_to_disconnected(now_ms);
                    }
                }
            }
            ClientState::Handshaking => {
                if (revents & (libc::POLLERR | libc::POLLHUP)) != 0 {
                    self.transition_to_disconnected(now_ms);
                } else if (revents & libc::POLLIN) != 0 {
                    self.handle_handshake_response(now_ms);
                    if self.state == ClientState::Online && self.assembler.len() >= HEADER_LEN {
                        self.receive_frames(now_ms, false, &mut on_data);
                    }
                }
            }
            ClientState::Online => {
                if (revents & (libc::POLLERR | libc::POLLHUP)) != 0 {
                    self.transition_to_disconnected(now_ms);
                } else {
                    let has_in = (revents & libc::POLLIN) != 0;
                    if has_in || self.assembler.len() >= HEADER_LEN {
                        self.receive_frames(now_ms, has_in, &mut on_data);
                    }
                    if self.state == ClientState::Online {
                        match self.inflight {
                            Some(f) if now_ms.saturating_sub(f.sent_ms) >= ACK_TIMEOUT_MS => {
                                self.transition_to_disconnected(now_ms);
                            }
                            _ => self.flush_outbox(now_ms),
                        }
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

    pub fn wait_and_step_with(
        &mut self,
        now_ms: u64,
        timeout_ms: libc::c_int,
        on_data: impl FnMut(MsgType, &[u8]),
    ) -> Option<NetworkStatus> {
        let fd = self.socket_fd();
        let revents = if fd >= 0 {
            let mut pfd = libc::pollfd {
                fd,
                events: self.poll_events(),
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if ret > 0 {
                pfd.revents
            } else {
                0
            }
        } else {
            0
        };
        self.poll_step_with(now_ms, revents, on_data)
    }

    fn transition_to_disconnected(&mut self, now_ms: u64) {
        self.socket.close();
        self.assembler.clear();
        // Unacked head stays queued and is re-sealed for the next session.
        self.inflight = None;
        let delay = self.backoff_ms;
        self.backoff_ms = delay.saturating_mul(2).min(MAX_BACKOFF_MS);
        self.state = ClientState::Disconnected {
            next_attempt_ms: now_ms + u64::from(delay),
            backoff_ms: self.backoff_ms,
        };
    }

    fn send_handshake_init(&mut self, now_ms: u64) {
        if crate::posix::fill_random(&mut self.client_nonce).is_err() {
            self.client_nonce = generate_client_nonce(&self.psk, &self.device_uuid, now_ms);
        }

        let init_payload = HandshakeInitPayload {
            client_nonce: self.client_nonce,
            device_uuid: self.device_uuid,
        };

        // HandshakeInit is authenticated using root PSK via HMAC-SHA256 (no cipher nonce reuse)
        let mut frame_buf = [0u8; MAX_FRAME_LEN];
        let payload_slice = &mut frame_buf[HEADER_LEN..HEADER_LEN + HandshakeInitPayload::LEN];
        if init_payload.encode(payload_slice).is_ok() {
            if let Ok(len) = pack_and_authenticate_hmac_inplace(
                &self.psk,
                MsgType::HandshakeInit,
                0,
                0,
                HandshakeInitPayload::LEN,
                &mut frame_buf,
            ) {
                let _ = self.socket.send(&frame_buf[..len]);
            }
        }
    }

    fn handle_handshake_response(&mut self, now_ms: u64) {
        if self.socket.is_open() {
            loop {
                match self.assembler.recv_from(&self.socket) {
                    RecvOutcome::Data => {}
                    RecvOutcome::WouldBlock => break,
                    RecvOutcome::Closed | RecvOutcome::Error => {
                        self.transition_to_disconnected(now_ms);
                        return;
                    }
                }
            }
        }

        match self.assembler.next_frame(HMAC_TAG_LEN) {
            Ok(Some((hdr, frame_total_len))) => {
                if hdr.msg_type == MsgType::HandshakeResp {
                    let frame = self.assembler.frame_slice(frame_total_len);
                    if let Ok((_hdr, pt)) = verify_and_unpack_hmac(&self.psk, frame) {
                        if let Ok(resp) = HandshakeRespPayload::decode(pt) {
                            let session_key = derive_session_key(
                                &self.psk,
                                &resp.session_salt,
                                &self.client_nonce,
                                &resp.server_nonce,
                            );
                            self.crypto.reset(
                                resp.assigned_session_id,
                                resp.session_salt,
                                session_key,
                            );
                            self.inflight = None;
                            self.assembler.consume(frame_total_len);
                            self.backoff_ms = INITIAL_BACKOFF_MS;
                            self.state = ClientState::Online;
                            self.flush_outbox(now_ms);
                            return;
                        }
                    }
                }
                // Authentication or format failure
                self.transition_to_disconnected(now_ms);
            }
            Ok(None) => {
                // Wait for full frame in subsequent poll
            }
            Err(_) => {
                self.transition_to_disconnected(now_ms);
            }
        }
    }

    /// Alternate between dispatching every complete buffered frame and reading
    /// more bytes. Because complete frames are consumed before each recv(), the
    /// buffer never holds more than one partial frame (< MAX_FRAME_LEN), so a
    /// burst of back-to-back frames can never overflow `rx_buf`.
    fn receive_frames(
        &mut self,
        now_ms: u64,
        can_read_socket: bool,
        on_data: &mut impl FnMut(MsgType, &[u8]),
    ) {
        let mut reads = 0;
        loop {
            if !self.dispatch_buffered_frames(now_ms, on_data) {
                return; // disconnected
            }
            if !can_read_socket || !self.socket.is_open() || reads >= MAX_RECV_PER_STEP {
                return;
            }
            reads += 1;
            match self.assembler.recv_from(&self.socket) {
                RecvOutcome::Data => {}
                RecvOutcome::WouldBlock => return,
                RecvOutcome::Closed | RecvOutcome::Error => {
                    self.transition_to_disconnected(now_ms);
                    return;
                }
            }
        }
    }

    /// Returns `false` if the connection was torn down.
    fn dispatch_buffered_frames(
        &mut self,
        now_ms: u64,
        on_data: &mut impl FnMut(MsgType, &[u8]),
    ) -> bool {
        loop {
            let (hdr, frame_total_len) = match self.assembler.next_frame(TAG_LEN) {
                Ok(Some(pair)) => pair,
                Ok(None) => break,
                Err(_) => {
                    self.transition_to_disconnected(now_ms);
                    return false;
                }
            };
            if !hdr.is_direction(Direction::ServerToClient) {
                self.transition_to_disconnected(now_ms);
                return false;
            }

            let frame = self.assembler.frame_slice_mut(frame_total_len);
            match self.crypto.open(frame) {
                Ok(Some((hdr, pt))) => {
                    match hdr.msg_type {
                        MsgType::Ack => {
                            if let (Ok(ack), Some(f)) = (AckPayload::decode(pt), self.inflight) {
                                if ack.acked_seq == f.seq {
                                    self.outbox.pop();
                                    self.inflight = None;
                                }
                            }
                        }
                        MsgType::Data | MsgType::AuthResp => {
                            on_data(hdr.msg_type, pt);
                        }
                        _ => {}
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    self.transition_to_disconnected(now_ms);
                    return false;
                }
            }

            self.assembler.consume(frame_total_len);
        }
        true
    }

    /// Seal the outbox head with the *current* session and write it, unless an
    /// event is already in flight (stop-and-wait: one unacked frame at a time).
    fn flush_outbox(&mut self, now_ms: u64) {
        if self.inflight.is_some() || !self.socket.is_open() {
            return;
        }
        let Some((msg_type, plaintext)) = self.outbox.peek() else {
            return;
        };

        let seq = self.crypto.tx_seq;
        let mut frame = [0u8; MAX_FRAME_LEN];
        let Ok(len) = self.crypto.seal(
            Direction::ClientToServer,
            msg_type,
            plaintext,
            &mut frame,
        ) else {
            // Unreachable: Outbox::push enforces MAX_EVENT_LEN. Drop rather than wedge the queue.
            self.outbox.pop();
            return;
        };

        match self.socket.send(&frame[..len]) {
            Ok(n) if n == len => {
                self.inflight = Some(Inflight { seq, sent_ms: now_ms });
            }
            // Socket buffer full: nothing written, retry when wants_write() -> POLLOUT fires.
            Err(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => {
                self.crypto.tx_seq = seq;
            }
            // Short write (stream now desynced) or hard error: reconnect, event stays queued.
            _ => self.transition_to_disconnected(now_ms),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use crate::test_support::{
        accept_peer, build_handshake_resp, read_exact_frame, read_handshake_init, write_ack,
        write_server_frame,
    };
    use crate::packet::{
        decrypt_and_unpack, derive_session_key, pack_and_encrypt, AckPayload,
        AuthRespPayload, FrameHeader, MsgType, HEADER_LEN, MAX_FRAME_LEN, MAX_PAYLOAD_LEN,
    };

    fn establish_online_session<const CAP: usize>(
        psk: [u8; 32],
        uuid: [u8; 16],
    ) -> (NetClient<CAP>, TcpStream, [u8; 32], [u8; 4], u32, u64) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        let mut client: NetClient<CAP> = NetClient::new(psk, uuid, [127, 0, 0, 1], port);
        let mut now_ms = 1000u64;

        // Initiate connection attempt
        client.poll_step(now_ms, 0);

        let mut server_stream = accept_peer(&listener);

        // Step client with POLLOUT -> client sends HandshakeInit
        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        // Server reads HandshakeInit
        let init_payload = read_handshake_init(&mut server_stream, &psk);
        assert_eq!(init_payload.device_uuid, uuid);

        // Server prepares and sends HandshakeResp
        let server_nonce = crate::crypto::sha256(b"SERVER_TEST_NONCE_ENTROPY");
        let session_id = 0xAABB_CCDD;
        let session_salt = [10, 20, 30, 40];
        let (resp_frame, resp_len) =
            build_handshake_resp(&psk, session_id, session_salt, server_nonce);
        server_stream.write_all(&resp_frame[..resp_len]).expect("write HandshakeResp");

        // Step client with POLLIN -> client completes handshake and becomes Online
        now_ms += 10;
        client.poll_step(now_ms, libc::POLLIN);
        assert_eq!(client.status(), NetworkStatus::Online);

        let session_key = derive_session_key(
            &psk,
            &session_salt,
            &init_payload.client_nonce,
            &server_nonce,
        );

        (client, server_stream, session_key, session_salt, session_id, now_ms)
    }


    #[test]
    fn test_client_initial_state() {
        let psk = [0x99u8; 32];
        let uuid = [0x11u8; 16];
        let client: NetClient<16> = NetClient::new(psk, uuid, [127, 0, 0, 1], 8088);
        assert_eq!(client.status(), NetworkStatus::Offline);
        assert_eq!(client.outbox_pending_count(), 0);
        assert_eq!(client.socket_fd(), -1);
    }

    #[test]
    fn test_outbox_fifo_ack_draining_and_durability_across_drops() {
        let psk = [0x11u8; 32];
        let uuid = [0x22u8; 16];
        let (mut client, mut server_stream, session_key, session_salt, session_id, mut now_ms) =
            establish_online_session::<4>(psk, uuid);

        assert_eq!(client.status(), NetworkStatus::Online);
        assert_eq!(client.outbox_pending_count(), 0);

        // 1. Enqueue 3 payloads
        client.send_data(b"PAYLOAD_1").unwrap();
        client.send_data(b"PAYLOAD_2").unwrap();
        client.send_data(b"PAYLOAD_3").unwrap();

        assert_eq!(client.status(), NetworkStatus::Syncing(3));
        assert_eq!(client.outbox_pending_count(), 3);

        // 2. Step client -> flushes front of outbox (PAYLOAD_1, seq 1)
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});

        // Server reads PAYLOAD_1
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = read_exact_frame(&mut server_stream, &mut buf);
        let (hdr, pt) = decrypt_and_unpack(&session_key, &session_salt, &mut buf[..n])
            .expect("server decrypt PAYLOAD_1");
        assert_eq!(hdr.msg_type, MsgType::Data);
        assert_eq!(hdr.seq_num, 1);
        assert_eq!(pt, b"PAYLOAD_1");

        // 3. Server sends ACK for seq 1
        write_ack(&mut server_stream, &session_key, &session_salt, session_id, 10, 1);

        // 4. Client steps -> receives ACK for seq 1, pops PAYLOAD_1, and flushes PAYLOAD_2 (seq 2)
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 2);
        assert_eq!(client.status(), NetworkStatus::Syncing(2));

        // Server reads PAYLOAD_2
        let n = read_exact_frame(&mut server_stream, &mut buf);
        let (hdr2, pt2) = decrypt_and_unpack(&session_key, &session_salt, &mut buf[..n])
            .expect("server decrypt PAYLOAD_2");
        assert_eq!(hdr2.msg_type, MsgType::Data);
        assert_eq!(hdr2.seq_num, 2);
        assert_eq!(pt2, b"PAYLOAD_2");

        // 5. Abrupt connection drop: Server drops the connection without ACKing PAYLOAD_2 or PAYLOAD_3
        drop(server_stream);

        // Client steps -> detects EOF/hangup on socket
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});

        // Invariants after drop:
        // - Status must be Offline
        assert_eq!(client.status(), NetworkStatus::Offline);
        // - Socket file descriptor must be released (closed) to prevent FD leak
        assert_eq!(client.socket_fd(), -1);
        // - Outbox MUST retain unacknowledged frames (PAYLOAD_2 and PAYLOAD_3)
        assert_eq!(client.outbox_pending_count(), 2);
    }

    #[test]
    fn test_adversarial_malformed_packets_never_panic_and_close_fd() {
        // Subcase 1: Oversized payload length header
        {
            let (mut client, mut server_stream, _, _, session_id, mut now_ms) =
                establish_online_session::<4>([0x31; 32], [0x41; 16]);
            let hdr = FrameHeader::new(MsgType::Data, session_id, 1, 0xFFFF);
            let mut malformed_hdr = [0u8; HEADER_LEN];
            hdr.encode(&mut malformed_hdr);
            server_stream.write_all(&malformed_hdr).unwrap();
            now_ms += 10;
            let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
            assert_eq!(client.status(), NetworkStatus::Offline);
            assert_eq!(client.socket_fd(), -1);
        }

        // Subcase 2: Invalid magic bytes
        {
            let (mut client, mut server_stream, _, _, _, mut now_ms) =
                establish_online_session::<4>([0x32; 32], [0x42; 16]);
            let bad_magic = [0xDE, 0xAD, 0x01, MsgType::Data as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0];
            server_stream.write_all(&bad_magic).unwrap();
            now_ms += 10;
            let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
            assert_eq!(client.status(), NetworkStatus::Offline);
            assert_eq!(client.socket_fd(), -1);
        }

        // Subcase 3: Corrupted Poly1305 MAC tag
        {
            let (mut client, mut server_stream, session_key, session_salt, session_id, mut now_ms) =
                establish_online_session::<4>([0x33; 32], [0x43; 16]);
            let mut frame = [0u8; MAX_FRAME_LEN];
            let len = pack_and_encrypt(
                &session_key,
                &session_salt,
                MsgType::Data,
                session_id,
                1,
                b"secret_data",
                &mut frame,
            ).unwrap();
            frame[len - 1] ^= 0xA5;
            server_stream.write_all(&frame[..len]).unwrap();
            now_ms += 10;
            let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
            assert_eq!(client.status(), NetworkStatus::Offline);
            assert_eq!(client.socket_fd(), -1);
        }

        // Subcase 4: 500 bytes of raw garbage noise
        {
            let (mut client, mut server_stream, _, _, _, mut now_ms) =
                establish_online_session::<4>([0x34; 32], [0x44; 16]);
            let garbage = [0xCCu8; 500];
            server_stream.write_all(&garbage).unwrap();
            now_ms += 10;
            let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
            assert_eq!(client.status(), NetworkStatus::Offline);
            assert_eq!(client.socket_fd(), -1);
        }
    }

    #[test]
    fn test_byte_by_byte_tcp_stream_fragmentation_reassembly() {
        let psk = [0x55u8; 32];
        let uuid = [0x66u8; 16];
        let (mut client, mut server_stream, session_key, session_salt, session_id, mut now_ms) =
            establish_online_session::<4>(psk, uuid);

        let test_payload = b"FRAGMENTED_TELEMETRY_RECORD_001";
        let mut frame = [0u8; MAX_FRAME_LEN];
        let frame_len = pack_and_encrypt(
            &session_key,
            &session_salt,
            MsgType::Data,
            session_id,
            1,
            test_payload,
            &mut frame,
        ).unwrap();

        let mut received = [0u8; 64];
        let mut received_len = 0;

        // Drip feed 1 byte at a time over TCP
        for (i, &byte) in frame[..frame_len].iter().enumerate() {
            server_stream.write_all(&[byte]).unwrap();
            now_ms += 1;
            let _ = client.wait_and_step_with(now_ms, 10, |msg_type, data| {
                assert_eq!(msg_type, MsgType::Data);
                received[..data.len()].copy_from_slice(data);
                received_len = data.len();
            });

            if i + 1 < frame_len {
                assert_eq!(received_len, 0, "Dispatched prematurely on byte {}", i);
                assert_eq!(client.status(), NetworkStatus::Online);
            }
        }

        // On the exact last byte, the frame must be fully reassembled and dispatched
        assert_eq!(received_len, test_payload.len());
        assert_eq!(&received[..received_len], test_payload);

        // Feed a second packet split across 7-byte chunks
        let second_payload = b"SECOND_PACKET_ARBITRARY_CHUNK_SPLIT";
        let mut frame2 = [0u8; MAX_FRAME_LEN];
        let frame2_len = pack_and_encrypt(
            &session_key,
            &session_salt,
            MsgType::Data,
            session_id,
            2,
            second_payload,
            &mut frame2,
        ).unwrap();

        let mut received2_len = 0;
        for chunk in frame2[..frame2_len].chunks(7) {
            server_stream.write_all(chunk).unwrap();
            now_ms += 1;
            let _ = client.wait_and_step_with(now_ms, 10, |msg_type, data| {
                assert_eq!(msg_type, MsgType::Data);
                received[..data.len()].copy_from_slice(data);
                received2_len = data.len();
            });
        }

        assert_eq!(received2_len, second_payload.len());
        assert_eq!(&received[..received2_len], second_payload);
        assert_eq!(client.status(), NetworkStatus::Online);
    }

    #[test]
    fn test_anti_replay_window_enforcement_over_wire() {
        let psk = [0x77u8; 32];
        let uuid = [0x88u8; 16];
        let (mut client, mut server_stream, session_key, session_salt, session_id, mut now_ms) =
            establish_online_session::<4>(psk, uuid);

        let mut dispatch_count = 0;
        let mut last_payload = [0u8; 32];
        let mut last_len = 0;

        // 1. Initial fresh packet with seq = 5
        write_server_frame(
            &mut server_stream,
            &session_key,
            &session_salt,
            session_id,
            5,
            MsgType::Data,
            b"INITIAL_SEQ_5",
        );
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, data| {
            dispatch_count += 1;
            last_payload[..data.len()].copy_from_slice(data);
            last_len = data.len();
        });
        assert_eq!(dispatch_count, 1);
        assert_eq!(&last_payload[..last_len], b"INITIAL_SEQ_5");

        // 2. Replayed packet with duplicate seq = 5
        write_server_frame(
            &mut server_stream,
            &session_key,
            &session_salt,
            session_id,
            5,
            MsgType::Data,
            b"REPLAY_SEQ_5",
        );
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {
            dispatch_count += 1;
        });
        assert_eq!(dispatch_count, 1, "Duplicate seq 5 must be dropped");

        // 3. Stale packet with old seq = 3 (< 5)
        write_server_frame(
            &mut server_stream,
            &session_key,
            &session_salt,
            session_id,
            3,
            MsgType::Data,
            b"STALE_SEQ_3",
        );
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {
            dispatch_count += 1;
        });
        assert_eq!(dispatch_count, 1, "Past seq 3 must be dropped");

        // 4. Fresh packet with seq = 6 (> 5)
        write_server_frame(
            &mut server_stream,
            &session_key,
            &session_salt,
            session_id,
            6,
            MsgType::Data,
            b"FRESH_SEQ_6",
        );
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, data| {
            dispatch_count += 1;
            last_payload[..data.len()].copy_from_slice(data);
            last_len = data.len();
        });
        assert_eq!(dispatch_count, 2);
        assert_eq!(&last_payload[..last_len], b"FRESH_SEQ_6");

        // 5. Sequence jump to seq = 50
        write_server_frame(
            &mut server_stream,
            &session_key,
            &session_salt,
            session_id,
            50,
            MsgType::Data,
            b"JUMP_SEQ_50",
        );
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, data| {
            dispatch_count += 1;
            last_payload[..data.len()].copy_from_slice(data);
            last_len = data.len();
        });
        assert_eq!(dispatch_count, 3);
        assert_eq!(&last_payload[..last_len], b"JUMP_SEQ_50");

        // 6. Packet with seq = 49 (stale after jump)
        write_server_frame(
            &mut server_stream,
            &session_key,
            &session_salt,
            session_id,
            49,
            MsgType::Data,
            b"STALE_SEQ_49",
        );
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {
            dispatch_count += 1;
        });
        assert_eq!(dispatch_count, 3, "Stale seq 49 must be dropped");
        assert_eq!(client.status(), NetworkStatus::Online);
    }

    #[test]
    fn test_connection_refused_cleans_up_fd_without_leak() {
        let psk = [0x55u8; 32];
        let uuid = [0x77u8; 16];
        // Port 1 on loopback is closed
        let mut client: NetClient<4> = NetClient::new(psk, uuid, [127, 0, 0, 1], 1);

        assert_eq!(client.status(), NetworkStatus::Offline);
        assert_eq!(client.socket_fd(), -1);

        // Trigger connection attempt at t = 1000ms
        let _ = client.poll_step(1000, 0);

        // If connection was EINPROGRESS, poll the socket for ECONNREFUSED
        let _ = client.wait_and_step_with(1050, 100, |_, _| {});

        // Must be cleanly disconnected with socket closed
        assert_eq!(client.status(), NetworkStatus::Offline);
        assert_eq!(client.socket_fd(), -1);
        match client.state() {
            ClientState::Disconnected { next_attempt_ms, backoff_ms } => {
                assert!(next_attempt_ms >= 1000);
                assert_eq!(backoff_ms, 2000);
            }
            s => panic!("Expected Disconnected state, got {:?}", s),
        }
    }

    #[test]
    fn test_handshake_hmac_tamper_rejection() {
        let psk = [0xAAu8; 32];
        let uuid = [0xBBu8; 16];

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        let mut client: NetClient<4> = NetClient::new(psk, uuid, [127, 0, 0, 1], port);
        let mut now_ms = 1000u64;

        // Trigger connect
        client.poll_step(now_ms, 0);

        // Accept on server
        let mut server_stream = accept_peer(&listener);

        // Client sends HandshakeInit
        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        // Server reads HandshakeInit
        let _init_payload = read_handshake_init(&mut server_stream, &psk);

        // Server crafts HandshakeResp
        let server_nonce = crate::crypto::sha256(b"SERVER_NONCE");
        let (mut resp_frame, resp_len) =
            build_handshake_resp(&psk, 12345, [1, 2, 3, 4], server_nonce);

        // Maliciously tamper with the HMAC tag (last byte)
        resp_frame[resp_len - 1] ^= 0xFF;
        server_stream.write_all(&resp_frame[..resp_len]).unwrap();

        // Client steps -> handles tampered response
        now_ms += 10;
        client.poll_step(now_ms, libc::POLLIN);

        // Verification must fail -> Client transitions to Offline and closes socket
        assert_eq!(client.status(), NetworkStatus::Offline);
        assert_eq!(client.socket_fd(), -1);
        assert!(matches!(client.state(), ClientState::Disconnected { .. }));
    }

    #[test]
    fn test_outbox_capacity_backpressure_and_status_tracking() {
        let psk = [0x12u8; 32];
        let uuid = [0x34u8; 16];
        let (mut client, mut server_stream, session_key, session_salt, _session_id, mut now_ms) =
            establish_online_session::<2>(psk, uuid);

        assert_eq!(client.status(), NetworkStatus::Online);
        assert_eq!(client.outbox_pending_count(), 0);

        // Fill outbox to capacity (OUTBOX_CAP = 2)
        assert!(client.send_data(b"MSG_1").is_ok());
        assert_eq!(client.status(), NetworkStatus::Syncing(1));
        assert_eq!(client.outbox_pending_count(), 1);

        assert!(client.send_data(b"MSG_2").is_ok());
        assert_eq!(client.status(), NetworkStatus::Syncing(2));
        assert_eq!(client.outbox_pending_count(), 2);

        // Exceed capacity -> Err(OutboxError::Full)
        assert_eq!(client.send_data(b"MSG_3"), Err(OutboxError::Full));
        assert_eq!(client.outbox_pending_count(), 2);

        // Exceed MAX_PAYLOAD_LEN -> Err(OutboxError::FrameTooLarge)
        let huge = [0u8; (MAX_PAYLOAD_LEN as usize) + 1];
        assert_eq!(client.send_data(&huge), Err(OutboxError::FrameTooLarge));

        // Flush MSG_1 and server ACKs it
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = read_exact_frame(&mut server_stream, &mut buf);
        let (hdr, _) = decrypt_and_unpack(&session_key, &session_salt, &mut buf[..n]).unwrap();
        assert_eq!(hdr.seq_num, 1);

        // Server sends ACK for seq 1
        write_ack(&mut server_stream, &session_key, &session_salt, hdr.session_id, 99, 1);

        // Client steps -> processes ACK, pops MSG_1
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 1);
        assert_eq!(client.status(), NetworkStatus::Syncing(1));

        // Now capacity is available again -> enqueueing MSG_3 succeeds!
        assert!(client.send_data(b"MSG_3").is_ok());
        assert_eq!(client.outbox_pending_count(), 2);
        assert_eq!(client.status(), NetworkStatus::Syncing(2));
    }

    #[test]
    fn test_offline_enqueued_events_survive_and_flush_on_connect() {
        let psk = [0x78u8; 32];
        let uuid = [0x56u8; 16];

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let mut client: NetClient<4> = NetClient::new(psk, uuid, [127, 0, 0, 1], port);

        // Enqueue 2 events while completely offline
        assert_eq!(client.status(), NetworkStatus::Offline);
        client.send_data(b"OFFLINE_EVENT_1").unwrap();
        client.send_data(b"OFFLINE_EVENT_2").unwrap();
        assert_eq!(client.outbox_pending_count(), 2);

        // Drive connection
        let mut now_ms = 1000u64;
        client.poll_step(now_ms, 0);

        let mut server_stream = accept_peer(&listener);

        // Step client with POLLOUT -> HandshakeInit
        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        let init_payload = read_handshake_init(&mut server_stream, &psk);

        // Send HandshakeResp
        let server_nonce = crate::crypto::sha256(b"SRV_NONCE");
        let session_id = 999;
        let session_salt = [1, 2, 3, 4];
        let (resp_frame, resp_len) =
            build_handshake_resp(&psk, session_id, session_salt, server_nonce);
        server_stream.write_all(&resp_frame[..resp_len]).unwrap();

        // Step client -> completes handshake, becomes Online, and flushes OFFLINE_EVENT_1!
        now_ms += 10;
        client.poll_step(now_ms, libc::POLLIN);
        assert_eq!(client.status(), NetworkStatus::Syncing(2));

        let session_key = derive_session_key(
            &psk,
            &session_salt,
            &init_payload.client_nonce,
            &server_nonce,
        );

        // Server receives OFFLINE_EVENT_1
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n1 = read_exact_frame(&mut server_stream, &mut buf);
        let (hdr1, pt1) = decrypt_and_unpack(&session_key, &session_salt, &mut buf[..n1]).unwrap();
        assert_eq!(hdr1.seq_num, 1);
        assert_eq!(pt1, b"OFFLINE_EVENT_1");

        // Server ACKs seq 1
        write_ack(&mut server_stream, &session_key, &session_salt, session_id, 1, 1);

        // Step client -> processes ACK for seq 1, pops EVENT_1, and flushes EVENT_2 (seq 2)
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 1);

        // Server receives OFFLINE_EVENT_2
        let n2 = read_exact_frame(&mut server_stream, &mut buf);
        let (hdr2, pt2) = decrypt_and_unpack(&session_key, &session_salt, &mut buf[..n2]).unwrap();
        assert_eq!(hdr2.seq_num, 2);
        assert_eq!(pt2, b"OFFLINE_EVENT_2");

        // Server ACKs seq 2
        write_ack(&mut server_stream, &session_key, &session_salt, session_id, 2, 2);

        // Step client -> processes ACK for seq 2, pops EVENT_2
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 0);
        assert_eq!(client.status(), NetworkStatus::Online);
    }

    #[test]
    fn test_ack_timeout_triggers_disconnect_and_retains_head() {
        let psk = [0x89u8; 32];
        let uuid = [0xABu8; 16];
        let (mut client, mut server_stream, session_key, session_salt, _session_id, mut now_ms) =
            establish_online_session::<4>(psk, uuid);

        client.send_data(b"UNACKED_DATA").unwrap();
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});

        // Server reads frame but does NOT ACK
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = read_exact_frame(&mut server_stream, &mut buf);
        let (hdr, _) = decrypt_and_unpack(&session_key, &session_salt, &mut buf[..n]).unwrap();
        assert_eq!(hdr.seq_num, 1);

        // Advance monotonic time by ACK_TIMEOUT_MS
        now_ms += ACK_TIMEOUT_MS + 100;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});

        // Must have detected timeout and transitioned to Offline, closing socket
        assert_eq!(client.status(), NetworkStatus::Offline);
        assert_eq!(client.socket_fd(), -1);
        // The unacknowledged frame must still be retained in outbox!
        assert_eq!(client.outbox_pending_count(), 1);
    }

    #[test]
    fn test_exponential_backoff_doubles_across_consecutive_connect_failures() {
        let psk = [0x55u8; 32];
        let uuid = [0xBBu8; 16];
        let mut client: NetClient<4> = NetClient::new(psk, uuid, [127, 0, 0, 1], 1);

        let mut now_ms = 1000u64;
        let expected_delays = [1000u64, 2000, 4000, 8000, 16000, 30000];
        let expected_next_backoffs = [2000u32, 4000, 8000, 16000, 30000, 30000];

        for i in 0..5 {
            // Disconnected -> Connecting
            let _ = client.poll_step(now_ms, 0);
            assert_eq!(client.state(), ClientState::Connecting);

            // Connecting -> Disconnected via POLLERR
            let _ = client.poll_step(now_ms, libc::POLLERR);
            match client.state() {
                ClientState::Disconnected { next_attempt_ms, backoff_ms } => {
                    assert_eq!(
                        next_attempt_ms - now_ms,
                        expected_delays[i],
                        "Cycle {}: unexpected delay",
                        i
                    );
                    assert_eq!(
                        backoff_ms,
                        expected_next_backoffs[i],
                        "Cycle {}: unexpected next backoff",
                        i
                    );
                    now_ms = next_attempt_ms;
                }
                other => panic!("Cycle {}: expected Disconnected, got {:?}", i, other),
            }
        }
    }

    #[test]
    fn test_unacked_inflight_head_resealed_and_delivered_on_new_session() {
        let psk = [0x77u8; 32];
        let uuid = [0x88u8; 16];

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let mut client: NetClient<4> = NetClient::new(psk, uuid, [127, 0, 0, 1], port);
        let mut now_ms = 1000u64;

        // --- Session 1 ---
        client.poll_step(now_ms, 0);

        let mut stream1 = accept_peer(&listener);

        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        // Server 1 receives HandshakeInit
        let init_payload1 = read_handshake_init(&mut stream1, &psk);

        // Server 1 sends HandshakeResp (session_id = 10, salt = [1, 2, 3, 4])
        let server_nonce1 = crate::crypto::sha256(b"SERVER_NONCE_SESSION_1");
        let session_id_1 = 10u32;
        let salt_1 = [1u8, 2, 3, 4];
        let (resp_frame1, resp_len1) =
            build_handshake_resp(&psk, session_id_1, salt_1, server_nonce1);
        stream1.write_all(&resp_frame1[..resp_len1]).unwrap();

        now_ms += 10;
        client.poll_step(now_ms, libc::POLLIN);
        assert_eq!(client.status(), NetworkStatus::Online);

        let session_key_1 = derive_session_key(
            &psk,
            &salt_1,
            &init_payload1.client_nonce,
            &server_nonce1,
        );

        // Client enqueues Event 1 and flushes it
        client.send_data(b"EVENT_1_DATA").unwrap();
        assert_eq!(client.outbox_pending_count(), 1);

        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);

        // Server 1 reads Event 1
        let mut frame_buf = [0u8; MAX_FRAME_LEN];
        let n_ev1 = read_exact_frame(&mut stream1, &mut frame_buf);
        let (hdr_ev1, pt_ev1) = decrypt_and_unpack(&session_key_1, &salt_1, &mut frame_buf[..n_ev1]).unwrap();
        assert_eq!(hdr_ev1.seq_num, 1);
        assert_eq!(pt_ev1, b"EVENT_1_DATA");

        // Client enqueues Event 2 while Event 1 is in-flight
        client.send_data(b"EVENT_2_DATA").unwrap();
        assert_eq!(client.outbox_pending_count(), 2);

        // Close server 1 stream WITHOUT ACKing event 1!
        drop(stream1);

        // Client detects disconnect
        now_ms += 10;
        client.poll_step(now_ms, libc::POLLERR | libc::POLLHUP);
        assert_eq!(client.status(), NetworkStatus::Offline);

        // Advance monotonic time past backoff to reconnect
        if let ClientState::Disconnected { next_attempt_ms, .. } = client.state() {
            now_ms = next_attempt_ms + 10;
        }

        // --- Session 2 ---
        client.poll_step(now_ms, 0);

        let mut stream2 = accept_peer(&listener);

        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        // Server 2 receives HandshakeInit
        let init_payload2 = read_handshake_init(&mut stream2, &psk);

        // Server 2 sends HandshakeResp (session_id = 20, salt = [9, 8, 7, 6])
        let server_nonce2 = crate::crypto::sha256(b"SERVER_NONCE_SESSION_2");
        let session_id_2 = 20u32;
        let salt_2 = [9u8, 8, 7, 6];
        let (resp_frame2, resp_len2) =
            build_handshake_resp(&psk, session_id_2, salt_2, server_nonce2);
        stream2.write_all(&resp_frame2[..resp_len2]).unwrap();

        now_ms += 10;
        client.poll_step(now_ms, libc::POLLIN);
        assert_eq!(client.state(), ClientState::Online);

        let session_key_2 = derive_session_key(
            &psk,
            &salt_2,
            &init_payload2.client_nonce,
            &server_nonce2,
        );

        // Client steps -> flushes Event 1 resealed under Session 2!
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});

        // Server 2 reads Event 1
        let n_resealed1 = read_exact_frame(&mut stream2, &mut frame_buf);
        let (hdr_s2_ev1, pt_s2_ev1) = decrypt_and_unpack(&session_key_2, &salt_2, &mut frame_buf[..n_resealed1]).unwrap();
        assert_eq!(hdr_s2_ev1.session_id, session_id_2);
        assert_eq!(hdr_s2_ev1.seq_num, 1);
        assert_eq!(pt_s2_ev1, b"EVENT_1_DATA");

        // Server 2 ACKs Event 1 (seq = 1)
        write_ack(&mut stream2, &session_key_2, &salt_2, session_id_2, 1, 1);

        // Client steps -> processes ACK 1, pops Event 1, and flushes Event 2!
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});

        // Server 2 reads Event 2
        let n_s2_ev2 = read_exact_frame(&mut stream2, &mut frame_buf);
        let (hdr_s2_ev2, pt_s2_ev2) = decrypt_and_unpack(&session_key_2, &salt_2, &mut frame_buf[..n_s2_ev2]).unwrap();
        assert_eq!(hdr_s2_ev2.session_id, session_id_2);
        assert_eq!(hdr_s2_ev2.seq_num, 2);
        assert_eq!(pt_s2_ev2, b"EVENT_2_DATA");

        // Server 2 ACKs Event 2 (seq = 2)
        write_ack(&mut stream2, &session_key_2, &salt_2, session_id_2, 2, 2);

        // Client steps -> processes ACK 2, pops Event 2
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 0);
        assert_eq!(client.status(), NetworkStatus::Online);
    }

    #[test]
    fn test_mismatched_ack_seq_does_not_pop_inflight_event() {
        let psk = [0x12u8; 32];
        let uuid = [0x34u8; 16];
        let (mut client, mut server_stream, session_key, session_salt, session_id, mut now_ms) =
            establish_online_session::<4>(psk, uuid);

        client.send_data(b"DATA_SEQ_1").unwrap();
        assert_eq!(client.outbox_pending_count(), 1);

        // Client steps -> flushes frame seq 1
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});

        // Server reads frame seq 1
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = read_exact_frame(&mut server_stream, &mut buf);
        let (hdr, _) = decrypt_and_unpack(&session_key, &session_salt, &mut buf[..n]).unwrap();
        assert_eq!(hdr.seq_num, 1);

        // Send ACK for seq 2 (mismatch: inflight is seq 1)
        write_ack(&mut server_stream, &session_key, &session_salt, session_id, 1, 2);
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 1);

        // Send ACK for seq 0 (mismatch: inflight is seq 1)
        write_ack(&mut server_stream, &session_key, &session_salt, session_id, 2, 0);
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 1);

        // Send ACK for seq 1 (matching inflight)
        write_ack(&mut server_stream, &session_key, &session_salt, session_id, 3, 1);
        now_ms += 10;
        let _ = client.wait_and_step_with(now_ms, 10, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 0);
    }

    #[test]
    fn test_coalesced_handshake_resp_and_encrypted_data_in_single_read() {
        let psk = [0x66u8; 32];
        let uuid = [0x99u8; 16];

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let mut client: NetClient<4> = NetClient::new(psk, uuid, [127, 0, 0, 1], port);
        let mut now_ms = 1000u64;

        // 1. Client connects
        client.poll_step(now_ms, 0);

        let mut server_stream = accept_peer(&listener);

        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        // Server reads HandshakeInit
        let init_payload = read_handshake_init(&mut server_stream, &psk);

        let server_nonce = crate::crypto::sha256(b"SERVER_NONCE_COALESCE");
        let session_id = 0x1234_5678u32;
        let session_salt = [5, 6, 7, 8];

        let session_key = derive_session_key(
            &psk,
            &session_salt,
            &init_payload.client_nonce,
            &server_nonce,
        );

        // Frame 1: HandshakeResp
        let (resp_frame, resp_len) =
            build_handshake_resp(&psk, session_id, session_salt, server_nonce);
        // Frame 2: Encrypted AuthResp (seq = 1)
        let auth_resp = AuthRespPayload { status: 0, role: 1, session_ttl_s: 3600 };
        let mut auth_pt = [0u8; AuthRespPayload::LEN];
        auth_resp.encode(&mut auth_pt).unwrap();
        let mut auth_frame = [0u8; MAX_FRAME_LEN];
        let auth_len = pack_and_encrypt(
            &session_key,
            &session_salt,
            MsgType::AuthResp,
            session_id,
            1,
            &auth_pt,
            &mut auth_frame,
        ).unwrap();

        // Frame 3: Encrypted Data (seq = 2)
        let data_payload = b"COALESCED_COMMAND_PAYLOAD";
        let mut data_frame = [0u8; MAX_FRAME_LEN];
        let data_len = pack_and_encrypt(
            &session_key,
            &session_salt,
            MsgType::Data,
            session_id,
            2,
            data_payload,
            &mut data_frame,
        ).unwrap();

        // Concatenate all 3 frames into a single buffer and write to socket
        let mut coalesced = std::vec::Vec::new();
        coalesced.extend_from_slice(&resp_frame[..resp_len]);
        coalesced.extend_from_slice(&auth_frame[..auth_len]);
        coalesced.extend_from_slice(&data_frame[..data_len]);
        server_stream.write_all(&coalesced).expect("write coalesced frames");

        // Client performs a SINGLE poll_step_with
        now_ms += 10;
        let mut delivered_events: std::vec::Vec<(MsgType, std::vec::Vec<u8>)> = std::vec::Vec::new();
        client.poll_step_with(now_ms, libc::POLLIN, |msg_type, payload| {
            delivered_events.push((msg_type, payload.to_vec()));
        });

        assert_eq!(client.status(), NetworkStatus::Online);
        assert_eq!(delivered_events.len(), 2);
        assert_eq!(delivered_events[0].0, MsgType::AuthResp);
        assert_eq!(delivered_events[1].0, MsgType::Data);
        assert_eq!(delivered_events[1].1, data_payload);
    }

    #[test]
    fn test_poll_events() {
        let mut client: NetClient<4> = NetClient::new([0x42; 32], [0x01; 16], [127, 0, 0, 1], 8080);
        // Initially Disconnected: wants_write is false, so poll_events should only be POLLIN.
        assert!(!client.wants_write());
        assert_eq!(client.poll_events(), libc::POLLIN);

        // Trigger connect attempt -> ClientState::Connecting
        client.poll_step(1000, 0);
        assert!(client.wants_write());
        assert_eq!(client.poll_events(), libc::POLLIN | libc::POLLOUT);
    }

    #[test]
    fn test_send_payload_success_and_too_large() {
        let mut client: NetClient<4> = NetClient::new([0x42; 32], [0x01; 16], [127, 0, 0, 1], 8080);
        let ack = AckPayload { acked_seq: 1, status: 0 };
        assert!(client.send_payload(&ack).is_ok());
        assert_eq!(client.outbox_pending_count(), 1);

        struct HugePayload;
        impl Payload for HugePayload {
            const MSG_TYPE: MsgType = MsgType::Data;
            const LEN: usize = crate::outbox::MAX_EVENT_LEN + 1;
            fn encode(&self, _out: &mut [u8]) -> Result<(), crate::packet::PacketError> {
                Ok(())
            }
        }

        assert_eq!(client.send_payload(&HugePayload), Err(OutboxError::FrameTooLarge));
    }

    #[test]
    fn test_send_session_event() {
        let mut client: NetClient<4> = NetClient::new([0x42; 32], [0x01; 16], [127, 0, 0, 1], 8080);
        let mut op: heapless::String<32> = heapless::String::new();
        op.push_str("OP-0042").unwrap();
        let mut job: heapless::String<64> = heapless::String::new();
        job.push_str("JOB-100").unwrap();

        let login = trillby_core::SessionEvent::OperatorLogin {
            operator_id: op.clone(),
            at_ms: 100,
        };
        assert!(client.send_session_event(&login, 100).is_ok());

        let start = trillby_core::SessionEvent::WorkStart {
            operator_id: op.clone(),
            job_id: job.clone(),
            started_at_ms: 200,
        };
        assert!(client.send_session_event(&start, 200).is_ok());

        let stop = trillby_core::SessionEvent::WorkStop {
            operator_id: op.clone(),
            job_id: job.clone(),
            started_at_ms: 200,
            stopped_at_ms: 500,
            duration_ms: 300,
        };
        assert!(client.send_session_event(&stop, 500).is_ok());

        let logout = trillby_core::SessionEvent::OperatorLogout {
            operator_id: op,
            at_ms: 600,
        };
        assert!(client.send_session_event(&logout, 600).is_ok());
        assert_eq!(client.outbox_pending_count(), 4);

        let extra = trillby_core::SessionEvent::OperatorLogin {
            operator_id: heapless::String::new(),
            at_ms: 700,
        };
        assert_eq!(client.send_session_event(&extra, 700), Err(OutboxError::Full));
    }

    #[test]
    fn handshake_response_split_across_reads_completes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let psk = [0x55u8; 32];
        let uuid = [0x66u8; 16];
        let mut client: NetClient<16> = NetClient::new(psk, uuid, [127, 0, 0, 1], port);
        let mut now_ms = 1000u64;

        // Initiate connection attempt
        client.poll_step(now_ms, 0);

        // Accept connection on listener
        let mut server_stream = accept_peer(&listener);

        // Step client with POLLOUT -> client sends HandshakeInit
        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.state(), ClientState::Handshaking);

        // Server reads HandshakeInit
        let init_payload = read_handshake_init(&mut server_stream, &psk);
        assert_eq!(init_payload.device_uuid, uuid);

        // Server prepares HandshakeResp
        let server_nonce = crate::crypto::sha256(b"SERVER_SPLIT_TEST_NONCE");
        let session_id = 0x1234_5678;
        let session_salt = [1, 2, 3, 4];
        let (resp_frame, resp_len) =
            build_handshake_resp(&psk, session_id, session_salt, server_nonce);
        // Write the first HEADER_LEN + 3 bytes of the response
        server_stream.write_all(&resp_frame[..HEADER_LEN + 3]).unwrap();

        // Step client: must remain in Handshaking state since frame is incomplete
        now_ms += 10;
        client.wait_and_step_with(now_ms, 10, |_, _| {});
        assert_eq!(client.state(), ClientState::Handshaking);

        // Write the remaining bytes
        server_stream.write_all(&resp_frame[HEADER_LEN + 3..resp_len]).unwrap();

        // Step client in a loop (up to 10 iterations)
        for _ in 0..10 {
            now_ms += 10;
            client.wait_and_step_with(now_ms, 10, |_, _| {});
            if client.state() == ClientState::Online {
                break;
            }
        }
        assert_eq!(client.state(), ClientState::Online);
    }
}
