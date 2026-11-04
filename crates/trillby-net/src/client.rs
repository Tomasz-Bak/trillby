//! Client Network State Machine & POSIX Event Loop Integration
//!
//! Driven directly by the non-blocking `libc::poll` loop in PID 1.
//! Operates on real monotonic millisecond timestamps (CLOCK_MONOTONIC).
//! Implements PSK + HKDF-SHA256 key establishment, automatic OTA rekeying,
//! offline outbox queuing, and anti-replay sequence tracking.

use crate::outbox::{Outbox, OutboxError};
use crate::packet::{
    decrypt_and_unpack, derive_session_key, generate_client_nonce, pack_and_authenticate_hmac,
    pack_and_encrypt_directed, verify_and_unpack_hmac, AckPayload, AuthInitPayload, Direction,
    FrameHeader, HandshakeInitPayload, HandshakeRespPayload, HeartbeatPayload, MsgType,
    WorkEventPayload, HEADER_LEN, HMAC_TAG_LEN, MAX_FRAME_LEN, TAG_LEN,
};
use crate::posix::PosixSocket;
use trillby_core::net_types::NetworkStatus;

/// If the in-flight event is not ACKed within this window the link is presumed
/// dead (half-open TCP, wedged server) and is torn down; the event is resent on
/// the next session. TCP already guarantees delivery within a live connection,
/// so there is no in-session retransmission.
pub const ACK_TIMEOUT_MS: u64 = 10_000;

/// Upper bound on recv() calls per poll step so a chatty peer can't starve the
/// UI loop. poll() is level-triggered, so leftover data wakes us immediately.
const MAX_RECV_PER_STEP: usize = 16;
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
    session_id: u32,
    session_salt: [u8; 4],
    session_key: [u8; 32],
    client_nonce: [u8; 32],
    tx_seq: u32,
    rx_seq: u32,
    outbox: Outbox<OUTBOX_CAP>,
    inflight: Option<Inflight>,
    rx_buf: [u8; MAX_FRAME_LEN * 2],
    rx_len: usize,
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
            session_id: 0,
            session_salt: [0u8; 4],
            session_key: [0u8; 32],
            client_nonce: [0u8; 32],
            tx_seq: 1,
            rx_seq: 0,
            outbox: Outbox::new(),
            inflight: None,
            rx_buf: [0u8; MAX_FRAME_LEN * 2],
            rx_len: 0,
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

    /// Enqueue an application data payload (MsgType::Data) for transmission.
    pub fn send_data(&mut self, data: &[u8]) -> Result<(), OutboxError> {
        self.enqueue_event(MsgType::Data, data)
    }

    /// Enqueue a structured work/session event payload (MsgType::Data) for transmission.
    pub fn send_work_event(&mut self, payload: &WorkEventPayload) -> Result<(), OutboxError> {
        let mut buf = [0u8; WorkEventPayload::LEN];
        payload.encode(&mut buf).map_err(|_| OutboxError::FrameTooLarge)?;
        self.enqueue_event(MsgType::Data, &buf)
    }

    /// Enqueue an authentication request payload (MsgType::AuthInit) for transmission.
    pub fn send_auth(&mut self, auth: &AuthInitPayload) -> Result<(), OutboxError> {
        let mut buf = [0u8; AuthInitPayload::LEN];
        auth.encode(&mut buf).map_err(|_| OutboxError::FrameTooLarge)?;
        self.enqueue_event(MsgType::AuthInit, &buf)
    }

    /// Enqueue a telemetry heartbeat payload (MsgType::Heartbeat) for transmission.
    pub fn send_heartbeat(&mut self, heartbeat: &HeartbeatPayload) -> Result<(), OutboxError> {
        let mut buf = [0u8; HeartbeatPayload::LEN];
        heartbeat.encode(&mut buf).map_err(|_| OutboxError::FrameTooLarge)?;
        self.enqueue_event(MsgType::Heartbeat, &buf)
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
                    if self.state == ClientState::Online && self.rx_len >= HEADER_LEN {
                        self.receive_frames(now_ms, false, &mut on_data);
                    }
                }
            }
            ClientState::Online => {
                if (revents & (libc::POLLERR | libc::POLLHUP)) != 0 {
                    self.transition_to_disconnected(now_ms);
                } else {
                    let has_in = (revents & libc::POLLIN) != 0;
                    if has_in || self.rx_len >= HEADER_LEN {
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

    fn transition_to_disconnected(&mut self, now_ms: u64) {
        self.socket.close();
        self.rx_len = 0;
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

        let mut pt_buf = [0u8; HandshakeInitPayload::LEN];
        let _ = init_payload.encode(&mut pt_buf);

        // HandshakeInit is authenticated using root PSK via HMAC-SHA256 (no cipher nonce reuse)
        let mut frame_buf = [0u8; MAX_FRAME_LEN];
        if let Ok(len) = pack_and_authenticate_hmac(
            &self.psk,
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
        if self.socket.is_open() {
            loop {
                if self.rx_len >= self.rx_buf.len() {
                    self.transition_to_disconnected(now_ms);
                    return;
                }
                match self.socket.recv(&mut self.rx_buf[self.rx_len..]) {
                    Ok(0) => {
                        self.transition_to_disconnected(now_ms);
                        return;
                    }
                    Ok(n) => {
                        self.rx_len += n;
                    }
                    Err(err) if err == libc::EAGAIN || err == libc::EWOULDBLOCK => {
                        break;
                    }
                    Err(_) => {
                        self.transition_to_disconnected(now_ms);
                        return;
                    }
                }
            }
        }

        if self.rx_len >= HEADER_LEN {
            let hdr = match FrameHeader::decode(&self.rx_buf[..HEADER_LEN]) {
                Ok(h) => h,
                Err(_) => {
                    self.transition_to_disconnected(now_ms);
                    return;
                }
            };

            let frame_total_len = HEADER_LEN + (hdr.payload_len as usize);
            if frame_total_len > MAX_FRAME_LEN || (hdr.payload_len as usize) < HMAC_TAG_LEN {
                self.transition_to_disconnected(now_ms);
                return;
            }

            if self.rx_len < frame_total_len {
                return; // Wait for full frame in subsequent poll
            }

            if hdr.msg_type == MsgType::HandshakeResp {
                let verify_res = verify_and_unpack_hmac(
                    &self.psk,
                    &self.rx_buf[..frame_total_len],
                );
                if let Ok((_hdr, pt)) = verify_res {
                    if let Ok(resp) = HandshakeRespPayload::decode(pt) {
                        self.session_id = resp.assigned_session_id;
                        self.session_salt = resp.session_salt;
                        self.session_key = derive_session_key(
                            &self.psk,
                            &resp.session_salt,
                            &self.client_nonce,
                            &resp.server_nonce,
                        );

                        self.tx_seq = 1;
                        self.rx_seq = 0;
                        self.inflight = None;
                        self.rx_buf.copy_within(frame_total_len..self.rx_len, 0);
                        self.rx_len -= frame_total_len;
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
            match self.socket.recv(&mut self.rx_buf[self.rx_len..]) {
                Ok(0) => {
                    self.transition_to_disconnected(now_ms);
                    return;
                }
                Ok(n) => self.rx_len += n,
                Err(err) if err == libc::EAGAIN || err == libc::EWOULDBLOCK => return,
                Err(_) => {
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
        while self.rx_len >= HEADER_LEN {
            let hdr = match FrameHeader::decode(&self.rx_buf[..HEADER_LEN]) {
                Ok(h) => h,
                Err(_) => {
                    self.transition_to_disconnected(now_ms);
                    return false;
                }
            };
            if hdr.direction() != Direction::ServerToClient {
                self.transition_to_disconnected(now_ms);
                return false;
            }

            let frame_total_len = HEADER_LEN + (hdr.payload_len as usize);
            if frame_total_len > MAX_FRAME_LEN || (hdr.payload_len as usize) < TAG_LEN {
                self.transition_to_disconnected(now_ms);
                return false;
            }

            if self.rx_len < frame_total_len {
                // Incomplete frame, wait for remaining bytes
                break;
            }

            let decrypt_res = decrypt_and_unpack(
                &self.session_key,
                &self.session_salt,
                &mut self.rx_buf[..frame_total_len],
            );

            match decrypt_res {
                Ok((hdr, pt)) => {
                    // Anti-replay check
                    if hdr.seq_num > self.rx_seq {
                        self.rx_seq = hdr.seq_num;
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
                }
                Err(_) => {
                    self.transition_to_disconnected(now_ms);
                    return false;
                }
            }

            self.rx_buf.copy_within(frame_total_len..self.rx_len, 0);
            self.rx_len -= frame_total_len;
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

        let seq = self.tx_seq;
        let mut frame = [0u8; MAX_FRAME_LEN];
        let Ok(len) = pack_and_encrypt_directed(
            &self.session_key,
            &self.session_salt,
            Direction::ClientToServer,
            msg_type,
            self.session_id,
            seq,
            plaintext,
            &mut frame,
        ) else {
            // Unreachable: Outbox::push enforces MAX_EVENT_LEN. Drop rather than wedge the queue.
            self.outbox.pop();
            return;
        };

        match self.socket.send(&frame[..len]) {
            Ok(n) if n == len => {
                self.tx_seq = self.tx_seq.wrapping_add(1);
                self.inflight = Some(Inflight { seq, sent_ms: now_ms });
            }
            // Socket buffer full: nothing written, retry when wants_write() -> POLLOUT fires.
            Err(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => {}
            // Short write (stream now desynced) or hard error: reconnect, event stays queued.
            _ => self.transition_to_disconnected(now_ms),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use crate::packet::{
        decrypt_and_unpack, derive_session_key, pack_and_authenticate_hmac, pack_and_encrypt,
        verify_and_unpack_hmac, AckPayload, AuthRespPayload, FrameHeader, HandshakeInitPayload,
        HandshakeRespPayload, MsgType, HEADER_LEN, MAX_FRAME_LEN, MAX_PAYLOAD_LEN,
    };

    fn establish_online_session<const CAP: usize>(
        psk: [u8; 32],
        uuid: [u8; 16],
    ) -> (NetClient<CAP>, TcpStream, [u8; 32], [u8; 4], u32, u64) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let mut client: NetClient<CAP> = NetClient::new(psk, uuid, [127, 0, 0, 1], port);
        let mut now_ms = 1000u64;

        // Initiate connection attempt
        client.poll_step(now_ms, 0);

        // Accept connection on listener
        let mut server_stream = {
            let start = std::time::Instant::now();
            loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if start.elapsed() > std::time::Duration::from_millis(500) {
                            panic!("Timeout waiting for client connection");
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(e) => panic!("Accept error: {:?}", e),
                }
            }
        };
        server_stream.set_nonblocking(true).unwrap();
        server_stream.set_nodelay(true).unwrap();

        // Step client with POLLOUT -> client sends HandshakeInit
        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        // Server reads HandshakeInit
        let mut init_buf = [0u8; MAX_FRAME_LEN];
        let n = read_exact_frame(&mut server_stream, &mut init_buf);
        let (_init_hdr, init_pt) = verify_and_unpack_hmac(&psk, &init_buf[..n])
            .expect("Server failed to verify HandshakeInit HMAC");
        let init_payload = HandshakeInitPayload::decode(init_pt).expect("decode HandshakeInit");
        assert_eq!(init_payload.device_uuid, uuid);

        // Server prepares and sends HandshakeResp
        let server_nonce = crate::crypto::sha256(b"SERVER_TEST_NONCE_ENTROPY");
        let session_id = 0xAABB_CCDD;
        let session_salt = [10, 20, 30, 40];
        let resp_payload = HandshakeRespPayload {
            server_nonce,
            assigned_session_id: session_id,
            session_salt,
        };
        let mut resp_pt = [0u8; HandshakeRespPayload::LEN];
        resp_payload.encode(&mut resp_pt).unwrap();

        let mut resp_frame = [0u8; MAX_FRAME_LEN];
        let resp_len = pack_and_authenticate_hmac(
            &psk,
            MsgType::HandshakeResp,
            session_id,
            0,
            &resp_pt,
            &mut resp_frame,
        ).unwrap();
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

    fn read_exact_frame(stream: &mut TcpStream, buf: &mut [u8; MAX_FRAME_LEN]) -> usize {
        stream.set_nonblocking(false).unwrap();
        stream.read_exact(&mut buf[..HEADER_LEN]).expect("read frame header");
        let hdr = FrameHeader::decode(&buf[..HEADER_LEN]).expect("decode frame header");
        let total_len = HEADER_LEN + (hdr.payload_len as usize);
        assert!(total_len <= MAX_FRAME_LEN, "Frame exceeds MAX_FRAME_LEN");
        stream.read_exact(&mut buf[HEADER_LEN..total_len]).expect("read frame payload");
        stream.set_nonblocking(true).unwrap();
        total_len
    }

    fn step_loopback<const CAP: usize, F>(
        client: &mut NetClient<CAP>,
        now_ms: u64,
        on_data: F,
    ) -> Option<NetworkStatus>
    where
        F: FnMut(MsgType, &[u8]),
    {
        let fd = client.socket_fd();
        let revents = if fd >= 0 {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLOUT,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut pfd, 1, 10) };
            if ret > 0 { pfd.revents } else { 0 }
        } else {
            0
        };
        client.poll_step_with(now_ms, revents, on_data)
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
        let _ = step_loopback(&mut client, now_ms, |_, _| {});

        // Server reads PAYLOAD_1
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = read_exact_frame(&mut server_stream, &mut buf);
        let (hdr, pt) = decrypt_and_unpack(&session_key, &session_salt, &mut buf[..n])
            .expect("server decrypt PAYLOAD_1");
        assert_eq!(hdr.msg_type, MsgType::Data);
        assert_eq!(hdr.seq_num, 1);
        assert_eq!(pt, b"PAYLOAD_1");

        // 3. Server sends ACK for seq 1
        let ack = AckPayload { acked_seq: 1, status: 0 };
        let mut ack_pt = [0u8; AckPayload::LEN];
        ack.encode(&mut ack_pt).unwrap();
        let mut ack_frame = [0u8; MAX_FRAME_LEN];
        let ack_len = pack_and_encrypt(
            &session_key,
            &session_salt,
            MsgType::Ack,
            session_id,
            10,
            &ack_pt,
            &mut ack_frame,
        ).unwrap();
        server_stream.write_all(&ack_frame[..ack_len]).unwrap();

        // 4. Client steps -> receives ACK for seq 1, pops PAYLOAD_1, and flushes PAYLOAD_2 (seq 2)
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, _| {});
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
        let _ = step_loopback(&mut client, now_ms, |_, _| {});

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
            let _ = step_loopback(&mut client, now_ms, |_, _| {});
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
            let _ = step_loopback(&mut client, now_ms, |_, _| {});
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
            let _ = step_loopback(&mut client, now_ms, |_, _| {});
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
            let _ = step_loopback(&mut client, now_ms, |_, _| {});
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
            let _ = step_loopback(&mut client, now_ms, |msg_type, data| {
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
            let _ = step_loopback(&mut client, now_ms, |msg_type, data| {
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

        let send_frame = |stream: &mut TcpStream, seq: u32, payload: &[u8]| {
            let mut frame = [0u8; MAX_FRAME_LEN];
            let len = pack_and_encrypt(
                &session_key,
                &session_salt,
                MsgType::Data,
                session_id,
                seq,
                payload,
                &mut frame,
            ).unwrap();
            stream.write_all(&frame[..len]).unwrap();
        };

        let mut dispatch_count = 0;
        let mut last_payload = [0u8; 32];
        let mut last_len = 0;

        // 1. Initial fresh packet with seq = 5
        send_frame(&mut server_stream, 5, b"INITIAL_SEQ_5");
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, data| {
            dispatch_count += 1;
            last_payload[..data.len()].copy_from_slice(data);
            last_len = data.len();
        });
        assert_eq!(dispatch_count, 1);
        assert_eq!(&last_payload[..last_len], b"INITIAL_SEQ_5");

        // 2. Replayed packet with duplicate seq = 5
        send_frame(&mut server_stream, 5, b"REPLAY_SEQ_5");
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, _| {
            dispatch_count += 1;
        });
        assert_eq!(dispatch_count, 1, "Duplicate seq 5 must be dropped");

        // 3. Stale packet with old seq = 3 (< 5)
        send_frame(&mut server_stream, 3, b"STALE_SEQ_3");
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, _| {
            dispatch_count += 1;
        });
        assert_eq!(dispatch_count, 1, "Past seq 3 must be dropped");

        // 4. Fresh packet with seq = 6 (> 5)
        send_frame(&mut server_stream, 6, b"FRESH_SEQ_6");
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, data| {
            dispatch_count += 1;
            last_payload[..data.len()].copy_from_slice(data);
            last_len = data.len();
        });
        assert_eq!(dispatch_count, 2);
        assert_eq!(&last_payload[..last_len], b"FRESH_SEQ_6");

        // 5. Sequence jump to seq = 50
        send_frame(&mut server_stream, 50, b"JUMP_SEQ_50");
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, data| {
            dispatch_count += 1;
            last_payload[..data.len()].copy_from_slice(data);
            last_len = data.len();
        });
        assert_eq!(dispatch_count, 3);
        assert_eq!(&last_payload[..last_len], b"JUMP_SEQ_50");

        // 6. Packet with seq = 49 (stale after jump)
        send_frame(&mut server_stream, 49, b"STALE_SEQ_49");
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, _| {
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
        if client.socket_fd() >= 0 {
            let mut pfd = libc::pollfd {
                fd: client.socket_fd(),
                events: libc::POLLIN | libc::POLLOUT,
                revents: 0,
            };
            let _ = unsafe { libc::poll(&mut pfd, 1, 100) };
            let _ = client.poll_step(1050, pfd.revents);
        }

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
        listener.set_nonblocking(true).unwrap();

        let mut client: NetClient<4> = NetClient::new(psk, uuid, [127, 0, 0, 1], port);
        let mut now_ms = 1000u64;

        // Trigger connect
        client.poll_step(now_ms, 0);

        // Accept on server
        let mut server_stream = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("Accept error: {:?}", e),
            }
        };
        server_stream.set_nonblocking(true).unwrap();

        // Client sends HandshakeInit
        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        // Server reads HandshakeInit
        let mut init_buf = [0u8; MAX_FRAME_LEN];
        let n = read_exact_frame(&mut server_stream, &mut init_buf);
        assert!(verify_and_unpack_hmac(&psk, &init_buf[..n]).is_ok());

        // Server crafts HandshakeResp
        let server_nonce = crate::crypto::sha256(b"SERVER_NONCE");
        let resp_payload = HandshakeRespPayload {
            server_nonce,
            assigned_session_id: 12345,
            session_salt: [1, 2, 3, 4],
        };
        let mut resp_pt = [0u8; HandshakeRespPayload::LEN];
        resp_payload.encode(&mut resp_pt).unwrap();

        let mut resp_frame = [0u8; MAX_FRAME_LEN];
        let resp_len = pack_and_authenticate_hmac(
            &psk,
            MsgType::HandshakeResp,
            12345,
            0,
            &resp_pt,
            &mut resp_frame,
        ).unwrap();

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
        let _ = step_loopback(&mut client, now_ms, |_, _| {});
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = read_exact_frame(&mut server_stream, &mut buf);
        let (hdr, _) = decrypt_and_unpack(&session_key, &session_salt, &mut buf[..n]).unwrap();
        assert_eq!(hdr.seq_num, 1);

        // Server sends ACK for seq 1
        let ack = AckPayload { acked_seq: 1, status: 0 };
        let mut ack_pt = [0u8; AckPayload::LEN];
        ack.encode(&mut ack_pt).unwrap();
        let mut ack_frame = [0u8; MAX_FRAME_LEN];
        let ack_len = pack_and_encrypt(
            &session_key,
            &session_salt,
            MsgType::Ack,
            hdr.session_id,
            99,
            &ack_pt,
            &mut ack_frame,
        ).unwrap();
        server_stream.write_all(&ack_frame[..ack_len]).unwrap();

        // Client steps -> processes ACK, pops MSG_1
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, _| {});
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

        let mut server_stream = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("Accept error: {:?}", e),
            }
        };
        server_stream.set_nonblocking(true).unwrap();
        server_stream.set_nodelay(true).unwrap();

        // Step client with POLLOUT -> HandshakeInit
        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        let mut init_buf = [0u8; MAX_FRAME_LEN];
        let n = read_exact_frame(&mut server_stream, &mut init_buf);
        let (_hdr, init_pt) = verify_and_unpack_hmac(&psk, &init_buf[..n]).unwrap();
        let init_payload = HandshakeInitPayload::decode(init_pt).unwrap();

        // Send HandshakeResp
        let server_nonce = crate::crypto::sha256(b"SRV_NONCE");
        let session_id = 999;
        let session_salt = [1, 2, 3, 4];
        let resp_payload = HandshakeRespPayload {
            server_nonce,
            assigned_session_id: session_id,
            session_salt,
        };
        let mut resp_pt = [0u8; HandshakeRespPayload::LEN];
        resp_payload.encode(&mut resp_pt).unwrap();
        let mut resp_frame = [0u8; MAX_FRAME_LEN];
        let resp_len = pack_and_authenticate_hmac(
            &psk,
            MsgType::HandshakeResp,
            session_id,
            0,
            &resp_pt,
            &mut resp_frame,
        ).unwrap();
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
        let ack1 = AckPayload { acked_seq: 1, status: 0 };
        let mut ack1_pt = [0u8; AckPayload::LEN];
        ack1.encode(&mut ack1_pt).unwrap();
        let mut ack1_frame = [0u8; MAX_FRAME_LEN];
        let ack1_len = pack_and_encrypt(
            &session_key,
            &session_salt,
            MsgType::Ack,
            session_id,
            1,
            &ack1_pt,
            &mut ack1_frame,
        ).unwrap();
        server_stream.write_all(&ack1_frame[..ack1_len]).unwrap();

        // Step client -> processes ACK for seq 1, pops EVENT_1, and flushes EVENT_2 (seq 2)
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 1);

        // Server receives OFFLINE_EVENT_2
        let n2 = read_exact_frame(&mut server_stream, &mut buf);
        let (hdr2, pt2) = decrypt_and_unpack(&session_key, &session_salt, &mut buf[..n2]).unwrap();
        assert_eq!(hdr2.seq_num, 2);
        assert_eq!(pt2, b"OFFLINE_EVENT_2");

        // Server ACKs seq 2
        let ack2 = AckPayload { acked_seq: 2, status: 0 };
        let mut ack2_pt = [0u8; AckPayload::LEN];
        ack2.encode(&mut ack2_pt).unwrap();
        let mut ack2_frame = [0u8; MAX_FRAME_LEN];
        let ack2_len = pack_and_encrypt(
            &session_key,
            &session_salt,
            MsgType::Ack,
            session_id,
            2,
            &ack2_pt,
            &mut ack2_frame,
        ).unwrap();
        server_stream.write_all(&ack2_frame[..ack2_len]).unwrap();

        // Step client -> processes ACK for seq 2, pops EVENT_2
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, _| {});
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
        let _ = step_loopback(&mut client, now_ms, |_, _| {});

        // Server reads frame but does NOT ACK
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = read_exact_frame(&mut server_stream, &mut buf);
        let (hdr, _) = decrypt_and_unpack(&session_key, &session_salt, &mut buf[..n]).unwrap();
        assert_eq!(hdr.seq_num, 1);

        // Advance monotonic time by ACK_TIMEOUT_MS
        now_ms += ACK_TIMEOUT_MS + 100;
        let _ = step_loopback(&mut client, now_ms, |_, _| {});

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

        let mut stream1 = {
            let start = std::time::Instant::now();
            loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if start.elapsed() > std::time::Duration::from_millis(500) {
                            panic!("Timeout waiting for client connection session 1");
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(e) => panic!("Accept error: {:?}", e),
                }
            }
        };
        stream1.set_nonblocking(true).unwrap();
        stream1.set_nodelay(true).unwrap();

        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        // Server 1 receives HandshakeInit
        let mut init_buf = [0u8; MAX_FRAME_LEN];
        let n1 = read_exact_frame(&mut stream1, &mut init_buf);
        let (_init_hdr, init_pt) = verify_and_unpack_hmac(&psk, &init_buf[..n1]).unwrap();
        let init_payload1 = HandshakeInitPayload::decode(init_pt).unwrap();

        // Server 1 sends HandshakeResp (session_id = 10, salt = [1, 2, 3, 4])
        let server_nonce1 = crate::crypto::sha256(b"SERVER_NONCE_SESSION_1");
        let session_id_1 = 10u32;
        let salt_1 = [1u8, 2, 3, 4];
        let resp_payload1 = HandshakeRespPayload {
            server_nonce: server_nonce1,
            assigned_session_id: session_id_1,
            session_salt: salt_1,
        };
        let mut resp_pt1 = [0u8; HandshakeRespPayload::LEN];
        resp_payload1.encode(&mut resp_pt1).unwrap();
        let mut resp_frame1 = [0u8; MAX_FRAME_LEN];
        let resp_len1 = pack_and_authenticate_hmac(
            &psk,
            MsgType::HandshakeResp,
            session_id_1,
            0,
            &resp_pt1,
            &mut resp_frame1,
        ).unwrap();
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

        let mut stream2 = {
            let start = std::time::Instant::now();
            loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if start.elapsed() > std::time::Duration::from_millis(500) {
                            panic!("Timeout waiting for client connection session 2");
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(e) => panic!("Accept error: {:?}", e),
                }
            }
        };
        stream2.set_nonblocking(true).unwrap();
        stream2.set_nodelay(true).unwrap();

        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        // Server 2 receives HandshakeInit
        let n2 = read_exact_frame(&mut stream2, &mut init_buf);
        let (_init_hdr2, init_pt2) = verify_and_unpack_hmac(&psk, &init_buf[..n2]).unwrap();
        let init_payload2 = HandshakeInitPayload::decode(init_pt2).unwrap();

        // Server 2 sends HandshakeResp (session_id = 20, salt = [9, 8, 7, 6])
        let server_nonce2 = crate::crypto::sha256(b"SERVER_NONCE_SESSION_2");
        let session_id_2 = 20u32;
        let salt_2 = [9u8, 8, 7, 6];
        let resp_payload2 = HandshakeRespPayload {
            server_nonce: server_nonce2,
            assigned_session_id: session_id_2,
            session_salt: salt_2,
        };
        let mut resp_pt2 = [0u8; HandshakeRespPayload::LEN];
        resp_payload2.encode(&mut resp_pt2).unwrap();
        let mut resp_frame2 = [0u8; MAX_FRAME_LEN];
        let resp_len2 = pack_and_authenticate_hmac(
            &psk,
            MsgType::HandshakeResp,
            session_id_2,
            0,
            &resp_pt2,
            &mut resp_frame2,
        ).unwrap();
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
        let _ = step_loopback(&mut client, now_ms, |_, _| {});

        // Server 2 reads Event 1
        let n_resealed1 = read_exact_frame(&mut stream2, &mut frame_buf);
        let (hdr_s2_ev1, pt_s2_ev1) = decrypt_and_unpack(&session_key_2, &salt_2, &mut frame_buf[..n_resealed1]).unwrap();
        assert_eq!(hdr_s2_ev1.session_id, session_id_2);
        assert_eq!(hdr_s2_ev1.seq_num, 1);
        assert_eq!(pt_s2_ev1, b"EVENT_1_DATA");

        // Server 2 ACKs Event 1 (seq = 1)
        let ack1 = AckPayload { acked_seq: 1, status: 0 };
        let mut ack1_pt = [0u8; AckPayload::LEN];
        ack1.encode(&mut ack1_pt).unwrap();
        let mut ack1_frame = [0u8; MAX_FRAME_LEN];
        let ack1_len = pack_and_encrypt(
            &session_key_2,
            &salt_2,
            MsgType::Ack,
            session_id_2,
            1,
            &ack1_pt,
            &mut ack1_frame,
        ).unwrap();
        stream2.write_all(&ack1_frame[..ack1_len]).unwrap();

        // Client steps -> processes ACK 1, pops Event 1, and flushes Event 2!
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, _| {});

        // Server 2 reads Event 2
        let n_s2_ev2 = read_exact_frame(&mut stream2, &mut frame_buf);
        let (hdr_s2_ev2, pt_s2_ev2) = decrypt_and_unpack(&session_key_2, &salt_2, &mut frame_buf[..n_s2_ev2]).unwrap();
        assert_eq!(hdr_s2_ev2.session_id, session_id_2);
        assert_eq!(hdr_s2_ev2.seq_num, 2);
        assert_eq!(pt_s2_ev2, b"EVENT_2_DATA");

        // Server 2 ACKs Event 2 (seq = 2)
        let ack2 = AckPayload { acked_seq: 2, status: 0 };
        let mut ack2_pt = [0u8; AckPayload::LEN];
        ack2.encode(&mut ack2_pt).unwrap();
        let mut ack2_frame = [0u8; MAX_FRAME_LEN];
        let ack2_len = pack_and_encrypt(
            &session_key_2,
            &salt_2,
            MsgType::Ack,
            session_id_2,
            2,
            &ack2_pt,
            &mut ack2_frame,
        ).unwrap();
        stream2.write_all(&ack2_frame[..ack2_len]).unwrap();

        // Client steps -> processes ACK 2, pops Event 2
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, _| {});
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
        let _ = step_loopback(&mut client, now_ms, |_, _| {});

        // Server reads frame seq 1
        let mut buf = [0u8; MAX_FRAME_LEN];
        let n = read_exact_frame(&mut server_stream, &mut buf);
        let (hdr, _) = decrypt_and_unpack(&session_key, &session_salt, &mut buf[..n]).unwrap();
        assert_eq!(hdr.seq_num, 1);

        // Helper closure to send ACK
        let mut send_ack = |acked_seq: u32, server_seq: u32| {
            let ack = AckPayload { acked_seq, status: 0 };
            let mut ack_pt = [0u8; AckPayload::LEN];
            ack.encode(&mut ack_pt).unwrap();
            let mut ack_frame = [0u8; MAX_FRAME_LEN];
            let len = pack_and_encrypt(
                &session_key,
                &session_salt,
                MsgType::Ack,
                session_id,
                server_seq,
                &ack_pt,
                &mut ack_frame,
            ).unwrap();
            server_stream.write_all(&ack_frame[..len]).unwrap();
        };

        // Send ACK for seq 2 (mismatch: inflight is seq 1)
        send_ack(2, 1);
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 1);

        // Send ACK for seq 0 (mismatch: inflight is seq 1)
        send_ack(0, 2);
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 1);

        // Send ACK for seq 1 (matching inflight)
        send_ack(1, 3);
        now_ms += 10;
        let _ = step_loopback(&mut client, now_ms, |_, _| {});
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

        let mut server_stream = {
            let start = std::time::Instant::now();
            loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if start.elapsed() > std::time::Duration::from_millis(500) {
                            panic!("Timeout waiting for client connection");
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(e) => panic!("Accept error: {:?}", e),
                }
            }
        };
        server_stream.set_nonblocking(true).unwrap();
        server_stream.set_nodelay(true).unwrap();

        now_ms += 10;
        client.poll_step(now_ms, libc::POLLOUT);
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        // Server reads HandshakeInit
        let mut init_buf = [0u8; MAX_FRAME_LEN];
        let n = read_exact_frame(&mut server_stream, &mut init_buf);
        let (_init_hdr, init_pt) = verify_and_unpack_hmac(&psk, &init_buf[..n]).unwrap();
        let init_payload = HandshakeInitPayload::decode(init_pt).unwrap();

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
        let resp_payload = HandshakeRespPayload {
            server_nonce,
            assigned_session_id: session_id,
            session_salt,
        };
        let mut resp_pt = [0u8; HandshakeRespPayload::LEN];
        resp_payload.encode(&mut resp_pt).unwrap();
        let mut resp_frame = [0u8; MAX_FRAME_LEN];
        let resp_len = pack_and_authenticate_hmac(
            &psk,
            MsgType::HandshakeResp,
            session_id,
            0,
            &resp_pt,
            &mut resp_frame,
        ).unwrap();

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
}
