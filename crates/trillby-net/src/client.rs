//! Client Network State Machine & POSIX Event Loop Integration
//!
//! Driven directly by the non-blocking `libc::poll` loop in PID 1.
//! Operates on real monotonic millisecond timestamps (CLOCK_MONOTONIC).
//! Implements PSK + HKDF-SHA256 key establishment, automatic OTA rekeying,
//! offline outbox queuing, and anti-replay sequence tracking.

use crate::outbox::{Outbox, OutboxError};
use crate::packet::{
    decrypt_and_unpack, derive_session_key, generate_client_nonce, pack_and_authenticate_hmac,
    pack_and_encrypt, verify_and_unpack_hmac, AckPayload, AuthInitPayload, FrameHeader,
    HandshakeInitPayload, HandshakeRespPayload, HeartbeatPayload, MsgType, HEADER_LEN,
    HMAC_TAG_LEN, MAX_FRAME_LEN, TAG_LEN,
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
    rx_buf: [u8; MAX_FRAME_LEN * 2],
    rx_len: usize,
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
            rx_buf: [0u8; MAX_FRAME_LEN * 2],
            rx_len: 0,
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

    /// Enqueue an application data payload (MsgType::Data) for transmission.
    pub fn send_data(&mut self, data: &[u8]) -> Result<(), OutboxError> {
        self.enqueue_event(MsgType::Data, data)
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
                    if self.state == ClientState::Online && self.rx_len >= HEADER_LEN {
                        self.receive_frames(now_ms, false, &mut on_data);
                    }
                }
            }
            ClientState::Online => {
                if (revents & (libc::POLLERR | libc::POLLHUP)) != 0 {
                    self.transition_to_disconnected(now_ms, 2000);
                } else {
                    let has_in = (revents & libc::POLLIN) != 0;
                    if has_in || self.rx_len >= HEADER_LEN {
                        self.receive_frames(now_ms, has_in, &mut on_data);
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
        self.rx_len = 0;
        let next_backoff = (prev_backoff * 2).min(30_000); // Max 30 seconds backoff
        self.state = ClientState::Disconnected {
            next_attempt_ms: now_ms + (prev_backoff as u64),
            backoff_ms: next_backoff,
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
                    self.transition_to_disconnected(now_ms, 2000);
                    return;
                }
                match self.socket.recv(&mut self.rx_buf[self.rx_len..]) {
                    Ok(0) => {
                        self.transition_to_disconnected(now_ms, 2000);
                        return;
                    }
                    Ok(n) => {
                        self.rx_len += n;
                    }
                    Err(err) if err == libc::EAGAIN || err == libc::EWOULDBLOCK => {
                        break;
                    }
                    Err(_) => {
                        self.transition_to_disconnected(now_ms, 2000);
                        return;
                    }
                }
            }
        }

        if self.rx_len >= HEADER_LEN {
            let hdr = match FrameHeader::decode(&self.rx_buf[..HEADER_LEN]) {
                Ok(h) => h,
                Err(_) => {
                    self.transition_to_disconnected(now_ms, 2000);
                    return;
                }
            };

            let frame_total_len = HEADER_LEN + (hdr.payload_len as usize);
            if frame_total_len > MAX_FRAME_LEN || (hdr.payload_len as usize) < HMAC_TAG_LEN {
                self.transition_to_disconnected(now_ms, 2000);
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
                        self.rx_buf.copy_within(frame_total_len..self.rx_len, 0);
                        self.rx_len -= frame_total_len;
                        self.state = ClientState::Online;
                        self.flush_outbox();
                        return;
                    }
                }
            }

            // Authentication or format failure
            self.transition_to_disconnected(now_ms, 2000);
        }
    }

    fn receive_frames(
        &mut self,
        now_ms: u64,
        can_read_socket: bool,
        on_data: &mut impl FnMut(MsgType, &[u8]),
    ) {
        if can_read_socket && self.socket.is_open() {
            loop {
                if self.rx_len >= self.rx_buf.len() {
                    self.transition_to_disconnected(now_ms, 2000);
                    return;
                }
                match self.socket.recv(&mut self.rx_buf[self.rx_len..]) {
                    Ok(0) => {
                        self.transition_to_disconnected(now_ms, 2000);
                        return;
                    }
                    Ok(n) => {
                        self.rx_len += n;
                    }
                    Err(err) if err == libc::EAGAIN || err == libc::EWOULDBLOCK => {
                        break;
                    }
                    Err(_) => {
                        self.transition_to_disconnected(now_ms, 2000);
                        return;
                    }
                }
            }
        }

        while self.rx_len >= HEADER_LEN {
            let hdr = match FrameHeader::decode(&self.rx_buf[..HEADER_LEN]) {
                Ok(h) => h,
                Err(_) => {
                    self.transition_to_disconnected(now_ms, 2000);
                    return;
                }
            };

            let frame_total_len = HEADER_LEN + (hdr.payload_len as usize);
            if frame_total_len > MAX_FRAME_LEN || (hdr.payload_len as usize) < TAG_LEN {
                self.transition_to_disconnected(now_ms, 2000);
                return;
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
                                if let Ok(ack) = AckPayload::decode(pt) {
                                    self.outbox.ack(ack.acked_seq);
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
                    self.transition_to_disconnected(now_ms, 2000);
                    return;
                }
            }

            self.rx_buf.copy_within(frame_total_len..self.rx_len, 0);
            self.rx_len -= frame_total_len;
        }
    }

    fn flush_outbox(&mut self) {
        if let Some((_seq, frame)) = self.outbox.peek() {
            let _ = self.socket.send(frame);
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
        verify_and_unpack_hmac, AckPayload, FrameHeader, HandshakeInitPayload, HandshakeRespPayload,
        MsgType, HEADER_LEN, MAX_FRAME_LEN, MAX_PAYLOAD_LEN,
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
                assert_eq!(backoff_ms, 4000);
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
}
