//! Non-blocking zero-allocation POSIX NetServer (#![no_std])
//!
//! Handles listening, accepting incoming client connections, verifying
//! HMAC-SHA256 pre-session handshakes, deriving session keys, reassembling
//! streaming frames, enforcing anti-replay protection, and auto-ACKing.

use crate::packet::{
    decrypt_and_unpack, derive_session_key, pack_and_authenticate_hmac, pack_and_encrypt,
    verify_and_unpack_hmac, AckPayload, AuthRespPayload, FrameHeader, HandshakeInitPayload,
    HandshakeRespPayload, MsgType, PacketError, HEADER_LEN, HMAC_TAG_LEN, MAX_FRAME_LEN, TAG_LEN,
};
use crate::posix::PosixSocket;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerSessionState {
    Handshaking,
    Online,
}

pub struct ServerSession {
    socket: PosixSocket,
    state: ServerSessionState,
    device_uuid: [u8; 16],
    session_id: u32,
    session_salt: [u8; 4],
    session_key: [u8; 32],
    rx_buf: [u8; MAX_FRAME_LEN * 2],
    rx_len: usize,
    tx_seq: u32,
    rx_seq: u32,
}

impl ServerSession {
    fn new(socket: PosixSocket) -> Self {
        Self {
            socket,
            state: ServerSessionState::Handshaking,
            device_uuid: [0; 16],
            session_id: 0,
            session_salt: [0; 4],
            session_key: [0; 32],
            rx_buf: [0; MAX_FRAME_LEN * 2],
            rx_len: 0,
            tx_seq: 1,
            rx_seq: 0,
        }
    }

    pub fn state(&self) -> ServerSessionState {
        self.state
    }

    pub fn device_uuid(&self) -> [u8; 16] {
        self.device_uuid
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    pub fn socket_fd(&self) -> libc::c_int {
        self.socket.fd()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent<'a> {
    Connected { client_idx: usize, device_uuid: [u8; 16], session_id: u32 },
    Disconnected { client_idx: usize },
    Data { client_idx: usize, msg_type: MsgType, payload: &'a [u8] },
}

pub struct NetServer<const MAX_CLIENTS: usize> {
    listener: PosixSocket,
    port: u16,
    sessions: [Option<ServerSession>; MAX_CLIENTS],
    next_session_id: u32,
    session_counter: u32,
}

impl<const MAX_CLIENTS: usize> NetServer<MAX_CLIENTS> {
    /// Bind non-blocking TCP listening socket to an IPv4 address and port.
    /// Use `port = 0` to let the OS allocate an ephemeral port.
    pub fn bind(ip: [u8; 4], port: u16) -> Result<Self, libc::c_int> {
        let (listener, bound_port) = PosixSocket::bind_and_listen_ipv4(ip, port, 128)?;
        const NONE_SESSION: Option<ServerSession> = None;
        Ok(Self {
            listener,
            port: bound_port,
            sessions: [NONE_SESSION; MAX_CLIENTS],
            next_session_id: 1000,
            session_counter: 1,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn listener_fd(&self) -> libc::c_int {
        self.listener.fd()
    }

    pub fn active_client_count(&self) -> usize {
        let mut count = 0;
        for s in &self.sessions {
            if s.is_some() {
                count += 1;
            }
        }
        count
    }

    pub fn is_client_online(&self, client_idx: usize) -> bool {
        self.sessions
            .get(client_idx)
            .and_then(|s| s.as_ref())
            .map(|s| s.state == ServerSessionState::Online)
            .unwrap_or(false)
    }

    pub fn client_uuid(&self, client_idx: usize) -> Option<[u8; 16]> {
        self.sessions.get(client_idx).and_then(|s| s.as_ref()).map(|s| s.device_uuid)
    }

    pub fn client_session_id(&self, client_idx: usize) -> Option<u32> {
        self.sessions.get(client_idx).and_then(|s| s.as_ref()).map(|s| s.session_id)
    }

    pub fn client_socket_fd(&self, client_idx: usize) -> Option<libc::c_int> {
        self.sessions.get(client_idx).and_then(|s| s.as_ref()).map(|s| s.socket.fd())
    }

    /// Explicitly disconnect a client session and release its socket.
    pub fn disconnect_client(&mut self, client_idx: usize) {
        if let Some(slot) = self.sessions.get_mut(client_idx) {
            *slot = None;
        }
    }

    /// Send an encrypted `MsgType::Data` frame to a connected client.
    pub fn send_data(&mut self, client_idx: usize, data: &[u8]) -> Result<(), PacketError> {
        if let Some(Some(ref mut session)) = self.sessions.get_mut(client_idx) {
            if session.state != ServerSessionState::Online {
                return Err(PacketError::AuthenticationFailed);
            }
            let seq = session.tx_seq;
            session.tx_seq = session.tx_seq.wrapping_add(1);

            let mut frame = [0u8; MAX_FRAME_LEN];
            let len = pack_and_encrypt(
                &session.session_key,
                &session.session_salt,
                MsgType::Data,
                session.session_id,
                seq,
                data,
                &mut frame,
            )?;
            let _ = session.socket.send(&frame[..len]);
            Ok(())
        } else {
            Err(PacketError::AuthenticationFailed)
        }
    }

    /// Send an encrypted `MsgType::AuthResp` frame to a connected client.
    pub fn send_auth_resp(
        &mut self,
        client_idx: usize,
        auth_resp: &AuthRespPayload,
    ) -> Result<(), PacketError> {
        let mut pt = [0u8; AuthRespPayload::LEN];
        auth_resp.encode(&mut pt).map_err(|_| PacketError::PayloadTooLarge)?;

        if let Some(Some(ref mut session)) = self.sessions.get_mut(client_idx) {
            if session.state != ServerSessionState::Online {
                return Err(PacketError::AuthenticationFailed);
            }
            let seq = session.tx_seq;
            session.tx_seq = session.tx_seq.wrapping_add(1);

            let mut frame = [0u8; MAX_FRAME_LEN];
            let len = pack_and_encrypt(
                &session.session_key,
                &session.session_salt,
                MsgType::AuthResp,
                session.session_id,
                seq,
                &pt,
                &mut frame,
            )?;
            let _ = session.socket.send(&frame[..len]);
            Ok(())
        } else {
            Err(PacketError::AuthenticationFailed)
        }
    }

    /// Send an encrypted `MsgType::Ack` frame to a connected client.
    pub fn send_ack(
        &mut self,
        client_idx: usize,
        acked_seq: u32,
        status: u8,
    ) -> Result<(), PacketError> {
        let ack_payload = AckPayload { acked_seq, status };
        let mut pt = [0u8; AckPayload::LEN];
        ack_payload.encode(&mut pt).map_err(|_| PacketError::PayloadTooLarge)?;

        if let Some(Some(ref mut session)) = self.sessions.get_mut(client_idx) {
            if session.state != ServerSessionState::Online {
                return Err(PacketError::AuthenticationFailed);
            }
            let seq = session.tx_seq;
            session.tx_seq = session.tx_seq.wrapping_add(1);

            let mut frame = [0u8; MAX_FRAME_LEN];
            let len = pack_and_encrypt(
                &session.session_key,
                &session.session_salt,
                MsgType::Ack,
                session.session_id,
                seq,
                &pt,
                &mut frame,
            )?;
            let _ = session.socket.send(&frame[..len]);
            Ok(())
        } else {
            Err(PacketError::AuthenticationFailed)
        }
    }

    /// Convenience step helper for tests or dedicated server threads.
    /// Performs non-blocking `libc::poll` over the listener and active client sockets,
    /// then drives `poll_step_with`.
    pub fn step<PskFn, F>(
        &mut self,
        now_ms: u64,
        psk_resolver: PskFn,
        on_event: F,
    ) where
        PskFn: Fn(&[u8; 16]) -> Option<[u8; 32]>,
        F: FnMut(ServerEvent),
    {
        const MAX_POLL_FDS: usize = 64;
        let mut pollfds = [libc::pollfd { fd: -1, events: 0, revents: 0 }; MAX_POLL_FDS];
        let mut poll_count = 0;

        let listener_idx = if self.listener.is_open() {
            pollfds[poll_count] = libc::pollfd {
                fd: self.listener.fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let idx = poll_count;
            poll_count += 1;
            Some(idx)
        } else {
            None
        };

        let mut client_poll_map = [None; MAX_CLIENTS];
        for (i, opt_s) in self.sessions.iter().enumerate() {
            if let Some(s) = opt_s {
                if s.socket.is_open() {
                    pollfds[poll_count] = libc::pollfd {
                        fd: s.socket.fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    client_poll_map[i] = Some(poll_count);
                    poll_count += 1;
                }
            }
        }

        if poll_count > 0 {
            let _ = unsafe { libc::poll(pollfds.as_mut_ptr(), poll_count as libc::nfds_t, 0) };
        }

        let listener_revents = listener_idx.map(|idx| pollfds[idx].revents).unwrap_or(0);
        let mut client_revents = [0i16; MAX_CLIENTS];
        for (i, opt_idx) in client_poll_map.iter().enumerate() {
            if let Some(idx) = opt_idx {
                client_revents[i] = pollfds[*idx].revents;
            }
        }

        self.poll_step_with(now_ms, listener_revents, &client_revents, psk_resolver, on_event);
    }

    /// Step method for integration into an external POSIX poll event loop.
    pub fn poll_step_with<PskFn, F>(
        &mut self,
        now_ms: u64,
        listener_revents: i16,
        client_revents: &[i16],
        psk_resolver: PskFn,
        mut on_event: F,
    ) where
        PskFn: Fn(&[u8; 16]) -> Option<[u8; 32]>,
        F: FnMut(ServerEvent),
    {
        // 1. Accept new incoming connections
        if (listener_revents & libc::POLLIN) != 0 && self.listener.is_open() {
            while let Ok(Some(client_sock)) = self.listener.accept_nonblocking() {
                let mut slot_opt = None;
                for slot in &mut self.sessions {
                    if slot.is_none() {
                        slot_opt = Some(slot);
                        break;
                    }
                }
                if let Some(slot) = slot_opt {
                    *slot = Some(ServerSession::new(client_sock));
                } else {
                    // Maximum capacity reached: drop connection to prevent unbounded growth
                    let mut sock_to_close = client_sock;
                    sock_to_close.close();
                }
            }
        }

        // 2. Process each client connection
        for client_idx in 0..MAX_CLIENTS {
            let revents = client_revents.get(client_idx).copied().unwrap_or(0);
            let mut should_disconnect = false;

            if let Some(ref mut session) = self.sessions[client_idx] {
                if (revents & (libc::POLLERR | libc::POLLHUP)) != 0 {
                    should_disconnect = true;
                } else {
                    let has_in = (revents & libc::POLLIN) != 0;
                    match session.state {
                        ServerSessionState::Handshaking => {
                            match Self::handle_session_handshake(
                                session,
                                has_in,
                                now_ms,
                                self.next_session_id,
                                self.session_counter,
                                &psk_resolver,
                            ) {
                                Ok(Some(event)) => {
                                    self.next_session_id = self.next_session_id.wrapping_add(1);
                                    self.session_counter = self.session_counter.wrapping_add(1);
                                    on_event(ServerEvent::Connected {
                                        client_idx,
                                        device_uuid: event.0,
                                        session_id: event.1,
                                    });
                                }
                                Ok(None) => {
                                    // Incomplete frame, wait for more data
                                }
                                Err(_) => {
                                    should_disconnect = true;
                                }
                            }
                        }
                        ServerSessionState::Online => {
                            if Self::handle_session_online(
                                session,
                                has_in,
                                client_idx,
                                &mut on_event,
                            ).is_err() {
                                should_disconnect = true;
                            }
                        }
                    }
                }
            }

            if should_disconnect {
                self.sessions[client_idx] = None;
                on_event(ServerEvent::Disconnected { client_idx });
            }
        }
    }

    fn handle_session_handshake<PskFn>(
        session: &mut ServerSession,
        has_in: bool,
        now_ms: u64,
        assigned_session_id: u32,
        counter: u32,
        psk_resolver: &PskFn,
    ) -> Result<Option<([u8; 16], u32)>, ()>
    where
        PskFn: Fn(&[u8; 16]) -> Option<[u8; 32]>,
    {
        if has_in && session.socket.is_open() {
            loop {
                if session.rx_len >= session.rx_buf.len() {
                    return Err(());
                }
                match session.socket.recv(&mut session.rx_buf[session.rx_len..]) {
                    Ok(0) => return Err(()), // Closed by peer
                    Ok(n) => session.rx_len += n,
                    Err(err) if err == libc::EAGAIN || err == libc::EWOULDBLOCK => break,
                    Err(_) => return Err(()),
                }
            }
        }

        if session.rx_len < HEADER_LEN {
            return Ok(None);
        }

        let hdr = FrameHeader::decode(&session.rx_buf[..HEADER_LEN]).map_err(|_| ())?;
        if hdr.msg_type != MsgType::HandshakeInit {
            return Err(());
        }

        let frame_total_len = HEADER_LEN + (hdr.payload_len as usize);
        if frame_total_len > MAX_FRAME_LEN || (hdr.payload_len as usize) < HMAC_TAG_LEN {
            return Err(());
        }

        if session.rx_len < frame_total_len {
            return Ok(None);
        }

        // Decode HandshakeInit payload plaintext to retrieve device_uuid
        let pt_len = (hdr.payload_len as usize) - HMAC_TAG_LEN;
        if pt_len != HandshakeInitPayload::LEN {
            return Err(());
        }
        let init_pt = &session.rx_buf[HEADER_LEN..HEADER_LEN + pt_len];
        let init_payload = HandshakeInitPayload::decode(init_pt).map_err(|_| ())?;

        // Resolve root PSK for this device UUID
        let psk = psk_resolver(&init_payload.device_uuid).ok_or(())?;

        // Authenticate the entire frame against the resolved PSK
        let (_verified_hdr, _verified_pt) =
            verify_and_unpack_hmac(&psk, &session.rx_buf[..frame_total_len]).map_err(|_| ())?;

        // Derive server nonce using CSPRNG with fallback seed
        let mut server_nonce = [0u8; 32];
        if crate::posix::fill_random(&mut server_nonce).is_err() {
            let mut nonce_seed = [0u8; 48];
            nonce_seed[..8].copy_from_slice(&now_ms.to_be_bytes());
            nonce_seed[8..12].copy_from_slice(&counter.to_be_bytes());
            nonce_seed[12..44].copy_from_slice(&init_payload.client_nonce);
            nonce_seed[44..48].copy_from_slice(&assigned_session_id.to_be_bytes());
            server_nonce = crate::crypto::sha256(&nonce_seed);
        }

        // Derive 4-byte session salt using CSPRNG with fallback
        let mut session_salt = [0u8; 4];
        if crate::posix::fill_random(&mut session_salt).is_err() {
            session_salt = [
                (assigned_session_id >> 24) as u8 ^ 0xA5,
                (assigned_session_id >> 16) as u8 ^ 0x5A,
                (assigned_session_id >> 8) as u8 ^ 0x3C,
                (assigned_session_id & 0xFF) as u8 ^ 0xC3,
            ];
        }

        let session_key = derive_session_key(
            &psk,
            &session_salt,
            &init_payload.client_nonce,
            &server_nonce,
        );

        // Prepare HandshakeResp
        let resp_payload = HandshakeRespPayload {
            server_nonce,
            assigned_session_id,
            session_salt,
        };
        let mut resp_pt = [0u8; HandshakeRespPayload::LEN];
        resp_payload.encode(&mut resp_pt).map_err(|_| ())?;

        let mut resp_frame = [0u8; MAX_FRAME_LEN];
        let resp_len = pack_and_authenticate_hmac(
            &psk,
            MsgType::HandshakeResp,
            assigned_session_id,
            0,
            &resp_pt,
            &mut resp_frame,
        ).map_err(|_| ())?;

        session.socket.send(&resp_frame[..resp_len]).map_err(|_| ())?;

        // Transition session to Online
        session.device_uuid = init_payload.device_uuid;
        session.session_id = assigned_session_id;
        session.session_salt = session_salt;
        session.session_key = session_key;
        session.state = ServerSessionState::Online;
        session.tx_seq = 1;
        session.rx_seq = 0;

        session.rx_buf.copy_within(frame_total_len..session.rx_len, 0);
        session.rx_len -= frame_total_len;

        Ok(Some((init_payload.device_uuid, assigned_session_id)))
    }

    fn handle_session_online(
        session: &mut ServerSession,
        has_in: bool,
        client_idx: usize,
        on_event: &mut impl FnMut(ServerEvent),
    ) -> Result<(), ()> {
        if has_in && session.socket.is_open() {
            loop {
                if session.rx_len >= session.rx_buf.len() {
                    return Err(());
                }
                match session.socket.recv(&mut session.rx_buf[session.rx_len..]) {
                    Ok(0) => return Err(()), // Closed by peer
                    Ok(n) => session.rx_len += n,
                    Err(err) if err == libc::EAGAIN || err == libc::EWOULDBLOCK => break,
                    Err(_) => return Err(()),
                }
            }
        }

        while session.rx_len >= HEADER_LEN {
            let hdr = match FrameHeader::decode(&session.rx_buf[..HEADER_LEN]) {
                Ok(h) => h,
                Err(_) => return Err(()),
            };

            let frame_total_len = HEADER_LEN + (hdr.payload_len as usize);
            if frame_total_len > MAX_FRAME_LEN || (hdr.payload_len as usize) < TAG_LEN {
                return Err(());
            }

            if session.rx_len < frame_total_len {
                break; // Incomplete frame
            }

            let decrypt_res = decrypt_and_unpack(
                &session.session_key,
                &session.session_salt,
                &mut session.rx_buf[..frame_total_len],
            );

            match decrypt_res {
                Ok((hdr, pt)) => {
                    // Anti-replay check
                    if hdr.seq_num > session.rx_seq {
                        session.rx_seq = hdr.seq_num;

                        match hdr.msg_type {
                            MsgType::Data | MsgType::AuthInit | MsgType::Heartbeat => {
                                // Auto-ACK received application data
                                let ack_payload = AckPayload {
                                    acked_seq: hdr.seq_num,
                                    status: 0,
                                };
                                let mut ack_pt = [0u8; AckPayload::LEN];
                                if ack_payload.encode(&mut ack_pt).is_ok() {
                                    let seq = session.tx_seq;
                                    session.tx_seq = session.tx_seq.wrapping_add(1);
                                    let mut ack_frame = [0u8; MAX_FRAME_LEN];
                                    if let Ok(ack_len) = pack_and_encrypt(
                                        &session.session_key,
                                        &session.session_salt,
                                        MsgType::Ack,
                                        session.session_id,
                                        seq,
                                        &ack_pt,
                                        &mut ack_frame,
                                    ) {
                                        let _ = session.socket.send(&ack_frame[..ack_len]);
                                    }
                                }

                                on_event(ServerEvent::Data {
                                    client_idx,
                                    msg_type: hdr.msg_type,
                                    payload: pt,
                                });
                            }
                            MsgType::Ack => {
                                // Server does not currently queue outbox frames to clients,
                                // but if it does, handle AckPayload here.
                            }
                            _ => {}
                        }
                    }
                }
                Err(_) => return Err(()),
            }

            session.rx_buf.copy_within(frame_total_len..session.rx_len, 0);
            session.rx_len -= frame_total_len;
        }

        Ok(())
    }

    pub fn close(&mut self) {
        self.listener.close();
        for slot in &mut self.sessions {
            *slot = None;
        }
    }
}

impl<const MAX_CLIENTS: usize> Drop for NetServer<MAX_CLIENTS> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientState, NetClient};
    use trillby_core::net_types::NetworkStatus;

    fn step_client_poll<const CAP: usize, F>(
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
    fn test_server_bind_and_ephemeral_port() {
        let server = NetServer::<4>::bind([127, 0, 0, 1], 0).expect("bind server");
        assert!(server.port() > 0);
        assert!(server.listener_fd() >= 0);
        assert_eq!(server.active_client_count(), 0);
    }

    #[test]
    fn test_client_server_handshake_and_bidirectional_data_flow() {
        let psk = [0x55u8; 32];
        let uuid = [0xAAu8; 16];

        let mut server = NetServer::<4>::bind([127, 0, 0, 1], 0).expect("bind server");
        let port = server.port();
        let mut client = NetClient::<8>::new(psk, uuid, [127, 0, 0, 1], port);

        let mut now_ms = 1000u64;

        // Drive handshake:
        // 1. Client connects
        step_client_poll(&mut client, now_ms, |_, _| {});
        assert_eq!(client.state(), ClientState::Connecting);

        // 2. Server accepts connection
        now_ms += 10;
        server.step(now_ms, |id| if *id == uuid { Some(psk) } else { None }, |_| {});
        assert_eq!(server.active_client_count(), 1);

        // 3. Client transmits HandshakeInit
        now_ms += 10;
        step_client_poll(&mut client, now_ms, |_, _| {});
        assert_eq!(client.status(), NetworkStatus::Handshaking);

        // 4. Server receives HandshakeInit, verifies, derives session key, transmits HandshakeResp
        now_ms += 10;
        let mut connected_event_fired = false;
        server.step(now_ms, |id| if *id == uuid { Some(psk) } else { None }, |event| {
            if let ServerEvent::Connected { client_idx, device_uuid, .. } = event {
                assert_eq!(client_idx, 0);
                assert_eq!(device_uuid, uuid);
                connected_event_fired = true;
            }
        });
        assert!(connected_event_fired);
        assert!(server.is_client_online(0));

        // 5. Client receives HandshakeResp -> transitions to Online!
        now_ms += 10;
        step_client_poll(&mut client, now_ms, |_, _| {});
        assert_eq!(client.status(), NetworkStatus::Online);

        // 6. Client sends application data
        let client_msg = b"WORK_EVENT:TAG_99812";
        client.send_data(client_msg).unwrap();
        assert_eq!(client.outbox_pending_count(), 1);

        // Step client -> flushes frame to server
        now_ms += 10;
        step_client_poll(&mut client, now_ms, |_, _| {});

        // Server steps -> receives data, decrypts, auto-ACKs!
        now_ms += 10;
        let mut received_by_server = [0u8; 64];
        let mut received_server_len = 0;
        server.step(now_ms, |id| if *id == uuid { Some(psk) } else { None }, |event| {
            if let ServerEvent::Data { client_idx, msg_type, payload } = event {
                assert_eq!(client_idx, 0);
                assert_eq!(msg_type, MsgType::Data);
                received_by_server[..payload.len()].copy_from_slice(payload);
                received_server_len = payload.len();
            }
        });
        assert_eq!(&received_by_server[..received_server_len], client_msg);

        // Step client -> receives auto-ACK from server and drains outbox to 0!
        now_ms += 10;
        step_client_poll(&mut client, now_ms, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 0);
        assert_eq!(client.status(), NetworkStatus::Online);

        // 7. Server sends command to client
        let server_cmd = b"CMD_PRINT_LABEL:LOT_42";
        server.send_data(0, server_cmd).unwrap();

        // Step client -> receives server command
        now_ms += 10;
        let mut received_by_client = [0u8; 64];
        let mut received_client_len = 0;
        step_client_poll(&mut client, now_ms, |msg_type, payload| {
            assert_eq!(msg_type, MsgType::Data);
            received_by_client[..payload.len()].copy_from_slice(payload);
            received_client_len = payload.len();
        });
        assert_eq!(&received_by_client[..received_client_len], server_cmd);
    }

    #[test]
    fn test_server_rejects_unauthorized_device_uuid() {
        let psk = [0x55u8; 32];
        let uuid = [0xEEu8; 16]; // Unknown UUID

        let mut server = NetServer::<4>::bind([127, 0, 0, 1], 0).expect("bind server");
        let port = server.port();
        let mut client = NetClient::<4>::new(psk, uuid, [127, 0, 0, 1], port);

        let mut now_ms = 1000u64;
        step_client_poll(&mut client, now_ms, |_, _| {});
        now_ms += 10;
        // psk_resolver returns None for unknown UUID
        server.step(now_ms, |_| None, |_| {});
        now_ms += 10;
        step_client_poll(&mut client, now_ms, |_, _| {});
        now_ms += 10;
        server.step(now_ms, |_| None, |_| {});

        // Server should drop the connection
        assert_eq!(server.active_client_count(), 0);

        // Client detects closed connection and transitions to Offline
        now_ms += 10;
        step_client_poll(&mut client, now_ms, |_, _| {});
        assert_eq!(client.status(), NetworkStatus::Offline);
    }

    #[test]
    fn test_server_multi_client_multiplexing_and_capacity_limit() {
        let psk1 = [0x11u8; 32];
        let uuid1 = [0x01u8; 16];
        let psk2 = [0x22u8; 32];
        let uuid2 = [0x02u8; 16];
        let psk3 = [0x33u8; 32];
        let uuid3 = [0x03u8; 16];

        // Capacity = 2 clients
        let mut server = NetServer::<2>::bind([127, 0, 0, 1], 0).expect("bind server");
        let port = server.port();

        let mut client1 = NetClient::<4>::new(psk1, uuid1, [127, 0, 0, 1], port);
        let mut client2 = NetClient::<4>::new(psk2, uuid2, [127, 0, 0, 1], port);

        let resolver = |id: &[u8; 16]| {
            if *id == uuid1 { Some(psk1) }
            else if *id == uuid2 { Some(psk2) }
            else { None }
        };

        let mut now_ms = 1000u64;

        // Connect client 1 & 2
        for _ in 0..5 {
            now_ms += 10;
            step_client_poll(&mut client1, now_ms, |_, _| {});
            step_client_poll(&mut client2, now_ms, |_, _| {});
            server.step(now_ms, resolver, |_| {});
        }

        assert_eq!(client1.status(), NetworkStatus::Online);
        assert_eq!(client2.status(), NetworkStatus::Online);
        assert_eq!(server.active_client_count(), 2);
        assert!(server.is_client_online(0));
        assert!(server.is_client_online(1));

        // Connect 3rd client (should be rejected since MAX_CLIENTS = 2)
        let mut client3 = NetClient::<4>::new(psk3, uuid3, [127, 0, 0, 1], port);
        for _ in 0..3 {
            now_ms += 10;
            step_client_poll(&mut client3, now_ms, |_, _| {});
            server.step(now_ms, resolver, |_| {});
        }
        assert_eq!(server.active_client_count(), 2);
        assert_ne!(client3.status(), NetworkStatus::Online);

        // Disconnect client 1 -> frees slot
        drop(client1);
        now_ms += 10;
        let mut disconnected_idx = None;
        server.step(now_ms, resolver, |ev| {
            if let ServerEvent::Disconnected { client_idx } = ev {
                disconnected_idx = Some(client_idx);
            }
        });
        assert_eq!(disconnected_idx, Some(0));
        assert_eq!(server.active_client_count(), 1);

        // Now client 3 can connect into the freed slot!
        let resolver3 = |id: &[u8; 16]| {
            if *id == uuid3 { Some(psk3) }
            else if *id == uuid2 { Some(psk2) }
            else { None }
        };
        // Advance clock past client3's disconnect backoff timer
        now_ms += 5000;
        for _ in 0..5 {
            now_ms += 10;
            step_client_poll(&mut client3, now_ms, |_, _| {});
            server.step(now_ms, resolver3, |_| {});
        }
        assert_eq!(client3.status(), NetworkStatus::Online);
        assert_eq!(server.active_client_count(), 2);
    }
}

