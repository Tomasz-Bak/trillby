//! Non-blocking zero-allocation POSIX NetServer (#![no_std])
//!
//! Handles listening, accepting incoming client connections, verifying
//! HMAC-SHA256 pre-session handshakes, deriving session keys, reassembling
//! streaming frames, enforcing anti-replay protection, and auto-ACKing.

use crate::framing::{FrameAssembler, RecvOutcome, SessionCrypto, MAX_RECV_PER_STEP};
use crate::packet::{
    derive_session_key, pack_and_authenticate_hmac_inplace,
    verify_and_unpack_hmac,
    AckPayload, AuthRespPayload, Direction, HandshakeInitPayload,
    HandshakeRespPayload, MsgType, PacketError, HEADER_LEN, HMAC_TAG_LEN,
    MAX_FRAME_LEN, TAG_LEN,
};
use crate::posix::PosixSocket;
const LISTEN_BACKLOG: i32 = 128;
pub(crate) const FIRST_SESSION_ID: u32 = 1000;
const FALLBACK_SALT_MASK: [u8; 4] = [0xA5, 0x5A, 0x3C, 0xC3];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerSessionState {
    Handshaking,
    Online,
}

struct ServerSession {
    socket: PosixSocket,
    state: ServerSessionState,
    device_uuid: [u8; 16],
    crypto: SessionCrypto,
    assembler: FrameAssembler,
}

impl ServerSession {
    fn new(socket: PosixSocket) -> Self {
        Self {
            socket,
            state: ServerSessionState::Handshaking,
            device_uuid: [0; 16],
            crypto: SessionCrypto::new(),
            assembler: FrameAssembler::new(),
        }
    }

    fn seal_and_send(&mut self, msg_type: MsgType, pt: &[u8]) -> Result<(), PacketError> {
        let mut frame = [0u8; MAX_FRAME_LEN];
        let len = self.crypto.seal(Direction::ServerToClient, msg_type, pt, &mut frame)?;
        match self.socket.send(&frame[..len]) {
            Ok(n) if n == len => Ok(()),
            _ => Err(PacketError::SendFailed),
        }
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
}

impl<const MAX_CLIENTS: usize> NetServer<MAX_CLIENTS> {
    /// Bind non-blocking TCP listening socket to an IPv4 address and port.
    /// Use `port = 0` to let the OS allocate an ephemeral port.
    pub fn bind(ip: [u8; 4], port: u16) -> Result<Self, libc::c_int> {
        let (listener, bound_port) = PosixSocket::bind_and_listen_ipv4(ip, port, LISTEN_BACKLOG)?;
        const NONE_SESSION: Option<ServerSession> = None;
        Ok(Self {
            listener,
            port: bound_port,
            sessions: [NONE_SESSION; MAX_CLIENTS],
            next_session_id: FIRST_SESSION_ID,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn listener_fd(&self) -> libc::c_int {
        self.listener.fd()
    }

    pub fn active_client_count(&self) -> usize {
        self.sessions.iter().flatten().count()
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
        self.sessions.get(client_idx).and_then(|s| s.as_ref()).map(|s| s.crypto.session_id)
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

    fn online_session_mut(&mut self, client_idx: usize) -> Result<&mut ServerSession, PacketError> {
        if let Some(Some(session)) = self.sessions.get_mut(client_idx) {
            if session.state != ServerSessionState::Online {
                return Err(PacketError::NotOnline);
            }
            Ok(session)
        } else {
            Err(PacketError::NotOnline)
        }
    }

    /// Send an encrypted `MsgType::Data` frame to a connected client.
    pub fn send_data(&mut self, client_idx: usize, data: &[u8]) -> Result<(), PacketError> {
        self.online_session_mut(client_idx)?.seal_and_send(MsgType::Data, data)
    }

    /// Send an encrypted `MsgType::AuthResp` frame to a connected client.
    pub fn send_auth_resp(
        &mut self,
        client_idx: usize,
        auth_resp: &AuthRespPayload,
    ) -> Result<(), PacketError> {
        let mut pt = [0u8; AuthRespPayload::LEN];
        auth_resp.encode(&mut pt).map_err(|_| PacketError::PayloadTooLarge)?;
        self.online_session_mut(client_idx)?.seal_and_send(MsgType::AuthResp, &pt)
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
        let _ = self.step_timeout(now_ms, 0, psk_resolver, on_event);
    }

    pub fn step_timeout<PskFn, F>(
        &mut self,
        now_ms: u64,
        timeout_ms: libc::c_int,
        psk_resolver: PskFn,
        on_event: F,
    ) -> Result<(), libc::c_int>
    where
        PskFn: Fn(&[u8; 16]) -> Option<[u8; 32]>,
        F: FnMut(ServerEvent),
    {
        const MAX_POLL_FDS: usize = 64;
        const { assert!(MAX_CLIENTS < MAX_POLL_FDS, "NetServer::step supports at most 63 clients") };
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
            loop {
                let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), poll_count as libc::nfds_t, timeout_ms) };
                if rc < 0 {
                    let errno = unsafe { *libc::__errno_location() };
                    if errno == libc::EINTR {
                        continue;
                    }
                    return Err(errno);
                }
                break;
            }
        }

        let listener_revents = listener_idx.map(|idx| pollfds[idx].revents).unwrap_or(0);
        let mut client_revents = [0i16; MAX_CLIENTS];
        for (i, opt_idx) in client_poll_map.iter().enumerate() {
            if let Some(idx) = opt_idx {
                client_revents[i] = pollfds[*idx].revents;
            }
        }

        self.poll_step_with(now_ms, listener_revents, &client_revents, psk_resolver, on_event);
        Ok(())
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
                if let Some(slot) = self.sessions.iter_mut().find(|s| s.is_none()) {
                    *slot = Some(ServerSession::new(client_sock));
                }
                // Maximum capacity reached: client_sock is dropped and closed automatically
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
                                &psk_resolver,
                            ) {
                                Ok(Some(event)) => {
                                    self.next_session_id = self.next_session_id.wrapping_add(1);
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
        psk_resolver: &PskFn,
    ) -> Result<Option<([u8; 16], u32)>, ()>
    where
        PskFn: Fn(&[u8; 16]) -> Option<[u8; 32]>,
    {
        const SERVER_NONCE_SEED_LEN: usize = 8 + 4 + 32 + 4;

        if has_in && session.socket.is_open() {
            loop {
                match session.assembler.recv_from(&session.socket) {
                    RecvOutcome::Data => {}
                    RecvOutcome::WouldBlock => break,
                    RecvOutcome::Closed | RecvOutcome::Error => return Err(()),
                }
            }
        }
        if let Some(hdr) = session.assembler.peek_header().map_err(|_| ())? {
            if hdr.msg_type != MsgType::HandshakeInit {
                return Err(());
            }
        }


        let (hdr, frame_total_len) = match session.assembler.next_frame(HMAC_TAG_LEN).map_err(|_| ())? {
            Some(res) => res,
            None => return Ok(None),
        };

        if hdr.msg_type != MsgType::HandshakeInit {
            return Err(());
        }

        // Decode HandshakeInit payload plaintext to retrieve device_uuid
        let pt_len = (hdr.payload_len as usize) - HMAC_TAG_LEN;
        if pt_len != HandshakeInitPayload::LEN {
            return Err(());
        }
        let init_pt = &session.assembler.frame_slice(frame_total_len)[HEADER_LEN..HEADER_LEN + pt_len];
        let init_payload = HandshakeInitPayload::decode(init_pt).map_err(|_| ())?;

        // Resolve root PSK for this device UUID
        let psk = psk_resolver(&init_payload.device_uuid).ok_or(())?;

        // Authenticate the entire frame against the resolved PSK
        let (_verified_hdr, _verified_pt) =
            verify_and_unpack_hmac(&psk, session.assembler.frame_slice(frame_total_len)).map_err(|_| ())?;

        // Derive server nonce using CSPRNG with fallback seed
        let mut server_nonce = [0u8; 32];
        if crate::posix::fill_random(&mut server_nonce).is_err() {
            let counter = assigned_session_id.wrapping_sub(FIRST_SESSION_ID - 1);
            let mut nonce_seed = [0u8; SERVER_NONCE_SEED_LEN];
            let mut w = crate::packet::ByteWriter::new(&mut nonce_seed);
            let _ = w.write_bytes(&now_ms.to_be_bytes());
            let _ = w.write_bytes(&counter.to_be_bytes());
            let _ = w.write_bytes(&init_payload.client_nonce);
            let _ = w.write_bytes(&assigned_session_id.to_be_bytes());
            server_nonce = crate::crypto::sha256(&nonce_seed);
        }
        // Derive 4-byte session salt using CSPRNG with fallback
        let mut session_salt = [0u8; 4];
        if crate::posix::fill_random(&mut session_salt).is_err() {
            let be = assigned_session_id.to_be_bytes();
            session_salt = core::array::from_fn(|i| be[i] ^ FALLBACK_SALT_MASK[i]);
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
        let mut resp_frame = [0u8; MAX_FRAME_LEN];
        resp_payload
            .encode(&mut resp_frame[HEADER_LEN..HEADER_LEN + HandshakeRespPayload::LEN])
            .map_err(|_| ())?;

        let resp_len = pack_and_authenticate_hmac_inplace(
            &psk,
            MsgType::HandshakeResp,
            assigned_session_id,
            0,
            HandshakeRespPayload::LEN,
            &mut resp_frame,
        ).map_err(|_| ())?;

        session.socket.send(&resp_frame[..resp_len]).map_err(|_| ())?;

        // Transition session to Online
        session.device_uuid = init_payload.device_uuid;
        session.crypto.reset(assigned_session_id, session_salt, session_key);
        session.state = ServerSessionState::Online;

        session.assembler.consume(frame_total_len);
        Ok(Some((init_payload.device_uuid, assigned_session_id)))
    }

    /// Alternate between dispatching every complete buffered frame and reading
    /// more bytes. Complete frames are consumed before each recv(), so the
    /// buffer never holds more than one partial frame and cannot overflow no
    /// matter how many frames a client sends back-to-back.
    fn handle_session_online(
        session: &mut ServerSession,
        has_in: bool,
        client_idx: usize,
        on_event: &mut impl FnMut(ServerEvent),
    ) -> Result<(), ()> {
        let mut reads = 0;
        loop {
            Self::dispatch_session_frames(session, client_idx, on_event)?;
            if !has_in || !session.socket.is_open() || reads >= MAX_RECV_PER_STEP {
                return Ok(());
            }
            reads += 1;
            match session.assembler.recv_from(&session.socket) {
                RecvOutcome::Data => {}
                RecvOutcome::WouldBlock => return Ok(()),
                RecvOutcome::Closed | RecvOutcome::Error => return Err(()),
            }
        }
    }

    fn dispatch_session_frames(
        session: &mut ServerSession,
        client_idx: usize,
        on_event: &mut impl FnMut(ServerEvent),
    ) -> Result<(), ()> {
        loop {
            let (hdr, frame_total_len) = match session.assembler.next_frame(TAG_LEN).map_err(|_| ())? {
                Some(res) => res,
                None => break,
            };
            if !hdr.is_direction(Direction::ClientToServer) {
                return Err(());
            }

            let frame = session.assembler.frame_slice_mut(frame_total_len);
            match session.crypto.open(frame).map_err(|_| ())? {
                Some((hdr, pt)) => {
                    match hdr.msg_type {
                        MsgType::Data | MsgType::AuthInit | MsgType::Heartbeat => {
                            on_event(ServerEvent::Data {
                                client_idx,
                                msg_type: hdr.msg_type,
                                payload: pt,
                            });

                            // Auto-ACK received application data
                            let ack_payload = AckPayload {
                                acked_seq: hdr.seq_num,
                                status: AckPayload::STATUS_OK,
                            };
                            let mut ack_pt = [0u8; AckPayload::LEN];
                            if ack_payload.encode(&mut ack_pt).is_ok() {
                                let _ = session.seal_and_send(MsgType::Ack, &ack_pt);
                            }
                        }
                        _ => {
                            // Server does not currently queue outbox frames to clients,
                            // but if it does, handle AckPayload here.
                        }
                    }
                }
                None => {
                    // Replayed seq: ignored
                }
            }

            session.assembler.consume(frame_total_len);
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
    use crate::packet::{pack_and_authenticate_hmac, pack_and_encrypt_directed};
    use crate::packet::FrameHeader;
    use crate::test_support::read_exact_frame;

    fn handshake_init_frame(
        psk: &[u8; 32],
        uuid: [u8; 16],
        client_nonce: [u8; 32],
    ) -> ([u8; MAX_FRAME_LEN], usize) {
        let payload = HandshakeInitPayload {
            client_nonce,
            device_uuid: uuid,
        };
        let mut pt = [0u8; HandshakeInitPayload::LEN];
        payload.encode(&mut pt).unwrap();
        let mut frame = [0u8; MAX_FRAME_LEN];
        let len = pack_and_authenticate_hmac(psk, MsgType::HandshakeInit, 0, 0, &pt, &mut frame).unwrap();
        (frame, len)
    }

    fn read_session_key(
        stream: &mut std::net::TcpStream,
        psk: &[u8; 32],
        client_nonce: &[u8; 32],
    ) -> ([u8; 32], HandshakeRespPayload) {
        let mut resp_buf = [0u8; MAX_FRAME_LEN];
        let n = crate::test_support::read_exact_frame(stream, &mut resp_buf);
        let (_hdr, resp_pt) = verify_and_unpack_hmac(psk, &resp_buf[..n]).unwrap();
        let resp_payload = HandshakeRespPayload::decode(resp_pt).unwrap();
        let session_key = derive_session_key(
            psk,
            &resp_payload.session_salt,
            client_nonce,
            &resp_payload.server_nonce,
        );
        (session_key, resp_payload)
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
        client.wait_and_step_with(now_ms, 10, |_, _| {});
        assert_eq!(client.state(), ClientState::Connecting);

        // 2. Server accepts connection
        now_ms += 10;
        server.step(now_ms, |id| if *id == uuid { Some(psk) } else { None }, |_| {});
        assert_eq!(server.active_client_count(), 1);

        // 3. Client transmits HandshakeInit
        now_ms += 10;
        client.wait_and_step_with(now_ms, 10, |_, _| {});
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
        client.wait_and_step_with(now_ms, 10, |_, _| {});
        assert_eq!(client.status(), NetworkStatus::Online);

        // 6. Client sends application data
        let client_msg = b"WORK_EVENT:TAG_99812";
        client.send_data(client_msg).unwrap();
        assert_eq!(client.outbox_pending_count(), 1);

        // Step client -> flushes frame to server
        now_ms += 10;
        client.wait_and_step_with(now_ms, 10, |_, _| {});

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
        client.wait_and_step_with(now_ms, 10, |_, _| {});
        assert_eq!(client.outbox_pending_count(), 0);
        assert_eq!(client.status(), NetworkStatus::Online);

        // 7. Server sends command to client
        let server_cmd = b"CMD_PRINT_LABEL:LOT_42";
        server.send_data(0, server_cmd).unwrap();

        // Step client -> receives server command
        now_ms += 10;
        let mut received_by_client = [0u8; 64];
        let mut received_client_len = 0;
        client.wait_and_step_with(now_ms, 10, |msg_type, payload| {
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
        client.wait_and_step_with(now_ms, 10, |_, _| {});
        now_ms += 10;
        // psk_resolver returns None for unknown UUID
        server.step(now_ms, |_| None, |_| {});
        now_ms += 10;
        client.wait_and_step_with(now_ms, 10, |_, _| {});
        now_ms += 10;
        server.step(now_ms, |_| None, |_| {});

        // Server should drop the connection
        assert_eq!(server.active_client_count(), 0);

        // Client detects closed connection and transitions to Offline
        now_ms += 10;
        client.wait_and_step_with(now_ms, 10, |_, _| {});
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
            client1.wait_and_step_with(now_ms, 10, |_, _| {});
            client2.wait_and_step_with(now_ms, 10, |_, _| {});
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
            client3.wait_and_step_with(now_ms, 10, |_, _| {});
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
            client3.wait_and_step_with(now_ms, 10, |_, _| {});
            server.step(now_ms, resolver3, |_| {});
        }
        assert_eq!(client3.status(), NetworkStatus::Online);
        assert_eq!(server.active_client_count(), 2);
    }
    #[test]
    fn test_server_rejects_malformed_handshakes_and_enforces_anti_replay() {
        use std::io::Write;
        let psk = [0x55u8; 32];
        let uuid = [0xAAu8; 16];
        let resolver = |id: &[u8; 16]| if *id == uuid { Some(psk) } else { None };
        let mut now_ms = 1000u64;

        let mut server = NetServer::<4>::bind([127, 0, 0, 1], 0).unwrap();
        let port = server.port();

        // (a) Bad magic
        let mut s_bad_magic = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        now_ms += 10;
        server.step(now_ms, resolver, |_| {});
        assert_eq!(server.active_client_count(), 1);
        s_bad_magic.write_all(&[0x00, 0x00, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0]).unwrap();
        now_ms += 10;
        server.step(now_ms, resolver, |_| {});
        assert_eq!(server.active_client_count(), 0);

        // (b) MsgType::Data before handshake completes
        let mut s_bad_type = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        now_ms += 10;
        server.step(now_ms, resolver, |_| {});
        assert_eq!(server.active_client_count(), 1);
        let hdr_data = FrameHeader::new(MsgType::Data, 0, 0, 32);
        let mut hdr_bytes = [0u8; HEADER_LEN];
        hdr_data.encode(&mut hdr_bytes);
        s_bad_type.write_all(&hdr_bytes).unwrap();
        now_ms += 10;
        server.step(now_ms, resolver, |_| {});
        assert_eq!(server.active_client_count(), 0);

        // (c) HandshakeInit with bad HMAC tag
        let mut s_bad_tag = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        now_ms += 10;
        server.step(now_ms, resolver, |_| {});
        assert_eq!(server.active_client_count(), 1);

        let (mut init_frame, init_len) = handshake_init_frame(&psk, uuid, [0x11; 32]);
        init_frame[init_len - 1] ^= 0x01; // Corrupt tag
        s_bad_tag.write_all(&init_frame[..init_len]).unwrap();
        now_ms += 10;
        server.step(now_ms, resolver, |_| {});
        assert_eq!(server.active_client_count(), 0);

        // Anti-replay test on valid connection
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        now_ms += 10;
        server.step(now_ms, resolver, |_| {});
        assert_eq!(server.active_client_count(), 1);

        // Valid HandshakeInit
        let client_nonce = [0x22; 32];
        let (init_frame, init_len) = handshake_init_frame(&psk, uuid, client_nonce);
        stream.write_all(&init_frame[..init_len]).unwrap();

        now_ms += 10;
        let mut connected = false;
        server.step(now_ms, resolver, |ev| {
            if let ServerEvent::Connected { .. } = ev {
                connected = true;
            }
        });
        assert!(connected);
        assert!(server.is_client_online(0));

        // Read HandshakeResp from server
        let (session_key, resp_payload) = read_session_key(&mut stream, &psk, &client_nonce);

        // Send seq = 1 frame
        let mut frame1 = [0u8; MAX_FRAME_LEN];
        let len1 = pack_and_encrypt_directed(
            &session_key,
            &resp_payload.session_salt,
            Direction::ClientToServer,
            MsgType::Data,
            resp_payload.assigned_session_id,
            1,
            b"PAYLOAD_1",
            &mut frame1,
        ).unwrap();
        stream.write_all(&frame1[..len1]).unwrap();

        let mut received_events: std::vec::Vec<(MsgType, std::vec::Vec<u8>)> = std::vec::Vec::new();
        now_ms += 10;
        server.step(now_ms, resolver, |ev| {
            if let ServerEvent::Data { msg_type, payload, .. } = ev {
                received_events.push((msg_type, payload.to_vec()));
            }
        });
        assert_eq!(received_events.len(), 1);
        assert_eq!(received_events[0].1, b"PAYLOAD_1");
        let mut ack_buf = [0u8; MAX_FRAME_LEN];
        let _ = read_exact_frame(&mut stream, &mut ack_buf);

        // Replay exact seq = 1 frame
        stream.write_all(&frame1[..len1]).unwrap();
        let sfd = server.sessions[0].as_ref().unwrap().socket.fd();
        let mut pfd = libc::pollfd { fd: sfd, events: libc::POLLIN, revents: 0 };
        unsafe { libc::poll(&mut pfd, 1, 100) };
        for _ in 0..10 {
            now_ms += 10;
            server.step(now_ms, resolver, |_| {});
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // Replayed seq = 1 must be ignored
        assert_eq!(received_events.len(), 1);
        assert!(server.is_client_online(0));

        // Send seq = 2 frame
        let mut frame2 = [0u8; MAX_FRAME_LEN];
        let len2 = pack_and_encrypt_directed(
            &session_key,
            &resp_payload.session_salt,
            Direction::ClientToServer,
            MsgType::Data,
            resp_payload.assigned_session_id,
            2,
            b"PAYLOAD_2",
            &mut frame2,
        ).unwrap();
        stream.write_all(&frame2[..len2]).unwrap();
        let sfd = server.sessions[0].as_ref().unwrap().socket.fd();
        let mut pfd = libc::pollfd { fd: sfd, events: libc::POLLIN, revents: 0 };
        unsafe { libc::poll(&mut pfd, 1, 100) };
        for _ in 0..10 {
            now_ms += 10;
            server.step(now_ms, resolver, |ev| {
                if let ServerEvent::Data { msg_type, payload, .. } = ev {
                    received_events.push((msg_type, payload.to_vec()));
                }
            });
            if received_events.len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(received_events.len(), 2);
        assert_eq!(received_events[1].1, b"PAYLOAD_2");
    }

    #[test]
    fn test_server_byte_by_byte_fragmented_handshake_and_data() {
        use std::io::Write;
        let psk = [0x77u8; 32];
        let uuid = [0x99u8; 16];
        let resolver = |id: &[u8; 16]| if *id == uuid { Some(psk) } else { None };
        let mut now_ms = 1000u64;

        let mut server = NetServer::<4>::bind([127, 0, 0, 1], 0).unwrap();
        let port = server.port();

        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        now_ms += 10;
        server.step(now_ms, resolver, |_| {});
        assert_eq!(server.active_client_count(), 1);

        // Prepare HandshakeInit frame
        let client_nonce = [0x33u8; 32];
        let (init_frame, init_len) = handshake_init_frame(&psk, uuid, client_nonce);

        // Stream HandshakeInit 3 bytes at a time
        let mut connected_fired = false;
        for chunk in init_frame[..init_len].chunks(3) {
            stream.write_all(chunk).unwrap();
            now_ms += 1;
            server.step(now_ms, resolver, |ev| {
                if let ServerEvent::Connected { .. } = ev {
                    connected_fired = true;
                }
            });
        }
        assert!(connected_fired);
        assert!(server.is_client_online(0));

        // Read HandshakeResp from server
        let (session_key, resp_payload) = read_session_key(&mut stream, &psk, &client_nonce);

        // Prepare encrypted Heartbeat frame
        let hb = crate::packet::HeartbeatPayload {
            battery_pct: 88,
            rssi: -50,
            pending_outbox: 0,
            uptime_s: 120,
        };
        let mut hb_pt = [0u8; crate::packet::HeartbeatPayload::LEN];
        hb.encode(&mut hb_pt).unwrap();
        let mut hb_frame = [0u8; MAX_FRAME_LEN];
        let hb_len = pack_and_encrypt_directed(
            &session_key,
            &resp_payload.session_salt,
            Direction::ClientToServer,
            MsgType::Heartbeat,
            resp_payload.assigned_session_id,
            1,
            &hb_pt,
            &mut hb_frame,
        ).unwrap();

        // Stream Heartbeat 3 bytes at a time
        let mut hb_received = false;
        for chunk in hb_frame[..hb_len].chunks(3) {
            stream.write_all(chunk).unwrap();
            for _ in 0..5 {
                now_ms += 1;
                server.step(now_ms, resolver, |ev| {
                    if let ServerEvent::Data { msg_type, payload, .. } = ev {
                        if msg_type == MsgType::Heartbeat {
                            let decoded_hb = crate::packet::HeartbeatPayload::decode(payload).unwrap();
                            assert_eq!(decoded_hb.battery_pct, 88);
                            assert_eq!(decoded_hb.uptime_s, 120);
                            hb_received = true;
                        }
                    }
                });
                if hb_received {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        assert!(hb_received);
    }


    #[test]
    fn test_send_failure_returns_send_failed() {
        let psk = [0x55u8; 32];
        let uuid = [0xAAu8; 16];

        let mut server = NetServer::<4>::bind([127, 0, 0, 1], 0).expect("bind server");
        let port = server.port();
        let mut client = NetClient::<8>::new(psk, uuid, [127, 0, 0, 1], port);

        let mut now_ms = 1000u64;
        client.wait_and_step_with(now_ms, 10, |_, _| {});
        now_ms += 10;
        server.step(now_ms, |id| if *id == uuid { Some(psk) } else { None }, |_| {});
        now_ms += 10;
        client.wait_and_step_with(now_ms, 10, |_, _| {});
        now_ms += 10;
        server.step(now_ms, |id| if *id == uuid { Some(psk) } else { None }, |_| {});
        assert!(server.is_client_online(0));

        // Shutdown socket for writing so send() fails with EPIPE
        let fd = server.client_socket_fd(0).unwrap();
        unsafe { libc::shutdown(fd, libc::SHUT_WR) };

        let res = server.send_data(0, b"test_payload");
        assert_eq!(res, Err(PacketError::SendFailed));
    }

    #[test]
    fn test_online_session_mut_returns_not_online() {
        let mut server = NetServer::<2>::bind([127, 0, 0, 1], 0).expect("bind server");
        assert_eq!(server.send_data(0, b"test"), Err(PacketError::NotOnline));
        assert_eq!(server.send_data(10, b"test"), Err(PacketError::NotOnline));
    }

    #[test]
    fn server_disconnects_on_server_to_client_direction_frame() {
        use std::io::Write;

        let psk = [0x55u8; 32];
        let uuid = [0xAAu8; 16];
        let client_nonce = [0x33u8; 32];
        let resolver = |id: &[u8; 16]| if *id == uuid { Some(psk) } else { None };

        let mut server = NetServer::<4>::bind([127, 0, 0, 1], 0).expect("bind server");
        let port = server.port();

        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_nodelay(true).unwrap();

        let mut now_ms = 1000u64;
        server.step(now_ms, resolver, |_| {});
        assert_eq!(server.active_client_count(), 1);

        let (init_frame, init_len) = handshake_init_frame(&psk, uuid, client_nonce);
        stream.write_all(&init_frame[..init_len]).unwrap();

        now_ms += 10;
        server.step(now_ms, resolver, |_| {});
        assert!(server.is_client_online(0));

        let (session_key, resp_payload) = read_session_key(&mut stream, &psk, &client_nonce);

        let mut frame = [0u8; MAX_FRAME_LEN];
        let len = pack_and_encrypt_directed(
            &session_key,
            &resp_payload.session_salt,
            Direction::ServerToClient,
            MsgType::Data,
            resp_payload.assigned_session_id,
            1,
            b"REFLECTED_PAYLOAD",
            &mut frame,
        )
        .unwrap();
        stream.write_all(&frame[..len]).unwrap();

        let mut data_events = 0;
        now_ms += 10;
        server.step(now_ms, resolver, |ev| {
            if let ServerEvent::Data { .. } = ev {
                data_events += 1;
            }
        });

        assert_eq!(server.active_client_count(), 0);
        assert_eq!(data_events, 0);
    }

}

