use trillby_net::{
    AuthInitPayload, AuthRespPayload, ClientState, MsgType, NetClient, NetServer, ServerEvent,
    WorkEventKind, WorkEventPayload,
};
use trillby_core::net_types::NetworkStatus;

fn step_client<const CAP: usize, F>(
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
fn test_end_to_end_handshake_and_work_event_flow() {
    let psk = [0x42u8; 32];
    let device_uuid = [0xAAu8; 16];

    let mut server = NetServer::<4>::bind([127, 0, 0, 1], 0).expect("bind NetServer");
    let port = server.port();
    let mut client = NetClient::<16>::new(psk, device_uuid, [127, 0, 0, 1], port);

    let mut now_ms = 1000u64;

    // 1. Initial state is Offline
    assert_eq!(client.status(), NetworkStatus::Offline);

    // 2. Drive handshake across loopback
    let psk_resolver = |uuid: &[u8; 16]| if *uuid == device_uuid { Some(psk) } else { None };

    for _ in 0..5 {
        now_ms += 10;
        step_client(&mut client, now_ms, |_, _| {});
        server.step(now_ms, psk_resolver, |_| {});
    }

    assert_eq!(client.status(), NetworkStatus::Online);
    assert_eq!(server.active_client_count(), 1);
    assert!(server.is_client_online(0));

    // 3. Client sends application domain event
    let app_event = b"WORK_START:WO-55102:OP-0042";
    client.send_data(app_event).unwrap();
    assert_eq!(client.outbox_pending_count(), 1);

    // 4. Client flushes frame; Server receives and auto-ACKs
    now_ms += 10;
    step_client(&mut client, now_ms, |_, _| {});

    let mut received_event = [0u8; 64];
    let mut received_len = 0;
    server.step(now_ms, psk_resolver, |event| {
        if let ServerEvent::Data { client_idx, msg_type, payload } = event {
            assert_eq!(client_idx, 0);
            assert_eq!(msg_type, MsgType::Data);
            received_event[..payload.len()].copy_from_slice(payload);
            received_len = payload.len();
        }
    });
    assert_eq!(&received_event[..received_len], app_event);

    // 5. Client receives auto-ACK -> outbox is drained
    now_ms += 10;
    step_client(&mut client, now_ms, |_, _| {});
    assert_eq!(client.outbox_pending_count(), 0);

    // 6. Server pushes an application command down to client
    let server_cmd = b"JOB_DISPATCH:WO-99120";
    server.send_data(0, server_cmd).unwrap();

    let mut client_received = [0u8; 64];
    let mut client_received_len = 0;
    now_ms += 10;
    step_client(&mut client, now_ms, |msg_type, data| {
        assert_eq!(msg_type, MsgType::Data);
        client_received[..data.len()].copy_from_slice(data);
        client_received_len = data.len();
    });
    assert_eq!(&client_received[..client_received_len], server_cmd);

    // 7. Client sends AuthInit (RFID/Operator scan)
    let auth_req = AuthInitPayload {
        auth_data_len: 8,
        auth_data: [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        timestamp_ms: now_ms,
    };
    client.send_auth(&auth_req).unwrap();
    assert_eq!(client.outbox_pending_count(), 1);

    now_ms += 10;
    step_client(&mut client, now_ms, |_, _| {});

    let mut auth_received = false;
    server.step(now_ms, psk_resolver, |event| {
        if let ServerEvent::Data { msg_type: MsgType::AuthInit, payload, .. } = event {
            let decoded = AuthInitPayload::decode(payload).unwrap();
            assert_eq!(decoded.auth_data_len, 8);
            assert_eq!(&decoded.auth_data[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
            auth_received = true;
        }
    });
    assert!(auth_received);

    // 8. Server responds with AuthResp
    let auth_resp = AuthRespPayload {
        status: 0, // Authorized
        role: 1,   // Operator role
        session_ttl_s: 3600,
    };
    server.send_auth_resp(0, &auth_resp).unwrap();

    now_ms += 10;
    let mut client_auth_resp = false;
    step_client(&mut client, now_ms, |msg_type, data| {
        if msg_type == MsgType::AuthResp {
            let resp = AuthRespPayload::decode(data).unwrap();
            assert_eq!(resp.status, 0);
            assert_eq!(resp.role, 1);
            assert_eq!(resp.session_ttl_s, 3600);
            client_auth_resp = true;
        }
    });
    assert!(client_auth_resp);
    assert_eq!(client.outbox_pending_count(), 0);
    assert_eq!(client.status(), NetworkStatus::Online);
}

#[test]
fn test_send_work_event_end_to_end() {
    let psk = [0x42u8; 32];
    let device_uuid = [0xCCu8; 16];

    let mut server = NetServer::<4>::bind([127, 0, 0, 1], 0).expect("bind NetServer");
    let port = server.port();
    let mut client = NetClient::<16>::new(psk, device_uuid, [127, 0, 0, 1], port);

    let mut now_ms = 1000u64;
    let psk_resolver = |uuid: &[u8; 16]| if *uuid == device_uuid { Some(psk) } else { None };

    for _ in 0..5 {
        now_ms += 10;
        step_client(&mut client, now_ms, |_, _| {});
        server.step(now_ms, psk_resolver, |_| {});
    }
    assert_eq!(client.status(), NetworkStatus::Online);

    // Enqueue WorkStart, WorkStop, and OperatorLogout
    let ev_start = WorkEventPayload::work_start(b"OP-0042", b"WO-55102", 1100);
    let ev_stop = WorkEventPayload::work_stop(b"OP-0042", b"WO-55102", 4600, 3500);
    let ev_logout = WorkEventPayload::operator_logout(b"OP-0042", 4700);

    client.send_work_event(&ev_start).unwrap();
    client.send_work_event(&ev_stop).unwrap();
    client.send_work_event(&ev_logout).unwrap();
    assert_eq!(client.outbox_pending_count(), 3);

    let mut received: Vec<WorkEventPayload> = Vec::new();
    for _ in 0..10 {
        now_ms += 10;
        step_client(&mut client, now_ms, |_, _| {});
        server.step(now_ms, psk_resolver, |event| {
            if let ServerEvent::Data { client_idx, msg_type, payload } = event {
                assert_eq!(client_idx, 0);
                assert_eq!(msg_type, MsgType::Data);
                assert_eq!(payload.len(), WorkEventPayload::LEN);
                let decoded = WorkEventPayload::decode(payload).expect("decode WorkEventPayload");
                received.push(decoded);
            }
        });
        if client.outbox_pending_count() == 0 && received.len() == 3 {
            break;
        }
    }

    assert_eq!(client.outbox_pending_count(), 0);
    assert_eq!(received.len(), 3);
    assert_eq!(received[0].kind, WorkEventKind::WorkStart);
    assert_eq!(received[0], ev_start);
    assert_eq!(received[1].kind, WorkEventKind::WorkStop);
    assert_eq!(received[1], ev_stop);
    assert_eq!(received[2].kind, WorkEventKind::OperatorLogout);
    assert_eq!(received[2], ev_logout);
}

#[test]
fn test_monotonic_backoff_timing() {
    let psk = [0x55u8; 32];
    let device_uuid = [0xBBu8; 16];

    // Pick an unreachable port so connection fails/times out
    let mut client: NetClient<16> = NetClient::new(psk, device_uuid, [127, 0, 0, 1], 1);

    // Trigger initial connection at t = 1000ms
    let _ = client.poll_step(1000, 0);

    // Socket encounters POLLERR at t = 1050ms
    let _ = client.poll_step(1050, libc::POLLERR);

    // Client must transition to Disconnected with next_attempt_ms = 1050 + 1000 = 2050ms
    assert!(matches!(
        client.state(),
        ClientState::Disconnected { next_attempt_ms: 2050, backoff_ms: 2000 }
    ));

    // Poll at t = 2000ms (< 2050ms) -> Must NOT initiate connection
    let _ = client.poll_step(2000, 0);
    assert!(matches!(
        client.state(),
        ClientState::Disconnected { next_attempt_ms: 2050, .. }
    ));

    // Poll at t = 2050ms (>= 2050ms) -> Must initiate reconnection attempt
    let _ = client.poll_step(2050, 0);
    assert!(!matches!(
        client.state(),
        ClientState::Disconnected { next_attempt_ms: 2050, .. }
    ));
}

#[test]
fn test_directional_aead_nonce_and_reflection_isolation() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use trillby_net::{
        derive_session_key, pack_and_authenticate_hmac, pack_and_encrypt,
        verify_and_unpack_hmac, FrameHeader, HandshakeInitPayload, HandshakeRespPayload,
        HEADER_LEN, MAX_FRAME_LEN,
    };

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();

    let psk = [0x42u8; 32];
    let uuid = [0x55u8; 16];
    let mut client: NetClient<4> = NetClient::new(psk, uuid, [127, 0, 0, 1], port);
    let mut now_ms = 1000u64;

    // Step 1: Connect client
    client.poll_step(now_ms, 0);

    let mut peer_stream = {
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
    peer_stream.set_nonblocking(true).unwrap();
    peer_stream.set_nodelay(true).unwrap();

    // Step 2: Client transmits HandshakeInit
    now_ms += 10;
    client.poll_step(now_ms, libc::POLLOUT);
    assert_eq!(client.status(), NetworkStatus::Handshaking);

    // Step 3: Peer reads HandshakeInit
    let mut init_buf = [0u8; MAX_FRAME_LEN];
    peer_stream.set_nonblocking(false).unwrap();
    peer_stream.read_exact(&mut init_buf[..HEADER_LEN]).unwrap();
    let init_hdr = FrameHeader::decode(&init_buf[..HEADER_LEN]).unwrap();
    let total_init_len = HEADER_LEN + init_hdr.payload_len as usize;
    peer_stream.read_exact(&mut init_buf[HEADER_LEN..total_init_len]).unwrap();
    peer_stream.set_nonblocking(true).unwrap();

    let (_hdr, init_pt) = verify_and_unpack_hmac(&psk, &init_buf[..total_init_len]).unwrap();
    let init_payload = HandshakeInitPayload::decode(init_pt).unwrap();

    // Step 4: Peer responds with HandshakeResp
    let server_nonce = [0x66u8; 32];
    let session_id = 12345u32;
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
    peer_stream.write_all(&resp_frame[..resp_len]).unwrap();

    // Step 5: Client receives HandshakeResp and transitions to Online
    now_ms += 10;
    client.poll_step(now_ms, libc::POLLIN);
    assert_eq!(client.status(), NetworkStatus::Online);

    let session_key = derive_session_key(
        &psk,
        &session_salt,
        &init_payload.client_nonce,
        &server_nonce,
    );

    // Step 6: Client flushes encrypted frame (seq_num = 1)
    let test_plaintext = b"DIRECTIONAL_ISOLATION_TEST_PLAINTEXT";
    client.send_data(test_plaintext).unwrap();
    now_ms += 10;
    client.poll_step(now_ms, libc::POLLOUT);

    // Step 7: Peer reads raw wire bytes of client frame
    let mut client_frame = [0u8; MAX_FRAME_LEN];
    peer_stream.set_nonblocking(false).unwrap();
    peer_stream.read_exact(&mut client_frame[..HEADER_LEN]).unwrap();
    let c_hdr = FrameHeader::decode(&client_frame[..HEADER_LEN]).unwrap();
    let client_frame_len = HEADER_LEN + c_hdr.payload_len as usize;
    peer_stream.read_exact(&mut client_frame[HEADER_LEN..client_frame_len]).unwrap();
    peer_stream.set_nonblocking(true).unwrap();
    assert_eq!(c_hdr.seq_num, 1);

    // Step 8: Encrypt same plaintext on server for seq_num = 1
    let mut server_frame = [0u8; MAX_FRAME_LEN];
    let server_frame_len = pack_and_encrypt(
        &session_key,
        &session_salt,
        MsgType::Data,
        session_id,
        1,
        test_plaintext,
        &mut server_frame,
    ).unwrap();
    assert_eq!(client_frame_len, server_frame_len);

    // Verify client->server and server->client ciphertexts are NOT equal (keystream isolation)
    assert_ne!(
        &client_frame[..client_frame_len],
        &server_frame[..server_frame_len],
        "Client->server and server->client ciphertexts must not reuse the same keystream"
    );

    // Step 9: Reflect client_frame directly back into client socket
    peer_stream.write_all(&client_frame[..client_frame_len]).unwrap();

    // Step 10: Step client with POLLIN
    now_ms += 10;
    let mut data_callbacks = 0;
    client.poll_step_with(now_ms, libc::POLLIN, |_msg_type, _payload| {
        data_callbacks += 1;
    });

    // Client must reject reflected client->server frame and transition to Disconnected
    assert_eq!(
        data_callbacks, 0,
        "Client must not accept and deliver reflected client->server frame"
    );
    assert!(
        matches!(client.state(), ClientState::Disconnected { .. }),
        "Client must disconnect upon receiving reflected client->server frame"
    );
}

