use std::net::TcpListener;
use std::io::{Read, Write};
use trillby_net::crypto::sha256;
use trillby_net::packet::{
    decrypt_and_unpack, derive_session_key, pack_and_encrypt, AckPayload, HandshakeInitPayload,
    HandshakeRespPayload, MsgType, WorkStartPayload, HEADER_LEN, MAX_FRAME_LEN,
};
use trillby_net::{ClientState, NetClient};
use trillby_core::net_types::NetworkStatus;

#[test]
fn test_end_to_end_handshake_and_work_event_flow() {
    let psk = [0x42u8; 32];
    let device_uuid = [0xAAu8; 16];

    // Bind server listener on loopback
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind test listener");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();

    let mut client: NetClient<16> = NetClient::new(psk, device_uuid, [127, 0, 0, 1], port);

    // Step 1: Initial state is Offline
    assert_eq!(client.status(), NetworkStatus::Offline);

    // Step 2: Trigger initial connection at t = 0ms
    let _ = client.poll_step(0, 0);
    assert_eq!(client.state(), ClientState::Connecting);

    // Accept incoming connection on server side
    let mut server_stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => panic!("Accept error: {:?}", e),
        }
    };
    server_stream.set_nonblocking(false).unwrap();

    // Step 3: Client notices socket is connected (POLLOUT) at t = 50ms
    let status_change = client.poll_step(50, libc::POLLOUT);
    assert_eq!(client.state(), ClientState::Handshaking);
    assert_eq!(status_change, Some(NetworkStatus::Handshaking));

    // Step 4: Server reads HandshakeInit
    let mut init_buf = [0u8; MAX_FRAME_LEN];
    let n = server_stream.read(&mut init_buf).expect("Server read failed");
    assert!(n >= HEADER_LEN);

    let (init_hdr, init_pt) = decrypt_and_unpack(&psk, &[0u8; 4], &mut init_buf[..n])
        .expect("Server failed to decrypt HandshakeInit");
    assert_eq!(init_hdr.msg_type, MsgType::HandshakeInit);

    let init_payload = HandshakeInitPayload::decode(init_pt).unwrap();
    assert_eq!(init_payload.device_uuid, device_uuid);

    // Step 5: Server prepares HandshakeResp
    let server_nonce = sha256(b"SERVER_ENTROPY_NONCE_991");
    let session_id = 999123u32;
    let session_salt = [0x55, 0x66, 0x77, 0x88];

    let resp_payload = HandshakeRespPayload {
        server_nonce,
        assigned_session_id: session_id,
        session_salt,
    };
    let mut resp_pt = [0u8; HandshakeRespPayload::LEN];
    resp_payload.encode(&mut resp_pt).unwrap();

    let mut resp_frame = [0u8; MAX_FRAME_LEN];
    let resp_len = pack_and_encrypt(
        &psk,
        &[0u8; 4],
        MsgType::HandshakeResp,
        0,
        0,
        &resp_pt,
        &mut resp_frame,
    ).unwrap();

    server_stream.write_all(&resp_frame[..resp_len]).unwrap();

    // Step 6: Client processes HandshakeResp (POLLIN) at t = 100ms
    let status_change = client.poll_step(100, libc::POLLIN);
    assert_eq!(client.state(), ClientState::Online);
    assert_eq!(status_change, Some(NetworkStatus::Online));

    // Server derives the exact same session key
    let server_session_key = derive_session_key(
        &session_salt,
        &init_payload.client_nonce,
        &server_nonce,
    );

    // Step 7: Client enqueues WorkStart event
    let mut wo_id = [0u8; 32];
    wo_id[..8].copy_from_slice(b"WO-55102");
    let mut op_id = [0u8; 16];
    op_id[..7].copy_from_slice(b"OP-0042");

    let work_start = WorkStartPayload {
        work_order_len: 8,
        work_order_id: wo_id,
        operator_id_len: 7,
        operator_id: op_id,
        timestamp_ms: 1728800000,
    };
    let mut work_pt = [0u8; WorkStartPayload::LEN];
    work_start.encode(&mut work_pt).unwrap();

    client.enqueue_event(MsgType::WorkStart, &work_pt).unwrap();
    assert_eq!(client.outbox_pending_count(), 1);

    // Step 8: Client flushes outbox during poll step at t = 150ms
    let _ = client.poll_step(150, libc::POLLOUT);

    // Step 9: Server receives and decrypts WorkStart frame
    let mut work_buf = [0u8; MAX_FRAME_LEN];
    let n = server_stream.read(&mut work_buf).unwrap();
    let (work_hdr, work_decrypted) = decrypt_and_unpack(
        &server_session_key,
        &session_salt,
        &mut work_buf[..n],
    ).expect("Server failed to decrypt WorkStart frame");

    assert_eq!(work_hdr.msg_type, MsgType::WorkStart);
    assert_eq!(work_hdr.seq_num, 1);
    let received_payload = WorkStartPayload::decode(work_decrypted).unwrap();
    assert_eq!(received_payload, work_start);

    // Step 10: Server sends Ack
    let ack_payload = AckPayload {
        acked_seq: work_hdr.seq_num,
        status: 0,
    };
    let mut ack_pt = [0u8; AckPayload::LEN];
    ack_payload.encode(&mut ack_pt).unwrap();

    let mut ack_frame = [0u8; MAX_FRAME_LEN];
    let ack_len = pack_and_encrypt(
        &server_session_key,
        &session_salt,
        MsgType::Ack,
        session_id,
        100, // server seq
        &ack_pt,
        &mut ack_frame,
    ).unwrap();
    server_stream.write_all(&ack_frame[..ack_len]).unwrap();

    // Step 11: Client receives Ack at t = 200ms
    let _ = client.poll_step(200, libc::POLLIN);

    // Outbox should now be completely drained
    assert_eq!(client.outbox_pending_count(), 0);
    assert_eq!(client.status(), NetworkStatus::Online);
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

    // Client must transition to Disconnected with next_attempt_ms = 1050 + 2000 = 3050ms
    assert!(matches!(
        client.state(),
        ClientState::Disconnected { next_attempt_ms: 3050, backoff_ms: 4000 }
    ));

    // Poll at t = 2500ms (< 3050ms) -> Must NOT initiate connection
    let _ = client.poll_step(2500, 0);
    assert!(matches!(
        client.state(),
        ClientState::Disconnected { next_attempt_ms: 3050, .. }
    ));

    // Poll at t = 3050ms (>= 3050ms) -> Must initiate reconnection attempt
    let _ = client.poll_step(3050, 0);
    assert!(!matches!(
        client.state(),
        ClientState::Disconnected { next_attempt_ms: 3050, .. }
    ));
}

