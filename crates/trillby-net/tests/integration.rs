use trillby_net::{
    AuthInitPayload, AuthRespPayload, ClientState, MsgType, NetClient, NetServer, ServerEvent,
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

