#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use trillby_net::{
    pack_and_authenticate_hmac_inplace, pack_and_encrypt, verify_and_unpack_hmac, AckPayload,
    FrameHeader, HandshakeInitPayload, HandshakeRespPayload, MsgType, HEADER_LEN,
    MAX_FRAME_LEN,
};

pub fn read_exact_frame(stream: &mut TcpStream, buf: &mut [u8; MAX_FRAME_LEN]) -> usize {
    stream.set_nonblocking(false).unwrap();
    stream.read_exact(&mut buf[..HEADER_LEN]).expect("read frame header");
    let hdr = FrameHeader::decode(&buf[..HEADER_LEN]).expect("decode frame header");
    let total_len = HEADER_LEN + (hdr.payload_len as usize);
    assert!(total_len <= MAX_FRAME_LEN, "Frame exceeds MAX_FRAME_LEN");
    stream.read_exact(&mut buf[HEADER_LEN..total_len]).expect("read frame payload");
    stream.set_nonblocking(true).unwrap();
    total_len
}

pub fn accept_peer(listener: &TcpListener) -> TcpStream {
    let _ = listener.set_nonblocking(true);
    let start = std::time::Instant::now();
    let stream = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if start.elapsed() > std::time::Duration::from_secs(1) {
                    panic!("Timeout waiting for peer connection");
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => panic!("Accept error: {:?}", e),
        }
    };
    stream.set_nonblocking(true).unwrap();
    stream.set_nodelay(true).unwrap();
    stream
}

pub fn read_handshake_init(
    stream: &mut TcpStream,
    psk: &[u8; 32],
) -> trillby_net::HandshakeInitPayload {
    let mut buf = [0u8; MAX_FRAME_LEN];
    let n = read_exact_frame(stream, &mut buf);
    let (_hdr, pt) =
        verify_and_unpack_hmac(psk, &buf[..n]).expect("verify HandshakeInit HMAC");
    HandshakeInitPayload::decode(pt).expect("decode HandshakeInit")
}

pub fn build_handshake_resp(
    psk: &[u8; 32],
    session_id: u32,
    salt: [u8; 4],
    server_nonce: [u8; 32],
) -> ([u8; MAX_FRAME_LEN], usize) {
    let resp_payload = HandshakeRespPayload {
        server_nonce,
        assigned_session_id: session_id,
        session_salt: salt,
    };
    let mut resp_frame = [0u8; MAX_FRAME_LEN];
    resp_payload
        .encode(&mut resp_frame[HEADER_LEN..HEADER_LEN + HandshakeRespPayload::LEN])
        .expect("encode HandshakeResp");
    let resp_len = pack_and_authenticate_hmac_inplace(
        psk,
        MsgType::HandshakeResp,
        session_id,
        0,
        HandshakeRespPayload::LEN,
        &mut resp_frame,
    )
    .expect("pack HandshakeResp");
    (resp_frame, resp_len)
}

pub fn write_server_frame(
    stream: &mut TcpStream,
    key: &[u8; 32],
    salt: &[u8; 4],
    session_id: u32,
    seq: u32,
    msg_type: MsgType,
    pt: &[u8],
) {
    let mut frame = [0u8; MAX_FRAME_LEN];
    let len = pack_and_encrypt(key, salt, msg_type, session_id, seq, pt, &mut frame)
        .expect("pack_and_encrypt server frame");
    stream.write_all(&frame[..len]).unwrap();
}

pub fn write_ack(
    stream: &mut TcpStream,
    key: &[u8; 32],
    salt: &[u8; 4],
    session_id: u32,
    seq: u32,
    acked_seq: u32,
) {
    let ack = AckPayload {
        acked_seq,
        status: AckPayload::STATUS_OK,
    };
    let mut pt = [0u8; AckPayload::LEN];
    ack.encode(&mut pt).expect("encode AckPayload");
    write_server_frame(stream, key, salt, session_id, seq, MsgType::Ack, &pt);
}

pub fn online_pair(
    psk: [u8; 32],
    uuid: [u8; 16],
) -> (trillby_net::NetServer<4>, trillby_net::NetClient<16>, u64) {
    let mut server = trillby_net::NetServer::<4>::bind([127, 0, 0, 1], 0).expect("bind NetServer");
    let port = server.port();
    let mut client = trillby_net::NetClient::<16>::new(psk, uuid, [127, 0, 0, 1], port);
    let mut now_ms = 1000u64;
    let resolver = |id: &[u8; 16]| if *id == uuid { Some(psk) } else { None };
    let mut online = false;
    for _ in 0..50 {
        now_ms += 10;
        client.wait_and_step_with(now_ms, 10, |_, _| {});
        server.step(now_ms, resolver, |_| {});
        if client.status() == trillby_core::net_types::NetworkStatus::Online {
            online = true;
            break;
        }
    }
    assert!(online, "online_pair timed out waiting for Online status");
    (server, client, now_ms)
}
