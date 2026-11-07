//! Frame reassembly, receive loop, and session cryptographic state.

use crate::packet::{
    decrypt_and_unpack, pack_and_encrypt_directed, Direction, FrameHeader, MsgType, PacketError,
    HEADER_LEN, MAX_FRAME_LEN,
};
use crate::posix::PosixSocket;

pub(crate) const MAX_RECV_PER_STEP: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvOutcome {
    Data,
    WouldBlock,
    Closed,
    Error,
}

pub struct FrameAssembler {
    buf: [u8; MAX_FRAME_LEN * 2],
    len: usize,
}

impl Default for FrameAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameAssembler {
    pub const fn new() -> Self {
        Self {
            buf: [0u8; MAX_FRAME_LEN * 2],
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn frame_slice(&self, frame_total_len: usize) -> &[u8] {
        &self.buf[..frame_total_len]
    }

    pub fn frame_slice_mut(&mut self, frame_total_len: usize) -> &mut [u8] {
        &mut self.buf[..frame_total_len]
    }

    pub fn recv_from(&mut self, socket: &PosixSocket) -> RecvOutcome {
        if self.len >= self.buf.len() {
            return RecvOutcome::Error;
        }
        match socket.recv(&mut self.buf[self.len..]) {
            Ok(0) => RecvOutcome::Closed,
            Ok(n) => {
                self.len += n;
                RecvOutcome::Data
            }
            Err(err) if err == libc::EAGAIN || err == libc::EWOULDBLOCK => RecvOutcome::WouldBlock,
            Err(_) => RecvOutcome::Error,
        }
    }

    pub fn peek_header(&self) -> Result<Option<FrameHeader>, PacketError> {
        if self.len < HEADER_LEN {
            return Ok(None);
        }
        Ok(Some(FrameHeader::decode(&self.buf[..HEADER_LEN])?))
    }

    pub fn next_frame(
        &self,
        min_payload: usize,
    ) -> Result<Option<(FrameHeader, usize)>, PacketError> {
        if self.len < HEADER_LEN {
            return Ok(None);
        }
        let hdr = FrameHeader::decode(&self.buf[..HEADER_LEN])?;
        if (hdr.payload_len as usize) < min_payload {
            return Err(PacketError::InvalidPayload);
        }
        let frame_total_len = HEADER_LEN + (hdr.payload_len as usize);
        if self.len < frame_total_len {
            return Ok(None);
        }
        Ok(Some((hdr, frame_total_len)))
    }

    pub fn consume(&mut self, n: usize) {
        if n >= self.len {
            self.len = 0;
        } else {
            self.buf.copy_within(n..self.len, 0);
            self.len -= n;
        }
    }
}

pub struct SessionCrypto {
    pub session_id: u32,
    pub salt: [u8; 4],
    pub key: [u8; 32],
    pub tx_seq: u32,
    pub rx_seq: u32,
}

impl Default for SessionCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionCrypto {
    pub const fn new() -> Self {
        Self {
            session_id: 0,
            salt: [0u8; 4],
            key: [0u8; 32],
            tx_seq: 1,
            rx_seq: 0,
        }
    }

    pub fn reset(&mut self, session_id: u32, salt: [u8; 4], key: [u8; 32]) {
        self.session_id = session_id;
        self.salt = salt;
        self.key = key;
        self.tx_seq = 1;
        self.rx_seq = 0;
    }

    pub fn seal(
        &mut self,
        dir: Direction,
        msg_type: MsgType,
        pt: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PacketError> {
        let seq = self.tx_seq;
        let len = pack_and_encrypt_directed(
            &self.key,
            &self.salt,
            dir,
            msg_type,
            self.session_id,
            seq,
            pt,
            out,
        )?;
        self.tx_seq = self.tx_seq.wrapping_add(1);
        Ok(len)
    }

    pub fn open<'a>(
        &mut self,
        frame: &'a mut [u8],
    ) -> Result<Option<(FrameHeader, &'a [u8])>, PacketError> {
        let (hdr, pt) = decrypt_and_unpack(&self.key, &self.salt, frame)?;
        if hdr.seq_num > self.rx_seq {
            self.rx_seq = hdr.seq_num;
            Ok(Some((hdr, pt)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::TAG_LEN;
    use std::io::Write;
    #[test]
    fn test_session_crypto_seal_open_and_anti_replay() {
        let mut server = SessionCrypto::new();
        server.reset(0x1234_5678, [1, 2, 3, 4], [0x42; 32]);

        let mut client = SessionCrypto::new();
        client.reset(0x1234_5678, [1, 2, 3, 4], [0x42; 32]);

        let payload = b"hello framing";
        let mut frame_buf = [0u8; MAX_FRAME_LEN];
        let len = client
            .seal(
                Direction::ClientToServer,
                MsgType::Data,
                payload,
                &mut frame_buf,
            )
            .expect("seal success");
        assert_eq!(client.tx_seq, 2);

        // First open on server succeeds
        let mut frame_copy = [0u8; MAX_FRAME_LEN];
        frame_copy[..len].copy_from_slice(&frame_buf[..len]);
        let opened = server
            .open(&mut frame_copy[..len])
            .expect("open success");
        assert!(opened.is_some());
        let (hdr, pt) = opened.unwrap();
        assert_eq!(hdr.seq_num, 1);
        assert_eq!(pt, payload);
        assert_eq!(server.rx_seq, 1);

        // Replay of same frame: open decrypts successfully but returns None
        frame_copy[..len].copy_from_slice(&frame_buf[..len]);
        let replayed = server
            .open(&mut frame_copy[..len])
            .expect("open replayed frame does not error");
        assert!(replayed.is_none());
        assert_eq!(server.rx_seq, 1);

        // Tampered frame fails authentication
        frame_copy[..len].copy_from_slice(&frame_buf[..len]);
        frame_copy[len - 1] ^= 0x01;
        assert!(server.open(&mut frame_copy[..len]).is_err());
    }

    fn socket_pair() -> (PosixSocket, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let reader = PosixSocket::new_nonblocking_tcp().unwrap();
        let _ = reader.connect_ipv4([127, 0, 0, 1], port);
        let (writer, _) = listener.accept().unwrap();
        let mut pfd = libc::pollfd {
            fd: reader.fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, 1000) };
        assert!(ret > 0, "socket connect poll failed");
        (reader, writer)
    }

    #[test]
    fn frame_assembler_reassembles_partial_frame() {
        let mut crypto = SessionCrypto::new();
        crypto.reset(1, [0; 4], [0x11; 32]);
        let mut frame = [0u8; MAX_FRAME_LEN];
        let payload = b"partial frame payload";
        let frame_len = crypto
            .seal(Direction::ClientToServer, MsgType::Data, payload, &mut frame)
            .unwrap();

        let (reader, mut writer) = socket_pair();
        let mut assembler = FrameAssembler::new();

        // 1. Write first 5 bytes
        writer.write_all(&frame[..5]).unwrap();
        assert_eq!(assembler.recv_from(&reader), RecvOutcome::Data);
        assert_eq!(assembler.next_frame(TAG_LEN).unwrap(), None);

        // 2. Write up to HEADER_LEN + 1
        writer.write_all(&frame[5..HEADER_LEN + 1]).unwrap();
        assert_eq!(assembler.recv_from(&reader), RecvOutcome::Data);
        assert_eq!(assembler.next_frame(TAG_LEN).unwrap(), None);

        // 3. Write the rest
        writer.write_all(&frame[HEADER_LEN + 1..frame_len]).unwrap();
        assert_eq!(assembler.recv_from(&reader), RecvOutcome::Data);
        let (hdr, len) = assembler.next_frame(TAG_LEN).unwrap().unwrap();
        assert_eq!(len, frame_len);
        assert_eq!(hdr.seq_num, 1);

        // 4. Nothing pending
        assert_eq!(assembler.recv_from(&reader), RecvOutcome::WouldBlock);
    }

    #[test]
    fn frame_assembler_consume_keeps_trailing_bytes() {
        let (reader, mut writer) = socket_pair();
        let mut assembler = FrameAssembler::new();
        let mut crypto = SessionCrypto::new();
        crypto.reset(1, [0; 4], [0x11; 32]);
        let mut f1 = [0u8; MAX_FRAME_LEN];
        let mut f2 = [0u8; MAX_FRAME_LEN];
        let len1 = crypto
            .seal(Direction::ClientToServer, MsgType::Data, b"frame1", &mut f1)
            .unwrap();
        let len2 = crypto
            .seal(Direction::ClientToServer, MsgType::Data, b"frame2", &mut f2)
            .unwrap();
        writer.write_all(&f1[..len1]).unwrap();
        writer.write_all(&f2[..len2]).unwrap();

        while assembler.len() < len1 + len2 {
            match assembler.recv_from(&reader) {
                RecvOutcome::Data => {}
                RecvOutcome::WouldBlock => {
                    let mut pfd = libc::pollfd {
                        fd: reader.fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ret = unsafe { libc::poll(&mut pfd, 1, 50) };
                    assert!(ret > 0, "socket poll timed out waiting for data");
                }
                other => panic!("unexpected outcome: {:?}", other),
            }
        }

        assembler.consume(len1);
        let (hdr2, second_len) = assembler.next_frame(TAG_LEN).unwrap().unwrap();
        assert_eq!(hdr2.seq_num, 2);
        assert_eq!(second_len, len2);
        assert_eq!(assembler.len(), len2);
    }

    #[test]
    fn frame_assembler_rejects_short_payload_and_bad_magic() {
        let mut assembler = FrameAssembler::new();
        let hdr = FrameHeader::new(MsgType::Data, 1, 1, (TAG_LEN - 1) as u16);
        let mut hdr_bytes = [0u8; HEADER_LEN];
        hdr.encode(&mut hdr_bytes);
        assembler.buf[..HEADER_LEN].copy_from_slice(&hdr_bytes);
        assembler.len = HEADER_LEN + TAG_LEN - 1;
        assert_eq!(
            assembler.next_frame(TAG_LEN),
            Err(PacketError::InvalidPayload)
        );

        assembler.clear();
        assembler.buf[..HEADER_LEN].fill(0xFF);
        assembler.len = HEADER_LEN;
        assert_eq!(
            assembler.next_frame(TAG_LEN),
            Err(PacketError::InvalidMagic)
        );
    }

    #[test]
    fn frame_assembler_reports_closed_and_full() {
        let (reader, writer) = socket_pair();
        let mut assembler = FrameAssembler::new();
        drop(writer);

        let mut outcome = assembler.recv_from(&reader);
        for _ in 0..50 {
            if outcome == RecvOutcome::Closed {
                break;
            }
            let mut pfd = libc::pollfd {
                fd: reader.fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe { libc::poll(&mut pfd, 1, 10) };
            outcome = assembler.recv_from(&reader);
        }
        assert_eq!(outcome, RecvOutcome::Closed);

        let (reader, mut writer) = socket_pair();
        let mut assembler = FrameAssembler::new();
        let big_payload = std::vec![0x42u8; MAX_FRAME_LEN * 2 + 1];
        writer.write_all(&big_payload).unwrap();

        while assembler.len() < MAX_FRAME_LEN * 2 {
            match assembler.recv_from(&reader) {
                RecvOutcome::Data => {}
                RecvOutcome::WouldBlock => {
                    let mut pfd = libc::pollfd {
                        fd: reader.fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ret = unsafe { libc::poll(&mut pfd, 1, 50) };
                    assert!(ret > 0, "socket poll timed out waiting for data");
                }
                other => panic!("unexpected outcome: {:?}", other),
            }
        }

        assert_eq!(assembler.len(), MAX_FRAME_LEN * 2);
        assert_eq!(assembler.recv_from(&reader), RecvOutcome::Error);
    }
}
