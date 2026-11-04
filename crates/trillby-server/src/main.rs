//! Trillby floor server sink.
//!
//! Accepts encrypted Trillby client sessions via `trillby_net::NetServer`,
//! resolves device PSKs from a registry file (as written by the `provision`
//! example with `--registry`), and logs every event to stdout, one line each.
//! Nothing is persisted and no commands are sent back (the transport layer
//! still auto-ACKs Data/AuthInit/Heartbeat frames so client outboxes drain).

use std::io::Write;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use trillby_net::{
    AuthInitPayload, HeartbeatPayload, MsgType, NetServer, ServerEvent, WorkEventKind,
    WorkEventPayload,
};

const MAX_CLIENTS: usize = 32;
const MAX_DEVICES: usize = 256;
/// poll() timeout. Only bounds idle wakeups; data is handled as soon as it arrives.
const POLL_TIMEOUT_MS: libc::c_int = 1000;

/// Fallback credentials hard-coded in `crates/trillby/src/main.rs` when no
/// `/etc/trillby/device.key` exists. Enabled with `--dev`.
const DEV_UUID: [u8; 16] = *b"TRILLBY_0001\0\0\0\0";
const DEV_PSK: [u8; 32] = [0x42; 32];

#[derive(Clone, Copy)]
struct Device {
    uuid: [u8; 16],
    psk: [u8; 32],
}

type Registry = heapless::Vec<Device, MAX_DEVICES>;

fn usage() -> ! {
    eprintln!(
        "Usage: trillby-server [OPTIONS]\n\
         \x20 --bind <ipv4>       Listen address (default: 0.0.0.0)\n\
         \x20 --port <port>       Listen port (default: 8088)\n\
         \x20 --registry <path>   Device registry: '<uuid_hex>\\t<psk_hex>[\\t...]' per line\n\
         \x20 --dev               Also accept the client's built-in dev credentials"
    );
    std::process::exit(2);
}

fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.as_bytes();
    if s.len() != N * 2 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(s[i * 2])? << 4) | nib(s[i * 2 + 1])?;
    }
    Some(out)
}

fn load_registry(path: &str, reg: &mut Registry) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut cols = line.split_whitespace();
        let (Some(uuid), Some(psk)) = (
            cols.next().and_then(parse_hex::<16>),
            cols.next().and_then(parse_hex::<32>),
        ) else {
            return Err(format!("{path}:{}: malformed entry", lineno + 1));
        };
        reg.push(Device { uuid, psk })
            .map_err(|_| format!("{path}: more than {MAX_DEVICES} devices"))?;
    }
    Ok(())
}

/// Writes `[unix_secs.millis] ` without allocating.
fn ts(out: &mut impl Write) -> std::io::Result<()> {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    write!(out, "[{}.{:03}] ", d.as_secs(), d.subsec_millis())
}

fn hex(out: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    for b in bytes {
        write!(out, "{b:02x}")?;
    }
    Ok(())
}

/// Printable ASCII is shown quoted (with escapes), anything else as hex.
fn bytes(out: &mut impl Write, b: &[u8]) -> std::io::Result<()> {
    if b.iter().all(|&c| (0x20..0x7f).contains(&c)) {
        write!(out, "\"{}\"", b.escape_ascii())
    } else {
        out.write_all(b"0x")?;
        hex(out, b)
    }
}

fn log_event(
    out: &mut impl Write,
    ev: &ServerEvent,
    uuids: &mut [Option<[u8; 16]>; MAX_CLIENTS],
) -> std::io::Result<()> {
    ts(out)?;
    match *ev {
        ServerEvent::Connected { client_idx, device_uuid, session_id } => {
            uuids[client_idx] = Some(device_uuid);
            write!(out, "CONNECT    client={client_idx} uuid=")?;
            hex(out, &device_uuid)?;
            write!(out, " session={session_id}")?;
        }
        ServerEvent::Disconnected { client_idx } => {
            write!(out, "DISCONNECT client={client_idx}")?;
            // Connections that never finished the handshake have no UUID.
            if let Some(u) = uuids[client_idx].take() {
                out.write_all(b" uuid=")?;
                hex(out, &u)?;
            }
        }
        ServerEvent::Data { client_idx, msg_type, payload } => match msg_type {
            MsgType::AuthInit => {
                write!(out, "AUTH       client={client_idx} ")?;
                match AuthInitPayload::decode(payload) {
                    Ok(a) => {
                        let n = (a.auth_data_len as usize).min(a.auth_data.len());
                        out.write_all(b"badge=")?;
                        bytes(out, &a.auth_data[..n])?;
                        write!(out, " device_ts_ms={}", a.timestamp_ms)?;
                    }
                    Err(_) => {
                        out.write_all(b"malformed=")?;
                        bytes(out, payload)?;
                    }
                }
            }
            MsgType::Heartbeat => {
                write!(out, "HEARTBEAT  client={client_idx} ")?;
                match HeartbeatPayload::decode(payload) {
                    Ok(h) => write!(
                        out,
                        "battery={}% rssi={}dBm pending={} uptime={}s",
                        h.battery_pct, h.rssi, h.pending_outbox, h.uptime_s
                    )?,
                    Err(_) => {
                        out.write_all(b"malformed=")?;
                        bytes(out, payload)?;
                    }
                }
            }
            MsgType::Data if payload.len() == WorkEventPayload::LEN => {
                match WorkEventPayload::decode(payload) {
                    Ok(w) => {
                        let op_len = (w.operator_id_len as usize).min(w.operator_id.len());
                        let job_len = (w.job_id_len as usize).min(w.job_id.len());
                        let op = &w.operator_id[..op_len];
                        let job = &w.job_id[..job_len];
                        match w.kind {
                            WorkEventKind::WorkStart => {
                                write!(out, "WORK_START client={client_idx} operator=")?;
                                bytes(out, op)?;
                                out.write_all(b" job=")?;
                                bytes(out, job)?;
                                write!(out, " device_ts_ms={}", w.timestamp_ms)?;
                            }
                            WorkEventKind::WorkStop => {
                                write!(out, "WORK_STOP  client={client_idx} operator=")?;
                                bytes(out, op)?;
                                out.write_all(b" job=")?;
                                bytes(out, job)?;
                                write!(
                                    out,
                                    " duration_ms={} device_ts_ms={}",
                                    w.duration_ms, w.timestamp_ms
                                )?;
                            }
                            WorkEventKind::OperatorLogout => {
                                write!(out, "LOGOUT     client={client_idx} operator=")?;
                                bytes(out, op)?;
                                write!(out, " device_ts_ms={}", w.timestamp_ms)?;
                            }
                        }
                    }
                    Err(_) => {
                        write!(out, "DATA       client={client_idx} type={msg_type:?} len={} ", payload.len())?;
                        bytes(out, payload)?;
                    }
                }
            }
            _ => {
                write!(out, "DATA       client={client_idx} type={msg_type:?} len={} ", payload.len())?;
                bytes(out, payload)?;
            }
        },
    }
    out.write_all(b"\n")
}

fn main() {
    let mut ip = Ipv4Addr::UNSPECIFIED;
    let mut port: u16 = 8088;
    let mut registry_path: Option<String> = None;
    let mut dev = false;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--bind" => ip = args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage()),
            "--port" => port = args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage()),
            "--registry" => registry_path = Some(args.next().unwrap_or_else(|| usage())),
            "--dev" => dev = true,
            _ => usage(),
        }
    }

    let mut registry = Registry::new();
    if let Some(p) = &registry_path {
        if let Err(e) = load_registry(p, &mut registry) {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
    if dev && registry.push(Device { uuid: DEV_UUID, psk: DEV_PSK }).is_err() {
        eprintln!("error: registry full, cannot add dev device");
        std::process::exit(1);
    }
    if registry.is_empty() {
        eprintln!("error: no devices known; pass --registry <path> and/or --dev");
        std::process::exit(1);
    }

    // NetServer is ~MAX_CLIENTS * 600 B; box it so a large MAX_CLIENTS can't blow the stack.
    let mut server: Box<NetServer<MAX_CLIENTS>> = match NetServer::bind(ip.octets(), port) {
        Ok(s) => Box::new(s),
        Err(errno) => {
            eprintln!("error: bind {ip}:{port} failed (errno {errno})");
            std::process::exit(1);
        }
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = ts(&mut out).and_then(|_| {
        writeln!(out, "LISTEN     addr={ip}:{} devices={}", server.port(), registry.len())
    });
    let _ = out.flush();

    let resolver = |uuid: &[u8; 16]| registry.iter().find(|d| d.uuid == *uuid).map(|d| d.psk);
    let mut uuids: [Option<[u8; 16]>; MAX_CLIENTS] = [None; MAX_CLIENTS];

    // Blocking poll() over listener + clients, then hand revents to NetServer.
    // (NetServer::step() polls with a 0 ms timeout, which would busy-spin a core.)
    let mut pfds = [libc::pollfd { fd: -1, events: 0, revents: 0 }; MAX_CLIENTS + 1];
    let mut client_revents = [0i16; MAX_CLIENTS];
    loop {
        pfds[0] = libc::pollfd { fd: server.listener_fd(), events: libc::POLLIN, revents: 0 };
        for i in 0..MAX_CLIENTS {
            // Negative fds are ignored by poll(), so empty slots need no special casing.
            let fd = server.client_socket_fd(i).unwrap_or(-1);
            pfds[i + 1] = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        }

        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, POLL_TIMEOUT_MS) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("error: poll: {err}");
            std::process::exit(1);
        }
        if rc == 0 {
            continue;
        }

        for i in 0..MAX_CLIENTS {
            client_revents[i] = pfds[i + 1].revents;
        }
        server.poll_step_with(
            trillby_net::monotonic_ms(),
            pfds[0].revents,
            &client_revents,
            resolver,
            |ev| {
                let _ = log_event(&mut out, &ev, &mut uuids);
            },
        );
        let _ = out.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_valid_and_invalid_inputs() {
        let hex_16_lower = "000102030405060708090a0b0c0d0e0f";
        let expected_16 = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        assert_eq!(parse_hex::<16>(hex_16_lower), Some(expected_16));

        let hex_32_lower = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let mut expected_32 = [0u8; 32];
        expected_32[..16].copy_from_slice(&expected_16);
        for i in 0..16 {
            expected_32[16 + i] = 0x10 + i as u8;
        }
        assert_eq!(parse_hex::<32>(hex_32_lower), Some(expected_32));

        let hex_16_upper = "000102030405060708090A0B0C0D0E0F";
        assert_eq!(parse_hex::<16>(hex_16_upper), Some(expected_16));
        let hex_32_upper = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        assert_eq!(parse_hex::<32>(hex_32_upper), Some(expected_32));

        let hex_16_mixed = "000102030405060708090a0B0c0D0e0F";
        assert_eq!(parse_hex::<16>(hex_16_mixed), Some(expected_16));

        assert_eq!(parse_hex::<16>("012"), None);
        assert_eq!(parse_hex::<16>("000102030405060708090a0b0c0d0e0"), None);
        assert_eq!(parse_hex::<16>("000102030405060708090a0b0c0d0e"), None);
        assert_eq!(parse_hex::<16>("000102030405060708090a0b0c0d0e0f00"), None);
        assert_eq!(parse_hex::<32>(hex_16_lower), None);

        assert_eq!(parse_hex::<16>("000102030405060708090a0b0c0d0e0g"), None);
        assert_eq!(parse_hex::<16>("000102030405060708090a0b0c0d0e0G"), None);
        assert_eq!(parse_hex::<16>("000102030405060708090a0b0c0d0e0/"), None);
        assert_eq!(parse_hex::<16>("000102030405060708090a0b0c0d0e0:"), None);
    }

    #[test]
    fn test_load_registry_parsing_comments_malformed_line_and_max_devices() {
        let pid = std::process::id();

        struct TempFile(String);
        impl Drop for TempFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }

        let path_a = format!("/tmp/trillby_test_reg_a_{}.tsv", pid);
        let _guard_a = TempFile(path_a.clone());
        let valid_uuid = "000102030405060708090a0b0c0d0e0f";
        let valid_psk = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let content_a = format!(
            "# Device registry comment\n\
             \n\
               # Indented comment\n\
             {valid_uuid}\t{valid_psk}\textra_col1\textra_col2\n\
             101112131415161718191a1b1c1d1e1f {valid_psk}\n"
        );
        std::fs::write(&path_a, content_a).expect("write temp registry a");
        let mut reg_a = Registry::new();
        assert!(load_registry(&path_a, &mut reg_a).is_ok());
        assert_eq!(reg_a.len(), 2);
        assert_eq!(reg_a[0].uuid, parse_hex::<16>(valid_uuid).unwrap());

        let path_b = format!("/tmp/trillby_test_reg_b_{}.tsv", pid);
        let _guard_b = TempFile(path_b.clone());
        let content_b = format!(
            "{valid_uuid}\t{valid_psk}\n\
             \n\
             bad_uuid_hex\t{valid_psk}\n"
        );
        std::fs::write(&path_b, content_b).expect("write temp registry b");
        let mut reg_b = Registry::new();
        let err_b = load_registry(&path_b, &mut reg_b).unwrap_err();
        assert!(
            err_b.contains(":3: malformed entry"),
            "expected ':3: malformed entry', got: {err_b}"
        );

        let path_c = format!("/tmp/trillby_test_reg_c_{}.tsv", pid);
        let _guard_c = TempFile(path_c.clone());
        let mut content_c = String::new();
        for i in 0..=MAX_DEVICES {
            let uuid = format!("{:032x}", i);
            content_c.push_str(&format!("{uuid}\t{valid_psk}\n"));
        }
        std::fs::write(&path_c, content_c).expect("write temp registry c");
        let mut reg_c = Registry::new();
        let err_c = load_registry(&path_c, &mut reg_c).unwrap_err();
        assert!(
            err_c.contains("more than 256 devices"),
            "expected 'more than 256 devices', got: {err_c}"
        );

        let path_d = format!("/tmp/trillby_test_reg_missing_{}.tsv", pid);
        let mut reg_d = Registry::new();
        let err_d = load_registry(&path_d, &mut reg_d).unwrap_err();
        assert!(err_d.contains(&path_d));
    }

    #[test]
    fn test_bytes_formatting_and_log_event_all_branches() {
        let mut out = Vec::new();
        bytes(&mut out, b"A\"B").unwrap();
        assert_eq!(core::str::from_utf8(&out).unwrap(), "\"A\\\"B\"");

        out.clear();
        bytes(&mut out, &[0x00, 0x1f, 0x7f, 0xff]).unwrap();
        assert_eq!(core::str::from_utf8(&out).unwrap(), "0x001f7fff");

        let mut uuids: [Option<[u8; 16]>; MAX_CLIENTS] = [None; MAX_CLIENTS];

        out.clear();
        let dev_uuid = [0x42; 16];
        log_event(
            &mut out,
            &ServerEvent::Connected {
                client_idx: 0,
                device_uuid: dev_uuid,
                session_id: 100,
            },
            &mut uuids,
        )
        .unwrap();
        assert_eq!(uuids[0], Some(dev_uuid));
        let s = core::str::from_utf8(&out).unwrap();
        assert!(
            s.contains("CONNECT    client=0 uuid=42424242424242424242424242424242 session=100\n"),
            "got: {s}"
        );

        out.clear();
        log_event(
            &mut out,
            &ServerEvent::Disconnected { client_idx: 0 },
            &mut uuids,
        )
        .unwrap();
        assert_eq!(uuids[0], None);
        let s = core::str::from_utf8(&out).unwrap();
        assert!(
            s.contains("DISCONNECT client=0 uuid=42424242424242424242424242424242\n"),
            "got: {s}"
        );

        out.clear();
        log_event(
            &mut out,
            &ServerEvent::Disconnected { client_idx: 1 },
            &mut uuids,
        )
        .unwrap();
        let s = core::str::from_utf8(&out).unwrap();
        assert!(s.contains("DISCONNECT client=1\n"), "got: {s}");
        assert!(!s.contains("uuid="), "must not have uuid=: {s}");

        out.clear();
        let mut auth_init = AuthInitPayload {
            auth_data_len: 4,
            auth_data: [0u8; 32],
            timestamp_ms: 12345,
        };
        auth_init.auth_data[..4].copy_from_slice(b"OP01");
        let mut auth_buf = [0u8; AuthInitPayload::LEN];
        auth_init.encode(&mut auth_buf).unwrap();
        log_event(
            &mut out,
            &ServerEvent::Data {
                client_idx: 0,
                msg_type: MsgType::AuthInit,
                payload: &auth_buf,
            },
            &mut uuids,
        )
        .unwrap();
        let s = core::str::from_utf8(&out).unwrap();
        assert!(s.contains("AUTH       client=0 badge=\"OP01\" device_ts_ms=12345\n"), "got: {s}");

        out.clear();
        log_event(
            &mut out,
            &ServerEvent::Data {
                client_idx: 0,
                msg_type: MsgType::AuthInit,
                payload: b"bad",
            },
            &mut uuids,
        )
        .unwrap();
        let s = core::str::from_utf8(&out).unwrap();
        assert!(s.contains("AUTH       client=0 malformed=\"bad\"\n"), "got: {s}");

        out.clear();
        let hb = HeartbeatPayload {
            battery_pct: 88,
            rssi: -55,
            pending_outbox: 3,
            uptime_s: 720,
        };
        let mut hb_buf = [0u8; HeartbeatPayload::LEN];
        hb.encode(&mut hb_buf).unwrap();
        log_event(
            &mut out,
            &ServerEvent::Data {
                client_idx: 0,
                msg_type: MsgType::Heartbeat,
                payload: &hb_buf,
            },
            &mut uuids,
        )
        .unwrap();
        let s = core::str::from_utf8(&out).unwrap();
        assert!(
            s.contains("HEARTBEAT  client=0 battery=88% rssi=-55dBm pending=3 uptime=720s\n"),
            "got: {s}"
        );

        out.clear();
        log_event(
            &mut out,
            &ServerEvent::Data {
                client_idx: 0,
                msg_type: MsgType::Heartbeat,
                payload: b"short",
            },
            &mut uuids,
        )
        .unwrap();
        let s = core::str::from_utf8(&out).unwrap();
        assert!(s.contains("HEARTBEAT  client=0 malformed=\"short\"\n"), "got: {s}");

        out.clear();
        let ws = WorkEventPayload::work_start(b"OP_A", b"JOB_X", 5000);
        let mut ws_buf = [0u8; WorkEventPayload::LEN];
        ws.encode(&mut ws_buf).unwrap();
        log_event(
            &mut out,
            &ServerEvent::Data {
                client_idx: 0,
                msg_type: MsgType::Data,
                payload: &ws_buf,
            },
            &mut uuids,
        )
        .unwrap();
        let s = core::str::from_utf8(&out).unwrap();
        assert!(
            s.contains("WORK_START client=0 operator=\"OP_A\" job=\"JOB_X\" device_ts_ms=5000\n"),
            "got: {s}"
        );

        out.clear();
        let wsp = WorkEventPayload::work_stop(b"OP_A", b"JOB_X", 1500, 6500);
        let mut wsp_buf = [0u8; WorkEventPayload::LEN];
        wsp.encode(&mut wsp_buf).unwrap();
        log_event(
            &mut out,
            &ServerEvent::Data {
                client_idx: 0,
                msg_type: MsgType::Data,
                payload: &wsp_buf,
            },
            &mut uuids,
        )
        .unwrap();
        let s = core::str::from_utf8(&out).unwrap();
        assert!(
            s.contains("WORK_STOP  client=0 operator=\"OP_A\" job=\"JOB_X\" duration_ms=6500 device_ts_ms=1500\n"),
            "got: {s}"
        );

        out.clear();
        let lo = WorkEventPayload::operator_logout(b"OP_A", 7000);
        let mut lo_buf = [0u8; WorkEventPayload::LEN];
        lo.encode(&mut lo_buf).unwrap();
        log_event(
            &mut out,
            &ServerEvent::Data {
                client_idx: 0,
                msg_type: MsgType::Data,
                payload: &lo_buf,
            },
            &mut uuids,
        )
        .unwrap();
        let s = core::str::from_utf8(&out).unwrap();
        assert!(
            s.contains("LOGOUT     client=0 operator=\"OP_A\" device_ts_ms=7000\n"),
            "got: {s}"
        );

        out.clear();
        let mut inv_work_buf = [0u8; WorkEventPayload::LEN];
        inv_work_buf[0] = 0xff;
        log_event(
            &mut out,
            &ServerEvent::Data {
                client_idx: 0,
                msg_type: MsgType::Data,
                payload: &inv_work_buf,
            },
            &mut uuids,
        )
        .unwrap();
        let s = core::str::from_utf8(&out).unwrap();
        assert!(
            s.contains("DATA       client=0 type=Data len=115 0xff"),
            "got: {s}"
        );

        out.clear();
        log_event(
            &mut out,
            &ServerEvent::Data {
                client_idx: 0,
                msg_type: MsgType::Data,
                payload: b"RAW_CMD",
            },
            &mut uuids,
        )
        .unwrap();
        let s = core::str::from_utf8(&out).unwrap();
        assert!(
            s.contains("DATA       client=0 type=Data len=7 \"RAW_CMD\"\n"),
            "got: {s}"
        );
    }
}
