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
    WorkEventPayload, DEFAULT_SERVER_PORT, DEV_DEVICE_UUID, DEV_PSK,
};

const MAX_CLIENTS: usize = 32;
const MAX_DEVICES: usize = 256;
/// poll() timeout. Only bounds idle wakeups; data is handled as soon as it arrives.
const POLL_TIMEOUT_MS: libc::c_int = 1000;

/// Fallback credentials hard-coded in `crates/trillby/src/main.rs` when no
/// `/etc/trillby/device.key` exists. Enabled with `--dev`.
const DEV_UUID: [u8; 16] = DEV_DEVICE_UUID;

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
         \x20 --port <port>       Listen port (default: {DEFAULT_SERVER_PORT})\n\
         \x20 --registry <path>   Device registry: '<uuid_hex>\\t<psk_hex>[\\t...]' per line\n\
         \x20 --dev               Also accept the client's built-in dev credentials"
    );
    std::process::exit(2);
}

fn load_registry(path: &str, reg: &mut Registry) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    for (lineno, line) in text.lines().enumerate() {
        let (uuid, psk) = match trillby_net::parse_registry_line(line) {
            Ok(Some((uuid, psk))) => (uuid, psk),
            Ok(None) => continue,
            Err(_) => return Err(format!("{path}:{}: malformed entry", lineno + 1)),
        };
        if reg.iter().any(|d| d.uuid == uuid) {
            return Err(format!("{path}:{}: duplicate uuid", lineno + 1));
        }
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
    if b.iter().all(|&c| c == b' ' || c.is_ascii_graphic()) {
        write!(out, "\"{}\"", b.escape_ascii())
    } else {
        out.write_all(b"0x")?;
        hex(out, b)
    }
}
const LABEL_WIDTH: usize = 10;

fn tag(out: &mut impl Write, label: &str, client_idx: usize) -> std::io::Result<()> {
    write!(out, "{label:<LABEL_WIDTH$} client={client_idx}")
}

fn log_malformed(out: &mut impl Write, payload: &[u8]) -> std::io::Result<()> {
    out.write_all(b"malformed=")?;
    bytes(out, payload)
}

fn log_raw(
    out: &mut impl Write,
    client_idx: usize,
    msg_type: MsgType,
    payload: &[u8],
) -> std::io::Result<()> {
    tag(out, "DATA", client_idx)?;
    write!(out, " type={msg_type:?} len={} ", payload.len())?;
    bytes(out, payload)
}

fn log_data(
    out: &mut impl Write,
    client_idx: usize,
    msg_type: MsgType,
    payload: &[u8],
) -> std::io::Result<()> {
    match msg_type {
        MsgType::AuthInit => {
            tag(out, "AUTH", client_idx)?;
            out.write_all(b" ")?;
            match AuthInitPayload::decode(payload) {
                Ok(a) => {
                    out.write_all(b"badge=")?;
                    bytes(out, a.auth_data_bytes())?;
                    write!(out, " device_ts_ms={}", a.timestamp_ms)
                }
                Err(_) => log_malformed(out, payload),
            }
        }
        MsgType::Heartbeat => {
            tag(out, "HEARTBEAT", client_idx)?;
            out.write_all(b" ")?;
            match HeartbeatPayload::decode(payload) {
                Ok(h) => write!(
                    out,
                    "battery={}% rssi={}dBm pending={} uptime={}s",
                    h.battery_pct, h.rssi, h.pending_outbox, h.uptime_s
                ),
                Err(_) => log_malformed(out, payload),
            }
        }
        MsgType::Data => match WorkEventPayload::decode(payload) {
            Ok(w) => {
                let op = w.operator_id_bytes();
                let job = w.job_id_bytes();
                match w.kind {
                    WorkEventKind::WorkStart => {
                        tag(out, "WORK_START", client_idx)?;
                        write!(out, " operator=")?;
                        bytes(out, op)?;
                        out.write_all(b" job=")?;
                        bytes(out, job)?;
                        write!(out, " device_ts_ms={}", w.timestamp_ms)
                    }
                    WorkEventKind::WorkStop => {
                        tag(out, "WORK_STOP", client_idx)?;
                        write!(out, " operator=")?;
                        bytes(out, op)?;
                        out.write_all(b" job=")?;
                        bytes(out, job)?;
                        write!(
                            out,
                            " duration_ms={} device_ts_ms={}",
                            w.duration_ms, w.timestamp_ms
                        )
                    }
                    WorkEventKind::OperatorLogout => {
                        tag(out, "LOGOUT", client_idx)?;
                        write!(out, " operator=")?;
                        bytes(out, op)?;
                        write!(out, " device_ts_ms={}", w.timestamp_ms)
                    }
                }
            }
            Err(_) => log_raw(out, client_idx, msg_type, payload),
        },
        _ => log_raw(out, client_idx, msg_type, payload),
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
            tag(out, "CONNECT", client_idx)?;
            write!(out, " uuid=")?;
            hex(out, &device_uuid)?;
            write!(out, " session={session_id}")?;
        }
        ServerEvent::Disconnected { client_idx } => {
            tag(out, "DISCONNECT", client_idx)?;
            // Connections that never finished the handshake have no UUID.
            if let Some(u) = uuids[client_idx].take() {
                out.write_all(b" uuid=")?;
                hex(out, &u)?;
            }
        }
        ServerEvent::Data { client_idx, msg_type, payload } => {
            log_data(out, client_idx, msg_type, payload)?;
        }
    }
    out.write_all(b"\n")
}

struct Args {
    ip: Ipv4Addr,
    port: u16,
    registry_path: Option<String>,
    dev: bool,
}

fn parse_args() -> Args {
    let mut ip = Ipv4Addr::UNSPECIFIED;
    let mut port: u16 = DEFAULT_SERVER_PORT;
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

    Args {
        ip,
        port,
        registry_path,
        dev,
    }
}

fn build_registry(args: &Args) -> Result<Registry, String> {
    let mut registry = Registry::new();
    if let Some(p) = &args.registry_path {
        load_registry(p, &mut registry)?;
    }
    if args.dev && registry.iter().any(|d| d.uuid == DEV_UUID) {
        return Err("--dev uuid is already in the registry".into());
    }
    if args.dev && registry.push(Device { uuid: DEV_UUID, psk: DEV_PSK }).is_err() {
        return Err("registry full, cannot add dev device".into());
    }
    if registry.is_empty() {
        return Err("no devices known; pass --registry <path> and/or --dev".into());
    }
    Ok(registry)
}

fn run(args: Args, registry: Registry) -> Result<(), String> {
    // NetServer is ~MAX_CLIENTS * 600 B; box it so a large MAX_CLIENTS can't blow the stack.
    let mut server: Box<NetServer<MAX_CLIENTS>> = match NetServer::bind(args.ip.octets(), args.port) {
        Ok(s) => Box::new(s),
        Err(errno) => {
            return Err(format!("bind {}:{} failed (errno {errno})", args.ip, args.port));
        }
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = ts(&mut out)
        .and_then(|_| writeln!(out, "{:<LABEL_WIDTH$} addr={}:{} devices={}", "LISTEN", args.ip, server.port(), registry.len()))
        .and_then(|_| out.flush())
    {
        return Err(format!("stdout: {e}"));
    }

    let resolver = |uuid: &[u8; 16]| registry.iter().find(|d| d.uuid == *uuid).map(|d| d.psk);
    let mut uuids: [Option<[u8; 16]>; MAX_CLIENTS] = [None; MAX_CLIENTS];

    let mut log_err: Option<std::io::Error> = None;
    loop {
        if let Err(errno) = server.step_timeout(
            trillby_net::monotonic_ms(),
            POLL_TIMEOUT_MS,
            resolver,
            |ev| {
                if log_err.is_none() {
                    if let Err(e) = log_event(&mut out, &ev, &mut uuids) {
                        log_err = Some(e);
                    }
                }
            },
        ) {
            return Err(format!("poll: errno {errno}"));
        }
        let res = match log_err.take() {
            Some(e) => Err(e),
            None => out.flush(),
        };
        if let Err(e) = res {
            return Err(format!("stdout: {e}"));
        }
    }
}

fn main() {
    let args = parse_args();
    let registry = match build_registry(&args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = run(args, registry) {
        eprintln!("error: {e}");
        std::process::exit(1);
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
        assert_eq!(trillby_net::decode_hex::<16>(hex_16_lower), Some(expected_16));

        let hex_32_lower = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let mut expected_32 = [0u8; 32];
        expected_32[..16].copy_from_slice(&expected_16);
        for i in 0..16 {
            expected_32[16 + i] = 0x10 + i as u8;
        }
        assert_eq!(trillby_net::decode_hex::<32>(hex_32_lower), Some(expected_32));

        let hex_16_upper = "000102030405060708090A0B0C0D0E0F";
        assert_eq!(trillby_net::decode_hex::<16>(hex_16_upper), Some(expected_16));
        let hex_32_upper = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        assert_eq!(trillby_net::decode_hex::<32>(hex_32_upper), Some(expected_32));

        let hex_16_mixed = "000102030405060708090a0B0c0D0e0F";
        assert_eq!(trillby_net::decode_hex::<16>(hex_16_mixed), Some(expected_16));

        assert_eq!(trillby_net::decode_hex::<16>("012"), None);
        assert_eq!(trillby_net::decode_hex::<16>("000102030405060708090a0b0c0d0e0"), None);
        assert_eq!(trillby_net::decode_hex::<16>("000102030405060708090a0b0c0d0e"), None);
        assert_eq!(trillby_net::decode_hex::<16>("000102030405060708090a0b0c0d0e0f00"), None);
        assert_eq!(trillby_net::decode_hex::<32>(hex_16_lower), None);

        assert_eq!(trillby_net::decode_hex::<16>("000102030405060708090a0b0c0d0e0g"), None);
        assert_eq!(trillby_net::decode_hex::<16>("000102030405060708090a0b0c0d0e0G"), None);
        assert_eq!(trillby_net::decode_hex::<16>("000102030405060708090a0b0c0d0e0/"), None);
        assert_eq!(trillby_net::decode_hex::<16>("000102030405060708090a0b0c0d0e0:"), None);
    }

    fn write_registry(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().expect("create temp registry");
        file.write_all(content.as_bytes()).expect("write temp registry");
        file.flush().expect("flush temp registry");
        file
    }

    #[test]
    fn test_load_registry_parsing_comments_malformed_line_and_max_devices() {
        let valid_uuid = "000102030405060708090a0b0c0d0e0f";
        let valid_psk = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let content_a = format!(
            "# Device registry comment\n\
             \n\
               # Indented comment\n\
             {valid_uuid}\t{valid_psk}\textra_col1\textra_col2\n\
             101112131415161718191a1b1c1d1e1f {valid_psk}\n"
        );
        let file_a = write_registry(&content_a);
        let path_a = file_a.path().to_str().unwrap();
        let mut reg_a = Registry::new();
        assert!(load_registry(path_a, &mut reg_a).is_ok());
        assert_eq!(reg_a.len(), 2);
        assert_eq!(reg_a[0].uuid, trillby_net::decode_hex::<16>(valid_uuid).unwrap());

        let content_b = format!(
            "{valid_uuid}\t{valid_psk}\n\
             \n\
             bad_uuid_hex\t{valid_psk}\n"
        );
        let file_b = write_registry(&content_b);
        let path_b = file_b.path().to_str().unwrap();
        let mut reg_b = Registry::new();
        let err_b = load_registry(path_b, &mut reg_b).unwrap_err();
        assert!(
            err_b.contains(":3: malformed entry"),
            "expected ':3: malformed entry', got: {err_b}"
        );

        let mut content_c = String::new();
        for i in 0..=MAX_DEVICES {
            let uuid = format!("{:032x}", i);
            content_c.push_str(&format!("{uuid}\t{valid_psk}\n"));
        }
        let file_c = write_registry(&content_c);
        let path_c = file_c.path().to_str().unwrap();
        let mut reg_c = Registry::new();
        let err_c = load_registry(path_c, &mut reg_c).unwrap_err();
        assert!(
            err_c.contains("more than 256 devices"),
            "expected 'more than 256 devices', got: {err_c}"
        );

        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path_d = temp_dir.path().join("missing.tsv");
        let path_d_str = path_d.to_str().unwrap();
        let mut reg_d = Registry::new();
        let err_d = load_registry(path_d_str, &mut reg_d).unwrap_err();
        assert!(err_d.contains(path_d_str));
    }

    #[test]
    fn test_load_registry_rejects_duplicate_uuid() {
        let valid_uuid = "000102030405060708090a0b0c0d0e0f";
        let valid_psk = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let content = format!(
            "{valid_uuid}\t{valid_psk}\n\
             # comment on line 2\n\
             {valid_uuid}\t{valid_psk}\n"
        );
        let file = write_registry(&content);
        let path = file.path().to_str().unwrap();
        let mut reg = Registry::new();
        let err = load_registry(path, &mut reg).unwrap_err();
        assert!(
            err.contains(":3: duplicate uuid"),
            "expected ':3: duplicate uuid', got: {err}"
        );
    }
    #[test]
    fn test_build_registry() {
        let args_empty = Args {
            ip: Ipv4Addr::LOCALHOST,
            port: 8088,
            registry_path: None,
            dev: false,
        };
        match build_registry(&args_empty) {
            Err(err) => assert!(err.contains("no devices known")),
            Ok(_) => panic!("expected err"),
        }

        let args_dev = Args {
            ip: Ipv4Addr::LOCALHOST,
            port: 8088,
            registry_path: None,
            dev: true,
        };
        let reg = match build_registry(&args_dev) {
            Ok(r) => r,
            Err(e) => panic!("unexpected err: {e}"),
        };
        assert_eq!(reg.len(), 1);
        assert_eq!(reg[0].uuid, DEV_UUID);
        assert_eq!(reg[0].psk, DEV_PSK);
    }

    fn logged(ev: &ServerEvent, uuids: &mut [Option<[u8; 16]>; MAX_CLIENTS]) -> String {
        let mut out = Vec::new();
        log_event(&mut out, ev, uuids).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn logged_data(msg_type: MsgType, payload: &[u8]) -> String {
        let mut uuids = [None; MAX_CLIENTS];
        logged(&ServerEvent::Data { client_idx: 0, msg_type, payload }, &mut uuids)
    }

    #[test]
    fn bytes_formatting() {
        let mut out = Vec::new();
        bytes(&mut out, b"A\"B").unwrap();
        assert_eq!(core::str::from_utf8(&out).unwrap(), "\"A\\\"B\"");

        out.clear();
        bytes(&mut out, b" hello ~ ").unwrap();
        assert_eq!(core::str::from_utf8(&out).unwrap(), "\" hello ~ \"");

        out.clear();
        bytes(&mut out, &[0x00, 0x1f, 0x7f, 0xff]).unwrap();
        assert_eq!(core::str::from_utf8(&out).unwrap(), "0x001f7fff");
    }

    #[test]
    fn log_event_connect_and_disconnect() {
        let mut uuids: [Option<[u8; 16]>; MAX_CLIENTS] = [None; MAX_CLIENTS];

        let dev_uuid = [0x42; 16];
        let s = logged(
            &ServerEvent::Connected {
                client_idx: 0,
                device_uuid: dev_uuid,
                session_id: 100,
            },
            &mut uuids,
        );
        assert_eq!(uuids[0], Some(dev_uuid));
        assert!(
            s.contains("CONNECT    client=0 uuid=42424242424242424242424242424242 session=100\n"),
            "got: {s}"
        );

        let s = logged(
            &ServerEvent::Disconnected { client_idx: 0 },
            &mut uuids,
        );
        assert_eq!(uuids[0], None);
        assert!(
            s.contains("DISCONNECT client=0 uuid=42424242424242424242424242424242\n"),
            "got: {s}"
        );

        let s = logged(
            &ServerEvent::Disconnected { client_idx: 1 },
            &mut uuids,
        );
        assert!(s.contains("DISCONNECT client=1\n"), "got: {s}");
        assert!(!s.contains("uuid="), "must not have uuid=: {s}");
    }

    #[test]
    fn log_event_auth() {
        let mut auth_init = AuthInitPayload {
            auth_data_len: 4,
            auth_data: [0u8; 32],
            timestamp_ms: 12345,
        };
        auth_init.auth_data[..4].copy_from_slice(b"OP01");
        let mut auth_buf = [0u8; AuthInitPayload::LEN];
        auth_init.encode(&mut auth_buf).unwrap();
        let s = logged_data(MsgType::AuthInit, &auth_buf);
        assert!(s.contains("AUTH       client=0 badge=\"OP01\" device_ts_ms=12345\n"), "got: {s}");

        let s = logged_data(MsgType::AuthInit, b"bad");
        assert!(s.contains("AUTH       client=0 malformed=\"bad\"\n"), "got: {s}");
    }

    #[test]
    fn log_event_heartbeat() {
        let hb = HeartbeatPayload {
            battery_pct: 88,
            rssi: -55,
            pending_outbox: 3,
            uptime_s: 720,
        };
        let mut hb_buf = [0u8; HeartbeatPayload::LEN];
        hb.encode(&mut hb_buf).unwrap();
        let s = logged_data(MsgType::Heartbeat, &hb_buf);
        assert!(
            s.contains("HEARTBEAT  client=0 battery=88% rssi=-55dBm pending=3 uptime=720s\n"),
            "got: {s}"
        );

        let s = logged_data(MsgType::Heartbeat, b"short");
        assert!(s.contains("HEARTBEAT  client=0 malformed=\"short\"\n"), "got: {s}");
    }

    #[test]
    fn log_event_work_events() {
        let ws = WorkEventPayload::work_start(b"OP_A", b"JOB_X", 5000);
        let mut ws_buf = [0u8; WorkEventPayload::LEN];
        ws.encode(&mut ws_buf).unwrap();
        let s = logged_data(MsgType::Data, &ws_buf);
        assert!(
            s.contains("WORK_START client=0 operator=\"OP_A\" job=\"JOB_X\" device_ts_ms=5000\n"),
            "got: {s}"
        );

        let wsp = WorkEventPayload::work_stop(b"OP_A", b"JOB_X", 1500, 6500);
        let mut wsp_buf = [0u8; WorkEventPayload::LEN];
        wsp.encode(&mut wsp_buf).unwrap();
        let s = logged_data(MsgType::Data, &wsp_buf);
        assert!(
            s.contains("WORK_STOP  client=0 operator=\"OP_A\" job=\"JOB_X\" duration_ms=6500 device_ts_ms=1500\n"),
            "got: {s}"
        );

        let lo = WorkEventPayload::operator_logout(b"OP_A", 7000);
        let mut lo_buf = [0u8; WorkEventPayload::LEN];
        lo.encode(&mut lo_buf).unwrap();
        let s = logged_data(MsgType::Data, &lo_buf);
        assert!(
            s.contains("LOGOUT     client=0 operator=\"OP_A\" device_ts_ms=7000\n"),
            "got: {s}"
        );
    }

    #[test]
    fn log_event_raw_and_malformed_data() {
        let mut inv_work_buf = [0u8; WorkEventPayload::LEN];
        inv_work_buf[0] = 0xff;
        let s = logged_data(MsgType::Data, &inv_work_buf);
        assert!(
            s.contains("DATA       client=0 type=Data len=115 0xff"),
            "got: {s}"
        );

        let s = logged_data(MsgType::Data, b"RAW_CMD");
        assert!(
            s.contains("DATA       client=0 type=Data len=7 \"RAW_CMD\"\n"),
            "got: {s}"
        );
    }
}
