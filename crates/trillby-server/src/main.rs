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
