//! End-to-End Application & Connection Resilience Test Suite
//!
//! Spins up `trillby-server` and `NetServer` instances alongside a full simulated
//! device (`UiState` + `OperatorSession` + `UiRenderer` + `NetClient`) to verify
//! encrypted telemetry delivery across the complete operator lifecycle, mid-job
//! connection drops, offline boot queueing, and half-open `ACK_TIMEOUT_MS` recovery.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use embedded_graphics::pixelcolor::{Rgb565, RgbColor};
use embedded_graphics::prelude::{Point, Size};
use embedded_graphics::primitives::Rectangle;
use embedded_graphics_framebuf::FrameBuf;

use trillby_core::{NetworkStatus, SessionState, UiEvent, UiState};
use trillby_net::client::ACK_TIMEOUT_MS;
use trillby_net::{
    ClientState, HeartbeatPayload, MsgType, NetClient, NetServer, ServerEvent,
    WorkEventKind, WorkEventPayload,
};
use trillby_ui::{
    eg_rect_to_core, LayoutZones, ScreenPixels, UiRenderer, SCREEN_HEIGHT, SCREEN_WIDTH,
};

const DEV_UUID: [u8; 16] = trillby_net::DEV_DEVICE_UUID;
const DEV_PSK: [u8; 32] = trillby_net::DEV_PSK;
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
const LOG_WAIT: Duration = Duration::from_secs(3);

pub struct SimulatedDevice {
    pub psk: [u8; 32],
    pub device_uuid: [u8; 16],
    pub state: UiState<256>,
    pub renderer: UiRenderer,
    pub pixels: Box<ScreenPixels>,
    pub net_client: NetClient<32>,
    pub render_count: usize,
}

impl SimulatedDevice {
    pub fn new(psk: [u8; 32], uuid: [u8; 16], server_ip: [u8; 4], server_port: u16) -> Self {
        let screen_bounds = Rectangle::new(Point::zero(), Size::new(SCREEN_WIDTH, SCREEN_HEIGHT));
        let mut state = UiState::new();
        let renderer = UiRenderer::new(screen_bounds);
        let mut pixels: Box<ScreenPixels> =
            vec![Rgb565::BLACK; trillby_ui::SCREEN_PIXELS]
                .into_boxed_slice()
                .try_into()
                .unwrap();

        {
            let mut fb = FrameBuf::new(&mut *pixels, SCREEN_WIDTH as usize, SCREEN_HEIGHT as usize);
            renderer.render(&mut fb, &state).expect("initial render");
        }
        state.dirty = false;

        Self {
            psk,
            device_uuid: uuid,
            state,
            renderer,
            pixels,
            net_client: NetClient::new(psk, uuid, server_ip, server_port),
            render_count: 1,
        }
    }
    fn render_if_dirty(&mut self) {
        if self.state.dirty {
            let mut fb = FrameBuf::new(&mut *self.pixels, SCREEN_WIDTH as usize, SCREEN_HEIGHT as usize);
            self.renderer
                .render(&mut fb, &self.state)
                .expect("dirty render");
            self.state.dirty = false;
            self.render_count += 1;
        }
    }

    pub fn advance_clock(&mut self, now_ms: u64) {
        self.state.set_now_ms(now_ms);
        self.render_if_dirty();
    }

    pub fn network_status(&self) -> NetworkStatus {
        self.state.network_status
    }


    pub fn handle_ui_event(&mut self, event: UiEvent, now_ms: u64) {
        let screen_bounds = Rectangle::new(Point::zero(), Size::new(SCREEN_WIDTH, SCREEN_HEIGHT));
        let zones = LayoutZones::compute(screen_bounds, self.state.keyboard_visible);
        self.state.set_now_ms(now_ms);
        match event {
            UiEvent::TouchDown { .. } | UiEvent::TouchUp { .. } | UiEvent::TouchMove { .. } => {
                trillby_ui::dispatch_touch(&mut self.state, &zones, event);
            }
            _ => {
                let core_kb_bounds = zones.keyboard_area.map(eg_rect_to_core);
                self.state.handle_event(event, core_kb_bounds, None);
            }
        }
        while let Some(ev) = self.state.pop_session_event() {
            self.net_client.send_session_event(&ev, now_ms).expect("enqueue session event");
        }

        self.state.pending_outbox_count = self.net_client.outbox_pending_count() as u16;

        self.render_if_dirty();
    }

    pub fn step_net(&mut self, now_ms: u64) {
        if let Some(status) = self.net_client.wait_and_step_with(now_ms, 10, |_, _| {}) {
            self.handle_ui_event(UiEvent::NetworkStatusChanged(status), now_ms);
        }
        self.state.pending_outbox_count = self.net_client.outbox_pending_count() as u16;
    }
}

pub struct ServerProcess {
    child: Option<Child>,
    lines: Arc<Mutex<Vec<String>>>,
}

impl ServerProcess {
    pub fn spawn_args(args: &[&str]) -> Self {
        let bin = env!("CARGO_BIN_EXE_trillby-server");
        let mut child = Command::new(bin)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn trillby-server");

        let stdout = child.stdout.take().expect("stdout piped");
        let lines = Arc::new(Mutex::new(Vec::new()));
        let lines_clone = Arc::clone(&lines);

        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                lines_clone.lock().unwrap().push(line);
            }
        });

        Self {
            child: Some(child),
            lines,
        }
    }

    pub fn spawn(port: u16) -> Self {
        let port_str = port.to_string();
        let bind_ip = std::net::Ipv4Addr::from(LOOPBACK).to_string();
        Self::spawn_args(&["--dev", "--bind", &bind_ip, "--port", &port_str])
    }

    pub fn spawn_with_registry(port: u16, registry_path: &str) -> Self {
        let port_str = port.to_string();
        let bind_ip = std::net::Ipv4Addr::from(LOOPBACK).to_string();
        Self::spawn_args(&["--bind", &bind_ip, "--port", &port_str, "--registry", registry_path])
    }

    pub fn try_wait_for_listen(&self, timeout: Duration) -> Option<u16> {
        let deadline = Instant::now() + timeout;
        let prefix = format!("LISTEN     addr={}:", std::net::Ipv4Addr::from(LOOPBACK));
        while Instant::now() < deadline {
            {
                let guard = self.lines.lock().unwrap();
                for line in guard.iter() {
                    if let Some(idx) = line.find(&prefix) {
                        let rest = &line[idx + prefix.len()..];
                        let port_str = rest.split_whitespace().next().unwrap_or("");
                        if let Ok(p) = port_str.parse::<u16>() {
                            return Some(p);
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }

    pub fn wait_for_listen(&self) -> u16 {
        self.try_wait_for_listen(LOG_WAIT)
            .unwrap_or_else(|| {
                let guard = self.lines.lock().unwrap();
                panic!("timed out waiting for LISTEN line; lines so far: {:?}", *guard)
            })
    }

    pub fn wait_for_line_timeout(&self, needle: &str, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            {
                let guard = self.lines.lock().unwrap();
                if let Some(found) = guard.iter().find(|l| l.contains(needle)) {
                    return found.clone();
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let guard = self.lines.lock().unwrap();
        panic!(
            "timed out waiting for line containing {:?}; collected lines: {:#?}",
            needle, *guard
        );
    }

    pub fn wait_for_line(&self, needle: &str) -> String {
        self.wait_for_line_timeout(needle, LOG_WAIT)
    }

    pub fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

fn rfid(s: &str) -> UiEvent {
    let mut h = heapless::String::new();
    h.push_str(s).expect("rfid fits in 32 bytes");
    UiEvent::RfidScanned(h)
}

fn barcode(s: &str) -> UiEvent {
    let mut h = heapless::String::new();
    h.push_str(s).expect("barcode fits in 64 bytes");
    UiEvent::BarcodeScanned(h)
}

fn write_registry(content: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new().expect("create temp registry file");
    file.write_all(content.as_bytes()).expect("write temp registry content");
    file.flush().expect("flush temp registry content");
    file
}

fn drive_until(
    device: &mut SimulatedDevice,
    now_ms: &mut u64,
    max_steps: usize,
    cond: impl Fn(&SimulatedDevice) -> bool,
) -> bool {
    for _ in 0..max_steps {
        *now_ms += 20;
        device.step_net(*now_ms);
        if cond(device) {
            return true;
        }
    }
    false
}

fn drive_with_server_until(
    device: &mut SimulatedDevice,
    server: &mut trillby_net::NetServer<4>,
    now_ms: &mut u64,
    max_steps: usize,
    mut on_event: impl FnMut(trillby_net::ServerEvent),
    cond: impl Fn(&SimulatedDevice) -> bool,
) -> bool {
    let device_uuid = device.device_uuid;
    let psk = device.psk;
    let resolver = move |id: &[u8; 16]| (*id == device_uuid).then_some(psk);
    for _ in 0..max_steps {
        *now_ms += 20;
        device.step_net(*now_ms);
        server.step(*now_ms, resolver, &mut on_event);
        if cond(device) {
            return true;
        }
    }
    false
}

fn connect(device: &mut SimulatedDevice, now_ms: &mut u64, max_steps: usize) -> bool {
    drive_until(device, now_ms, max_steps, |d| {
        d.network_status() == trillby_core::net_types::NetworkStatus::Online
    })
}

fn drain(device: &mut SimulatedDevice, now_ms: &mut u64, max_steps: usize) -> bool {
    drive_until(device, now_ms, max_steps, |d| {
        d.net_client.outbox_pending_count() == 0
    })
}

fn advance_by(device: &mut SimulatedDevice, now_ms: &mut u64, ms: u64) {
    *now_ms += ms;
    device.advance_clock(*now_ms);
}

#[test]
fn e2e_server_process_full_operator_lifecycle() {
    let mut server = ServerProcess::spawn(0);
    let port = server.wait_for_listen();
    assert!(port > 0);

    let mut device = SimulatedDevice::new(DEV_PSK, DEV_UUID, LOOPBACK, port);
    let mut now_ms = 1_000u64;

    // Connect to trillby-server
    assert!(connect(&mut device, &mut now_ms, 50));
    assert_eq!(device.net_client.state(), ClientState::Online);
    assert_eq!(device.state.network_status, NetworkStatus::Online);

    // 1. RFID login: Idle -> Authenticated
    device.handle_ui_event(rfid("BADGE_101"), now_ms);
    assert!(matches!(
        device.state.session_state(),
        SessionState::Authenticated { .. }
    ));
    assert!(!device.state.keyboard_visible);

    // 2. Barcode scan: Authenticated -> Working (keyboard auto-shown)
    now_ms += 100;
    device.handle_ui_event(barcode("JOB_5001"), now_ms);
    assert!(matches!(
        device.state.session_state(),
        SessionState::Working { .. }
    ));
    assert!(device.state.keyboard_visible);

    // 3. Advance 40 ticks (40 * 50ms = 2000ms)
    advance_by(&mut device, &mut now_ms, 40 * 50);

    // 4. Barcode scan: Working -> Authenticated (duration_ms = 2000, keyboard auto-hidden)
    device.handle_ui_event(barcode("JOB_5001"), now_ms);
    assert!(matches!(
        device.state.session_state(),
        SessionState::Authenticated { .. }
    ));
    assert!(!device.state.keyboard_visible);

    // 5. RFID scan: Authenticated -> Idle (logout)
    now_ms += 100;
    device.handle_ui_event(rfid("BADGE_101"), now_ms);
    assert_eq!(*device.state.session_state(), SessionState::Idle);

    // 6. Enqueue heartbeat
    device
        .net_client
        .send_payload(&HeartbeatPayload {
            battery_pct: 95,
            rssi: -48,
            pending_outbox: device.net_client.outbox_pending_count() as u16,
            uptime_s: (now_ms / 1000) as u32,
        })
        .expect("send_heartbeat");

    // Drive network until outbox is completely drained and ACKed
    assert!(drain(&mut device, &mut now_ms, 100));
    assert_eq!(device.net_client.outbox_pending_count(), 0);
    assert_eq!(device.state.pending_outbox_count, 0);
    assert!(device.render_count > 1);

    server.wait_for_line("CONNECT    client=0");
    let auth_line = server.wait_for_line("AUTH       client=0");
    assert!(auth_line.contains("badge=\"BADGE_101\""), "{auth_line}");

    let start_line = server.wait_for_line("WORK_START client=0");
    assert!(
        start_line.contains("operator=\"BADGE_101\" job=\"JOB_5001\""),
        "{start_line}"
    );

    let stop_line = server.wait_for_line("WORK_STOP  client=0");
    assert!(
        stop_line.contains("operator=\"BADGE_101\" job=\"JOB_5001\" duration_ms=2000"),
        "{stop_line}"
    );

    let logout_line = server.wait_for_line("LOGOUT     client=0");
    assert!(
        logout_line.contains("operator=\"BADGE_101\""),
        "{logout_line}"
    );

    let hb_line = server.wait_for_line("HEARTBEAT  client=0");
    assert!(hb_line.contains("battery=95% rssi=-48dBm"), "{hb_line}");
    server.kill();
}

#[test]
fn e2e_connection_drop_mid_job_and_server_restart_recovery() {
    let mut server = NetServer::<4>::bind(LOOPBACK, 0).expect("bind NetServer");
    let port = server.port();

    let mut device = SimulatedDevice::new(DEV_PSK, DEV_UUID, LOOPBACK, port);
    let mut now_ms = 1_000u64;

    // Connect device and log in OP_77 + start JOB_A
    device.handle_ui_event(rfid("OP_77"), now_ms);
    device.handle_ui_event(barcode("JOB_A"), now_ms + 50);
    now_ms += 50;

    let mut initial_events = Vec::new();
    let ok = drive_with_server_until(
        &mut device,
        &mut server,
        &mut now_ms,
        50,
        |ev| {
            if let ServerEvent::Data {
                msg_type, payload, ..
            } = ev
            {
                initial_events.push((msg_type, payload.to_vec()));
            }
        },
        |d| d.net_client.outbox_pending_count() == 0 && d.net_client.state() == ClientState::Online,
    );
    assert!(ok);
    assert_eq!(device.net_client.outbox_pending_count(), 0);
    assert_eq!(initial_events.len(), 2);
    assert_eq!(server.client_session_id(0), Some(1000));

    // Drop the client connection on the server mid-job
    if let Some(fd) = server.client_socket_fd(0) {
        unsafe {
            libc::shutdown(fd, libc::SHUT_RDWR);
        }
    }
    server.disconnect_client(0);

    // Step device so it observes POLLHUP / EOF and transitions to Offline
    assert!(drive_until(&mut device, &mut now_ms, 10, |d| d.network_status() == NetworkStatus::Offline));
    assert_eq!(device.state.network_status, NetworkStatus::Offline);
    assert!(matches!(
        device.net_client.state(),
        ClientState::Disconnected { .. }
    ));

    // While offline: advance 30 ticks (1500ms), stop JOB_A, start JOB_B, advance 20 ticks (1000ms), stop JOB_B, logout OP_77
    advance_by(&mut device, &mut now_ms, 30 * 50);
    device.handle_ui_event(barcode("JOB_A"), now_ms);

    now_ms += 50;
    device.handle_ui_event(barcode("JOB_B"), now_ms);
    advance_by(&mut device, &mut now_ms, 20 * 50);
    device.handle_ui_event(barcode("JOB_B"), now_ms);

    now_ms += 50;
    device.handle_ui_event(rfid("OP_77"), now_ms);

    assert_eq!(device.state.pending_outbox_count, 4);
    assert_eq!(device.state.network_status, NetworkStatus::Offline);

    // Advance synthetic clock past 1000ms disconnect backoff and recover on the server
    now_ms += 2_500;
    let mut recovered_work_events = Vec::new();
    let mut reconnected_session_id = None;

    let ok = drive_with_server_until(
        &mut device,
        &mut server,
        &mut now_ms,
        80,
        |ev| match ev {
            ServerEvent::Connected { session_id, .. } => {
                reconnected_session_id = Some(session_id);
            }
            ServerEvent::Data {
                msg_type: MsgType::Data,
                payload,
                ..
            } => {
                let w = WorkEventPayload::decode(payload).expect("valid WorkEventPayload");
                recovered_work_events.push(w);
            }
            _ => {}
        },
        |d| d.net_client.outbox_pending_count() == 0 && d.net_client.state() == ClientState::Online,
    );
    assert!(ok);

    assert_eq!(reconnected_session_id, Some(1001));
    assert_eq!(device.net_client.outbox_pending_count(), 0);
    assert_eq!(device.state.pending_outbox_count, 0);
    assert_eq!(device.state.network_status, NetworkStatus::Online);

    // Verify all 4 offline-queued events arrived in exact FIFO order
    assert_eq!(recovered_work_events.len(), 4);
    assert_eq!(recovered_work_events[0].kind, WorkEventKind::WorkStop);
    assert_eq!(recovered_work_events[0].job_id_bytes(), b"JOB_A");
    assert_eq!(recovered_work_events[0].duration_ms, 1620);

    assert_eq!(recovered_work_events[1].kind, WorkEventKind::WorkStart);
    assert_eq!(recovered_work_events[1].job_id_bytes(), b"JOB_B");

    assert_eq!(recovered_work_events[2].kind, WorkEventKind::WorkStop);
    assert_eq!(recovered_work_events[2].job_id_bytes(), b"JOB_B");
    assert_eq!(recovered_work_events[2].duration_ms, 1000);

    assert_eq!(recovered_work_events[3].kind, WorkEventKind::OperatorLogout);
    assert_eq!(recovered_work_events[3].operator_id_bytes(), b"OP_77");
}

#[test]
fn e2e_device_offline_boot_queues_events_before_server_starts() {
    for attempt in 0..3 {
        // Reserve a free localhost port and drop the listener so nothing is listening yet
        let port = {
            let listener = TcpListener::bind((std::net::Ipv4Addr::from(LOOPBACK), 0)).expect("bind ephemeral port");
            listener.local_addr().unwrap().port()
        };

        let mut device = SimulatedDevice::new(DEV_PSK, DEV_UUID, LOOPBACK, port);
        let mut now_ms = 1_000u64;

        // Attempt initial connection while server is not running (ECONNREFUSED)
        device.step_net(now_ms);
        if device.net_client.state() == ClientState::Connecting {
            device.step_net(now_ms);
        }
        assert!(
            matches!(
                device.net_client.state(),
                ClientState::Disconnected {
                    next_attempt_ms: 2000 | 3000,
                    backoff_ms: 2000 | 4000
                }
            ),
            "unexpected state after ECONNREFUSED: {:?}",
            device.net_client.state()
        );
        assert_eq!(device.state.network_status, NetworkStatus::Offline);

        // Queue operator workflow while server is still down
        device.handle_ui_event(rfid("OP_BOOT"), now_ms);
        now_ms += 50;
        device.handle_ui_event(barcode("JOB_BOOT"), now_ms);
        advance_by(&mut device, &mut now_ms, 10 * 50);
        device.handle_ui_event(barcode("JOB_BOOT"), now_ms);

        assert_eq!(device.state.pending_outbox_count, 3);
        assert_eq!(device.net_client.outbox_pending_count(), 3);

        // Now start trillby-server on that reserved port
        let mut server = ServerProcess::spawn(port);
        if server.try_wait_for_listen(Duration::from_secs(2)).is_none() {
            server.kill();
            assert!(
                attempt < 2,
                "failed to bind reserved port {port} after 3 attempts"
            );
            continue;
        }

        // Advance time past reconnect backoff and drive net loop until drained
        now_ms += 4_000;
        assert!(drain(&mut device, &mut now_ms, 100));

        assert_eq!(device.net_client.outbox_pending_count(), 0);
        assert_eq!(device.state.pending_outbox_count, 0);
        assert_eq!(device.state.network_status, NetworkStatus::Online);

        let auth_line = server.wait_for_line("AUTH       client=0");
        assert!(auth_line.contains("badge=\"OP_BOOT\""), "{auth_line}");

        let start_line = server.wait_for_line("WORK_START client=0");
        assert!(
            start_line.contains("operator=\"OP_BOOT\" job=\"JOB_BOOT\""),
            "{start_line}"
        );

        let stop_line = server.wait_for_line("WORK_STOP  client=0");
        assert!(
            stop_line.contains("operator=\"OP_BOOT\" job=\"JOB_BOOT\" duration_ms=500"),
            "{stop_line}"
        );

        server.kill();
        return;
    }
}

#[test]
fn e2e_half_open_ack_timeout_triggers_reconnect_and_retains_event() {
    let mut server = NetServer::<4>::bind(LOOPBACK, 0).expect("bind NetServer");
    let port = server.port();

    let mut device = SimulatedDevice::new(DEV_PSK, DEV_UUID, LOOPBACK, port);
    let mut now_ms = 1_000u64;

    // Establish initial session (session_id == 1000) and deliver RfidScanned("OP_TIMEOUT")
    device.handle_ui_event(rfid("OP_TIMEOUT"), now_ms);
    let ok = drive_with_server_until(
        &mut device,
        &mut server,
        &mut now_ms,
        50,
        |_| {},
        |d| d.net_client.outbox_pending_count() == 0 && d.net_client.state() == ClientState::Online,
    );
    assert!(ok);
    assert_eq!(device.net_client.state(), ClientState::Online);
    assert_eq!(device.net_client.outbox_pending_count(), 0);
    assert_eq!(server.client_session_id(0), Some(1000));

    // At t = 2000, scan JOB_TIMEOUT and step device ONLY so WorkStart is sent (inflight at sent_ms = 2000),
    // but do NOT step NetServer so no MsgType::Ack is ever sent back (simulating a half-open / wedged peer).
    let sent_ms = 2_000u64;
    device.handle_ui_event(barcode("JOB_TIMEOUT"), sent_ms);
    assert_eq!(device.net_client.outbox_pending_count(), 1);
    device.step_net(sent_ms);
    assert_eq!(device.net_client.state(), ClientState::Online);
    assert_eq!(device.net_client.outbox_pending_count(), 1);

    // Step at t = sent_ms + ACK_TIMEOUT_MS - 1 (11_999): still Online, event still in outbox
    device.step_net(sent_ms + ACK_TIMEOUT_MS - 1);
    assert_eq!(device.net_client.state(), ClientState::Online);
    assert_eq!(device.net_client.outbox_pending_count(), 1);

    // Step at t = sent_ms + ACK_TIMEOUT_MS (12_000): ACK timeout fires, transitions to Disconnected,
    // and preserves the unacknowledged WorkStart at the head of the outbox.
    device.step_net(sent_ms + ACK_TIMEOUT_MS);
    assert!(matches!(
        device.net_client.state(),
        ClientState::Disconnected {
            next_attempt_ms: 13_000,
            backoff_ms: 2_000
        }
    ));
    assert_eq!(device.state.network_status, NetworkStatus::Offline);
    assert_eq!(device.net_client.outbox_pending_count(), 1);
    assert_eq!(device.state.pending_outbox_count, 1);

    // Clear the stale half-open slot on NetServer, advance past the 1000ms backoff to t = 14_500,
    // and verify the device reconnects under session 1001 and re-encrypts + delivers WorkStart.
    server.disconnect_client(0);
    now_ms = 14_500;
    let mut new_session_id = None;
    let mut delivered_work = Vec::new();

    let ok = drive_with_server_until(
        &mut device,
        &mut server,
        &mut now_ms,
        50,
        |ev| match ev {
            ServerEvent::Connected { session_id, .. } => {
                new_session_id = Some(session_id);
            }
            ServerEvent::Data {
                msg_type: MsgType::Data,
                payload,
                ..
            } => {
                let w = WorkEventPayload::decode(payload).expect("decode WorkEventPayload");
                delivered_work.push(w);
            }
            _ => {}
        },
        |d| d.net_client.outbox_pending_count() == 0 && d.net_client.state() == ClientState::Online,
    );
    assert!(ok);

    assert_eq!(new_session_id, Some(1001));
    assert_eq!(device.net_client.outbox_pending_count(), 0);
    assert_eq!(device.state.pending_outbox_count, 0);
    assert_eq!(device.state.network_status, NetworkStatus::Online);
    assert_eq!(delivered_work.len(), 1);
    assert_eq!(delivered_work[0].kind, WorkEventKind::WorkStart);
    assert_eq!(delivered_work[0].operator_id_bytes(), b"OP_TIMEOUT");
    assert_eq!(delivered_work[0].job_id_bytes(), b"JOB_TIMEOUT");
}

#[test]
fn e2e_registry_multi_client_isolation_and_unauthorized_device_rejection() {
    let dev1_uuid = *b"DEV_0001_UUID\0\0\0";
    let dev1_psk = [0x11u8; 32];
    let dev2_uuid = *b"DEV_0002_UUID\0\0\0";
    let dev2_psk = [0x22u8; 32];
    let bad_uuid = *b"DEV_BAD_UUID\0\0\0\0";
    let bad_psk = [0x99u8; 32];

    let mut dev1_uuid_hex = String::new();
    let _ = trillby_net::write_hex(&mut dev1_uuid_hex, &dev1_uuid);
    let mut dev1_psk_hex = String::new();
    let _ = trillby_net::write_hex(&mut dev1_psk_hex, &dev1_psk);
    let mut dev2_uuid_hex = String::new();
    let _ = trillby_net::write_hex(&mut dev2_uuid_hex, &dev2_uuid);
    let mut dev2_psk_hex = String::new();
    let _ = trillby_net::write_hex(&mut dev2_psk_hex, &dev2_psk);

    let reg_content = format!(
        "{dev1_uuid_hex}\t{dev1_psk_hex}\n\
         {dev2_uuid_hex}\t{dev2_psk_hex}\n"
    );
    let reg_file = write_registry(&reg_content);

    let server = ServerProcess::spawn_with_registry(0, reg_file.path().to_str().unwrap());
    let port = server.wait_for_listen();

    let mut dev1 = SimulatedDevice::new(dev1_psk, dev1_uuid, LOOPBACK, port);
    let mut dev2 = SimulatedDevice::new(dev2_psk, dev2_uuid, LOOPBACK, port);
    let mut dev_bad = SimulatedDevice::new(bad_psk, bad_uuid, LOOPBACK, port);

    let mut now_ms = 1_000u64;
    for _ in 0..60 {
        now_ms += 20;
        dev1.step_net(now_ms);
        dev2.step_net(now_ms);
        dev_bad.step_net(now_ms);
        if dev1.net_client.state() == ClientState::Online
            && dev2.net_client.state() == ClientState::Online
        {
            break;
        }
    }

    assert_eq!(dev1.net_client.state(), ClientState::Online);
    assert_eq!(dev2.net_client.state(), ClientState::Online);
    assert_ne!(dev_bad.net_client.state(), ClientState::Online);

    dev1.handle_ui_event(rfid("OP_1"), now_ms);
    now_ms += 50;
    dev1.handle_ui_event(barcode("JOB_A"), now_ms);

    dev2.handle_ui_event(rfid("OP_2"), now_ms);
    now_ms += 50;
    dev2.handle_ui_event(barcode("JOB_B"), now_ms);

    for _ in 0..10 {
        now_ms += 50;
        dev1.advance_clock(now_ms);
        dev2.advance_clock(now_ms);
        dev1.step_net(now_ms);
        dev2.step_net(now_ms);
        dev_bad.step_net(now_ms);
    }

    dev1.handle_ui_event(barcode("JOB_A"), now_ms);
    dev2.handle_ui_event(barcode("JOB_B"), now_ms);

    for _ in 0..100 {
        now_ms += 20;
        dev1.step_net(now_ms);
        dev2.step_net(now_ms);
        dev_bad.step_net(now_ms);
        if dev1.net_client.outbox_pending_count() == 0
            && dev2.net_client.outbox_pending_count() == 0
        {
            break;
        }
    }

    assert_eq!(dev1.net_client.outbox_pending_count(), 0);
    assert_eq!(dev2.net_client.outbox_pending_count(), 0);

    let dev1_conn = server.wait_for_line(&format!("uuid={dev1_uuid_hex}"));
    let dev2_conn = server.wait_for_line(&format!("uuid={dev2_uuid_hex}"));
    assert!(dev1_conn.contains("CONNECT"));
    assert!(dev2_conn.contains("CONNECT"));

    let dev1_work = server.wait_for_line("operator=\"OP_1\" job=\"JOB_A\"");
    let dev2_work = server.wait_for_line("operator=\"OP_2\" job=\"JOB_B\"");
    assert!(dev1_work.contains("WORK_START"));
    assert!(dev2_work.contains("WORK_START"));
    let lines = server.lines.lock().unwrap();
    let has_bad_disconnect = lines.iter().any(|l| l.contains("DISCONNECT") && !l.contains("uuid="));
    assert!(has_bad_disconnect, "server must log DISCONNECT without uuid for unauthorized device; lines: {:#?}", *lines);
}

#[test]
fn e2e_operator_rfid_hot_swap_mid_job_and_barcode_rejection() {
    let server = ServerProcess::spawn(0);
    let port = server.wait_for_listen();
    let mut device = SimulatedDevice::new(DEV_PSK, DEV_UUID, LOOPBACK, port);
    let mut now_ms = 1_000u64;

    assert!(connect(&mut device, &mut now_ms, 50));
    assert_eq!(device.net_client.state(), ClientState::Online);

    device.handle_ui_event(barcode("JOB_EARLY"), now_ms);
    assert_eq!(*device.state.session_state(), SessionState::Idle);
    assert_eq!(device.net_client.outbox_pending_count(), 0);

    now_ms += 50;
    device.handle_ui_event(rfid("BADGE_101"), now_ms);
    assert!(matches!(
        device.state.session_state(),
        SessionState::Authenticated { .. }
    ));

    now_ms += 50;
    device.handle_ui_event(barcode("JOB_5001"), now_ms);
    assert!(matches!(
        device.state.session_state(),
        SessionState::Working { .. }
    ));

    assert!(drain(&mut device, &mut now_ms, 50));
    assert_eq!(device.net_client.outbox_pending_count(), 0);

    advance_by(&mut device, &mut now_ms, 20 * 50);

    device.handle_ui_event(barcode("JOB_9999"), now_ms);
    match device.state.session_state() {
        SessionState::Working { job_id, .. } => {
            assert_eq!(job_id.as_str(), "JOB_5001");
        }
        other => panic!("expected Working(JOB_5001), got: {:?}", other),
    }
    assert_eq!(device.net_client.outbox_pending_count(), 0);

    device.handle_ui_event(rfid("BADGE_202"), now_ms);
    match device.state.session_state() {
        SessionState::Authenticated { operator_id } => {
            assert_eq!(operator_id.as_str(), "BADGE_202");
        }
        other => panic!("expected Authenticated(BADGE_202), got: {:?}", other),
    }

    assert!(drain(&mut device, &mut now_ms, 100));
    assert_eq!(device.net_client.outbox_pending_count(), 0);

    server.wait_for_line(
        "WORK_STOP  client=0 operator=\"BADGE_101\" job=\"JOB_5001\" duration_ms=1060",
    );
    server.wait_for_line(
        "LOGOUT     client=0 operator=\"BADGE_101\"",
    );
    server.wait_for_line(
        "AUTH       client=0 badge=\"BADGE_202\"",
    );

    let guard = server.lines.lock().unwrap();
    let stop_idx = guard
        .iter()
        .position(|l| l.contains("WORK_STOP") && l.contains("BADGE_101") && l.contains("duration_ms=1060"))
        .expect("WORK_STOP line found");
    let logout_idx = guard
        .iter()
        .position(|l| l.contains("LOGOUT") && l.contains("BADGE_101"))
        .expect("LOGOUT line found");
    let auth_idx = guard
        .iter()
        .position(|l| l.contains("AUTH") && l.contains("BADGE_202"))
        .expect("AUTH line found");
    assert!(stop_idx < logout_idx, "WORK_STOP must precede LOGOUT");
    assert!(logout_idx < auth_idx, "LOGOUT must precede AUTH");
}

#[test]
fn e2e_true_server_process_kill_and_restart_recovery() {
    let mut server1 = ServerProcess::spawn(0);
    let port = server1.wait_for_listen();
    assert!(port > 0);

    let mut device = SimulatedDevice::new(DEV_PSK, DEV_UUID, LOOPBACK, port);
    let mut now_ms = 1_000u64;

    assert!(connect(&mut device, &mut now_ms, 50));
    assert_eq!(device.net_client.state(), ClientState::Online);

    device.handle_ui_event(rfid("OP_RESTART"), now_ms);
    now_ms += 50;
    device.handle_ui_event(barcode("JOB_R1"), now_ms);

    assert!(drain(&mut device, &mut now_ms, 50));
    assert_eq!(device.net_client.outbox_pending_count(), 0);

    server1.kill();

    advance_by(&mut device, &mut now_ms, 30 * 50);

    device.handle_ui_event(barcode("JOB_R1"), now_ms);
    assert_eq!(device.net_client.outbox_pending_count(), 1);

    device.step_net(now_ms);

    let mut server2 = None;
    for _ in 0..20 {
        let s = ServerProcess::spawn(port);
        if s.try_wait_for_listen(Duration::from_millis(500)).is_some() {
            server2 = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let server2 = server2.expect("server #2 spawned on same port");

    now_ms += 5_000;

    let ok = drive_until(&mut device, &mut now_ms, 100, |d| {
        d.net_client.state() == ClientState::Online
            && d.net_client.outbox_pending_count() == 0
    });
    assert!(ok);

    assert_eq!(device.net_client.state(), ClientState::Online);
    assert_eq!(device.net_client.outbox_pending_count(), 0);

    server2.wait_for_line("CONNECT");
    server2.wait_for_line(
        "WORK_STOP  client=0 operator=\"OP_RESTART\" job=\"JOB_R1\" duration_ms=1560",
    );
}
