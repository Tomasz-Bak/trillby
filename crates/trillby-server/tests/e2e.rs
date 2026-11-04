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

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::{Point, Size};
use embedded_graphics::primitives::Rectangle;
use embedded_graphics_framebuf::FrameBuf;

use trillby_core::{NetworkStatus, SessionEvent, SessionState, UiEvent, UiState};
use trillby_net::client::ACK_TIMEOUT_MS;
use trillby_net::{
    AuthInitPayload, ClientState, HeartbeatPayload, MsgType, NetClient, NetServer, ServerEvent,
    WorkEventKind, WorkEventPayload,
};
use trillby_ui::{
    core_point_to_eg, eg_rect_to_core, KeyboardGrid, LayoutZones, UiRenderer,
};

const DEV_UUID: [u8; 16] = *b"TRILLBY_0001\0\0\0\0";
const DEV_PSK: [u8; 32] = [0x42; 32];

pub struct SimulatedDevice {
    pub state: UiState<256>,
    pub renderer: UiRenderer,
    pub pixels: Box<[Rgb565; 800 * 480]>,
    pub net_client: NetClient<32>,
    pub render_count: usize,
}

impl SimulatedDevice {
    pub fn new(psk: [u8; 32], uuid: [u8; 16], server_ip: [u8; 4], server_port: u16) -> Self {
        let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
        let mut state = UiState::new();
        let renderer = UiRenderer::new(screen_bounds);
        let mut pixels: Box<[Rgb565; 800 * 480]> = vec![Rgb565::new(0, 0, 0); 800 * 480]
            .into_boxed_slice()
            .try_into()
            .expect("800x480 framebuffer slice");

        {
            let mut fb = FrameBuf::new(&mut *pixels, 800, 480);
            renderer.render(&mut fb, &state).expect("initial render");
        }
        state.dirty = false;

        Self {
            state,
            renderer,
            pixels,
            net_client: NetClient::new(psk, uuid, server_ip, server_port),
            render_count: 1,
        }
    }

    pub fn handle_ui_event(&mut self, event: UiEvent, now_ms: u64) {
        let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
        let zones = LayoutZones::compute(screen_bounds, self.state.keyboard_visible);
        let core_bounds = eg_rect_to_core(screen_bounds);
        let core_kb_bounds = zones.keyboard_area.map(eg_rect_to_core);

        let resolved_key = match &event {
            UiEvent::TouchDown { scaled, .. }
            | UiEvent::TouchUp { scaled, .. }
            | UiEvent::TouchMove { scaled, .. } => {
                let eg_pt = core_point_to_eg(*scaled);
                zones
                    .keyboard_area
                    .and_then(|kb| KeyboardGrid::resolve_key(kb, eg_pt, self.state.keyboard_layer))
            }
            _ => None,
        };

        self.state
            .handle_event(event, core_bounds, core_kb_bounds, resolved_key);

        while let Some(ev) = self.state.pop_session_event() {
            match ev {
                SessionEvent::OperatorLogin { operator_id, .. } => {
                    let op_bytes = operator_id.as_bytes();
                    let len = op_bytes.len().min(32);
                    let mut payload = AuthInitPayload {
                        auth_data_len: len as u8,
                        auth_data: [0u8; 32],
                        timestamp_ms: now_ms,
                    };
                    payload.auth_data[..len].copy_from_slice(&op_bytes[..len]);
                    self.net_client.send_auth(&payload).expect("enqueue auth");
                }
                SessionEvent::OperatorLogout { operator_id, .. } => {
                    self.net_client
                        .send_work_event(&WorkEventPayload::operator_logout(
                            operator_id.as_bytes(),
                            now_ms,
                        ))
                        .expect("enqueue logout");
                }
                SessionEvent::WorkStart {
                    operator_id,
                    job_id,
                    ..
                } => {
                    self.net_client
                        .send_work_event(&WorkEventPayload::work_start(
                            operator_id.as_bytes(),
                            job_id.as_bytes(),
                            now_ms,
                        ))
                        .expect("enqueue work_start");
                }
                SessionEvent::WorkStop {
                    operator_id,
                    job_id,
                    duration_ms,
                    ..
                } => {
                    self.net_client
                        .send_work_event(&WorkEventPayload::work_stop(
                            operator_id.as_bytes(),
                            job_id.as_bytes(),
                            now_ms,
                            duration_ms,
                        ))
                        .expect("enqueue work_stop");
                }
            }
        }

        self.state.pending_outbox_count = self.net_client.outbox_pending_count() as u16;

        if self.state.dirty {
            let mut fb = FrameBuf::new(&mut *self.pixels, 800, 480);
            self.renderer
                .render(&mut fb, &self.state)
                .expect("dirty render");
            self.state.dirty = false;
            self.render_count += 1;
        }
    }

    pub fn step_net(&mut self, now_ms: u64) {
        let fd = self.net_client.socket_fd();
        let mut revents = 0i16;
        if fd >= 0 {
            let mut events = libc::POLLIN;
            if self.net_client.wants_write() {
                events |= libc::POLLOUT;
            }
            let mut pfd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut pfd, 1, 10) };
            if ret > 0 {
                revents = pfd.revents;
            }
        }

        if let Some(status) = self.net_client.poll_step(now_ms, revents) {
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
    pub fn spawn(port: u16) -> Self {
        let bin = env!("CARGO_BIN_EXE_trillby-server");
        let mut child = Command::new(bin)
            .args(["--dev", "--bind", "127.0.0.1", "--port", &port.to_string()])
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

    pub fn spawn_with_registry(port: u16, registry_path: &str) -> Self {
        let bin = env!("CARGO_BIN_EXE_trillby-server");
        let mut child = Command::new(bin)
            .args(["--bind", "127.0.0.1", "--port", &port.to_string(), "--registry", registry_path])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn trillby-server with registry");

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

    pub fn try_wait_for_listen(&self, timeout: Duration) -> Option<u16> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            {
                let guard = self.lines.lock().unwrap();
                for line in guard.iter() {
                    if let Some(idx) = line.find("LISTEN     addr=127.0.0.1:") {
                        let rest = &line[idx + "LISTEN     addr=127.0.0.1:".len()..];
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
        self.try_wait_for_listen(Duration::from_secs(3))
            .unwrap_or_else(|| {
                let guard = self.lines.lock().unwrap();
                panic!("timed out waiting for LISTEN line; lines so far: {:?}", *guard)
            })
    }

    pub fn wait_for_line(&self, needle: &str, timeout: Duration) -> String {
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

#[test]
fn e2e_server_process_full_operator_lifecycle() {
    let mut server = ServerProcess::spawn(0);
    let port = server.wait_for_listen();
    assert!(port > 0);

    let mut device = SimulatedDevice::new(DEV_PSK, DEV_UUID, [127, 0, 0, 1], port);
    let mut now_ms = 1_000u64;

    // Connect to trillby-server
    for _ in 0..50 {
        device.step_net(now_ms);
        if device.net_client.state() == ClientState::Online {
            break;
        }
        now_ms += 20;
    }
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
    for _ in 0..40 {
        now_ms += 50;
        device.handle_ui_event(UiEvent::Tick, now_ms);
    }

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
        .send_heartbeat(&HeartbeatPayload {
            battery_pct: 95,
            rssi: -48,
            pending_outbox: device.net_client.outbox_pending_count() as u16,
            uptime_s: (now_ms / 1000) as u32,
        })
        .expect("send_heartbeat");

    // Drive network until outbox is completely drained and ACKed
    for _ in 0..100 {
        now_ms += 20;
        device.step_net(now_ms);
        if device.net_client.outbox_pending_count() == 0 {
            break;
        }
    }
    assert_eq!(device.net_client.outbox_pending_count(), 0);
    assert_eq!(device.state.pending_outbox_count, 0);
    assert!(device.render_count > 1);

    let timeout = Duration::from_secs(3);
    server.wait_for_line("CONNECT    client=0", timeout);
    let auth_line = server.wait_for_line("AUTH       client=0", timeout);
    assert!(auth_line.contains("badge=\"BADGE_101\""), "{auth_line}");

    let start_line = server.wait_for_line("WORK_START client=0", timeout);
    assert!(
        start_line.contains("operator=\"BADGE_101\" job=\"JOB_5001\""),
        "{start_line}"
    );

    let stop_line = server.wait_for_line("WORK_STOP  client=0", timeout);
    assert!(
        stop_line.contains("operator=\"BADGE_101\" job=\"JOB_5001\" duration_ms=2000"),
        "{stop_line}"
    );

    let logout_line = server.wait_for_line("LOGOUT     client=0", timeout);
    assert!(
        logout_line.contains("operator=\"BADGE_101\""),
        "{logout_line}"
    );

    let hb_line = server.wait_for_line("HEARTBEAT  client=0", timeout);
    assert!(hb_line.contains("battery=95% rssi=-48dBm"), "{hb_line}");

    server.kill();
}

#[test]
fn e2e_connection_drop_mid_job_and_server_restart_recovery() {
    let mut server = NetServer::<4>::bind([127, 0, 0, 1], 0).expect("bind NetServer");
    let port = server.port();
    let resolver = |uuid: &[u8; 16]| (*uuid == DEV_UUID).then_some(DEV_PSK);

    let mut device = SimulatedDevice::new(DEV_PSK, DEV_UUID, [127, 0, 0, 1], port);
    let mut now_ms = 1_000u64;

    // Connect device and log in OP_77 + start JOB_A
    device.handle_ui_event(rfid("OP_77"), now_ms);
    device.handle_ui_event(barcode("JOB_A"), now_ms + 50);
    now_ms += 50;

    let mut initial_events = Vec::new();
    for _ in 0..50 {
        now_ms += 20;
        device.step_net(now_ms);
        server.step(now_ms, resolver, |ev| {
            if let ServerEvent::Data {
                msg_type, payload, ..
            } = ev
            {
                initial_events.push((msg_type, payload.to_vec()));
            }
        });
        if device.net_client.outbox_pending_count() == 0
            && device.net_client.state() == ClientState::Online
        {
            break;
        }
    }
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
    for _ in 0..10 {
        now_ms += 20;
        device.step_net(now_ms);
        if device.state.network_status == NetworkStatus::Offline {
            break;
        }
    }
    assert_eq!(device.state.network_status, NetworkStatus::Offline);
    assert!(matches!(
        device.net_client.state(),
        ClientState::Disconnected { .. }
    ));

    // While offline: advance 30 ticks (1500ms), stop JOB_A, start JOB_B, advance 20 ticks (1000ms), stop JOB_B, logout OP_77
    for _ in 0..30 {
        now_ms += 50;
        device.handle_ui_event(UiEvent::Tick, now_ms);
    }
    device.handle_ui_event(barcode("JOB_A"), now_ms);

    now_ms += 50;
    device.handle_ui_event(barcode("JOB_B"), now_ms);
    for _ in 0..20 {
        now_ms += 50;
        device.handle_ui_event(UiEvent::Tick, now_ms);
    }
    device.handle_ui_event(barcode("JOB_B"), now_ms);

    now_ms += 50;
    device.handle_ui_event(rfid("OP_77"), now_ms);

    assert_eq!(device.state.pending_outbox_count, 4);
    assert_eq!(device.state.network_status, NetworkStatus::Offline);

    // Advance synthetic clock past 1000ms disconnect backoff and recover on the server
    now_ms += 2_500;
    let mut recovered_work_events = Vec::new();
    let mut reconnected_session_id = None;

    for _ in 0..80 {
        now_ms += 20;
        device.step_net(now_ms);
        server.step(now_ms, resolver, |ev| match ev {
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
        });
        if device.net_client.outbox_pending_count() == 0
            && device.net_client.state() == ClientState::Online
        {
            break;
        }
    }

    assert_eq!(reconnected_session_id, Some(1001));
    assert_eq!(device.net_client.outbox_pending_count(), 0);
    assert_eq!(device.state.pending_outbox_count, 0);
    assert_eq!(device.state.network_status, NetworkStatus::Online);

    // Verify all 4 offline-queued events arrived in exact FIFO order
    assert_eq!(recovered_work_events.len(), 4);
    assert_eq!(recovered_work_events[0].kind, WorkEventKind::WorkStop);
    assert_eq!(
        &recovered_work_events[0].job_id[..recovered_work_events[0].job_id_len as usize],
        b"JOB_A"
    );
    assert_eq!(recovered_work_events[0].duration_ms, 1500);

    assert_eq!(recovered_work_events[1].kind, WorkEventKind::WorkStart);
    assert_eq!(
        &recovered_work_events[1].job_id[..recovered_work_events[1].job_id_len as usize],
        b"JOB_B"
    );

    assert_eq!(recovered_work_events[2].kind, WorkEventKind::WorkStop);
    assert_eq!(
        &recovered_work_events[2].job_id[..recovered_work_events[2].job_id_len as usize],
        b"JOB_B"
    );
    assert_eq!(recovered_work_events[2].duration_ms, 1000);

    assert_eq!(recovered_work_events[3].kind, WorkEventKind::OperatorLogout);
    assert_eq!(
        &recovered_work_events[3].operator_id[..recovered_work_events[3].operator_id_len as usize],
        b"OP_77"
    );
}

#[test]
fn e2e_device_offline_boot_queues_events_before_server_starts() {
    for attempt in 0..3 {
        // Reserve a free localhost port and drop the listener so nothing is listening yet
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
            listener.local_addr().unwrap().port()
        };

        let mut device = SimulatedDevice::new(DEV_PSK, DEV_UUID, [127, 0, 0, 1], port);
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
        for _ in 0..10 {
            now_ms += 50;
            device.handle_ui_event(UiEvent::Tick, now_ms);
        }
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
        for _ in 0..100 {
            now_ms += 20;
            device.step_net(now_ms);
            if device.net_client.outbox_pending_count() == 0 {
                break;
            }
        }

        assert_eq!(device.net_client.outbox_pending_count(), 0);
        assert_eq!(device.state.pending_outbox_count, 0);
        assert_eq!(device.state.network_status, NetworkStatus::Online);

        let timeout = Duration::from_secs(3);
        let auth_line = server.wait_for_line("AUTH       client=0", timeout);
        assert!(auth_line.contains("badge=\"OP_BOOT\""), "{auth_line}");

        let start_line = server.wait_for_line("WORK_START client=0", timeout);
        assert!(
            start_line.contains("operator=\"OP_BOOT\" job=\"JOB_BOOT\""),
            "{start_line}"
        );

        let stop_line = server.wait_for_line("WORK_STOP  client=0", timeout);
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
    let mut server = NetServer::<4>::bind([127, 0, 0, 1], 0).expect("bind NetServer");
    let port = server.port();
    let resolver = |uuid: &[u8; 16]| (*uuid == DEV_UUID).then_some(DEV_PSK);

    let mut device = SimulatedDevice::new(DEV_PSK, DEV_UUID, [127, 0, 0, 1], port);
    let mut now_ms = 1_000u64;

    // Establish initial session (session_id == 1000) and deliver RfidScanned("OP_TIMEOUT")
    device.handle_ui_event(rfid("OP_TIMEOUT"), now_ms);
    for _ in 0..50 {
        now_ms += 20;
        device.step_net(now_ms);
        server.step(now_ms, resolver, |_| {});
        if device.net_client.outbox_pending_count() == 0
            && device.net_client.state() == ClientState::Online
        {
            break;
        }
    }
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

    for _ in 0..50 {
        now_ms += 20;
        device.step_net(now_ms);
        server.step(now_ms, resolver, |ev| match ev {
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
        });
        if device.net_client.outbox_pending_count() == 0
            && device.net_client.state() == ClientState::Online
        {
            break;
        }
    }

    assert_eq!(new_session_id, Some(1001));
    assert_eq!(device.net_client.outbox_pending_count(), 0);
    assert_eq!(device.state.pending_outbox_count, 0);
    assert_eq!(device.state.network_status, NetworkStatus::Online);
    assert_eq!(delivered_work.len(), 1);
    assert_eq!(delivered_work[0].kind, WorkEventKind::WorkStart);
    assert_eq!(
        &delivered_work[0].operator_id[..delivered_work[0].operator_id_len as usize],
        b"OP_TIMEOUT"
    );
    assert_eq!(
        &delivered_work[0].job_id[..delivered_work[0].job_id_len as usize],
        b"JOB_TIMEOUT"
    );
}

#[test]
fn e2e_registry_multi_client_isolation_and_unauthorized_device_rejection() {
    let pid = std::process::id();
    let reg_path = format!("/tmp/trillby_test_reg_multi_{}.tsv", pid);
    struct TempFile(String);
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _guard = TempFile(reg_path.clone());

    let dev1_uuid = *b"DEV_0001_UUID\0\0\0";
    let dev1_psk = [0x11u8; 32];
    let dev2_uuid = *b"DEV_0002_UUID\0\0\0";
    let dev2_psk = [0x22u8; 32];
    let bad_uuid = *b"DEV_BAD_UUID\0\0\0\0";
    let bad_psk = [0x99u8; 32];

    let mut dev1_uuid_hex = String::new();
    for b in &dev1_uuid {
        dev1_uuid_hex.push_str(&format!("{b:02x}"));
    }
    let mut dev1_psk_hex = String::new();
    for b in &dev1_psk {
        dev1_psk_hex.push_str(&format!("{b:02x}"));
    }
    let mut dev2_uuid_hex = String::new();
    for b in &dev2_uuid {
        dev2_uuid_hex.push_str(&format!("{b:02x}"));
    }
    let mut dev2_psk_hex = String::new();
    for b in &dev2_psk {
        dev2_psk_hex.push_str(&format!("{b:02x}"));
    }

    let reg_content = format!(
        "{dev1_uuid_hex}\t{dev1_psk_hex}\n\
         {dev2_uuid_hex}\t{dev2_psk_hex}\n"
    );
    std::fs::write(&reg_path, reg_content).expect("write registry");

    let server = ServerProcess::spawn_with_registry(0, &reg_path);
    let port = server.wait_for_listen();

    let mut dev1 = SimulatedDevice::new(dev1_psk, dev1_uuid, [127, 0, 0, 1], port);
    let mut dev2 = SimulatedDevice::new(dev2_psk, dev2_uuid, [127, 0, 0, 1], port);
    let mut dev_bad = SimulatedDevice::new(bad_psk, bad_uuid, [127, 0, 0, 1], port);

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
        dev1.handle_ui_event(UiEvent::Tick, now_ms);
        dev2.handle_ui_event(UiEvent::Tick, now_ms);
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

    let dev1_conn = server.wait_for_line(&format!("uuid={dev1_uuid_hex}"), Duration::from_secs(3));
    let dev2_conn = server.wait_for_line(&format!("uuid={dev2_uuid_hex}"), Duration::from_secs(3));
    assert!(dev1_conn.contains("CONNECT"));
    assert!(dev2_conn.contains("CONNECT"));

    let dev1_work = server.wait_for_line("operator=\"OP_1\" job=\"JOB_A\"", Duration::from_secs(3));
    let dev2_work = server.wait_for_line("operator=\"OP_2\" job=\"JOB_B\"", Duration::from_secs(3));
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
    let mut device = SimulatedDevice::new(DEV_PSK, DEV_UUID, [127, 0, 0, 1], port);
    let mut now_ms = 1_000u64;

    for _ in 0..50 {
        now_ms += 20;
        device.step_net(now_ms);
        if device.net_client.state() == ClientState::Online {
            break;
        }
    }
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

    for _ in 0..50 {
        now_ms += 20;
        device.step_net(now_ms);
        if device.net_client.outbox_pending_count() == 0 {
            break;
        }
    }
    assert_eq!(device.net_client.outbox_pending_count(), 0);

    for _ in 0..20 {
        now_ms += 50;
        device.handle_ui_event(UiEvent::Tick, now_ms);
    }

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

    for _ in 0..100 {
        now_ms += 20;
        device.step_net(now_ms);
        if device.net_client.outbox_pending_count() == 0 {
            break;
        }
    }
    assert_eq!(device.net_client.outbox_pending_count(), 0);

    server.wait_for_line(
        "WORK_STOP  client=0 operator=\"BADGE_101\" job=\"JOB_5001\" duration_ms=1000",
        Duration::from_secs(3),
    );
    server.wait_for_line(
        "LOGOUT     client=0 operator=\"BADGE_101\"",
        Duration::from_secs(3),
    );
    server.wait_for_line(
        "AUTH       client=0 badge=\"BADGE_202\"",
        Duration::from_secs(3),
    );

    let guard = server.lines.lock().unwrap();
    let stop_idx = guard
        .iter()
        .position(|l| l.contains("WORK_STOP") && l.contains("BADGE_101") && l.contains("duration_ms=1000"))
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

    let mut device = SimulatedDevice::new(DEV_PSK, DEV_UUID, [127, 0, 0, 1], port);
    let mut now_ms = 1_000u64;

    for _ in 0..50 {
        now_ms += 20;
        device.step_net(now_ms);
        if device.net_client.state() == ClientState::Online {
            break;
        }
    }
    assert_eq!(device.net_client.state(), ClientState::Online);

    device.handle_ui_event(rfid("OP_RESTART"), now_ms);
    now_ms += 50;
    device.handle_ui_event(barcode("JOB_R1"), now_ms);

    for _ in 0..50 {
        now_ms += 20;
        device.step_net(now_ms);
        if device.net_client.outbox_pending_count() == 0 {
            break;
        }
    }
    assert_eq!(device.net_client.outbox_pending_count(), 0);

    server1.kill();

    for _ in 0..30 {
        now_ms += 50;
        device.handle_ui_event(UiEvent::Tick, now_ms);
    }

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
        std::thread::sleep(Duration::from_millis(100));
    }
    let server2 = server2.expect("server #2 spawned on same port");

    now_ms += 5_000;

    for _ in 0..100 {
        now_ms += 20;
        device.step_net(now_ms);
        if device.net_client.state() == ClientState::Online
            && device.net_client.outbox_pending_count() == 0
        {
            break;
        }
    }

    assert_eq!(device.net_client.state(), ClientState::Online);
    assert_eq!(device.net_client.outbox_pending_count(), 0);

    server2.wait_for_line("CONNECT", Duration::from_secs(3));
    server2.wait_for_line(
        "WORK_STOP  client=0 operator=\"OP_RESTART\" job=\"JOB_R1\" duration_ms=1500",
        Duration::from_secs(3),
    );
}
