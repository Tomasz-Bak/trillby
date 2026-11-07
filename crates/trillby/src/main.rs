#![no_std]
#![cfg_attr(not(test), no_main)]

//! Trillby PID-1 binary.
//!
//! Boot path: kernel execs `/init` -> musl crt1 `_start` -> [`main`]
//! -> [`init::setup_pid1`] -> UI poll loop in [`run_app`].

extern crate libc;

#[cfg(test)]
extern crate std;

mod console;
mod fb;
mod hw;
mod init;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

// Entered via musl's crt1.o `_start` -> `main`.
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn main(_argc: libc::c_int, _argv: *const *const libc::c_char) -> libc::c_int {
    run_app();
    0
}

pub(crate) const LOG_LINE_CAP: usize = 128;
#[cfg(not(test))]
const PANIC_EXIT_CODE: libc::c_int = 101;

pub(crate) fn raw_write(fd: libc::c_int, msg: &str) {
    unsafe {
        libc::write(fd, msg.as_ptr() as *const libc::c_void, msg.len());
    }
}

pub(crate) fn raw_print(msg: &str) {
    raw_write(1, msg);
}

pub(crate) fn print_fmt(args: core::fmt::Arguments) {
    use core::fmt::Write;
    let mut buf: heapless::String<LOG_LINE_CAP> = heapless::String::new();
    let _ = buf.write_fmt(args);
    raw_print(&buf);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    struct StderrWriter;
    impl core::fmt::Write for StderrWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            raw_write(2, s);
            Ok(())
        }
    }
    let mut writer = StderrWriter;
    let _ = writeln!(writer, "PANIC: {}", info);
    unsafe {
        libc::exit(PANIC_EXIT_CODE);
    }
}

use embedded_graphics::{
    geometry::{Point, Size},
    pixelcolor::Rgb565,
    primitives::Rectangle,
};
use embedded_graphics_framebuf::FrameBuf;
use fb::FramebufferWriter;
use trillby_core::{UiEvent, UiState, POLL_TIMEOUT_MS};
use trillby_ui::{
    eg_rect_to_core, LayoutZones, ScreenPixels, UiRenderer, SCREEN_HEIGHT, SCREEN_PIXELS,
    SCREEN_WIDTH,
};

pub(crate) type AppState = UiState<256>;

type Frame = ScreenPixels;
static mut FRAME: Frame = [Rgb565::new(0, 0, 0); SCREEN_PIXELS];

pub(crate) struct BufferWriter<'a> {
    buf: &'a mut [u8],
    pub(crate) offset: usize,
}

impl<'a> BufferWriter<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }
}

impl<'a> core::fmt::Write for BufferWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let rem = self.buf.len().saturating_sub(self.offset);
        let mut n = s.len().min(rem);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.offset..self.offset + n].copy_from_slice(&s.as_bytes()[..n]);
        self.offset += n;
        if n < s.len() {
            Err(core::fmt::Error)
        } else {
            Ok(())
        }
    }
}


const HEARTBEAT_INTERVAL_MS: u64 = 10_000;
/// Placeholder battery percentage (no battery sensor hardware wired).
const PLACEHOLDER_BATTERY_PCT: u8 = 100;
/// Placeholder RSSI value in dBm (no physical wireless RSSI reader wired).
const PLACEHOLDER_RSSI_DBM: i8 = -45;
const MS_PER_S: u64 = 1000;

fn warn_on_enqueue_err(what: &str, r: Result<(), trillby_net::OutboxError>) {
    if let Err(e) = r {
        print_fmt(format_args!("WARN: failed to enqueue {what}: {e:?}\n"));
    }
}

fn present(renderer: &UiRenderer, buffer: &mut Frame, fb: &mut FramebufferWriter, state: &AppState) {
    let mut framebuffer = FrameBuf::new(&mut *buffer, SCREEN_WIDTH as usize, SCREEN_HEIGHT as usize);
    let _ = renderer.render(&mut framebuffer, state);
    fb.write_frame(buffer);
}

fn load_provisioning() -> trillby_net::DeviceProvisioning {
    trillby_net::DeviceProvisioning::load_from_file(trillby_net::DEFAULT_PATH).unwrap_or_else(|_| {
        raw_print("NOTICE: /etc/trillby/device.key not found; using fallback dev credentials\n");
        trillby_net::DeviceProvisioning::dev_fallback(hw::default_server_ip())
    })
}

fn forward_session_events(state: &mut AppState, net_client: &mut trillby_net::NetClient<32>, now_ms: u64) {
    while let Some(ev) = state.pop_session_event() {
        warn_on_enqueue_err("session event", net_client.send_session_event(&ev, now_ms));
    }
}

fn maybe_send_heartbeat(
    net_client: &mut trillby_net::NetClient<32>,
    last_heartbeat_ms: &mut u64,
    now_ms: u64,
) {
    if now_ms.saturating_sub(*last_heartbeat_ms) >= HEARTBEAT_INTERVAL_MS
        && net_client.state() == trillby_net::ClientState::Online
    {
        *last_heartbeat_ms = now_ms;
        let hb = trillby_net::HeartbeatPayload {
            battery_pct: PLACEHOLDER_BATTERY_PCT,
            rssi: PLACEHOLDER_RSSI_DBM,
            pending_outbox: net_client.outbox_pending_count() as u16,
            uptime_s: (now_ms / MS_PER_S) as u32,
        };
        let _ = net_client.send_payload(&hb);
    }
}

#[cfg_attr(test, allow(dead_code))]
fn run_app() {
    init::setup_pid1();

    raw_print("====================================================\n");
    raw_print(" Trillby Handheld Scanner — #![no_std] UI Engine\n");
    raw_print(" Mode: Zero-Allocation POSIX Poll Loop (800x480)\n");
    raw_print(" Architecture: Multi-Crate Workspace (core/ui/bin)\n");
    raw_print("====================================================\n");

    let screen_bounds = Rectangle::new(Point::zero(), Size::new(SCREEN_WIDTH, SCREEN_HEIGHT));

    let mut state = AppState::new();
    let renderer = UiRenderer::new(screen_bounds);
    let mut fb_writer = FramebufferWriter::new();
    let buffer: &'static mut Frame = unsafe { &mut *core::ptr::addr_of_mut!(FRAME) };

    // Initial render pass
    present(&renderer, buffer, &mut fb_writer, &state);

    // Load provisioned device credentials from /etc/trillby/device.key (with fallback for dev/sim)
    let provisioning = load_provisioning();

    let mut net_client: trillby_net::NetClient<32> = trillby_net::NetClient::new(
        provisioning.psk,
        provisioning.device_uuid,
        provisioning.server_ip,
        provisioning.server_port,
    );

    let mut hw = hw::Hardware::new();
    let mut last_heartbeat_ms: u64 = 0;

    // Single-threaded zero-allocation POSIX poll loop with centralized timeout
    loop {
        let mut poll_set = hw::PollSet::new();

        hw.register_poll(&mut poll_set);

        let net_fd = net_client.socket_fd();
        let net_poll_idx = if net_fd >= 0 {
            let events = net_client.poll_events();
            Some(poll_set.push(net_fd, events))
        } else {
            None
        };

        let ret = unsafe {
            libc::poll(
                poll_set.as_mut_slice().as_mut_ptr(),
                poll_set.len() as libc::nfds_t,
                POLL_TIMEOUT_MS,
            )
        };
        let now_ms = trillby_net::monotonic_ms();
        state.set_now_ms(now_ms);
        let zones = LayoutZones::compute(screen_bounds, state.keyboard_visible);

        let net_revents = net_poll_idx.map_or(0, |idx| poll_set.revents(idx));

        if ret > 0 {
            hw.handle_poll(
                poll_set.as_slice(),
                &mut state,
                &zones,
            );
        }

        // Drain pending session events generated during UI event handling into network outbox
        forward_session_events(&mut state, &mut net_client, now_ms);

        // Network step: drive connection state machine and outbox transmission
        if let Some(new_status) = net_client.poll_step(now_ms, net_revents) {
            let kb_bounds = zones.keyboard_area.map(eg_rect_to_core);
            state.handle_event(UiEvent::NetworkStatusChanged(new_status), kb_bounds, None);
        }
        state.pending_outbox_count = net_client.outbox_pending_count() as u16;

        // Periodic heartbeat telemetry when online (monotonic timing)
        maybe_send_heartbeat(&mut net_client, &mut last_heartbeat_ms, now_ms);

        // Repaint framebuffer only when state is marked dirty
        if state.dirty || !fb_writer.is_bound() {
            present(&renderer, buffer, &mut fb_writer, &state);
            state.dirty = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;
    use trillby_core::NetworkStatus;

    #[test]
    fn test_buffer_writer_exact_fill() {
        let mut buf = [0u8; 5];
        let mut w = BufferWriter::new(&mut buf);
        let _ = write!(w, "hello");
        assert_eq!(w.offset, 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_buffer_writer_multi_write_chaining() {
        let mut buf = [0u8; 10];
        let mut w = BufferWriter::new(&mut buf);
        let _ = write!(w, "foo");
        let _ = write!(w, "bar");
        let _ = write!(w, "12");
        assert_eq!(w.offset, 8);
        assert_eq!(&buf[..8], b"foobar12");
    }

    #[test]
    fn test_buffer_writer_overflow_clamping() {
        let mut buf = [0u8; 5];
        let mut w = BufferWriter::new(&mut buf);
        let _ = write!(w, "hello world");
        assert_eq!(w.offset, 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_buffer_writer_utf8_truncation_does_not_split_codepoint() {
        let mut buf = [0u8; 4];
        let offset = {
            let mut w = BufferWriter::new(&mut buf);
            let _ = write!(w, "aé🦀");
            w.offset
        };
        assert!(
            core::str::from_utf8(&buf[..offset]).is_ok(),
            "truncated buffer must contain valid UTF-8, got invalid slice at offset {}",
            offset
        );
    }


    #[test]
    fn test_raw_write_to_pipe() {
        let mut fds = [0; 2];
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) };
        assert_eq!(rc, 0);
        raw_write(fds[1], "hello pipe");
        let mut read_buf = [0u8; 32];
        let n = unsafe { libc::read(fds[0], read_buf.as_mut_ptr() as *mut libc::c_void, read_buf.len()) };
        assert_eq!(n, 10);
        assert_eq!(&read_buf[..10], b"hello pipe");
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }


    #[test]
    fn test_forward_session_events() {
        let mut state = AppState::new();
        state.handle_event(UiEvent::RfidScanned(heapless::String::try_from("OP1").unwrap()), None, None);
        let mut net_client = trillby_net::NetClient::<32>::new([0u8; 32], [0u8; 16], [127, 0, 0, 1], 9999);
        assert_eq!(net_client.outbox_pending_count(), 0);
        forward_session_events(&mut state, &mut net_client, 1000);
        assert_eq!(state.pop_session_event(), None);
        assert_eq!(net_client.outbox_pending_count(), 1);
    }

    #[test]
    fn maybe_send_heartbeat_requires_online_and_interval() {
        let mut net_client = trillby_net::NetClient::<32>::new([0u8; 32], [0u8; 16], [127, 0, 0, 1], 9999);
        let mut last_heartbeat_ms = 0;
        // Not online, so should not send heartbeat
        maybe_send_heartbeat(&mut net_client, &mut last_heartbeat_ms, 10_000);
        assert_eq!(last_heartbeat_ms, 0);
        assert_eq!(net_client.outbox_pending_count(), 0);

        let mut server = trillby_net::NetServer::<2>::bind([127, 0, 0, 1], 0).unwrap();
        let port = server.port();
        let psk = [7u8; 32];
        let uuid = [9u8; 16];
        let mut client = trillby_net::NetClient::<32>::new(psk, uuid, [127, 0, 0, 1], port);
        let mut now_ms = 1000u64;
        let resolver = |id: &[u8; 16]| if *id == uuid { Some(psk) } else { None };
        for _ in 0..50 {
            now_ms += 10;
            client.wait_and_step_with(now_ms, 10, |_, _| {});
            server.step(now_ms, resolver, |_| {});
            if client.status() == NetworkStatus::Online {
                break;
            }
        }
        assert_eq!(client.status(), NetworkStatus::Online);

        let mut last = 0;
        let base = client.outbox_pending_count();
        maybe_send_heartbeat(&mut client, &mut last, 9_999);
        assert_eq!(client.outbox_pending_count(), base);
        assert_eq!(last, 0);

        maybe_send_heartbeat(&mut client, &mut last, 10_000);
        assert_eq!(client.outbox_pending_count(), base + 1);
        assert_eq!(last, 10_000);

        maybe_send_heartbeat(&mut client, &mut last, 19_999);
        assert_eq!(client.outbox_pending_count(), base + 1);
        assert_eq!(last, 10_000);

        maybe_send_heartbeat(&mut client, &mut last, 20_000);
        assert_eq!(client.outbox_pending_count(), base + 2);
        assert_eq!(last, 20_000);
    }
}
