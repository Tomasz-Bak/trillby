#![no_std]
#![cfg_attr(not(test), no_main)]
#![allow(dead_code)]

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


#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    struct StderrWriter;
    impl core::fmt::Write for StderrWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            unsafe {
                libc::write(2, s.as_ptr() as *const _, s.len());
            }
            Ok(())
        }
    }
    let mut writer = StderrWriter;
    let _ = write!(writer, "PANIC: {}\n", info);
    unsafe {
        libc::exit(101);
    }
}

use embedded_graphics::{
    geometry::{Point, Size},
    pixelcolor::Rgb565,
    primitives::Rectangle,
};
use embedded_graphics_framebuf::FrameBuf;
use fb::FramebufferWriter;
use trillby_core::{SessionEvent, UiEvent, UiState, POLL_TIMEOUT_MS};
use trillby_ui::{eg_rect_to_core, LayoutZones, UiRenderer};

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

pub(crate) fn raw_print(msg: &str) {
    unsafe {
        libc::write(1, msg.as_ptr() as *const _, msg.len());
    }
}


fn run_app() {
    init::setup_pid1();

    raw_print("====================================================\n");
    raw_print(" Trillby Handheld Scanner — #![no_std] UI Engine\n");
    raw_print(" Mode: Zero-Allocation POSIX Poll Loop (800x480)\n");
    raw_print(" Architecture: Multi-Crate Workspace (core/ui/bin)\n");
    raw_print("====================================================\n");

    let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
    let core_bounds = eg_rect_to_core(screen_bounds);

    let mut state: UiState<256> = UiState::new();
    let renderer = UiRenderer::new(screen_bounds);
    let mut fb_writer = FramebufferWriter::new();
    let mut buffer = [Rgb565::new(0, 0, 0); 800 * 480];

    // Initial render pass
    {
        let mut framebuffer = FrameBuf::new(&mut buffer, 800, 480);
        let _ = renderer.render(&mut framebuffer, &state);
    }
    fb_writer.write_frame(&buffer);

    // Load provisioned device credentials from /etc/trillby/device.key (with fallback for dev/sim)
    let provisioning = trillby_net::DeviceProvisioning::load_from_file("/etc/trillby/device.key")
        .unwrap_or_else(|_| {
            raw_print("NOTICE: /etc/trillby/device.key not found; using fallback dev credentials\n");
            trillby_net::DeviceProvisioning {
                psk: [0x42u8; 32],
                device_uuid: [
                    0x54, 0x52, 0x49, 0x4C, 0x4C, 0x42, 0x59, 0x5F,
                    0x30, 0x30, 0x30, 0x31, 0x00, 0x00, 0x00, 0x00,
                ],
                server_ip: hw::default_server_ip(),
                server_port: 8088,
            }
        });

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
        let mut pollfds: [libc::pollfd; 16] = unsafe { core::mem::zeroed() };
        let mut poll_count = 0;

        hw.register_poll(&mut pollfds, &mut poll_count);

        let net_fd = net_client.socket_fd();
        let mut net_poll_idx: i32 = -1;
        if net_fd >= 0 {
            let mut events = libc::POLLIN;
            if net_client.wants_write() {
                events |= libc::POLLOUT;
            }
            net_poll_idx = poll_count as i32;
            pollfds[poll_count] = libc::pollfd { fd: net_fd, events, revents: 0 };
            poll_count += 1;
        }

        let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), poll_count as libc::nfds_t, POLL_TIMEOUT_MS) };
        let now_ms = trillby_net::monotonic_ms();
        let zones = LayoutZones::compute(screen_bounds, state.keyboard_visible);
        let core_kb_bounds = zones.keyboard_area.map(eg_rect_to_core);

        let net_revents = if net_poll_idx >= 0 {
            pollfds[net_poll_idx as usize].revents
        } else {
            0
        };

        if ret == 0 {
            // 50ms Timeout -> send 20Hz Tick event
            state.handle_event(UiEvent::Tick, core_bounds, core_kb_bounds, None);
        } else if ret > 0 {
            hw.handle_poll(
                &pollfds[..poll_count],
                &mut state,
                &zones,
                core_bounds,
                core_kb_bounds,
            );
        }

        // Drain pending session events generated during UI event handling into network outbox
        while let Some(ev) = state.pop_session_event() {
            match ev {
                SessionEvent::OperatorLogin { operator_id, .. } => {
                    let op_bytes = operator_id.as_bytes();
                    let len = op_bytes.len().min(32);
                    let mut payload = trillby_net::AuthInitPayload {
                        auth_data_len: len as u8,
                        auth_data: [0u8; 32],
                        timestamp_ms: now_ms,
                    };
                    payload.auth_data[..len].copy_from_slice(&op_bytes[..len]);
                    let _ = net_client.send_auth(&payload);
                }
                SessionEvent::OperatorLogout { operator_id, .. } => {
                    let _ = net_client.send_work_event(
                        &trillby_net::WorkEventPayload::operator_logout(
                            operator_id.as_bytes(),
                            now_ms,
                        ),
                    );
                }
                SessionEvent::WorkStart { operator_id, job_id, .. } => {
                    let _ = net_client.send_work_event(
                        &trillby_net::WorkEventPayload::work_start(
                            operator_id.as_bytes(),
                            job_id.as_bytes(),
                            now_ms,
                        ),
                    );
                }
                SessionEvent::WorkStop { operator_id, job_id, duration_ms, .. } => {
                    let _ = net_client.send_work_event(
                        &trillby_net::WorkEventPayload::work_stop(
                            operator_id.as_bytes(),
                            job_id.as_bytes(),
                            now_ms,
                            duration_ms,
                        ),
                    );
                }
            }
        }

        // Network step: drive connection state machine and outbox transmission
        if let Some(new_status) = net_client.poll_step(now_ms, net_revents) {
            state.handle_event(UiEvent::NetworkStatusChanged(new_status), core_bounds, core_kb_bounds, None);
        }
        state.pending_outbox_count = net_client.outbox_pending_count() as u16;

        // Periodic 10-second heartbeat telemetry when online (monotonic timing)
        if now_ms.saturating_sub(last_heartbeat_ms) >= 10_000 && net_client.state() == trillby_net::ClientState::Online {
            last_heartbeat_ms = now_ms;
            let hb = trillby_net::HeartbeatPayload {
                battery_pct: 100,
                rssi: -45,
                pending_outbox: net_client.outbox_pending_count() as u16,
                uptime_s: (now_ms / 1000) as u32,
            };
            let _ = net_client.send_heartbeat(&hb);
        }

        // Repaint framebuffer only when state is marked dirty
        if state.dirty || fb_writer.fd < 0 {
            let mut framebuffer = FrameBuf::new(&mut buffer, 800, 480);
            let _ = renderer.render(&mut framebuffer, &state);
            fb_writer.write_frame(&buffer);
            state.dirty = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

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
}
