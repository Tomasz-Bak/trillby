//! QEMU simulation device adapter (`/dev/ttyAMA0` command injection, SLIRP
//! network setup, and `virtio-tablet` coordinate scaling).

use crate::{raw_print, BufferWriter};
use core::fmt::Write;
use embedded_graphics::geometry::Point;
use trillby_core::{Point as CorePoint, Rect, UiEvent, UiState};
use trillby_ui::{KeyboardGrid, LayoutZones};

const QEMU_RAW_MAX_X: i64 = ((32767 * 340) / 800) * 2; // 27850
const QEMU_RAW_MAX_Y: i64 = ((32767 * 222) / 480) * 2; // 30308

pub fn configure_network() {
    crate::init::configure_ipv4_iface(c"eth0", [10, 0, 2, 15], [255, 255, 255, 0]);
}

pub fn default_server_ip() -> [u8; 4] {
    if unsafe { libc::getpid() } == 1 {
        [10, 0, 2, 2] // QEMU SLIRP host gateway when running as guest PID 1
    } else {
        [127, 0, 0, 1]
    }
}

pub struct DeviceAdapter {
    tty_fd: libc::c_int,
    touch_max_x: i64,
    touch_max_y: i64,
    serial_line_buf: [u8; 128],
    serial_line_len: usize,
}

impl DeviceAdapter {
    pub fn new() -> Self {
        let tty_fd = unsafe {
            libc::open(
                b"/dev/ttyAMA0\0".as_ptr() as *const _,
                libc::O_RDONLY | libc::O_NONBLOCK,
            )
        };
        if tty_fd >= 0 {
            raw_print("Serial stdin listener enabled on /dev/ttyAMA0\n");
            raw_print("  Commands: rfid <id> | barcode <code> | type <text> | click <x> <y> | scale <max_x> <max_y>\n");
        }

        Self {
            tty_fd,
            touch_max_x: QEMU_RAW_MAX_X,
            touch_max_y: QEMU_RAW_MAX_Y,
            serial_line_buf: [0u8; 128],
            serial_line_len: 0,
        }
    }

    pub fn register_poll(&self, pollfds: &mut [libc::pollfd], poll_count: &mut usize) {
        if self.tty_fd >= 0 {
            pollfds[*poll_count] = libc::pollfd {
                fd: self.tty_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            *poll_count += 1;
        }
    }

    pub fn handle_fd(
        &mut self,
        pfd: &libc::pollfd,
        state: &mut UiState<256>,
        zones: &LayoutZones,
        core_bounds: Rect,
        core_kb_bounds: Option<Rect>,
    ) -> bool {
        if self.tty_fd < 0 || pfd.fd != self.tty_fd {
            return false;
        }

        let mut read_buf = [0u8; 64];
        let n = unsafe {
            libc::read(
                self.tty_fd,
                read_buf.as_mut_ptr() as *mut _,
                read_buf.len(),
            )
        };
        if n > 0 {
            for &b in &read_buf[..n as usize] {
                if b == b'\n' || b == b'\r' {
                    if self.serial_line_len > 0 {
                        if let Ok(line) =
                            core::str::from_utf8(&self.serial_line_buf[..self.serial_line_len])
                        {
                            let trimmed = line.trim();
                            if let Some(rest) = trimmed.strip_prefix("rfid ") {
                                if let Ok(id) = heapless::String::try_from(rest) {
                                    state.handle_event(
                                        UiEvent::RfidScanned(id),
                                        core_bounds,
                                        core_kb_bounds,
                                        None,
                                    );
                                }
                            } else if let Some(rest) = trimmed.strip_prefix("barcode ") {
                                if let Ok(data) = heapless::String::try_from(rest) {
                                    state.handle_event(
                                        UiEvent::BarcodeScanned(data),
                                        core_bounds,
                                        core_kb_bounds,
                                        None,
                                    );
                                }
                            } else if let Some(rest) = trimmed.strip_prefix("type ") {
                                for c in rest.chars() {
                                    state.apply_key(trillby_core::Key::Char(c));
                                }
                                state.dirty = true;
                            } else if let Some(rest) = trimmed.strip_prefix("scale ") {
                                let mut parts = rest.split_whitespace();
                                if let (Some(mx_str), Some(my_str)) = (parts.next(), parts.next()) {
                                    if let (Ok(mx), Ok(my)) =
                                        (mx_str.parse::<i64>(), my_str.parse::<i64>())
                                    {
                                        if mx > 0 && my > 0 {
                                            self.touch_max_x = mx;
                                            self.touch_max_y = my;
                                            let mut log_buf = [0u8; 96];
                                            let mut w = BufferWriter::new(&mut log_buf);
                                            let _ = write!(
                                                w,
                                                "[TOUCH] scale max updated -> ({}, {})\n",
                                                self.touch_max_x, self.touch_max_y
                                            );
                                            let len = w.offset;
                                            if let Ok(s) = core::str::from_utf8(&log_buf[..len]) {
                                                raw_print(s);
                                            }
                                        }
                                    }
                                }
                            } else if let Some(rest) = trimmed.strip_prefix("click ") {
                                let mut parts = rest.split_whitespace();
                                if let (Some(x_str), Some(y_str)) = (parts.next(), parts.next()) {
                                    if let (Ok(x), Ok(y)) =
                                        (x_str.parse::<i32>(), y_str.parse::<i32>())
                                    {
                                        let eg_pt = Point::new(x, y);
                                        let core_pt = CorePoint::new(x, y);
                                        let key = zones.keyboard_area.and_then(|kb| {
                                            KeyboardGrid::resolve_key(
                                                kb,
                                                eg_pt,
                                                state.keyboard_layer,
                                            )
                                        });

                                        state.handle_event(
                                            UiEvent::TouchDown {
                                                scaled: core_pt,
                                                raw: (x, y),
                                            },
                                            core_bounds,
                                            core_kb_bounds,
                                            key,
                                        );
                                        state.handle_event(
                                            UiEvent::TouchUp {
                                                scaled: core_pt,
                                                raw: (x, y),
                                            },
                                            core_bounds,
                                            core_kb_bounds,
                                            None,
                                        );
                                    }
                                }
                            }
                        }
                        self.serial_line_len = 0;
                    }
                } else if self.serial_line_len < self.serial_line_buf.len() {
                    self.serial_line_buf[self.serial_line_len] = b;
                    self.serial_line_len += 1;
                }
            }
        }

        true
    }

    pub fn scale_touch(&self, raw_x: i32, raw_y: i32) -> Point {
        let mx = self.touch_max_x.max(1);
        let my = self.touch_max_y.max(1);
        let x = (raw_x.clamp(0, mx as i32) as i64 * 800 / mx) as i32;
        let y = (raw_y.clamp(0, my as i32) as i64 * 480 / my) as i32;
        Point::new(x.clamp(0, 799), y.clamp(0, 479))
    }

    pub fn log_touch_down(&self, raw_x: i32, raw_y: i32, scaled: CorePoint) {
        let mut log_buf = [0u8; 128];
        let mut w = BufferWriter::new(&mut log_buf);
        let _ = write!(
            w,
            "[TOUCH] raw=({}, {}) scaled=({}, {}) max=({}, {})\n",
            raw_x, raw_y, scaled.x, scaled.y, self.touch_max_x, self.touch_max_y
        );
        let len = w.offset;
        if let Ok(s) = core::str::from_utf8(&log_buf[..len]) {
            raw_print(s);
        }
    }
}
