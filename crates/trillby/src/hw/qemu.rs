//! QEMU simulation device adapter (`/dev/ttyAMA0` command injection, SLIRP
//! network setup, and `virtio-tablet` coordinate scaling).

use crate::raw_print;
use embedded_graphics::geometry::Point;
use trillby_core::{Point as CorePoint, UiEvent};
use trillby_ui::{LayoutZones, SCREEN_HEIGHT, SCREEN_WIDTH};

fn parse_pair<T: core::str::FromStr>(rest: &str) -> Option<(T, T)> {
    let mut parts = rest.split_whitespace();
    let first = parts.next()?.parse().ok()?;
    let second = parts.next()?.parse().ok()?;
    Some((first, second))
}

#[derive(Debug, PartialEq, Eq)]
enum SerialCommand<'a> {
    Rfid(&'a str),
    Barcode(&'a str),
    Type(&'a str),
    Scale(i32, i32),
    Click(i32, i32),
}

impl<'a> SerialCommand<'a> {
    fn parse(line: &'a str) -> Option<Self> {
        let (cmd, rest) = line.trim().split_once(' ')?;
        match cmd {
            "rfid" => Some(SerialCommand::Rfid(rest)),
            "barcode" => Some(SerialCommand::Barcode(rest)),
            "type" => Some(SerialCommand::Type(rest)),
            "scale" => {
                let (mx, my) = parse_pair(rest)?;
                if mx > 0 && my > 0 {
                    Some(SerialCommand::Scale(mx, my))
                } else {
                    None
                }
            }
            "click" => {
                let (x, y) = parse_pair(rest)?;
                Some(SerialCommand::Click(x, y))
            }
            _ => None,
        }
    }
}

/// QEMU virtio-tablet empirical coordinate scaling calibration factors
const TABLET_CALIB_X: i64 = 340;
const TABLET_CALIB_Y: i64 = 222;

const QEMU_RAW_MAX_X: i64 = ((super::evdev::RAW_AXIS_MAX as i64 * TABLET_CALIB_X) / SCREEN_WIDTH as i64) * 2; // 27850
const QEMU_RAW_MAX_Y: i64 = ((super::evdev::RAW_AXIS_MAX as i64 * TABLET_CALIB_Y) / SCREEN_HEIGHT as i64) * 2; // 30308

const SLIRP_GUEST_IP: [u8; 4] = [10, 0, 2, 15];
const SLIRP_NETMASK: [u8; 4] = [255, 255, 255, 0];
const SLIRP_HOST_IP: [u8; 4] = [10, 0, 2, 2];

pub fn configure_network() {
    crate::init::configure_ipv4_iface(c"eth0", SLIRP_GUEST_IP, SLIRP_NETMASK);
}

pub fn default_server_ip() -> [u8; 4] {
    if crate::init::is_pid1() {
        SLIRP_HOST_IP // QEMU SLIRP host gateway when running as guest PID 1
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
    pub(crate) fn with_tty_fd(tty_fd: libc::c_int) -> Self {
        Self {
            tty_fd,
            touch_max_x: QEMU_RAW_MAX_X,
            touch_max_y: QEMU_RAW_MAX_Y,
            serial_line_buf: [0u8; 128],
            serial_line_len: 0,
        }
    }

    pub fn new() -> Self {
        let tty_fd = unsafe {
            libc::open(
                c"/dev/ttyAMA0".as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK,
            )
        };
        if tty_fd >= 0 {
            raw_print("Serial stdin listener enabled on /dev/ttyAMA0\n");
            raw_print("  Commands: rfid <id> | barcode <code> | type <text> | click <x> <y> | scale <max_x> <max_y>\n");
        }

        Self::with_tty_fd(tty_fd)
    }

    pub fn register_poll(&self, poll_set: &mut super::PollSet) {
        if self.tty_fd >= 0 {
            poll_set.push(self.tty_fd, libc::POLLIN);
        }
    }

    pub fn drop_fd(&mut self, fd: libc::c_int) -> bool {
        if self.tty_fd >= 0 && fd == self.tty_fd {
            unsafe { libc::close(self.tty_fd) };
            self.tty_fd = -1;
            crate::print_fmt(format_args!("WARN: input fd {} hung up; closed\n", fd));
            true
        } else {
            false
        }
    }

    fn push_serial_byte(&mut self, b: u8) -> Option<([u8; 128], usize)> {
        if b == b'\n' || b == b'\r' {
            if self.serial_line_len > 0 {
                let mut line_buf = [0u8; 128];
                let len = self.serial_line_len;
                line_buf[..len].copy_from_slice(&self.serial_line_buf[..len]);
                self.serial_line_len = 0;
                return Some((line_buf, len));
            }
        } else if self.serial_line_len < self.serial_line_buf.len() {
            self.serial_line_buf[self.serial_line_len] = b;
            self.serial_line_len += 1;
        }
        None
    }

    pub fn handle_serial_line(
        &mut self,
        line: &str,
        state: &mut crate::AppState,
        zones: &LayoutZones,
    ) {
        if let Some(cmd) = SerialCommand::parse(line) {
            self.execute_command(cmd, state, zones);
        }
    }

    pub fn handle_fd(
        &mut self,
        pfd: &libc::pollfd,
        state: &mut crate::AppState,
        zones: &LayoutZones,
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
        if n < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno != libc::EAGAIN && errno != libc::EINTR {
                self.drop_fd(self.tty_fd);
            }
        } else if n > 0 {
            for &b in &read_buf[..n as usize] {
                if let Some((line_buf, len)) = self.push_serial_byte(b) {
                    if let Ok(line) = core::str::from_utf8(&line_buf[..len]) {
                        self.handle_serial_line(line, state, zones);
                    }
                }
            }
        }

        true
    }

    fn execute_command(
        &mut self,
        cmd: SerialCommand<'_>,
        state: &mut crate::AppState,
        zones: &LayoutZones,
    ) {
        match cmd {
            SerialCommand::Rfid(rest) => {
                if let Ok(id) = heapless::String::try_from(rest) {
                    let kb_bounds = zones.keyboard_area.map(trillby_ui::eg_rect_to_core);
                    state.handle_event(
                        UiEvent::RfidScanned(id),
                        kb_bounds,
                        None,
                    );
                }
            }
            SerialCommand::Barcode(rest) => {
                if let Ok(data) = heapless::String::try_from(rest) {
                    let kb_bounds = zones.keyboard_area.map(trillby_ui::eg_rect_to_core);
                    state.handle_event(
                        UiEvent::BarcodeScanned(data),
                        kb_bounds,
                        None,
                    );
                }
            }
            SerialCommand::Type(rest) => {
                for c in rest.chars() {
                    state.apply_key(trillby_core::Key::Char(c));
                }
                state.dirty = true;
            }
            SerialCommand::Scale(mx, my) => {
                self.touch_max_x = i64::from(mx);
                self.touch_max_y = i64::from(my);
                crate::print_fmt(format_args!(
                    "[TOUCH] scale max updated -> ({}, {})\n",
                    self.touch_max_x, self.touch_max_y
                ));
            }
            SerialCommand::Click(x, y) => {
                let core_pt = CorePoint::new(x, y);
                trillby_ui::dispatch_touch(
                    state,
                    zones,
                    UiEvent::TouchDown {
                        scaled: core_pt,
                        raw: (x, y),
                    },
                );
                trillby_ui::dispatch_touch(
                    state,
                    zones,
                    UiEvent::TouchUp {
                        scaled: core_pt,
                        raw: (x, y),
                    },
                );
            }
        }
    }

    pub fn scale_touch(&self, raw_x: i32, raw_y: i32) -> Point {
        let mx = self.touch_max_x.max(1);
        let my = self.touch_max_y.max(1);
        let x = (raw_x.clamp(0, mx as i32) as i64 * SCREEN_WIDTH as i64 / mx) as i32;
        let y = (raw_y.clamp(0, my as i32) as i64 * SCREEN_HEIGHT as i64 / my) as i32;
        Point::new(
            x.clamp(0, SCREEN_WIDTH as i32 - 1),
            y.clamp(0, SCREEN_HEIGHT as i32 - 1),
        )
    }

    pub fn log_touch_down(&self, raw_x: i32, raw_y: i32, scaled: CorePoint) {
        crate::print_fmt(format_args!(
            "[TOUCH] raw=({}, {}) scaled=({}, {}) max=({}, {})\n",
            raw_x, raw_y, scaled.x, scaled.y, self.touch_max_x, self.touch_max_y
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hw::test_util::{PipeFds, UiFixture};
    use trillby_core::SessionState;

    #[test]
    fn test_qemu_scale_touch_boundaries_and_clamping() {
        let adapter = DeviceAdapter::with_tty_fd(-1);

        assert_eq!(adapter.scale_touch(0, 0), Point::new(0, 0));
        assert_eq!(
            adapter.scale_touch(QEMU_RAW_MAX_X as i32, QEMU_RAW_MAX_Y as i32),
            Point::new(SCREEN_WIDTH as i32 - 1, SCREEN_HEIGHT as i32 - 1)
        );
        assert_eq!(adapter.scale_touch(-100, -200), Point::new(0, 0));
        assert_eq!(
            adapter.scale_touch(50_000, 60_000),
            Point::new(SCREEN_WIDTH as i32 - 1, SCREEN_HEIGHT as i32 - 1)
        );
    }

    #[test]
    fn test_qemu_pipe_serial_commands_and_click_key_dispatch() {
        let pipe = PipeFds::new();
        let mut adapter = DeviceAdapter::with_tty_fd(pipe.rfd);
        let mut ui = UiFixture::new();

        let mut pfd = pipe.readable_pollfd();
        pfd.revents = libc::POLLIN;

        let send_cmd = |wfd: libc::c_int, cmd: &[u8]| {
            let n = unsafe { libc::write(wfd, cmd.as_ptr() as *const _, cmd.len()) };
            assert_eq!(n as usize, cmd.len());
        };

        // 1. Fragmented rfid read: write "rfid OP_" -> handle_fd -> write "77\r\n" -> handle_fd
        send_cmd(pipe.wfd, b"rfid OP_");
        adapter.handle_fd(&pfd, &mut ui.state, &ui.zones);
        assert_eq!(*ui.state.session_state(), SessionState::Idle);

        send_cmd(pipe.wfd, b"77\r\n");
        adapter.handle_fd(&pfd, &mut ui.state, &ui.zones);
        match ui.state.session_state() {
            SessionState::Authenticated { operator_id } => {
                assert_eq!(operator_id.as_str(), "OP_77");
            }
            other => panic!("expected Authenticated(OP_77), got: {:?}", other),
        }

        // 2. Barcode JOB_88\n -> starts job, auto-shows virtual keyboard
        ui.refresh();
        send_cmd(pipe.wfd, b"barcode JOB_88\n");
        adapter.handle_fd(&pfd, &mut ui.state, &ui.zones);
        match ui.state.session_state() {
            SessionState::Working { job_id, .. } => {
                assert_eq!(job_id.as_str(), "JOB_88");
            }
            other => panic!("expected Working(JOB_88), got: {:?}", other),
        }
        assert!(ui.state.keyboard_visible);

        // 3. Type AB\n -> appends "AB" to state.input_buffer
        ui.refresh();
        send_cmd(pipe.wfd, b"type AB\n");
        adapter.handle_fd(&pfd, &mut ui.state, &ui.zones);
        assert_eq!(ui.state.input_buffer.as_str(), "AB");

        // 4. Scale 1600 960\n -> updates touch_max_x = 1600, touch_max_y = 960
        send_cmd(pipe.wfd, b"scale 1600 960\n");
        adapter.handle_fd(&pfd, &mut ui.state, &ui.zones);
        assert_eq!(adapter.touch_max_x, 1600);
        assert_eq!(adapter.touch_max_y, 960);

        // Scale -1 500\n -> ignored
        send_cmd(pipe.wfd, b"scale -1 500\n");
        adapter.handle_fd(&pfd, &mut ui.state, &ui.zones);
        assert_eq!(adapter.touch_max_x, 1600);
        assert_eq!(adapter.touch_max_y, 960);

        // 5. Click 40 320\n (hits 'Q' on the visible Alpha virtual keyboard)
        ui.refresh();
        send_cmd(pipe.wfd, b"click 40 320\n");
        adapter.handle_fd(&pfd, &mut ui.state, &ui.zones);
        assert_eq!(
            ui.state.input_buffer.as_str(),
            "ABQ",
            "click on virtual key 'Q' must append 'Q' to input_buffer"
        );
        assert_eq!(
            ui.state.key_count,
            1,
            "click on virtual key 'Q' must increment key_count"
        );
    }

    #[test]
    fn test_scale_overflow_ignored() {
        let pipe = PipeFds::new();
        let mut adapter = DeviceAdapter::with_tty_fd(pipe.rfd);

        let mut ui = UiFixture::new();
        let mut pfd = pipe.readable_pollfd();
        pfd.revents = libc::POLLIN;

        let cmd = b"scale 4294967295 1\n";
        let n = unsafe { libc::write(pipe.wfd, cmd.as_ptr() as *const _, cmd.len()) };
        assert_eq!(n as usize, cmd.len());

        adapter.handle_fd(&pfd, &mut ui.state, &ui.zones);
        assert_eq!(adapter.touch_max_x, QEMU_RAW_MAX_X);
        assert_eq!(adapter.touch_max_y, QEMU_RAW_MAX_Y);
        let pt = adapter.scale_touch(100, 100);
        assert!(pt.x >= 0 && pt.y >= 0);
    }

    #[test]
    fn test_qemu_drop_fd() {
        let mut pipe = PipeFds::new();
        let rfd = pipe.rfd;

        let mut adapter = DeviceAdapter::with_tty_fd(rfd);

        assert!(!adapter.drop_fd(999));
        assert_eq!(adapter.tty_fd, rfd);
        assert!(adapter.drop_fd(rfd));
        assert_eq!(adapter.tty_fd, -1);
        assert!(!adapter.drop_fd(rfd));
        assert!(!adapter.drop_fd(999));
        pipe.rfd = -1;
    }

    #[test]
    fn test_serial_command_parse() {
        assert_eq!(SerialCommand::parse("rfid OP_123"), Some(SerialCommand::Rfid("OP_123")));
        assert_eq!(SerialCommand::parse("barcode JOB_456"), Some(SerialCommand::Barcode("JOB_456")));
        assert_eq!(SerialCommand::parse("type Hello"), Some(SerialCommand::Type("Hello")));
        assert_eq!(SerialCommand::parse("scale 1600 960"), Some(SerialCommand::Scale(1600, 960)));
        assert_eq!(SerialCommand::parse("scale 4294967295 1"), None);
        assert_eq!(SerialCommand::parse("scale 0 500"), None);
        assert_eq!(SerialCommand::parse("scale -1 500"), None);
        assert_eq!(SerialCommand::parse("click 40 320"), Some(SerialCommand::Click(40, 320)));
        assert_eq!(SerialCommand::parse("unknown cmd"), None);
    }

    #[test]
    fn test_parse_pair() {
        assert_eq!(parse_pair::<i32>("10 20"), Some((10, 20)));
        assert_eq!(parse_pair::<i32>("  10   20  "), Some((10, 20)));
        assert_eq!(parse_pair::<i32>("10"), None);
        assert_eq!(parse_pair::<i32>("10 bad"), None);
        assert_eq!(parse_pair::<i32>(""), None);
    }

    #[test]
    fn test_push_serial_byte() {
        let mut adapter = DeviceAdapter::with_tty_fd(-1);

        assert_eq!(adapter.push_serial_byte(b'a'), None);
        assert_eq!(adapter.push_serial_byte(b'b'), None);
        let res = adapter.push_serial_byte(b'\n');
        assert!(res.is_some());
        let (buf, len) = res.unwrap();
        assert_eq!(&buf[..len], b"ab");

        assert_eq!(adapter.push_serial_byte(b'\r'), None);
    }

    #[test]
    fn test_qemu_register_poll() {
        let adapter = DeviceAdapter::with_tty_fd(55);
        let mut poll_set = super::super::PollSet::new();
        adapter.register_poll(&mut poll_set);
        assert_eq!(poll_set.len(), 1);
        assert_eq!(poll_set.as_slice()[0].fd, 55);
        assert_eq!(poll_set.as_slice()[0].events, libc::POLLIN);
    }
}
