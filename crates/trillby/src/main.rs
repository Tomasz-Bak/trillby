#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate libc;

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
    prelude::RgbColor,
    primitives::Rectangle,
};
use embedded_graphics_framebuf::FrameBuf;
use trillby_core::{
    Point as CorePoint, UiEvent, UiState,
};
use trillby_ui::{
    eg_rect_to_core, KeyboardGrid, LayoutZones, UiRenderer,
};

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct InputEvent {
    pub time: libc::timeval,
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

struct BufferWriter<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> BufferWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }
}

impl<'a> core::fmt::Write for BufferWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let rem = self.buf.len().saturating_sub(self.offset);
        let to_copy = bytes.len().min(rem);
        self.buf[self.offset..self.offset + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.offset += to_copy;
        Ok(())
    }
}

fn raw_print(msg: &str) {
    unsafe {
        libc::write(1, msg.as_ptr() as *const _, msg.len());
    }
}

fn mount_pseudo_filesystems() {
    unsafe {
        if libc::getpid() == 1 {
            raw_print("Running as PID 1 — mounting pseudo-filesystems (/proc, /sys, /dev)...\n");
            let _ = libc::mkdir(b"/proc\0".as_ptr() as *const _, 0o755);
            let _ = libc::mkdir(b"/sys\0".as_ptr() as *const _, 0o755);
            let _ = libc::mkdir(b"/dev\0".as_ptr() as *const _, 0o755);

            let _ = libc::mount(
                b"proc\0".as_ptr() as *const _,
                b"/proc\0".as_ptr() as *const _,
                b"proc\0".as_ptr() as *const _,
                0,
                core::ptr::null(),
            );
            let _ = libc::mount(
                b"sysfs\0".as_ptr() as *const _,
                b"/sys\0".as_ptr() as *const _,
                b"sysfs\0".as_ptr() as *const _,
                0,
                core::ptr::null(),
            );
            let _ = libc::mount(
                b"devtmpfs\0".as_ptr() as *const _,
                b"/dev\0".as_ptr() as *const _,
                b"devtmpfs\0".as_ptr() as *const _,
                0,
                core::ptr::null(),
            );
        }
    }
}

fn scale_touch_point(raw_x: i32, raw_y: i32) -> Point {
    #[cfg(feature = "qemu-sim")]
    {
        // virtio-tablet-pci reports 0..32767 absolute range in QEMU simulation mode
        let x = (raw_x.clamp(0, 32767) as i64 * 800 / 32767) as i32;
        let y = (raw_y.clamp(0, 32767) as i64 * 480 / 32767) as i32;
        Point::new(x.clamp(0, 799), y.clamp(0, 479))
    }

    #[cfg(not(feature = "qemu-sim"))]
    {
        // Physical touchscreens report direct 1:1 pixel coordinates (0..799, 0..479)
        Point::new(raw_x.clamp(0, 799), raw_y.clamp(0, 479))
    }
}

#[repr(C)]
struct FbVarScreeninfo {
    xres: u32,
    yres: u32,
    xres_virtual: u32,
    yres_virtual: u32,
    xoffset: u32,
    yoffset: u32,
    bits_per_pixel: u32,
    _pad: [u8; 132],
}

struct FramebufferWriter {
    fd: libc::c_int,
    bpp: u32,
    bgrx_buf: [u8; 800 * 480 * 4],
    reported_error: bool,
}

impl FramebufferWriter {
    fn new() -> Self {
        Self {
            fd: -1,
            bpp: 16,
            bgrx_buf: [0u8; 800 * 480 * 4],
            reported_error: false,
        }
    }

    fn open_fb(&mut self) -> bool {
        if self.fd >= 0 {
            return true;
        }
        let fd = unsafe { libc::open(b"/dev/fb0\0".as_ptr() as *const _, libc::O_RDWR) };
        if fd >= 0 {
            let mut var_info: FbVarScreeninfo = unsafe { core::mem::zeroed() };
            let res = unsafe {
                libc::ioctl(fd, 0x4600, &mut var_info as *mut _ as *mut libc::c_void)
            };
            self.bpp = if res == 0 && (var_info.bits_per_pixel == 16 || var_info.bits_per_pixel == 32) {
                var_info.bits_per_pixel
            } else {
                16
            };
            self.fd = fd;
            self.reported_error = false;
            raw_print("SUCCESS: Framebuffer /dev/fb0 bound!\n");
            true
        } else {
            if !self.reported_error {
                raw_print("Waiting for /dev/fb0 to become available...\n");
                self.reported_error = true;
            }
            false
        }
    }

    fn write_frame(&mut self, buffer: &[Rgb565; 800 * 480]) {
        if !self.open_fb() {
            return;
        }
        unsafe {
            libc::lseek(self.fd, 0, libc::SEEK_SET);
        }

        let res = if self.bpp == 32 {
            for (i, pixel) in buffer.iter().enumerate() {
                let r = ((pixel.r() as u16 * 255) / 31) as u8;
                let g = ((pixel.g() as u16 * 255) / 63) as u8;
                let b = ((pixel.b() as u16 * 255) / 31) as u8;
                let base = i * 4;
                self.bgrx_buf[base] = b;
                self.bgrx_buf[base + 1] = g;
                self.bgrx_buf[base + 2] = r;
                self.bgrx_buf[base + 3] = 0xff;
            }
            unsafe {
                libc::write(self.fd, self.bgrx_buf.as_ptr() as *const _, self.bgrx_buf.len())
            }
        } else {
            let bytes_len = buffer.len() * core::mem::size_of::<Rgb565>();
            unsafe {
                libc::write(self.fd, buffer.as_ptr() as *const _, bytes_len)
            }
        };

        if res < 0 {
            unsafe { libc::close(self.fd); }
            self.fd = -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8) -> i32 {
    #[cfg(test)]
    {
        0
    }
    #[cfg(not(test))]
    {
        run_app();
        0
    }
}

fn run_app() {
    mount_pseudo_filesystems();

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

    // Prepare non-blocking POSIX poll descriptors
    let mut pollfds: [libc::pollfd; 12] = unsafe { core::mem::zeroed() };
    let mut poll_count = 0;

    #[cfg(feature = "qemu-sim")]
    let tty_fd = unsafe {
        libc::open(b"/dev/ttyAMA0\0".as_ptr() as *const _, libc::O_RDONLY | libc::O_NONBLOCK)
    };
    #[cfg(feature = "qemu-sim")]
    if tty_fd >= 0 {
        pollfds[poll_count] = libc::pollfd { fd: tty_fd, events: libc::POLLIN, revents: 0 };
        poll_count += 1;
        raw_print("Serial stdin listener enabled on /dev/ttyAMA0\n");
    }

    // Open evdev devices (/dev/input/event0 .. event9)
    let mut evdev_fds: [libc::c_int; 10] = [-1; 10];
    let mut evdev_cnt = 0;

    for i in 0..10 {
        let mut path_buf = [0u8; 32];
        use core::fmt::Write;
        let mut w = BufferWriter::new(&mut path_buf);
        let _ = write!(w, "/dev/input/event{}\0", i);

        let fd = unsafe { libc::open(path_buf.as_ptr() as *const _, libc::O_RDONLY | libc::O_NONBLOCK) };
        if fd >= 0 {
            evdev_fds[evdev_cnt] = fd;
            evdev_cnt += 1;
            pollfds[poll_count] = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            poll_count += 1;
        }
    }

    let mut raw_x: i32 = 0;
    let mut raw_y: i32 = 0;

    #[cfg(feature = "qemu-sim")]
    let mut serial_line_buf = [0u8; 128];
    #[cfg(feature = "qemu-sim")]
    let mut serial_line_len = 0;

    // Single-threaded zero-allocation POSIX poll loop (20Hz / 50ms tick timeout)
    loop {
        for i in 0..poll_count {
            pollfds[i].revents = 0;
        }

        let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), poll_count as libc::nfds_t, 50) };
        let zones = LayoutZones::compute(screen_bounds, state.keyboard_mode);
        let core_kb_bounds = zones.keyboard_area.map(eg_rect_to_core);

        if ret == 0 {
            // 50ms Timeout -> send 20Hz Tick event
            state.handle_event(UiEvent::Tick, core_bounds, core_kb_bounds, None);
        } else if ret > 0 {
            for i in 0..poll_count {
                let pfd = pollfds[i];
                if (pfd.revents & libc::POLLIN) != 0 {
                    #[cfg(feature = "qemu-sim")]
                    if tty_fd >= 0 && pfd.fd == tty_fd {
                        let mut read_buf = [0u8; 64];
                        let n = unsafe {
                            libc::read(tty_fd, read_buf.as_mut_ptr() as *mut _, read_buf.len())
                        };
                        if n > 0 {
                            for &b in &read_buf[..n as usize] {
                                if b == b'\n' || b == b'\r' {
                                    if serial_line_len > 0 {
                                        if let Ok(line) = core::str::from_utf8(&serial_line_buf[..serial_line_len]) {
                                            let trimmed = line.trim();
                                            if let Some(rest) = trimmed.strip_prefix("rfid ") {
                                                if let Ok(id) = heapless::String::try_from(rest) {
                                                    state.handle_event(UiEvent::RfidScanned(id), core_bounds, core_kb_bounds, None);
                                                }
                                            } else if let Some(rest) = trimmed.strip_prefix("barcode ") {
                                                if let Ok(data) = heapless::String::try_from(rest) {
                                                    state.handle_event(UiEvent::BarcodeScanned(data), core_bounds, core_kb_bounds, None);
                                                }
                                            } else if let Some(rest) = trimmed.strip_prefix("type ") {
                                                if let Ok(data) = heapless::String::try_from(rest) {
                                                    state.handle_event(UiEvent::BarcodeScanned(data), core_bounds, core_kb_bounds, None);
                                                }
                                            } else if let Some(rest) = trimmed.strip_prefix("click ") {
                                                let mut parts = rest.split_whitespace();
                                                if let (Some(x_str), Some(y_str)) = (parts.next(), parts.next()) {
                                                    if let (Ok(x), Ok(y)) = (x_str.parse::<i32>(), y_str.parse::<i32>()) {
                                                        let eg_pt = Point::new(x, y);
                                                        let core_pt = CorePoint::new(x, y);
                                                        let key = zones.keyboard_area.and_then(|kb| KeyboardGrid::resolve_key(kb, eg_pt, state.keyboard_mode));

                                                        state.handle_event(UiEvent::TouchDown { scaled: core_pt, raw: (x, y) }, core_bounds, core_kb_bounds, key);
                                                        state.handle_event(UiEvent::TouchUp { scaled: core_pt, raw: (x, y) }, core_bounds, core_kb_bounds, None);
                                                    }
                                                }
                                            }
                                        }
                                        serial_line_len = 0;
                                    }
                                } else if serial_line_len < serial_line_buf.len() {
                                    serial_line_buf[serial_line_len] = b;
                                    serial_line_len += 1;
                                }
                            }
                        }
                        continue;
                    }

                    // Read evdev InputEvents
                    let mut events = [InputEvent::default(); 8];
                    let n = unsafe {
                        libc::read(
                            pfd.fd,
                            events.as_mut_ptr() as *mut _,
                            events.len() * core::mem::size_of::<InputEvent>(),
                        )
                    };
                    if n > 0 {
                        let ev_count = n as usize / core::mem::size_of::<InputEvent>();
                        for ev in &events[..ev_count] {
                            match ev.type_ {
                                3 => { // EV_ABS
                                    if ev.code == 0 || ev.code == 53 {
                                        raw_x = ev.value;
                                    } else if ev.code == 1 || ev.code == 54 {
                                        raw_y = ev.value;
                                    }
                                    let eg_pt = scale_touch_point(raw_x, raw_y);
                                    let core_pt = CorePoint::new(eg_pt.x, eg_pt.y);
                                    state.handle_event(UiEvent::TouchMove { scaled: core_pt, raw: (raw_x, raw_y) }, core_bounds, core_kb_bounds, None);
                                }
                                2 => { // EV_REL
                                    if ev.code == 0 {
                                        raw_x = (raw_x + ev.value * 10).clamp(0, 32767);
                                    } else if ev.code == 1 {
                                        raw_y = (raw_y + ev.value * 10).clamp(0, 32767);
                                    }
                                    let eg_pt = scale_touch_point(raw_x, raw_y);
                                    let core_pt = CorePoint::new(eg_pt.x, eg_pt.y);
                                    state.handle_event(UiEvent::TouchMove { scaled: core_pt, raw: (raw_x, raw_y) }, core_bounds, core_kb_bounds, None);
                                }
                                1 => { // EV_KEY
                                    if ev.code == 330 || ev.code == 272 { // BTN_TOUCH or BTN_LEFT
                                        let eg_pt = scale_touch_point(raw_x, raw_y);
                                        let core_pt = CorePoint::new(eg_pt.x, eg_pt.y);
                                        if ev.value == 1 {
                                            let key = zones.keyboard_area.and_then(|kb| KeyboardGrid::resolve_key(kb, eg_pt, state.keyboard_mode));
                                            state.handle_event(UiEvent::TouchDown { scaled: core_pt, raw: (raw_x, raw_y) }, core_bounds, core_kb_bounds, key);
                                        } else if ev.value == 0 {
                                            state.handle_event(UiEvent::TouchUp { scaled: core_pt, raw: (raw_x, raw_y) }, core_bounds, core_kb_bounds, None);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
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
