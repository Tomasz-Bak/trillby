//! Linux framebuffer (/dev/fb0) output.

use crate::raw_print;
use embedded_graphics::{pixelcolor::Rgb565, prelude::RgbColor};

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

pub struct FramebufferWriter {
    pub fd: libc::c_int,
    bpp: u32,
    bgrx_buf: [u8; 800 * 480 * 4],
    reported_error: bool,
}

impl FramebufferWriter {
    pub fn new() -> Self {
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

    pub fn write_frame(&mut self, buffer: &[Rgb565; 800 * 480]) {
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
