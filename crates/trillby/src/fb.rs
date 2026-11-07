//! Linux framebuffer (/dev/fb0) output.

use crate::raw_print;
use embedded_graphics::{pixelcolor::Rgb565, prelude::RgbColor};
use trillby_ui::{ScreenPixels, SCREEN_HEIGHT, SCREEN_PIXELS, SCREEN_WIDTH};

// From <linux/fb.h>
const FBIOGET_VSCREENINFO: libc::c_ulong = 0x4600;
const BPP_RGB565: u32 = 16;
const BPP_XRGB8888: u32 = 32;

#[allow(dead_code)] // kernel ABI layout
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
type BgrxBuf = [u8; SCREEN_PIXELS * 4];
static mut BGRX: BgrxBuf = [0u8; SCREEN_PIXELS * 4];

pub struct FramebufferWriter {
    fd: libc::c_int,
    bpp: u32,
    bgrx_buf: &'static mut BgrxBuf,
    reported_error: bool,
}

impl FramebufferWriter {
    #[inline]
    pub fn is_bound(&self) -> bool {
        self.fd >= 0
    }

    pub fn new() -> Self {
        Self {
            fd: -1,
            bpp: BPP_RGB565,
            bgrx_buf: unsafe { &mut *core::ptr::addr_of_mut!(BGRX) },
            reported_error: false,
        }
    }

    fn open_fb(&mut self) -> bool {
        if self.fd >= 0 {
            return true;
        }
        let fd = unsafe { libc::open(c"/dev/fb0".as_ptr(), libc::O_RDWR) };
        if fd >= 0 {
            let mut var_info: FbVarScreeninfo = unsafe { core::mem::zeroed() };
            let res = unsafe {
                libc::ioctl(fd, FBIOGET_VSCREENINFO as _, &mut var_info as *mut _ as *mut libc::c_void)
            };
            if res == 0 && (var_info.xres != SCREEN_WIDTH || var_info.yres != SCREEN_HEIGHT) {
                crate::print_fmt(format_args!(
                    "WARN: /dev/fb0 is {}x{}, expected {}x{}\n",
                    var_info.xres, var_info.yres, SCREEN_WIDTH, SCREEN_HEIGHT
                ));
            }
            self.bpp = if res == 0
                && (var_info.bits_per_pixel == BPP_RGB565
                    || var_info.bits_per_pixel == BPP_XRGB8888)
            {
                var_info.bits_per_pixel
            } else {
                BPP_RGB565
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

    pub fn write_frame(&mut self, buffer: &ScreenPixels) {
        if !self.open_fb() {
            return;
        }
        unsafe {
            libc::lseek(self.fd, 0, libc::SEEK_SET);
        }

        let res = if self.bpp == BPP_XRGB8888 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    fn create_temp_fd() -> libc::c_int {
        let pid = unsafe { libc::getpid() };
        let mut path = [0u8; 64];
        let mut w = crate::BufferWriter::new(&mut path);
        let _ = write!(w, "/tmp/trillby_fb_{}_{}\0", pid, unsafe { libc::rand() });
        let fd = unsafe {
            libc::open(
                path.as_ptr() as *const _,
                libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
                0o600,
            )
        };
        assert!(fd >= 0, "failed to create temp file");
        unsafe {
            libc::unlink(path.as_ptr() as *const _);
        }
        fd
    }

    fn new_boxed_pixels() -> std::boxed::Box<ScreenPixels> {
        std::vec![Rgb565::BLACK; SCREEN_PIXELS]
            .into_boxed_slice()
            .try_into()
            .unwrap()
    }

    const EXPECTED_BGRX_PRIMARIES: [u8; 12] = [
        0, 0, 255, 255, // Red: B=0, G=0, R=255, X=255
        0, 255, 0, 255, // Green: B=0, G=255, R=0, X=255
        255, 0, 0, 255, // Blue: B=255, G=0, R=0, X=255
    ];

    fn write_primaries(bpp: u32) -> (libc::c_int, FramebufferWriter) {
        let fd = create_temp_fd();
        let mut fb = FramebufferWriter::new();
        fb.fd = fd;
        fb.bpp = bpp;
        let mut pixels = new_boxed_pixels();
        pixels[0] = Rgb565::new(31, 0, 0);
        pixels[1] = Rgb565::new(0, 63, 0);
        pixels[2] = Rgb565::new(0, 0, 31);
        fb.write_frame(&pixels);
        (fd, fb)
    }

    #[test]
    fn test_fb_write_frame_16bpp() {
        let (fd, fb) = write_primaries(BPP_RGB565);
        assert_eq!(fb.fd, fd);

        unsafe {
            libc::lseek(fd, 0, libc::SEEK_SET);
        }
        let expected_len = SCREEN_PIXELS * 2;
        let mut read_buf = std::vec![0u8; expected_len];
        let n = unsafe {
            libc::read(fd, read_buf.as_mut_ptr() as *mut _, expected_len)
        };
        assert_eq!(n as usize, expected_len);
        assert_eq!(&read_buf[..6], &[0x00, 0xF8, 0xE0, 0x07, 0x1F, 0x00]);
        assert!(read_buf[6..].iter().all(|&b| b == 0));

        unsafe {
            libc::close(fd);
        }
    }

    #[test]
    fn test_fb_write_frame_32bpp_bgrx_conversion() {
        let (fd, fb) = write_primaries(BPP_XRGB8888);
        assert_eq!(fb.fd, fd);

        assert_eq!(&fb.bgrx_buf[0..12], &EXPECTED_BGRX_PRIMARIES);

        unsafe {
            libc::lseek(fd, 0, libc::SEEK_SET);
        }
        let mut read_header = [0u8; 12];
        let n = unsafe {
            libc::read(fd, read_header.as_mut_ptr() as *mut _, 12)
        };
        assert_eq!(n, 12);
        assert_eq!(&read_header, &EXPECTED_BGRX_PRIMARIES);

        unsafe {
            libc::close(fd);
        }
    }

    #[test]
    fn test_fb_write_frame_invalid_fd_resets_to_minus_one() {
        let mut fb = FramebufferWriter::new();
        let read_only_fd = unsafe { libc::open(b"/dev/null\0".as_ptr() as *const _, libc::O_RDONLY) };
        assert!(read_only_fd >= 0);
        fb.fd = read_only_fd;
        fb.bpp = BPP_RGB565;

        let pixels = new_boxed_pixels();

        fb.write_frame(&pixels);
        assert_eq!(fb.fd, -1, "invalid writable fd must reset fb.fd to -1");
    }

}
