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
    fn new_boxed_fb() -> std::boxed::Box<FramebufferWriter> {
        unsafe {
            let layout = std::alloc::Layout::new::<FramebufferWriter>();
            let ptr = std::alloc::alloc_zeroed(layout) as *mut FramebufferWriter;
            assert!(!ptr.is_null());
            (*ptr).fd = -1;
            std::boxed::Box::from_raw(ptr)
        }
    }

    fn new_boxed_pixels() -> std::boxed::Box<[Rgb565; 800 * 480]> {
        std::vec![Rgb565::new(0, 0, 0); 800 * 480]
            .into_boxed_slice()
            .try_into()
            .unwrap()
    }

    #[test]
    fn test_fb_write_frame_16bpp() {
        let fd = create_temp_fd();
        let mut fb = new_boxed_fb();
        fb.fd = fd;
        fb.bpp = 16;

        let mut pixels = new_boxed_pixels();

        pixels[0] = Rgb565::new(31, 0, 0);
        pixels[1] = Rgb565::new(0, 63, 0);
        pixels[2] = Rgb565::new(0, 0, 31);

        fb.write_frame(&pixels);
        assert_eq!(fb.fd, fd);

        unsafe {
            libc::lseek(fd, 0, libc::SEEK_SET);
        }
        let expected_len = 800 * 480 * 2;
        let mut read_buf = std::vec![0u8; expected_len];
        let n = unsafe {
            libc::read(fd, read_buf.as_mut_ptr() as *mut _, expected_len)
        };
        assert_eq!(n as usize, expected_len);

        let raw_pixels: &[u8] = unsafe {
            core::slice::from_raw_parts(pixels.as_ptr() as *const u8, expected_len)
        };
        assert_eq!(&read_buf[..], raw_pixels);

        unsafe {
            libc::close(fd);
        }
    }

    #[test]
    fn test_fb_write_frame_32bpp_bgrx_conversion() {
        let fd = create_temp_fd();
        let mut fb = new_boxed_fb();
        fb.fd = fd;
        fb.bpp = 32;

        let mut pixels = new_boxed_pixels();

        pixels[0] = Rgb565::new(31, 0, 0);
        pixels[1] = Rgb565::new(0, 63, 0);
        pixels[2] = Rgb565::new(0, 0, 31);

        fb.write_frame(&pixels);
        assert_eq!(fb.fd, fd);

        assert_eq!(
            &fb.bgrx_buf[0..12],
            &[0, 0, 255, 255, 0, 255, 0, 255, 255, 0, 0, 255]
        );

        unsafe {
            libc::lseek(fd, 0, libc::SEEK_SET);
        }
        let mut read_header = [0u8; 12];
        let n = unsafe {
            libc::read(fd, read_header.as_mut_ptr() as *mut _, 12)
        };
        assert_eq!(n, 12);
        assert_eq!(
            &read_header,
            &[0, 0, 255, 255, 0, 255, 0, 255, 255, 0, 0, 255]
        );

        unsafe {
            libc::close(fd);
        }
    }

    #[test]
    fn test_fb_write_frame_invalid_fd_resets_to_minus_one() {
        let mut fb = new_boxed_fb();
        let read_only_fd = unsafe { libc::open(b"/dev/null\0".as_ptr() as *const _, libc::O_RDONLY) };
        assert!(read_only_fd >= 0);
        fb.fd = read_only_fd;
        fb.bpp = 16;

        let pixels = new_boxed_pixels();

        fb.write_frame(&pixels);
        assert_eq!(fb.fd, -1, "invalid writable fd must reset fb.fd to -1");
    }
}
